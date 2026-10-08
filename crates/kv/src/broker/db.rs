//! Runs an authorized `db_query` on a connection of its own and scrubs what
//! comes back. Postgres queries use the simple query protocol, so values
//! arrive as text; Redis replies become JSON.

use std::collections::BTreeMap;
use std::pin::pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use futures_util::StreamExt;
use kv_core::db::split_command;
use kv_core::proto::{
    AgentErrorCode, AgentResponse, MAX_OUTPUT_LEN, RedisReply, ResultSet, RowsReply,
};
use kv_core::scrub::Scrubber;
use kv_core::secret::SecretValue;
use rustls_platform_verifier::BuilderVerifierExt;
use tokio_postgres::SimpleQueryMessage;

use super::DbJob;
use crate::audit::Use;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Whether a write-capable role is behind each read-only Postgres handle,
/// learned on its first query since the vault was unlocked. Shared by the
/// daemon, which shows the warnings and forgets them when a handle changes
/// or the vault locks, and the jobs that run the checks.
#[derive(Clone, Default)]
pub struct RoleChecks(Arc<Mutex<BTreeMap<String, Option<String>>>>);

impl RoleChecks {
    fn map(&self) -> std::sync::MutexGuard<'_, BTreeMap<String, Option<String>>> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub fn is_checked(&self, handle: &str) -> bool {
        self.map().contains_key(handle)
    }

    pub fn record(&self, handle: &str, warning: Option<String>) {
        self.map().insert(handle.to_owned(), warning);
    }

    pub fn forget(&self, handle: &str) {
        self.map().remove(handle);
    }

    pub fn clear(&self) {
        self.map().clear();
    }

    /// The handles whose role can write, with the warning for each.
    pub fn warnings(&self) -> BTreeMap<String, String> {
        self.map()
            .iter()
            .filter_map(|(handle, warning)| Some((handle.clone(), warning.clone()?)))
            .collect()
    }
}

/// Runs the query within the job's timeout and records it in the audit log.
pub async fn run(job: DbJob) -> AgentResponse {
    let response = match tokio::time::timeout(job.timeout, query(&job)).await {
        Ok(Ok(response) | Err(response)) => response,
        Err(_) => error(
            AgentErrorCode::UpstreamError,
            format!("the query timed out after {}s", job.timeout.as_secs()),
        ),
    };
    let outcome = match &response {
        AgentResponse::Error { code, .. } => code.as_str(),
        _ => "ok",
    };
    let summary: String = job.call.query.chars().take(200).collect();
    job.audit.record_use(&Use {
        action: "db_query",
        handle: &job.secret.name,
        decision: job.decision,
        summary: &summary,
        outcome,
        duration: job.started.elapsed(),
    });
    response
}

async fn query(job: &DbJob) -> Result<AgentResponse, AgentResponse> {
    match &job.secret.value {
        SecretValue::Postgres { url } => postgres(job, url.expose()).await,
        SecretValue::Redis { url } => redis(job, url.expose()).await,
        _ => Err(error(AgentErrorCode::BadRequest, "not a database handle")),
    }
}

async fn postgres(job: &DbJob, url: &str) -> Result<AgentResponse, AgentResponse> {
    let scrubber = &job.scrubber;
    // The server enforces the timeout too, so an abandoned query stops.
    let mut options = format!(" -c statement_timeout={}", job.timeout.as_millis());
    if job.secret.policy.read_only {
        options.push_str(" -c default_transaction_read_only=on");
    }
    let client = connect(url, &options, scrubber).await?;

    let mut warnings = Vec::new();
    if job.secret.policy.read_only && !job.role_checks.is_checked(&job.secret.name) {
        let warning = role_can_write(&client)
            .await
            .map_err(|e| upstream(scrubber, &e))?
            .then(|| role_warning(&job.secret.name));
        job.role_checks.record(&job.secret.name, warning);
    }
    if let Some(warning) = job.role_checks.warnings().remove(&job.secret.name) {
        warnings.push(warning);
    }

    let stream = client
        .simple_query_raw(&job.call.query)
        .await
        .map_err(|e| upstream(scrubber, &e))?;
    let mut stream = pin!(stream);
    let mut results: Vec<ResultSet> = Vec::new();
    let mut open: Option<ResultSet> = None;
    let mut size = 0;
    let mut truncated = false;
    while let Some(message) = stream.next().await {
        match message.map_err(|e| upstream(scrubber, &e))? {
            SimpleQueryMessage::RowDescription(columns) => {
                let columns: Vec<String> = columns
                    .iter()
                    .map(|c| scrub_text(scrubber, c.name().as_bytes()))
                    .collect();
                size += columns.iter().map(|c| c.len() + 3).sum::<usize>();
                open = Some(ResultSet {
                    columns,
                    rows: Vec::new(),
                    rows_affected: None,
                });
            }
            SimpleQueryMessage::Row(row) => {
                let cells: Vec<Option<String>> = (0..row.len())
                    .map(|i| row.get(i).map(|v| scrub_text(scrubber, v.as_bytes())))
                    .collect();
                size += cells
                    .iter()
                    .map(|c| c.as_ref().map_or(4, |v| v.len() + 3))
                    .sum::<usize>();
                if size > MAX_OUTPUT_LEN {
                    truncated = true;
                    break;
                }
                if let Some(set) = &mut open {
                    set.rows.push(cells);
                }
            }
            SimpleQueryMessage::CommandComplete(count) => {
                let mut set = open.take().unwrap_or(ResultSet {
                    columns: Vec::new(),
                    rows: Vec::new(),
                    rows_affected: None,
                });
                set.rows_affected = Some(count);
                results.push(set);
            }
            _ => {}
        }
    }
    results.extend(open);
    Ok(AgentResponse::Rows(RowsReply {
        results,
        truncated,
        warnings,
    }))
}

/// Connects with `options` added to any the URL has. The connection runs
/// until the client is dropped, which also stops a query cut short.
async fn connect(
    url: &str,
    options: &str,
    scrubber: &Scrubber,
) -> Result<tokio_postgres::Client, AgentResponse> {
    let mut config: tokio_postgres::Config = url.parse().map_err(|_| {
        error(
            AgentErrorCode::BadRequest,
            "the handle's connection URL is not a valid Postgres URL",
        )
    })?;
    let mut all = config.get_options().unwrap_or_default().to_owned();
    all.push_str(options);
    config
        .options(all.trim())
        .application_name("kv")
        .connect_timeout(CONNECT_TIMEOUT);
    let tls = tokio_postgres_rustls::MakeRustlsConnect::new(tls_config()?);
    let (client, connection) = config
        .connect(tls)
        .await
        .map_err(|e| upstream(scrubber, &e))?;
    tokio::spawn(connection);
    Ok(client)
}

fn role_warning(handle: &str) -> String {
    format!(
        "{handle} is read-only, but its database role can write; kv keeps the session \
         read-only only on a best-effort basis. Use a role that can only read."
    )
}

/// Whether the session's role can change data: a superuser, or one with
/// INSERT, UPDATE, DELETE or TRUNCATE on any table, or CREATE on any
/// schema, outside the system schemas.
async fn role_can_write(client: &tokio_postgres::Client) -> Result<bool, tokio_postgres::Error> {
    const CHECK: &str = "\
SELECT r.rolsuper
  OR EXISTS (
    SELECT 1 FROM pg_catalog.pg_class c
    JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
    WHERE c.relkind IN ('r', 'p')
      AND n.nspname NOT IN ('pg_catalog', 'information_schema')
      AND n.nspname NOT LIKE 'pg\\_%'
      AND (has_table_privilege(c.oid, 'INSERT') OR has_table_privilege(c.oid, 'UPDATE')
        OR has_table_privilege(c.oid, 'DELETE') OR has_table_privilege(c.oid, 'TRUNCATE')))
  OR EXISTS (
    SELECT 1 FROM pg_catalog.pg_namespace n
    WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
      AND n.nspname NOT LIKE 'pg\\_%'
      AND has_schema_privilege(n.oid, 'CREATE'))
FROM pg_catalog.pg_roles r WHERE r.rolname = current_user";
    let messages = client.simple_query(CHECK).await?;
    Ok(messages
        .iter()
        .any(|message| matches!(message, SimpleQueryMessage::Row(row) if row.get(0) == Some("t"))))
}

/// Certificates are always checked against the platform's trust store,
/// whatever `sslmode` says; `sslmode=disable` still turns TLS off.
fn tls_config() -> Result<rustls::ClientConfig, AgentResponse> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .and_then(|builder| builder.with_platform_verifier())
        .map(|builder| builder.with_no_client_auth())
        .map_err(|e| {
            error(
                AgentErrorCode::UpstreamError,
                format!("could not set up TLS: {e}"),
            )
        })
}

async fn redis(job: &DbJob, url: &str) -> Result<AgentResponse, AgentResponse> {
    let scrubber = &job.scrubber;
    // Checked by the daemon already; this split cannot fail.
    let args = split_command(&job.call.query)
        .map_err(|message| error(AgentErrorCode::BadRequest, message))?;
    let client = redis::Client::open(url).map_err(|_| {
        error(
            AgentErrorCode::BadRequest,
            "the handle's connection URL is not a valid Redis URL",
        )
    })?;
    let config = redis::AsyncConnectionConfig::new()
        .set_connection_timeout(Some(CONNECT_TIMEOUT))
        .set_response_timeout(Some(job.timeout));
    let mut connection = client
        .get_multiplexed_async_connection_with_config(&config)
        .await
        .map_err(|e| upstream(scrubber, &e))?;
    let mut command = redis::cmd(&String::from_utf8_lossy(&args[0]));
    for arg in &args[1..] {
        command.arg(arg.as_slice());
    }
    let value: redis::Value = command
        .query_async(&mut connection)
        .await
        .map_err(|e| upstream(scrubber, &e))?;
    let mut budget = MAX_OUTPUT_LEN;
    let mut truncated = false;
    let value = to_json(scrubber, value, &mut budget, &mut truncated);
    Ok(AgentResponse::Redis(RedisReply { value, truncated }))
}

/// A Redis value as JSON, scrubbed, spending `budget` bytes at most.
/// Anything past the budget is left out and `truncated` is set.
fn to_json(
    scrubber: &Scrubber,
    value: redis::Value,
    budget: &mut usize,
    truncated: &mut bool,
) -> serde_json::Value {
    use redis::Value;
    use serde_json::Value as Json;
    let text = |bytes: &[u8], budget: &mut usize| {
        let text = scrub_text(scrubber, bytes);
        *budget = budget.saturating_sub(text.len() + 3);
        Json::String(text)
    };
    // A number could be a numeric secret, so it goes through the scrubber
    // too, and comes back as a string if it was replaced.
    let number = |digits: String, json: Json, budget: &mut usize| {
        *budget = budget.saturating_sub(digits.len() + 1);
        let scrubbed = scrub_text(scrubber, digits.as_bytes());
        if scrubbed == digits {
            json
        } else {
            Json::String(scrubbed)
        }
    };
    let list = |items: Vec<Value>, budget: &mut usize, truncated: &mut bool| {
        let mut out = Vec::new();
        for item in items {
            if *budget == 0 {
                *truncated = true;
                break;
            }
            out.push(to_json(scrubber, item, budget, truncated));
        }
        Json::Array(out)
    };
    match value {
        Value::Nil => Json::Null,
        Value::Okay => text(b"OK", budget),
        Value::Int(n) => number(n.to_string(), Json::from(n), budget),
        Value::Double(n) => number(n.to_string(), Json::from(n), budget),
        Value::Boolean(b) => Json::Bool(b),
        Value::BulkString(bytes) => text(&bytes, budget),
        Value::SimpleString(s) => text(s.as_bytes(), budget),
        Value::VerbatimString { text: s, .. } => text(s.as_bytes(), budget),
        Value::BigNumber(digits) => text(&digits, budget),
        Value::Array(items) | Value::Set(items) => list(items, budget, truncated),
        Value::Map(pairs) => list(
            pairs
                .into_iter()
                .map(|(k, v)| Value::Array(vec![k, v]))
                .collect(),
            budget,
            truncated,
        ),
        Value::Attribute { data, .. } => to_json(scrubber, *data, budget, truncated),
        Value::Push { data, .. } => list(data, budget, truncated),
        Value::ServerError(e) => text(e.to_string().as_bytes(), budget),
        _ => Json::Null,
    }
}

fn scrub_text(scrubber: &Scrubber, bytes: &[u8]) -> String {
    String::from_utf8_lossy(&scrubber.scrub(bytes)).into_owned()
}

/// An `upstream_error` with the whole chain of causes, scrubbed: database
/// errors can quote the query, and connection errors can name the host.
fn upstream(scrubber: &Scrubber, e: &(dyn std::error::Error + 'static)) -> AgentResponse {
    let mut message = e.to_string();
    let mut source = e.source();
    while let Some(cause) = source {
        let cause = cause.to_string();
        if !message.contains(&cause) {
            message.push_str(": ");
            message.push_str(&cause);
        }
        source = source.and_then(|s| s.source());
    }
    error(
        AgentErrorCode::UpstreamError,
        scrub_text(scrubber, message.as_bytes()),
    )
}

fn error(code: AgentErrorCode, message: impl Into<String>) -> AgentResponse {
    AgentResponse::Error {
        code,
        message: message.into(),
    }
}
