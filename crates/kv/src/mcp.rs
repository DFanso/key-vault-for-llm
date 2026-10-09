//! `kv mcp`: an MCP server on stdin and stdout for agents such as Claude
//! Code. Each tool call becomes one agent-socket request, so this process
//! never holds a secret: the daemon does the work and returns scrubbed
//! results.

use std::collections::BTreeMap;
use std::io;
use std::path::PathBuf;

use kv_core::crypto::fill_random;
use kv_core::proto::{
    AgentRequest, AgentResponse, ConnectCall, DbCall, ExecCall, HandleRequest, HttpCall,
    SessionInfo,
};
use kv_core::secret::{AuthPlacement, SecretKind};
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, ContentBlock};
use rmcp::{
    ErrorData, Peer, RoleServer, ServerHandler, ServiceExt, schemars, tool, tool_handler,
    tool_router,
};
use serde::Deserialize;

use crate::client;
use crate::paths::Paths;

#[derive(Deserialize, schemars::JsonSchema)]
pub struct HttpRequestArgs {
    /// Handle name from list_handles.
    handle: String,
    /// HTTP method, such as GET or POST.
    method: String,
    /// The full URL. For handles whose takes_path is true, a path such as
    /// /v1/items instead.
    url: String,
    /// Extra request headers. kv adds the credential itself.
    #[serde(default)]
    headers: BTreeMap<String, String>,
    /// Request body.
    #[serde(default)]
    body: Option<String>,
}

#[derive(Deserialize, schemars::JsonSchema)]
pub struct ExecArgs {
    /// env handles whose variables the program receives.
    handles: Vec<String>,
    /// The program and its arguments, such as ["terraform", "plan"]. Never
    /// run through a shell.
    argv: Vec<String>,
    /// Absolute working directory. Defaults to the directory kv mcp runs in.
    #[serde(default)]
    cwd: Option<PathBuf>,
    /// Seconds before the program is killed: 60 by default, at most 600.
    #[serde(default)]
    timeout_secs: Option<u64>,
}

#[derive(Deserialize, schemars::JsonSchema)]
pub struct DbQueryArgs {
    /// A postgres or redis handle from list_handles.
    handle: String,
    /// postgres: SQL, one or more statements separated by semicolons.
    /// redis: one command line, such as HGETALL user:1 (quote arguments
    /// with spaces as redis-cli does).
    query: String,
    /// Seconds before the query is stopped: 30 by default, at most 300.
    #[serde(default)]
    timeout_secs: Option<u64>,
}

#[derive(Deserialize, schemars::JsonSchema)]
pub struct DbConnectArgs {
    /// A postgres or redis handle from list_handles.
    handle: String,
    /// Seconds the URL keeps working: 900 by default, at most 3600.
    #[serde(default)]
    ttl_secs: Option<u64>,
}

/// Never carries a secret value: unknown fields such as `token` are refused.
#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RequestHandleArgs {
    /// Handle name: lowercase letters, digits, - and _, such as prod-db.
    name: String,
    /// http, env, postgres or redis.
    kind: String,
    /// Shown to agents in list_handles, such as "Staging Dokploy API".
    #[serde(default)]
    description: String,
    /// Why you need it. Shown to the user.
    #[serde(default)]
    reason: String,
    /// http: the header the token goes in, such as Authorization or x-api-key.
    #[serde(default)]
    header: Option<String>,
    /// http: the header value with {} where the token goes, such as "Bearer {}" or "{}".
    #[serde(default)]
    template: Option<String>,
    /// http: a query parameter the token goes in instead of a header.
    #[serde(default)]
    query_param: Option<String>,
    /// http: true if the service's address should stay hidden too; you
    /// then send paths and the user enters the base URL.
    #[serde(default)]
    base_url: bool,
    /// http: hosts the token may be sent to, such as api.example.com.
    #[serde(default)]
    allowed_hosts: Vec<String>,
    /// env: names of the variables the handle should set.
    #[serde(default)]
    env_vars: Vec<String>,
    /// env: programs allowed to receive them, such as terraform.
    #[serde(default)]
    allowed_cmds: Vec<String>,
}

#[derive(Clone)]
pub struct KvServer {
    paths: Paths,
    /// Where `kv mcp` was started, normally the agent's project directory.
    cwd: PathBuf,
    /// Random per `kv mcp` process, so "allow for the session" in `kv tui`
    /// covers this agent and no other.
    session_id: String,
}

#[tool_router]
impl KvServer {
    #[tool(
        description = "List the secret handles you can use, with their kind, description and policy. Never returns secret values."
    )]
    async fn list_handles(&self) -> Result<CallToolResult, ErrorData> {
        Ok(self.ask(None, AgentRequest::ListHandles).await)
    }

    #[tool(description = "Whether the vault exists and is unlocked.")]
    async fn status(&self) -> Result<CallToolResult, ErrorData> {
        Ok(self.ask(None, AgentRequest::Status).await)
    }

    #[tool(
        description = "Send an HTTP request with a handle's credential attached. Returns the status, headers and body (at most 256 KiB), with secrets replaced by [kv:<handle>]. If the handle's mode is ask, this waits up to 60 s for the user to approve it in kv tui."
    )]
    async fn http_request(
        &self,
        peer: Peer<RoleServer>,
        Parameters(args): Parameters<HttpRequestArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let session = self.session(&peer);
        Ok(self
            .ask(
                Some(&session),
                AgentRequest::HttpRequest(HttpCall {
                    handle: args.handle,
                    method: args.method,
                    url: args.url,
                    headers: args.headers,
                    body: args.body,
                }),
            )
            .await)
    }

    #[tool(
        description = "Run a program with the variables of one or more env handles set. Returns the exit code, stdout and stderr (each at most 256 KiB), with secrets replaced by [kv:<handle>]. If a handle's mode is ask, this waits up to 60 s for the user to approve it in kv tui."
    )]
    async fn exec(
        &self,
        peer: Peer<RoleServer>,
        Parameters(args): Parameters<ExecArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let session = self.session(&peer);
        Ok(self
            .ask(
                Some(&session),
                AgentRequest::Exec(ExecCall {
                    handles: args.handles,
                    argv: args.argv,
                    cwd: args.cwd.unwrap_or_else(|| self.cwd.clone()),
                    timeout_secs: args.timeout_secs,
                }),
            )
            .await)
    }

    #[tool(
        description = "Run a query on a postgres or redis handle. Postgres returns one result per statement, with values as text and NULL as null; redis returns the reply as JSON. Results are capped at 256 KiB, with secrets replaced by [kv:<handle>]. Read-only handles refuse writes. If the handle's mode is ask, this waits up to 60 s for the user to approve it in kv tui."
    )]
    async fn db_query(
        &self,
        peer: Peer<RoleServer>,
        Parameters(args): Parameters<DbQueryArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let session = self.session(&peer);
        Ok(self
            .ask(
                Some(&session),
                AgentRequest::DbQuery(DbCall {
                    handle: args.handle,
                    query: args.query,
                    timeout_secs: args.timeout_secs,
                }),
            )
            .await)
    }

    #[tool(
        description = "Get a connection URL for a postgres or redis handle, for a tool that needs its own connection (psql, redis-cli, a migration tool, a test suite). The URL points at kv on 127.0.0.1 and holds a lease token instead of the password; it works only on this machine and stops working when it expires, the vault locks or the handle changes, which also closes its connections. Results through it are scrubbed, and read-only handles stay read-only. Prefer db_query for single queries. If the handle's mode is ask, this waits up to 60 s for the user to approve it in kv tui."
    )]
    async fn db_connect(
        &self,
        peer: Peer<RoleServer>,
        Parameters(args): Parameters<DbConnectArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let session = self.session(&peer);
        Ok(self
            .ask(
                Some(&session),
                AgentRequest::DbConnect(ConnectCall {
                    handle: args.handle,
                    ttl_secs: args.ttl_secs,
                }),
            )
            .await)
    }

    #[tool(
        description = "Ask the user to add a handle you need but do not have. Never include a secret value: the user types it in kv tui, where your request appears with the form filled in, and decides the policy. Returns at once; call list_handles later to see whether it was added."
    )]
    async fn request_handle(
        &self,
        peer: Peer<RoleServer>,
        Parameters(args): Parameters<RequestHandleArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let kind = match args.kind.as_str() {
            "http" => SecretKind::Http,
            "env" => SecretKind::Env,
            "postgres" => SecretKind::Postgres,
            "redis" => SecretKind::Redis,
            _ => {
                return Ok(CallToolResult::error(vec![ContentBlock::text(
                    "bad_request: kind must be http, env, postgres or redis",
                )]));
            }
        };
        let auth = match (args.query_param, args.header) {
            (Some(param), _) => Some(AuthPlacement::Query { param }),
            (None, Some(name)) => Some(AuthPlacement::Header {
                name,
                template: args.template.unwrap_or_else(|| "{}".into()),
            }),
            (None, None) => None,
        };
        let session = self.session(&peer);
        let request = AgentRequest::RequestHandle(HandleRequest {
            name: args.name,
            kind,
            description: args.description,
            reason: args.reason,
            auth,
            base_url: args.base_url,
            allowed_hosts: args.allowed_hosts,
            env_vars: args.env_vars,
            allowed_cmds: args.allowed_cmds,
        });
        Ok(
            match client::agent(&self.paths, Some(&session), &request).await {
                Ok(AgentResponse::Requested { name }) => {
                    CallToolResult::success(vec![ContentBlock::text(format!(
                        "Asked the user to add {name}. It is waiting for them in kv tui; tell them, and call list_handles later to see whether it was added."
                    ))])
                }
                Ok(other) => describe(other),
                Err(e) => unreachable_daemon(e),
            },
        )
    }
}

#[tool_handler(
    name = "kv",
    instructions = "kv lets you use the user's API keys, tokens and other secrets \
without seeing them. Call list_handles to see what is available and how each handle may be \
used, then call http_request, exec, db_query or db_connect with a handle name. Secret values never appear in \
results; where one would, you see [kv:<handle>]. Handles in ask mode wait for the user to \
approve each use in kv tui; approval_denied means they said no, so do not retry it. If a call \
fails with vault_locked, ask the user to run `kv unlock`. If you need a secret that has no \
handle, call request_handle and tell the user; never ask them to paste a secret into the chat."
)]
impl ServerHandler for KvServer {}

impl KvServer {
    /// Who is asking: this process's session id and the client's
    /// self-reported name from MCP initialization.
    fn session(&self, peer: &Peer<RoleServer>) -> SessionInfo {
        let client = peer
            .peer_info()
            .map(|info| info.client_info.name.clone())
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| "unknown MCP client".into());
        SessionInfo {
            id: self.session_id.clone(),
            client,
        }
    }

    /// Sends one request, starting the daemon if needed. Daemon errors come
    /// back as tool errors that start with their code.
    async fn ask(&self, session: Option<&SessionInfo>, request: AgentRequest) -> CallToolResult {
        match client::agent(&self.paths, session, &request).await {
            Ok(response) => describe(response),
            Err(e) => unreachable_daemon(e),
        }
    }
}

/// A daemon reply as a tool result; errors start with their code.
fn describe(response: AgentResponse) -> CallToolResult {
    match response {
        AgentResponse::Error { code, message } => CallToolResult::error(vec![ContentBlock::text(
            format!("{}: {message}", code.as_str()),
        )]),
        response => {
            let json = serde_json::to_string_pretty(&response).unwrap_or_default();
            CallToolResult::success(vec![ContentBlock::text(json)])
        }
    }
}

fn unreachable_daemon(e: io::Error) -> CallToolResult {
    CallToolResult::error(vec![ContentBlock::text(format!(
        "daemon_unavailable: the kv daemon could not be started or reached: {e}"
    ))])
}

/// Serves MCP on stdin and stdout until the client disconnects.
pub async fn serve(paths: Paths) -> io::Result<()> {
    let mut id = [0u8; 16];
    fill_random(&mut id);
    let server = KvServer {
        paths,
        cwd: std::env::current_dir()?,
        session_id: id.iter().map(|b| format!("{b:02x}")).collect(),
    };
    let running = server
        .serve(rmcp::transport::stdio())
        .await
        .map_err(io::Error::other)?;
    running.waiting().await.map_err(io::Error::other)?;
    Ok(())
}
