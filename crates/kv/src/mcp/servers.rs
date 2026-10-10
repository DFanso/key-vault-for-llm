//! The servers `kv mcp` reaches for an agent: handles with a `run` command,
//! started through the daemon on first use and kept for this process. Each
//! is an MCP client on the program's relayed stdin and stdout, so this
//! process sees only scrubbed output and never a secret.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use kv_core::proto::{AgentRequest, AgentResponse, SessionInfo};
use rmcp::ServiceExt;
use rmcp::model::{
    CallToolRequestParams, CallToolResult, ClientCapabilities, ClientConfig, ContentBlock,
    Implementation, ResultType,
};
use rmcp::service::{RoleClient, RunningService};
use serde_json::{Map, Value, json};
use tokio::io::AsyncWriteExt;
use tokio::sync::{OnceCell, watch};

use crate::client::{self, RunEnd, RunGuard, RunStream};
use crate::paths::Paths;

/// How long a started server has to finish MCP initialization: room for a
/// launcher such as bunx to download a pinned version the first time.
const INIT_TIMEOUT: Duration = Duration::from_secs(120);

/// Characters of a tool's first description line shown without `schemas`.
const SHORT_DESCRIPTION: usize = 160;

type Table = BTreeMap<String, Arc<OnceCell<Arc<Server>>>>;

pub struct Servers {
    paths: Paths,
    /// One entry per server started or starting in this process.
    running: Arc<Mutex<Table>>,
}

/// A running server: the MCP client on its relay, why it ended once it
/// has, and the connection that keeps it alive.
struct Server {
    client: RunningService<RoleClient, ClientConfig>,
    end: watch::Receiver<Option<String>>,
    guard: Mutex<Option<RunGuard>>,
}

impl Servers {
    pub fn new(paths: Paths) -> Self {
        Self {
            paths,
            running: Arc::default(),
        }
    }

    fn table(&self) -> MutexGuard<'_, Table> {
        self.running.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub async fn list(&self) -> CallToolResult {
        let handles = match client::agent(&self.paths, None, &AgentRequest::ListHandles).await {
            Ok(AgentResponse::Handles { handles }) => handles,
            Ok(AgentResponse::Error { code, message }) => {
                return failure(format!("{}: {message}", code.as_str()));
            }
            Ok(other) => return failure(format!("upstream_error: unexpected reply {other:?}")),
            Err(e) => return failure(unreachable_daemon(e)),
        };
        let running: Vec<String> = self
            .table()
            .iter()
            .filter(|(_, cell)| cell.initialized())
            .map(|(name, _)| name.clone())
            .collect();
        let servers: Vec<Value> = handles
            .iter()
            .filter_map(|handle| {
                let program = handle.runs.as_ref()?;
                Some(json!({
                    "name": handle.name,
                    "description": handle.description,
                    "runs": program,
                    "mode": handle.mode,
                    "running": running.contains(&handle.name),
                }))
            })
            .collect();
        success(&Value::Array(servers))
    }

    pub async fn list_tools(
        &self,
        name: &str,
        session: SessionInfo,
        filter: Option<&str>,
        schemas: bool,
    ) -> CallToolResult {
        let server = match self.get(name, session).await {
            Ok(server) => server,
            Err(message) => return failure(message),
        };
        let tools = match server.client.list_all_tools().await {
            Ok(tools) => tools,
            Err(e) => return failure(self.lost(name, &server, e).await),
        };
        let needle = filter.unwrap_or_default().to_lowercase();
        let matches: Vec<Value> = tools
            .iter()
            .filter(|tool| {
                let text = format!(
                    "{} {}",
                    tool.name,
                    tool.description.as_deref().unwrap_or_default()
                );
                needle.is_empty() || text.to_lowercase().contains(&needle)
            })
            .map(|tool| {
                if schemas {
                    json!({
                        "name": tool.name,
                        "description": tool.description,
                        "inputSchema": Value::Object((*tool.input_schema).clone()),
                    })
                } else {
                    json!({
                        "name": tool.name,
                        "description": first_line(tool.description.as_deref().unwrap_or_default()),
                    })
                }
            })
            .collect();
        success(&json!({
            "total": tools.len(),
            "matched": matches.len(),
            "tools": matches,
        }))
    }

    pub async fn call(
        &self,
        name: &str,
        session: SessionInfo,
        tool: String,
        arguments: Map<String, Value>,
    ) -> CallToolResult {
        let server = match self.get(name, session).await {
            Ok(server) => server,
            Err(message) => return failure(message),
        };
        let params = CallToolRequestParams::new(tool).with_arguments(arguments);
        match server.client.call_tool(params).await {
            Ok(mut result) => {
                // Servers on revisions before 2026-07-28 leave it out, which
                // means complete; clients on that revision require it.
                result.result_type.get_or_insert(ResultType::COMPLETE);
                result
            }
            Err(e) => failure(self.lost(name, &server, e).await),
        }
    }

    pub async fn stop(&self, name: &str) -> CallToolResult {
        let cell = self.table().remove(name);
        let Some(server) = cell.as_ref().and_then(|cell| cell.get()).cloned() else {
            return text(format!("{name} is not running in this session."));
        };
        // Closing the connection makes the daemon end the program.
        drop(
            server
                .guard
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .take(),
        );
        text(format!("Stopped {name}."))
    }

    /// The running server, starting it first if needed. Calls that arrive
    /// while it starts wait for that one start.
    async fn get(&self, name: &str, session: SessionInfo) -> Result<Arc<Server>, String> {
        let cell = self.table().entry(name.to_owned()).or_default().clone();
        let started = cell
            .get_or_try_init(|| self.start(name, session))
            .await
            .cloned();
        if started.is_err() {
            // Forget the failed start, so the next call tries again.
            let mut table = self.table();
            if table
                .get(name)
                .is_some_and(|c| Arc::ptr_eq(c, &cell) && !c.initialized())
            {
                table.remove(name);
            }
        }
        started
    }

    async fn start(&self, name: &str, session: SessionInfo) -> Result<Arc<Server>, String> {
        let stream = match client::run_stream(&self.paths, Some(&session), name).await {
            Ok(Ok(stream)) => stream,
            Ok(Err(AgentResponse::Error { code, message })) => {
                return Err(format!("{}: {message}", code.as_str()));
            }
            Ok(Err(other)) => {
                return Err(format!(
                    "upstream_error: unexpected reply from the daemon: {other:?}"
                ));
            }
            Err(e) => return Err(unreachable_daemon(e)),
        };
        let RunStream {
            stdin,
            stdout,
            mut stderr,
            ended,
            guard,
        } = stream;
        // The program's stderr, already scrubbed, goes where MCP clients keep
        // a server's logs.
        tokio::spawn(async move {
            let mut err = tokio::io::stderr();
            while let Some(chunk) = stderr.recv().await {
                let _ = err.write_all(&chunk).await;
            }
        });
        let info = ClientConfig::new(
            ClientCapabilities::default(),
            Implementation::new(format!("kv/{name}"), env!("CARGO_PKG_VERSION")),
        );
        let client = match tokio::time::timeout(INIT_TIMEOUT, info.serve((stdout, stdin))).await {
            Ok(Ok(client)) => client,
            Ok(Err(e)) => {
                return Err(format!(
                    "upstream_error: {name} did not start as an MCP server: {e}"
                ));
            }
            Err(_) => {
                return Err(format!(
                    "upstream_error: {name} did not finish starting within {}s",
                    INIT_TIMEOUT.as_secs()
                ));
            }
        };
        let (end_sender, end) = watch::channel(None);
        let server = Arc::new(Server {
            client,
            end,
            guard: Mutex::new(Some(guard)),
        });
        let running = self.running.clone();
        let key = name.to_owned();
        let watched = Arc::downgrade(&server);
        tokio::spawn(async move {
            let reason = match ended.await {
                Ok(RunEnd::Exited {
                    code: Some(code), ..
                }) => format!("the server exited with code {code}"),
                Ok(RunEnd::Exited { .. }) => "the server was killed".to_owned(),
                Ok(RunEnd::Ended(reason)) => reason,
                Ok(RunEnd::Lost) | Err(_) => "kv stopped".to_owned(),
            };
            let _ = end_sender.send(Some(reason));
            // Forget it, so the next call starts it again.
            let mut table = running.lock().unwrap_or_else(PoisonError::into_inner);
            let same = table
                .get(&key)
                .and_then(|cell| cell.get())
                .is_some_and(|s| std::ptr::eq(Arc::as_ptr(s), watched.as_ptr()));
            if same {
                table.remove(&key);
            }
        });
        Ok(server)
    }

    /// The error for a call that failed: `server_stopped` with the reason
    /// once the server has ended, which also forgets it.
    async fn lost(
        &self,
        name: &str,
        server: &Arc<Server>,
        error: impl std::fmt::Display,
    ) -> String {
        let mut end = server.end.clone();
        // The client can notice the end a moment before the reason arrives.
        let _ = tokio::time::timeout(Duration::from_secs(1), end.wait_for(Option::is_some)).await;
        let reason = end.borrow().clone();
        let stopped = reason.is_some() || server.client.is_closed();
        if stopped {
            self.forget(name, server);
        }
        match reason {
            Some(reason) => format!("server_stopped: {reason}"),
            None if stopped => format!("server_stopped: {error}"),
            None => format!("upstream_error: {error}"),
        }
    }

    fn forget(&self, name: &str, server: &Arc<Server>) {
        let mut table = self.table();
        if table
            .get(name)
            .and_then(|cell| cell.get())
            .is_some_and(|s| Arc::ptr_eq(s, server))
        {
            table.remove(name);
        }
    }
}

fn first_line(text: &str) -> String {
    text.lines()
        .next()
        .unwrap_or_default()
        .chars()
        .take(SHORT_DESCRIPTION)
        .collect()
}

fn success(value: &Value) -> CallToolResult {
    CallToolResult::success(vec![ContentBlock::text(
        serde_json::to_string_pretty(value).unwrap_or_default(),
    )])
}

fn text(message: String) -> CallToolResult {
    CallToolResult::success(vec![ContentBlock::text(message)])
}

fn failure(message: String) -> CallToolResult {
    CallToolResult::error(vec![ContentBlock::text(message)])
}

fn unreachable_daemon(e: std::io::Error) -> String {
    format!("daemon_unavailable: the kv daemon could not be started or reached: {e}")
}
