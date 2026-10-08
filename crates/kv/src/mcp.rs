//! `kv mcp`: an MCP server on stdin and stdout for agents such as Claude
//! Code. Each tool call becomes one agent-socket request, so this process
//! never holds a secret: the daemon does the work and returns scrubbed
//! results.

use std::collections::BTreeMap;
use std::io;
use std::path::PathBuf;

use kv_core::proto::{AgentRequest, AgentResponse, ExecCall, HttpCall};
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, ContentBlock};
use rmcp::{ErrorData, ServerHandler, ServiceExt, schemars, tool, tool_handler, tool_router};
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

#[derive(Clone)]
pub struct KvServer {
    paths: Paths,
    /// Where `kv mcp` was started, normally the agent's project directory.
    cwd: PathBuf,
}

#[tool_router]
impl KvServer {
    #[tool(
        description = "List the secret handles you can use, with their kind, description and policy. Never returns secret values."
    )]
    async fn list_handles(&self) -> Result<CallToolResult, ErrorData> {
        Ok(self.ask(AgentRequest::ListHandles).await)
    }

    #[tool(description = "Whether the vault exists and is unlocked.")]
    async fn status(&self) -> Result<CallToolResult, ErrorData> {
        Ok(self.ask(AgentRequest::Status).await)
    }

    #[tool(
        description = "Send an HTTP request with a handle's credential attached. Returns the status, headers and body (at most 256 KiB), with secrets replaced by [kv:<handle>]."
    )]
    async fn http_request(
        &self,
        Parameters(args): Parameters<HttpRequestArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        Ok(self
            .ask(AgentRequest::HttpRequest(HttpCall {
                handle: args.handle,
                method: args.method,
                url: args.url,
                headers: args.headers,
                body: args.body,
            }))
            .await)
    }

    #[tool(
        description = "Run a program with the variables of one or more env handles set. Returns the exit code, stdout and stderr (each at most 256 KiB), with secrets replaced by [kv:<handle>]."
    )]
    async fn exec(
        &self,
        Parameters(args): Parameters<ExecArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        Ok(self
            .ask(AgentRequest::Exec(ExecCall {
                handles: args.handles,
                argv: args.argv,
                cwd: args.cwd.unwrap_or_else(|| self.cwd.clone()),
                timeout_secs: args.timeout_secs,
            }))
            .await)
    }
}

#[tool_handler(
    name = "kv",
    instructions = "kv lets you use the user's API keys, tokens and other secrets \
without seeing them. Call list_handles to see what is available and how each handle may be \
used, then call http_request or exec with a handle name. Secret values never appear in \
results; where one would, you see [kv:<handle>]. If a call fails with vault_locked, ask the \
user to run `kv unlock`."
)]
impl ServerHandler for KvServer {}

impl KvServer {
    /// Sends one request, starting the daemon if needed. Daemon errors come
    /// back as tool errors that start with their code.
    async fn ask(&self, request: AgentRequest) -> CallToolResult {
        match client::agent(&self.paths, &request).await {
            Ok(AgentResponse::Error { code, message }) => {
                CallToolResult::error(vec![ContentBlock::text(format!(
                    "{}: {message}",
                    code.as_str()
                ))])
            }
            Ok(response) => {
                let json = serde_json::to_string_pretty(&response).unwrap_or_default();
                CallToolResult::success(vec![ContentBlock::text(json)])
            }
            Err(e) => CallToolResult::error(vec![ContentBlock::text(format!(
                "daemon_unavailable: the kv daemon could not be started or reached: {e}"
            ))]),
        }
    }
}

/// Serves MCP on stdin and stdout until the client disconnects.
pub async fn serve(paths: Paths) -> io::Result<()> {
    let server = KvServer {
        paths,
        cwd: std::env::current_dir()?,
    };
    let running = server
        .serve(rmcp::transport::stdio())
        .await
        .map_err(io::Error::other)?;
    running.waiting().await.map_err(io::Error::other)?;
    Ok(())
}
