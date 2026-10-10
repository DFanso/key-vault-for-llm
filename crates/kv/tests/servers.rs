//! `kv mcp`'s servers end to end: an MCP client drives the `kv` binary,
//! whose daemon starts this test binary as an MCP server; the `helper` test
//! is that server when `KV_SERVERS_HELPER` is set.

use std::io::Write;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use kv::client;
use kv::paths::Paths;
use kv_core::proto::{Approval, ControlCommand, ControlRequest, ControlResponse, Verdict};
use kv_core::secret::SecretText;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{
    CallToolRequestParams, CallToolResult, ContentBlock, ProtocolVersion, ResultType,
};
use rmcp::service::{ClientLifecycleMode, ClientServiceExt, RoleClient, RunningService};
use rmcp::transport::TokioChildProcess;
use rmcp::{ErrorData, ServerHandler, ServiceExt, schemars, tool, tool_handler, tool_router};
use serde::Deserialize;
use serde_json::{Value, json};
use tempfile::TempDir;

const PASS: &str = "correct horse battery";
const SECRET: &str = "s3cr3t-server-value-0123456789";
const MODE_VAR: &str = "KV_SERVERS_HELPER";

#[derive(Clone)]
struct Helper;

#[derive(Deserialize, schemars::JsonSchema)]
struct EchoArgs {
    text: String,
}

#[tool_router]
impl Helper {
    #[tool(description = "Returns the secret from the environment.")]
    async fn reveal(&self) -> Result<CallToolResult, ErrorData> {
        let secret = std::env::var("SECRET_VALUE").unwrap_or_default();
        Ok(CallToolResult::success(vec![ContentBlock::text(format!(
            "secret={secret}"
        ))]))
    }

    #[tool(description = "Echoes its text.\nA second line that list_server_tools leaves out.")]
    async fn echo(
        &self,
        Parameters(args): Parameters<EchoArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        Ok(CallToolResult::success(vec![ContentBlock::text(args.text)]))
    }

    #[tool(description = "Exits the server at once.")]
    async fn quit(&self) -> Result<CallToolResult, ErrorData> {
        std::process::exit(0)
    }
}

#[tool_handler(name = "helper")]
impl ServerHandler for Helper {}

/// Not a real test. Started by kv with `KV_SERVERS_HELPER` set, it serves
/// MCP on stdin and stdout until its client goes away.
#[test]
fn helper() {
    if std::env::var(MODE_VAR).is_err() {
        return;
    }
    // libtest has written "test helper ... " with no newline; end that line
    // so the first MCP message starts a line of its own.
    println!();
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        let running = Helper.serve(rmcp::transport::stdio()).await.unwrap();
        let _ = running.waiting().await;
    });
    std::process::exit(0);
}

struct Home {
    dir: TempDir,
}

impl Home {
    fn new() -> Self {
        let home = Self {
            dir: TempDir::new().unwrap(),
        };
        home.kv(&["init", "--insecure-fast-kdf"], &format!("{PASS}\n"));
        home
    }

    fn paths(&self) -> Paths {
        Paths::under(self.dir.path())
    }

    fn kv(&self, args: &[&str], stdin: &str) -> String {
        let mut child = Command::new(env!("CARGO_BIN_EXE_kv"))
            .args(args)
            .env("KV_HOME", self.dir.path())
            .env("KV_NOTIFY", "off")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(stdin.as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "kv {args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap()
    }

    fn add_server(&self, name: &str, mode: &str) {
        let exe = std::env::current_exe().unwrap();
        self.kv(
            &[
                "add",
                name,
                "--kind",
                "env",
                "--var",
                "SECRET_VALUE",
                "--var",
                MODE_VAR,
                "--mode",
                mode,
                "--run",
                "--",
                exe.to_str().unwrap(),
                "helper",
                "--exact",
                "--nocapture",
                "--test-threads=1",
            ],
            &format!("{PASS}\n{SECRET}\non\n"),
        );
    }

    async fn mcp(&self) -> RunningService<RoleClient, ()> {
        ().serve(self.mcp_transport()).await.unwrap()
    }

    /// A client on the current revision, which has no `initialize` and
    /// requires `resultType` on every result.
    async fn mcp_current(&self) -> RunningService<RoleClient, ()> {
        let lifecycle = ClientLifecycleMode::Discover {
            preferred_versions: vec![ProtocolVersion::V_2026_07_28],
        };
        ().serve_with_lifecycle(self.mcp_transport(), lifecycle)
            .await
            .unwrap()
    }

    fn mcp_transport(&self) -> TokioChildProcess {
        let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_kv"));
        command
            .arg("mcp")
            .env("KV_HOME", self.dir.path())
            .env("KV_NOTIFY", "off")
            .current_dir(self.dir.path());
        TokioChildProcess::new(command).unwrap()
    }

    /// Audit entries for runs of `handle` that ended with `outcome`.
    fn runs(&self, handle: &str, outcome: &str) -> usize {
        std::fs::read_to_string(&self.paths().audit)
            .unwrap_or_default()
            .lines()
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .filter(|e| e["action"] == "run" && e["handle"] == handle && e["outcome"] == outcome)
            .count()
    }

    fn starts(&self, handle: &str) -> usize {
        self.runs(handle, "started")
    }
}

impl Drop for Home {
    fn drop(&mut self) {
        let _ = Command::new(env!("CARGO_BIN_EXE_kv"))
            .arg("stop")
            .env("KV_HOME", self.dir.path())
            .stdin(Stdio::null())
            .output();
    }
}

async fn call(
    client: &RunningService<RoleClient, ()>,
    tool: &'static str,
    args: Value,
) -> (bool, String) {
    let mut params = CallToolRequestParams::new(tool);
    if let Value::Object(map) = args {
        params = params.with_arguments(map);
    }
    let result = client.call_tool(params).await.unwrap();
    let text = result
        .content
        .iter()
        .filter_map(|block| match block {
            ContentBlock::Text(text) => Some(text.text.clone()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("\n");
    (result.is_error.unwrap_or(false), text)
}

fn json_of(text: &str) -> Value {
    serde_json::from_str(text).unwrap_or_else(|e| panic!("{e}: {text}"))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn list_servers_shows_servers_and_whether_they_run() {
    let home = Home::new();
    home.add_server("srv", "auto");
    home.kv(
        &[
            "add", "plain", "--kind", "env", "--var", "A", "--cmd", "tool",
        ],
        &format!("{PASS}\nvalue-0123456789\n"),
    );
    let client = home.mcp().await;
    let (error, text) = call(&client, "list_servers", json!({})).await;
    assert!(!error, "{text}");
    let servers = json_of(&text);
    let servers = servers.as_array().unwrap();
    assert_eq!(servers.len(), 1, "{text}");
    assert_eq!(servers[0]["name"], "srv");
    assert_eq!(servers[0]["running"], false);
    assert!(!text.contains("--nocapture"), "{text}");
    let (error, text) = call(&client, "list_server_tools", json!({"server": "srv"})).await;
    assert!(!error, "{text}");
    let (_, text) = call(&client, "list_servers", json!({})).await;
    assert_eq!(json_of(&text)[0]["running"], true);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn list_server_tools_filters_and_shows_schemas() {
    let home = Home::new();
    home.add_server("srv", "auto");
    let client = home.mcp().await;
    let (_, text) = call(&client, "list_server_tools", json!({"server": "srv"})).await;
    let listed = json_of(&text);
    assert_eq!(listed["total"], 3);
    assert!(!text.contains("second line"), "{text}");
    assert!(!text.contains("inputSchema"), "{text}");
    let (_, text) = call(
        &client,
        "list_server_tools",
        json!({"server": "srv", "filter": "ECHO", "schemas": true}),
    )
    .await;
    let listed = json_of(&text);
    assert_eq!(listed["matched"], 1);
    assert_eq!(listed["tools"][0]["name"], "echo");
    assert!(text.contains("inputSchema"), "{text}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn call_server_tool_returns_the_result_scrubbed() {
    let home = Home::new();
    home.add_server("srv", "auto");
    let client = home.mcp().await;
    let (error, text) = call(
        &client,
        "call_server_tool",
        json!({"server": "srv", "tool": "reveal"}),
    )
    .await;
    assert!(!error, "{text}");
    assert_eq!(text, "secret=[kv:srv]");
    let (error, text) = call(
        &client,
        "call_server_tool",
        json!({"server": "srv", "tool": "echo", "arguments": {"text": "hi"}}),
    )
    .await;
    assert!(!error, "{text}");
    assert_eq!(text, "hi");
}

// kv reaches its servers over `initialize`, so they answer on an older
// revision and leave `resultType` out, as servers run through bunx do.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_relayed_result_carries_result_type_for_a_current_client() {
    let home = Home::new();
    home.add_server("srv", "auto");
    let client = home.mcp_current().await;
    let params = CallToolRequestParams::new("call_server_tool").with_arguments(
        json!({"server": "srv", "tool": "echo", "arguments": {"text": "hi"}})
            .as_object()
            .unwrap()
            .clone(),
    );
    let result = client.call_tool(params).await.unwrap();
    assert_ne!(result.is_error, Some(true), "{result:?}");
    assert_eq!(result.result_type, Some(ResultType::COMPLETE));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_first_calls_start_the_server_once() {
    let home = Home::new();
    home.add_server("srv", "auto");
    let client = home.mcp().await;
    let args = json!({"server": "srv", "tool": "reveal"});
    let (a, b) = tokio::join!(
        call(&client, "call_server_tool", args.clone()),
        call(&client, "call_server_tool", args)
    );
    assert!(!a.0 && !b.0, "{a:?} {b:?}");
    assert_eq!(home.starts("srv"), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_server_that_quits_or_is_stopped_starts_again() {
    let home = Home::new();
    home.add_server("srv", "auto");
    let client = home.mcp().await;
    let reveal = json!({"server": "srv", "tool": "reveal"});
    assert!(!call(&client, "call_server_tool", reveal.clone()).await.0);
    let (error, text) = call(
        &client,
        "call_server_tool",
        json!({"server": "srv", "tool": "quit"}),
    )
    .await;
    assert!(error, "{text}");
    assert!(text.starts_with("server_stopped"), "{text}");
    let (error, text) = call(&client, "call_server_tool", reveal.clone()).await;
    assert!(!error, "{text}");
    assert_eq!(home.starts("srv"), 2);
    let (error, text) = call(&client, "stop_server", json!({"server": "srv"})).await;
    assert!(!error, "{text}");
    let (_, text) = call(&client, "list_servers", json!({})).await;
    assert_eq!(json_of(&text)[0]["running"], false);
    assert!(!call(&client, "call_server_tool", reveal).await.0);
    assert_eq!(home.starts("srv"), 3);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn locking_stops_servers_and_the_next_call_says_vault_locked() {
    let home = Home::new();
    home.add_server("srv", "auto");
    let client = home.mcp().await;
    let reveal = json!({"server": "srv", "tool": "reveal"});
    assert!(!call(&client, "call_server_tool", reveal.clone()).await.0);
    home.kv(&["lock"], "");
    // The daemon records the end as it ends the server.
    let deadline = Instant::now() + Duration::from_secs(20);
    while home.runs("srv", "locked") == 0 {
        assert!(Instant::now() < deadline, "the lock did not end the server");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    // A call that reaches the old server learns why it stopped; the call
    // after that tries to start it again, on a locked vault.
    let (error, text) = call(&client, "call_server_tool", reveal.clone()).await;
    assert!(error, "{text}");
    let text = if text.starts_with("server_stopped") {
        assert!(text.contains("the vault locked"), "{text}");
        let (error, text) = call(&client, "call_server_tool", reveal).await;
        assert!(error, "{text}");
        text
    } else {
        text
    };
    assert!(text.starts_with("vault_locked"), "{text}");
}

async fn waiting_approval(paths: &Paths, token: &SecretText) -> Approval {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let request = ControlRequest {
            passphrase: None,
            device: None,
            token: Some(token.clone()),
            command: ControlCommand::Overview,
        };
        if let ControlResponse::Overview { overview } =
            client::control(paths, &request, false).await.unwrap()
            && let Some(approval) = overview.approvals.into_iter().next()
        {
            return approval;
        }
        assert!(Instant::now() < deadline, "nothing is waiting");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_ask_server_can_be_allowed_for_the_session() {
    let home = Home::new();
    home.add_server("prod", "ask");
    let paths = home.paths();
    let open = ControlRequest {
        passphrase: Some(SecretText::new(PASS)),
        device: None,
        token: None,
        command: ControlCommand::OpenSession,
    };
    let ControlResponse::Session { token } = client::control(&paths, &open, false).await.unwrap()
    else {
        panic!("no session");
    };
    let client = home.mcp().await;
    let peer = client.peer().clone();
    let reveal = || {
        let mut params = CallToolRequestParams::new("call_server_tool");
        if let Value::Object(map) = json!({"server": "prod", "tool": "reveal"}) {
            params = params.with_arguments(map);
        }
        params
    };
    let pending = tokio::spawn({
        let peer = peer.clone();
        let params = reveal();
        async move { peer.call_tool(params).await.unwrap() }
    });
    let approval = waiting_approval(&paths, &token).await;
    assert_eq!(approval.tool, "run");
    assert!(approval.can_grant);
    assert!(
        approval.detail.starts_with("starts "),
        "{}",
        approval.detail
    );
    let decide = ControlRequest {
        passphrase: None,
        device: None,
        token: Some(token.clone()),
        command: ControlCommand::Decide {
            id: approval.id,
            verdict: Verdict::AllowSession,
        },
    };
    client::control(&paths, &decide, false).await.unwrap();
    assert_ne!(pending.await.unwrap().is_error, Some(true));
    call(&client, "stop_server", json!({"server": "prod"})).await;
    // The grant covers the next start: no approval is needed.
    let again = tokio::time::timeout(Duration::from_secs(20), peer.call_tool(reveal()))
        .await
        .expect("the second start waited for approval")
        .unwrap();
    assert_ne!(again.is_error, Some(true));
}
