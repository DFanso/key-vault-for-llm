//! `kv mcp` end to end: a real MCP client drives the `kv` binary, which
//! talks to a real daemon in a temporary `KV_HOME`.

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use rmcp::ServiceExt;
use rmcp::model::{CallToolRequestParams, CallToolResult, ContentBlock};
use rmcp::service::{RoleClient, RunningService};
use rmcp::transport::TokioChildProcess;
use tempfile::TempDir;
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, ResponseTemplate};

const PASS: &str = "correct horse battery";
const TOKEN: &str = "sk-or-v1-0123456789abcdef";
const SECRET: &str = "s3cr3t-value-0123456789";
const MODE_VAR: &str = "KV_MCP_HELPER";

/// Not a real test. Run through `exec` with `KV_MCP_HELPER` set, it prints
/// the injected secret and its working directory.
#[test]
fn helper() {
    if std::env::var(MODE_VAR).is_err() {
        return;
    }
    let mut out = std::io::stdout();
    writeln!(out, "secret={}", std::env::var("SECRET_VALUE").unwrap()).unwrap();
    writeln!(out, "cwd={}", std::env::current_dir().unwrap().display()).unwrap();
    out.flush().unwrap();
    std::process::exit(0);
}

struct Home {
    dir: TempDir,
}

impl Home {
    fn new() -> Self {
        Self {
            dir: TempDir::new().unwrap(),
        }
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

    async fn mcp(&self, cwd: &Path) -> RunningService<RoleClient, ()> {
        let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_kv"));
        command
            .arg("mcp")
            .env("KV_HOME", self.dir.path())
            .env("KV_NOTIFY", "off")
            .current_dir(cwd);
        ().serve(TokioChildProcess::new(command).unwrap())
            .await
            .unwrap()
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
    args: serde_json::Value,
) -> (bool, String) {
    let mut params = CallToolRequestParams::new(tool);
    if let serde_json::Value::Object(map) = args {
        params = params.with_arguments(map);
    }
    let result: CallToolResult = client.call_tool(params).await.unwrap();
    let text = result
        .content
        .iter()
        .filter_map(|block| match block {
            ContentBlock::Text(text) => Some(text.text.clone()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("\n");
    (result.is_error == Some(true), text)
}

fn helper_argv() -> Vec<String> {
    let exe = std::env::current_exe().unwrap();
    [
        exe.to_str().unwrap(),
        "helper",
        "--exact",
        "--nocapture",
        "--test-threads=1",
    ]
    .map(String::from)
    .to_vec()
}

#[tokio::test]
async fn an_agent_uses_handles_through_mcp_without_seeing_secrets() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string(format!("echo {TOKEN}")))
        .mount(&server)
        .await;
    let host = server.uri().trim_start_matches("http://").to_owned();
    let exe = std::env::current_exe().unwrap();

    let home = Home::new();
    home.kv(&["init", "--insecure-fast-kdf"], &format!("{PASS}\n"));
    home.kv(
        &[
            "add",
            "api",
            "--kind",
            "http",
            "--host",
            &host,
            "--allow-plain-http",
            "true",
            "--mode",
            "auto",
        ],
        &format!("{PASS}\n{TOKEN}\n"),
    );
    home.kv(
        &[
            "add",
            "tool",
            "--kind",
            "env",
            "--var",
            "SECRET_VALUE",
            "--var",
            MODE_VAR,
            "--cmd",
            exe.to_str().unwrap(),
            "--mode",
            "auto",
        ],
        &format!("{PASS}\n{SECRET}\nprint\n"),
    );

    let project = TempDir::new().unwrap();
    let client = home.mcp(project.path()).await;
    let tools: Vec<String> = client
        .list_all_tools()
        .await
        .unwrap()
        .into_iter()
        .map(|t| t.name.to_string())
        .collect();
    for name in ["list_handles", "status", "http_request", "exec"] {
        assert!(tools.contains(&name.to_owned()), "{tools:?}");
    }

    let (failed, handles) = call(&client, "list_handles", serde_json::json!({})).await;
    assert!(!failed, "{handles}");
    assert!(
        handles.contains("\"api\"") && handles.contains("\"tool\""),
        "{handles}"
    );
    assert!(
        !handles.contains(TOKEN) && !handles.contains(SECRET),
        "{handles}"
    );

    let (failed, reply) = call(
        &client,
        "http_request",
        serde_json::json!({"handle": "api", "method": "GET", "url": format!("{}/models", server.uri())}),
    )
    .await;
    assert!(!failed, "{reply}");
    assert!(reply.contains("echo [kv:api]"), "{reply}");
    assert!(!reply.contains(TOKEN), "{reply}");

    let (failed, output) = call(
        &client,
        "exec",
        serde_json::json!({"handles": ["tool"], "argv": helper_argv()}),
    )
    .await;
    assert!(!failed, "{output}");
    assert!(output.contains("secret=[kv:tool]"), "{output}");
    assert!(!output.contains(SECRET), "{output}");
    // Compare canonical paths: Windows may report a short 8.3 name
    // (RUNNER~1) and macOS a /var path that resolves to /private/var.
    let reply: serde_json::Value = serde_json::from_str(&output).unwrap();
    let reported = reply["stdout"]
        .as_str()
        .unwrap()
        .lines()
        .find_map(|line| line.strip_prefix("cwd="))
        .unwrap_or_else(|| panic!("no cwd line: {output}"));
    assert_eq!(
        Path::new(reported).canonicalize().unwrap(),
        project.path().canonicalize().unwrap(),
        "kv mcp's directory is the default cwd: {output}"
    );

    home.kv(&["lock"], "");
    let (failed, error) = call(
        &client,
        "http_request",
        serde_json::json!({"handle": "api", "method": "GET", "url": server.uri()}),
    )
    .await;
    assert!(failed);
    assert!(error.starts_with("vault_locked: "), "{error}");
    client.cancel().await.unwrap();
}

#[tokio::test]
async fn bad_arguments_are_tool_errors_not_crashes() {
    let home = Home::new();
    let project = TempDir::new().unwrap();
    let client = home.mcp(project.path()).await;
    let (failed, error) = call(&client, "http_request", serde_json::json!({"handle": "x"})).await;
    assert!(failed, "{error}");
    let (failed, status) = call(&client, "status", serde_json::json!({})).await;
    assert!(!failed, "{status}");
    assert!(status.contains("\"vault_exists\": false"), "{status}");
    client.cancel().await.unwrap();
}

#[tokio::test]
async fn an_ask_handle_waits_for_approval_and_shows_the_client() {
    use kv::paths::Paths;
    use kv_core::proto::{ControlCommand, ControlRequest, ControlResponse, Verdict};
    use kv_core::secret::SecretText;

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string("fine"))
        .mount(&server)
        .await;
    let host = server.uri().trim_start_matches("http://").to_owned();
    let home = Home::new();
    home.kv(&["init", "--insecure-fast-kdf"], &format!("{PASS}\n"));
    home.kv(
        &[
            "add",
            "api",
            "--kind",
            "http",
            "--host",
            &host,
            "--allow-plain-http",
            "true",
            "--mode",
            "ask",
        ],
        &format!("{PASS}\n{TOKEN}\n"),
    );
    let project = TempDir::new().unwrap();
    let client = home.mcp(project.path()).await;
    let url = format!("{}/x", server.uri());
    let call = tokio::spawn({
        let peer = client.peer().clone();
        async move {
            let params = CallToolRequestParams::new("http_request").with_arguments(
                serde_json::json!({"handle": "api", "method": "GET", "url": url})
                    .as_object()
                    .unwrap()
                    .clone(),
            );
            peer.call_tool(params).await.unwrap()
        }
    });

    let paths = Paths::under(home.dir.path());
    let control = |token: Option<SecretText>, passphrase: Option<&str>, command| {
        let request = ControlRequest {
            passphrase: passphrase.map(SecretText::new),
            device: None,
            token,
            command,
        };
        let paths = paths.clone();
        async move { kv::client::control(&paths, &request, false).await.unwrap() }
    };
    let token = match control(None, Some(PASS), ControlCommand::OpenSession).await {
        ControlResponse::Session { token } => token,
        other => panic!("{other:?}"),
    };
    let approval = loop {
        if let ControlResponse::Overview { overview } =
            control(Some(token.clone()), None, ControlCommand::Overview).await
            && let Some(approval) = overview.approvals.into_iter().next()
        {
            break approval;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    };
    assert!(
        approval.client.as_deref().is_some_and(|c| !c.is_empty()),
        "{approval:?}"
    );
    assert!(approval.can_grant, "kv mcp names its session");
    let decide = ControlCommand::Decide {
        id: approval.id,
        verdict: Verdict::AllowOnce,
    };
    control(Some(token), None, decide).await;
    let result = call.await.unwrap();
    assert_ne!(result.is_error, Some(true), "{result:?}");
    client.cancel().await.unwrap();
}

#[tokio::test]
async fn an_agent_asks_for_a_handle_it_does_not_have() {
    use kv::paths::Paths;
    use kv_core::proto::{ControlCommand, ControlRequest, ControlResponse};
    use kv_core::secret::{AuthPlacement, SecretText};

    let home = Home::new();
    home.kv(&["init", "--insecure-fast-kdf"], &format!("{PASS}\n"));
    let project = TempDir::new().unwrap();
    let client = home.mcp(project.path()).await;
    let (failed, text) = call(
        &client,
        "request_handle",
        serde_json::json!({
            "name": "dokploy",
            "kind": "http",
            "description": "KYC dev Dokploy",
            "reason": "to list Dokploy projects",
            "header": "x-api-key",
            "template": "{}",
            "base_url": true
        }),
    )
    .await;
    assert!(!failed, "{text}");
    assert!(text.contains("kv tui"), "{text}");

    let (failed, text) = call(
        &client,
        "request_handle",
        serde_json::json!({"name": "x", "kind": "http", "token": "sk-should-not-be-here"}),
    )
    .await;
    assert!(failed, "a value is refused: {text}");
    assert!(!text.contains("sk-should-not-be-here"), "{text}");

    let paths = Paths::under(home.dir.path());
    let send = |token: Option<SecretText>, passphrase: Option<&str>, command| {
        let request = ControlRequest {
            passphrase: passphrase.map(SecretText::new),
            device: None,
            token,
            command,
        };
        let paths = paths.clone();
        async move { kv::client::control(&paths, &request, false).await.unwrap() }
    };
    let token = match send(None, Some(PASS), ControlCommand::OpenSession).await {
        ControlResponse::Session { token } => token,
        other => panic!("{other:?}"),
    };
    let requests = match send(Some(token), None, ControlCommand::Overview).await {
        ControlResponse::Overview { overview } => overview.handle_requests,
        other => panic!("{other:?}"),
    };
    assert_eq!(requests.len(), 1, "{requests:?}");
    let request = &requests[0].request;
    assert_eq!(request.name, "dokploy");
    assert!(request.base_url);
    assert_eq!(
        request.auth,
        Some(AuthPlacement::Header {
            name: "x-api-key".into(),
            template: "{}".into(),
        })
    );
    assert!(requests[0].client.is_some());
    client.cancel().await.unwrap();
}

#[tokio::test]
async fn an_agent_queries_a_database_through_mcp() {
    let password = "pg-mcp-password-0123";
    let home = Home::new();
    home.kv(&["init", "--insecure-fast-kdf"], &format!("{PASS}\n"));
    // Port 1: nothing listens, so the query fails upstream.
    home.kv(
        &[
            "add",
            "pg",
            "--kind",
            "postgres",
            "--read-only",
            "true",
            "--mode",
            "auto",
        ],
        &format!("{PASS}\npostgres://app:{password}@127.0.0.1:1/app\n"),
    );
    let project = TempDir::new().unwrap();
    let client = home.mcp(project.path()).await;
    let tools: Vec<String> = client
        .list_all_tools()
        .await
        .unwrap()
        .into_iter()
        .map(|t| t.name.to_string())
        .collect();
    assert!(tools.contains(&"db_query".to_owned()), "{tools:?}");

    let (failed, text) = call(
        &client,
        "db_query",
        serde_json::json!({"handle": "pg", "query": "BEGIN READ WRITE"}),
    )
    .await;
    assert!(failed && text.starts_with("policy_denied"), "{text}");

    let (failed, text) = call(
        &client,
        "db_query",
        serde_json::json!({"handle": "pg", "query": "select 1", "timeout_secs": 5}),
    )
    .await;
    assert!(failed && text.starts_with("upstream_error"), "{text}");
    assert!(!text.contains(password), "{text}");
    client.cancel().await.unwrap();
}

#[tokio::test]
async fn an_agent_gets_a_database_lease_through_mcp() {
    let home = Home::new();
    home.kv(&["init", "--insecure-fast-kdf"], &format!("{PASS}\n"));
    home.kv(
        &["add", "cache", "--kind", "redis", "--mode", "auto"],
        &format!("{PASS}\nredis://:cache-password-0123@127.0.0.1:1/0\n"),
    );
    let project = TempDir::new().unwrap();
    let client = home.mcp(project.path()).await;
    let (failed, text) = call(
        &client,
        "db_connect",
        serde_json::json!({"handle": "cache", "ttl_secs": 60}),
    )
    .await;
    assert!(!failed, "{text}");
    let reply: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(reply["expires_in_secs"], 60);
    let url = url::Url::parse(reply["url"].as_str().unwrap()).unwrap();
    assert_eq!(url.host_str(), Some("127.0.0.1"));
    assert!(!text.contains("cache-password"), "{text}");

    // The daemon holds the lease, so it answers after this call returns.
    let mut socket = tokio::net::TcpStream::connect(("127.0.0.1", url.port().unwrap()))
        .await
        .unwrap();
    tokio::io::AsyncWriteExt::write_all(&mut socket, b"*1\r\n$4\r\nPING\r\n")
        .await
        .unwrap();
    let mut answer = [0u8; 6];
    tokio::io::AsyncReadExt::read_exact(&mut socket, &mut answer)
        .await
        .unwrap();
    assert_eq!(&answer, b"-NOAUT");
    client.cancel().await.unwrap();
}
