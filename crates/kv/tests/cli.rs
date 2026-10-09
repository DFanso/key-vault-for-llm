//! End-to-end tests that drive the real `kv` binary against a daemon in a
//! temporary KV_HOME.

use std::io::Write;
#[cfg(unix)]
use std::path::PathBuf;
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use kv::frame::{read_frame, write_frame};
use kv::ipc;
use kv::paths::Paths;
use kv_core::proto::{AgentErrorCode, AgentResponse, ControlCommand, ControlRequest};
use kv_core::secret::SecretText;
use tempfile::TempDir;

const PASS: &str = "correct horse battery";
const TOKEN: &str = "sk-test-0123456789abcdef";

struct Kv {
    home: TempDir,
    daemon: Option<Child>,
}

impl Kv {
    /// A KV_HOME with no daemon running; commands start one on demand.
    fn new() -> Self {
        Self {
            home: TempDir::new().unwrap(),
            daemon: None,
        }
    }

    /// Starts `kv daemon` in the foreground with the given extra arguments
    /// and waits until it accepts connections.
    fn with_daemon(args: &[&str]) -> Self {
        let mut kv = Self::new();
        let child = kv
            .command(&[&["daemon"], args].concat())
            .stdin(Stdio::null())
            .spawn()
            .unwrap();
        kv.daemon = Some(child);
        kv.wait_until_listening();
        kv
    }

    fn initialized() -> Self {
        let kv = Self::with_daemon(&[]);
        kv.ok(&["init", "--insecure-fast-kdf"], &format!("{PASS}\n"));
        kv
    }

    fn paths(&self) -> Paths {
        Paths::under(self.home.path())
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_kv"));
        command.args(args).env("KV_HOME", self.home.path());
        command
    }

    fn run(&self, args: &[&str], stdin: &str) -> Output {
        run_kv(self.command(args), stdin)
    }

    fn ok(&self, args: &[&str], stdin: &str) -> String {
        let output = self.run(args, stdin);
        assert!(
            output.status.success(),
            "kv {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap()
    }

    fn fails(&self, args: &[&str], stdin: &str) -> String {
        let output = self.run(args, stdin);
        assert!(
            !output.status.success(),
            "kv {args:?} unexpectedly succeeded"
        );
        String::from_utf8(output.stderr).unwrap()
    }

    fn add_openrouter(&self) {
        self.ok(
            &[
                "add",
                "openrouter",
                "--kind",
                "http",
                "--host",
                "openrouter.ai",
                "--mode",
                "auto",
            ],
            &format!("{PASS}\n{TOKEN}\n"),
        );
    }

    fn wait_until_listening(&self) {
        let endpoint = self.paths().agent_endpoint();
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while runtime.block_on(ipc::connect(&endpoint)).is_err() {
            assert!(Instant::now() < deadline, "daemon did not start listening");
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    fn audit_log(&self) -> String {
        std::fs::read_to_string(self.home.path().join("audit.jsonl")).unwrap_or_default()
    }
}

impl Drop for Kv {
    fn drop(&mut self) {
        let _ = self.run(&["stop"], "");
        if let Some(mut child) = self.daemon.take()
            && wait_with_timeout(&mut child, Duration::from_secs(5)).is_none()
        {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn run_kv(mut command: Command, stdin: &str) -> Output {
    let mut child = command
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
    child.wait_with_output().unwrap()
}

fn wait_with_timeout(child: &mut Child, timeout: Duration) -> Option<std::process::ExitStatus> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait().unwrap() {
            return Some(status);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    None
}

#[test]
fn init_add_list_and_status() {
    let kv = Kv::initialized();
    kv.add_openrouter();
    let table = kv.ok(&["list"], "");
    assert!(table.contains("openrouter"), "{table}");
    assert!(table.contains("hosts=openrouter.ai"), "{table}");
    let json: serde_json::Value = serde_json::from_str(&kv.ok(&["list", "--json"], "")).unwrap();
    assert_eq!(json[0]["name"], "openrouter");
    assert_eq!(json[0]["mode"], "auto");
    let status = kv.ok(&["status"], "");
    assert!(status.starts_with("unlocked: 1 handle"), "{status}");
    for output in [table, json.to_string(), status] {
        assert!(!output.contains(TOKEN));
    }
}

#[test]
fn control_commands_need_the_right_passphrase() {
    let kv = Kv::initialized();
    let error = kv.fails(
        &[
            "add",
            "openrouter",
            "--kind",
            "http",
            "--host",
            "openrouter.ai",
        ],
        &format!("wrong horse battery\n{TOKEN}\n"),
    );
    assert!(error.contains("wrong passphrase"), "{error}");
    assert!(kv.ok(&["list"], "").contains("no handles yet"));
}

#[test]
fn lock_and_unlock() {
    let kv = Kv::initialized();
    kv.add_openrouter();
    kv.ok(&["lock"], "");
    let error = kv.fails(&["list"], "");
    assert!(error.contains("locked"), "{error}");
    assert!(kv.ok(&["status"], "").starts_with("locked"));
    kv.ok(&["unlock"], &format!("{PASS}\n"));
    assert!(kv.ok(&["list"], "").contains("openrouter"));
}

#[test]
fn wrong_passphrases_back_off() {
    let kv = Kv::initialized();
    kv.ok(&["lock"], "");
    for _ in 0..5 {
        let error = kv.fails(&["unlock"], "wrong horse battery\n");
        assert!(error.contains("wrong passphrase"), "{error}");
    }
    let error = kv.fails(&["unlock"], &format!("{PASS}\n"));
    assert!(error.contains("too many wrong passphrases"), "{error}");
}

#[test]
fn idle_vault_locks_itself() {
    let kv = Kv::with_daemon(&["--idle-lock", "1s"]);
    kv.ok(&["init", "--insecure-fast-kdf"], &format!("{PASS}\n"));
    std::thread::sleep(Duration::from_millis(2500));
    let status = kv.ok(&["status"], "");
    assert!(status.starts_with("locked"), "{status}");
}

#[test]
fn rm_policy_and_passwd() {
    let kv = Kv::initialized();
    kv.add_openrouter();
    kv.ok(
        &["policy", "openrouter", "--mode", "deny", "--method", "GET"],
        &format!("{PASS}\n"),
    );
    let json: serde_json::Value = serde_json::from_str(&kv.ok(&["list", "--json"], "")).unwrap();
    assert_eq!(json[0]["mode"], "deny");
    assert_eq!(json[0]["allowed_methods"][0], "GET");
    assert_eq!(json[0]["allowed_hosts"][0], "openrouter.ai");

    kv.ok(&["rm", "openrouter"], &format!("{PASS}\n"));
    assert!(kv.ok(&["list"], "").contains("no handles yet"));

    kv.ok(&["passwd"], &format!("{PASS}\na brand new passphrase\n"));
    kv.ok(&["lock"], "");
    assert!(
        kv.fails(&["unlock"], &format!("{PASS}\n"))
            .contains("wrong passphrase")
    );
    kv.ok(&["unlock"], "a brand new passphrase\n");
}

#[test]
fn add_prints_warnings_for_unusable_policies() {
    let kv = Kv::initialized();
    let output = kv.run(
        &["add", "loose", "--kind", "http"],
        &format!("{PASS}\n{TOKEN}\n"),
    );
    assert!(output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("warning: loose has no allowed hosts"),
        "{stderr}"
    );
}

#[test]
fn audit_log_has_actions_but_no_values() {
    let kv = Kv::initialized();
    kv.add_openrouter();
    kv.ok(&["list"], "");
    let log = kv.audit_log();
    assert!(log.contains(r#""action":"add""#), "{log}");
    assert!(log.contains(r#""action":"list_handles""#), "{log}");
    assert!(!log.contains(TOKEN), "{log}");
    assert!(!log.contains(PASS), "{log}");
}

#[test]
fn agent_socket_rejects_control_requests() {
    let kv = Kv::initialized();
    kv.ok(&["lock"], "");
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let response: AgentResponse = runtime.block_on(async {
        let mut stream = ipc::connect(&kv.paths().agent_endpoint()).await.unwrap();
        let request = ControlRequest {
            passphrase: Some(SecretText::new(PASS)),
            device: None,
            token: None,
            command: ControlCommand::Unlock,
        };
        write_frame(&mut stream, &request).await.unwrap();
        read_frame(&mut stream).await.unwrap().unwrap()
    });
    assert!(
        matches!(
            response,
            AgentResponse::Error {
                code: AgentErrorCode::BadRequest,
                ..
            }
        ),
        "{response:?}"
    );
    assert!(kv.ok(&["status"], "").starts_with("locked"));
}

#[test]
fn garbage_on_a_socket_does_not_take_the_daemon_down() {
    let kv = Kv::initialized();
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        use tokio::io::AsyncWriteExt;
        for endpoint in [kv.paths().agent_endpoint(), kv.paths().control_endpoint()] {
            let mut stream = ipc::connect(&endpoint).await.unwrap();
            stream.write_all(&[0xff, 0xff, 0xff, 0xff]).await.unwrap();
            // The daemon may already have rejected the oversized length and
            // closed the connection, so this write is allowed to fail.
            let _ = stream.write_all(b"not json at all").await;
            let mut half = ipc::connect(&endpoint).await.unwrap();
            half.write_all(&[0, 0, 0, 50, b'{']).await.unwrap();
            drop(half);
        }
    });
    assert!(kv.ok(&["status"], "").starts_with("unlocked"));
}

#[test]
fn commands_start_the_daemon_and_stop_ends_it() {
    let kv = Kv::new();
    let status = kv.ok(&["status"], "");
    assert!(status.contains("no vault yet"), "{status}");
    kv.ok(&["init", "--insecure-fast-kdf"], &format!("{PASS}\n"));
    kv.ok(&["stop"], "");
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while runtime
        .block_on(ipc::connect(&kv.paths().agent_endpoint()))
        .is_ok()
    {
        assert!(
            Instant::now() < deadline,
            "daemon still listening after stop"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn lock_and_stop_succeed_when_no_daemon_runs() {
    let kv = Kv::new();
    kv.ok(&["lock"], "");
    kv.ok(&["stop"], "");
}

#[test]
fn concurrent_commands_start_only_one_daemon() {
    let kv = Kv::new();
    let outputs: Vec<Output> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..4)
            .map(|_| scope.spawn(|| kv.run(&["status"], "")))
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });
    for output in outputs {
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    kv.ok(&["init", "--insecure-fast-kdf"], &format!("{PASS}\n"));
    assert!(kv.ok(&["status"], "").starts_with("unlocked"));
}

#[test]
fn a_second_daemon_exits_while_one_is_running() {
    let kv = Kv::with_daemon(&[]);
    let mut second = kv
        .command(&["daemon", "--autostart"])
        .stdin(Stdio::null())
        .spawn()
        .unwrap();
    let status = wait_with_timeout(&mut second, Duration::from_secs(5));
    assert!(status.is_some_and(|s| s.success()), "{status:?}");
    kv.ok(&["status"], "");
}

#[test]
fn kv_daemon_refuses_to_start_beside_a_running_daemon() {
    let kv = Kv::new();
    kv.ok(&["status"], "");
    let error = kv.fails(&["daemon", "--idle-lock", "2h"], "");
    assert!(error.contains("already running"), "{error}");
    assert!(error.contains("kv stop"), "{error}");
}

#[test]
fn kv_idle_lock_applies_to_daemons_started_on_demand() {
    let kv = Kv::new();
    let mut init = kv.command(&["init", "--insecure-fast-kdf"]);
    init.env("KV_IDLE_LOCK", "1s");
    let output = run_kv(init, &format!("{PASS}\n"));
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    std::thread::sleep(Duration::from_millis(2500));
    let status = kv.ok(&["status"], "");
    assert!(status.starts_with("locked"), "{status}");
}

#[cfg(unix)]
#[test]
fn stale_socket_files_from_a_crashed_daemon_are_replaced() {
    let kv = Kv::new();
    let paths = kv.paths();
    std::fs::create_dir_all(&paths.runtime).unwrap();
    for endpoint in [paths.agent_endpoint(), paths.control_endpoint()] {
        std::fs::write(&endpoint.path, b"left over").unwrap();
    }
    std::fs::write(paths.lock_file(), b"").unwrap();
    let status = kv.ok(&["status"], "");
    assert!(status.contains("no vault yet"), "{status}");
}

#[test]
fn passphrases_keep_every_character_but_the_line_ending() {
    let kv = Kv::with_daemon(&[]);
    let passphrase = "  pässwörd 🔑 with spaces  ";
    kv.ok(
        &["init", "--insecure-fast-kdf"],
        &format!("{passphrase}\r\n"),
    );
    kv.ok(&["lock"], "");
    let error = kv.fails(&["unlock"], &format!("{}\n", passphrase.trim()));
    assert!(error.contains("wrong passphrase"), "{error}");
    kv.ok(&["unlock"], &format!("{passphrase}\n"));
}

#[test]
fn missing_stdin_lines_fail_with_a_clear_message() {
    let kv = Kv::initialized();
    let error = kv.fails(
        &["add", "openrouter", "--kind", "http"],
        &format!("{PASS}\n"),
    );
    assert!(
        error.contains("stdin ended before: Token for openrouter"),
        "{error}"
    );
}

#[cfg(unix)]
#[test]
fn an_overlong_socket_path_fails_cleanly() {
    let base = TempDir::new().unwrap();
    let home: PathBuf = base.path().join("a".repeat(120));
    std::fs::create_dir_all(&home).unwrap();
    let output = run_kv(
        {
            let mut command = Command::new(env!("CARGO_BIN_EXE_kv"));
            command.args(["daemon"]).env("KV_HOME", &home);
            command
        },
        "",
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success());
    assert!(!stderr.contains("panicked"), "{stderr}");
    assert!(stderr.starts_with("kv: "), "{stderr}");
}

#[cfg(unix)]
#[test]
fn lock_fails_loudly_when_the_daemon_cannot_be_reached() {
    let base = TempDir::new().unwrap();
    let home: PathBuf = base.path().join("a".repeat(120));
    std::fs::create_dir_all(&home).unwrap();
    for args in [["lock"], ["stop"]] {
        let output = run_kv(
            {
                let mut command = Command::new(env!("CARGO_BIN_EXE_kv"));
                command.args(args).env("KV_HOME", &home);
                command
            },
            "",
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!output.status.success(), "{args:?} reported success");
        assert!(stderr.starts_with("kv: "), "{stderr}");
    }
}

#[test]
fn output_pipes_close_when_a_command_that_started_the_daemon_exits() {
    let kv = Kv::new();
    let mut child = kv
        .command(&["status"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdout = child.stdout.take().unwrap();
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut text = String::new();
        let _ = std::io::Read::read_to_string(&mut stdout, &mut text);
        let _ = sender.send(text);
    });
    let text = receiver
        .recv_timeout(Duration::from_secs(15))
        .expect("stdout stayed open after kv exited, so the daemon inherited it");
    assert!(text.contains("no vault yet"), "{text}");
    child.wait().unwrap();
}

#[test]
fn a_base_url_handle_lists_as_paths_only_without_its_address() {
    let kv = Kv::initialized();
    kv.ok(
        &[
            "add",
            "dokploy",
            "--kind",
            "http",
            "--base-url",
            "--header",
            "x-api-key",
            "--template",
            "{}",
        ],
        &format!("{PASS}\ndokploy-token-0123456789\n  https://dokploy.internal.example/api  \n"),
    );
    let list = kv.ok(&["list"], "");
    assert!(list.contains("paths-only"), "{list}");
    assert!(!list.contains("dokploy.internal"), "{list}");
    let json = kv.ok(&["list", "--json"], "");
    assert!(
        json.contains(r#""takes_path": true"#) || json.contains(r#""takes_path":true"#),
        "{json}"
    );
    assert!(!json.contains("dokploy.internal"), "{json}");
}
