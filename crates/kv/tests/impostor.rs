//! A process that is not kv listening where the daemon's control socket
//! should be gets nothing secret from kv's clients: no passphrase, session
//! token, device key or secret value, whichever client is asking (the CLI,
//! `kv tui` and `kv tray` through the TUI driver).
//!
//! The impostor is a copy of this test binary, run from another path, so to
//! the client it is a different program, as any other program would be.
//! It records every request it reads and answers each with `done`.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use kv::client;
use kv::frame::{read_frame, write_frame};
use kv::paths::Paths;
use kv::tui::Driver;
use kv::tui::app::{App, Effect, Screen};
use kv_core::proto::{ControlCommand, ControlRequest, ControlResponse, DeviceCredential};
use kv_core::secret::{AuthPlacement, Secret, SecretText, SecretValue};
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use tempfile::TempDir;

const HOME_ENV: &str = "KV_TEST_IMPOSTOR_HOME";
const LOG_ENV: &str = "KV_TEST_IMPOSTOR_LOG";
const PASS: &str = "impostor-test passphrase 7f3a";
const TOKEN: &str = "impostor-test session token 91c2";
const DEVICE_KEY: &str = "impostor-test device key 5be0";
const VALUE: &str = "sk-impostor-test-value-0d4e";

/// The impostor itself. Does nothing unless another test started it.
#[test]
#[ignore = "started by the other tests, from a copy of this binary"]
fn impostor_daemon() {
    let (Some(home), Some(log)) = (std::env::var_os(HOME_ENV), std::env::var_os(LOG_ENV)) else {
        return;
    };
    let paths = Paths::under(Path::new(&home));
    let log = PathBuf::from(log);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async move {
        paths.ensure_runtime_dir().unwrap();
        let mut listener = kv::ipc::bind(&paths.control_endpoint()).unwrap();
        std::fs::write(ready_file(&log), b"").unwrap();
        loop {
            let mut stream = listener.accept().await.unwrap();
            while let Ok(Some(request)) = read_frame::<_, serde_json::Value>(&mut stream).await {
                let mut line = request.to_string();
                line.push('\n');
                use std::io::Write;
                let mut file = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&log)
                    .unwrap();
                file.write_all(line.as_bytes()).unwrap();
                let done = ControlResponse::Done {
                    warnings: Vec::new(),
                };
                if write_frame(&mut stream, &done).await.is_err() {
                    break;
                }
            }
        }
    });
}

fn ready_file(log: &Path) -> PathBuf {
    log.with_extension("ready")
}

/// The copy of this test binary every impostor runs, made once. It lives
/// until the test process ends, in a folder of its own.
fn impostor_program() -> &'static Path {
    static COPY: OnceLock<(TempDir, PathBuf)> = OnceLock::new();
    &COPY
        .get_or_init(|| {
            let bin = TempDir::new().unwrap();
            let copy = bin
                .path()
                .join(format!("not-kv{}", std::env::consts::EXE_SUFFIX));
            std::fs::copy(std::env::current_exe().unwrap(), &copy).unwrap();
            (bin, copy)
        })
        .1
}

/// A running impostor at the control socket of a fresh `KV_HOME`.
struct Impostor {
    child: Child,
    home: TempDir,
    _log_dir: TempDir,
    log: PathBuf,
}

impl Impostor {
    fn start() -> Self {
        let home = TempDir::new().unwrap();
        let log_dir = TempDir::new().unwrap();
        let log = log_dir.path().join("received.jsonl");
        let mut command = Command::new(impostor_program());
        command
            .args([
                "impostor_daemon",
                "--exact",
                "--ignored",
                "--test-threads=1",
            ])
            .env(HOME_ENV, home.path())
            .env(LOG_ENV, &log)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        // On Linux, a child another test thread forks while the copy is
        // still open for writing holds it open until that child execs, and
        // until then the copy cannot be run ("text file busy").
        let mut tries = 0;
        let child = loop {
            match command.spawn() {
                Err(e) if e.kind() == std::io::ErrorKind::ExecutableFileBusy && tries < 50 => {
                    tries += 1;
                    std::thread::sleep(Duration::from_millis(20));
                }
                result => break result.unwrap(),
            }
        };
        let deadline = Instant::now() + Duration::from_secs(10);
        while !ready_file(&log).exists() {
            assert!(Instant::now() < deadline, "the impostor did not start");
            std::thread::sleep(Duration::from_millis(20));
        }
        Self {
            child,
            home,
            _log_dir: log_dir,
            log,
        }
    }

    fn paths(&self) -> Paths {
        Paths::under(self.home.path())
    }

    /// Everything the impostor was sent.
    fn received(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }

    fn assert_got_nothing_secret(&self) {
        let received = self.received();
        for secret in [PASS, TOKEN, DEVICE_KEY, VALUE] {
            assert!(
                !received.contains(secret),
                "the impostor received {secret:?}: {received}"
            );
        }
    }
}

impl Drop for Impostor {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn request(
    passphrase: Option<&str>,
    device: Option<&str>,
    token: Option<&str>,
    command: ControlCommand,
) -> ControlRequest {
    ControlRequest {
        passphrase: passphrase.map(SecretText::new),
        device: device.map(|key| DeviceCredential {
            id: "kv-device".into(),
            key: SecretText::new(key),
        }),
        token: token.map(SecretText::new),
        command,
    }
}

fn add_command() -> ControlCommand {
    ControlCommand::Add {
        secret: Secret {
            name: "api".into(),
            description: String::new(),
            value: SecretValue::Http {
                token: SecretText::new(VALUE),
                placement: AuthPlacement::Header {
                    name: "Authorization".into(),
                    template: "Bearer {}".into(),
                },
                base_url: None,
            },
            policy: Default::default(),
            created_at: 0,
            updated_at: 0,
            from_share: None,
        },
        replace: false,
    }
}

fn assert_refused<T: std::fmt::Debug>(result: std::io::Result<T>) {
    match result {
        Err(e) => {
            assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied, "{e}");
            assert!(e.to_string().contains("not this kv"), "{e}");
        }
        Ok(reply) => panic!("the client talked to the impostor: {reply:?}"),
    }
}

#[tokio::test]
async fn the_passphrase_is_not_sent_to_an_impostor() {
    let impostor = Impostor::start();
    let unlock = request(Some(PASS), None, None, ControlCommand::Unlock);
    assert_refused(client::control(&impostor.paths(), &unlock, false).await);
    assert_refused(client::control(&impostor.paths(), &unlock, true).await);
    let session = request(Some(PASS), None, None, ControlCommand::OpenSession);
    assert_refused(client::control_if_running(&impostor.paths(), &session).await);
    impostor.assert_got_nothing_secret();
    assert_eq!(impostor.received(), "", "nothing at all was sent");
}

#[tokio::test]
async fn a_session_token_is_not_sent_to_an_impostor() {
    let impostor = Impostor::start();
    let overview = request(None, None, Some(TOKEN), ControlCommand::Overview);
    assert_refused(client::control_if_running(&impostor.paths(), &overview).await);
    assert_refused(client::control(&impostor.paths(), &overview, false).await);
    impostor.assert_got_nothing_secret();
}

#[tokio::test]
async fn a_device_key_is_not_sent_to_an_impostor_on_any_path() {
    let impostor = Impostor::start();
    // `kv tui` sends a device key with its session to reveal a value, on the
    // path that does not start the daemon.
    let reveal = request(
        None,
        Some(DEVICE_KEY),
        Some(TOKEN),
        ControlCommand::RevealHandle {
            handle: "api".into(),
        },
    );
    assert_refused(client::control_if_running(&impostor.paths(), &reveal).await);
    let unlock = request(None, Some(DEVICE_KEY), None, ControlCommand::Unlock);
    assert_refused(client::control(&impostor.paths(), &unlock, false).await);
    impostor.assert_got_nothing_secret();
}

#[tokio::test]
async fn a_secret_value_is_not_sent_to_an_impostor() {
    let impostor = Impostor::start();
    let add = request(Some(PASS), None, None, add_command());
    assert_refused(client::control(&impostor.paths(), &add, false).await);
    let add = request(None, None, Some(TOKEN), add_command());
    assert_refused(client::control_if_running(&impostor.paths(), &add).await);
    impostor.assert_got_nothing_secret();
}

#[tokio::test]
async fn lock_and_stop_still_reach_whatever_holds_the_socket() {
    // They carry nothing secret, and `kv stop` must still end an older kv
    // daemon left running from a binary that has since been replaced.
    let impostor = Impostor::start();
    for command in [ControlCommand::Lock, ControlCommand::Stop] {
        let reply =
            client::control_if_running(&impostor.paths(), &request(None, None, None, command))
                .await
                .unwrap();
        assert!(
            matches!(reply, Some(ControlResponse::Done { .. })),
            "{reply:?}"
        );
    }
    impostor.assert_got_nothing_secret();
    assert_eq!(impostor.received().lines().count(), 2);
}

#[tokio::test]
async fn lock_with_a_credential_is_not_sent_to_an_impostor() {
    let impostor = Impostor::start();
    let lock = request(None, None, Some(TOKEN), ControlCommand::Lock);
    assert_refused(client::control_if_running(&impostor.paths(), &lock).await);
    impostor.assert_got_nothing_secret();
}

#[tokio::test]
async fn kv_tui_does_not_send_the_passphrase_to_an_impostor() {
    let impostor = Impostor::start();
    let mut driver = Driver::new(impostor.paths());
    let mut app = App::new();
    let mut keys: Vec<KeyCode> = PASS.chars().map(KeyCode::Char).collect();
    keys.push(KeyCode::Enter);
    for code in keys {
        let effect: Option<Effect> = app.handle_key(KeyEvent::new(code, KeyModifiers::NONE));
        if let Some(effect) = effect {
            let outcome = driver.run(effect).await;
            app.apply(outcome);
        }
    }
    assert_ne!(app.screen(), Screen::Main, "the tui must not unlock");
    impostor.assert_got_nothing_secret();
    assert_eq!(impostor.received(), "");
}

#[test]
fn kv_unlock_does_not_send_the_passphrase_to_an_impostor() {
    let impostor = Impostor::start();
    let mut child = Command::new(env!("CARGO_BIN_EXE_kv"))
        .arg("unlock")
        .env("KV_HOME", impostor.home.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    {
        use std::io::Write;
        let mut stdin = child.stdin.take().unwrap();
        stdin.write_all(format!("{PASS}\n").as_bytes()).unwrap();
    }
    let output = child.wait_with_output().unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "kv unlock succeeded: {stderr}");
    assert!(stderr.contains("not this kv"), "{stderr}");
    impostor.assert_got_nothing_secret();
    assert_eq!(impostor.received(), "");
}
