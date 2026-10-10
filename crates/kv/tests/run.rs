//! Programs started through `run`, end to end: a daemon in this process,
//! reached through its real sockets, starts this test binary, whose
//! `helper` test acts as the program when `KV_RUN_HELPER` is set.

mod common;
mod live;

use std::io::{BufRead, Write};
use std::time::{Duration, Instant};

use kv::client::{self, RunEnd, RunStream};
use kv_core::policy::Mode;
use kv_core::proto::{AgentErrorCode, AgentResponse, ControlCommand, SessionInfo, Verdict};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

const SECRET: &str = "s3cr3t-run-value-0123456789";
const MODE_VAR: &str = "KV_RUN_HELPER";

/// Not a real test. Started by kv with `KV_RUN_HELPER` set, it behaves as
/// the program under test and exits without letting the harness print more.
#[test]
fn helper() {
    let Ok(mode) = std::env::var(MODE_VAR) else {
        return;
    };
    let secret = std::env::var("SECRET_VALUE").unwrap_or_default();
    let mut out = std::io::stdout();
    match mode.as_str() {
        // One reply per line, then exit 3 at end of input.
        "echo" => {
            for line in std::io::stdin().lock().lines() {
                writeln!(out, "got {} secret={secret}", line.unwrap()).unwrap();
                out.flush().unwrap();
            }
            std::process::exit(3);
        }
        // More than a frame's worth in one write.
        "big" => {
            let mut text = "x".repeat(1 << 20);
            text.push_str(&format!(" secret={secret}\n"));
            out.write_all(text.as_bytes()).unwrap();
            out.flush().unwrap();
            std::process::exit(0);
        }
        "sleep" => {
            writeln!(out, "ready pid={} end", std::process::id()).unwrap();
            out.flush().unwrap();
            std::thread::sleep(Duration::from_secs(60));
            std::process::exit(0);
        }
        #[cfg(unix)]
        "signal" => {
            writeln!(out, "ready").unwrap();
            out.flush().unwrap();
            let me = rustix::process::getpid();
            let _ = rustix::process::kill_process(me, rustix::process::Signal::TERM);
            std::thread::sleep(Duration::from_secs(60));
            std::process::exit(0);
        }
        other => panic!("unknown helper mode {other}"),
    }
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

async fn add_server(daemon: &live::Daemon, name: &str, mode: &str, policy_mode: Mode) {
    let argv = helper_argv();
    let argv: Vec<&str> = argv.iter().map(String::as_str).collect();
    let secret = common::run_secret(
        name,
        &[("SECRET_VALUE", SECRET), (MODE_VAR, mode)],
        &argv,
        policy_mode,
    );
    daemon
        .control(
            Some(live::PASS),
            ControlCommand::Add {
                secret,
                replace: false,
            },
        )
        .await;
}

async fn start(daemon: &live::Daemon, name: &str) -> RunStream {
    match client::run_stream(&daemon.paths, None, name).await.unwrap() {
        Ok(stream) => stream,
        Err(refusal) => panic!("refused: {refusal:?}"),
    }
}

/// Reads until `text` appears, without sending anything more.
async fn read_until(stdout: &mut (impl AsyncRead + Unpin), text: &str) -> String {
    let mut seen = Vec::new();
    let mut buffer = [0u8; 4096];
    tokio::time::timeout(Duration::from_secs(20), async {
        while !String::from_utf8_lossy(&seen).contains(text) {
            let n = stdout.read(&mut buffer).await.unwrap();
            assert!(
                n > 0,
                "output ended before {text:?}: {}",
                String::from_utf8_lossy(&seen)
            );
            seen.extend_from_slice(&buffer[..n]);
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timed out waiting for {text:?}"));
    String::from_utf8_lossy(&seen).into_owned()
}

fn audit_has(daemon: &live::Daemon, outcome: &str) -> bool {
    std::fs::read_to_string(&daemon.paths.audit)
        .unwrap_or_default()
        .lines()
        .any(|line| line.contains("\"action\":\"run\"") && line.contains(outcome))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn output_is_scrubbed_and_each_reply_arrives_at_once() {
    let daemon = live::Daemon::start().await;
    add_server(&daemon, "echo", "echo", Mode::Auto).await;
    let mut run = start(&daemon, "echo").await;
    run.stdin.write_all(b"hello\n").await.unwrap();
    // The whole reply arrives while the program waits for more input.
    let seen = read_until(&mut run.stdout, "got hello secret=[kv:echo]\n").await;
    assert!(!seen.contains(SECRET), "{seen}");
    run.stdin.write_all(b"again\n").await.unwrap();
    read_until(&mut run.stdout, "got again").await;
    run.stdin.shutdown().await.unwrap();
    let end = tokio::time::timeout(Duration::from_secs(20), run.ended)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        end,
        RunEnd::Exited {
            code: Some(3),
            signal: None
        }
    );
    assert!(audit_has(&daemon, "exited:3"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_large_write_arrives_whole_and_scrubbed() {
    let daemon = live::Daemon::start().await;
    add_server(&daemon, "big", "big", Mode::Auto).await;
    let mut run = start(&daemon, "big").await;
    let mut all = String::new();
    tokio::time::timeout(Duration::from_secs(30), run.stdout.read_to_string(&mut all))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(all.matches('x').count(), 1 << 20);
    assert!(all.contains("secret=[kv:big]"));
    assert!(!all.contains(SECRET));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn locking_ends_the_program() {
    let daemon = live::Daemon::start().await;
    add_server(&daemon, "sleeper", "sleep", Mode::Auto).await;
    let mut run = start(&daemon, "sleeper").await;
    read_until(&mut run.stdout, "ready").await;
    daemon.control(None, ControlCommand::Lock).await;
    let end = tokio::time::timeout(Duration::from_secs(20), run.ended)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(end, RunEnd::Ended("the vault locked".into()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn changing_the_handle_ends_the_program() {
    let daemon = live::Daemon::start().await;
    add_server(&daemon, "sleeper", "sleep", Mode::Auto).await;
    let mut run = start(&daemon, "sleeper").await;
    read_until(&mut run.stdout, "ready").await;
    daemon
        .control(
            Some(live::PASS),
            ControlCommand::SetPolicy {
                name: "sleeper".into(),
                patch: kv_core::proto::PolicyPatch {
                    grant_ttl: Some(Duration::from_secs(60)),
                    ..Default::default()
                },
            },
        )
        .await;
    let end = tokio::time::timeout(Duration::from_secs(20), run.ended)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(end, RunEnd::Ended("the handle changed".into()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn disconnecting_kills_the_program() {
    let daemon = live::Daemon::start().await;
    add_server(&daemon, "sleeper", "sleep", Mode::Auto).await;
    let mut run = start(&daemon, "sleeper").await;
    let seen = read_until(&mut run.stdout, " end").await;
    let pid: i32 = seen
        .split("pid=")
        .nth(1)
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .parse()
        .unwrap();
    drop(run);
    let deadline = Instant::now() + Duration::from_secs(20);
    while !audit_has(&daemon, "client_closed") {
        assert!(Instant::now() < deadline, "the run was not ended");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    #[cfg(unix)]
    {
        let pid = rustix::process::Pid::from_raw(pid).unwrap();
        while rustix::process::test_kill_process(pid).is_ok() {
            assert!(Instant::now() < deadline, "the program is still running");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
    let _ = pid;
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_signal_is_reported() {
    let daemon = live::Daemon::start().await;
    add_server(&daemon, "signal", "signal", Mode::Auto).await;
    let run = start(&daemon, "signal").await;
    let end = tokio::time::timeout(Duration::from_secs(20), run.ended)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        end,
        RunEnd::Exited {
            code: None,
            signal: Some(15)
        }
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_missing_program_is_refused_without_its_arguments() {
    let daemon = live::Daemon::start().await;
    let secret = common::run_secret(
        "missing",
        &[("SECRET_VALUE", SECRET)],
        &["/nonexistent-kv-test/tool", "--host=10.9.8.7"],
        Mode::Auto,
    );
    daemon
        .control(
            Some(live::PASS),
            ControlCommand::Add {
                secret,
                replace: false,
            },
        )
        .await;
    match client::run_stream(&daemon.paths, None, "missing")
        .await
        .unwrap()
    {
        Err(AgentResponse::Error { code, message }) => {
            assert_eq!(code, AgentErrorCode::UpstreamError);
            assert!(message.contains("tool"), "{message}");
            assert!(!message.contains("10.9.8.7"), "{message}");
            assert!(!message.contains("nonexistent"), "{message}");
        }
        Ok(_) => panic!("a missing program started"),
        Err(other) => panic!("unexpected reply {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_ask_server_starts_once_approved() {
    let daemon = live::Daemon::start().await;
    add_server(&daemon, "asker", "echo", Mode::Ask).await;
    let paths = daemon.paths.clone();
    let pending = tokio::spawn(async move {
        let session = SessionInfo {
            id: "session-1".into(),
            client: "approval test".into(),
        };
        client::run_stream(&paths, Some(&session), "asker")
            .await
            .unwrap()
    });
    let id = daemon.waiting_id().await;
    daemon
        .with_token(ControlCommand::Decide {
            id,
            verdict: Verdict::AllowOnce,
        })
        .await;
    let Ok(mut run) = pending.await.unwrap() else {
        panic!("the approved run was refused");
    };
    run.stdin.write_all(b"hi\n").await.unwrap();
    read_until(&mut run.stdout, "got hi").await;
}
