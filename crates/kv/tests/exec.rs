//! `exec` end to end. The program kv runs is this test binary itself: the
//! `helper` test below acts as a small tool when `KV_EXEC_HELPER` is set,
//! which kv injects through the env handle like any other variable.

mod common;

use std::io::Write;
use std::time::{Duration, Instant};

use common::*;
use kv::broker::exec::run;
use kv_core::policy::Mode;
use kv_core::proto::{AgentErrorCode, AgentResponse, ExecCall, ExecReply, MAX_OUTPUT_LEN};

const SECRET: &str = "s3cr3t-value-0123456789";
const MODE_VAR: &str = "KV_EXEC_HELPER";

/// Not a real test. Run by kv with `KV_EXEC_HELPER` set, it behaves as the
/// program under test and exits without letting the harness print more.
#[test]
fn helper() {
    let Ok(mode) = std::env::var(MODE_VAR) else {
        return;
    };
    let value = std::env::var("SECRET_VALUE").unwrap_or_default();
    let mut out = std::io::stdout();
    match mode.as_str() {
        "print" => {
            let hex: String = value.bytes().map(|b| format!("{b:02x}")).collect();
            writeln!(out, "raw={value}").unwrap();
            writeln!(out, "hex={hex}").unwrap();
            writeln!(out, "b64={}", base64(value.as_bytes())).unwrap();
            eprintln!("err={value}");
        }
        "exit" => std::process::exit(3),
        "big" => {
            let line = "x".repeat(1023);
            for _ in 0..(MAX_OUTPUT_LEN / 1024 + 64) {
                writeln!(out, "{line}").unwrap();
            }
        }
        "slow-secret" => {
            write!(out, "{}", &value[..4]).unwrap();
            out.flush().unwrap();
            std::thread::sleep(Duration::from_secs(30));
        }
        "spawn" => {
            let mut child = std::process::Command::new(std::env::current_exe().unwrap())
                .args(helper_args())
                .env(MODE_VAR, "sleep")
                .spawn()
                .unwrap();
            std::fs::write(std::env::var("PID_FILE").unwrap(), child.id().to_string()).unwrap();
            let _ = child.wait();
        }
        "sleep" => std::thread::sleep(Duration::from_secs(30)),
        "orphan" => {
            // Leaves a child holding part of the secret on stdout, then exits.
            #[expect(clippy::zombie_processes, reason = "the orphan is the point")]
            let _orphan = std::process::Command::new(std::env::current_exe().unwrap())
                .args(helper_args())
                .env(MODE_VAR, "slow-secret")
                .spawn()
                .unwrap();
            std::thread::sleep(Duration::from_millis(500));
        }
        other => panic!("unknown helper mode {other}"),
    }
    out.flush().unwrap();
    std::process::exit(0);
}

fn helper_args() -> Vec<String> {
    ["helper", "--exact", "--nocapture", "--test-threads=1"]
        .map(String::from)
        .to_vec()
}

fn base64(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(TABLE[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// A fixture whose `tool` handle runs this test binary in `mode`.
fn fixture(mode: &str, extra: &[(&str, &str)]) -> (Fixture, ExecCall) {
    let mut f = Fixture::new();
    let exe = std::env::current_exe().unwrap();
    let mut vars = vec![("SECRET_VALUE", SECRET), (MODE_VAR, mode)];
    vars.extend_from_slice(extra);
    f.add(env_secret(
        "tool",
        &vars,
        &[exe.to_str().unwrap()],
        Mode::Auto,
    ));
    let mut argv = vec![exe.to_str().unwrap().to_owned()];
    argv.extend(helper_args());
    let call = ExecCall {
        handles: vec!["tool".into()],
        argv,
        cwd: f.dir.path().to_path_buf(),
        timeout_secs: None,
    };
    (f, call)
}

async fn exec(f: &mut Fixture, call: ExecCall) -> ExecReply {
    let job = f.exec(call).expect("authorized");
    match run(job).await {
        AgentResponse::Exec(reply) => reply,
        other => panic!("expected output, got {other:?}"),
    }
}

#[tokio::test]
async fn injected_values_never_come_back_in_any_encoding() {
    let (mut f, call) = fixture("print", &[]);
    let reply = exec(&mut f, call).await;
    assert_eq!(reply.exit_code, Some(0), "{reply:?}");
    let hex: String = SECRET.bytes().map(|b| format!("{b:02x}")).collect();
    for output in [&reply.stdout, &reply.stderr] {
        assert!(!output.contains(SECRET), "{output}");
        assert!(!output.contains(&hex), "{output}");
        assert!(!output.contains(&base64(SECRET.as_bytes())), "{output}");
    }
    assert!(reply.stdout.contains("raw=[kv:tool]"), "{}", reply.stdout);
    assert!(reply.stderr.contains("err=[kv:tool]"), "{}", reply.stderr);
    let audit = f.audit_lines().pop().unwrap();
    assert_eq!(audit["action"], "exec");
    assert_eq!(audit["outcome"], "exit 0");
}

#[tokio::test]
async fn the_exit_code_is_reported() {
    let (mut f, call) = fixture("exit", &[]);
    let reply = exec(&mut f, call).await;
    assert_eq!((reply.exit_code, reply.timed_out), (Some(3), false));
}

#[tokio::test]
async fn long_output_is_cut_at_the_cap() {
    let (mut f, call) = fixture("big", &[]);
    let reply = exec(&mut f, call).await;
    assert!(reply.truncated);
    assert!(reply.stdout.len() <= MAX_OUTPUT_LEN);
    assert_eq!(reply.exit_code, Some(0));
}

#[tokio::test]
async fn a_timeout_kills_the_program_without_flushing_part_of_a_secret() {
    let (mut f, mut call) = fixture("slow-secret", &[]);
    call.timeout_secs = Some(1);
    let started = Instant::now();
    let reply = exec(&mut f, call).await;
    assert!(started.elapsed() < Duration::from_secs(10));
    assert!(reply.timed_out);
    assert_eq!(reply.exit_code, None);
    assert!(!reply.stdout.contains(&SECRET[..4]), "{}", reply.stdout);
}

#[cfg(unix)]
#[tokio::test]
async fn a_timeout_also_kills_what_the_program_started() {
    let pid_dir = tempfile::TempDir::new().unwrap();
    let pid_file = pid_dir.path().join("pid");
    let (mut f, mut call) = fixture("spawn", &[("PID_FILE", pid_file.to_str().unwrap())]);
    call.timeout_secs = Some(2);
    let reply = exec(&mut f, call).await;
    assert!(reply.timed_out);
    let pid: i32 = std::fs::read_to_string(&pid_file).unwrap().parse().unwrap();
    let pid = rustix::process::Pid::from_raw(pid).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while rustix::process::test_kill_process(pid).is_ok() {
        assert!(Instant::now() < deadline, "the grandchild is still running");
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[tokio::test]
async fn a_missing_program_is_a_bad_request() {
    let mut f = Fixture::new();
    f.add(env_secret(
        "tool",
        &[("SECRET_VALUE", SECRET)],
        &["kv-no-such-program"],
        Mode::Auto,
    ));
    let call = ExecCall {
        handles: vec!["tool".into()],
        argv: vec!["kv-no-such-program".into()],
        cwd: f.dir.path().to_path_buf(),
        timeout_secs: None,
    };
    let job = f.exec(call).unwrap();
    match run(job).await {
        AgentResponse::Error { message, .. } => {
            assert!(message.contains("not found"), "{message}")
        }
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn a_child_left_running_after_exit_cannot_leak_part_of_a_secret() {
    let (mut f, call) = fixture("orphan", &[]);
    let started = Instant::now();
    let reply = exec(&mut f, call).await;
    assert!(started.elapsed() < Duration::from_secs(10));
    assert_eq!((reply.exit_code, reply.timed_out), (Some(0), false));
    assert!(!reply.stdout.contains(&SECRET[..4]), "{}", reply.stdout);
}

#[tokio::test]
async fn a_missing_cwd_is_a_bad_request() {
    let (mut f, mut call) = fixture("print", &[]);
    call.cwd = f.dir.path().join("missing");
    let job = f.exec(call).expect("authorized");
    match run(job).await {
        AgentResponse::Error { code, message } => {
            assert_eq!(code, AgentErrorCode::BadRequest);
            assert!(message.contains("cwd"), "{message}");
        }
        other => panic!("{other:?}"),
    }
}
