//! `exec` with a `file` handle end to end: the program reads the file kv
//! writes for it, byte for byte, and the file is gone afterwards. The
//! program is this test binary again, as in `exec.rs`.

mod common;

use std::io::Write;
use std::path::Path;

use common::*;
use kv::broker::exec::run;
use kv_core::policy::{Mode, Policy};
use kv_core::proto::{AgentErrorCode, AgentResponse, ExecCall, ExecReply};
use kv_core::secret::SecretValue;

const MODE_VAR: &str = "KV_EXEC_FILE_HELPER";

/// Not a real test: the program kv runs when `KV_EXEC_FILE_HELPER` is set.
/// It reads the file through the variable and through the last argument,
/// and says what it found.
#[test]
fn helper() {
    if std::env::var(MODE_VAR).is_err() {
        return;
    }
    let by_env = std::env::var("KV_FILE_PASSWORDS").unwrap_or_default();
    let by_arg = std::env::args().next_back().unwrap_or_default();
    let bytes = std::fs::read(&by_env).unwrap_or_default();
    let path = Path::new(&by_env);
    let mut out = std::io::stdout();
    // libtest has started a line with "test helper ... ".
    writeln!(out).unwrap();
    writeln!(out, "same_path={}", by_env == by_arg).unwrap();
    writeln!(
        out,
        "name={}",
        path.file_name().unwrap_or_default().to_string_lossy()
    )
    .unwrap();
    writeln!(
        out,
        "folder={}",
        path.parent().unwrap().parent().unwrap().display()
    )
    .unwrap();
    writeln!(out, "len={}", bytes.len()).unwrap();
    writeln!(
        out,
        "crlf={}",
        bytes.windows(2).filter(|w| w == b"\r\n").count()
    )
    .unwrap();
    writeln!(out, "last={}", bytes.last().copied().unwrap_or(0)).unwrap();
    writeln!(out, "text={}", String::from_utf8_lossy(&bytes)).unwrap();
    out.flush().unwrap();
    std::process::exit(0);
}

fn helper_args() -> Vec<String> {
    ["helper", "--exact", "--nocapture", "--test-threads=1"]
        .map(String::from)
        .to_vec()
}

fn fixture(bytes: &[u8]) -> (Fixture, ExecCall) {
    let mut f = Fixture::new();
    let exe = std::env::current_exe().unwrap();
    f.add(secret(
        "passwords",
        SecretValue::file("passwords.txt", bytes).unwrap(),
        Policy {
            mode: Mode::Auto,
            allowed_cmds: vec![exe.to_str().unwrap().to_owned()],
            ..Policy::default()
        },
    ));
    // The program learns the path from the variable; the placeholder in the
    // last argument has to be the same path.
    let mut argv = vec![exe.to_str().unwrap().to_owned()];
    argv.extend(helper_args());
    argv.push("{file:passwords}".into());
    let call = ExecCall {
        handles: vec!["passwords".into()],
        argv,
        cwd: f.dir.path().to_path_buf(),
        timeout_secs: None,
    };
    (f, call)
}

async fn exec(f: &mut Fixture, call: ExecCall) -> ExecReply {
    let mut job = f.exec(call).expect("authorized");
    // The helper only acts when this is set, which no handle sets.
    job.env
        .push((MODE_VAR.into(), kv_core::secret::SecretText::new("1")));
    match run(job).await {
        AgentResponse::Exec(reply) => reply,
        other => panic!("expected output, got {other:?}"),
    }
}

fn field<'a>(reply: &'a ExecReply, name: &str) -> &'a str {
    reply
        .stdout
        .lines()
        .find_map(|line| line.strip_prefix(&format!("{name}=")))
        .unwrap_or_else(|| panic!("no {name} in {}", reply.stdout))
}

#[tokio::test]
async fn a_program_reads_the_exact_file_and_it_is_removed_afterwards() {
    let bytes = "correct-horse-battery\r\nlonger-password-2\r\nxyz".as_bytes();
    let (mut f, call) = fixture(bytes);
    let reply = exec(&mut f, call).await;
    assert_eq!(reply.exit_code, Some(0), "{reply:?}");
    assert_eq!(field(&reply, "same_path"), "true");
    assert_eq!(field(&reply, "name"), "passwords.txt");
    assert_eq!(field(&reply, "len"), bytes.len().to_string());
    assert_eq!(field(&reply, "crlf"), "2");
    assert_eq!(field(&reply, "last"), b'z'.to_string());
    // What the program prints of the file's lines is scrubbed, and the
    // line too short to scrub is not.
    assert!(
        !reply.stdout.contains("correct-horse-battery"),
        "{}",
        reply.stdout
    );
    assert!(
        !reply.stdout.contains("longer-password-2"),
        "{}",
        reply.stdout
    );
    assert!(reply.stdout.contains("[kv:passwords]"), "{}", reply.stdout);
    // The folder kv made for the file is gone once the program has ended.
    assert!(!Path::new(field(&reply, "folder")).exists());
}

#[tokio::test]
async fn a_placeholder_for_a_handle_that_is_not_listed_is_refused() {
    let (mut f, mut call) = fixture(b"correct-horse-battery\n");
    call.argv.push("{file:other}".into());
    match f.exec(call) {
        Err((code, message)) => {
            assert_eq!(code, AgentErrorCode::BadRequest);
            assert!(message.contains("other"), "{message}");
        }
        Ok(_) => panic!("a placeholder for an unlisted handle went through"),
    }
}
