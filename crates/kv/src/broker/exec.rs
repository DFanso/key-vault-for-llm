//! Runs an authorized program with the handles' variables injected and
//! returns its scrubbed output. Never uses a shell.

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use kv_core::proto::{AgentErrorCode, AgentResponse, ExecReply, MAX_OUTPUT_LEN};
use kv_core::scrub::Scrubber;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::Command;

use super::process::{ProcessTree, isolate};
use super::{ExecJob, capped_text};
use crate::audit::Use;

/// How long to wait for the output pipes once the program has ended and
/// anything it left running has been killed.
const DRAIN_GRACE: Duration = Duration::from_secs(2);

/// Runs the program and records it in the audit log.
pub async fn run(job: ExecJob) -> AgentResponse {
    let response = match execute(&job).await {
        Ok(response) => response,
        Err(response) => response,
    };
    let outcome = match &response {
        AgentResponse::Exec(reply) if reply.timed_out => "timed_out".to_owned(),
        AgentResponse::Exec(reply) => match reply.exit_code {
            Some(code) => format!("exit {code}"),
            None => "killed".to_owned(),
        },
        AgentResponse::Error { code, .. } => code.as_str().to_owned(),
        _ => "error".to_owned(),
    };
    job.audit.record_use(&Use {
        action: "exec",
        handle: &job.handles.join(","),
        decision: "auto",
        summary: &job.argv[0],
        outcome: &outcome,
        duration: job.started.elapsed(),
    });
    response
}

async fn execute(job: &ExecJob) -> Result<AgentResponse, AgentResponse> {
    let name = &job.argv[0];
    let cwd = job.cwd.clone();
    if !tokio::task::spawn_blocking(move || cwd.is_dir())
        .await
        .unwrap_or(false)
    {
        return Err(error(
            AgentErrorCode::BadRequest,
            "cwd must be an existing absolute directory",
        ));
    }
    let program = resolve(name, std::env::var_os("PATH").as_deref()).ok_or_else(|| {
        error(
            AgentErrorCode::BadRequest,
            format!("{name} was not found on the daemon's PATH"),
        )
    })?;
    let mut command = Command::new(&program);
    command
        .args(&job.argv[1..])
        .current_dir(&job.cwd)
        .envs(job.env.iter().map(|(name, value)| (name, value.expose())))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    isolate(&mut command);
    let mut child = command.spawn().map_err(|e| {
        error(
            AgentErrorCode::UpstreamError,
            format!("could not start {name}: {e}"),
        )
    })?;
    let tree = ProcessTree::adopt(&child).map_err(|e| {
        error(
            AgentErrorCode::UpstreamError,
            format!("could not track {name}: {e}"),
        )
    })?;
    let cut = Arc::new(AtomicBool::new(false));
    let stdout = tokio::spawn(capture(
        child.stdout.take(),
        job.scrubber.clone(),
        cut.clone(),
    ));
    let stderr = tokio::spawn(capture(
        child.stderr.take(),
        job.scrubber.clone(),
        cut.clone(),
    ));
    let (status, timed_out) = match tokio::time::timeout(job.timeout, child.wait()).await {
        Ok(status) => (status.ok(), false),
        Err(_) => {
            cut.store(true, Ordering::SeqCst);
            tree.kill();
            (child.wait().await.ok(), true)
        }
    };
    // Anything the program left running would keep the pipes open and could
    // still hold the secrets. Killing it cuts the output, so the held-back
    // tail, which may be part of a secret, is dropped.
    if tree.running() {
        cut.store(true, Ordering::SeqCst);
    }
    tree.kill();
    let (stdout, stdout_cut) = drain(stdout).await;
    let (stderr, stderr_cut) = drain(stderr).await;
    Ok(AgentResponse::Exec(ExecReply {
        exit_code: if timed_out {
            None
        } else {
            status.and_then(|s| s.code())
        },
        timed_out,
        stdout,
        stderr,
        truncated: stdout_cut || stderr_cut,
    }))
}

/// Reads one output stream through the scrubber. Keeps reading past the
/// cap, discarding, so the program never blocks on a full pipe.
async fn capture(
    reader: Option<impl AsyncRead + Unpin>,
    scrubber: Arc<Scrubber>,
    cut: Arc<AtomicBool>,
) -> (Vec<u8>, bool) {
    let Some(mut reader) = reader else {
        return (Vec::new(), false);
    };
    let mut stream = scrubber.stream();
    let mut out = Vec::new();
    let mut kept = 0;
    let mut truncated = false;
    let mut buffer = vec![0; 16 * 1024];
    loop {
        let n = match reader.read(&mut buffer).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        if truncated {
            continue;
        }
        let room = MAX_OUTPUT_LEN - kept;
        if n > room {
            out.extend(stream.push(&buffer[..room]));
            truncated = true;
        } else {
            kept += n;
            out.extend(stream.push(&buffer[..n]));
        }
    }
    // Output cut short, by the cap or by a kill, may end inside a secret, so
    // the held-back tail is dropped rather than flushed.
    if !truncated && !cut.load(Ordering::SeqCst) {
        out.extend(stream.finish());
    }
    (out, truncated)
}

async fn drain(task: tokio::task::JoinHandle<(Vec<u8>, bool)>) -> (String, bool) {
    match tokio::time::timeout(DRAIN_GRACE, task).await {
        Ok(Ok((bytes, truncated))) => {
            let (text, cut) = capped_text(&bytes);
            (text, truncated || cut)
        }
        _ => (String::new(), true),
    }
}

/// Finds the program to run. An absolute path is used as is. A bare name is
/// looked up in `path`, skipping empty and relative entries so the working
/// directory can never supply the program. On Windows a name without an
/// extension gets `.exe`.
pub fn resolve(program: &str, path: Option<&OsStr>) -> Option<PathBuf> {
    let given = Path::new(program);
    if given.is_absolute() {
        return is_executable(given).then(|| given.to_path_buf());
    }
    if program.contains('/') || (cfg!(windows) && program.contains('\\')) {
        return None;
    }
    let name: OsString = if cfg!(windows) && given.extension().is_none() {
        format!("{program}.exe").into()
    } else {
        program.into()
    };
    std::env::split_paths(path?)
        .filter(|dir| dir.is_absolute())
        .map(|dir| dir.join(&name))
        .find(|candidate| is_executable(candidate))
}

fn is_executable(path: &Path) -> bool {
    let Ok(metadata) = path.metadata() else {
        return false;
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.is_file() && metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        metadata.is_file()
    }
}

fn error(code: AgentErrorCode, message: impl Into<String>) -> AgentResponse {
    AgentResponse::Error {
        code,
        message: message.into(),
    }
}
