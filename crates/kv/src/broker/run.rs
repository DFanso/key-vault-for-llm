//! `run`: starts a handle's `run` command with its variables set, in the
//! user's home directory, and relays its stdin, stdout and stderr over the
//! connection that asked, scrubbing what comes out. The program ends when
//! it exits, when the client goes away, when the vault locks or when the
//! handle changes.

use std::process::{ExitStatus, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use kv_core::policy::program_name;
use kv_core::proto::{AgentErrorCode, AgentResponse, MAX_RUN_CHUNK, RunInput, RunOutput};
use kv_core::scrub::Scrubber;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::process::{Child, ChildStdin, Command};
use tokio::sync::{mpsc, watch};

use super::RunJob;
use super::exec::resolve;
use super::lease::EndReason;
use super::process::{ProcessTree, isolate};
use crate::audit::Use;
use crate::frame::{read_frame, write_frame};

/// How long to wait for the output pipes once the program has ended and
/// anything it left running has been killed.
const DRAIN_GRACE: Duration = Duration::from_secs(2);

#[derive(Clone, Copy)]
enum Pipe {
    Stdout,
    Stderr,
}

enum End {
    Exited(Option<ExitStatus>),
    Ended(EndReason),
    ClientClosed,
}

/// Starts the program and relays it over `stream` until it ends. Records
/// the launch, or the refusal, and the end in the audit log.
pub async fn serve<S>(stream: S, job: RunJob)
where
    S: AsyncRead + AsyncWrite + Send + 'static,
{
    let (reader, mut writer) = tokio::io::split(stream);
    let program = program_name(&job.argv[0]);
    let (mut child, tree) = match launch(&job, &program) {
        Ok(started) => started,
        Err(response) => {
            let outcome = match &response {
                AgentResponse::Error { code, .. } => code.as_str(),
                _ => "error",
            };
            record(&job, &program, outcome, job.started.elapsed());
            let _ = write_frame(&mut writer, &response).await;
            return;
        }
    };
    record(&job, &program, "started", job.started.elapsed());
    let running = Instant::now();
    if write_frame(&mut writer, &AgentResponse::Started)
        .await
        .is_err()
    {
        tree.kill();
        let _ = child.wait().await;
        record(&job, &program, "client_closed", running.elapsed());
        return;
    }
    let cut = Arc::new(AtomicBool::new(false));
    let (queue, outbox) = mpsc::channel(16);
    let delivery = tokio::spawn(deliver(writer, outbox));
    let stdout = tokio::spawn(pump(
        child.stdout.take(),
        job.scrubber.clone(),
        queue.clone(),
        cut.clone(),
        Pipe::Stdout,
    ));
    let stderr = tokio::spawn(pump(
        child.stderr.take(),
        job.scrubber.clone(),
        queue.clone(),
        cut.clone(),
        Pipe::Stderr,
    ));
    let mut input = tokio::spawn(feed(reader, child.stdin.take()));
    let end = tokio::select! {
        status = child.wait() => End::Exited(status.ok()),
        reason = job.ticket.ended() => End::Ended(reason),
        _ = &mut input => End::ClientClosed,
    };
    // Output cut by a kill may end inside a secret, and so may output from
    // anything the program left running: the held-back tail is dropped.
    if !matches!(end, End::Exited(_)) || tree.running() {
        cut.store(true, Ordering::SeqCst);
    }
    tree.kill();
    let status = match &end {
        End::Exited(status) => *status,
        _ => child.wait().await.ok(),
    };
    input.abort();
    let (stdout_abort, stderr_abort) = (stdout.abort_handle(), stderr.abort_handle());
    let drained = tokio::time::timeout(DRAIN_GRACE, async {
        let _ = stdout.await;
        let _ = stderr.await;
    })
    .await;
    if drained.is_err() {
        stdout_abort.abort();
        stderr_abort.abort();
    }
    let (last, outcome) = match end {
        End::Exited(_) => {
            let (code, signal) = exit_parts(status);
            let outcome = match (code, signal) {
                (Some(code), _) => format!("exited:{code}"),
                (None, Some(signal)) => format!("signal:{signal}"),
                (None, None) => "exited".to_owned(),
            };
            (Some(RunOutput::Exited { code, signal }), outcome)
        }
        End::Ended(reason) => (
            Some(RunOutput::Ended {
                reason: reason.message().to_owned(),
            }),
            reason.outcome().to_owned(),
        ),
        End::ClientClosed => (None, "client_closed".to_owned()),
    };
    // Audited before the client hears of the end, as every request is
    // audited before its reply.
    record(&job, &program, &outcome, running.elapsed());
    if let Some(last) = last {
        let _ = queue.send(last).await;
    }
    drop(queue);
    let _ = delivery.await;
}

fn launch(job: &RunJob, program: &str) -> Result<(Child, ProcessTree), AgentResponse> {
    if job.ticket.has_ended() {
        return Err(error(
            AgentErrorCode::PolicyDenied,
            "the vault locked or the handle changed before the program started; try again",
        ));
    }
    let path = resolve(&job.argv[0], std::env::var_os("PATH").as_deref()).ok_or_else(|| {
        error(
            AgentErrorCode::UpstreamError,
            format!("{program} was not found, or is not a program kv can start"),
        )
    })?;
    let home = dirs::home_dir().ok_or_else(|| {
        error(
            AgentErrorCode::UpstreamError,
            "kv cannot find the home directory to start the program in",
        )
    })?;
    let mut command = Command::new(&path);
    command
        .args(&job.argv[1..])
        .current_dir(&home)
        .envs(job.env.iter().map(|(name, value)| (name, value.expose())))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    isolate(&mut command);
    let child = command.spawn().map_err(|e| {
        error(
            AgentErrorCode::UpstreamError,
            format!("could not start {program}: {e}"),
        )
    })?;
    let tree = ProcessTree::adopt(&child).map_err(|e| {
        error(
            AgentErrorCode::UpstreamError,
            format!("could not track {program}: {e}"),
        )
    })?;
    Ok((child, tree))
}

/// Passes what the client writes to the program until the client goes
/// away, which is when this returns.
async fn feed<R: AsyncRead + Unpin>(mut reader: R, mut stdin: Option<ChildStdin>) {
    loop {
        match read_frame::<_, RunInput>(&mut reader).await {
            Ok(Some(RunInput::Stdin { data })) => {
                if let Some(pipe) = &mut stdin
                    && pipe.write_all(&data).await.is_err()
                {
                    // The program closed its stdin; keep reading, so a client
                    // that goes away is still noticed.
                    stdin = None;
                }
            }
            Ok(Some(RunInput::CloseStdin)) => stdin = None,
            Ok(None) | Err(_) => return,
        }
    }
}

/// Reads one output pipe through the scrubber, following the scrubber as
/// secrets change, and queues it for the client.
async fn pump(
    reader: Option<impl AsyncRead + Unpin>,
    mut scrubber: watch::Receiver<Arc<Scrubber>>,
    queue: mpsc::Sender<RunOutput>,
    cut: Arc<AtomicBool>,
    pipe: Pipe,
) {
    let Some(mut reader) = reader else {
        return;
    };
    let mut held = Vec::new();
    let mut buffer = vec![0; MAX_RUN_CHUNK];
    loop {
        let n = match reader.read(&mut buffer).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        let current = scrubber.borrow_and_update().clone();
        let mut stream = current.resume(std::mem::take(&mut held));
        let scrubbed = stream.push(&buffer[..n]);
        held = stream.into_pending();
        if !send(&queue, pipe, scrubbed).await {
            return;
        }
    }
    if !cut.load(Ordering::SeqCst) {
        let current = scrubber.borrow().clone();
        let rest = current.resume(held).finish();
        send(&queue, pipe, rest).await;
    }
}

/// Queues `bytes` in frames of at most `MAX_RUN_CHUNK`. False once the
/// client is gone.
async fn send(queue: &mpsc::Sender<RunOutput>, pipe: Pipe, bytes: Vec<u8>) -> bool {
    for piece in bytes.chunks(MAX_RUN_CHUNK) {
        let data = piece.to_vec();
        let message = match pipe {
            Pipe::Stdout => RunOutput::Stdout { data },
            Pipe::Stderr => RunOutput::Stderr { data },
        };
        if queue.send(message).await.is_err() {
            return false;
        }
    }
    true
}

/// Writes queued output to the client, in order, until the queue closes or
/// the client goes away.
async fn deliver<W: AsyncWrite + Unpin>(mut writer: W, mut outbox: mpsc::Receiver<RunOutput>) {
    while let Some(message) = outbox.recv().await {
        if write_frame(&mut writer, &message).await.is_err() {
            return;
        }
    }
    let _ = writer.flush().await;
}

fn exit_parts(status: Option<ExitStatus>) -> (Option<i32>, Option<i32>) {
    let Some(status) = status else {
        return (None, None);
    };
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        (status.code(), status.signal())
    }
    #[cfg(not(unix))]
    {
        (status.code(), None)
    }
}

fn record(job: &RunJob, program: &str, outcome: &str, duration: Duration) {
    job.audit.record_use(&Use {
        action: "run",
        handle: &job.handle,
        decision: job.decision,
        summary: program,
        outcome,
        duration,
    });
}

fn error(code: AgentErrorCode, message: impl Into<String>) -> AgentResponse {
    AgentResponse::Error {
        code,
        message: message.into(),
    }
}
