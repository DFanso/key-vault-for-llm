//! Accepts connections on the agent and control sockets and feeds requests
//! to `Daemon`.

use std::fs::{File, TryLockError};
use std::io;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant, SystemTime};

use kv_core::proto::{
    AgentErrorCode, AgentRequest, AgentResponse, ControlErrorCode, ControlRequest, ControlResponse,
    SessionInfo, Verdict,
};
use tokio::io::AsyncReadExt;
use tokio::sync::watch;

use super::harden;
use super::state::{After, Daemon, Prepared, Settings, Waiting};
use crate::audit::Audit;
use crate::broker;
use crate::frame::{read_frame, write_frame};
use crate::ipc::{self, ServerStream};
use crate::notify;
use crate::paths::Paths;

type Shared = Arc<Mutex<Daemon>>;

#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    Stopped,
    /// Another daemon holds the lock file; this one never started.
    AlreadyRunning,
}

/// Runs until `kv stop`, or until the daemon has been locked and idle for
/// `settings.locked_exit`. Returns immediately if another daemon already
/// holds the lock file.
pub async fn run(paths: Paths, settings: Settings) -> io::Result<Outcome> {
    harden::apply();
    paths.ensure_runtime_dir()?;
    let lock_file = File::options()
        .create(true)
        .truncate(false)
        .write(true)
        .open(paths.lock_file())?;
    match lock_file.try_lock() {
        Ok(()) => {}
        Err(TryLockError::WouldBlock) => return Ok(Outcome::AlreadyRunning),
        Err(TryLockError::Error(e)) => return Err(e),
    }

    let agent_endpoint = paths.agent_endpoint();
    let control_endpoint = paths.control_endpoint();
    let mut agent = ipc::bind(&agent_endpoint)?;
    let mut control = ipc::bind(&control_endpoint)?;

    let daemon: Shared = Arc::new(Mutex::new(Daemon::new(
        paths.vault.clone(),
        Audit::new(paths.audit.clone()),
        settings,
        Instant::now(),
    )));
    let http = broker::http::client().map_err(io::Error::other)?;
    let (stop_tx, mut stop_rx) = watch::channel(false);
    let check_every = (settings.idle_lock.min(settings.locked_exit) / 4)
        .clamp(Duration::from_millis(100), Duration::from_secs(30));
    let mut ticker = tokio::time::interval(check_every);

    loop {
        tokio::select! {
            accepted = agent.accept() => match accepted {
                Ok(stream) => {
                    tokio::spawn(serve_agent(stream, daemon.clone(), http.clone(), settings.notify));
                }
                Err(e) => accept_failed("agent", e).await,
            },
            accepted = control.accept() => match accepted {
                Ok(stream) => {
                    tokio::spawn(serve_control(stream, daemon.clone(), stop_tx.clone()));
                }
                Err(e) => accept_failed("control", e).await,
            },
            _ = ticker.tick() => {
                if lock(&daemon).tick(Instant::now(), SystemTime::now()) == After::Stop {
                    break;
                }
            }
            _ = stop_rx.changed() => break,
        }
    }

    ipc::cleanup(&agent_endpoint);
    ipc::cleanup(&control_endpoint);
    drop(lock_file);
    Ok(Outcome::Stopped)
}

async fn serve_agent(
    mut stream: ServerStream,
    daemon: Shared,
    http: reqwest::Client,
    notify: bool,
) {
    let mut session: Option<SessionInfo> = None;
    loop {
        let request: AgentRequest = match read_frame(&mut stream).await {
            Ok(Some(request)) => request,
            Ok(None) => return,
            Err(e) if e.kind() == io::ErrorKind::InvalidData => {
                let response = AgentResponse::Error {
                    code: AgentErrorCode::BadRequest,
                    message: format!("malformed request: {e}"),
                };
                let _ = write_frame(&mut stream, &response).await;
                return;
            }
            Err(_) => return,
        };
        if let AgentRequest::Hello(info) = request {
            if info.id.len() > 128 || info.client.len() > 1024 {
                let response = AgentResponse::Error {
                    code: AgentErrorCode::BadRequest,
                    message: "the session id or client name is too long".into(),
                };
                let _ = write_frame(&mut stream, &response).await;
                return;
            }
            session = Some(info);
            continue;
        }
        let shared = daemon.clone();
        let asking = session.clone();
        let prepared = tokio::task::spawn_blocking(move || {
            lock(&shared).prepare_in(asking.as_ref(), request, Instant::now())
        })
        .await;
        let Ok(prepared) = prepared else { return };
        let response = match prepared {
            Prepared::Wait(waiting) => {
                if notify {
                    notify::approval_needed(waiting.notice.clone());
                }
                match wait_then_run(&daemon, &http, &mut stream, *waiting).await {
                    Some(response) => response,
                    None => return,
                }
            }
            prepared => run_job(prepared, &http).await,
        };
        if write_frame(&mut stream, &response).await.is_err() {
            return;
        }
    }
}

async fn run_job(prepared: Prepared, http: &reqwest::Client) -> AgentResponse {
    match prepared {
        Prepared::Reply(response) => response,
        Prepared::Http(job) => broker::http::send(http, *job).await,
        Prepared::Exec(job) => broker::exec::run(*job).await,
        // `Waiting::then` is always a job; it never waits twice.
        Prepared::Wait(_) => AgentResponse::Error {
            code: AgentErrorCode::UpstreamError,
            message: "internal error: a request waited twice".into(),
        },
    }
}

/// Waits for the user's decision without holding the daemon lock, then runs
/// the job or explains why not. `None` when the agent hung up while it
/// waited: the request is withdrawn and nothing runs.
async fn wait_then_run(
    daemon: &Shared,
    http: &reqwest::Client,
    stream: &mut ServerStream,
    waiting: Waiting,
) -> Option<AgentResponse> {
    let Waiting {
        id,
        mut verdict,
        then,
        wait,
        ..
    } = waiting;
    // The agent sends nothing until it has its reply, so any read that
    // returns means it closed the connection (or broke the protocol).
    let mut byte = [0u8; 1];
    let decided = tokio::select! {
        waited = tokio::time::timeout(wait, &mut verdict) => match waited {
            Ok(decided) => decided.ok(),
            Err(_) => {
                let shared = daemon.clone();
                let expired = tokio::task::spawn_blocking(move || {
                    lock(&shared).expire(id, Instant::now())
                })
                .await;
                if let Ok(Some(response)) = expired {
                    return Some(response);
                }
                // Decided, or locked, just as the wait ran out.
                verdict.try_recv().ok()
            }
        },
        _ = stream.read(&mut byte) => {
            let shared = daemon.clone();
            let _ = tokio::task::spawn_blocking(move || {
                lock(&shared).withdraw(id, Instant::now())
            })
            .await;
            return None;
        }
    };
    Some(match decided {
        Some(Verdict::AllowOnce | Verdict::AllowSession) => run_job(then, http).await,
        Some(Verdict::Deny | Verdict::DenyAlways) => AgentResponse::Error {
            code: AgentErrorCode::ApprovalDenied,
            message: "the user denied the request".into(),
        },
        None => AgentResponse::Error {
            code: AgentErrorCode::VaultLocked,
            message:
                "the vault was locked before the request was approved; ask the user to unlock it"
                    .into(),
        },
    })
}

async fn serve_control(mut stream: ServerStream, daemon: Shared, stop: watch::Sender<bool>) {
    loop {
        let request: ControlRequest = match read_frame(&mut stream).await {
            Ok(Some(request)) => request,
            Ok(None) => return,
            Err(e) if e.kind() == io::ErrorKind::InvalidData => {
                // No detail: the parse error could quote part of the request,
                // which may contain the passphrase.
                let response = ControlResponse::Error {
                    code: ControlErrorCode::BadRequest,
                    message: "malformed request".into(),
                };
                let _ = write_frame(&mut stream, &response).await;
                return;
            }
            Err(_) => return,
        };
        let daemon = daemon.clone();
        // Argon2 takes a noticeable fraction of a second, so it runs off the
        // async worker threads.
        let handled = tokio::task::spawn_blocking(move || {
            lock(&daemon).handle_control(request, Instant::now())
        })
        .await;
        let Ok((response, after)) = handled else {
            return;
        };
        let written = write_frame(&mut stream, &response).await;
        if after == After::Stop {
            let _ = stop.send(true);
            return;
        }
        if written.is_err() {
            return;
        }
    }
}

async fn accept_failed(socket: &str, error: io::Error) {
    eprintln!("kv daemon: accepting on the {socket} socket failed: {error}");
    tokio::time::sleep(Duration::from_millis(100)).await;
}

fn lock(daemon: &Shared) -> MutexGuard<'_, Daemon> {
    daemon.lock().unwrap_or_else(PoisonError::into_inner)
}
