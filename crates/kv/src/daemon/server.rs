//! Accepts connections on the agent and control sockets and feeds requests
//! to `Daemon`.

use std::fs::{File, TryLockError};
use std::io;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant, SystemTime};

use kv_core::proto::{
    AgentErrorCode, AgentRequest, AgentResponse, ControlErrorCode, ControlRequest, ControlResponse,
    NoticeKind, SessionInfo, Verdict,
};
use tokio::io::AsyncReadExt;
use tokio::sync::{Semaphore, watch};

use super::harden;
use super::notices::Plain;
use super::state::{After, Daemon, Prepared, Settings, Waiting, locked_tool};
use crate::audit::Audit;
use crate::broker;
use crate::frame::{read_frame, write_frame};
use crate::ipc::{self, ServerStream};
use crate::notify;
use crate::paths::Paths;

type Shared = Arc<Mutex<Daemon>>;

/// Agent calls that may wait for an unlock at once, the same bound as
/// requests waiting for approval. Past it, a call refused because the
/// vault is locked is answered `vault_locked` at once, as without the wait.
pub const MAX_UNLOCK_WAITERS: usize = 32;

/// How often the server posts the notices no client took and checks for
/// missed requests to tell of.
const NOTICE_TICK: Duration = Duration::from_secs(1);

/// What every agent connection shares.
#[derive(Clone)]
struct Agents {
    daemon: Shared,
    http: reqwest::Client,
    settings: Settings,
    uses: Arc<Mutex<notify::UseNotices>>,
    asks: Arc<Mutex<notify::RateCap>>,
    /// Whether the vault is unlocked, for calls waiting for an unlock.
    unlocked: watch::Receiver<bool>,
    unlock_waiters: Arc<Semaphore>,
}

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
    #[cfg(target_os = "linux")]
    let (mut control, listener_process) = if settings.listener_process {
        let (listener, process) = ipc::bind_with_listener_process(&control_endpoint)?;
        (listener, Some(process))
    } else {
        (ipc::bind(&control_endpoint)?, None)
    };
    #[cfg(not(target_os = "linux"))]
    let mut control = ipc::bind(&control_endpoint)?;

    let audit = Audit::new(paths.audit.clone());
    housekeep(audit.clone());
    let daemon: Shared = Arc::new(Mutex::new(Daemon::new(
        paths.vault.clone(),
        audit,
        settings,
        Instant::now(),
    )));
    let http = broker::http::client().map_err(io::Error::other)?;
    let (unlocked_tx, unlocked) = watch::channel(false);
    let agents = Agents {
        daemon: daemon.clone(),
        http,
        settings,
        uses: Arc::new(Mutex::new(notify::UseNotices::default())),
        asks: Arc::new(Mutex::new(notify::RateCap::default())),
        unlocked,
        unlock_waiters: Arc::new(Semaphore::new(MAX_UNLOCK_WAITERS)),
    };
    let unlocked_tx = Arc::new(unlocked_tx);
    let (stop_tx, mut stop_rx) = watch::channel(false);
    let check_every = (settings.idle_lock.min(settings.locked_exit) / 4)
        .clamp(Duration::from_millis(100), Duration::from_secs(30));
    let mut ticker = tokio::time::interval(check_every);
    let mut notice_ticker = tokio::time::interval(NOTICE_TICK);

    loop {
        tokio::select! {
            accepted = agent.accept() => match accepted {
                Ok(stream) => {
                    tokio::spawn(serve_agent(stream, agents.clone()));
                }
                Err(e) => accept_failed("agent", e).await,
            },
            accepted = control.accept() => match accepted {
                Ok(stream) => {
                    tokio::spawn(serve_control(
                        stream,
                        daemon.clone(),
                        stop_tx.clone(),
                        unlocked_tx.clone(),
                    ));
                }
                Err(e) => accept_failed("control", e).await,
            },
            _ = notice_ticker.tick() => {
                let plain = {
                    let mut daemon = lock(&daemon);
                    daemon.notice_tick(Instant::now());
                    daemon.take_plain_notices()
                };
                post_plain(plain, &agents);
            }
            _ = ticker.tick() => {
                let (after, is_unlocked) = {
                    let mut daemon = lock(&daemon);
                    let after = daemon.tick(Instant::now(), SystemTime::now());
                    (after, daemon.is_unlocked())
                };
                set_unlocked(&unlocked_tx, is_unlocked);
                if after == After::Stop {
                    break;
                }
                // Without it clients refuse this daemon; stop, and the next
                // command starts a new one.
                #[cfg(target_os = "linux")]
                if listener_process.as_ref().is_some_and(|p| p.exited()) {
                    break;
                }
            }
            _ = stop_rx.changed() => break,
        }
    }

    ipc::cleanup(&agent_endpoint);
    ipc::cleanup(&control_endpoint);
    #[cfg(target_os = "linux")]
    drop(listener_process);
    drop(lock_file);
    Ok(Outcome::Stopped)
}

/// The tool and handles of work that runs without waiting for the user:
/// a handle in mode auto, or one allowed for the agent's session.
fn immediate_use(prepared: &Prepared) -> Option<(&'static str, Vec<String>)> {
    match prepared {
        Prepared::Http(job) => Some(("http_request", vec![job.secret.name.clone()])),
        Prepared::Exec(job) => Some(("exec", job.handles.clone())),
        Prepared::Db(job) => Some(("db_query", vec![job.secret.name.clone()])),
        Prepared::Connect(job) => Some(("db_connect", vec![job.secret.name.clone()])),
        Prepared::Run(job) => Some(("run", vec![job.handle.clone()])),
        Prepared::Reply(_) | Prepared::Wait(_) => None,
    }
}

async fn serve_agent(mut stream: ServerStream, agents: Agents) {
    let settings = agents.settings;
    let (level, sound) = (settings.notify, settings.sound);
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
        // Only with notifications on: the user learns from the "unlock
        // needed" notice, posted or queued as the call was refused, why the
        // call waits.
        let again = (!settings.unlock_wait.is_zero()
            && level.approvals()
            && locked_tool(&request).is_some())
        .then(|| request.clone());
        let Some((mut prepared, mut notifier)) = prepare(&agents, &session, request).await else {
            return;
        };
        if let Some(request) = again
            && is_locked(&prepared)
        {
            match wait_for_unlock(&mut stream, &agents).await {
                Unlock::Unlocked => {
                    let Some(again) = prepare(&agents, &session, request).await else {
                        return;
                    };
                    (prepared, notifier) = again;
                }
                // The same `vault_locked` reply as without the wait.
                Unlock::TimedOut | Unlock::Busy => {}
                Unlock::HungUp => return,
            }
        }
        if level.uses()
            && let Some((tool, handles)) = immediate_use(&prepared)
            && let Some(text) = agents
                .uses
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .notice(session.as_ref(), &handles, tool, Instant::now())
        {
            notify::handle_used(text, sound);
        }
        let prepared = match prepared {
            Prepared::Wait(waiting) => {
                // kv tray shows it with buttons to answer it; one is enough.
                if level.approvals()
                    && !notifier
                    && let Some(text) = notify::approval_notice(
                        &mut agents.asks.lock().unwrap_or_else(PoisonError::into_inner),
                        &waiting.notice,
                        Instant::now(),
                    )
                {
                    notify::approval_needed(text, sound);
                }
                match wait_for_decision(&agents, &mut stream, *waiting).await {
                    Some(prepared) => prepared,
                    None => return,
                }
            }
            prepared => prepared,
        };
        // A run keeps the connection: from here on it carries the program's
        // input and output.
        if let Prepared::Run(job) = prepared {
            broker::run::serve(stream, *job).await;
            return;
        }
        let response = run_job(prepared, &agents.http).await;
        if write_frame(&mut stream, &response).await.is_err() {
            return;
        }
    }
}

/// Prepares `request` without holding up the async workers, and posts the
/// notices that brought about. Also says whether a client is showing
/// waiting requests with buttons, so the daemon need not. `None` if the
/// daemon's task failed.
async fn prepare(
    agents: &Agents,
    session: &Option<SessionInfo>,
    request: AgentRequest,
) -> Option<(Prepared, bool)> {
    let shared = agents.daemon.clone();
    let asking = session.clone();
    let (prepared, plain, notifier) = tokio::task::spawn_blocking(move || {
        let mut daemon = lock(&shared);
        let now = Instant::now();
        let prepared = daemon.prepare_in(asking.as_ref(), request, now);
        (
            prepared,
            daemon.take_plain_notices(),
            daemon.has_notifier(now),
        )
    })
    .await
    .ok()?;
    post_plain(plain, agents);
    Some((prepared, notifier))
}

fn is_locked(prepared: &Prepared) -> bool {
    matches!(
        prepared,
        Prepared::Reply(AgentResponse::Error {
            code: AgentErrorCode::VaultLocked,
            ..
        })
    )
}

/// How a wait for the vault to unlock ended.
enum Unlock {
    Unlocked,
    TimedOut,
    /// `MAX_UNLOCK_WAITERS` calls wait already.
    Busy,
    /// The agent closed the connection.
    HungUp,
}

/// Waits up to `unlock_wait` for the vault to unlock, holding one of the
/// waiting places while it does.
async fn wait_for_unlock(stream: &mut ServerStream, agents: &Agents) -> Unlock {
    let Ok(_place) = agents.unlock_waiters.try_acquire() else {
        return Unlock::Busy;
    };
    let mut unlocked = agents.unlocked.clone();
    // The agent sends nothing until it has its reply, so any read that
    // returns means it closed the connection (or broke the protocol).
    let mut byte = [0u8; 1];
    tokio::select! {
        waited = tokio::time::timeout(
            agents.settings.unlock_wait,
            unlocked.wait_for(|unlocked| *unlocked),
        ) => match waited {
            Ok(Ok(_)) => Unlock::Unlocked,
            _ => Unlock::TimedOut,
        },
        _ = stream.read(&mut byte) => Unlock::HungUp,
    }
}

/// Posts the notices the daemon left for the server. A reminder counts
/// against the same cap as the approval notices.
fn post_plain(plain: Vec<Plain>, agents: &Agents) {
    let sound = agents.settings.sound;
    for notice in plain {
        let body = if let NoticeKind::Reminder { .. } = notice.kind {
            let mut asks = agents.asks.lock().unwrap_or_else(PoisonError::into_inner);
            match notify::approval_notice(&mut asks, &notice.body, Instant::now()) {
                Some(body) => body,
                None => continue,
            }
        } else {
            notice.body.clone()
        };
        let waiting = notice.waiting();
        notify::post(notice.title, body, sound.tone(waiting), waiting);
    }
}

/// Tells the calls waiting for an unlock whether the vault is unlocked.
fn set_unlocked(unlocked: &watch::Sender<bool>, is_unlocked: bool) {
    unlocked.send_if_modified(|was| std::mem::replace(was, is_unlocked) != is_unlocked);
}

async fn run_job(prepared: Prepared, http: &reqwest::Client) -> AgentResponse {
    match prepared {
        Prepared::Reply(response) => response,
        Prepared::Http(job) => broker::http::send(http, *job).await,
        Prepared::Exec(job) => broker::exec::run(*job).await,
        Prepared::Db(job) => broker::db::run(*job).await,
        Prepared::Connect(job) => broker::lease::start(*job).await,
        // `Waiting::then` is always a job; it never waits twice.
        Prepared::Wait(_) => AgentResponse::Error {
            code: AgentErrorCode::UpstreamError,
            message: "internal error: a request waited twice".into(),
        },
        // `serve_agent` gives a run its connection before this point.
        Prepared::Run(_) => AgentResponse::Error {
            code: AgentErrorCode::UpstreamError,
            message: "internal error: a run reached the reply path".into(),
        },
    }
}

/// Waits for the user's decision without holding the daemon lock, and
/// reminds them halfway through. Returns the job to run, or a reply saying
/// why not; `None` when the agent hung up while it waited, and the request
/// is withdrawn.
async fn wait_for_decision(
    agents: &Agents,
    stream: &mut ServerStream,
    waiting: Waiting,
) -> Option<Prepared> {
    let daemon = &agents.daemon;
    let Waiting {
        id,
        mut verdict,
        then,
        wait,
        ..
    } = waiting;
    let started = tokio::time::Instant::now();
    let deadline = started + wait;
    let remind_at = started + wait / 2;
    let mut reminded = false;
    // The agent sends nothing until it has its reply, so any read that
    // returns means it closed the connection (or broke the protocol).
    let mut byte = [0u8; 1];
    let decided = loop {
        tokio::select! {
            decided = &mut verdict => break decided.ok(),
            _ = tokio::time::sleep_until(remind_at), if !reminded => {
                reminded = true;
                let shared = daemon.clone();
                let plain = tokio::task::spawn_blocking(move || {
                    let mut daemon = lock(&shared);
                    daemon.remind(id, Instant::now());
                    daemon.take_plain_notices()
                })
                .await;
                if let Ok(plain) = plain {
                    post_plain(plain, agents);
                }
            }
            _ = tokio::time::sleep_until(deadline) => {
                let shared = daemon.clone();
                let expired = tokio::task::spawn_blocking(move || {
                    lock(&shared).expire(id, Instant::now())
                })
                .await;
                if let Ok(Some(response)) = expired {
                    return Some(Prepared::Reply(response));
                }
                // Decided, or locked, just as the wait ran out.
                break verdict.try_recv().ok();
            }
            _ = stream.read(&mut byte) => {
                let shared = daemon.clone();
                let _ = tokio::task::spawn_blocking(move || {
                    lock(&shared).withdraw(id, Instant::now())
                })
                .await;
                return None;
            }
        }
    };
    Some(match decided {
        Some(Verdict::AllowOnce | Verdict::AllowSession) => then,
        Some(Verdict::Deny | Verdict::DenyAlways) => Prepared::Reply(AgentResponse::Error {
            code: AgentErrorCode::ApprovalDenied,
            message: "the user denied the request".into(),
        }),
        None => {
            let shared = daemon.clone();
            let ended = tokio::task::spawn_blocking(move || lock(&shared).take_ended(id)).await;
            Prepared::Reply(ended.ok().flatten().unwrap_or_else(|| AgentResponse::Error {
                code: AgentErrorCode::VaultLocked,
                message:
                    "the vault was locked before the request was approved; ask the user to unlock it"
                        .into(),
            }))
        }
    })
}

async fn serve_control(
    mut stream: ServerStream,
    daemon: Shared,
    stop: watch::Sender<bool>,
    unlocked: Arc<watch::Sender<bool>>,
) {
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
            let mut daemon = lock(&daemon);
            let (response, after) = daemon.handle_control(request, Instant::now());
            (response, after, daemon.is_unlocked())
        })
        .await;
        let Ok((response, after, is_unlocked)) = handled else {
            return;
        };
        set_unlocked(&unlocked, is_unlocked);
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

/// Clears up after an earlier daemon in the background, so the sockets are
/// ready at once: the files of `file` handles a crash left in the temp
/// directory, and audit records past their age.
fn housekeep(audit: Audit) {
    tokio::task::spawn_blocking(move || {
        broker::files::remove_stale();
        audit.prune(SystemTime::now());
    });
}
