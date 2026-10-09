//! `db_connect`: a loopback listener per lease that checks the lease token,
//! connects to the database with the real credentials and passes traffic
//! both ways, scrubbing what comes back and keeping read-only handles
//! read-only. Connections close when the lease ends: at its expiry, when
//! the vault locks, or when its handle changes.

use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use kv_core::crypto::fill_random;
use kv_core::proto::{AgentErrorCode, AgentResponse, LeaseReply};
use kv_core::scrub::Scrubber;
use kv_core::secret::SecretValue;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, watch};

use super::ConnectJob;
use super::resp::RedisTarget;
use crate::audit::{Audit, Use};

mod redis;

pub const DEFAULT_TTL: Duration = Duration::from_secs(900);
pub const MAX_TTL: Duration = Duration::from_secs(3600);
/// Leases open at once, counting those waiting for approval.
pub const MAX_LEASES: usize = 16;
/// Connections open at once on one lease.
const MAX_CONNECTIONS: usize = 16;
/// How long a client has to log in.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);
/// How long the server has to accept the login.
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(20);

/// The leases that are open. The daemon ends them when the vault locks or
/// a handle changes, and keeps their scrubber current as secrets change.
#[derive(Clone)]
pub struct Leases {
    book: Arc<Mutex<Book>>,
    scrubber: Arc<watch::Sender<Arc<Scrubber>>>,
}

#[derive(Default)]
struct Book {
    next: u64,
    /// Dropping an entry's sender ends that lease.
    live: Vec<(u64, String, watch::Sender<()>)>,
}

impl Default for Leases {
    fn default() -> Self {
        Self {
            book: Arc::default(),
            scrubber: Arc::new(watch::Sender::new(Arc::new(Scrubber::new([])))),
        }
    }
}

impl Leases {
    fn book(&self) -> std::sync::MutexGuard<'_, Book> {
        self.book.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// A place for a new lease on `handle`; `None` when `MAX_LEASES` are
    /// open.
    pub fn open(&self, handle: &str) -> Option<LeaseTicket> {
        let mut book = self.book();
        if book.live.len() >= MAX_LEASES {
            return None;
        }
        book.next += 1;
        let id = book.next;
        let (sender, end) = watch::channel(());
        book.live.push((id, handle.to_owned(), sender));
        Some(LeaseTicket {
            id,
            leases: self.clone(),
            end,
        })
    }

    pub fn end_handle(&self, handle: &str) {
        self.book().live.retain(|(_, h, _)| h != handle);
    }

    pub fn end_all(&self) {
        self.book().live.clear();
    }

    pub fn count(&self) -> usize {
        self.book().live.len()
    }

    /// The scrubber a new lease follows.
    pub fn subscribe(&self) -> watch::Receiver<Arc<Scrubber>> {
        self.scrubber.subscribe()
    }

    /// The scrubber open leases use from now on.
    pub fn set_scrubber(&self, scrubber: Arc<Scrubber>) {
        self.scrubber.send_replace(scrubber);
    }
}

/// A lease's entry in the book; the lease ends when the entry goes, and
/// the entry goes when this is dropped.
pub struct LeaseTicket {
    id: u64,
    leases: Leases,
    end: watch::Receiver<()>,
}

impl LeaseTicket {
    pub fn has_ended(&self) -> bool {
        self.end.has_changed().is_err()
    }
}

impl Drop for LeaseTicket {
    fn drop(&mut self) {
        let id = self.id;
        self.leases.book().live.retain(|(i, _, _)| *i != id);
    }
}

/// Waits until the lease ends.
async fn ended(mut end: watch::Receiver<()>) {
    while end.changed().await.is_ok() {}
}

/// What every connection on a lease needs.
struct Lease {
    handle: String,
    token: String,
    target: Target,
    read_only: bool,
    scrubber: watch::Receiver<Arc<Scrubber>>,
    audit: Audit,
}

impl Lease {
    fn scrubber(&self) -> Arc<Scrubber> {
        self.scrubber.borrow().clone()
    }
}

enum Target {
    Redis(RedisTarget),
}

/// Opens the lease and returns its URL, recording it in the audit log.
pub async fn start(job: ConnectJob) -> AgentResponse {
    let ticket = job.ticket;
    let ttl = job.ttl;
    let opened = open(&job.secret, ttl, job.scrubber.clone(), &job.audit, ticket);
    let response = match opened.await {
        Ok(reply) => AgentResponse::Lease(reply),
        Err(response) => response,
    };
    let outcome = match &response {
        AgentResponse::Error { code, .. } => code.as_str(),
        _ => "ok",
    };
    job.audit.record_use(&Use {
        action: "db_connect",
        handle: &job.secret.name,
        decision: job.decision,
        summary: &format!("lease for {}s", ttl.as_secs()),
        outcome,
        duration: job.started.elapsed(),
    });
    response
}

async fn open(
    secret: &kv_core::secret::Secret,
    ttl: Duration,
    scrubber_rx: watch::Receiver<Arc<Scrubber>>,
    audit: &Audit,
    ticket: LeaseTicket,
) -> Result<LeaseReply, AgentResponse> {
    if ticket.has_ended() {
        return Err(error(
            AgentErrorCode::PolicyDenied,
            "the vault locked or the handle changed before the lease started; ask again",
        ));
    }
    let bad = |message: String| error(AgentErrorCode::BadRequest, message);
    let read_only = secret.policy.read_only;
    let target = match &secret.value {
        SecretValue::Redis { url } => Target::Redis(RedisTarget::parse(url.expose()).map_err(bad)?),
        SecretValue::Postgres { .. } => {
            return Err(bad("db_connect does not take postgres handles yet".into()));
        }
        _ => return Err(bad("not a database handle".into())),
    };
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .map_err(|e| {
            error(
                AgentErrorCode::UpstreamError,
                format!("could not listen: {e}"),
            )
        })?;
    let port = listener
        .local_addr()
        .map_err(|e| {
            error(
                AgentErrorCode::UpstreamError,
                format!("could not listen: {e}"),
            )
        })?
        .port();
    let mut bytes = [0u8; 32];
    fill_random(&mut bytes);
    let token = hex(&bytes);
    let url = match &target {
        Target::Redis(target) => format!("redis://kv:{token}@127.0.0.1:{port}/{}", target.db),
    };
    let lease = Arc::new(Lease {
        handle: secret.name.clone(),
        token,
        target,
        read_only,
        scrubber: scrubber_rx,
        audit: audit.clone(),
    });
    let expires = tokio::time::Instant::now() + ttl;
    tokio::spawn(serve(listener, lease, ticket, expires));
    Ok(LeaseReply {
        url,
        expires_in_secs: ttl.as_secs(),
        warnings: Vec::new(),
    })
}

/// Accepts connections until the lease ends, then closes the listener and,
/// by dropping the ticket, every connection.
async fn serve(
    listener: TcpListener,
    lease: Arc<Lease>,
    ticket: LeaseTicket,
    expires: tokio::time::Instant,
) {
    let connections = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let expiry = tokio::time::sleep_until(expires);
    tokio::pin!(expiry);
    loop {
        tokio::select! {
            _ = &mut expiry => break,
            _ = ended(ticket.end.clone()) => break,
            accepted = listener.accept() => {
                let Ok((stream, _)) = accepted else { continue };
                let Ok(permit) = connections.clone().try_acquire_owned() else {
                    record(&lease, "too_many_connections", Instant::now());
                    continue;
                };
                let lease = lease.clone();
                let end = ticket.end.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    connection(stream, lease, end).await;
                });
            }
        }
    }
    drop(ticket);
}

/// Serves one client. The relays watch for the lease's end themselves, so
/// a Postgres client is told why; a client still logging in when the lease
/// ends finds the relay closed the moment it starts.
async fn connection(stream: TcpStream, lease: Arc<Lease>, end: watch::Receiver<()>) {
    let started = Instant::now();
    let _ = stream.set_nodelay(true);
    let outcome = match &lease.target {
        Target::Redis(target) => redis::serve(stream, &lease, target, end).await,
    };
    record(&lease, outcome, started);
}

fn record(lease: &Lease, outcome: &str, started: Instant) {
    lease.audit.record_use(&Use {
        action: "db_connect",
        handle: &lease.handle,
        decision: "lease",
        summary: "connection",
        outcome,
        duration: started.elapsed(),
    });
}

/// Compares without stopping at the first difference, so timing reveals
/// nothing about the token.
fn token_matches(given: &[u8], token: &str) -> bool {
    given.len() == token.len()
        && given
            .iter()
            .zip(token.bytes())
            .fold(0u8, |diff, (x, y)| diff | (x ^ y))
            == 0
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn error(code: AgentErrorCode, message: impl Into<String>) -> AgentResponse {
    AgentResponse::Error {
        code,
        message: message.into(),
    }
}
