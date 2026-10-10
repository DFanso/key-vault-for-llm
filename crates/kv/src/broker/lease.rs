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
use super::pgwire::PgTarget;
use super::resp::RedisTarget;
use crate::audit::{Audit, Use};

mod postgres;
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

/// Why the daemon ended a lease or a run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EndReason {
    Locked,
    HandleChanged,
}

impl EndReason {
    /// Told to the client.
    pub fn message(self) -> &'static str {
        match self {
            Self::Locked => "the vault locked",
            Self::HandleChanged => "the handle changed",
        }
    }

    /// For the audit log.
    pub fn outcome(self) -> &'static str {
        match self {
            Self::Locked => "locked",
            Self::HandleChanged => "handle_changed",
        }
    }
}

/// Open entries the daemon ends when the vault locks or a handle changes,
/// with the scrubber they follow as secrets change. `db_connect` leases and
/// programs started through `run` each keep one book.
#[derive(Clone)]
pub struct Leases {
    book: Arc<Mutex<Book>>,
    scrubber: Arc<watch::Sender<Arc<Scrubber>>>,
    limit: usize,
}

#[derive(Default)]
struct Book {
    next: u64,
    /// Ending an entry sends its reason, then drops its sender.
    live: Vec<(u64, String, watch::Sender<Option<EndReason>>)>,
}

impl Default for Leases {
    fn default() -> Self {
        Self::with_limit(MAX_LEASES)
    }
}

impl Leases {
    /// A book that holds at most `limit` entries at once.
    pub fn with_limit(limit: usize) -> Self {
        Self {
            book: Arc::default(),
            scrubber: Arc::new(watch::Sender::new(Arc::new(Scrubber::new([])))),
            limit,
        }
    }

    fn book(&self) -> std::sync::MutexGuard<'_, Book> {
        self.book.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// A place for a new entry on `handle`; `None` when the book is full.
    pub fn open(&self, handle: &str) -> Option<LeaseTicket> {
        let mut book = self.book();
        if book.live.len() >= self.limit {
            return None;
        }
        book.next += 1;
        let id = book.next;
        let (sender, end) = watch::channel(None);
        book.live.push((id, handle.to_owned(), sender));
        Some(LeaseTicket {
            id,
            leases: self.clone(),
            end,
        })
    }

    pub fn end_handle(&self, handle: &str) {
        self.end_where(EndReason::HandleChanged, |h| h == handle);
    }

    pub fn end_all(&self) {
        self.end_where(EndReason::Locked, |_| true);
    }

    fn end_where(&self, reason: EndReason, matches: impl Fn(&str) -> bool) {
        self.book().live.retain(|(_, handle, sender)| {
            if !matches(handle) {
                return true;
            }
            sender.send_replace(Some(reason));
            false
        });
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
    end: watch::Receiver<Option<EndReason>>,
}

impl LeaseTicket {
    pub fn has_ended(&self) -> bool {
        self.end.has_changed().is_err()
    }

    /// Waits until the daemon ends this entry, and says why.
    pub async fn ended(&self) -> EndReason {
        let mut end = self.end.clone();
        while end.changed().await.is_ok() {}
        let reason = *end.borrow();
        reason.unwrap_or(EndReason::Locked)
    }
}

impl Drop for LeaseTicket {
    fn drop(&mut self) {
        let id = self.id;
        self.leases.book().live.retain(|(i, _, _)| *i != id);
    }
}

/// Waits until the lease ends.
async fn ended(mut end: watch::Receiver<Option<EndReason>>) {
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
    Postgres(PgTarget),
    Redis(RedisTarget),
}

/// Opens the lease and returns its URL, recording it in the audit log.
pub async fn start(job: ConnectJob) -> AgentResponse {
    let ticket = job.ticket;
    let ttl = job.ttl;
    let opened = open(
        &job.secret,
        ttl,
        job.scrubber.clone(),
        &job.audit,
        &job.role_checks,
        job.role_stamp,
        ticket,
    );
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
    role_checks: &super::RoleChecks,
    role_stamp: u64,
    ticket: LeaseTicket,
) -> Result<LeaseReply, AgentResponse> {
    if ticket.has_ended() {
        return Err(error(
            AgentErrorCode::PolicyDenied,
            "the vault locked or the handle changed before the lease started; ask again",
        ));
    }
    let scrubber = scrubber_rx.borrow().clone();
    let bad = |message: String| error(AgentErrorCode::BadRequest, message);
    let read_only = secret.policy.read_only;
    let mut warnings = Vec::new();
    let target = match &secret.value {
        SecretValue::Postgres { url } => {
            let target = PgTarget::parse(url.expose()).map_err(bad)?;
            if read_only {
                warnings.extend(
                    super::db::role_warning(
                        &secret.name,
                        url.expose(),
                        role_checks,
                        role_stamp,
                        &scrubber,
                    )
                    .await?,
                );
            }
            Target::Postgres(target)
        }
        SecretValue::Redis { url } => Target::Redis(RedisTarget::parse(url.expose()).map_err(bad)?),
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
        Target::Postgres(target) => {
            let mut url = url::Url::parse(&format!("postgres://127.0.0.1:{port}"))
                .expect("a loopback URL parses");
            url.set_username("kv").expect("postgres URLs take a user");
            url.set_password(Some(&token))
                .expect("postgres URLs take a password");
            url.set_path(&target.dbname);
            url.set_query(Some("sslmode=disable"));
            url.to_string()
        }
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
        warnings,
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
async fn connection(stream: TcpStream, lease: Arc<Lease>, end: watch::Receiver<Option<EndReason>>) {
    let started = Instant::now();
    let _ = stream.set_nodelay(true);
    let outcome = match &lease.target {
        Target::Postgres(target) => postgres::serve(stream, &lease, target, end).await,
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
