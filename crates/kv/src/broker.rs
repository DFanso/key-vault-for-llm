//! Work an agent asked for, authorized by the daemon and run outside the
//! daemon lock: HTTP requests, programs, database queries and database
//! leases.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use kv_core::proto::{DbCall, HttpCall};
use kv_core::scrub::Scrubber;
use kv_core::secret::{Secret, SecretText};

use kv_core::proto::MAX_OUTPUT_LEN;

use crate::audit::Audit;

pub mod db;
pub mod exec;
pub mod http;
pub mod lease;
pub mod net;
pub mod pgwire;
mod process;
pub mod resp;

pub use db::RoleChecks;
pub use lease::{LeaseTicket, Leases};

/// An `http_request` that passed every check.
pub struct HttpJob {
    pub secret: Secret,
    /// Where the first request goes, already checked against the policy.
    pub url: url::Url,
    pub call: HttpCall,
    pub scrubber: Arc<Scrubber>,
    pub audit: Audit,
    pub started: Instant,
    /// `auto`, or `approved` after a decision in `kv tui`, for the audit log.
    pub decision: &'static str,
}

/// An `exec` that passed every check.
pub struct ExecJob {
    pub handles: Vec<String>,
    pub argv: Vec<String>,
    pub cwd: PathBuf,
    pub timeout: Duration,
    /// Variables from every handle, already checked for clashes.
    pub env: Vec<(String, SecretText)>,
    pub scrubber: Arc<Scrubber>,
    pub audit: Audit,
    pub started: Instant,
    /// `auto`, or `approved` after a decision in `kv tui`, for the audit log.
    pub decision: &'static str,
}

/// A `db_query` that passed every check.
pub struct DbJob {
    pub secret: Secret,
    pub call: DbCall,
    pub timeout: Duration,
    pub scrubber: Arc<Scrubber>,
    pub audit: Audit,
    pub started: Instant,
    /// `auto`, or `approved` after a decision in `kv tui`, for the audit log.
    pub decision: &'static str,
    /// Where a read-only Postgres handle's role check is kept; the job runs
    /// the check if this handle has none since the vault was unlocked.
    pub role_checks: RoleChecks,
    /// `role_checks.stamp()` when the job was authorized; a check whose
    /// handle changed since is not kept.
    pub role_stamp: u64,
}

/// A `db_connect` that passed every check.
pub struct ConnectJob {
    pub secret: Secret,
    pub ttl: Duration,
    /// The lease's place among the open leases, taken when the request was
    /// authorized, so a lock or a change to the handle ends it even before
    /// it starts.
    pub ticket: LeaseTicket,
    /// The scrubber for every unlocked secret, kept current while the lease
    /// is open.
    pub scrubber: tokio::sync::watch::Receiver<Arc<Scrubber>>,
    pub audit: Audit,
    pub started: Instant,
    /// `auto`, or `approved` after a decision in `kv tui`, for the audit log.
    pub decision: &'static str,
    pub role_checks: RoleChecks,
    pub role_stamp: u64,
}

/// Decodes scrubbed bytes, cutting them to `MAX_OUTPUT_LEN` (replacement
/// markers can make scrubbed output longer than its input).
pub(crate) fn capped_text(bytes: &[u8]) -> (String, bool) {
    let mut text = String::from_utf8_lossy(bytes).into_owned();
    if text.len() <= MAX_OUTPUT_LEN {
        return (text, false);
    }
    let mut end = MAX_OUTPUT_LEN;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text.truncate(end);
    (text, true)
}

/// Names only: the URL may hold a hidden base URL, and the job holds values.
impl std::fmt::Debug for HttpJob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpJob")
            .field("handle", &self.secret.name)
            .field("method", &self.call.method)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for ExecJob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExecJob")
            .field("handles", &self.handles)
            .field("program", &self.argv.first())
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for ConnectJob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectJob")
            .field("handle", &self.secret.name)
            .field("ttl", &self.ttl)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for DbJob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DbJob")
            .field("handle", &self.secret.name)
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}
