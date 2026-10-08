//! Work an agent asked for, authorized by the daemon and run outside the
//! daemon lock: HTTP requests and programs.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use kv_core::proto::HttpCall;
use kv_core::scrub::Scrubber;
use kv_core::secret::{Secret, SecretText};

use crate::audit::Audit;

pub mod http;

/// An `http_request` that passed every check.
pub struct HttpJob {
    pub secret: Secret,
    /// Where the first request goes, already checked against the policy.
    pub url: url::Url,
    pub call: HttpCall,
    pub scrubber: Arc<Scrubber>,
    pub audit: Audit,
    pub started: Instant,
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
