//! Messages exchanged with the daemon over its two local sockets.
//!
//! Agent-socket responses are built from `HandleInfo`, status data and
//! scrubbed output, and no agent message type has a field that holds a
//! secret value. Control requests carry the vault passphrase, because every
//! control command except `lock` and `stop` must prove the user is present.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::policy::{Mode, Policy};
use crate::secret::{HandleInfo, Secret, SecretText};

/// Largest frame either side accepts, in bytes. Room for the output caps
/// below even when every byte is JSON-escaped as `\u00XX`.
pub const MAX_FRAME_LEN: usize = 4 * 1024 * 1024;

/// Largest HTTP response body, and largest stdout or stderr from `exec`,
/// returned to an agent, in bytes. Longer output is cut and marked
/// `truncated`.
pub const MAX_OUTPUT_LEN: usize = 256 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AgentRequest {
    ListHandles,
    Status,
    HttpRequest(HttpCall),
    Exec(ExecCall),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpCall {
    pub handle: String,
    pub method: String,
    /// A full URL, or a path such as `/v1/items` for handles whose
    /// `takes_path` is true.
    pub url: String,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(default)]
    pub body: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecCall {
    /// `env` handles whose variables are injected.
    pub handles: Vec<String>,
    /// Program and arguments. Never run through a shell.
    pub argv: Vec<String>,
    /// Absolute working directory.
    pub cwd: PathBuf,
    /// Defaults to 60 seconds; at most 600.
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AgentResponse {
    Handles {
        handles: Vec<HandleInfo>,
    },
    Status {
        status: Status,
    },
    Http(HttpReply),
    Exec(ExecReply),
    Error {
        code: AgentErrorCode,
        message: String,
    },
}

/// A scrubbed HTTP response.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpReply {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    /// Decoded as UTF-8, with invalid bytes replaced.
    pub body: String,
    pub truncated: bool,
}

/// Scrubbed output of a finished or killed program.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecReply {
    /// `None` if the program was killed or ended by a signal.
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub stdout: String,
    pub stderr: String,
    pub truncated: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Status {
    pub vault_exists: bool,
    pub locked: bool,
    /// Present only while unlocked.
    pub handle_count: Option<usize>,
    /// Seconds until the idle timeout locks the vault, while unlocked.
    pub locks_in_secs: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentErrorCode {
    NoVault,
    VaultLocked,
    BadRequest,
    UnknownHandle,
    PolicyDenied,
    /// The handle needs approval. Until `kv tui` exists, these requests
    /// fail at once.
    ApprovalTimeout,
    UpstreamError,
}

impl AgentErrorCode {
    /// The code as it appears on the wire, e.g. `vault_locked`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NoVault => "no_vault",
            Self::VaultLocked => "vault_locked",
            Self::BadRequest => "bad_request",
            Self::UnknownHandle => "unknown_handle",
            Self::PolicyDenied => "policy_denied",
            Self::ApprovalTimeout => "approval_timeout",
            Self::UpstreamError => "upstream_error",
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ControlRequest {
    /// Required by every command except `lock` and `stop`. For `init` it is
    /// the new passphrase.
    pub passphrase: Option<SecretText>,
    pub command: ControlCommand,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ControlCommand {
    /// Creates the vault. `insecure_fast_kdf` uses cheap Argon2 settings and
    /// exists only for tests.
    Init {
        #[serde(default)]
        insecure_fast_kdf: bool,
    },
    Unlock,
    Lock,
    /// Locks the vault and shuts the daemon down.
    Stop,
    Add {
        secret: Secret,
        #[serde(default)]
        replace: bool,
    },
    Remove {
        name: String,
    },
    SetPolicy {
        name: String,
        patch: PolicyPatch,
    },
    ChangePassphrase {
        new_passphrase: SecretText,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ControlResponse {
    Done {
        #[serde(default)]
        warnings: Vec<String>,
    },
    Error {
        code: ControlErrorCode,
        message: String,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlErrorCode {
    NoVault,
    VaultExists,
    PassphraseRequired,
    WrongPassphrase,
    TooManyAttempts,
    UnknownHandle,
    HandleExists,
    Invalid,
    BadRequest,
    Internal,
}

/// A partial policy update: only the fields that are `Some` change.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyPatch {
    #[serde(default)]
    pub mode: Option<Mode>,
    #[serde(default)]
    pub allowed_hosts: Option<Vec<String>>,
    #[serde(default)]
    pub allow_plain_http: Option<bool>,
    #[serde(default)]
    pub allowed_methods: Option<Vec<String>>,
    #[serde(default)]
    pub read_only: Option<bool>,
    #[serde(default)]
    pub allowed_cmds: Option<Vec<String>>,
    #[serde(default, with = "humantime_serde")]
    pub grant_ttl: Option<Duration>,
}

impl PolicyPatch {
    pub fn apply(&self, policy: &mut Policy) {
        if let Some(mode) = self.mode {
            policy.mode = mode;
        }
        if let Some(hosts) = &self.allowed_hosts {
            policy.allowed_hosts = hosts.clone();
        }
        if let Some(plain) = self.allow_plain_http {
            policy.allow_plain_http = plain;
        }
        if let Some(methods) = &self.allowed_methods {
            policy.allowed_methods = methods.clone();
        }
        if let Some(read_only) = self.read_only {
            policy.read_only = read_only;
        }
        if let Some(cmds) = &self.allowed_cmds {
            policy.allowed_cmds = cmds.clone();
        }
        if let Some(ttl) = self.grant_ttl {
            policy.grant_ttl = ttl;
        }
    }
}
