//! Messages exchanged with the daemon over its two local sockets.
//!
//! Agent-socket responses are built from `HandleInfo`, status data and
//! scrubbed output, and no agent message type has a field that holds a
//! secret value. Control requests carry the vault passphrase, or a session
//! token that `kv tui` got for it, because every control command except
//! `lock` and `stop` must prove the user is present.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::policy::{Mode, Policy};
use crate::secret::{AuthPlacement, HandleInfo, Secret, SecretKind, SecretText, SecretValue};

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
    /// Names the agent session for the rest of the connection, so approvals
    /// can show who is asking and session grants can apply. Gets no reply.
    Hello(SessionInfo),
    ListHandles,
    Status,
    HttpRequest(HttpCall),
    Exec(ExecCall),
    /// Asks the user to add a handle. Answered at once; the user finishes
    /// it in `kv tui`.
    RequestHandle(HandleRequest),
}

/// A handle an agent would like the user to add. It has no field for a
/// value or a mode: the user types the secret and decides the policy in
/// `kv tui`. Unknown fields are refused, so a value sent by mistake is an
/// error rather than silently dropped.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HandleRequest {
    pub name: String,
    pub kind: SecretKind,
    #[serde(default)]
    pub description: String,
    /// Why the agent needs it, shown to the user.
    #[serde(default)]
    pub reason: String,
    /// http: where the token goes.
    #[serde(default)]
    pub auth: Option<AuthPlacement>,
    /// http: the service's address should stay hidden behind a base URL.
    #[serde(default)]
    pub base_url: bool,
    /// http: hosts the token may be sent to.
    #[serde(default)]
    pub allowed_hosts: Vec<String>,
    /// env: names of the variables the handle should set.
    #[serde(default)]
    pub env_vars: Vec<String>,
    /// env: programs allowed to receive them.
    #[serde(default)]
    pub allowed_cmds: Vec<String>,
}

/// Who is asking, as `kv mcp` reports it. The id is random per `kv mcp`
/// process; the client name comes from the MCP client and is self-reported.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionInfo {
    pub id: String,
    pub client: String,
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
    /// The handle request is waiting for the user in `kv tui`.
    Requested {
        name: String,
    },
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
    /// Agent requests waiting for a decision in `kv tui`.
    #[serde(default)]
    pub pending_approvals: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentErrorCode {
    NoVault,
    VaultLocked,
    BadRequest,
    UnknownHandle,
    PolicyDenied,
    /// No decision in time, or too many requests already waiting.
    ApprovalTimeout,
    ApprovalDenied,
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
            Self::ApprovalDenied => "approval_denied",
            Self::UpstreamError => "upstream_error",
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ControlRequest {
    /// Required by every command except `lock` and `stop`. For `init` it is
    /// the new passphrase.
    pub passphrase: Option<SecretText>,
    /// A token from `open_session`, accepted instead of the passphrase by
    /// every command except `init`, `open_session` and `change_passphrase`.
    /// `overview` accepts only a token.
    #[serde(default)]
    pub token: Option<SecretText>,
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
    /// Changes a handle's description or value and keeps its policy. The
    /// value must be of the same kind; an http value without a base URL
    /// keeps the base URL the handle has.
    Update {
        name: String,
        #[serde(default)]
        description: Option<String>,
        #[serde(default)]
        value: Option<SecretValue>,
    },
    ChangePassphrase {
        new_passphrase: SecretText,
    },
    /// Unlocks if needed and replies with a session token that works until
    /// the vault locks. Needs the passphrase.
    OpenSession,
    /// Status, handles and waiting requests in one reply, for `kv tui` to
    /// poll. Not counted as use of the vault and not audited.
    Overview,
    /// Answers a request waiting for approval.
    Decide {
        id: u64,
        verdict: Verdict,
    },
    /// Turns down a handle request.
    DismissRequest {
        id: u64,
    },
}

/// The user's answer to a request waiting for approval.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    AllowOnce,
    /// Allows this request, and the same handles from the same agent session
    /// for each handle's `grant_ttl`.
    AllowSession,
    Deny,
    /// Denies, and sets the handles to `mode: deny`.
    DenyAlways,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ControlResponse {
    Done {
        #[serde(default)]
        warnings: Vec<String>,
    },
    Session {
        token: SecretText,
    },
    Overview {
        overview: Overview,
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
    /// The session token is unknown, or the vault locked since it was issued.
    SessionEnded,
}

/// Everything `kv tui` shows, from one request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Overview {
    pub status: Status,
    pub handles: Vec<HandleInfo>,
    #[serde(default)]
    pub approvals: Vec<Approval>,
    #[serde(default)]
    pub handle_requests: Vec<RequestedHandle>,
}

/// A handle request waiting for the user. Agent text has been made safe to
/// show.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestedHandle {
    pub id: u64,
    /// Self-reported by the MCP client.
    pub client: Option<String>,
    pub request: HandleRequest,
}

/// A request waiting for approval. Text that came from the agent has
/// control characters replaced and is cut to a safe length.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Approval {
    pub id: u64,
    /// Self-reported by the MCP client.
    pub client: Option<String>,
    /// `http_request` or `exec`.
    pub tool: String,
    /// The handles that need approval.
    pub handles: Vec<String>,
    /// Method and URL, or the argv as a JSON array.
    pub detail: String,
    /// Working directory, for `exec`.
    pub cwd: Option<String>,
    /// Whether `allow_session` can grant anything: the request named its
    /// agent session.
    pub can_grant: bool,
    pub expires_in_secs: u64,
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
