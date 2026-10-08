//! Messages exchanged with the daemon over its two local sockets.
//!
//! Agent-socket responses are built only from `HandleInfo` and status data,
//! so no agent message can carry a secret value. Control requests carry the
//! vault passphrase, because every control command except `lock` and `stop`
//! must prove the user is present.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::policy::{Mode, Policy};
use crate::secret::{HandleInfo, Secret, SecretText};

/// Largest frame either side accepts, in bytes.
pub const MAX_FRAME_LEN: usize = 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AgentRequest {
    ListHandles,
    Status,
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
    Error {
        code: AgentErrorCode,
        message: String,
    },
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
