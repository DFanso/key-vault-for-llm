//! Per-secret policy and the check every agent request goes through.

use std::time::Duration;

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Auto,
    #[default]
    Ask,
    Deny,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Policy {
    #[serde(default)]
    pub mode: Mode,
    /// `http`: exact hostnames the token may be sent to. Empty denies all.
    #[serde(default)]
    pub allowed_hosts: Vec<String>,
    #[serde(default)]
    pub allow_plain_http: bool,
    /// `http`: allowed methods. Empty allows any method.
    #[serde(default)]
    pub allowed_methods: Vec<String>,
    /// `postgres`/`redis`: enforced by the database layer, not here.
    #[serde(default)]
    pub read_only: bool,
    /// `env`: program names allowed to receive the variables. Empty denies all.
    #[serde(default)]
    pub allowed_cmds: Vec<String>,
    #[serde(with = "humantime_serde", default = "default_grant_ttl")]
    pub grant_ttl: Duration,
}

fn default_grant_ttl() -> Duration {
    Duration::from_secs(15 * 60)
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            mode: Mode::Ask,
            allowed_hosts: Vec::new(),
            allow_plain_http: false,
            allowed_methods: Vec::new(),
            read_only: false,
            allowed_cmds: Vec::new(),
            grant_ttl: default_grant_ttl(),
        }
    }
}
