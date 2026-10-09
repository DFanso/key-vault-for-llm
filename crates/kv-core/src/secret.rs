//! Secret records, the agent-visible view of them, and the values the
//! scrubber must hide.

use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;

use percent_encoding::percent_decode_str;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::VaultError;
use crate::policy::{Mode, Policy};

/// A secret string. Zeroed on drop; `Debug` never shows it.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SecretText(Zeroizing<String>);

impl SecretText {
    pub fn new(value: impl Into<String>) -> Self {
        Self(Zeroizing::new(value.into()))
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SecretKind {
    Http,
    Postgres,
    Redis,
    Env,
}

/// Where an HTTP token goes on the outgoing request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum AuthPlacement {
    /// `template` contains `{}` where the token is inserted, e.g. `Bearer {}`.
    Header {
        name: String,
        template: String,
    },
    Query {
        param: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum SecretValue {
    Http {
        token: SecretText,
        placement: AuthPlacement,
        /// Keeps the service's address hidden too: agents send a path, which
        /// is appended to this URL, e.g. `https://dokploy.example.com/api`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        base_url: Option<String>,
    },
    Postgres {
        url: SecretText,
    },
    Redis {
        url: SecretText,
    },
    Env {
        vars: BTreeMap<String, SecretText>,
    },
}

impl SecretValue {
    pub fn kind(&self) -> SecretKind {
        match self {
            Self::Http { .. } => SecretKind::Http,
            Self::Postgres { .. } => SecretKind::Postgres,
            Self::Redis { .. } => SecretKind::Redis,
            Self::Env { .. } => SecretKind::Env,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Secret {
    pub name: String,
    pub description: String,
    pub value: SecretValue,
    pub policy: Policy,
    /// Unix seconds. Set by `Vault::upsert`.
    pub created_at: u64,
    pub updated_at: u64,
}

/// What an agent may learn about a handle. Has no field that can hold a
/// secret value, so it is safe to send over the agent socket.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandleInfo {
    pub name: String,
    pub kind: SecretKind,
    pub description: String,
    pub mode: Mode,
    pub allowed_hosts: Vec<String>,
    pub allow_plain_http: bool,
    pub allowed_methods: Vec<String>,
    pub read_only: bool,
    pub allowed_cmds: Vec<String>,
    #[serde(with = "humantime_serde")]
    pub grant_ttl: Duration,
    /// Names of the variables an `env` secret injects.
    pub env_vars: Vec<String>,
    /// `http_request` with this handle takes a path such as `/v1/items`
    /// instead of a URL; the service's address stays hidden.
    pub takes_path: bool,
    /// `http`: where kv puts the token. Names a header or query parameter,
    /// never the token itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<AuthPlacement>,
}

impl Secret {
    pub fn kind(&self) -> SecretKind {
        self.value.kind()
    }

    pub fn info(&self) -> HandleInfo {
        let env_vars = match &self.value {
            SecretValue::Env { vars } => vars.keys().cloned().collect(),
            _ => Vec::new(),
        };
        let auth = match &self.value {
            SecretValue::Http { placement, .. } => Some(placement.clone()),
            _ => None,
        };
        HandleInfo {
            name: self.name.clone(),
            kind: self.kind(),
            description: self.description.clone(),
            mode: self.policy.mode,
            allowed_hosts: self.policy.allowed_hosts.clone(),
            allow_plain_http: self.policy.allow_plain_http,
            allowed_methods: self.policy.allowed_methods.clone(),
            read_only: self.policy.read_only,
            allowed_cmds: self.policy.allowed_cmds.clone(),
            grant_ttl: self.policy.grant_ttl,
            env_vars,
            takes_path: matches!(
                self.value,
                SecretValue::Http {
                    base_url: Some(_),
                    ..
                }
            ),
            auth,
        }
    }

    /// Every string that must never appear in output: the token or URL, for
    /// connection URLs the password both as written and percent-decoded and
    /// the host unless it is loopback, and for an http `base_url` the URL
    /// and its host.
    pub fn sensitive_values(&self) -> Vec<Zeroizing<String>> {
        let mut out = Vec::new();
        match &self.value {
            SecretValue::Http {
                token, base_url, ..
            } => {
                out.push(Zeroizing::new(token.expose().to_owned()));
                if let Some(base) = base_url {
                    out.push(Zeroizing::new(base.trim_end_matches('/').to_owned()));
                    if let Some(host) = url::Url::parse(base)
                        .ok()
                        .and_then(|u| u.host_str().map(str::to_owned))
                    {
                        out.push(Zeroizing::new(host));
                    }
                }
            }
            SecretValue::Postgres { url } | SecretValue::Redis { url } => {
                out.push(Zeroizing::new(url.expose().to_owned()));
                let parsed = url::Url::parse(url.expose()).ok();
                if let Some(host) = parsed.as_ref().and_then(url::Url::host)
                    && !is_loopback(&host)
                {
                    out.push(Zeroizing::new(host.to_string()));
                }
                if let Some(parsed) = &parsed
                    && let Some(password) = parsed.password()
                {
                    out.push(Zeroizing::new(password.to_owned()));
                    let decoded = percent_decode_str(password).decode_utf8_lossy();
                    if decoded != password {
                        out.push(Zeroizing::new(decoded.into_owned()));
                    }
                }
            }
            SecretValue::Env { vars } => {
                out.extend(vars.values().map(|v| Zeroizing::new(v.expose().to_owned())));
            }
        }
        out
    }
}

/// `localhost` and loopback addresses say nothing about where a database
/// lives, and scrubbing them would mangle ordinary output. In `postgres://`
/// and `redis://` URLs an IPv4 address arrives as a domain name.
fn is_loopback(host: &url::Host<&str>) -> bool {
    match host {
        url::Host::Domain(name) => {
            name.eq_ignore_ascii_case("localhost")
                || name
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback())
        }
        url::Host::Ipv4(ip) => ip.is_loopback(),
        url::Host::Ipv6(ip) => ip.is_loopback(),
    }
}

/// Handle names: 1-63 chars of `[a-z0-9_-]`, starting with `[a-z0-9]`.
pub fn validate_handle(name: &str) -> Result<(), VaultError> {
    let mut chars = name.chars();
    let first_ok = chars
        .next()
        .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit());
    let rest_ok =
        chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_');
    if first_ok && rest_ok && name.len() <= 63 {
        Ok(())
    } else {
        Err(VaultError::InvalidHandle(name.to_owned()))
    }
}
