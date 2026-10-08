//! Per-secret policy and the check every agent request goes through.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::secret::{Secret, SecretKind};

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

/// What the agent wants to do with a handle.
#[derive(Clone, Copy, Debug)]
pub enum Operation<'a> {
    Http {
        method: &'a str,
        url: &'a str,
    },
    DbQuery,
    DbConnect,
    /// `program` is argv[0] exactly as the agent sent it.
    Exec {
        program: &'a str,
    },
}

impl Operation<'_> {
    fn name(&self) -> &'static str {
        match self {
            Self::Http { .. } => "http_request",
            Self::DbQuery => "db_query",
            Self::DbConnect => "db_connect",
            Self::Exec { .. } => "exec",
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Ask,
    Deny(DenyReason),
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum DenyReason {
    #[error("this handle is set to deny")]
    ModeDeny,
    #[error("a {kind:?} handle cannot be used with {op}")]
    WrongKind { kind: SecretKind, op: &'static str },
    #[error("invalid URL: {0}")]
    InvalidUrl(String),
    #[error("plain http is not allowed for this handle; use https")]
    PlainHttp,
    #[error("host {host:?} is not in allowed_hosts {allowed:?}")]
    HostNotAllowed { host: String, allowed: Vec<String> },
    #[error("method {method} is not in allowed_methods {allowed:?}")]
    MethodNotAllowed {
        method: String,
        allowed: Vec<String>,
    },
    #[error("program {program:?} is not in allowed_cmds {allowed:?}")]
    CommandNotAllowed {
        program: String,
        allowed: Vec<String>,
    },
}

pub fn evaluate(secret: &Secret, op: &Operation<'_>) -> Decision {
    let policy = &secret.policy;
    if policy.mode == Mode::Deny {
        return Decision::Deny(DenyReason::ModeDeny);
    }
    let kind = secret.kind();
    let kind_ok = matches!(
        (op, kind),
        (Operation::Http { .. }, SecretKind::Http)
            | (
                Operation::DbQuery | Operation::DbConnect,
                SecretKind::Postgres | SecretKind::Redis
            )
            | (Operation::Exec { .. }, SecretKind::Env)
    );
    if !kind_ok {
        return Decision::Deny(DenyReason::WrongKind {
            kind,
            op: op.name(),
        });
    }
    let check = match op {
        Operation::Http { method, url } => check_http(policy, method, url),
        Operation::Exec { program } => check_exec(policy, program),
        Operation::DbQuery | Operation::DbConnect => Ok(()),
    };
    match check {
        Err(reason) => Decision::Deny(reason),
        Ok(()) if policy.mode == Mode::Auto => Decision::Allow,
        Ok(()) => Decision::Ask,
    }
}

fn check_http(policy: &Policy, method: &str, raw_url: &str) -> Result<(), DenyReason> {
    let url = url::Url::parse(raw_url).map_err(|e| DenyReason::InvalidUrl(e.to_string()))?;
    match url.scheme() {
        "https" => {}
        "http" if policy.allow_plain_http => {}
        "http" => return Err(DenyReason::PlainHttp),
        other => {
            return Err(DenyReason::InvalidUrl(format!(
                "unsupported scheme {other:?}"
            )));
        }
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(DenyReason::InvalidUrl(
            "credentials in the URL are not allowed".into(),
        ));
    }
    let host = url
        .host_str()
        .ok_or_else(|| DenyReason::InvalidUrl("URL has no host".into()))?;
    let host = normalize_host(host);
    if !policy
        .allowed_hosts
        .iter()
        .any(|h| normalize_host(h) == host)
    {
        return Err(DenyReason::HostNotAllowed {
            host,
            allowed: policy.allowed_hosts.clone(),
        });
    }
    if !policy.allowed_methods.is_empty()
        && !policy
            .allowed_methods
            .iter()
            .any(|m| m.eq_ignore_ascii_case(method))
    {
        return Err(DenyReason::MethodNotAllowed {
            method: method.to_ascii_uppercase(),
            allowed: policy.allowed_methods.clone(),
        });
    }
    Ok(())
}

fn normalize_host(host: &str) -> String {
    host.trim_end_matches('.').to_ascii_lowercase()
}

fn check_exec(policy: &Policy, program: &str) -> Result<(), DenyReason> {
    let name = program_name(program);
    if policy.allowed_cmds.iter().any(|c| program_name(c) == name) {
        Ok(())
    } else {
        Err(DenyReason::CommandNotAllowed {
            program: program.to_owned(),
            allowed: policy.allowed_cmds.clone(),
        })
    }
}

/// `C:\tools\Terraform.EXE`, `./terraform` and `terraform` all become
/// `terraform`. Matching is case-insensitive on every platform.
fn program_name(program: &str) -> String {
    let base = program.rsplit(['/', '\\']).next().unwrap_or(program);
    let lower = base.to_ascii_lowercase();
    lower.strip_suffix(".exe").unwrap_or(&lower).to_owned()
}
