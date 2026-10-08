//! Per-secret policy and the check every agent request goes through.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::secret::{Secret, SecretKind, SecretValue};

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
    /// `http`: where the token may be sent, as `host` (default port only) or
    /// `host:port`. Empty denies all.
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
    /// `env`: programs allowed to receive the variables, as a bare name looked
    /// up on PATH or an absolute path. Empty denies all.
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
    /// Deliberately vague: the base URL is hidden from the agent.
    #[error("this handle only reaches its own service; send a path such as /v1/items")]
    OutsideBaseUrl,
    #[error("invalid path: {0}")]
    InvalidPath(&'static str),
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
        Operation::Http { method, url } => {
            base_url(secret).and_then(|base| check_http(policy, base.as_ref(), method, url))
        }
        Operation::Exec { program } => check_exec(policy, program),
        Operation::DbQuery | Operation::DbConnect => Ok(()),
    };
    match check {
        Err(reason) => Decision::Deny(reason),
        Ok(()) if policy.mode == Mode::Auto => Decision::Allow,
        Ok(()) => Decision::Ask,
    }
}

/// The URL an `http_request` goes to. A handle with a `base_url` takes a
/// path, which is appended to the base URL's path and may not climb out of
/// it; any other http handle takes an absolute URL.
pub fn http_target(secret: &Secret, requested: &str) -> Result<url::Url, DenyReason> {
    let Some(base) = base_url(secret)? else {
        if requested.starts_with('/') {
            return Err(DenyReason::InvalidUrl(
                "this handle takes a full URL such as https://host/path".into(),
            ));
        }
        return url::Url::parse(requested).map_err(|e| DenyReason::InvalidUrl(e.to_string()));
    };
    check_path(requested)?;
    let prefix = base.path().trim_end_matches('/');
    let joined = format!("{}{prefix}{requested}", base.origin().ascii_serialization());
    let url = url::Url::parse(&joined).map_err(|_| DenyReason::InvalidPath("not a valid path"))?;
    let path = url.path();
    let inside = path == prefix || path.starts_with(&format!("{prefix}/"));
    if url.origin() != base.origin() || !inside {
        return Err(DenyReason::OutsideBaseUrl);
    }
    Ok(url)
}

/// Rejects paths that could leave the base URL's path once a server decodes
/// them: dot segments (also percent-encoded), encoded slashes and
/// backslashes.
fn check_path(path: &str) -> Result<(), DenyReason> {
    if !path.starts_with('/') {
        return Err(DenyReason::InvalidPath(
            "send a path starting with /, such as /v1/items; this handle's address is fixed",
        ));
    }
    if path.starts_with("//") {
        return Err(DenyReason::InvalidPath("a path cannot start with //"));
    }
    if path.contains(['\\', '#']) {
        return Err(DenyReason::InvalidPath(
            "backslashes and fragments are not allowed",
        ));
    }
    let path_only = path.split('?').next().unwrap_or_default();
    let lower = path_only.to_ascii_lowercase();
    if lower.contains("%2f") || lower.contains("%5c") {
        return Err(DenyReason::InvalidPath("encoded slashes are not allowed"));
    }
    let dot_segment = path_only.split('/').any(|segment| {
        let decoded = percent_encoding::percent_decode_str(segment).decode_utf8_lossy();
        decoded == "." || decoded == ".."
    });
    if dot_segment {
        return Err(DenyReason::InvalidPath(". and .. segments are not allowed"));
    }
    Ok(())
}

/// The parsed `base_url` of an http secret, if it has one.
fn base_url(secret: &Secret) -> Result<Option<url::Url>, DenyReason> {
    match &secret.value {
        SecretValue::Http {
            base_url: Some(base),
            ..
        } => url::Url::parse(base)
            .map(Some)
            .map_err(|_| DenyReason::InvalidUrl("this handle's base URL is invalid".into())),
        _ => Ok(None),
    }
}

fn check_http(
    policy: &Policy,
    base: Option<&url::Url>,
    method: &str,
    raw_url: &str,
) -> Result<(), DenyReason> {
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
    let port = url
        .port_or_known_default()
        .ok_or_else(|| DenyReason::InvalidUrl("URL has no port".into()))?;
    let target = (normalize_host(host), port);
    match base {
        Some(base) if url.origin() != base.origin() => return Err(DenyReason::OutsideBaseUrl),
        Some(_) => {}
        None if !policy
            .allowed_hosts
            .iter()
            .any(|entry| host_entry(url.scheme(), entry).as_ref() == Some(&target)) =>
        {
            return Err(DenyReason::HostNotAllowed {
                host: format!("{}:{}", target.0, target.1),
                allowed: policy.allowed_hosts.clone(),
            });
        }
        None => {}
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

/// Whether `entry` is an `allowed_hosts` entry written in plain ASCII, so
/// what the user reads is the host the token goes to: no lookalike letters
/// and no commas that a list would split on.
pub fn is_host_entry(entry: &str) -> bool {
    entry.is_ascii() && !entry.contains(',') && host_entry("https", entry).is_some()
}

fn normalize_host(host: &str) -> String {
    host.trim_end_matches('.').to_ascii_lowercase()
}

/// Parses an `allowed_hosts` entry (`host`, `host:port`, `[v6]:port` or a
/// bare IPv6 address) into the host and port it permits for `scheme`. A
/// bare host permits only the scheme's default port. Malformed entries
/// permit nothing.
fn host_entry(scheme: &str, entry: &str) -> Option<(String, u16)> {
    let entry = entry.trim();
    if entry.is_empty() {
        return None;
    }
    let authority = if entry.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{entry}]")
    } else {
        entry.to_owned()
    };
    let url = url::Url::parse(&format!("{scheme}://{authority}/")).ok()?;
    if !url.username().is_empty() || url.password().is_some() || url.path() != "/" {
        return None;
    }
    Some((
        normalize_host(url.host_str()?),
        url.port_or_known_default()?,
    ))
}

fn check_exec(policy: &Policy, program: &str) -> Result<(), DenyReason> {
    let allowed = !program.trim().is_empty()
        && policy
            .allowed_cmds
            .iter()
            .any(|entry| cmd_matches(entry.trim(), program));
    if allowed {
        Ok(())
    } else {
        Err(DenyReason::CommandNotAllowed {
            program: program.to_owned(),
            allowed: policy.allowed_cmds.clone(),
        })
    }
}

/// A bare entry (`terraform`) matches only a bare argv[0], which the runner
/// resolves through PATH; `./terraform` or `/tmp/x/terraform` do not match
/// it. A path entry matches only that exact path. On Windows, matching
/// ignores case and a trailing `.exe`.
fn cmd_matches(entry: &str, program: &str) -> bool {
    if entry.is_empty() {
        return false;
    }
    let entry_is_path = has_separator(entry);
    if has_separator(program) {
        entry_is_path
            && std::path::Path::new(entry).is_absolute()
            && canonical_cmd(entry) == canonical_cmd(program)
    } else {
        !entry_is_path && canonical_cmd(entry) == canonical_cmd(program)
    }
}

fn has_separator(s: &str) -> bool {
    s.contains('/') || (cfg!(windows) && s.contains('\\'))
}

fn canonical_cmd(s: &str) -> String {
    if cfg!(windows) {
        let lower = s.to_ascii_lowercase();
        lower.strip_suffix(".exe").unwrap_or(&lower).to_owned()
    } else {
        s.to_owned()
    }
}
