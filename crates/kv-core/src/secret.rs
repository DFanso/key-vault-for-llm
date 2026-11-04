//! Secret records, the agent-visible view of them, and the values the
//! scrubber must hide.

use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use percent_encoding::percent_decode_str;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::envvars::MAX_VALUE_LEN;
use crate::error::VaultError;
use crate::policy::{Mode, Policy};
use crate::scrub::MIN_SECRET_LEN;

/// Most bytes one `file` handle holds. A share of it has to fit the
/// vault, the control socket's frame and a chat attachment.
pub const MAX_FILE_LEN: usize = 1024 * 1024;

/// Longest file name a `file` handle keeps, in bytes.
const MAX_FILE_NAME_LEN: usize = 255;

/// Why a file cannot become a handle's value.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FileError {
    #[error("the file has no name")]
    NoName,
    #[error("the file's name is not one kv can keep")]
    BadName,
    #[error("a file handle holds at most 1 MiB, and this file is {0} bytes")]
    TooLarge(usize),
    /// The bytes are not the ones the value's SHA-256 was made from, or do
    /// not decode.
    #[error("the file is not the one that was sent: its contents do not match its checksum")]
    Altered,
}

/// The part of `name` after the last `/` or `\`: all a file handle keeps of
/// where a file came from, and all a receiver is told, so a share can never
/// carry a path that climbs out of the folder the file is saved in.
pub fn file_base_name(name: &str) -> Result<String, FileError> {
    let base = name.rsplit(['/', '\\']).next().unwrap_or_default().trim();
    if base.is_empty() {
        return Err(FileError::NoName);
    }
    if matches!(base, "." | "..")
        || base.len() > MAX_FILE_NAME_LEN
        || base.chars().any(char::is_control)
    {
        return Err(FileError::BadName);
    }
    Ok(base.to_owned())
}

/// The variable that carries a `file` handle's path to a program kv
/// starts: `KV_FILE_` and the handle's name in capitals.
pub fn file_env_var(handle: &str) -> String {
    format!("KV_FILE_{}", handle.to_ascii_uppercase().replace('-', "_"))
}

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
    File,
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
    /// Any file, kept as it is: raw bytes, never read as text. kv hands
    /// it to programs as a file and never shows it to an agent.
    File {
        /// The file's base name, kept so a program and a receiver see it.
        file_name: String,
        /// The file's bytes as standard padded base64.
        data: SecretText,
        /// SHA-256 of the bytes, in lowercase hex. A share carries it so
        /// the receiver can tell the file arrived exactly as it left.
        #[serde(default)]
        sha256: String,
    },
}

impl SecretValue {
    pub fn kind(&self) -> SecretKind {
        match self {
            Self::Http { .. } => SecretKind::Http,
            Self::Postgres { .. } => SecretKind::Postgres,
            Self::Redis { .. } => SecretKind::Redis,
            Self::Env { .. } => SecretKind::Env,
            Self::File { .. } => SecretKind::File,
        }
    }

    /// A `file` value holding `bytes` exactly, under the base name of
    /// `file_name`.
    pub fn file(file_name: &str, bytes: &[u8]) -> Result<Self, FileError> {
        let file_name = file_base_name(file_name)?;
        if bytes.len() > MAX_FILE_LEN {
            return Err(FileError::TooLarge(bytes.len()));
        }
        Ok(Self::File {
            file_name,
            data: SecretText::new(STANDARD.encode(bytes)),
            sha256: hex::encode(Sha256::digest(bytes)),
        })
    }

    /// Checks that a `file` value is what it says: a usable base name,
    /// bytes that decode and fit, and a checksum that matches them. A
    /// value of another kind passes.
    pub fn verify_file(&self) -> Result<(), FileError> {
        let Self::File {
            file_name, sha256, ..
        } = self
        else {
            return Ok(());
        };
        if file_base_name(file_name)? != *file_name {
            return Err(FileError::BadName);
        }
        let (_, bytes) = self.file_parts().ok_or(FileError::Altered)?;
        if bytes.len() > MAX_FILE_LEN {
            return Err(FileError::TooLarge(bytes.len()));
        }
        if hex::encode(Sha256::digest(&bytes[..])) != *sha256 {
            return Err(FileError::Altered);
        }
        Ok(())
    }

    /// Twelve characters such as `A1B2-C3D4-E5F6` from the file's
    /// checksum, which the sender and the receiver can read out to each
    /// other to confirm the same file.
    pub fn file_fingerprint(&self) -> Option<String> {
        let Self::File { sha256, .. } = self else {
            return None;
        };
        let head = sha256.get(..12)?.to_ascii_uppercase();
        Some(format!("{}-{}-{}", &head[..4], &head[4..8], &head[8..]))
    }

    /// A `file` value's name and bytes; `None` for any other kind, or
    /// bytes that do not decode.
    pub fn file_parts(&self) -> Option<(String, Zeroizing<Vec<u8>>)> {
        let Self::File {
            file_name, data, ..
        } = self
        else {
            return None;
        };
        let bytes = STANDARD.decode(data.expose()).ok()?;
        Some((file_name.clone(), Zeroizing::new(bytes)))
    }

    /// The size in bytes of a `file` value's file.
    pub fn file_len(&self) -> Option<usize> {
        let Self::File { data, .. } = self else {
            return None;
        };
        let text = data.expose();
        let padding = text.bytes().rev().take_while(|b| *b == b'=').count();
        Some((text.len() / 4 * 3).saturating_sub(padding))
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
    /// Whether kv saved this handle from a share: its variable names were
    /// picked by someone else. The daemon sets it when it adds or receives
    /// a handle and keeps it through edits; `None` only in a vault saved
    /// before kv kept it, which `Vault` settles when it opens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_share: Option<bool>,
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
    /// `env`: the file name of the program the handle's `run` command
    /// starts, never its arguments.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runs: Option<String>,
}

impl Secret {
    pub fn kind(&self) -> SecretKind {
        self.value.kind()
    }

    pub fn info(&self) -> HandleInfo {
        let env_vars = match &self.value {
            SecretValue::Env { vars } => vars.keys().cloned().collect(),
            SecretValue::File { .. } => vec![file_env_var(&self.name)],
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
            runs: self
                .policy
                .run
                .as_ref()
                .and_then(|argv| argv.first())
                .map(|program| crate::policy::program_name(program)),
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
            SecretValue::Postgres { url } => {
                let url = url.expose();
                out.push(Zeroizing::new(url.to_owned()));
                for host in crate::db::postgres_hosts(url) {
                    if !crate::db::is_local(&host) {
                        out.push(Zeroizing::new(host));
                    }
                }
                for password in crate::db::postgres_passwords(url) {
                    let decoded = percent_decode_str(&password).decode_utf8_lossy();
                    if decoded != password {
                        out.push(Zeroizing::new(decoded.into_owned()));
                    }
                    out.push(Zeroizing::new(password));
                }
            }
            SecretValue::Redis { url } => {
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
            SecretValue::File { .. } => out.extend(self.file_lines()),
        }
        out
    }

    /// For a text file, each line a program could print: the scrubber
    /// cannot take the whole file, but it takes its lines. A binary file
    /// has none. Lines too short to scrub are left out, repeats kept once,
    /// and a line longer than a value may be is cut into pieces that are.
    fn file_lines(&self) -> Vec<Zeroizing<String>> {
        let Some((_, bytes)) = self.value.file_parts() else {
            return Vec::new();
        };
        let Ok(text) = std::str::from_utf8(&bytes) else {
            return Vec::new();
        };
        if text.contains('\0') {
            return Vec::new();
        }
        let mut seen = std::collections::BTreeSet::new();
        let mut out = Vec::new();
        for line in text.lines().map(str::trim) {
            let chars: Vec<char> = line.chars().collect();
            for piece in chars.chunks(MAX_VALUE_LEN) {
                let piece: String = piece.iter().collect();
                if piece.chars().count() >= MIN_SECRET_LEN && seen.insert(piece.clone()) {
                    out.push(Zeroizing::new(piece));
                }
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
