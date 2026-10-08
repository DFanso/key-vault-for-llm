//! Daemon state and request handling, kept free of sockets and clocks so it
//! can be tested directly.

use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime};

use kv_core::VaultError;
use kv_core::crypto::KdfParams;
use kv_core::proto::{
    AgentErrorCode, AgentRequest, AgentResponse, ControlCommand, ControlErrorCode, ControlRequest,
    ControlResponse, PolicyPatch, Status,
};
use kv_core::scrub::MIN_SECRET_LEN;
use kv_core::secret::{AuthPlacement, Secret, SecretText, SecretValue};
use kv_core::vault::Vault;

use crate::audit::Audit;
use crate::throttle::Throttle;

/// Argon2 settings for `kv init --insecure-fast-kdf`. Tests only.
const TEST_KDF: KdfParams = KdfParams {
    m_kib: 8,
    t: 1,
    p: 1,
};

#[derive(Clone, Copy, Debug)]
pub struct Settings {
    /// Lock the vault after it has not been used for this long.
    pub idle_lock: Duration,
    /// Exit after receiving no requests for this long while locked.
    pub locked_exit: Duration,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            idle_lock: Duration::from_secs(8 * 60 * 60),
            locked_exit: Duration::from_secs(10 * 60),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum After {
    Continue,
    Stop,
}

pub struct Daemon {
    vault_path: PathBuf,
    vault: Option<Vault>,
    throttle: Throttle,
    audit: Audit,
    settings: Settings,
    /// Last use of the unlocked vault. Drives the idle lock.
    last_used: Instant,
    /// The same moment on the wall clock. `Instant` stops while the machine
    /// sleeps, so the idle lock also checks this.
    last_used_wall: SystemTime,
    /// Last request of any kind. Drives the exit while locked.
    last_request: Instant,
}

struct Failure {
    code: ControlErrorCode,
    message: String,
}

fn fail(code: ControlErrorCode, message: impl Into<String>) -> Failure {
    Failure {
        code,
        message: message.into(),
    }
}

fn internal(error: impl std::fmt::Display) -> Failure {
    fail(ControlErrorCode::Internal, error.to_string())
}

impl Daemon {
    pub fn new(vault_path: PathBuf, audit: Audit, settings: Settings, now: Instant) -> Self {
        Self {
            vault_path,
            vault: None,
            throttle: Throttle::default(),
            audit,
            settings,
            last_used: now,
            last_used_wall: SystemTime::now(),
            last_request: now,
        }
    }

    pub fn is_unlocked(&self) -> bool {
        self.vault.is_some()
    }

    pub fn handle_agent(&mut self, request: AgentRequest, now: Instant) -> AgentResponse {
        self.last_request = now;
        match request {
            AgentRequest::Status => AgentResponse::Status {
                status: self.status(now),
            },
            AgentRequest::ListHandles => {
                let response = match &self.vault {
                    Some(vault) => {
                        self.last_used = now;
                        self.last_used_wall = SystemTime::now();
                        AgentResponse::Handles {
                            handles: vault.secrets().iter().map(Secret::info).collect(),
                        }
                    }
                    None => self.locked_error(),
                };
                self.audit
                    .record("agent", "list_handles", None, agent_outcome(&response));
                response
            }
        }
    }

    pub fn handle_control(
        &mut self,
        request: ControlRequest,
        now: Instant,
    ) -> (ControlResponse, After) {
        self.last_request = now;
        let ControlRequest {
            passphrase,
            command,
        } = request;
        let (action, handle) = describe(&command);
        let mut after = After::Continue;
        let result = match command {
            ControlCommand::Lock => {
                self.vault = None;
                Ok(Vec::new())
            }
            ControlCommand::Stop => {
                self.vault = None;
                after = After::Stop;
                Ok(Vec::new())
            }
            ControlCommand::Init { insecure_fast_kdf } => {
                self.init(passphrase.as_ref(), insecure_fast_kdf, now)
            }
            command => self
                .authenticate(passphrase.as_ref(), now)
                .and_then(|vault| run_authenticated(vault, command)),
        };
        let response = match result {
            Ok(warnings) => ControlResponse::Done { warnings },
            Err(failure) => ControlResponse::Error {
                code: failure.code,
                message: failure.message,
            },
        };
        let outcome = match &response {
            ControlResponse::Done { .. } => "done",
            ControlResponse::Error { .. } => "error",
        };
        self.audit
            .record("control", action, handle.as_deref(), outcome);
        (response, after)
    }

    /// Runs the idle lock and decides whether the daemon should exit. `wall`
    /// is the current wall-clock time, so time spent asleep counts as idle.
    pub fn tick(&mut self, now: Instant, wall: SystemTime) -> After {
        if self.vault.is_some() && self.idle_for(now, wall) >= self.settings.idle_lock {
            self.vault = None;
            self.audit.record("daemon", "idle_lock", None, "locked");
        }
        if self.vault.is_none()
            && now.duration_since(self.last_request) >= self.settings.locked_exit
        {
            return After::Stop;
        }
        After::Continue
    }

    fn touch(&mut self, now: Instant) {
        self.last_used = now;
        self.last_used_wall = SystemTime::now();
    }

    /// The longer of the awake time and the wall-clock time since last use.
    /// A wall clock set backwards counts as zero, leaving the awake time.
    fn idle_for(&self, now: Instant, wall: SystemTime) -> Duration {
        let awake = now.duration_since(self.last_used);
        let elapsed = wall.duration_since(self.last_used_wall).unwrap_or_default();
        awake.max(elapsed)
    }

    fn status(&self, now: Instant) -> Status {
        Status {
            vault_exists: self.vault.is_some() || self.vault_path.exists(),
            locked: self.vault.is_none(),
            handle_count: self.vault.as_ref().map(|v| v.secrets().len()),
            locks_in_secs: self.vault.as_ref().map(|_| {
                self.settings
                    .idle_lock
                    .saturating_sub(self.idle_for(now, SystemTime::now()))
                    .as_secs()
            }),
        }
    }

    fn locked_error(&self) -> AgentResponse {
        if self.vault_path.exists() {
            AgentResponse::Error {
                code: AgentErrorCode::VaultLocked,
                message: "the vault is locked; ask the user to run `kv unlock`".into(),
            }
        } else {
            AgentResponse::Error {
                code: AgentErrorCode::NoVault,
                message: "there is no vault yet; ask the user to run `kv init`".into(),
            }
        }
    }

    fn init(
        &mut self,
        passphrase: Option<&SecretText>,
        insecure_fast_kdf: bool,
        now: Instant,
    ) -> Result<Vec<String>, Failure> {
        let passphrase = passphrase.ok_or_else(|| {
            fail(
                ControlErrorCode::PassphraseRequired,
                "init needs the new passphrase",
            )
        })?;
        let kdf = if insecure_fast_kdf {
            TEST_KDF
        } else {
            KdfParams::RECOMMENDED
        };
        match Vault::create(&self.vault_path, passphrase.expose(), kdf) {
            Ok(vault) => {
                self.vault = Some(vault);
                self.touch(now);
                Ok(Vec::new())
            }
            Err(VaultError::AlreadyExists(_)) => Err(fail(
                ControlErrorCode::VaultExists,
                "a vault already exists",
            )),
            Err(VaultError::WeakPassphrase) => Err(fail(
                ControlErrorCode::Invalid,
                "the passphrase must be at least 8 characters",
            )),
            Err(e) => Err(internal(e)),
        }
    }

    /// Checks the passphrase, unlocking the vault if it is locked, and
    /// returns the unlocked vault. Wrong passphrases count toward the backoff.
    fn authenticate(
        &mut self,
        passphrase: Option<&SecretText>,
        now: Instant,
    ) -> Result<&mut Vault, Failure> {
        let passphrase = passphrase.ok_or_else(|| {
            fail(
                ControlErrorCode::PassphraseRequired,
                "this command needs the vault passphrase",
            )
        })?;
        if let Err(wait) = self.throttle.check(now) {
            return Err(fail(
                ControlErrorCode::TooManyAttempts,
                format!(
                    "too many wrong passphrases; try again in {}s",
                    wait.as_secs().max(1)
                ),
            ));
        }
        let result = if let Some(vault) = &self.vault {
            vault.verify_passphrase(passphrase.expose())
        } else {
            Vault::unlock(&self.vault_path, passphrase.expose()).map(|vault| {
                self.vault = Some(vault);
            })
        };
        match result {
            Ok(()) => {
                self.throttle.record_success();
                self.touch(now);
                Ok(self
                    .vault
                    .as_mut()
                    .expect("authenticated vault is unlocked"))
            }
            Err(VaultError::WrongPassphrase) => {
                self.throttle.record_failure(now);
                Err(fail(ControlErrorCode::WrongPassphrase, "wrong passphrase"))
            }
            Err(VaultError::NotFound(_)) => Err(fail(
                ControlErrorCode::NoVault,
                "there is no vault yet; run `kv init`",
            )),
            Err(e) => Err(internal(e)),
        }
    }
}

fn run_authenticated(vault: &mut Vault, command: ControlCommand) -> Result<Vec<String>, Failure> {
    match command {
        ControlCommand::Add { secret, replace } => add(vault, secret, replace),
        ControlCommand::Remove { name } => remove(vault, &name),
        ControlCommand::SetPolicy { name, patch } => set_policy(vault, &name, &patch),
        ControlCommand::ChangePassphrase { new_passphrase } => {
            match vault.change_passphrase(new_passphrase.expose(), KdfParams::RECOMMENDED) {
                Ok(()) => Ok(Vec::new()),
                Err(VaultError::WeakPassphrase) => Err(fail(
                    ControlErrorCode::Invalid,
                    "the passphrase must be at least 8 characters",
                )),
                Err(e) => Err(internal(e)),
            }
        }
        ControlCommand::Unlock
        | ControlCommand::Init { .. }
        | ControlCommand::Lock
        | ControlCommand::Stop => Ok(Vec::new()),
    }
}

fn add(vault: &mut Vault, secret: Secret, replace: bool) -> Result<Vec<String>, Failure> {
    validate_value(&secret.value)?;
    let previous = vault.get(&secret.name).cloned();
    if previous.is_some() && !replace {
        return Err(fail(
            ControlErrorCode::HandleExists,
            format!(
                "{} already exists; use --replace to overwrite it",
                secret.name
            ),
        ));
    }
    let warnings = warnings_for(&secret);
    let name = secret.name.clone();
    vault
        .upsert(secret)
        .map_err(|e| fail(ControlErrorCode::Invalid, e.to_string()))?;
    save_or_restore(vault, &name, previous)?;
    Ok(warnings)
}

fn remove(vault: &mut Vault, name: &str) -> Result<Vec<String>, Failure> {
    let previous = vault.get(name).cloned().ok_or_else(|| unknown(name))?;
    vault.remove(name);
    save_or_restore(vault, name, Some(previous))?;
    Ok(Vec::new())
}

fn set_policy(vault: &mut Vault, name: &str, patch: &PolicyPatch) -> Result<Vec<String>, Failure> {
    let previous = vault.get(name).cloned().ok_or_else(|| unknown(name))?;
    let mut updated = previous.clone();
    patch.apply(&mut updated.policy);
    let warnings = warnings_for(&updated);
    vault
        .upsert(updated)
        .map_err(|e| fail(ControlErrorCode::Invalid, e.to_string()))?;
    save_or_restore(vault, name, Some(previous))?;
    Ok(warnings)
}

/// Saves, or puts `name` back the way it was if the save fails, so memory
/// never holds changes that are not on disk.
fn save_or_restore(vault: &mut Vault, name: &str, previous: Option<Secret>) -> Result<(), Failure> {
    let Err(error) = vault.save() else {
        return Ok(());
    };
    match previous {
        Some(secret) => {
            let _ = vault.upsert(secret);
        }
        None => {
            vault.remove(name);
        }
    }
    Err(internal(format!("could not save the vault: {error}")))
}

fn unknown(name: &str) -> Failure {
    fail(
        ControlErrorCode::UnknownHandle,
        format!("there is no handle named {name}"),
    )
}

fn validate_value(value: &SecretValue) -> Result<(), Failure> {
    let invalid = |message: &str| Err(fail(ControlErrorCode::Invalid, message));
    match value {
        SecretValue::Http {
            token,
            placement,
            base_url,
        } => {
            if token.expose().is_empty() {
                return invalid("the token is empty");
            }
            if let Some(base) = base_url {
                let Ok(parsed) = url::Url::parse(base) else {
                    return invalid("the base URL is not a valid URL");
                };
                if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
                    return invalid("the base URL must start with https:// or http://");
                }
                if !parsed.username().is_empty()
                    || parsed.password().is_some()
                    || parsed.query().is_some()
                    || parsed.fragment().is_some()
                {
                    return invalid(
                        "the base URL cannot contain credentials, a query or a fragment",
                    );
                }
            }
            match placement {
                AuthPlacement::Header { name, template } => {
                    if name.is_empty() {
                        return invalid("the header name is empty");
                    }
                    if !template.contains("{}") {
                        return invalid("the header template must contain {} where the token goes");
                    }
                }
                AuthPlacement::Query { param } => {
                    if param.is_empty() {
                        return invalid("the query parameter name is empty");
                    }
                }
            }
        }
        SecretValue::Postgres { url } | SecretValue::Redis { url } => {
            if url.expose().is_empty() {
                return invalid("the connection URL is empty");
            }
        }
        SecretValue::Env { vars } => {
            if vars.is_empty() {
                return invalid("an env secret needs at least one variable");
            }
            if vars.keys().any(|k| k.is_empty() || k.contains(['=', '\0'])) {
                return invalid("variable names must be non-empty and contain no '=' or NUL");
            }
        }
    }
    Ok(())
}

fn warnings_for(secret: &Secret) -> Vec<String> {
    let name = &secret.name;
    let mut warnings = Vec::new();
    let short = |value: &SecretText| value.expose().chars().count() < MIN_SECRET_LEN;
    let mut short_values: Vec<String> = Vec::new();
    match &secret.value {
        SecretValue::Http { token, .. } if short(token) => short_values.push(name.clone()),
        SecretValue::Postgres { url } | SecretValue::Redis { url } if short(url) => {
            short_values.push(name.clone())
        }
        SecretValue::Env { vars } => short_values.extend(
            vars.iter()
                .filter(|(_, v)| short(v))
                .map(|(k, _)| k.clone()),
        ),
        _ => {}
    }
    for value_name in short_values {
        warnings.push(format!(
            "the value of {value_name} is shorter than {MIN_SECRET_LEN} characters, so kv cannot scrub it from output"
        ));
    }
    match &secret.value {
        SecretValue::Http {
            base_url: Some(base),
            ..
        } if base.starts_with("http:") && !secret.policy.allow_plain_http => {
            warnings.push(format!(
                "{name} has a plain http:// base URL, so every request with it is denied until you run `kv policy {name} --allow-plain-http true`"
            ));
        }
        SecretValue::Http { base_url: None, .. } if secret.policy.allowed_hosts.is_empty() => {
            warnings.push(format!(
                "{name} has no allowed hosts, so every request with it is denied; add one with `kv policy {name} --host <host>`"
            ));
        }
        SecretValue::Env { .. } if secret.policy.allowed_cmds.is_empty() => {
            warnings.push(format!(
                "{name} has no allowed commands, so every exec with it is denied; add one with `kv policy {name} --cmd <program>`"
            ));
        }
        _ => {}
    }
    warnings
}

fn describe(command: &ControlCommand) -> (&'static str, Option<String>) {
    match command {
        ControlCommand::Init { .. } => ("init", None),
        ControlCommand::Unlock => ("unlock", None),
        ControlCommand::Lock => ("lock", None),
        ControlCommand::Stop => ("stop", None),
        ControlCommand::Add { secret, .. } => ("add", Some(secret.name.clone())),
        ControlCommand::Remove { name } => ("remove", Some(name.clone())),
        ControlCommand::SetPolicy { name, .. } => ("set_policy", Some(name.clone())),
        ControlCommand::ChangePassphrase { .. } => ("change_passphrase", None),
    }
}

fn agent_outcome(response: &AgentResponse) -> &'static str {
    match response {
        AgentResponse::Error { .. } => "error",
        _ => "done",
    }
}
