//! Daemon state and request handling, kept free of sockets and clocks so it
//! can be tested directly.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use kv_core::VaultError;
use kv_core::crypto::KdfParams;
use kv_core::policy::{Decision, DenyReason, Operation, evaluate, http_target};
use kv_core::proto::{
    AgentErrorCode, AgentRequest, AgentResponse, ControlCommand, ControlErrorCode, ControlRequest,
    ControlResponse, ExecCall, HttpCall, PolicyPatch, Status,
};
use kv_core::scrub::{MIN_SECRET_LEN, Scrubber};
use kv_core::secret::{AuthPlacement, Secret, SecretText, SecretValue};
use kv_core::vault::Vault;
use zeroize::Zeroizing;

use crate::audit::{Audit, Use};
use crate::broker::{ExecJob, HttpJob};
use crate::throttle::Throttle;

const DEFAULT_EXEC_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_EXEC_TIMEOUT: Duration = Duration::from_secs(600);

/// Headers kv sets itself, that would change how the request is framed, or
/// that would let a response carry a secret past the scrubber: compressed,
/// or cut into pieces too short to match.
const RESERVED_HEADERS: [&str; 13] = [
    "host",
    "content-length",
    "transfer-encoding",
    "connection",
    "upgrade",
    "te",
    "trailer",
    "keep-alive",
    "proxy-authorization",
    "proxy-connection",
    "accept-encoding",
    "range",
    "if-range",
];

/// Headers many frameworks and gateways read as the real method, which would
/// get around `allowed_methods`.
const METHOD_OVERRIDES: [&str; 3] = [
    "x-http-method-override",
    "x-http-method",
    "x-method-override",
];

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
    /// Built from the unlocked secrets on first use; cleared whenever they
    /// may have changed.
    scrubber: Option<Arc<Scrubber>>,
}

/// The outcome of an agent request: either an answer now, or authorized
/// work for the broker to run without holding the daemon lock.
pub enum Prepared {
    Reply(AgentResponse),
    Http(Box<HttpJob>),
    Exec(Box<ExecJob>),
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
            scrubber: None,
        }
    }

    pub fn is_unlocked(&self) -> bool {
        self.vault.is_some()
    }

    pub fn prepare(&mut self, request: AgentRequest, now: Instant) -> Prepared {
        self.last_request = now;
        match request {
            AgentRequest::Status => Prepared::Reply(AgentResponse::Status {
                status: self.status(now),
            }),
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
                Prepared::Reply(response)
            }
            AgentRequest::HttpRequest(call) => self.prepare_http(call, now),
            AgentRequest::Exec(call) => self.prepare_exec(call, now),
        }
    }

    fn prepare_http(&mut self, call: HttpCall, now: Instant) -> Prepared {
        let summary = format!("{} {}", call.method, call.url);
        let refuse = |daemon: &Self, decision, response| {
            daemon.refuse("http_request", &call.handle, &summary, decision, response)
        };
        let Some(vault) = &self.vault else {
            return refuse(self, "locked", self.locked_error());
        };
        let Some(secret) = vault.get(&call.handle).cloned() else {
            return refuse(self, "invalid", unknown_handle(vault, &call.handle));
        };
        let url = match http_target(&secret, &call.url) {
            Ok(url) => url,
            Err(reason @ (DenyReason::InvalidUrl(_) | DenyReason::InvalidPath(_))) => {
                return refuse(
                    self,
                    "invalid",
                    agent_error(AgentErrorCode::BadRequest, reason),
                );
            }
            Err(reason) => {
                return refuse(
                    self,
                    "policy",
                    agent_error(AgentErrorCode::PolicyDenied, reason),
                );
            }
        };
        if let Err(message) =
            check_method(&call.method).and_then(|()| check_headers(&secret, &call.headers))
        {
            return refuse(
                self,
                "invalid",
                agent_error(AgentErrorCode::BadRequest, message),
            );
        }
        let operation = Operation::Http {
            method: &call.method,
            url: url.as_str(),
        };
        match evaluate(&secret, &operation) {
            Decision::Allow => {}
            Decision::Deny(reason) => {
                return refuse(
                    self,
                    "policy",
                    agent_error(AgentErrorCode::PolicyDenied, reason),
                );
            }
            Decision::Ask => return refuse(self, "denied", approval_needed(&call.handle)),
        }
        self.touch(now);
        Prepared::Http(Box::new(HttpJob {
            secret,
            url,
            call,
            scrubber: self.scrubber(),
            audit: self.audit.clone(),
            started: now,
        }))
    }

    fn prepare_exec(&mut self, call: ExecCall, now: Instant) -> Prepared {
        let handles = call.handles.join(",");
        let summary = call.argv.first().cloned().unwrap_or_default();
        let refuse = |daemon: &Self, decision, response| {
            daemon.refuse("exec", &handles, &summary, decision, response)
        };
        let bad = |message: &str| agent_error(AgentErrorCode::BadRequest, message);
        let Some(vault) = &self.vault else {
            return refuse(self, "locked", self.locked_error());
        };
        let Some(program) = call.argv.first().filter(|p| !p.is_empty()) else {
            return refuse(
                self,
                "invalid",
                bad("argv must start with the program to run"),
            );
        };
        if call.handles.is_empty() {
            return refuse(self, "invalid", bad("exec needs at least one env handle"));
        }
        // Only the form is checked here: touching the disk under the daemon
        // lock could hang every request on a stalled network mount. The
        // runner checks that the directory exists.
        if !call.cwd.is_absolute() {
            return refuse(self, "invalid", bad("cwd must be an absolute path"));
        }
        let timeout = call
            .timeout_secs
            .map_or(DEFAULT_EXEC_TIMEOUT, Duration::from_secs);
        if timeout.is_zero() || timeout > MAX_EXEC_TIMEOUT {
            return refuse(
                self,
                "invalid",
                bad("timeout_secs must be between 1 and 600"),
            );
        }
        let mut env = Vec::new();
        let mut set_by: BTreeMap<String, &str> = BTreeMap::new();
        let mut needs_approval = None;
        for name in &call.handles {
            let Some(secret) = vault.get(name) else {
                return refuse(self, "invalid", unknown_handle(vault, name));
            };
            match evaluate(secret, &Operation::Exec { program }) {
                Decision::Allow => {}
                Decision::Ask => needs_approval = needs_approval.or(Some(name)),
                Decision::Deny(reason) => {
                    let message = format!("{name}: {reason}");
                    return refuse(
                        self,
                        "policy",
                        agent_error(AgentErrorCode::PolicyDenied, message),
                    );
                }
            }
            if let SecretValue::Env { vars } = &secret.value {
                for (var, value) in vars {
                    let key = if cfg!(windows) {
                        var.to_ascii_uppercase()
                    } else {
                        var.clone()
                    };
                    if let Some(other) = set_by.insert(key, name) {
                        let message = if other == name.as_str() {
                            format!("{name} is listed twice")
                        } else {
                            format!("{other} and {name} both set {var}")
                        };
                        return refuse(self, "invalid", bad(&message));
                    }
                    env.push((var.clone(), value.clone()));
                }
            }
        }
        if let Some(name) = needs_approval {
            return refuse(self, "denied", approval_needed(name));
        }
        self.touch(now);
        Prepared::Exec(Box::new(ExecJob {
            handles: call.handles,
            argv: call.argv,
            cwd: call.cwd,
            timeout,
            env,
            scrubber: self.scrubber(),
            audit: self.audit.clone(),
            started: now,
        }))
    }

    /// Records a request that never reached the broker and returns its reply.
    fn refuse(
        &self,
        action: &str,
        handle: &str,
        summary: &str,
        decision: &str,
        response: AgentResponse,
    ) -> Prepared {
        let outcome = match &response {
            AgentResponse::Error { code, .. } => code.as_str(),
            _ => "error",
        };
        self.audit.record_use(&Use {
            action,
            handle,
            decision,
            summary,
            outcome,
            duration: Duration::ZERO,
        });
        Prepared::Reply(response)
    }

    /// The scrubber for every unlocked secret. Only call while unlocked.
    fn scrubber(&mut self) -> Arc<Scrubber> {
        if let Some(scrubber) = &self.scrubber {
            return scrubber.clone();
        }
        let values: Vec<(String, Zeroizing<String>)> = self
            .vault
            .iter()
            .flat_map(|vault| vault.secrets())
            .flat_map(|secret| {
                secret
                    .sensitive_values()
                    .into_iter()
                    .map(|value| (secret.name.clone(), value))
            })
            .collect();
        let scrubber = Arc::new(Scrubber::new(
            values
                .iter()
                .map(|(name, value)| (name.as_str(), value.as_str())),
        ));
        self.scrubber = Some(scrubber.clone());
        scrubber
    }

    pub fn handle_control(
        &mut self,
        request: ControlRequest,
        now: Instant,
    ) -> (ControlResponse, After) {
        self.last_request = now;
        self.scrubber = None;
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
            self.scrubber = None;
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

fn agent_error(code: AgentErrorCode, message: impl ToString) -> AgentResponse {
    AgentResponse::Error {
        code,
        message: message.to_string(),
    }
}

fn unknown_handle(vault: &Vault, name: &str) -> AgentResponse {
    let names: Vec<&str> = vault.secrets().iter().map(|s| s.name.as_str()).collect();
    let available = if names.is_empty() {
        "there are none yet".to_owned()
    } else {
        format!("available: {}", names.join(", "))
    };
    agent_error(
        AgentErrorCode::UnknownHandle,
        format!("there is no handle named {name}; {available}"),
    )
}

fn approval_needed(name: &str) -> AgentResponse {
    agent_error(
        AgentErrorCode::ApprovalTimeout,
        format!(
            "{name} needs approval for each use, and kv cannot ask for approval yet (that arrives with `kv tui`). Ask the user whether to allow it with `kv policy {name} --mode auto`"
        ),
    )
}

fn check_method(method: &str) -> Result<(), String> {
    if !method.is_empty() && method.len() <= 16 && method.bytes().all(|b| b.is_ascii_alphabetic()) {
        Ok(())
    } else {
        Err("method must be a word such as GET or POST".into())
    }
}

fn check_headers(secret: &Secret, headers: &BTreeMap<String, String>) -> Result<(), String> {
    let auth_header = match &secret.value {
        SecretValue::Http {
            placement: AuthPlacement::Header { name, .. },
            ..
        } => Some(name.as_str()),
        _ => None,
    };
    for (name, value) in headers {
        let token_char = |b: u8| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b);
        if name.is_empty() || !name.bytes().all(token_char) {
            return Err(format!("{name:?} is not a valid header name"));
        }
        let lower = name.to_ascii_lowercase();
        if RESERVED_HEADERS.contains(&lower.as_str()) {
            return Err(format!("the {name} header is set by kv"));
        }
        if auth_header.is_some_and(|auth| auth.eq_ignore_ascii_case(name)) {
            return Err(format!(
                "the {name} header carries this handle's credential and is set by kv"
            ));
        }
        if !secret.policy.allowed_methods.is_empty() && METHOD_OVERRIDES.contains(&lower.as_str()) {
            return Err(format!(
                "the {name} header can change the method, which this handle's policy restricts"
            ));
        }
        if value.contains(['\r', '\n', '\0']) {
            return Err(format!("the value of {name} contains a line break or NUL"));
        }
    }
    Ok(())
}

fn agent_outcome(response: &AgentResponse) -> &'static str {
    match response {
        AgentResponse::Error { .. } => "error",
        _ => "done",
    }
}
