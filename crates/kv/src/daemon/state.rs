//! Daemon state and request handling, kept free of sockets and clocks so it
//! can be tested directly.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use kv_core::VaultError;
use kv_core::crypto::KdfParams;
use kv_core::crypto::fill_random;
use kv_core::db::{RedisRefusal, check_redis, pg_read_only_violation, split_command};
use kv_core::policy::{
    Decision, DenyReason, Mode, Operation, evaluate, http_target, is_host_entry,
};
use kv_core::proto::{
    AgentErrorCode, AgentRequest, AgentResponse, Approval, ConnectCall, ControlCommand,
    ControlErrorCode, ControlRequest, ControlResponse, DbCall, ExecCall, HandleRequest, HttpCall,
    Overview, PolicyPatch, RequestedHandle, SessionInfo, Status, Verdict,
};
use kv_core::scrub::{MIN_SECRET_LEN, Scrubber};
use kv_core::secret::{
    AuthPlacement, Secret, SecretKind, SecretText, SecretValue, validate_handle,
};
use kv_core::vault::Vault;
use tokio::sync::oneshot;
use zeroize::Zeroizing;

use crate::audit::{Audit, Use};
use crate::broker::lease::{DEFAULT_TTL, MAX_LEASES, MAX_TTL};
use crate::broker::{ConnectJob, DbJob, ExecJob, HttpJob, Leases, RoleChecks};
use crate::throttle::Throttle;

const DEFAULT_EXEC_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_EXEC_TIMEOUT: Duration = Duration::from_secs(600);
const DEFAULT_DB_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_DB_TIMEOUT: Duration = Duration::from_secs(300);

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

/// Open `kv tui` sessions kept at once; the oldest is dropped beyond this.
const MAX_SESSIONS: usize = 16;

/// Requests that may wait for approval at once. More are refused, so an
/// agent cannot flood the approval list or the notifications.
const MAX_PENDING: usize = 32;

/// Handle requests kept for the user at once.
const MAX_HANDLE_REQUESTS: usize = 16;
const MAX_REQUESTED_HOSTS: usize = 4;

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
    /// How long a request waits for a decision in `kv tui`.
    pub approval_wait: Duration,
    /// Show a desktop notification when a request starts waiting.
    pub notify: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            idle_lock: Duration::from_secs(8 * 60 * 60),
            locked_exit: Duration::from_secs(10 * 60),
            approval_wait: Duration::from_secs(60),
            notify: false,
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
    /// Tokens of open `kv tui` sessions. Cleared whenever the vault locks.
    sessions: Vec<SecretText>,
    /// Requests waiting for a decision, oldest first.
    approvals: Vec<Pending>,
    next_approval: u64,
    /// "Allow for the session" decisions. Cleared whenever the vault locks.
    grants: Vec<Grant>,
    /// Answers for requests withdrawn while they waited, for the server to
    /// pick up. Oldest are dropped past `MAX_PENDING`.
    ended: BTreeMap<u64, AgentResponse>,
    /// Handles agents asked the user to add, oldest first. They hold no
    /// secrets, so they outlast a lock.
    handle_requests: Vec<RequestedHandle>,
    next_request: u64,
    /// The name of a handle request not yet announced; only new names are.
    request_notice: Option<String>,
    /// Read-only Postgres handles whose role has been checked since the
    /// vault was unlocked. Forgotten when the handle changes.
    role_checks: RoleChecks,
    /// Open `db_connect` leases. All end when the vault locks; a handle's
    /// end when it changes.
    leases: Leases,
}

/// A request waiting for approval, as the daemon keeps it.
struct Pending {
    id: u64,
    tool: &'static str,
    /// The handles that need approval.
    ask: Vec<String>,
    /// Every handle in the request, for the audit log.
    handles: String,
    summary: String,
    detail: String,
    cwd: Option<String>,
    client: Option<String>,
    session: Option<String>,
    queued: Instant,
    expires: Instant,
    /// Dropping it without sending tells the waiting request the vault
    /// locked.
    reply: oneshot::Sender<Verdict>,
}

struct Grant {
    session: String,
    handle: String,
    until: Instant,
}

/// What `prepare` knows about a request that has to wait for approval.
struct Ask {
    tool: &'static str,
    ask: Vec<String>,
    handles: String,
    summary: String,
    detail: String,
    cwd: Option<String>,
}

/// An authorized request waiting for the user. The server waits on
/// `verdict` for at most `wait`, then runs `then` if allowed.
pub struct Waiting {
    pub id: u64,
    pub verdict: oneshot::Receiver<Verdict>,
    /// The job to run once allowed, already marked as approved.
    pub then: Prepared,
    pub wait: Duration,
    /// One line for the desktop notification. Never contains a value.
    pub notice: String,
}

/// The outcome of an agent request: either an answer now, or authorized
/// work for the broker to run without holding the daemon lock.
pub enum Prepared {
    Reply(AgentResponse),
    Http(Box<HttpJob>),
    Exec(Box<ExecJob>),
    Db(Box<DbJob>),
    Connect(Box<ConnectJob>),
    Wait(Box<Waiting>),
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
            sessions: Vec::new(),
            approvals: Vec::new(),
            next_approval: 0,
            handle_requests: Vec::new(),
            next_request: 0,
            request_notice: None,
            role_checks: RoleChecks::default(),
            leases: Leases::default(),
            ended: BTreeMap::new(),
            grants: Vec::new(),
        }
    }

    pub fn is_unlocked(&self) -> bool {
        self.vault.is_some()
    }

    pub fn prepare(&mut self, request: AgentRequest, now: Instant) -> Prepared {
        self.prepare_in(None, request, now)
    }

    /// Like `prepare`, for a request from a named agent session.
    pub fn prepare_in(
        &mut self,
        session: Option<&SessionInfo>,
        request: AgentRequest,
        now: Instant,
    ) -> Prepared {
        self.last_request = now;
        match request {
            AgentRequest::Hello(_) => Prepared::Reply(agent_error(
                AgentErrorCode::BadRequest,
                "hello may only open a connection",
            )),
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
            AgentRequest::HttpRequest(call) => self.prepare_http(call, session, now),
            AgentRequest::Exec(call) => self.prepare_exec(call, session, now),
            AgentRequest::DbQuery(call) => self.prepare_db(call, session, now),
            AgentRequest::DbConnect(call) => self.prepare_connect(call, session, now),
            AgentRequest::RequestHandle(request) => {
                let name = printable(&request.name, 63);
                let response = self.request_handle(session, request);
                self.audit.record(
                    "agent",
                    "request_handle",
                    Some(&name),
                    agent_outcome(&response),
                );
                Prepared::Reply(response)
            }
        }
    }

    /// The name of a newly requested handle to announce, once.
    pub fn take_request_notice(&mut self) -> Option<String> {
        self.request_notice.take()
    }

    /// Queues a handle for the user to add in `kv tui`, keeping only what
    /// fits its kind and making agent text safe to show.
    fn request_handle(
        &mut self,
        session: Option<&SessionInfo>,
        mut request: HandleRequest,
    ) -> AgentResponse {
        let bad = |message: String| agent_error(AgentErrorCode::BadRequest, message);
        if validate_handle(&request.name).is_err() {
            return bad(
                "a handle name is up to 63 lowercase letters, digits, - and _, starting with a letter or digit"
                    .into(),
            );
        }
        if let Some(vault) = &self.vault
            && vault.get(&request.name).is_some()
        {
            return bad(format!(
                "{} already exists; use it, or ask the user to change it in kv tui",
                request.name
            ));
        }
        let replaces = self
            .handle_requests
            .iter()
            .position(|r| r.request.name == request.name);
        if replaces.is_none() && self.handle_requests.len() >= MAX_HANDLE_REQUESTS {
            return bad(format!(
                "{MAX_HANDLE_REQUESTS} handle requests are already waiting; ask the user to open kv tui"
            ));
        }
        // Few enough to read in full in the form, which is where the user
        // decides where the token may go.
        if request.kind == SecretKind::Http && request.allowed_hosts.len() > MAX_REQUESTED_HOSTS {
            return bad(format!(
                "ask for at most {MAX_REQUESTED_HOSTS} hosts; the user can add more"
            ));
        }
        if request.kind == SecretKind::Http
            && let Some(host) = request
                .allowed_hosts
                .iter()
                .find(|h| !is_host_entry(h.trim()))
        {
            return bad(format!(
                "{:?} is not a host or host:port in plain ASCII (use punycode for other letters)",
                printable(host, 253)
            ));
        }
        request.description = printable(&request.description, 300);
        request.reason = printable(&request.reason, 300);
        let list = |items: Vec<String>, keep: &dyn Fn(&str) -> bool, max: usize| -> Vec<String> {
            items
                .iter()
                .map(|item| printable(item.trim(), 253))
                .filter(|item| !item.is_empty() && keep(item))
                .take(max)
                .collect()
        };
        if request.kind == SecretKind::Http {
            request.auth = request.auth.map(|auth| match auth {
                AuthPlacement::Header { name, template } => AuthPlacement::Header {
                    name: printable(&name, 100),
                    template: printable(&template, 200),
                },
                AuthPlacement::Query { param } => AuthPlacement::Query {
                    param: printable(&param, 100),
                },
            });
            request.allowed_hosts = list(request.allowed_hosts, &|_| true, MAX_REQUESTED_HOSTS);
        } else {
            request.auth = None;
            request.base_url = false;
            request.allowed_hosts.clear();
        }
        if request.kind == SecretKind::Env {
            request.env_vars = list(request.env_vars, &is_variable_name, 32);
            request.allowed_cmds = list(request.allowed_cmds, &|_| true, 16);
        } else {
            request.env_vars.clear();
            request.allowed_cmds.clear();
        }
        let name = request.name.clone();
        // A replacement keeps its id, so the user's selection and a
        // dismiss already on its way still find it.
        let id = match replaces {
            Some(index) => self.handle_requests[index].id,
            None => {
                self.next_request += 1;
                self.next_request
            }
        };
        let requested = RequestedHandle {
            id,
            client: session.map(|s| printable(&s.client, 64)),
            request,
        };
        match replaces {
            Some(index) => self.handle_requests[index] = requested,
            None => {
                self.handle_requests.push(requested);
                self.request_notice = Some(name.clone());
            }
        }
        AgentResponse::Requested { name }
    }

    /// Removes a handle request and returns its name.
    fn dismiss_request(&mut self, id: u64) -> Result<String, Failure> {
        let index = self
            .handle_requests
            .iter()
            .position(|r| r.id == id)
            .ok_or_else(|| fail(ControlErrorCode::Invalid, "that handle request is gone"))?;
        Ok(self.handle_requests.remove(index).request.name)
    }

    fn prepare_http(
        &mut self,
        call: HttpCall,
        session: Option<&SessionInfo>,
        now: Instant,
    ) -> Prepared {
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
        let (decision, ask) = match evaluate(&secret, &operation) {
            Decision::Allow => ("auto", false),
            Decision::Deny(reason) => {
                return refuse(
                    self,
                    "policy",
                    agent_error(AgentErrorCode::PolicyDenied, reason),
                );
            }
            Decision::Ask => ("approved", !self.granted(session, &call.handle, now)),
        };
        if ask && self.approvals.len() >= MAX_PENDING {
            return refuse(self, "denied", too_many_waiting());
        }
        self.touch(now);
        // The URL as it will be sent; for a base_url handle, the agent's
        // path, since the base path is part of the hidden address.
        let detail = match &secret.value {
            SecretValue::Http {
                base_url: Some(_), ..
            } => format!("{} {}", call.method, call.url),
            _ => format!("{} {}", call.method, url.as_str()),
        };
        let handle = call.handle.clone();
        let job = Prepared::Http(Box::new(HttpJob {
            secret,
            url,
            call,
            scrubber: self.scrubber(),
            audit: self.audit.clone(),
            started: now,
            decision,
        }));
        if !ask {
            return job;
        }
        let ask = Ask {
            tool: "http_request",
            ask: vec![handle.clone()],
            handles: handle,
            summary,
            detail,
            cwd: None,
        };
        self.queue(ask, job, session, now)
    }

    fn prepare_exec(
        &mut self,
        call: ExecCall,
        session: Option<&SessionInfo>,
        now: Instant,
    ) -> Prepared {
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
        let mut asks = Vec::new();
        let mut asked = false;
        for name in &call.handles {
            let Some(secret) = vault.get(name) else {
                return refuse(self, "invalid", unknown_handle(vault, name));
            };
            match evaluate(secret, &Operation::Exec { program }) {
                Decision::Allow => {}
                Decision::Ask => {
                    asked = true;
                    if !self.granted(session, name, now) {
                        asks.push(name.clone());
                    }
                }
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
        if !asks.is_empty() && self.approvals.len() >= MAX_PENDING {
            return refuse(self, "denied", too_many_waiting());
        }
        self.touch(now);
        let detail = serde_json::to_string(&call.argv).unwrap_or_default();
        let cwd = call.cwd.display().to_string();
        let job = Prepared::Exec(Box::new(ExecJob {
            handles: call.handles,
            argv: call.argv,
            cwd: call.cwd,
            timeout,
            env,
            scrubber: self.scrubber(),
            audit: self.audit.clone(),
            started: now,
            decision: if asked { "approved" } else { "auto" },
        }));
        if asks.is_empty() {
            return job;
        }
        let ask = Ask {
            tool: "exec",
            ask: asks,
            handles,
            summary,
            detail,
            cwd: Some(cwd),
        };
        self.queue(ask, job, session, now)
    }

    fn prepare_db(
        &mut self,
        call: DbCall,
        session: Option<&SessionInfo>,
        now: Instant,
    ) -> Prepared {
        let summary: String = call.query.chars().take(200).collect();
        let refuse = |daemon: &Self, decision, response| {
            daemon.refuse("db_query", &call.handle, &summary, decision, response)
        };
        let bad = |message: String| agent_error(AgentErrorCode::BadRequest, message);
        let denied = |message: String| agent_error(AgentErrorCode::PolicyDenied, message);
        let Some(vault) = &self.vault else {
            return refuse(self, "locked", self.locked_error());
        };
        let Some(secret) = vault.get(&call.handle).cloned() else {
            return refuse(self, "invalid", unknown_handle(vault, &call.handle));
        };
        let timeout = call
            .timeout_secs
            .map_or(DEFAULT_DB_TIMEOUT, Duration::from_secs);
        if timeout.is_zero() || timeout > MAX_DB_TIMEOUT {
            return refuse(
                self,
                "invalid",
                bad("timeout_secs must be between 1 and 300".into()),
            );
        }
        if call.query.trim().is_empty() {
            return refuse(self, "invalid", bad("the query is empty".into()));
        }
        let decision = evaluate(&secret, &Operation::DbQuery);
        if let Decision::Deny(reason) = decision {
            return refuse(self, "policy", denied(reason.to_string()));
        }
        // The read-only guards run before any approval, so the user is
        // never asked about a query that would be refused anyway.
        let read_only = secret.policy.read_only;
        match &secret.value {
            SecretValue::Postgres { .. } if read_only => {
                if let Some(reason) = pg_read_only_violation(&call.query) {
                    return refuse(self, "policy", denied(reason.into()));
                }
            }
            SecretValue::Redis { .. } => {
                let args = match split_command(&call.query) {
                    Ok(args) => args,
                    Err(message) => return refuse(self, "invalid", bad(message)),
                };
                match check_redis(&args, read_only) {
                    Ok(()) => {}
                    Err(refusal @ RedisRefusal::Never(_)) => {
                        return refuse(self, "invalid", bad(refusal.to_string()));
                    }
                    Err(refusal @ RedisRefusal::NotRead(_)) => {
                        return refuse(self, "policy", denied(refusal.to_string()));
                    }
                }
            }
            _ => {}
        }
        let ask = decision == Decision::Ask && !self.granted(session, &call.handle, now);
        if ask && self.approvals.len() >= MAX_PENDING {
            return refuse(self, "denied", too_many_waiting());
        }
        self.touch(now);
        let handle = call.handle.clone();
        let detail = call.query.clone();
        let job = Prepared::Db(Box::new(DbJob {
            secret,
            call,
            timeout,
            scrubber: self.scrubber(),
            audit: self.audit.clone(),
            started: now,
            decision: if decision == Decision::Ask {
                "approved"
            } else {
                "auto"
            },
            role_checks: self.role_checks.clone(),
            role_stamp: self.role_checks.stamp(),
        }));
        if !ask {
            return job;
        }
        let ask = Ask {
            tool: "db_query",
            ask: vec![handle.clone()],
            handles: handle,
            summary,
            detail,
            cwd: None,
        };
        self.queue(ask, job, session, now)
    }

    fn prepare_connect(
        &mut self,
        call: ConnectCall,
        session: Option<&SessionInfo>,
        now: Instant,
    ) -> Prepared {
        let ttl = call.ttl_secs.map_or(DEFAULT_TTL, Duration::from_secs);
        let summary = format!("lease for {}s", ttl.as_secs());
        let refuse = |daemon: &Self, decision, response| {
            daemon.refuse("db_connect", &call.handle, &summary, decision, response)
        };
        let Some(vault) = &self.vault else {
            return refuse(self, "locked", self.locked_error());
        };
        let Some(secret) = vault.get(&call.handle).cloned() else {
            return refuse(self, "invalid", unknown_handle(vault, &call.handle));
        };
        if ttl.is_zero() || ttl > MAX_TTL {
            let message = "ttl_secs must be between 1 and 3600";
            return refuse(
                self,
                "invalid",
                agent_error(AgentErrorCode::BadRequest, message),
            );
        }
        let decision = evaluate(&secret, &Operation::DbConnect);
        if let Decision::Deny(reason) = decision {
            return refuse(
                self,
                "policy",
                agent_error(AgentErrorCode::PolicyDenied, reason),
            );
        }
        let ask = decision == Decision::Ask && !self.granted(session, &call.handle, now);
        if ask && self.approvals.len() >= MAX_PENDING {
            return refuse(self, "denied", too_many_waiting());
        }
        let Some(ticket) = self.leases.open(&call.handle) else {
            let message = format!(
                "{MAX_LEASES} leases are open already; let one expire, or ask the user to lock \
                 the vault"
            );
            return refuse(
                self,
                "denied",
                agent_error(AgentErrorCode::PolicyDenied, message),
            );
        };
        self.touch(now);
        let scrubber = self.scrubber();
        self.leases.set_scrubber(scrubber);
        let handle = call.handle.clone();
        let job = Prepared::Connect(Box::new(ConnectJob {
            secret,
            ttl,
            ticket,
            scrubber: self.leases.subscribe(),
            audit: self.audit.clone(),
            started: now,
            decision: if decision == Decision::Ask {
                "approved"
            } else {
                "auto"
            },
            role_checks: self.role_checks.clone(),
            role_stamp: self.role_checks.stamp(),
        }));
        if !ask {
            return job;
        }
        let ask = Ask {
            tool: "db_connect",
            ask: vec![handle.clone()],
            handles: handle,
            summary,
            detail: format!(
                "a connection URL that works for {}",
                humantime::format_duration(ttl)
            ),
            cwd: None,
        };
        self.queue(ask, job, session, now)
    }

    fn granted(&self, session: Option<&SessionInfo>, handle: &str, now: Instant) -> bool {
        session.is_some_and(|session| {
            self.grants
                .iter()
                .any(|g| g.session == session.id && g.handle == handle && g.until > now)
        })
    }

    /// Adds `job` to the requests waiting for approval.
    fn queue(
        &mut self,
        ask: Ask,
        job: Prepared,
        session: Option<&SessionInfo>,
        now: Instant,
    ) -> Prepared {
        self.next_approval += 1;
        let id = self.next_approval;
        let client = session.map(|s| printable(&s.client, 64));
        let notice = format!(
            "{} wants to use {} ({}). Open kv tui to answer.",
            client.as_deref().unwrap_or("An agent"),
            printable(&ask.ask.join(", "), 120),
            ask.tool
        );
        let (reply, verdict) = oneshot::channel();
        self.approvals.push(Pending {
            id,
            tool: ask.tool,
            ask: ask.ask,
            handles: ask.handles,
            summary: ask.summary,
            detail: printable(&ask.detail, 300),
            cwd: ask.cwd.map(|cwd| printable(&cwd, 300)),
            client,
            session: session.map(|s| s.id.clone()),
            queued: now,
            expires: now + self.settings.approval_wait,
            reply,
        });
        Prepared::Wait(Box::new(Waiting {
            id,
            verdict,
            then: job,
            wait: self.settings.approval_wait,
            notice,
        }))
    }

    /// Drops what was decided about a handle that was added, changed or
    /// removed: its grants, its role check, its leases, and the requests
    /// waiting on it, which hold its old value and policy and so may not
    /// run.
    fn handle_changed(&mut self, name: &str, now: Instant) {
        self.grants.retain(|g| g.handle != name);
        self.role_checks.forget(name);
        self.leases.end_handle(name);
        let (stale, kept) = std::mem::take(&mut self.approvals)
            .into_iter()
            .partition(|p: &Pending| p.handles.split(',').any(|h| h == name));
        self.approvals = kept;
        for pending in stale {
            self.record_unanswered(&pending, "withdrawn", "handle_changed", now);
            self.ended.insert(
                pending.id,
                agent_error(
                    AgentErrorCode::PolicyDenied,
                    format!("{name} changed while the request waited; send it again"),
                ),
            );
            while self.ended.len() > MAX_PENDING {
                self.ended.pop_first();
            }
        }
    }

    /// Why a request stopped waiting without a decision, if it was
    /// withdrawn; `None` means the vault locked.
    pub fn take_ended(&mut self, id: u64) -> Option<AgentResponse> {
        self.ended.remove(&id)
    }

    /// Ends the wait for a request nobody answered, and returns its reply.
    /// `None` if it was already decided or the vault locked.
    pub fn expire(&mut self, id: u64, now: Instant) -> Option<AgentResponse> {
        let index = self.approvals.iter().position(|p| p.id == id)?;
        let pending = self.approvals.remove(index);
        self.record_unanswered(&pending, "denied", "approval_timeout", now);
        Some(agent_error(
            AgentErrorCode::ApprovalTimeout,
            format!(
                "no one approved the request within {}s",
                self.settings.approval_wait.as_secs()
            ),
        ))
    }

    /// Takes back a request whose agent hung up before anyone answered, so
    /// it can no longer be approved. Returns whether it was still waiting.
    pub fn withdraw(&mut self, id: u64, now: Instant) -> bool {
        let Some(index) = self.approvals.iter().position(|p| p.id == id) else {
            return false;
        };
        let pending = self.approvals.remove(index);
        self.record_unanswered(&pending, "denied", "cancelled", now);
        true
    }

    fn decide(&mut self, id: u64, verdict: Verdict, now: Instant) -> Result<Vec<String>, Failure> {
        let index = self
            .approvals
            .iter()
            .position(|p| p.id == id)
            .ok_or_else(|| {
                fail(
                    ControlErrorCode::Invalid,
                    "that request is no longer waiting for approval",
                )
            })?;
        let pending = self.approvals.remove(index);
        let mut warnings = Vec::new();
        let vault = self
            .vault
            .as_mut()
            .expect("deciding needs the vault unlocked");
        match verdict {
            Verdict::AllowOnce | Verdict::Deny => {}
            Verdict::AllowSession => {
                if let Some(session) = &pending.session {
                    self.grants.retain(|g| g.until > now);
                    for handle in &pending.ask {
                        let ttl = vault
                            .get(handle)
                            .map_or(Duration::ZERO, |s| s.policy.grant_ttl);
                        self.grants.push(Grant {
                            session: session.clone(),
                            handle: handle.clone(),
                            until: now + ttl,
                        });
                    }
                }
            }
            Verdict::DenyAlways => {
                let patch = PolicyPatch {
                    mode: Some(Mode::Deny),
                    ..PolicyPatch::default()
                };
                for handle in &pending.ask {
                    if vault.get(handle).is_some() {
                        warnings.extend(set_policy(vault, handle, &patch)?);
                    }
                }
            }
        }
        if matches!(verdict, Verdict::Deny | Verdict::DenyAlways) {
            self.record_unanswered(&pending, "denied", "approval_denied", now);
        }
        // The request may have given up already; then nothing is waiting.
        let _ = pending.reply.send(verdict);
        // The handles' policy changed, so what else waits on them may not
        // be approved under the old one.
        if verdict == Verdict::DenyAlways {
            for handle in &pending.ask {
                self.handle_changed(handle, now);
            }
        }
        Ok(warnings)
    }

    /// Audits a waiting request that ends without running.
    fn record_unanswered(&self, pending: &Pending, decision: &str, outcome: &str, now: Instant) {
        self.audit.record_use(&Use {
            action: pending.tool,
            handle: &pending.handles,
            decision,
            summary: &pending.summary,
            outcome,
            duration: now.saturating_duration_since(pending.queued),
        });
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
        let ControlRequest {
            passphrase,
            token,
            command,
        } = request;
        // Polled by `kv tui` several times a second: not use of the vault,
        // not audited, and it leaves the cached scrubber alone.
        if let ControlCommand::Overview = command {
            return (self.overview(token.as_ref(), now), After::Continue);
        }
        self.scrubber = None;
        let (action, mut handle) = describe(&command);
        let mut after = After::Continue;
        let done = |warnings| ControlResponse::Done { warnings };
        let result = match command {
            ControlCommand::Lock => {
                self.lock_vault();
                Ok(done(Vec::new()))
            }
            ControlCommand::Stop => {
                self.lock_vault();
                after = After::Stop;
                Ok(done(Vec::new()))
            }
            ControlCommand::Init { insecure_fast_kdf } => self
                .init(passphrase.as_ref(), insecure_fast_kdf, now)
                .map(done),
            ControlCommand::OpenSession => self
                .authenticate(passphrase.as_ref(), None, now)
                .map(drop)
                .map(|()| self.open_session()),
            ControlCommand::Decide { id, verdict } => self
                .authenticate(passphrase.as_ref(), token.as_ref(), now)
                .map(drop)
                .and_then(|()| self.decide(id, verdict, now))
                .map(done),
            // A session token is not enough to change the passphrase, and
            // the change ends every session.
            command @ ControlCommand::ChangePassphrase { .. } => self
                .authenticate(passphrase.as_ref(), None, now)
                .and_then(|vault| run_authenticated(vault, command))
                .map(|warnings| {
                    self.sessions.clear();
                    done(warnings)
                }),
            ControlCommand::DismissRequest { id } => self
                .authenticate(passphrase.as_ref(), token.as_ref(), now)
                .map(drop)
                .and_then(|()| self.dismiss_request(id))
                .map(|name| {
                    handle = Some(name);
                    done(Vec::new())
                }),
            command => {
                // Adding a handle someone asked for answers the request.
                let added = match &command {
                    ControlCommand::Add { secret, .. } => Some(secret.name.clone()),
                    _ => None,
                };
                self.authenticate(passphrase.as_ref(), token.as_ref(), now)
                    .and_then(|vault| run_authenticated(vault, command))
                    .map(|warnings| {
                        if let Some(name) = added {
                            self.handle_requests.retain(|r| r.request.name != name);
                        }
                        if let Some(name) = &handle {
                            self.handle_changed(name, now);
                        }
                        // Open leases scrub with the secrets as they are now.
                        if self.leases.count() > 0 {
                            let scrubber = self.scrubber();
                            self.leases.set_scrubber(scrubber);
                        }
                        done(warnings)
                    })
            }
        };
        let response = result.unwrap_or_else(|failure| ControlResponse::Error {
            code: failure.code,
            message: failure.message,
        });
        let outcome = match &response {
            ControlResponse::Error { .. } => "error",
            _ => "done",
        };
        self.audit
            .record("control", action, handle.as_deref(), outcome);
        (response, after)
    }

    /// Runs the idle lock and decides whether the daemon should exit. `wall`
    /// is the current wall-clock time, so time spent asleep counts as idle.
    pub fn tick(&mut self, now: Instant, wall: SystemTime) -> After {
        if self.vault.is_some() && self.idle_for(now, wall) >= self.settings.idle_lock {
            self.lock_vault();
            self.audit.record("daemon", "idle_lock", None, "locked");
        }
        if self.vault.is_none()
            && now.duration_since(self.last_request) >= self.settings.locked_exit
        {
            return After::Stop;
        }
        After::Continue
    }

    /// Forgets the vault key, the scrubber, every session and every grant,
    /// ends every lease, and answers every waiting request with
    /// `vault_locked`.
    fn lock_vault(&mut self) {
        self.vault = None;
        self.scrubber = None;
        self.sessions.clear();
        self.grants.clear();
        self.role_checks.clear();
        self.leases.end_all();
        let now = Instant::now();
        for pending in std::mem::take(&mut self.approvals) {
            self.record_unanswered(&pending, "locked", "vault_locked", now);
        }
    }

    fn open_session(&mut self) -> ControlResponse {
        let mut bytes = Zeroizing::new([0u8; 32]);
        fill_random(bytes.as_mut());
        let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        let token = SecretText::new(hex);
        if self.sessions.len() == MAX_SESSIONS {
            self.sessions.remove(0);
        }
        self.sessions.push(token.clone());
        ControlResponse::Session { token }
    }

    fn session_is_open(&self, token: &SecretText) -> bool {
        self.vault.is_some()
            && self
                .sessions
                .iter()
                .any(|open| constant_time_eq(open.expose(), token.expose()))
    }

    fn overview(&self, token: Option<&SecretText>, now: Instant) -> ControlResponse {
        let Some(vault) = self
            .vault
            .as_ref()
            .filter(|_| token.is_some_and(|t| self.session_is_open(t)))
        else {
            return session_ended();
        };
        let approvals = self
            .approvals
            .iter()
            .map(|p| Approval {
                id: p.id,
                client: p.client.clone(),
                tool: p.tool.into(),
                handles: p.ask.clone(),
                detail: p.detail.clone(),
                cwd: p.cwd.clone(),
                can_grant: p.session.is_some(),
                expires_in_secs: p.expires.saturating_duration_since(now).as_secs(),
            })
            .collect();
        ControlResponse::Overview {
            overview: Overview {
                status: self.status(now),
                handles: vault.secrets().iter().map(Secret::info).collect(),
                approvals,
                handle_requests: self.handle_requests.clone(),
                role_warnings: self.role_checks.warnings(),
            },
        }
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
            pending_approvals: self.approvals.len(),
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

    /// Checks the passphrase, unlocking the vault if it is locked, or else
    /// a session token, and returns the unlocked vault. Wrong passphrases
    /// count toward the backoff; a token is too long to guess.
    fn authenticate(
        &mut self,
        passphrase: Option<&SecretText>,
        token: Option<&SecretText>,
        now: Instant,
    ) -> Result<&mut Vault, Failure> {
        if let (None, Some(token)) = (passphrase, token) {
            if !self.session_is_open(token) {
                return Err(fail(ControlErrorCode::SessionEnded, SESSION_ENDED));
            }
            self.touch(now);
            return Ok(self
                .vault
                .as_mut()
                .expect("a session needs the vault unlocked"));
        }
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
        ControlCommand::Update {
            name,
            description,
            value,
        } => update(vault, &name, description, value),
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
        | ControlCommand::Stop
        | ControlCommand::OpenSession
        | ControlCommand::Overview
        | ControlCommand::Decide { .. }
        | ControlCommand::DismissRequest { .. } => Ok(Vec::new()),
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

fn update(
    vault: &mut Vault,
    name: &str,
    description: Option<String>,
    value: Option<SecretValue>,
) -> Result<Vec<String>, Failure> {
    let previous = vault.get(name).cloned().ok_or_else(|| unknown(name))?;
    let mut updated = previous.clone();
    if let Some(description) = description {
        updated.description = description;
    }
    if let Some(mut value) = value {
        let kind = previous.value.kind();
        if value.kind() != kind {
            return Err(fail(
                ControlErrorCode::Invalid,
                format!(
                    "{name} holds a value of kind {}; remove it and add it again to change its kind",
                    kind_name(kind)
                ),
            ));
        }
        if let (
            SecretValue::Http { base_url, .. },
            SecretValue::Http {
                base_url: Some(old),
                ..
            },
        ) = (&mut value, &previous.value)
            && base_url.is_none()
        {
            *base_url = Some(old.clone());
        }
        validate_value(&value)?;
        updated.value = value;
    }
    let warnings = warnings_for(&updated);
    vault
        .upsert(updated)
        .map_err(|e| fail(ControlErrorCode::Invalid, e.to_string()))?;
    save_or_restore(vault, name, Some(previous))?;
    Ok(warnings)
}

fn kind_name(kind: SecretKind) -> &'static str {
    match kind {
        SecretKind::Http => "http",
        SecretKind::Postgres => "postgres",
        SecretKind::Redis => "redis",
        SecretKind::Env => "env",
    }
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
        SecretValue::Postgres { url } => {
            let scheme = url::Url::parse(url.expose()).map(|u| u.scheme().to_owned());
            if !matches!(scheme.as_deref(), Ok("postgres" | "postgresql")) {
                return invalid("a postgres handle needs a postgres:// or postgresql:// URL");
            }
        }
        SecretValue::Redis { url } => {
            let scheme = url::Url::parse(url.expose()).map(|u| u.scheme().to_owned());
            if !matches!(scheme.as_deref(), Ok("redis" | "rediss")) {
                return invalid("a redis handle needs a redis:// or rediss:// URL");
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
        ControlCommand::Update { name, .. } => ("update", Some(name.clone())),
        ControlCommand::ChangePassphrase { .. } => ("change_passphrase", None),
        ControlCommand::OpenSession => ("open_session", None),
        ControlCommand::Overview => ("overview", None),
        ControlCommand::Decide { .. } => ("decide", None),
        ControlCommand::DismissRequest { .. } => ("dismiss_request", None),
    }
}

const SESSION_ENDED: &str = "the kv tui session has ended because the vault locked; unlock again";

fn session_ended() -> ControlResponse {
    ControlResponse::Error {
        code: ControlErrorCode::SessionEnded,
        message: SESSION_ENDED.into(),
    }
}

/// Compares without stopping at the first difference, so timing reveals
/// nothing about a token.
fn constant_time_eq(a: &str, b: &str) -> bool {
    a.len() == b.len()
        && a.bytes()
            .zip(b.bytes())
            .fold(0u8, |diff, (x, y)| diff | (x ^ y))
            == 0
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

fn too_many_waiting() -> AgentResponse {
    agent_error(
        AgentErrorCode::ApprovalTimeout,
        "too many requests are already waiting for approval; try again shortly",
    )
}

/// Agent-supplied text for the terminal: control characters, which could
/// drive the user's terminal, become U+FFFD, and long text is cut.
/// Makes agent-supplied text safe to show the user: control characters
/// become U+FFFD, invisible format characters (bidi overrides, zero-width
/// spaces) are dropped and runs of whitespace become one space, so the text
/// can neither drive the terminal nor pose as extra lines in the TUI.
fn printable(text: &str, max_chars: usize) -> String {
    let mut clean = String::with_capacity(text.len());
    for c in text.chars() {
        if c.is_whitespace() {
            if !clean.ends_with(' ') {
                clean.push(' ');
            }
        } else if c.is_control() {
            clean.push('\u{FFFD}');
        } else if !is_format(c) {
            clean.push(c);
        }
    }
    let mut out: String = clean.chars().take(max_chars).collect();
    if clean.chars().count() > max_chars {
        out.pop();
        out.push('…');
    }
    out
}

/// Unicode format characters that change how text is laid out without
/// being visible.
fn is_format(c: char) -> bool {
    matches!(c,
        '\u{00AD}' | '\u{061C}' | '\u{180E}' | '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}' | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{206F}' | '\u{FEFF}' | '\u{FFF9}'..='\u{FFFB}')
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

/// Letters, digits and `_`, not starting with a digit.
fn is_variable_name(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}
