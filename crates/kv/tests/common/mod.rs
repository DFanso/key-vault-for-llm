//! Shared test fixture: a daemon with an unlocked vault, driven directly
//! through `Daemon::prepare` and `Daemon::handle_control`.
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Instant;

use kv::audit::Audit;
use kv::broker::{ExecJob, HttpJob};
use kv::daemon::{Daemon, Prepared, Settings, Waiting};
use kv_core::policy::{Mode, Policy};
use kv_core::proto::{
    AgentErrorCode, AgentRequest, AgentResponse, ControlCommand, ControlRequest, ControlResponse,
    ExecCall, HttpCall, Overview, SessionInfo, Verdict,
};
use kv_core::secret::{AuthPlacement, Secret, SecretText, SecretValue};
use tempfile::TempDir;

pub const PASS: &str = "correct horse battery";
pub const TOKEN: &str = "sk-or-v1-0123456789abcdef";
pub const AWS_KEY: &str = "AKIAEXAMPLEKEY0123456";

pub struct Fixture {
    pub dir: TempDir,
    pub daemon: Daemon,
    pub t0: Instant,
}

impl Fixture {
    pub fn new() -> Self {
        let dir = TempDir::new().unwrap();
        let t0 = Instant::now();
        let daemon = Daemon::new(
            dir.path().join("vault.kv"),
            Audit::new(dir.path().join("audit.jsonl")),
            Settings::default(),
            t0,
        );
        let mut f = Self { dir, daemon, t0 };
        f.control(ControlCommand::Init {
            insecure_fast_kdf: true,
        });
        f
    }

    pub fn control(&mut self, command: ControlCommand) {
        let (response, _) = self.daemon.handle_control(
            ControlRequest {
                passphrase: Some(SecretText::new(PASS)),
                token: None,
                command,
            },
            self.t0,
        );
        assert!(
            matches!(response, ControlResponse::Done { .. }),
            "{response:?}"
        );
    }

    pub fn add(&mut self, secret: Secret) {
        self.control(ControlCommand::Add {
            secret,
            replace: false,
        });
    }

    pub fn prepare(&mut self, request: AgentRequest) -> Prepared {
        self.daemon.prepare(request, self.t0)
    }

    pub fn http(&mut self, call: HttpCall) -> Result<HttpJob, (AgentErrorCode, String)> {
        match self.prepare(AgentRequest::HttpRequest(call)) {
            Prepared::Http(job) => Ok(*job),
            Prepared::Reply(AgentResponse::Error { code, message }) => Err((code, message)),
            Prepared::Reply(other) => panic!("unexpected reply {other:?}"),
            Prepared::Exec(_) => panic!("unexpected exec job"),
            Prepared::Wait(_) => panic!("unexpected wait for approval"),
        }
    }

    pub fn exec(&mut self, call: ExecCall) -> Result<ExecJob, (AgentErrorCode, String)> {
        match self.prepare(AgentRequest::Exec(call)) {
            Prepared::Exec(job) => Ok(*job),
            Prepared::Reply(AgentResponse::Error { code, message }) => Err((code, message)),
            Prepared::Reply(other) => panic!("unexpected reply {other:?}"),
            Prepared::Http(_) => panic!("unexpected http job"),
            Prepared::Wait(_) => panic!("unexpected wait for approval"),
        }
    }

    /// Prepares a request from an agent session at `now`, expecting it to
    /// wait for approval.
    pub fn wait(
        &mut self,
        session: Option<&SessionInfo>,
        request: AgentRequest,
        now: Instant,
    ) -> Waiting {
        match self.daemon.prepare_in(session, request, now) {
            Prepared::Wait(waiting) => *waiting,
            Prepared::Reply(reply) => panic!("expected a wait, got {reply:?}"),
            Prepared::Http(_) | Prepared::Exec(_) => panic!("expected a wait, got a job"),
        }
    }

    /// Opens a `kv tui` session and returns its token.
    pub fn token(&mut self) -> SecretText {
        match self.send(Some(PASS), None, ControlCommand::OpenSession) {
            ControlResponse::Session { token } => token,
            other => panic!("expected a session, got {other:?}"),
        }
    }

    pub fn send(
        &mut self,
        passphrase: Option<&str>,
        token: Option<&SecretText>,
        command: ControlCommand,
    ) -> ControlResponse {
        self.send_at(self.t0, passphrase, token, command)
    }

    pub fn send_at(
        &mut self,
        now: Instant,
        passphrase: Option<&str>,
        token: Option<&SecretText>,
        command: ControlCommand,
    ) -> ControlResponse {
        let request = ControlRequest {
            passphrase: passphrase.map(SecretText::new),
            token: token.cloned(),
            command,
        };
        self.daemon.handle_control(request, now).0
    }

    pub fn overview(&mut self, token: &SecretText) -> Overview {
        match self.send(None, Some(token), ControlCommand::Overview) {
            ControlResponse::Overview { overview } => overview,
            other => panic!("expected an overview, got {other:?}"),
        }
    }

    pub fn decide(&mut self, token: &SecretText, id: u64, verdict: Verdict) -> ControlResponse {
        self.send(None, Some(token), ControlCommand::Decide { id, verdict })
    }

    pub fn audit_lines(&self) -> Vec<serde_json::Value> {
        std::fs::read_to_string(self.dir.path().join("audit.jsonl"))
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }
}

pub fn secret(name: &str, value: SecretValue, policy: Policy) -> Secret {
    Secret {
        name: name.into(),
        description: String::new(),
        value,
        policy,
        created_at: 0,
        updated_at: 0,
    }
}

pub fn openrouter(mode: Mode) -> Secret {
    secret(
        "openrouter",
        SecretValue::Http {
            token: SecretText::new(TOKEN),
            placement: AuthPlacement::Header {
                name: "Authorization".into(),
                template: "Bearer {}".into(),
            },
            base_url: None,
        },
        Policy {
            mode,
            allowed_hosts: vec!["openrouter.ai".into()],
            ..Policy::default()
        },
    )
}

pub fn dokploy() -> Secret {
    secret(
        "dokploy",
        SecretValue::Http {
            token: SecretText::new("dokploy-token-0123456789"),
            placement: AuthPlacement::Header {
                name: "x-api-key".into(),
                template: "{}".into(),
            },
            base_url: Some("https://dokploy.internal.example/api".into()),
        },
        Policy {
            mode: Mode::Auto,
            ..Policy::default()
        },
    )
}

pub fn env_secret(name: &str, vars: &[(&str, &str)], cmds: &[&str], mode: Mode) -> Secret {
    secret(
        name,
        SecretValue::Env {
            vars: vars
                .iter()
                .map(|(k, v)| (k.to_string(), SecretText::new(*v)))
                .collect(),
        },
        Policy {
            mode,
            allowed_cmds: cmds.iter().map(|c| c.to_string()).collect(),
            ..Policy::default()
        },
    )
}

pub fn get(handle: &str, url: &str) -> HttpCall {
    HttpCall {
        handle: handle.into(),
        method: "GET".into(),
        url: url.into(),
        headers: BTreeMap::new(),
        body: None,
    }
}

pub fn run(handles: &[&str], argv: &[&str], cwd: PathBuf) -> ExecCall {
    ExecCall {
        handles: handles.iter().map(|h| h.to_string()).collect(),
        argv: argv.iter().map(|a| a.to_string()).collect(),
        cwd,
        timeout_secs: None,
    }
}

pub fn session(id: &str) -> SessionInfo {
    SessionInfo {
        id: id.into(),
        client: "test agent".into(),
    }
}
