//! A daemon running in this test process, reached through its real
//! sockets, with one `mode: ask` http handle pointing at a local server.
#![allow(dead_code)]

use std::time::{Duration, Instant};

use kv::client;
use kv::daemon::Settings;
use kv::paths::Paths;
use kv_core::policy::{Mode, Policy};
use kv_core::proto::{
    AgentRequest, AgentResponse, ControlCommand, ControlRequest, ControlResponse, HttpCall,
    Overview, SessionInfo,
};
use kv_core::secret::{AuthPlacement, Secret, SecretText, SecretValue};
use tempfile::TempDir;
use tokio::task::JoinHandle;
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, ResponseTemplate};

pub const PASS: &str = "correct horse battery";
pub const TOKEN: &str = "sk-or-v1-0123456789abcdef";

pub struct Daemon {
    _dir: TempDir,
    pub paths: Paths,
    pub upstream: MockServer,
    pub token: SecretText,
}

impl Daemon {
    /// Starts a daemon in this process with a 2 s approval wait and one
    /// `mode: ask` http handle pointing at a local server.
    pub async fn start() -> Self {
        let dir = TempDir::new().unwrap();
        let paths = Paths::under(dir.path());
        let settings = Settings {
            approval_wait: Duration::from_secs(2),
            ..Settings::default()
        };
        tokio::spawn(kv::daemon::run(paths.clone(), settings));
        let upstream = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
            .mount(&upstream)
            .await;
        let mut daemon = Self {
            _dir: dir,
            paths,
            upstream,
            token: SecretText::new(""),
        };
        let deadline = Instant::now() + Duration::from_secs(5);
        while client::control_if_running(&daemon.paths, &request(None, None, ControlCommand::Lock))
            .await
            .ok()
            .flatten()
            .is_none()
        {
            assert!(Instant::now() < deadline, "the daemon did not start");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let init = ControlCommand::Init {
            insecure_fast_kdf: true,
        };
        daemon.control(Some(PASS), init).await;
        let host = daemon
            .upstream
            .uri()
            .trim_start_matches("http://")
            .to_owned();
        let secret = Secret {
            name: "api".into(),
            description: String::new(),
            value: SecretValue::Http {
                token: SecretText::new(TOKEN),
                placement: AuthPlacement::Header {
                    name: "Authorization".into(),
                    template: "Bearer {}".into(),
                },
                base_url: None,
            },
            policy: Policy {
                mode: Mode::Ask,
                allowed_hosts: vec![host],
                allow_plain_http: true,
                ..Policy::default()
            },
            created_at: 0,
            updated_at: 0,
        };
        let add = ControlCommand::Add {
            secret,
            replace: false,
        };
        daemon.control(Some(PASS), add).await;
        daemon.token = match daemon
            .control(Some(PASS), ControlCommand::OpenSession)
            .await
        {
            ControlResponse::Session { token } => token,
            other => panic!("{other:?}"),
        };
        daemon
    }

    pub async fn control(
        &self,
        passphrase: Option<&str>,
        command: ControlCommand,
    ) -> ControlResponse {
        let response = client::control(&self.paths, &request(passphrase, None, command), false)
            .await
            .unwrap();
        assert!(
            !matches!(response, ControlResponse::Error { .. }),
            "{response:?}"
        );
        response
    }

    pub async fn with_token(&self, command: ControlCommand) -> ControlResponse {
        client::control(
            &self.paths,
            &request(None, Some(&self.token), command),
            false,
        )
        .await
        .unwrap()
    }

    /// Sends one http_request from an agent session in the background.
    pub fn agent_call(&self) -> JoinHandle<AgentResponse> {
        let paths = self.paths.clone();
        let call = HttpCall {
            handle: "api".into(),
            method: "GET".into(),
            url: format!("{}/models", self.upstream.uri()),
            headers: Default::default(),
            body: None,
        };
        tokio::spawn(async move {
            let session = SessionInfo {
                id: "session-1".into(),
                client: "approval test".into(),
            };
            client::agent(&paths, Some(&session), &AgentRequest::HttpRequest(call))
                .await
                .unwrap()
        })
    }

    /// Polls like `kv tui` until a request is waiting, and returns its id.
    pub async fn waiting_id(&self) -> u64 {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let ControlResponse::Overview {
                overview: Overview { approvals, .. },
            } = self.with_token(ControlCommand::Overview).await
                && let Some(approval) = approvals.first()
            {
                assert_eq!(approval.client.as_deref(), Some("approval test"));
                return approval.id;
            }
            assert!(Instant::now() < deadline, "nothing is waiting");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let paths = self.paths.clone();
        let _ = std::thread::spawn(move || {
            tokio::runtime::Runtime::new().unwrap().block_on(async {
                let stop = request(None, None, ControlCommand::Stop);
                let _ = client::control_if_running(&paths, &stop).await;
            })
        })
        .join();
    }
}

pub fn request(
    passphrase: Option<&str>,
    token: Option<&SecretText>,
    command: ControlCommand,
) -> ControlRequest {
    ControlRequest {
        passphrase: passphrase.map(SecretText::new),
        device: None,
        token: token.cloned(),
        command,
    }
}
