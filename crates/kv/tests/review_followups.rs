//! What the user sees before a program gets a handle's variables, and the
//! name and size checks on the paths the first round of them left out:
//! updates, kv's window, and an agent's handle request.

mod common;

use common::*;
use kv::daemon::Prepared;
use kv_core::policy::Mode;
use kv_core::proto::{
    AgentErrorCode, AgentRequest, AgentResponse, ControlCommand, ControlErrorCode, ControlResponse,
    HandleRequest, SendShareCall, ShareRequestCall,
};
use kv_core::secret::{SecretKind, SecretText, SecretValue};
use kv_core::share::{self, ShareRequest, SharedSecret};

const API_KEY: &str = "sk-test-0123456789abcdef";

fn vars(pairs: &[(&str, &str)]) -> SecretValue {
    SecretValue::Env {
        vars: pairs
            .iter()
            .map(|(k, v)| (k.to_string(), SecretText::new(*v)))
            .collect(),
    }
}

#[test]
fn an_exec_approval_names_the_variables_the_program_gets_never_their_values() {
    let mut f = Fixture::new();
    f.add(env_secret(
        "app",
        &[
            ("API_KEY", API_KEY),
            ("DATABASE_URL", "postgres://u:p@db/app"),
        ],
        &["node"],
        Mode::Ask,
    ));
    let token = f.token();
    let cwd = f.dir.path().to_path_buf();
    let agent = session("s1");
    f.wait(
        Some(&agent),
        AgentRequest::Exec(run(&["app"], &["node", "app.js"], cwd)),
        f.t0,
    );
    let approval = f.overview(&token).approvals.remove(0);
    assert_eq!(approval.env_vars, ["API_KEY", "DATABASE_URL"]);
    let shown = serde_json::to_string(&approval).unwrap();
    assert!(!shown.contains(API_KEY), "{shown}");
}

#[test]
fn a_run_approval_names_them_too_and_other_tools_name_none() {
    let mut f = Fixture::new();
    f.add(run_secret(
        "server",
        &[("SERVER_TOKEN", API_KEY)],
        &["/usr/local/bin/server", "--stdio"],
        Mode::Ask,
    ));
    f.add(openrouter(Mode::Ask));
    let token = f.token();
    let agent = session("s1");
    f.wait(Some(&agent), AgentRequest::Run(launch("server")), f.t0);
    f.wait(
        Some(&agent),
        AgentRequest::HttpRequest(get("openrouter", "https://openrouter.ai/api/v1/models")),
        f.t0,
    );
    let approvals = f.overview(&token).approvals;
    let run = approvals.iter().find(|a| a.tool == "run").unwrap();
    assert_eq!(run.env_vars, ["SERVER_TOKEN"]);
    let http = approvals.iter().find(|a| a.tool == "http_request").unwrap();
    assert!(http.env_vars.is_empty());
}

fn env_request(names: &[&str]) -> HandleRequest {
    HandleRequest {
        name: "app".into(),
        kind: SecretKind::Env,
        description: String::new(),
        reason: "to run the app".into(),
        auth: None,
        base_url: false,
        allowed_hosts: Vec::new(),
        env_vars: names.iter().map(|n| n.to_string()).collect(),
        allowed_cmds: vec!["node".into()],
    }
}

fn ask(f: &mut Fixture, request: HandleRequest) -> AgentResponse {
    match f.prepare(AgentRequest::RequestHandle(request)) {
        Prepared::Reply(response) => response,
        _ => panic!("a handle request is answered at once"),
    }
}

#[test]
fn an_agent_cannot_ask_the_user_for_a_variable_that_loads_code() {
    let mut f = Fixture::new();
    match ask(&mut f, env_request(&["API_KEY", "NODE_OPTIONS"])) {
        AgentResponse::Error {
            code: AgentErrorCode::BadRequest,
            message,
        } => assert!(message.contains("NODE_OPTIONS"), "{message}"),
        other => panic!("expected a refusal, got {other:?}"),
    }
    let token = f.token();
    assert!(f.overview(&token).handle_requests.is_empty());

    // Names too long to be variable names are dropped like other bad ones.
    let long = "A".repeat(129);
    assert!(!matches!(
        ask(&mut f, env_request(&["API_KEY", long.as_str()])),
        AgentResponse::Error { .. }
    ));
    let request = f.overview(&token).handle_requests.remove(0);
    assert_eq!(request.request.env_vars, ["API_KEY"]);
}

#[test]
fn an_update_is_held_to_the_same_size_limits() {
    let mut f = Fixture::new();
    f.add(env_secret(
        "app",
        &[("API_KEY", API_KEY)],
        &["node"],
        Mode::Ask,
    ));
    let third = "w".repeat(3000);
    let long = "x".repeat(4097);
    for value in [
        vars(&[
            ("A", third.as_str()),
            ("B", third.as_str()),
            ("C", third.as_str()),
        ]),
        vars(&[("A", long.as_str())]),
    ] {
        let response = f.send(
            Some(PASS),
            None,
            ControlCommand::Update {
                name: "app".into(),
                description: None,
                value: Some(value),
            },
        );
        match response {
            ControlResponse::Error { code, .. } => assert_eq!(code, ControlErrorCode::Invalid),
            other => panic!("expected a refusal, got {other:?}"),
        }
    }
}

fn bobs_code() -> String {
    let mut bob = Fixture::new();
    match bob.prepare(AgentRequest::RequestShare(ShareRequestCall {
        note: String::new(),
        from: "bob".into(),
    })) {
        Prepared::Reply(AgentResponse::ShareRequested { code, .. }) => code,
        _ => panic!("expected a request code"),
    }
}

#[test]
fn the_window_refuses_to_send_a_handle_a_share_would_refuse() {
    let mut alice = Fixture::new();
    alice.add(env_secret(
        "pip",
        &[("PIP_INDEX_URL", "https://pypi.example.com/simple")],
        &["pip"],
        Mode::Ask,
    ));
    let token = alice.token();
    let response = alice.send(
        None,
        Some(&token),
        ControlCommand::SendShare(SendShareCall {
            request: bobs_code(),
            handle: "pip".into(),
            name: None,
            from: "alice".into(),
            note: String::new(),
        }),
    );
    match response {
        ControlResponse::Error { message, .. } => {
            assert!(message.contains("PIP_INDEX_URL"), "{message}")
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
    assert!(alice.overview(&token).shares.sent.is_empty());
}

#[test]
fn updating_a_shared_handle_to_set_a_risky_variable_warns_it_will_not_run() {
    let mut bob = Fixture::new();
    let code = match bob.prepare(AgentRequest::RequestShare(ShareRequestCall {
        note: String::new(),
        from: "bob".into(),
    })) {
        Prepared::Reply(AgentResponse::ShareRequested { code, .. }) => code,
        _ => panic!("expected a request code"),
    };
    let sealed = share::seal(
        &ShareRequest::decode(&code).unwrap(),
        &SharedSecret {
            name: "app".into(),
            description: String::new(),
            value: vars(&[("API_KEY", API_KEY)]),
            allowed_hosts: Vec::new(),
            allow_plain_http: false,
            allowed_methods: Vec::new(),
            read_only: false,
            from: "alice".into(),
            note: String::new(),
        },
    )
    .unwrap();
    assert!(matches!(
        bob.prepare(AgentRequest::ReceiveShare(
            kv_core::proto::ReceiveShareCall {
                share: sealed,
                name: None,
            }
        )),
        Prepared::Reply(AgentResponse::ShareReceived { .. })
    ));
    let response = bob.send(
        Some(PASS),
        None,
        ControlCommand::Update {
            name: "app".into(),
            description: None,
            value: Some(vars(&[("API_KEY", API_KEY), ("NODE_OPTIONS", "--inspect")])),
        },
    );
    match response {
        ControlResponse::Done { warnings } => assert!(
            warnings
                .iter()
                .any(|w| w.contains("came from a share") && w.contains("NODE_OPTIONS")),
            "{warnings:?}"
        ),
        other => panic!("expected the update to be saved, got {other:?}"),
    }
}
