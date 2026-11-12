//! `login` handles end to end: HTTP Basic auth to the allowed hosts, two
//! variables for the allowed programs, an edit that changes one half, and
//! a share from one vault to another. The username and password never
//! come back to the agent.

mod common;

use std::io::Write;

use common::*;
use kv::broker::exec::run;
use kv::broker::http::{client, send};
use kv::daemon::Prepared;
use kv_core::policy::{Mode, Policy};
use kv_core::proto::{
    AgentErrorCode, AgentRequest, AgentResponse, ControlCommand, ControlResponse, ExecCall,
    HttpCall, ReceiveShareCall, RevealedField, SendShareCall, ShareRequestCall, Verdict,
};
use kv_core::secret::{Secret, SecretKind, SecretText, SecretValue};
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const USERNAME: &str = "svc-reports@example.com";
const PASSWORD: &str = "w0rd-pass-0123456789";
const HELPER_VAR: &str = "KV_LOGIN_HELPER";

/// Not a real test. Run by kv with `KV_LOGIN_HELPER` set, it prints the
/// login's two variables, as a program that echoes its config would.
#[test]
fn helper() {
    if std::env::var(HELPER_VAR).is_err() {
        return;
    }
    let mut out = std::io::stdout();
    for var in ["JIRA_USERNAME", "JIRA_PASSWORD"] {
        writeln!(out, "{var}={}", std::env::var(var).unwrap_or_default()).unwrap();
    }
    out.flush().unwrap();
    std::process::exit(0);
}

fn login(hosts: Vec<String>, cmds: Vec<String>) -> Secret {
    secret(
        "jira",
        SecretValue::Login {
            username: SecretText::new(USERNAME),
            password: SecretText::new(PASSWORD),
        },
        Policy {
            mode: Mode::Auto,
            allowed_hosts: hosts,
            allowed_cmds: cmds,
            allow_plain_http: true,
            ..Policy::default()
        },
    )
}

fn basic() -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(format!("{USERNAME}:{PASSWORD}"))
}

fn call(url: &str) -> HttpCall {
    HttpCall {
        handle: "jira".into(),
        method: "GET".into(),
        url: url.into(),
        headers: Default::default(),
        body: None,
    }
}

#[tokio::test]
async fn a_login_signs_requests_with_basic_auth_and_nothing_comes_back() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/api/2/myself"))
        .and(header("authorization", format!("Basic {}", basic())))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(format!("{{\"name\":\"{USERNAME}\",\"pw\":\"{PASSWORD}\"}}")),
        )
        .mount(&server)
        .await;
    let host = server.uri().trim_start_matches("http://").to_owned();
    let mut f = Fixture::new();
    f.add(login(vec![host], Vec::new()));

    let job = f
        .http(call(&format!("{}/rest/api/2/myself", server.uri())))
        .expect("authorized");
    let reply = match send(&client().unwrap(), job).await {
        AgentResponse::Http(reply) => reply,
        other => panic!("expected a reply, got {other:?}"),
    };
    assert_eq!(reply.status, 200, "the server saw Basic auth");
    assert_eq!(reply.body, "{\"name\":\"[kv:jira]\",\"pw\":\"[kv:jira]\"}");

    // The agent cannot set the header the credential goes in.
    let mut own = call(&format!("{}/x", server.uri()));
    own.headers
        .insert("Authorization".into(), "Basic Z3Vlc3M6Z3Vlc3M=".into());
    let (code, message) = f.http(own).expect_err("refused");
    assert_eq!(code, AgentErrorCode::BadRequest);
    assert!(message.contains("credential"), "{message}");

    // Nor send it anywhere else.
    let (code, _) = f
        .http(call("https://elsewhere.example.net/"))
        .expect_err("refused");
    assert_eq!(code, AgentErrorCode::PolicyDenied);
}

#[tokio::test]
async fn a_login_gives_a_program_its_username_and_password_and_hides_them() {
    let exe = std::env::current_exe().unwrap();
    let exe = exe.to_str().unwrap().to_owned();
    let mut f = Fixture::new();
    f.add(login(Vec::new(), vec![exe.clone()]));
    f.add(env_secret(
        "helper",
        &[(HELPER_VAR, "1")],
        &[&exe],
        Mode::Auto,
    ));
    let call = ExecCall {
        handles: vec!["jira".into(), "helper".into()],
        argv: vec![
            exe,
            "helper".into(),
            "--exact".into(),
            "--nocapture".into(),
            "--test-threads=1".into(),
        ],
        cwd: f.dir.path().to_path_buf(),
        timeout_secs: None,
    };
    let job = f.exec(call).expect("authorized");
    let reply = match run(job).await {
        AgentResponse::Exec(reply) => reply,
        other => panic!("expected output, got {other:?}"),
    };
    assert_eq!(reply.exit_code, Some(0), "{reply:?}");
    assert!(
        reply.stdout.contains("JIRA_USERNAME=[kv:jira]"),
        "{}",
        reply.stdout
    );
    assert!(
        reply.stdout.contains("JIRA_PASSWORD=[kv:jira]"),
        "{}",
        reply.stdout
    );
    assert!(!reply.stdout.contains(PASSWORD));
    assert!(!reply.stdout.contains(USERNAME));
}

fn update(f: &mut Fixture, username: &str, password: &str) -> ControlResponse {
    f.send(
        Some(PASS),
        None,
        ControlCommand::Update {
            name: "jira".into(),
            description: None,
            value: Some(SecretValue::Login {
                username: SecretText::new(username),
                password: SecretText::new(password),
            }),
        },
    )
}

fn revealed(f: &mut Fixture) -> Vec<(String, String)> {
    let token = f.token();
    match f.send(
        Some(PASS),
        Some(&token),
        ControlCommand::RevealHandle {
            handle: "jira".into(),
        },
    ) {
        ControlResponse::Revealed { fields, .. } => fields
            .into_iter()
            .map(|RevealedField { label, value }| (label, value.expose().to_owned()))
            .collect(),
        other => panic!("expected the value, got {other:?}"),
    }
}

fn refused(response: ControlResponse) -> String {
    match response {
        ControlResponse::Error { message, .. } => message,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn an_edit_changes_one_half_and_keeps_the_other() {
    let mut f = Fixture::new();
    f.add(login(vec!["jira.example.com".into()], Vec::new()));
    assert_eq!(
        revealed(&mut f),
        [
            ("Username".to_owned(), USERNAME.to_owned()),
            ("Password".to_owned(), PASSWORD.to_owned()),
        ]
    );

    // A blank username keeps the one the handle has.
    assert!(matches!(
        update(&mut f, "", "a-new-password-4567"),
        ControlResponse::Done { .. }
    ));
    assert_eq!(
        revealed(&mut f),
        [
            ("Username".to_owned(), USERNAME.to_owned()),
            ("Password".to_owned(), "a-new-password-4567".to_owned()),
        ]
    );

    // And a blank password the password.
    assert!(matches!(
        update(&mut f, "svc-other", ""),
        ControlResponse::Done { .. }
    ));
    assert_eq!(
        revealed(&mut f),
        [
            ("Username".to_owned(), "svc-other".to_owned()),
            ("Password".to_owned(), "a-new-password-4567".to_owned()),
        ]
    );
}

#[test]
fn a_login_needs_both_halves_and_a_username_basic_auth_can_carry() {
    let mut f = Fixture::new();
    let add = |f: &mut Fixture, username: &str, password: &str| {
        let mut secret = login(vec!["jira.example.com".into()], Vec::new());
        secret.value = SecretValue::Login {
            username: SecretText::new(username),
            password: SecretText::new(password),
        };
        f.send(
            Some(PASS),
            None,
            ControlCommand::Add {
                secret,
                replace: true,
            },
        )
    };
    assert!(refused(add(&mut f, "", PASSWORD)).contains("username is empty"));
    assert!(refused(add(&mut f, USERNAME, "")).contains("password is empty"));
    assert!(refused(add(&mut f, "domain:user", PASSWORD)).contains("colon"));
    assert!(refused(add(&mut f, USERNAME, "two\nlines")).contains("line breaks"));
}

#[test]
fn nothing_allowed_is_warned_about_when_the_login_is_added() {
    let mut f = Fixture::new();
    match f.send(
        Some(PASS),
        None,
        ControlCommand::Add {
            secret: login(Vec::new(), Vec::new()),
            replace: false,
        },
    ) {
        ControlResponse::Done { warnings, .. } => {
            assert!(
                warnings
                    .iter()
                    .any(|w| w.contains("no allowed hosts or commands")),
                "{warnings:?}"
            );
        }
        other => panic!("expected it saved, got {other:?}"),
    }
}

#[test]
fn a_login_can_be_shared_and_arrives_as_a_login() {
    let mut alice = Fixture::new();
    alice.add(login(vec!["jira.example.com".into()], Vec::new()));
    let mut bob = Fixture::new();

    let code = match bob.prepare(AgentRequest::RequestShare(ShareRequestCall {
        note: "the Jira login".into(),
        from: "bob".into(),
    })) {
        Prepared::Reply(AgentResponse::ShareRequested { code, .. }) => code,
        _ => panic!("expected a request code"),
    };

    let alice_token = alice.token();
    let mut waiting = alice.wait(
        Some(&session("alice-agent")),
        AgentRequest::SendShare(SendShareCall {
            request: code,
            handle: "jira".into(),
            name: None,
            from: "alice".into(),
            note: String::new(),
        }),
        alice.t0,
    );
    assert!(matches!(
        alice.decide(&alice_token, waiting.id, Verdict::AllowOnce),
        ControlResponse::Done { .. }
    ));
    let share = match waiting.then {
        Prepared::Reply(AgentResponse::ShareSealed { share, .. }) => share,
        _ => panic!("expected sealed text"),
    };
    assert!(!share.contains(PASSWORD) && !share.contains(USERNAME));
    let _ = waiting.verdict.try_recv();

    let handle = match bob.prepare(AgentRequest::ReceiveShare(ReceiveShareCall {
        share,
        name: None,
    })) {
        Prepared::Reply(AgentResponse::ShareReceived { handle, .. }) => handle,
        _ => panic!("expected a saved share"),
    };
    assert_eq!(handle.kind, SecretKind::Login);
    assert_eq!(handle.mode, Mode::Ask);
    assert_eq!(handle.allowed_hosts, ["jira.example.com"]);
    assert_eq!(handle.env_vars, ["JIRA_USERNAME", "JIRA_PASSWORD"]);
    let shown = serde_json::to_string(&handle).unwrap();
    assert!(!shown.contains(PASSWORD) && !shown.contains(USERNAME));

    let bob_token = bob.token();
    match bob.send(
        None,
        Some(&bob_token),
        ControlCommand::RevealShare {
            handle: "jira".into(),
        },
    ) {
        ControlResponse::Revealed { fields, .. } => assert_eq!(
            fields,
            [
                RevealedField {
                    label: "Username".into(),
                    value: SecretText::new(USERNAME),
                },
                RevealedField {
                    label: "Password".into(),
                    value: SecretText::new(PASSWORD),
                },
            ]
        ),
        other => panic!("expected the value, got {other:?}"),
    }
}
