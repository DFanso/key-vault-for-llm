//! Handle requests: an agent proposes a handle without its value, and the
//! user finishes it in `kv tui`.

mod common;

use common::*;
use kv::daemon::Prepared;
use kv_core::policy::Mode;
use kv_core::proto::{
    AgentErrorCode, AgentRequest, AgentResponse, ControlCommand, ControlErrorCode, ControlResponse,
    HandleRequest, SessionInfo,
};
use kv_core::secret::{AuthPlacement, SecretKind};

fn dokploy_request(name: &str) -> HandleRequest {
    HandleRequest {
        name: name.into(),
        kind: SecretKind::Http,
        description: "KYC dev Dokploy".into(),
        reason: "to list Dokploy projects".into(),
        auth: Some(AuthPlacement::Header {
            name: "x-api-key".into(),
            template: "{}".into(),
        }),
        base_url: true,
        allowed_hosts: Vec::new(),
        env_vars: Vec::new(),
        allowed_cmds: Vec::new(),
    }
}

fn ask(f: &mut Fixture, session: Option<&SessionInfo>, request: HandleRequest) -> AgentResponse {
    match f
        .daemon
        .prepare_in(session, AgentRequest::RequestHandle(request), f.t0)
    {
        Prepared::Reply(response) => response,
        _ => panic!("a handle request is answered at once"),
    }
}

fn refused(response: AgentResponse) -> String {
    match response {
        AgentResponse::Error {
            code: AgentErrorCode::BadRequest,
            message,
        } => message,
        other => panic!("expected bad_request, got {other:?}"),
    }
}

#[test]
fn a_request_waits_in_the_overview_with_who_asked() {
    let mut f = Fixture::new();
    let token = f.token();
    let response = ask(&mut f, Some(&session("s1")), dokploy_request("dokploy"));
    assert_eq!(
        response,
        AgentResponse::Requested {
            name: "dokploy".into()
        }
    );
    let requests = f.overview(&token).handle_requests;
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].client.as_deref(), Some("test agent"));
    assert_eq!(requests[0].request, dokploy_request("dokploy"));
    let last = f.audit_lines().pop().unwrap();
    assert_eq!(
        (last["action"].as_str(), last["handle"].as_str()),
        (Some("request_handle"), Some("dokploy"))
    );
}

#[test]
fn asking_again_for_a_name_replaces_the_request() {
    let mut f = Fixture::new();
    let token = f.token();
    ask(&mut f, None, dokploy_request("dokploy"));
    let first_id = f.overview(&token).handle_requests[0].id;
    let mut again = dokploy_request("dokploy");
    again.reason = "a better reason".into();
    ask(&mut f, None, again);
    let requests = f.overview(&token).handle_requests;
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].request.reason, "a better reason");
    assert_eq!(requests[0].id, first_id, "the request keeps its id");
}

#[test]
fn existing_names_bad_names_and_too_many_requests_are_refused() {
    let mut f = Fixture::new();
    f.add(openrouter(Mode::Auto));
    assert!(refused(ask(&mut f, None, dokploy_request("openrouter"))).contains("already"));
    assert!(refused(ask(&mut f, None, dokploy_request("Not A Name"))).contains("name"));
    for i in 0..16 {
        ask(&mut f, None, dokploy_request(&format!("svc-{i}")));
    }
    assert!(refused(ask(&mut f, None, dokploy_request("svc-16"))).contains("waiting"));
}

#[test]
fn agent_text_is_made_safe_and_fields_of_other_kinds_are_dropped() {
    let mut f = Fixture::new();
    let token = f.token();
    let mut request = dokploy_request("aws");
    request.kind = SecretKind::Env;
    request.reason = format!("deploy\u{1b}[2J\u{202e}{}", "x".repeat(500));
    request.env_vars = vec!["AWS_ACCESS_KEY_ID".into(), "BAD NAME".into()];
    request.allowed_cmds = vec!["terraform".into()];
    ask(&mut f, None, request);
    let shown = f.overview(&token).handle_requests.remove(0).request;
    assert!(
        !shown.reason.chars().any(char::is_control),
        "{:?}",
        shown.reason
    );
    assert!(!shown.reason.contains('\u{202e}'));
    assert!(shown.reason.chars().count() <= 300);
    assert_eq!(shown.auth, None, "auth is for http handles");
    assert!(!shown.base_url);
    assert_eq!(shown.env_vars, ["AWS_ACCESS_KEY_ID"]);
    assert_eq!(shown.allowed_cmds, ["terraform"]);
}

#[test]
fn adding_the_handle_answers_the_request() {
    let mut f = Fixture::new();
    let token = f.token();
    ask(&mut f, None, dokploy_request("dokploy"));
    let mut secret = dokploy();
    secret.name = "dokploy".into();
    let response = f.send(
        None,
        Some(&token),
        ControlCommand::Add {
            secret,
            replace: false,
        },
    );
    assert!(
        matches!(response, ControlResponse::Done { .. }),
        "{response:?}"
    );
    assert!(f.overview(&token).handle_requests.is_empty());
}

#[test]
fn dismissing_needs_the_user_and_is_audited() {
    let mut f = Fixture::new();
    let token = f.token();
    ask(&mut f, None, dokploy_request("dokploy"));
    let id = f.overview(&token).handle_requests[0].id;
    match f.send(None, None, ControlCommand::DismissRequest { id }) {
        ControlResponse::Error { code, .. } => {
            assert_eq!(code, ControlErrorCode::PassphraseRequired)
        }
        other => panic!("{other:?}"),
    }
    let done = f.send(None, Some(&token), ControlCommand::DismissRequest { id });
    assert!(matches!(done, ControlResponse::Done { .. }), "{done:?}");
    assert!(f.overview(&token).handle_requests.is_empty());
    let last = f.audit_lines().pop().unwrap();
    assert_eq!(
        (last["action"].as_str(), last["handle"].as_str()),
        (Some("dismiss_request"), Some("dokploy"))
    );
    match f.send(None, Some(&token), ControlCommand::DismissRequest { id }) {
        ControlResponse::Error { code, .. } => assert_eq!(code, ControlErrorCode::Invalid),
        other => panic!("{other:?}"),
    }
}

#[test]
fn requests_survive_a_lock() {
    let mut f = Fixture::new();
    ask(&mut f, None, dokploy_request("dokploy"));
    f.send(None, None, ControlCommand::Lock);
    let token = f.token();
    assert_eq!(f.overview(&token).handle_requests.len(), 1);
}

#[test]
fn requested_hosts_must_be_plain_ascii_host_names() {
    let mut f = Fixture::new();
    for host in [
        "api.githu\u{042c}.com",
        "api.github.com,evil.example",
        "https://api.github.com/",
        "user@api.github.com",
    ] {
        let mut request = dokploy_request("gh");
        request.allowed_hosts = vec![host.into()];
        let message = refused(ask(&mut f, None, request));
        assert!(message.contains("host"), "{host}: {message}");
    }
    let mut request = dokploy_request("gh");
    request.allowed_hosts = vec!["api.github.com".into(), "[::1]:8443".into()];
    assert!(matches!(
        ask(&mut f, None, request),
        AgentResponse::Requested { .. }
    ));
}

#[test]
fn only_a_new_name_is_announced() {
    let mut f = Fixture::new();
    ask(&mut f, None, dokploy_request("dokploy"));
    assert_eq!(f.daemon.take_request_notice().as_deref(), Some("dokploy"));
    assert_eq!(f.daemon.take_request_notice(), None);
    ask(&mut f, None, dokploy_request("dokploy"));
    assert_eq!(
        f.daemon.take_request_notice(),
        None,
        "asking again is not news"
    );
}

#[test]
fn a_request_names_at_most_four_hosts() {
    let mut f = Fixture::new();
    let mut request = dokploy_request("gh");
    request.allowed_hosts = (0..5).map(|i| format!("api-{i}.example.com")).collect();
    assert!(refused(ask(&mut f, None, request)).contains("4 hosts"));
}
