//! Approvals for `mode: ask` handles, driven directly through the daemon
//! state: requests wait, `kv tui` decides, and grants last for `grant_ttl`
//! within one agent session.

mod common;

use std::time::Duration;

use common::*;
use kv::daemon::{Prepared, Waiting};
use kv_core::policy::Mode;
use kv_core::proto::{
    AgentErrorCode, AgentRequest, AgentResponse, ControlCommand, ControlErrorCode, ControlResponse,
    SessionInfo, Verdict,
};

fn ask_get() -> AgentRequest {
    AgentRequest::HttpRequest(get("openrouter", "https://openrouter.ai/api/v1/models"))
}

fn fixture() -> Fixture {
    let mut f = Fixture::new();
    f.add(openrouter(Mode::Ask));
    f
}

fn job_decision(prepared: Prepared) -> &'static str {
    match prepared {
        Prepared::Http(job) => job.decision,
        Prepared::Exec(job) => job.decision,
        Prepared::Db(job) => job.decision,
        Prepared::Connect(job) => job.decision,
        Prepared::Run(job) => job.decision,
        Prepared::Reply(reply) => panic!("expected a job, got {reply:?}"),
        Prepared::Wait(_) => panic!("expected a job, got a wait"),
    }
}

fn verdict(waiting: &mut Waiting) -> Option<Verdict> {
    waiting.verdict.try_recv().ok()
}

fn done(response: &ControlResponse) {
    assert!(
        matches!(response, ControlResponse::Done { .. }),
        "{response:?}"
    );
}

#[test]
fn an_ask_request_waits_and_the_tui_sees_it() {
    let mut f = fixture();
    let token = f.token();
    let agent = session("s1");
    let mut waiting = f.wait(Some(&agent), ask_get(), f.t0);
    assert!(verdict(&mut waiting).is_none(), "nothing decided yet");

    let overview = f.overview(&token);
    assert_eq!(overview.status.pending_approvals, 1);
    let approval = &overview.approvals[0];
    assert_eq!(approval.id, waiting.id);
    assert_eq!(approval.client.as_deref(), Some("test agent"));
    assert_eq!(approval.tool, "http_request");
    assert_eq!(approval.handles, ["openrouter"]);
    assert_eq!(approval.detail, "GET https://openrouter.ai/api/v1/models");
    assert!(approval.can_grant);
    assert_eq!(approval.expires_in_secs, 60);

    done(&f.decide(&token, waiting.id, Verdict::AllowOnce));
    assert_eq!(verdict(&mut waiting), Some(Verdict::AllowOnce));
    assert_eq!(job_decision(waiting.then), "approved");
    assert!(f.overview(&token).approvals.is_empty());
    assert_eq!(f.audit_lines().last().unwrap()["action"], "decide");
}

#[test]
fn allow_once_grants_nothing() {
    let mut f = fixture();
    let token = f.token();
    let agent = session("s1");
    let waiting = f.wait(Some(&agent), ask_get(), f.t0);
    done(&f.decide(&token, waiting.id, Verdict::AllowOnce));
    f.wait(Some(&agent), ask_get(), f.t0);
}

#[test]
fn allow_for_the_session_covers_that_session_and_handle_until_grant_ttl() {
    let mut f = fixture();
    let token = f.token();
    let agent = session("s1");
    let waiting = f.wait(Some(&agent), ask_get(), f.t0);
    done(&f.decide(&token, waiting.id, Verdict::AllowSession));

    let later = f.t0 + Duration::from_secs(60);
    let again = f.daemon.prepare_in(Some(&agent), ask_get(), later);
    assert_eq!(job_decision(again), "approved");

    // Another session, or a caller with no session, still has to ask.
    f.wait(Some(&session("s2")), ask_get(), later);
    f.wait(None, ask_get(), later);

    // The default grant_ttl is 15 minutes.
    let expired = f.t0 + Duration::from_secs(15 * 60 + 1);
    f.wait(Some(&agent), ask_get(), expired);
}

#[test]
fn a_request_without_a_session_cannot_be_granted_for_a_session() {
    let mut f = fixture();
    let token = f.token();
    let waiting = f.wait(None, ask_get(), f.t0);
    assert!(!f.overview(&token).approvals[0].can_grant);
    done(&f.decide(&token, waiting.id, Verdict::AllowSession));
    f.wait(None, ask_get(), f.t0);
}

#[test]
fn deny_is_audited_and_deny_always_sets_the_mode_to_deny() {
    let mut f = fixture();
    let token = f.token();
    let agent = session("s1");
    let mut waiting = f.wait(Some(&agent), ask_get(), f.t0);
    done(&f.decide(&token, waiting.id, Verdict::Deny));
    assert_eq!(verdict(&mut waiting), Some(Verdict::Deny));
    let audit = f.audit_lines();
    let denial = audit.iter().find(|l| l["decision"] == "denied").unwrap();
    assert_eq!(denial["outcome"], "approval_denied");
    assert_eq!(denial["handle"], "openrouter");

    let waiting = f.wait(Some(&agent), ask_get(), f.t0);
    done(&f.decide(&token, waiting.id, Verdict::DenyAlways));
    let handle = &f.overview(&token).handles[0];
    assert_eq!(handle.mode, Mode::Deny);
    let (code, _) = f
        .http(get("openrouter", "https://openrouter.ai/api/v1/models"))
        .unwrap_err();
    assert_eq!(code, AgentErrorCode::PolicyDenied);
}

#[test]
fn deciding_needs_a_session_or_the_passphrase() {
    let mut f = fixture();
    let waiting = f.wait(None, ask_get(), f.t0);
    let decide = || ControlCommand::Decide {
        id: waiting.id,
        verdict: Verdict::AllowOnce,
    };
    match f.send(None, None, decide()) {
        ControlResponse::Error { code, .. } => {
            assert_eq!(code, ControlErrorCode::PassphraseRequired)
        }
        other => panic!("{other:?}"),
    }
    done(&f.send(Some(PASS), None, decide()));
}

#[test]
fn a_decision_for_a_request_that_is_gone_is_an_error() {
    let mut f = fixture();
    let token = f.token();
    match f.decide(&token, 99, Verdict::AllowOnce) {
        ControlResponse::Error { code, message } => {
            assert_eq!(code, ControlErrorCode::Invalid);
            assert!(message.contains("no longer waiting"), "{message}");
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn locking_drops_waiting_requests_and_grants() {
    let mut f = fixture();
    let token = f.token();
    let agent = session("s1");
    let granted = f.wait(Some(&agent), ask_get(), f.t0);
    done(&f.decide(&token, granted.id, Verdict::AllowSession));
    let mut waiting = f.wait(Some(&session("s2")), ask_get(), f.t0);

    f.send(None, None, ControlCommand::Lock);
    assert!(
        waiting.verdict.try_recv().is_err(),
        "the sender is dropped, so the server answers vault_locked"
    );
    let audit = f.audit_lines();
    assert!(
        audit
            .iter()
            .any(|l| l["decision"] == "locked" && l["outcome"] == "vault_locked"),
        "{audit:?}"
    );

    f.send(Some(PASS), None, ControlCommand::Unlock);
    f.wait(Some(&agent), ask_get(), f.t0);
}

#[test]
fn an_unanswered_request_expires_and_is_audited() {
    let mut f = fixture();
    let token = f.token();
    let waiting = f.wait(None, ask_get(), f.t0);
    let later = f.t0 + Duration::from_secs(60);
    match f.daemon.expire(waiting.id, later) {
        Some(AgentResponse::Error { code, .. }) => {
            assert_eq!(code, AgentErrorCode::ApprovalTimeout)
        }
        other => panic!("{other:?}"),
    }
    assert!(f.overview(&token).approvals.is_empty());
    let last = f.audit_lines().pop().unwrap();
    assert_eq!(
        (last["decision"].as_str(), last["outcome"].as_str()),
        (Some("denied"), Some("approval_timeout"))
    );
    // Already decided or expired: nothing to expire.
    assert!(f.daemon.expire(waiting.id, later).is_none());
}

#[test]
fn exec_waits_for_the_handles_that_ask_and_grants_cover_each() {
    let mut f = Fixture::new();
    f.add(env_secret(
        "aws",
        &[("AWS_SECRET_ACCESS_KEY", AWS_KEY)],
        &["terraform"],
        Mode::Ask,
    ));
    f.add(env_secret(
        "cf",
        &[("CF_API_TOKEN", "cf-token-0123456789")],
        &["terraform"],
        Mode::Auto,
    ));
    let token = f.token();
    let agent = session("s1");
    let cwd = f.dir.path().to_path_buf();
    let call = || AgentRequest::Exec(run(&["aws", "cf"], &["terraform", "plan"], cwd.clone()));
    let waiting = f.wait(Some(&agent), call(), f.t0);
    let approval = f.overview(&token).approvals.remove(0);
    assert_eq!(approval.tool, "exec");
    assert_eq!(approval.handles, ["aws"]);
    assert_eq!(approval.detail, r#"["terraform","plan"]"#);
    assert_eq!(approval.cwd.as_deref(), Some(cwd.to_str().unwrap()));
    done(&f.decide(&token, waiting.id, Verdict::AllowSession));
    assert_eq!(
        job_decision(f.daemon.prepare_in(Some(&agent), call(), f.t0)),
        "approved"
    );
}

#[test]
fn agent_supplied_text_is_made_safe_for_the_terminal() {
    let mut f = fixture();
    let token = f.token();
    let agent = SessionInfo {
        id: "s1".into(),
        client: format!("evil\u{1b}[2J\u{7}{}", "x".repeat(500)),
    };
    let mut call = get("openrouter", "https://openrouter.ai/a\u{1b}]52;c;bad\u{7}");
    call.method = "GET".into();
    f.wait(Some(&agent), AgentRequest::HttpRequest(call), f.t0);
    let approval = f.overview(&token).approvals.remove(0);
    let client = approval.client.unwrap();
    for text in [&client, &approval.detail] {
        assert!(!text.chars().any(char::is_control), "{text:?}");
    }
    assert!(client.chars().count() <= 64, "{client}");
}

#[test]
fn too_many_waiting_requests_are_refused() {
    let mut f = fixture();
    let mut waiting = Vec::new();
    for _ in 0..32 {
        waiting.push(f.wait(None, ask_get(), f.t0));
    }
    match f.daemon.prepare_in(None, ask_get(), f.t0) {
        Prepared::Reply(AgentResponse::Error { code, message }) => {
            assert_eq!(code, AgentErrorCode::ApprovalTimeout);
            assert!(message.contains("waiting for approval"), "{message}");
        }
        _ => panic!("expected a refusal"),
    }
}

#[test]
fn agent_text_cannot_fake_lines_or_hide_characters() {
    let mut f = fixture();
    let token = f.token();
    let agent = SessionInfo {
        id: "s1".into(),
        client: "claude\u{202e}edoc   \u{200b}x".into(),
    };
    let mut call = get("openrouter", "https://openrouter.ai/a    b\u{2066}c");
    call.method = "GET".into();
    f.wait(Some(&agent), AgentRequest::HttpRequest(call), f.t0);
    let approval = f.overview(&token).approvals.remove(0);
    let client = approval.client.unwrap();
    for text in [&client, &approval.detail] {
        assert!(!text.contains("  "), "{text:?}");
        assert!(
            !text
                .chars()
                .any(|c| matches!(c, '\u{200b}' | '\u{202e}' | '\u{2066}')),
            "{text:?}"
        );
    }
    // The URL as it will be sent, not as the agent typed it.
    assert_eq!(
        approval.detail,
        "GET https://openrouter.ai/a%20%20%20%20b%E2%81%A6c"
    );
}

#[test]
fn a_base_url_request_shows_its_path_not_the_address() {
    let mut f = Fixture::new();
    let mut secret = dokploy();
    secret.policy.mode = Mode::Ask;
    f.add(secret);
    let token = f.token();
    f.wait(
        None,
        AgentRequest::HttpRequest(get("dokploy", "/projects?all=1")),
        f.t0,
    );
    let approval = f.overview(&token).approvals.remove(0);
    // The agent's path; the base path is part of the hidden address.
    assert_eq!(approval.detail, "GET /projects?all=1");
}

#[test]
fn a_grant_ends_when_its_handle_is_removed() {
    let mut f = fixture();
    let token = f.token();
    let agent = session("s1");
    let granted = f.wait(Some(&agent), ask_get(), f.t0);
    done(&f.decide(&token, granted.id, Verdict::AllowSession));
    f.control(ControlCommand::Remove {
        name: "openrouter".into(),
    });
    f.add(openrouter(Mode::Ask));
    // A new handle of the same name is asked about afresh.
    f.wait(Some(&agent), ask_get(), f.t0);
}

#[test]
fn changing_a_handle_withdraws_the_requests_waiting_on_it() {
    let mut f = fixture();
    f.add(env_secret(
        "aws",
        &[("AWS_KEY", AWS_KEY)],
        &["terraform"],
        Mode::Ask,
    ));
    let token = f.token();
    let mut changed = f.wait(Some(&session("s1")), ask_get(), f.t0);
    let mut other = f.wait(
        Some(&session("s1")),
        AgentRequest::Exec(run(&["aws"], &["terraform"], std::env::temp_dir())),
        f.t0,
    );
    done(&f.send(
        None,
        Some(&token),
        ControlCommand::SetPolicy {
            name: "openrouter".into(),
            patch: kv_core::proto::PolicyPatch {
                allowed_hosts: Some(vec!["evil.example".into()]),
                ..Default::default()
            },
        },
    ));
    assert!(
        changed.verdict.try_recv().is_err(),
        "the old request can no longer be approved"
    );
    match f.daemon.take_ended(changed.id) {
        Some(AgentResponse::Error { code, message }) => {
            assert_eq!(code, AgentErrorCode::PolicyDenied);
            assert!(message.contains("changed"), "{message}");
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(f.daemon.take_ended(changed.id), None, "answered once");
    let approvals = f.overview(&token).approvals;
    assert_eq!(approvals.len(), 1);
    assert_eq!(approvals[0].id, other.id);
    assert!(verdict(&mut other).is_none());
    assert!(
        f.audit_lines()
            .iter()
            .any(|l| l["decision"] == "withdrawn" && l["outcome"] == "handle_changed")
    );
}

#[test]
fn deny_always_also_withdraws_other_requests_for_the_handle() {
    let mut f = fixture();
    let token = f.token();
    let denied = f.wait(Some(&session("s1")), ask_get(), f.t0);
    let other = f.wait(Some(&session("s2")), ask_get(), f.t0);
    done(&f.decide(&token, denied.id, Verdict::DenyAlways));
    assert!(f.overview(&token).approvals.is_empty());
    assert!(matches!(
        f.daemon.take_ended(other.id),
        Some(AgentResponse::Error {
            code: AgentErrorCode::PolicyDenied,
            ..
        })
    ));
}
