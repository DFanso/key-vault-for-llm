//! Authorizing `run`: which handles may start their command, approval,
//! the limit, validation of run commands, and what ends a run.

mod common;

use common::*;
use kv::broker::lease::EndReason;
use kv_core::policy::Mode;
use kv_core::proto::{
    AgentErrorCode, AgentRequest, ControlCommand, ControlErrorCode, ControlResponse, PolicyPatch,
    Verdict,
};

const SECRET: &str = "hunter2-hunter2-0123";
const HOST: &str = "10.0.0.5";

fn add_server(f: &mut Fixture, name: &str, mode: Mode) {
    f.add(run_secret(
        name,
        &[("SSH_MCP_PASSWORD", SECRET)],
        &[
            "/usr/local/bin/bunx",
            "-y",
            "ssh-mcp@1.2.3",
            "--host=10.0.0.5",
        ],
        mode,
    ));
}

#[test]
fn run_is_refused_while_the_vault_is_locked() {
    let mut f = Fixture::new();
    add_server(&mut f, "srv", Mode::Auto);
    f.control(ControlCommand::Lock);
    let (code, _) = f.run_job(launch("srv")).unwrap_err();
    assert_eq!(code, AgentErrorCode::VaultLocked);
}

#[test]
fn run_needs_a_known_env_handle_with_a_run_command() {
    let mut f = Fixture::new();
    f.add(env_secret("plain", &[("A", SECRET)], &["tool"], Mode::Auto));
    f.add(openrouter(Mode::Auto));
    assert_eq!(
        f.run_job(launch("nope")).unwrap_err().0,
        AgentErrorCode::UnknownHandle
    );
    let (code, message) = f.run_job(launch("plain")).unwrap_err();
    assert_eq!(code, AgentErrorCode::PolicyDenied);
    assert!(message.contains("no run command"), "{message}");
    assert_eq!(
        f.run_job(launch("openrouter")).unwrap_err().0,
        AgentErrorCode::PolicyDenied
    );
}

#[test]
fn an_auto_server_gets_its_command_and_variables() {
    let mut f = Fixture::new();
    add_server(&mut f, "srv", Mode::Auto);
    let job = f.run_job(launch("srv")).unwrap();
    assert_eq!(job.handle, "srv");
    assert_eq!(job.argv[0], "/usr/local/bin/bunx");
    assert_eq!(job.argv[3], "--host=10.0.0.5");
    assert_eq!(job.env.len(), 1);
    assert_eq!(job.env[0].0, "SSH_MCP_PASSWORD");
    assert_eq!(job.env[0].1.expose(), SECRET);
    assert_eq!(job.decision, "auto");
    assert!(!format!("{job:?}").contains(HOST));
}

#[test]
fn a_deny_server_is_refused() {
    let mut f = Fixture::new();
    add_server(&mut f, "srv", Mode::Deny);
    assert_eq!(
        f.run_job(launch("srv")).unwrap_err().0,
        AgentErrorCode::PolicyDenied
    );
}

#[test]
fn an_ask_server_waits_and_a_session_grant_covers_the_next_start() {
    let mut f = Fixture::new();
    add_server(&mut f, "srv", Mode::Ask);
    let agent = session("s1");
    let waiting = f.wait(Some(&agent), AgentRequest::Run(launch("srv")), f.t0);
    let token = f.token();
    let approval = f.overview(&token).approvals.remove(0);
    assert_eq!(approval.tool, "run");
    assert_eq!(approval.detail, "starts bunx");
    assert!(approval.can_grant);
    assert!(!format!("{approval:?}").contains(HOST));
    assert!(matches!(
        f.decide(&token, waiting.id, Verdict::AllowSession),
        ControlResponse::Done { .. }
    ));
    match f
        .daemon
        .prepare_in(Some(&agent), AgentRequest::Run(launch("srv")), f.t0)
    {
        kv::daemon::Prepared::Run(job) => assert_eq!(job.decision, "approved"),
        _ => panic!("expected the grant to cover the second start"),
    }
    let other = session("s2");
    f.wait(Some(&other), AgentRequest::Run(launch("srv")), f.t0);
}

#[test]
fn at_most_32_programs_run_at_once() {
    let mut f = Fixture::new();
    add_server(&mut f, "srv", Mode::Auto);
    let jobs: Vec<_> = (0..32).map(|_| f.run_job(launch("srv")).unwrap()).collect();
    let (code, message) = f.run_job(launch("srv")).unwrap_err();
    assert_eq!(code, AgentErrorCode::PolicyDenied);
    assert!(message.contains("32 programs"), "{message}");
    drop(jobs);
    assert!(f.run_job(launch("srv")).is_ok());
}

#[tokio::test]
async fn changing_the_handle_and_locking_end_runs() {
    let mut f = Fixture::new();
    add_server(&mut f, "srv", Mode::Auto);
    add_server(&mut f, "other", Mode::Auto);
    let changed = f.run_job(launch("srv")).unwrap();
    let locked = f.run_job(launch("other")).unwrap();
    f.control(ControlCommand::SetPolicy {
        name: "srv".into(),
        patch: PolicyPatch {
            grant_ttl: Some(std::time::Duration::from_secs(60)),
            ..PolicyPatch::default()
        },
    });
    assert_eq!(changed.ticket.ended().await, EndReason::HandleChanged);
    assert!(!locked.ticket.has_ended());
    f.control(ControlCommand::Lock);
    assert_eq!(locked.ticket.ended().await, EndReason::Locked);
}

#[test]
fn run_commands_are_validated_when_stored() {
    let mut f = Fixture::new();
    let refused = |f: &mut Fixture, secret| match f.send(
        Some(PASS),
        None,
        ControlCommand::Add {
            secret,
            replace: false,
        },
    ) {
        ControlResponse::Error {
            code: ControlErrorCode::Invalid,
            message,
        } => message,
        other => panic!("expected invalid, got {other:?}"),
    };
    let mut web = openrouter(Mode::Auto);
    web.policy.run = Some(vec!["/bin/tool".into()]);
    assert!(refused(&mut f, web).contains("only env handles"));
    let empty = env_secret("empty", &[], &[], Mode::Auto);
    assert!(refused(&mut f, empty).contains("at least one variable"));
    let mut blank = env_secret("blank", &[], &[], Mode::Auto);
    blank.policy.run = Some(vec![String::new()]);
    assert!(refused(&mut f, blank).contains("program is empty"));

    // A run-only handle: a command and no variables.
    f.add(run_secret("bare", &[], &["/usr/bin/true"], Mode::Auto));
    match f.send(
        Some(PASS),
        None,
        ControlCommand::SetPolicy {
            name: "bare".into(),
            patch: PolicyPatch {
                run: Some(Vec::new()),
                ..PolicyPatch::default()
            },
        },
    ) {
        ControlResponse::Error { message, .. } => {
            assert!(message.contains("at least one variable"), "{message}")
        }
        other => panic!("expected an error, got {other:?}"),
    }
    let job = f.run_job(launch("bare")).unwrap();
    assert!(job.env.is_empty());
}

#[test]
fn the_audit_log_names_the_program_but_not_its_arguments() {
    let mut f = Fixture::new();
    add_server(&mut f, "srv", Mode::Deny);
    let _ = f.run_job(launch("srv"));
    let lines = f.audit_lines();
    let run = lines
        .iter()
        .find(|line| line["action"] == "run")
        .expect("a run entry");
    assert_eq!(run["handle"], "srv");
    assert_eq!(run["summary"], "bunx");
    assert_eq!(run["decision"], "policy");
    for line in &lines {
        assert!(!line.to_string().contains(HOST), "{line}");
        assert!(!line.to_string().contains(SECRET), "{line}");
    }
}
