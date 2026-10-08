//! Approvals through the real daemon sockets: an agent request waits on the
//! agent socket while a `kv tui` session decides on the control socket.

mod live;

use std::time::{Duration, Instant};

use kv_core::proto::{AgentErrorCode, AgentResponse, ControlCommand, ControlResponse, Verdict};
use live::Daemon;

fn error_code(response: AgentResponse) -> AgentErrorCode {
    match response {
        AgentResponse::Error { code, .. } => code,
        other => panic!("expected an error, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn an_approved_request_runs_and_reaches_upstream() {
    let daemon = Daemon::start().await;
    let call = daemon.agent_call();
    let id = daemon.waiting_id().await;
    assert!(
        daemon
            .upstream
            .received_requests()
            .await
            .unwrap()
            .is_empty()
    );
    let decided = daemon
        .with_token(ControlCommand::Decide {
            id,
            verdict: Verdict::AllowOnce,
        })
        .await;
    assert!(
        matches!(decided, ControlResponse::Done { .. }),
        "{decided:?}"
    );
    match call.await.unwrap() {
        AgentResponse::Http(reply) => assert_eq!((reply.status, reply.body.as_str()), (200, "ok")),
        other => panic!("{other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_denied_request_never_reaches_upstream() {
    let daemon = Daemon::start().await;
    let call = daemon.agent_call();
    let id = daemon.waiting_id().await;
    daemon
        .with_token(ControlCommand::Decide {
            id,
            verdict: Verdict::Deny,
        })
        .await;
    assert_eq!(
        error_code(call.await.unwrap()),
        AgentErrorCode::ApprovalDenied
    );
    assert!(
        daemon
            .upstream
            .received_requests()
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unanswered_request_times_out() {
    let daemon = Daemon::start().await;
    let started = Instant::now();
    let call = daemon.agent_call();
    daemon.waiting_id().await;
    assert_eq!(
        error_code(call.await.unwrap()),
        AgentErrorCode::ApprovalTimeout
    );
    assert!(started.elapsed() >= Duration::from_secs(2));
    match daemon.with_token(ControlCommand::Overview).await {
        ControlResponse::Overview { overview } => assert!(overview.approvals.is_empty()),
        other => panic!("{other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn locking_answers_a_waiting_request_at_once() {
    let daemon = Daemon::start().await;
    let call = daemon.agent_call();
    daemon.waiting_id().await;
    let started = Instant::now();
    daemon.control(None, ControlCommand::Lock).await;
    assert_eq!(error_code(call.await.unwrap()), AgentErrorCode::VaultLocked);
    assert!(started.elapsed() < Duration::from_secs(1));
    assert!(
        daemon
            .upstream
            .received_requests()
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_request_whose_agent_hung_up_is_withdrawn() {
    let daemon = Daemon::start().await;
    let call = daemon.agent_call();
    let id = daemon.waiting_id().await;
    call.abort();
    let _ = call.await;
    // Well before the 2 s approval wait runs out.
    let deadline = Instant::now() + Duration::from_secs(1);
    loop {
        match daemon.with_token(ControlCommand::Overview).await {
            ControlResponse::Overview { overview } if overview.approvals.is_empty() => break,
            ControlResponse::Overview { .. } => {}
            other => panic!("{other:?}"),
        }
        assert!(Instant::now() < deadline, "the request is still waiting");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let late = daemon
        .with_token(ControlCommand::Decide {
            id,
            verdict: Verdict::AllowOnce,
        })
        .await;
    assert!(matches!(late, ControlResponse::Error { .. }), "{late:?}");
    assert!(
        daemon
            .upstream
            .received_requests()
            .await
            .unwrap()
            .is_empty()
    );
    let audit = std::fs::read_to_string(&daemon.paths.audit).unwrap();
    assert!(audit.contains(r#""outcome":"cancelled""#), "{audit}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_request_waiting_on_a_changed_handle_is_told_why() {
    let daemon = Daemon::start().await;
    let call = daemon.agent_call();
    daemon.waiting_id().await;
    daemon
        .with_token(ControlCommand::SetPolicy {
            name: "api".into(),
            patch: kv_core::proto::PolicyPatch {
                allow_plain_http: Some(false),
                ..Default::default()
            },
        })
        .await;
    match call.await.unwrap() {
        AgentResponse::Error { code, message } => {
            assert_eq!(code, AgentErrorCode::PolicyDenied);
            assert!(message.contains("changed"), "{message}");
        }
        other => panic!("{other:?}"),
    }
}
