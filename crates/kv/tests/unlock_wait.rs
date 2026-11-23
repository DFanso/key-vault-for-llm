//! Through the real daemon sockets: an agent call refused because the vault
//! is locked waits for an unlock (`KV_UNLOCK_WAIT`), after its notice is
//! queued, and runs once the user unlocks; it fails as before when the
//! wait runs out, is off, or too many calls wait already. And the reminder
//! halfway through an approval's wait reaches kv tray.
//!
//! Each test takes the daemon's notices as kv tray does, so none is posted
//! on the machine running the tests.

mod live;

use std::time::{Duration, Instant};

use kv::client;
use kv::daemon::{MAX_UNLOCK_WAITERS, Settings};
use kv::notify::Level;
use kv_core::proto::{
    AgentErrorCode, AgentResponse, ControlCommand, ControlResponse, Notice, NoticeKind, Verdict,
};
use live::{Daemon, PASS, request};

fn settings(unlock_wait: Duration, notify: Level) -> Settings {
    Settings {
        approval_wait: Duration::from_secs(2),
        notify,
        unlock_wait,
        ..Settings::default()
    }
}

/// What `kv tray` asks every second: no credential, and it marks the
/// asker as the one posting notices.
async fn take_notices(daemon: &Daemon) -> Vec<Notice> {
    let ask = request(None, None, ControlCommand::NotifyingStatus);
    match client::control_if_running(&daemon.paths, &ask).await {
        Ok(Some(ControlResponse::Notices { notices, .. })) => notices,
        other => panic!("expected notices, got {other:?}"),
    }
}

/// Takes notices until one of `kind` shows up.
async fn notice_of(daemon: &Daemon, kind: NoticeKind) -> Notice {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(notice) = take_notices(daemon)
            .await
            .into_iter()
            .find(|notice| notice.kind == kind)
        {
            return notice;
        }
        assert!(Instant::now() < deadline, "no {kind:?} notice");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

fn error_code(response: AgentResponse) -> AgentErrorCode {
    match response {
        AgentResponse::Error { code, .. } => code,
        other => panic!("expected an error, got {other:?}"),
    }
}

async fn locked(settings: Settings) -> Daemon {
    let daemon = Daemon::start_with(settings).await;
    daemon.control(None, ControlCommand::Lock).await;
    take_notices(&daemon).await;
    daemon
}

#[tokio::test(flavor = "multi_thread")]
async fn a_call_waits_for_the_unlock_after_its_notice_and_then_runs() {
    let mut daemon = locked(settings(Duration::from_secs(20), Level::Ask)).await;
    let call = daemon.agent_call();
    let notice = notice_of(&daemon, NoticeKind::UnlockNeeded).await;
    assert_eq!(
        notice.body,
        "approval test is waiting (http_request): unlock kv."
    );
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!call.is_finished(), "the call waits for the unlock");

    daemon.token = match daemon
        .control(Some(PASS), ControlCommand::OpenSession)
        .await
    {
        ControlResponse::Session { token } => token,
        other => panic!("{other:?}"),
    };
    // It runs again, unlocked: the handle is in mode ask, so it waits for
    // approval now.
    let id = daemon.waiting_id().await;
    daemon
        .with_token(ControlCommand::Decide {
            id,
            verdict: Verdict::AllowOnce,
        })
        .await;
    match call.await.unwrap() {
        AgentResponse::Http(reply) => assert_eq!(reply.status, 200),
        other => panic!("{other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_call_no_one_unlocks_for_fails_as_before_when_the_wait_runs_out() {
    let daemon = locked(settings(Duration::from_secs(1), Level::Ask)).await;
    let started = Instant::now();
    let call = daemon.agent_call();
    notice_of(&daemon, NoticeKind::UnlockNeeded).await;
    assert_eq!(error_code(call.await.unwrap()), AgentErrorCode::VaultLocked);
    assert!(started.elapsed() >= Duration::from_secs(1));
}

#[tokio::test(flavor = "multi_thread")]
async fn without_the_wait_or_without_notifications_a_call_fails_at_once() {
    for (wait, notify) in [
        (Duration::ZERO, Level::Ask),
        (Duration::from_secs(20), Level::Off),
    ] {
        let daemon = locked(settings(wait, notify)).await;
        let started = Instant::now();
        let reply = daemon.agent_call().await.unwrap();
        assert_eq!(error_code(reply), AgentErrorCode::VaultLocked);
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "{wait:?} {notify:?}: {:?}",
            started.elapsed()
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn only_so_many_calls_wait_for_an_unlock_at_once() {
    let daemon = locked(settings(Duration::from_secs(4), Level::Ask)).await;
    let waiting: Vec<_> = (0..MAX_UNLOCK_WAITERS)
        .map(|_| daemon.agent_call())
        .collect();
    tokio::time::sleep(Duration::from_millis(1500)).await;
    take_notices(&daemon).await;
    assert!(waiting.iter().all(|call| !call.is_finished()));

    let started = Instant::now();
    let reply = daemon.agent_call().await.unwrap();
    assert_eq!(error_code(reply), AgentErrorCode::VaultLocked);
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "one past the limit fails at once: {:?}",
        started.elapsed()
    );
    for call in waiting {
        assert_eq!(error_code(call.await.unwrap()), AgentErrorCode::VaultLocked);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_request_still_waiting_halfway_is_reminded_through_kv_tray() {
    let daemon = Daemon::start_with(settings(Duration::ZERO, Level::Ask)).await;
    take_notices(&daemon).await;
    let started = Instant::now();
    let call = daemon.agent_call();
    let id = daemon.waiting_id().await;
    let notice = notice_of(&daemon, NoticeKind::Reminder { id }).await;
    assert!(started.elapsed() >= Duration::from_secs(1));
    assert!(notice.body.ends_with("About 1 s left."), "{}", notice.body);
    assert!(!call.is_finished());
    assert_eq!(
        error_code(call.await.unwrap()),
        AgentErrorCode::ApprovalTimeout
    );
}
