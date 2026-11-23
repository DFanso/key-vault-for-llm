//! What the daemon tells the user about things waiting on them, besides
//! approval notices: an agent refused because the vault is locked, a
//! reminder halfway through a request's wait, requests that timed out, and
//! where each notice goes: to kv tray while it takes them, else to the
//! daemon's own plain notifications.

mod common;

use std::time::{Duration, SystemTime};

use common::*;
use kv::daemon::{After, MISSED_GATHER, Plain, Settings, TAKER_FRESH};
use kv_core::policy::Mode;
use kv_core::proto::{
    AgentErrorCode, AgentRequest, AgentResponse, ControlCommand, ControlResponse, Notice,
    NoticeKind, Status,
};

fn call() -> AgentRequest {
    AgentRequest::HttpRequest(get("openrouter", "https://openrouter.ai/api/v1/models"))
}

fn notifying_status(f: &mut Fixture, at: std::time::Instant) -> (Status, Vec<Notice>) {
    match f.send_at(at, None, None, ControlCommand::NotifyingStatus) {
        ControlResponse::Notices { status, notices } => (status, notices),
        other => panic!("expected notices, got {other:?}"),
    }
}

fn plain(f: &mut Fixture) -> Vec<Plain> {
    f.daemon.take_plain_notices()
}

fn locked_reply(prepared: kv::daemon::Prepared) {
    match prepared {
        kv::daemon::Prepared::Reply(AgentResponse::Error { code, .. }) => {
            assert_eq!(code, AgentErrorCode::VaultLocked)
        }
        _ => panic!("expected vault_locked"),
    }
}

#[test]
fn an_agent_refused_for_a_locked_vault_is_announced_with_who_and_what() {
    let mut f = Fixture::notifying();
    let t0 = f.t0;
    f.add(openrouter(Mode::Auto));
    f.control(ControlCommand::Lock);
    let s = session("s1");
    locked_reply(f.daemon.prepare_in(Some(&s), call(), t0));
    let notices = plain(&mut f);
    assert_eq!(notices.len(), 1, "{notices:?}");
    assert_eq!(notices[0].kind, NoticeKind::UnlockNeeded);
    assert_eq!(notices[0].title, "kv: unlock needed");
    assert!(
        notices[0]
            .body
            .starts_with("test agent is waiting (http_request): unlock kv."),
        "{}",
        notices[0].body
    );
    // kv tray reads the status every second, and agents list handles on
    // their own: neither means an agent waits on the user.
    let mut f = Fixture::notifying();
    let t0 = f.t0;
    f.control(ControlCommand::Lock);
    f.daemon.prepare_in(Some(&s), AgentRequest::Status, t0);
    locked_reply(f.daemon.prepare_in(Some(&s), AgentRequest::ListHandles, t0));
    assert!(plain(&mut f).is_empty());
}

#[test]
fn nothing_is_announced_with_notifications_off() {
    let mut f = Fixture::new();
    let t0 = f.t0;
    f.control(ControlCommand::Lock);
    locked_reply(f.daemon.prepare_in(None, call(), t0));
    assert!(plain(&mut f).is_empty());
}

#[test]
fn an_unlock_starts_a_new_locked_period() {
    let mut f = Fixture::notifying();
    let t0 = f.t0;
    f.control(ControlCommand::Lock);
    f.daemon.prepare_in(None, call(), t0);
    f.daemon
        .prepare_in(None, call(), t0 + Duration::from_secs(1));
    assert_eq!(plain(&mut f).len(), 1, "once per locked period");
    f.control(ControlCommand::Unlock);
    f.control(ControlCommand::Lock);
    f.daemon
        .prepare_in(None, call(), t0 + Duration::from_secs(2));
    assert_eq!(plain(&mut f).len(), 1, "a new period is told at once");
}

#[test]
fn notifying_status_needs_no_credential_and_queues_notices_for_its_client() {
    let mut f = Fixture::notifying();
    let t0 = f.t0;
    f.control(ControlCommand::Lock);
    let audited = f.audit_lines().len();
    let (status, notices) = notifying_status(&mut f, t0);
    assert!(status.locked);
    assert!(notices.is_empty());
    assert!(f.daemon.has_notice_taker(t0));
    assert_eq!(f.audit_lines().len(), audited, "not audited");

    let s = session("s1");
    f.daemon.prepare_in(Some(&s), call(), t0);
    assert!(plain(&mut f).is_empty(), "kv tray posts it, not the daemon");
    let (_, notices) = notifying_status(&mut f, t0 + Duration::from_secs(1));
    assert_eq!(notices.len(), 1);
    assert_eq!(notices[0].kind, NoticeKind::UnlockNeeded);
    assert_eq!(
        notices[0].body,
        "test agent is waiting (http_request): unlock kv."
    );
    // Taken once.
    let (_, notices) = notifying_status(&mut f, t0 + Duration::from_secs(2));
    assert!(notices.is_empty());
}

#[test]
fn notices_the_tray_stops_taking_go_to_the_daemons_own() {
    let mut f = Fixture::notifying();
    let t0 = f.t0;
    f.control(ControlCommand::Lock);
    notifying_status(&mut f, t0);
    f.daemon.prepare_in(None, call(), t0);
    f.daemon
        .notice_tick(t0 + TAKER_FRESH - Duration::from_millis(1));
    assert!(plain(&mut f).is_empty());
    f.daemon.notice_tick(t0 + TAKER_FRESH);
    let notices = plain(&mut f);
    assert_eq!(notices.len(), 1);
    assert!(
        notices[0]
            .body
            .ends_with("Run `kv unlock`, or unlock it from kv tray."),
        "{}",
        notices[0].body
    );
    let (_, taken) = notifying_status(&mut f, t0 + TAKER_FRESH);
    assert!(taken.is_empty(), "nothing shows twice");
}

#[test]
fn polling_notifying_status_does_not_keep_a_locked_daemon_running() {
    let mut f = Fixture::notifying();
    let t0 = f.t0;
    f.control(ControlCommand::Lock);
    let exit = Settings::default().locked_exit;
    for secs in (0..=exit.as_secs()).step_by(60) {
        notifying_status(&mut f, t0 + Duration::from_secs(secs));
    }
    assert_eq!(f.daemon.tick(t0 + exit, SystemTime::now()), After::Stop);
}

#[test]
fn a_request_still_waiting_is_reminded_with_the_time_left() {
    let mut f = Fixture::notifying();
    let t0 = f.t0;
    f.add(openrouter(Mode::Ask));
    let s = session("s1");
    let waiting = f.wait(Some(&s), call(), t0);
    let wait = Settings::default().approval_wait;
    assert!(f.daemon.remind(waiting.id, t0 + wait / 2));
    let notices = plain(&mut f);
    assert_eq!(notices.len(), 1);
    assert_eq!(notices[0].kind, NoticeKind::Reminder { id: waiting.id });
    assert_eq!(notices[0].title, "kv: still waiting");
    assert_eq!(
        notices[0].body,
        format!("{} About 30 s left.", waiting.notice)
    );
    assert!(notices[0].waiting());

    // Answered: nothing to remind of.
    let token = f.token();
    f.decide(&token, waiting.id, kv_core::proto::Verdict::Deny);
    assert!(!f.daemon.remind(waiting.id, t0 + wait / 2));
    assert!(plain(&mut f).is_empty());
}

#[test]
fn requests_that_time_out_are_told_of_together() {
    let mut f = Fixture::notifying();
    let t0 = f.t0;
    f.add(openrouter(Mode::Ask));
    let s = session("s1");
    let first = f.wait(Some(&s), call(), t0);
    let second = f.wait(Some(&s), call(), t0);
    let wait = Settings::default().approval_wait;
    let out = t0 + wait;
    assert!(f.daemon.expire(first.id, out).is_some());
    assert!(f.daemon.expire(second.id, out).is_some());
    f.daemon
        .notice_tick(out + MISSED_GATHER - Duration::from_millis(1));
    assert!(plain(&mut f).is_empty(), "they gather first");
    f.daemon.notice_tick(out + MISSED_GATHER);
    let notices = plain(&mut f);
    assert_eq!(notices.len(), 1, "{notices:?}");
    assert_eq!(notices[0].kind, NoticeKind::Missed);
    assert_eq!(
        notices[0].body,
        "You missed 2 requests (test agent: openrouter). Open kv tui's Audit tab to see them."
    );
}

#[test]
fn a_reminder_goes_to_kv_tray_while_it_takes_notices() {
    let mut f = Fixture::notifying();
    let t0 = f.t0;
    f.add(openrouter(Mode::Ask));
    let waiting = f.wait(None, call(), t0);
    notifying_status(&mut f, t0);
    assert!(f.daemon.remind(waiting.id, t0 + Duration::from_secs(1)));
    assert!(plain(&mut f).is_empty());
    let (_, notices) = notifying_status(&mut f, t0 + Duration::from_secs(2));
    assert_eq!(notices.len(), 1);
    assert_eq!(notices[0].kind, NoticeKind::Reminder { id: waiting.id });
}
