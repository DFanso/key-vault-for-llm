//! `kv tui`'s app and driver against a real daemon in this process: unlock,
//! see a waiting agent request, approve it, lock.

mod live;

use std::time::{Duration, Instant};

use kv::tui::Driver;
use kv::tui::app::{App, Effect, Outcome, Screen};
use kv_core::proto::{AgentResponse, ControlCommand};
use live::{Daemon, PASS};
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

fn key(app: &mut App, code: KeyCode) -> Option<Effect> {
    app.handle_key(KeyEvent::new(code, KeyModifiers::NONE))
}

/// Feeds one key to the app and carries out what it asks for, as the
/// terminal loop does.
async fn press(app: &mut App, driver: &mut Driver, code: KeyCode) {
    if let Some(effect) = key(app, code) {
        let outcome = driver.run(effect).await;
        app.apply(outcome);
    }
}

async fn unlock(app: &mut App, driver: &mut Driver, passphrase: &str) {
    for c in passphrase.chars() {
        press(app, driver, KeyCode::Char(c)).await;
    }
    press(app, driver, KeyCode::Enter).await;
}

async fn refresh(app: &mut App, driver: &mut Driver) {
    if let Some(outcome) = driver.refresh().await {
        app.apply(outcome);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn unlock_approve_and_lock_through_the_tui() {
    let daemon = Daemon::start().await;
    let mut driver = Driver::new(daemon.paths.clone());
    let mut app = App::new();
    assert!(driver.refresh().await.is_none(), "no session yet");

    unlock(&mut app, &mut driver, PASS).await;
    assert_eq!(app.screen(), Screen::Main);
    refresh(&mut app, &mut driver).await;
    assert_eq!(app.overview().unwrap().handles[0].name, "api");

    let call = daemon.agent_call();
    let deadline = Instant::now() + Duration::from_secs(5);
    while app.overview().is_none_or(|o| o.approvals.is_empty()) {
        assert!(Instant::now() < deadline, "the request never showed up");
        tokio::time::sleep(Duration::from_millis(20)).await;
        refresh(&mut app, &mut driver).await;
    }
    press(&mut app, &mut driver, KeyCode::Char('a')).await;
    match call.await.unwrap() {
        AgentResponse::Http(reply) => assert_eq!(reply.status, 200),
        other => panic!("{other:?}"),
    }

    press(&mut app, &mut driver, KeyCode::Char('L')).await;
    assert_eq!(app.screen(), Screen::Unlock);
    assert!(
        driver.refresh().await.is_none(),
        "locking drops the session"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn locking_elsewhere_ends_the_tui_session() {
    let daemon = Daemon::start().await;
    let mut driver = Driver::new(daemon.paths.clone());
    let mut app = App::new();
    unlock(&mut app, &mut driver, PASS).await;
    daemon.control(None, ControlCommand::Lock).await;
    refresh(&mut app, &mut driver).await;
    assert_eq!(app.screen(), Screen::Unlock);
    assert!(
        app.message().unwrap().contains("locked"),
        "{:?}",
        app.message()
    );
    assert!(driver.refresh().await.is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_wrong_passphrase_is_reported() {
    let daemon = Daemon::start().await;
    let mut driver = Driver::new(daemon.paths.clone());
    let mut app = App::new();
    unlock(&mut app, &mut driver, "not the passphrase").await;
    assert_eq!(app.screen(), Screen::Unlock);
    assert!(
        app.message().unwrap().contains("wrong passphrase"),
        "{:?}",
        app.message()
    );
    assert!(matches!(
        driver.run(Effect::Quit).await,
        Outcome::Done(warnings) if warnings.is_empty()
    ));
}
