//! The worker behind `kv tray`, against a daemon running in this process,
//! a fake Touch ID and a desktop that records what it was asked to do.

mod fake;
mod live;

use std::io;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use fake::Fake;
use kv::device::{self, Device};
use kv::paths::Paths;
use kv::tray::model::{Action, IconState, Item, Model};
use kv::tray::worker::{Desktop, Worker};
use kv_core::proto::{AgentErrorCode, AgentResponse, ControlCommand, Verdict};
use live::{Daemon, PASS};
use tempfile::TempDir;

const REASON: &str = "open kv tray, where you approve agent requests";

#[derive(Clone, Default)]
struct Desk {
    notes: Arc<Mutex<Vec<String>>>,
    tuis: Arc<Mutex<usize>>,
    login: Arc<Mutex<bool>>,
}

impl Desktop for Desk {
    fn notify(&self, text: &str) {
        self.notes.lock().unwrap().push(text.to_owned());
    }

    fn open_tui(&self) -> io::Result<()> {
        *self.tuis.lock().unwrap() += 1;
        Ok(())
    }

    fn login_is_on(&self) -> bool {
        *self.login.lock().unwrap()
    }

    fn set_login(&self, on: bool) -> io::Result<()> {
        *self.login.lock().unwrap() = on;
        Ok(())
    }
}

impl Desk {
    fn notes(&self) -> Vec<String> {
        self.notes.lock().unwrap().clone()
    }
}

/// A daemon with Touch ID set up and the vault locked, and a worker for it.
async fn locked() -> (Daemon, Arc<Fake>, Desk, Worker<Desk>) {
    let daemon = Daemon::start().await;
    let fake = Arc::new(Fake::default());
    let (slot, key) = device::enroll(fake.as_ref()).unwrap();
    daemon
        .control(Some(PASS), device::enroll_command(slot, &key))
        .await;
    daemon.control(None, ControlCommand::Lock).await;
    let desk = Desk::default();
    let worker = Worker::new(
        daemon.paths.clone(),
        Some(fake.clone() as Arc<dyn Device>),
        desk.clone(),
    );
    (daemon, fake, desk, worker)
}

async fn unlocked() -> (Daemon, Arc<Fake>, Desk, Worker<Desk>) {
    let (daemon, fake, desk, mut worker) = locked().await;
    assert!(!worker.act(Action::Unlock).await);
    assert_eq!(desk.notes(), Vec::<String>::new());
    (daemon, fake, desk, worker)
}

fn labels(items: &[Item]) -> Vec<String> {
    items
        .iter()
        .map(|item| match item {
            Item::Action { label, .. } | Item::Check { label, .. } => label.clone(),
            Item::Submenu { label, .. } => format!("> {label}"),
            Item::Text(text) => format!("({text})"),
            Item::Separator => "--".into(),
        })
        .collect()
}

/// Asks for models until one shows a waiting request, and returns the
/// action behind `answer` in its submenu.
async fn waiting(worker: &mut Worker<Desk>, answer: &str) -> Action {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let model = worker.model().await;
        if model.icon == IconState::Waiting(1) {
            let Some(Item::Submenu { items, .. }) = model.menu.first() else {
                panic!("{:?}", model.menu);
            };
            return items
                .iter()
                .find_map(|item| match item {
                    Item::Action { label, action } if label == answer => Some(action.clone()),
                    _ => None,
                })
                .unwrap_or_else(|| panic!("no {answer:?} in {items:?}"));
        }
        assert!(Instant::now() < deadline, "the request never showed up");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn without_a_daemon_the_icon_is_off_and_none_is_started() {
    let dir = TempDir::new().unwrap();
    let paths = Paths::under(dir.path());
    let mut worker = Worker::new(paths.clone(), None, Desk::default());
    let model = worker.model().await;
    assert_eq!(model.icon, IconState::Off);
    assert_eq!(model.tooltip, "kv: not running");
    assert!(
        !paths.lock_file().exists(),
        "showing must not start a daemon"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn touch_id_unlocks_the_tray() {
    let (_daemon, fake, desk, mut worker) = locked().await;
    let model = worker.model().await;
    assert_eq!(model.icon, IconState::Locked);
    assert_eq!(labels(&model.menu)[0], "Unlock with Touch ID");

    assert!(!worker.act(Action::Unlock).await);
    assert_eq!(*fake.reasons.lock().unwrap(), vec![REASON.to_owned()]);
    assert_eq!(desk.notes(), Vec::<String>::new());
    let model = worker.model().await;
    assert_eq!(model.icon, IconState::Unlocked);
    assert_eq!(
        labels(&model.menu)[..3],
        ["(No requests waiting)", "--", "Lock vault"]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_cancelled_prompt_is_a_notification() {
    let (_daemon, fake, desk, mut worker) = locked().await;
    fake.keys.lock().unwrap().clear();
    assert!(!worker.act(Action::Unlock).await);
    let notes = desk.notes();
    assert_eq!(notes.len(), 1, "{notes:?}");
    assert!(notes[0].starts_with("Touch ID: "), "{notes:?}");
    assert_eq!(worker.model().await.icon, IconState::Locked);
}

#[tokio::test(flavor = "multi_thread")]
async fn allowing_from_the_menu_lets_the_call_through() {
    let (daemon, _fake, desk, mut worker) = unlocked().await;
    let call = daemon.agent_call();
    let allow = waiting(&mut worker, "Allow once").await;
    assert!(matches!(
        allow,
        Action::Decide {
            verdict: Verdict::AllowOnce,
            ..
        }
    ));
    assert!(!worker.act(allow).await);
    match call.await.unwrap() {
        AgentResponse::Http(reply) => assert_eq!(reply.status, 200),
        other => panic!("{other:?}"),
    }
    assert_eq!(desk.notes(), Vec::<String>::new());
    assert_eq!(worker.model().await.icon, IconState::Unlocked);
}

#[tokio::test(flavor = "multi_thread")]
async fn denying_from_the_menu_denies_the_call() {
    let (daemon, _fake, _desk, mut worker) = unlocked().await;
    let call = daemon.agent_call();
    let deny = waiting(&mut worker, "Deny").await;
    assert!(!worker.act(deny).await);
    match call.await.unwrap() {
        AgentResponse::Error { code, .. } => assert_eq!(code, AgentErrorCode::ApprovalDenied),
        other => panic!("{other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn answering_a_request_that_has_gone_is_a_notification() {
    let (_daemon, _fake, desk, mut worker) = unlocked().await;
    let gone = Action::Decide {
        id: 999,
        verdict: Verdict::AllowOnce,
    };
    assert!(!worker.act(gone).await);
    let notes = desk.notes();
    assert_eq!(notes.len(), 1, "{notes:?}");
    assert!(
        notes[0].starts_with("That request is no longer waiting"),
        "{notes:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn locking_elsewhere_or_from_the_menu_shows_locked() {
    let (daemon, _fake, desk, mut worker) = unlocked().await;
    daemon.control(None, ControlCommand::Lock).await;
    let model = worker.model().await;
    assert_eq!(model.icon, IconState::Locked);
    assert_eq!(labels(&model.menu)[0], "Unlock with Touch ID");

    assert!(!worker.act(Action::Unlock).await);
    assert_eq!(worker.model().await.icon, IconState::Unlocked);
    assert!(!worker.act(Action::Lock).await);
    let model = worker.model().await;
    assert_eq!(model.icon, IconState::Locked);
    assert_eq!(labels(&model.menu)[0], "Unlock with Touch ID");
    assert_eq!(desk.notes(), Vec::<String>::new());
}

/// The tray keeps its session only while the daemon runs; a new daemon
/// needs a new unlock.
#[tokio::test(flavor = "multi_thread")]
async fn a_stopped_daemon_ends_the_session() {
    let (daemon, _fake, _desk, mut worker) = unlocked().await;
    daemon.control(None, ControlCommand::Stop).await;
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let model = worker.model().await;
        if model.icon == IconState::Off {
            assert_eq!(model.tooltip, "kv: not running");
            assert_eq!(labels(&model.menu)[0], "Unlock with Touch ID");
            break;
        }
        assert!(Instant::now() < deadline, "{model:?}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_tui_and_the_login_item_go_to_the_desktop() {
    let (_daemon, _fake, desk, mut worker) = locked().await;
    assert!(!worker.act(Action::OpenTui).await);
    assert!(!worker.act(Action::HandleRequests).await);
    assert_eq!(*desk.tuis.lock().unwrap(), 2);

    assert!(!worker.act(Action::Login(true)).await);
    assert!(*desk.login.lock().unwrap());
    let model = worker.model().await;
    let check = model.menu.iter().find_map(|item| match item {
        Item::Check {
            checked, action, ..
        } => Some((*checked, action.clone())),
        _ => None,
    });
    assert_eq!(check, Some((true, Action::Login(false))));
    assert!(worker.act(Action::Quit).await);
}

/// The loop shows a model every tick, keeps showing them while a Touch ID
/// prompt is open, and stops on Quit.
#[tokio::test(flavor = "multi_thread")]
async fn the_loop_keeps_showing_while_the_prompt_is_open() {
    let (_daemon, fake, _desk, worker) = locked().await;
    let (release, gate) = std::sync::mpsc::channel();
    *fake.gate.lock().unwrap() = Some(gate);
    let shown: Arc<Mutex<Vec<Model>>> = Arc::default();
    let (actions, inbox) = tokio::sync::mpsc::unbounded_channel();
    let record = shown.clone();
    let running = tokio::spawn(worker.run(inbox, move |model| {
        record.lock().unwrap().push(model);
    }));

    let wait_for = |what: &'static str, test: fn(&Model) -> bool| {
        let shown = shown.clone();
        async move {
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                if shown.lock().unwrap().iter().any(test) {
                    return;
                }
                assert!(Instant::now() < deadline, "never showed {what}");
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }
    };
    wait_for("locked", |m| m.icon == IconState::Locked).await;
    actions.send(Action::Unlock).unwrap();
    let before = shown.lock().unwrap().len();
    let deadline = Instant::now() + Duration::from_secs(5);
    while shown.lock().unwrap().len() < before + 2 {
        assert!(Instant::now() < deadline, "the prompt held up the loop");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        shown
            .lock()
            .unwrap()
            .iter()
            .all(|m| m.icon == IconState::Locked),
        "not unlocked before the prompt answers"
    );
    release.send(()).unwrap();
    wait_for("unlocked", |m| m.icon == IconState::Unlocked).await;

    actions.send(Action::Quit).unwrap();
    tokio::time::timeout(Duration::from_secs(5), running)
        .await
        .expect("the loop stops on Quit")
        .unwrap();
}
