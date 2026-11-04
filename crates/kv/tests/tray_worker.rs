//! The worker behind `kv tray`, against a daemon running in this process,
//! a fake Touch ID and a desktop that records what it was asked to do,
//! including every message to the window's page.

mod fake;
mod live;

use std::collections::BTreeMap;
use std::io;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use fake::Fake;
use kv::client;
use kv::device::{self, Device};
use kv::paths::Paths;
use kv::tray::model::{Action, IconState, Item, Model};
use kv::tray::window::{FormRequest, FromPage, ImportVar, Tab, Theme, ToPage};
use kv::tray::worker::{Desktop, Worker};
use kv::tui::app::ShareDone;
use kv_core::proto::{
    AgentErrorCode, AgentRequest, AgentResponse, ControlCommand, HandleRequest, Overview,
    SessionInfo, Verdict,
};
use kv_core::secret::{SecretKind, SecretText};
use live::{Daemon, PASS};
use tempfile::TempDir;

const REASON: &str = "open kv tray, where you approve agent requests";

#[derive(Clone, Default)]
struct Desk {
    notes: Arc<Mutex<Vec<String>>>,
    windows: Arc<Mutex<Vec<Tab>>>,
    pages: Arc<Mutex<Vec<ToPage>>>,
    login: Arc<Mutex<bool>>,
}

impl Desktop for Desk {
    fn notify(&self, text: &str) {
        self.notes.lock().unwrap().push(text.to_owned());
    }

    fn show_window(&self, tab: Tab) {
        self.windows.lock().unwrap().push(tab);
    }

    fn page(&self, message: ToPage) {
        self.pages.lock().unwrap().push(message);
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

    /// The page messages since the last call.
    fn take(&self) -> Vec<ToPage> {
        std::mem::take(&mut *self.pages.lock().unwrap())
    }
}

/// The last `State` in `pages`: whether locked, whether waiting for the
/// device, and the overview.
fn state(pages: &[ToPage]) -> (bool, bool, Option<Overview>) {
    pages
        .iter()
        .rev()
        .find_map(|page| match page {
            ToPage::State {
                locked,
                waiting_for_device,
                overview,
                ..
            } => Some((*locked, *waiting_for_device, overview.clone())),
            _ => None,
        })
        .unwrap_or_else(|| panic!("no state in {pages:?}"))
}

fn messages(pages: &[ToPage]) -> Vec<(String, Option<u64>)> {
    pages
        .iter()
        .filter_map(|page| match page {
            ToPage::Message { text, request } => Some((text.clone(), *request)),
            _ => None,
        })
        .collect()
}

fn page(message: FromPage) -> Action {
    Action::Window(message)
}

fn values(pairs: &[(&str, &str)]) -> BTreeMap<String, SecretText> {
    pairs
        .iter()
        .map(|(key, value)| ((*key).to_owned(), SecretText::new(*value)))
        .collect()
}

/// The handle names the last state's overview lists.
async fn handles(worker: &mut Worker<Desk>, desk: &Desk) -> Vec<String> {
    worker.model().await;
    let (_, _, overview) = state(&desk.take());
    overview
        .expect("a session")
        .handles
        .into_iter()
        .map(|handle| handle.name)
        .collect()
}

/// What an agent's `request_handle` sends.
async fn request_handle(daemon: &Daemon, name: &str) {
    let session = SessionInfo {
        id: "session-1".into(),
        client: "tray test".into(),
    };
    let request = AgentRequest::RequestHandle(HandleRequest {
        name: name.into(),
        kind: SecretKind::Http,
        description: "Staging API".into(),
        reason: "to check the staging deploy".into(),
        auth: None,
        base_url: false,
        allowed_hosts: vec!["staging.example.com".into()],
        env_vars: Vec::new(),
        allowed_cmds: Vec::new(),
    });
    let response = client::agent(&daemon.paths, Some(&session), &request)
        .await
        .unwrap();
    assert_eq!(response, AgentResponse::Requested { name: name.into() });
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
async fn the_window_and_the_login_item_go_to_the_desktop() {
    let (_daemon, _fake, desk, mut worker) = unlocked().await;
    assert!(!worker.act(Action::Open(Tab::Approvals)).await);
    assert!(!worker.act(Action::Open(Tab::Handles)).await);
    assert_eq!(
        *desk.windows.lock().unwrap(),
        [Tab::Approvals, Tab::Handles]
    );
    let pages = desk.take();
    assert!(
        pages.contains(&ToPage::Show { tab: Tab::Handles }),
        "{pages:?}"
    );

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

/// The menu a click on the icon opens shows kv on Home without a prompt;
/// its Unlock asks.
#[tokio::test(flavor = "multi_thread")]
async fn the_menu_waits_for_unlock_to_ask_for_touch_id() {
    let (_daemon, fake, desk, mut worker) = locked().await;
    assert!(!worker.act(Action::Menu).await);
    assert!(fake.reasons.lock().unwrap().is_empty(), "no prompt yet");
    let pages = desk.take();
    assert!(
        pages.contains(&ToPage::Show { tab: Tab::Home }),
        "{pages:?}"
    );

    assert!(!worker.act(page(FromPage::DeviceUnlock)).await);
    assert_eq!(fake.reasons.lock().unwrap().len(), 1);
    worker.model().await;
    let (locked, _, _) = state(&desk.take());
    assert!(!locked);
}

/// Opening the window while locked asks for Touch ID once; a cancelled
/// prompt says why in the window, not in a notification, and the window can
/// ask again.
#[tokio::test(flavor = "multi_thread")]
async fn the_window_asks_for_touch_id_when_it_opens() {
    let (_daemon, fake, desk, mut worker) = locked().await;
    let key = fake.keys.lock().unwrap().clone();
    fake.keys.lock().unwrap().clear();
    assert!(!worker.act(Action::Open(Tab::Approvals)).await);
    assert_eq!(fake.reasons.lock().unwrap().len(), 1);
    let pages = desk.take();
    let said = messages(&pages);
    assert_eq!(said.len(), 1, "{pages:?}");
    assert!(said[0].0.starts_with("Touch ID: "), "{said:?}");
    assert_eq!(desk.notes(), Vec::<String>::new());

    // Already open: no second prompt.
    assert!(!worker.act(Action::Open(Tab::Approvals)).await);
    assert_eq!(fake.reasons.lock().unwrap().len(), 1);

    *fake.keys.lock().unwrap() = key;
    assert!(!worker.act(page(FromPage::DeviceUnlock)).await);
    assert_eq!(fake.reasons.lock().unwrap().len(), 2);
    worker.model().await;
    let (locked, waiting, overview) = state(&desk.take());
    assert!(!locked && !waiting && overview.is_some());
}

#[tokio::test(flavor = "multi_thread")]
async fn the_passphrase_typed_in_the_window_unlocks() {
    let (daemon, _fake, _desk, _worker) = locked().await;
    let desk = Desk::default();
    let mut worker = Worker::new(daemon.paths.clone(), None, desk.clone());
    // No device: the window opens on the passphrase field, asking nothing.
    assert!(!worker.act(Action::Open(Tab::Approvals)).await);
    worker.model().await;
    let pages = desk.take();
    assert!(state(&pages).0, "{pages:?}");
    assert!(messages(&pages).is_empty(), "{pages:?}");

    let wrong = FromPage::Unlock {
        passphrase: SecretText::new("not it"),
    };
    assert!(!worker.act(page(wrong)).await);
    let pages = desk.take();
    assert_eq!(
        messages(&pages),
        [("Wrong passphrase".to_owned(), None)],
        "{pages:?}"
    );

    let right = FromPage::Unlock {
        passphrase: SecretText::new(PASS),
    };
    assert!(!worker.act(page(right)).await);
    assert_eq!(worker.model().await.icon, IconState::Unlocked);
    assert!(!state(&desk.take()).0);
    assert_eq!(desk.notes(), Vec::<String>::new());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_card_in_the_window_answers_its_request() {
    let (daemon, _fake, desk, mut worker) = unlocked().await;
    assert!(!worker.act(Action::Open(Tab::Approvals)).await);
    let call = daemon.agent_call();
    let Action::Decide { id, .. } = waiting(&mut worker, "Allow once").await else {
        unreachable!()
    };
    let allow = FromPage::Decide {
        id,
        verdict: Verdict::AllowOnce,
    };
    assert!(!worker.act(page(allow)).await);
    match call.await.unwrap() {
        AgentResponse::Http(reply) => assert_eq!(reply.status, 200),
        other => panic!("{other:?}"),
    }

    desk.take();
    let gone = FromPage::Decide {
        id: 999,
        verdict: Verdict::Deny,
    };
    assert!(!worker.act(page(gone)).await);
    let said = messages(&desk.take());
    assert_eq!(said.len(), 1, "{said:?}");
    assert!(
        said[0].0.starts_with("That request is no longer waiting"),
        "{said:?}"
    );
    assert_eq!(said[0].1, Some(999));
    assert_eq!(desk.notes(), Vec::<String>::new());
}

#[tokio::test(flavor = "multi_thread")]
async fn handles_are_added_edited_policed_and_removed_from_the_window() {
    let (_daemon, _fake, desk, mut worker) = unlocked().await;
    assert!(!worker.act(Action::Open(Tab::Handles)).await);
    worker.model().await;
    desk.take();

    let open = |form| page(FromPage::OpenForm { form });
    let submit = |pairs: &[(&str, &str)]| {
        page(FromPage::SubmitForm {
            values: values(pairs),
        })
    };
    assert!(!worker.act(open(FormRequest::New)).await);
    let pages = desk.take();
    let Some(ToPage::Form { view }) = pages.last() else {
        panic!("{pages:?}");
    };
    assert_eq!(view.title, "New handle");

    // Rust checks the form: no token yet.
    assert!(
        !worker
            .act(submit(&[("name", "github"), ("hosts", "api.github.com")]))
            .await
    );
    let pages = desk.take();
    assert!(
        matches!(pages.as_slice(), [ToPage::FormError { .. }]),
        "{pages:?}"
    );
    assert!(
        !worker
            .act(submit(&[
                ("name", "github"),
                ("hosts", "api.github.com"),
                ("token", "ghp_secret"),
            ]))
            .await
    );
    assert!(desk.take().contains(&ToPage::FormDone));
    assert!(handles(&mut worker, &desk).await.contains(&"github".into()));

    assert!(
        !worker
            .act(open(FormRequest::Edit {
                name: "github".into()
            }))
            .await
    );
    let pages = desk.take();
    let Some(ToPage::Form { view }) = pages.last() else {
        panic!("{pages:?}");
    };
    assert_eq!(view.title, "Edit github");
    assert!(
        !serde_json::to_string(view).unwrap().contains("ghp_secret"),
        "{view:?}"
    );
    assert!(!worker.act(submit(&[("description", "GitHub API")])).await);
    assert!(desk.take().contains(&ToPage::FormDone));

    assert!(
        !worker
            .act(open(FormRequest::Policy {
                name: "github".into()
            }))
            .await
    );
    assert!(!worker.act(submit(&[("mode", "deny")])).await);
    assert!(desk.take().contains(&ToPage::FormDone));
    worker.model().await;
    let (_, _, overview) = state(&desk.take());
    let github = overview
        .unwrap()
        .handles
        .into_iter()
        .find(|handle| handle.name == "github")
        .unwrap();
    assert_eq!(github.description, "GitHub API");
    assert_eq!(github.mode, kv_core::policy::Mode::Deny);

    assert!(
        !worker
            .act(page(FromPage::Remove {
                name: "github".into()
            }))
            .await
    );
    assert!(!handles(&mut worker, &desk).await.contains(&"github".into()));
    assert_eq!(desk.notes(), Vec::<String>::new());
}

#[tokio::test(flavor = "multi_thread")]
async fn an_agents_handle_request_is_filled_in_or_dismissed_from_the_window() {
    let (daemon, _fake, desk, mut worker) = unlocked().await;
    assert!(!worker.act(Action::Open(Tab::Handles)).await);
    request_handle(&daemon, "staging").await;
    request_handle(&daemon, "other").await;
    worker.model().await;
    let (_, _, overview) = state(&desk.take());
    let ids: Vec<(u64, String)> = overview
        .unwrap()
        .handle_requests
        .into_iter()
        .map(|r| (r.id, r.request.name))
        .collect();
    let id_of = |name: &str| ids.iter().find(|(_, n)| n == name).unwrap().0;

    let fill = FromPage::OpenForm {
        form: FormRequest::Request {
            id: id_of("staging"),
        },
    };
    assert!(!worker.act(page(fill)).await);
    let pages = desk.take();
    let Some(ToPage::Form { view }) = pages.last() else {
        panic!("{pages:?}");
    };
    assert_eq!(view.focus.as_deref(), Some("token"));
    let name = view.fields.iter().find(|f| f.key == "name").unwrap();
    assert_eq!(name.value, "staging");
    let submit = FromPage::SubmitForm {
        values: values(&[("token", "t0ken")]),
    };
    assert!(!worker.act(page(submit)).await);
    assert!(desk.take().contains(&ToPage::FormDone));

    let dismiss = FromPage::Dismiss { id: id_of("other") };
    assert!(!worker.act(page(dismiss)).await);
    worker.model().await;
    let (_, _, overview) = state(&desk.take());
    let overview = overview.unwrap();
    assert!(overview.handle_requests.is_empty(), "{overview:?}");
    assert!(overview.handles.iter().any(|h| h.name == "staging"));
}

/// Home shows the latest activity, so it gets the log too.
#[tokio::test(flavor = "multi_thread")]
async fn the_audit_log_goes_to_the_window_only_on_home_and_its_tab() {
    let (_daemon, _fake, desk, mut worker) = unlocked().await;
    let audits = |pages: &[ToPage]| {
        pages
            .iter()
            .filter(|page| matches!(page, ToPage::Audit { .. }))
            .count()
    };
    assert!(!worker.act(Action::Open(Tab::Approvals)).await);
    worker.model().await;
    assert_eq!(audits(&desk.take()), 0);
    assert!(!worker.act(page(FromPage::Tab { tab: Tab::Audit })).await);
    assert_eq!(audits(&desk.take()), 1);
    worker.model().await;
    assert_eq!(audits(&desk.take()), 1);
    assert!(!worker.act(page(FromPage::Tab { tab: Tab::Home })).await);
    assert_eq!(audits(&desk.take()), 1);
}

/// The page's Settings screen: the appearance is saved and comes back with
/// the state, the login item follows the switch, and Quit quits.
#[tokio::test(flavor = "multi_thread")]
async fn the_settings_screen_reaches_the_tray() {
    let (daemon, _fake, desk, mut worker) = unlocked().await;
    assert!(!worker.act(Action::Open(Tab::Home)).await);
    let theme = |pages: &[ToPage]| {
        pages.iter().rev().find_map(|page| match page {
            ToPage::State { theme, login, .. } => Some((*theme, *login)),
            _ => None,
        })
    };
    assert_eq!(theme(&desk.take()), Some((Theme::System, false)));

    assert!(
        !worker
            .act(page(FromPage::Theme { theme: Theme::Dark }))
            .await
    );
    assert_eq!(theme(&desk.take()), Some((Theme::Dark, false)));
    assert_eq!(Theme::load(&daemon.paths.tray_theme_file()), Theme::Dark);

    assert!(!worker.act(page(FromPage::Login { on: true })).await);
    assert!(*desk.login.lock().unwrap());
    assert_eq!(theme(&desk.take()), Some((Theme::Dark, true)));

    assert!(
        !worker.act(page(FromPage::Hide)).await,
        "the window side hides"
    );
    assert!(worker.act(page(FromPage::Quit)).await);
}

/// A lock from anywhere sends the locked state and drops the open form with
/// what was typed into it.
#[tokio::test(flavor = "multi_thread")]
async fn a_lock_elsewhere_drops_the_open_form() {
    let (daemon, _fake, desk, mut worker) = unlocked().await;
    assert!(!worker.act(Action::Open(Tab::Handles)).await);
    let new = FromPage::OpenForm {
        form: FormRequest::New,
    };
    assert!(!worker.act(page(new)).await);
    let pages = desk.take();
    assert!(
        pages.iter().any(|page| matches!(page, ToPage::Form { .. })),
        "{pages:?}"
    );
    daemon.control(None, ControlCommand::Lock).await;
    worker.model().await;
    let pages = desk.take();
    assert!(state(&pages).0, "{pages:?}");

    // Unlocked again, the old form is gone: Ready brings no form back.
    assert!(!worker.act(Action::Unlock).await);
    assert!(!worker.act(page(FromPage::Ready)).await);
    let pages = desk.take();
    assert!(
        !pages.iter().any(|page| matches!(page, ToPage::Form { .. })),
        "{pages:?}"
    );
    let submit = FromPage::SubmitForm {
        values: values(&[("name", "x"), ("token", "t")]),
    };
    assert!(!worker.act(page(submit)).await);
    assert!(!desk.take().contains(&ToPage::FormDone));
}

/// A page that has just loaded gets the tab, the state and the open form.
#[tokio::test(flavor = "multi_thread")]
async fn a_page_that_loads_gets_everything() {
    let (_daemon, _fake, desk, mut worker) = unlocked().await;
    assert!(!worker.act(Action::Open(Tab::Handles)).await);
    let new = FromPage::OpenForm {
        form: FormRequest::New,
    };
    assert!(!worker.act(page(new)).await);
    desk.take();
    assert!(!worker.act(page(FromPage::Ready)).await);
    let pages = desk.take();
    assert!(
        pages.contains(&ToPage::Show { tab: Tab::Handles }),
        "{pages:?}"
    );
    assert!(!state(&pages).0);
    assert!(
        pages.iter().any(|page| matches!(page, ToPage::Form { .. })),
        "{pages:?}"
    );
}

/// Once closed, the window hears nothing and its form is gone; the session
/// stays.
#[tokio::test(flavor = "multi_thread")]
async fn a_closed_window_hears_nothing() {
    let (_daemon, _fake, desk, mut worker) = unlocked().await;
    assert!(!worker.act(Action::Open(Tab::Handles)).await);
    let new = FromPage::OpenForm {
        form: FormRequest::New,
    };
    assert!(!worker.act(page(new)).await);
    let pages = desk.take();
    assert!(
        pages.iter().any(|page| matches!(page, ToPage::Form { .. })),
        "{pages:?}"
    );
    assert!(!worker.act(Action::WindowClosed).await);
    desk.take();
    assert_eq!(worker.model().await.icon, IconState::Unlocked);
    assert!(desk.take().is_empty());

    assert!(!worker.act(Action::Open(Tab::Handles)).await);
    assert!(!worker.act(page(FromPage::Ready)).await);
    let pages = desk.take();
    assert!(
        !pages.iter().any(|page| matches!(page, ToPage::Form { .. })),
        "{pages:?}"
    );
}

/// In the loop, the window's Touch ID prompt runs beside it, and the page
/// is told it is waiting.
#[tokio::test(flavor = "multi_thread")]
async fn the_window_shows_it_is_waiting_for_touch_id() {
    let (_daemon, fake, desk, worker) = locked().await;
    let (release, gate) = std::sync::mpsc::channel();
    *fake.gate.lock().unwrap() = Some(gate);
    let (actions, inbox) = tokio::sync::mpsc::unbounded_channel();
    let running = tokio::spawn(worker.run(inbox, |_| {}));
    actions.send(Action::Open(Tab::Approvals)).unwrap();

    let saw = |test: fn(&ToPage) -> bool| {
        let pages = desk.pages.clone();
        async move {
            let deadline = Instant::now() + Duration::from_secs(5);
            while !pages.lock().unwrap().iter().any(test) {
                assert!(Instant::now() < deadline, "never sent it");
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }
    };
    saw(|page| {
        matches!(
            page,
            ToPage::State {
                locked: true,
                waiting_for_device: true,
                ..
            }
        )
    })
    .await;
    release.send(()).unwrap();
    saw(|page| {
        matches!(
            page,
            ToPage::State {
                locked: false,
                waiting_for_device: false,
                ..
            }
        )
    })
    .await;
    actions.send(Action::Quit).unwrap();
    tokio::time::timeout(Duration::from_secs(5), running)
        .await
        .expect("the loop stops on Quit")
        .unwrap();
}

/// When the session ends at a tick, the page hears it is locked first, so
/// the reason lands on the unlock screen.
#[tokio::test(flavor = "multi_thread")]
async fn a_session_that_ends_says_why_after_the_locked_state() {
    let (daemon, _fake, desk, mut worker) = unlocked().await;
    assert!(!worker.act(Action::Open(Tab::Approvals)).await);
    desk.take();
    daemon.control(None, ControlCommand::Lock).await;
    worker.model().await;
    let pages = desk.take();
    let locked = pages
        .iter()
        .position(|page| matches!(page, ToPage::State { locked: true, .. }))
        .unwrap_or_else(|| panic!("{pages:?}"));
    let reason = pages
        .iter()
        .position(|page| matches!(page, ToPage::Message { .. }))
        .unwrap_or_else(|| panic!("{pages:?}"));
    assert!(locked < reason, "{pages:?}");
}

/// A page that loads is a window that is open, even if the worker heard it
/// close: an "Open kv…" and a close can cross on their way to the worker.
#[tokio::test(flavor = "multi_thread")]
async fn a_page_that_loads_is_an_open_window() {
    let (_daemon, _fake, desk, mut worker) = unlocked().await;
    assert!(!worker.act(Action::Open(Tab::Handles)).await);
    assert!(!worker.act(Action::WindowClosed).await);
    desk.take();
    assert!(!worker.act(page(FromPage::Ready)).await);
    let pages = desk.take();
    assert!(
        pages
            .iter()
            .any(|page| matches!(page, ToPage::State { .. })),
        "{pages:?}"
    );
    worker.model().await;
    assert!(
        desk.take()
            .iter()
            .any(|page| matches!(page, ToPage::State { .. }))
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_received_share_is_listed_viewed_and_forgotten_in_the_window() {
    use kv_core::proto::{ReceiveShareCall, ShareRequestCall};
    use kv_core::secret::{AuthPlacement, SecretValue};
    use kv_core::share::{ShareRequest, SharedSecret, seal};

    let (daemon, _fake, desk, mut worker) = unlocked().await;
    assert!(!worker.act(Action::Open(Tab::Shares)).await);
    let code = match client::agent(
        &daemon.paths,
        None,
        &AgentRequest::RequestShare(ShareRequestCall {
            note: "the staging key".into(),
            from: "bob".into(),
        }),
    )
    .await
    .unwrap()
    {
        AgentResponse::ShareRequested { code, .. } => code,
        other => panic!("expected a request code, got {other:?}"),
    };
    // Someone else's kv seals a token to it.
    let share = seal(
        &ShareRequest::decode(&code).unwrap(),
        &SharedSecret {
            name: "staging".into(),
            description: "Staging API".into(),
            value: SecretValue::Http {
                token: SecretText::new("stg-0123456789abcdef"),
                placement: AuthPlacement::Header {
                    name: "Authorization".into(),
                    template: "Bearer {}".into(),
                },
                base_url: None,
            },
            allowed_hosts: vec!["staging.example.com".into()],
            allow_plain_http: false,
            allowed_methods: Vec::new(),
            read_only: false,
            from: "alice".into(),
            note: String::new(),
        },
    )
    .unwrap();
    let received = client::agent(
        &daemon.paths,
        None,
        &AgentRequest::ReceiveShare(ReceiveShareCall { share, name: None }),
    )
    .await
    .unwrap();
    assert!(
        matches!(received, AgentResponse::ShareReceived { .. }),
        "{received:?}"
    );

    worker.model().await;
    let (_, _, overview) = state(&desk.take());
    let shares = overview.unwrap().shares;
    assert!(shares.requests.is_empty());
    assert_eq!(shares.received.len(), 1);
    assert!(shares.received[0].viewable);
    let id = shares.received[0].id.clone();

    assert!(
        !worker
            .act(page(FromPage::Reveal {
                handle: "staging".into()
            }))
            .await
    );
    let pages = desk.take();
    let fields = pages
        .iter()
        .find_map(|page| match page {
            ToPage::Revealed { handle, fields } if handle == "staging" => Some(fields.clone()),
            _ => None,
        })
        .unwrap_or_else(|| panic!("nothing revealed in {pages:?}"));
    assert_eq!(fields[0].value.expose(), "stg-0123456789abcdef");

    // A handle the user typed in stays hidden.
    assert!(
        !worker
            .act(page(FromPage::Reveal {
                handle: "missing".into()
            }))
            .await
    );
    let pages = desk.take();
    assert!(
        !pages.iter().any(|p| matches!(p, ToPage::Revealed { .. })),
        "{pages:?}"
    );
    assert_eq!(messages(&pages).len(), 1, "{pages:?}");

    assert!(!worker.act(page(FromPage::Forget { id })).await);
    worker.model().await;
    let (_, _, overview) = state(&desk.take());
    assert!(overview.unwrap().shares.received.is_empty());
    assert_eq!(desk.notes(), Vec::<String>::new());
}

/// The `Shared` results and share errors in `pages`.
fn shared(pages: &[ToPage]) -> (Vec<ShareDone>, Vec<String>) {
    let mut done = Vec::new();
    let mut errors = Vec::new();
    for page in pages {
        match page {
            ToPage::Shared { result } => done.push(result.clone()),
            ToPage::ShareError { message } => errors.push(message.clone()),
            _ => {}
        }
    }
    (done, errors)
}

#[tokio::test(flavor = "multi_thread")]
async fn a_share_is_requested_sealed_and_received_by_hand_in_the_window() {
    use kv_core::policy::Policy;
    use kv_core::secret::{AuthPlacement, Secret, SecretValue};

    let (daemon, _fake, desk, mut worker) = unlocked().await;
    daemon
        .control(
            Some(PASS),
            ControlCommand::Add {
                secret: Secret {
                    name: "staging".into(),
                    description: "Staging API".into(),
                    value: SecretValue::Http {
                        token: SecretText::new("stg-0123456789abcdef"),
                        placement: AuthPlacement::Header {
                            name: "Authorization".into(),
                            template: "Bearer {}".into(),
                        },
                        base_url: None,
                    },
                    policy: Policy::default(),
                    created_at: 0,
                    updated_at: 0,
                    from_share: None,
                },
                replace: false,
            },
        )
        .await;
    assert!(!worker.act(Action::Open(Tab::Shares)).await);
    desk.take();

    // A request made in the window comes back as a code to copy.
    assert!(
        !worker
            .act(page(FromPage::RequestShare {
                note: "the staging key".into(),
                from: "bob".into(),
            }))
            .await
    );
    let (done, errors) = shared(&desk.take());
    assert_eq!(errors, Vec::<String>::new());
    let [ShareDone::Requested { code, safety_code }] = done.as_slice() else {
        panic!("expected a request code, got {done:?}");
    };
    assert!(code.starts_with("kv-request:v1:"), "{code}");

    // A handle that is not there is said in the dialog, not sealed.
    assert!(
        !worker
            .act(page(FromPage::SendShare {
                request: code.clone(),
                handle: "missing".into(),
                name: String::new(),
                from: "alice".into(),
                note: String::new(),
            }))
            .await
    );
    let (done, errors) = shared(&desk.take());
    assert!(done.is_empty(), "{done:?}");
    assert_eq!(errors.len(), 1, "{errors:?}");
    assert!(
        errors[0].starts_with("There is no handle named missing"),
        "{errors:?}"
    );

    // The vault seals its own handle to its own request: as good a test of
    // the window as two people.
    assert!(
        !worker
            .act(page(FromPage::SendShare {
                request: format!("can you send it?\n{code}"),
                handle: "staging".into(),
                name: String::new(),
                from: "alice".into(),
                note: "for the deploy".into(),
            }))
            .await
    );
    let (done, errors) = shared(&desk.take());
    assert_eq!(errors, Vec::<String>::new());
    let [
        ShareDone::Sealed {
            share,
            safety_code: sealed_to,
            to,
            asked_for,
        },
    ] = done.as_slice()
    else {
        panic!("expected a sealed share, got {done:?}");
    };
    assert_eq!(sealed_to, safety_code);
    assert_eq!(
        (to.as_str(), asked_for.as_str()),
        ("bob", "the staging key")
    );
    assert!(!share.contains("stg-0123456789abcdef"));

    // Its suggested name is taken here, so the dialog says to pick another.
    let receive = |name: &str| {
        page(FromPage::ReceiveShare {
            share: share.clone(),
            name: name.into(),
        })
    };
    assert!(!worker.act(receive("")).await);
    let (done, errors) = shared(&desk.take());
    assert!(done.is_empty(), "{done:?}");
    assert!(
        errors.len() == 1 && errors[0].contains("exists already"),
        "{errors:?}"
    );
    assert!(!worker.act(receive("staging-copy")).await);
    let (done, errors) = shared(&desk.take());
    assert_eq!(errors, Vec::<String>::new());
    assert_eq!(
        done,
        [ShareDone::Received {
            handle: "staging-copy".into(),
            kind: SecretKind::Http,
            from: "alice".into(),
            safety_code: safety_code.clone(),
        }]
    );

    worker.model().await;
    let (_, _, overview) = state(&desk.take());
    let overview = overview.unwrap();
    assert!(overview.shares.requests.is_empty());
    assert_eq!(overview.shares.sent.len(), 1);
    assert_eq!(overview.shares.received.len(), 1);
    assert!(overview.handles.iter().any(|h| h.name == "staging-copy"));
    // The user did all of it: nothing to notify.
    assert_eq!(desk.notes(), Vec::<String>::new());
}

#[tokio::test(flavor = "multi_thread")]
async fn sharing_from_a_locked_window_asks_to_unlock() {
    let (_daemon, _fake, desk, mut worker) = locked().await;
    // A page that loads opens the window without a Touch ID prompt.
    assert!(!worker.act(page(FromPage::Ready)).await);
    desk.take();
    assert!(
        !worker
            .act(page(FromPage::RequestShare {
                note: String::new(),
                from: String::new(),
            }))
            .await
    );
    let pages = desk.take();
    let (done, _) = shared(&pages);
    assert!(done.is_empty(), "{pages:?}");
    assert!(state(&pages).0, "{pages:?}");
    assert_eq!(messages(&pages), [("Unlock first".to_owned(), None)]);
}

/// The env handle `name` in the last overview, if there is one.
async fn handle(
    worker: &mut Worker<Desk>,
    desk: &Desk,
    name: &str,
) -> Option<kv_core::secret::HandleInfo> {
    worker.model().await;
    let (_, _, overview) = state(&desk.take());
    overview?.handles.into_iter().find(|h| h.name == name)
}

const DEMO_ENV: &str = "# demo fixture\nexport API_TOKEN=demo-token-1\nDB_URL=\"postgres://demo:demo-pass@db.example.test/app\"\nNODE_OPTIONS=--require ./x.js\n";

#[tokio::test(flavor = "multi_thread")]
async fn a_file_imported_in_the_window_shows_names_and_saves_the_ticked_ones() {
    let (_daemon, _fake, desk, mut worker) = unlocked().await;
    assert!(!worker.act(Action::Open(Tab::Handles)).await);
    worker.model().await;
    desk.take();

    assert!(
        !worker
            .act(page(FromPage::ImportFile {
                file_name: ".env".into(),
                text: SecretText::new(DEMO_ENV),
            }))
            .await
    );
    let pages = desk.take();
    let [
        ToPage::ImportPreview {
            file_name,
            name,
            format,
            vars,
            ..
        },
    ] = pages.as_slice()
    else {
        panic!("{pages:?}");
    };
    assert_eq!(file_name, ".env");
    assert_eq!(name, "env");
    assert_eq!(format, ".env");
    let var = |name: &str, risky: bool, keep: bool| ImportVar {
        name: name.into(),
        risky,
        keep,
    };
    assert_eq!(
        vars,
        &[
            var("API_TOKEN", false, true),
            var("DB_URL", false, true),
            var("NODE_OPTIONS", true, false),
        ]
    );
    // Names only: no value goes to the page.
    let shown = format!("{pages:?}");
    for value in ["demo-token-1", "demo-pass", "./x.js"] {
        assert!(!shown.contains(value), "{shown}");
    }

    // Nothing ticked is refused, and the file stays read for another try.
    assert!(
        !worker
            .act(page(FromPage::ImportSave {
                name: "demo-app".into(),
                keep: Vec::new(),
            }))
            .await
    );
    let pages = desk.take();
    assert!(
        matches!(pages.as_slice(), [ToPage::ImportError { .. }]),
        "{pages:?}"
    );

    assert!(
        !worker
            .act(page(FromPage::ImportSave {
                name: "demo-app".into(),
                keep: vec!["API_TOKEN".into(), "DB_URL".into()],
            }))
            .await
    );
    let pages = desk.take();
    assert!(
        pages
            .iter()
            .any(|p| matches!(p, ToPage::Imported { name, .. } if name == "demo-app")),
        "{pages:?}"
    );
    let saved = handle(&mut worker, &desk, "demo-app").await.expect("saved");
    assert_eq!(saved.kind, SecretKind::Env);
    assert_eq!(saved.env_vars, ["API_TOKEN", "DB_URL"]);
    assert_eq!(saved.mode, kv_core::policy::Mode::Ask);

    // The file went with the save.
    assert!(
        !worker
            .act(page(FromPage::ImportSave {
                name: "again".into(),
                keep: vec!["API_TOKEN".into()],
            }))
            .await
    );
    assert_eq!(desk.take(), Vec::<ToPage>::new());
    assert_eq!(desk.notes(), Vec::<String>::new());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refused_import_keeps_the_file_and_a_cancel_or_lock_drops_it() {
    let (_daemon, _fake, desk, mut worker) = unlocked().await;
    assert!(!worker.act(Action::Open(Tab::Handles)).await);
    worker.model().await;
    let import = || {
        page(FromPage::ImportFile {
            file_name: "demo.env".into(),
            text: SecretText::new(DEMO_ENV),
        })
    };
    let save = |name: &str| {
        page(FromPage::ImportSave {
            name: name.into(),
            keep: vec!["API_TOKEN".into()],
        })
    };

    assert!(!worker.act(import()).await);
    desk.take();
    // A name the daemon refuses: the file is still there for a better one.
    assert!(!worker.act(save("not a name")).await);
    let pages = desk.take();
    assert!(
        matches!(pages.as_slice(), [ToPage::ImportError { .. }]),
        "{pages:?}"
    );
    assert!(!worker.act(save("demo-app")).await);
    assert!(
        desk.take()
            .iter()
            .any(|p| matches!(p, ToPage::Imported { .. }))
    );

    // Cancelled: a save afterwards does nothing.
    assert!(!worker.act(import()).await);
    assert!(!worker.act(page(FromPage::ImportCancel)).await);
    desk.take();
    assert!(!worker.act(save("other")).await);
    assert_eq!(desk.take(), Vec::<ToPage>::new());

    // Locked: the same.
    assert!(!worker.act(import()).await);
    assert!(!worker.act(page(FromPage::Lock)).await);
    assert!(!worker.act(Action::Unlock).await);
    desk.take();
    assert!(!worker.act(save("other")).await);
    assert!(
        !desk
            .take()
            .iter()
            .any(|p| matches!(p, ToPage::Imported { .. } | ToPage::ImportError { .. }))
    );
    assert!(handle(&mut worker, &desk, "other").await.is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_file_that_cannot_be_read_says_why() {
    let (_daemon, _fake, desk, mut worker) = unlocked().await;
    assert!(!worker.act(Action::Open(Tab::Handles)).await);
    desk.take();
    assert!(
        !worker
            .act(page(FromPage::ImportFile {
                file_name: "demo.env".into(),
                text: SecretText::new("A=\"never closed\n"),
            }))
            .await
    );
    let pages = desk.take();
    assert!(
        matches!(pages.as_slice(), [ToPage::ImportError { .. }]),
        "{pages:?}"
    );
}

/// A file as the page sends it: its name and its bytes as base64.
fn picked(file_name: &str, bytes: &[u8]) -> FromPage {
    use base64::Engine;
    FromPage::FileRead {
        file_name: file_name.into(),
        data: SecretText::new(base64::engine::general_purpose::STANDARD.encode(bytes)),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_file_picked_in_the_window_is_kept_as_a_file_handle() {
    let (_daemon, _fake, desk, mut worker) = unlocked().await;
    assert!(!worker.act(Action::Open(Tab::Handles)).await);
    worker.model().await;
    desk.take();

    // A text file: the page hears its size and fingerprint, never a byte.
    let text = b"correct-horse-battery\r\nlonger-password-2\r\n";
    assert!(!worker.act(page(picked("passwords.txt", text))).await);
    let pages = desk.take();
    let [
        ToPage::FilePreview {
            file_name,
            name,
            size,
            fingerprint,
            scrubbed,
            notes,
        },
    ] = pages.as_slice()
    else {
        panic!("expected one preview, got {pages:?}");
    };
    assert_eq!(file_name, "passwords.txt");
    assert_eq!(name, "passwords");
    assert_eq!(*size, text.len());
    assert_eq!(fingerprint.len(), 14);
    assert!(*scrubbed && notes.is_empty(), "{notes:?}");
    assert!(!format!("{pages:?}").contains("correct-horse"));

    // A name kv refuses keeps the file for another try.
    assert!(
        !worker
            .act(page(FromPage::FileSave {
                name: "Bad Name".into(),
                cmds: "hydra".into(),
            }))
            .await
    );
    let pages = desk.take();
    assert!(
        matches!(pages.as_slice(), [ToPage::FileError { .. }]),
        "{pages:?}"
    );
    assert!(
        !worker
            .act(page(FromPage::FileSave {
                name: "passwords".into(),
                cmds: "hydra, medusa,".into(),
            }))
            .await
    );
    let pages = desk.take();
    let [ToPage::FileAdded { name, warnings }] = pages.as_slice() else {
        panic!("expected the file saved, got {pages:?}");
    };
    assert_eq!(name, "passwords");
    assert!(warnings.is_empty(), "{warnings:?}");
    let saved = handle(&mut worker, &desk, "passwords").await.unwrap();
    assert_eq!(saved.kind, SecretKind::File);
    assert_eq!(saved.allowed_cmds, ["hydra", "medusa"]);
    assert_eq!(saved.mode, kv_core::policy::Mode::Ask);
    assert_eq!(saved.env_vars, ["KV_FILE_PASSWORDS"]);

    // Nothing is left to save, and a second Save does nothing.
    assert!(
        !worker
            .act(page(FromPage::FileSave {
                name: "again".into(),
                cmds: String::new(),
            }))
            .await
    );
    assert!(desk.take().is_empty());

    // A file that is not text says kv cannot scrub it; a cancel drops it.
    let binary: Vec<u8> = (0..300u32).map(|i| (i * 7 % 256) as u8 | 0x80).collect();
    assert!(!worker.act(page(picked("keystore.p12", &binary))).await);
    let pages = desk.take();
    let [
        ToPage::FilePreview {
            scrubbed, notes, ..
        },
    ] = pages.as_slice()
    else {
        panic!("expected one preview, got {pages:?}");
    };
    assert!(!*scrubbed);
    assert!(notes[0].contains("cannot scrub"), "{notes:?}");
    assert!(!worker.act(page(FromPage::FileCancel)).await);
    assert!(
        !worker
            .act(page(FromPage::FileSave {
                name: "keystore".into(),
                cmds: String::new(),
            }))
            .await
    );
    assert!(handle(&mut worker, &desk, "keystore").await.is_none());

    // Too big, or not base64 at all, says why.
    let big = vec![0u8; kv_core::secret::MAX_FILE_LEN + 1];
    assert!(!worker.act(page(picked("big.bin", &big))).await);
    let pages = desk.take();
    let [ToPage::FileError { message }] = pages.as_slice() else {
        panic!("expected an error, got {pages:?}");
    };
    assert!(message.contains("1 MiB"), "{message}");
    assert!(
        !worker
            .act(page(FromPage::FileRead {
                file_name: "x.txt".into(),
                data: SecretText::new("not base64!!"),
            }))
            .await
    );
    assert!(matches!(desk.take().as_slice(), [ToPage::FileError { .. }]));
    assert_eq!(desk.notes(), Vec::<String>::new());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_file_is_sent_as_a_kvshare_file_and_a_received_one_is_saved_as_it_arrived() {
    use kv_core::proto::{ReceiveShareCall, ShareRequestCall};
    use kv_core::secret::SecretValue;
    use kv_core::share::{OpenRequest, ShareRequest, SharedSecret, open, seal};

    let (daemon, _fake, desk, worker) = unlocked().await;
    let downloads = TempDir::new().unwrap();
    let mut worker = worker.with_downloads(downloads.path().join("Downloads"));
    assert!(!worker.act(Action::Open(Tab::Shares)).await);

    // Someone seals a file to this vault's request. Not text, with CRLF, a
    // NUL and no newline at the end, and too long for a message.
    let mut bytes = b"\xEF\xBB\xBFcorrect-horse-battery\r\nsecond-line\r\n".to_vec();
    bytes.extend([0, 159, 146, 150, 255, 13, 10, 0]);
    bytes.extend((0..9_000u32).map(|i| (i.wrapping_mul(2_654_435_761) >> 24) as u8));
    bytes.extend(b"no newline at the end");
    let code = match client::agent(
        &daemon.paths,
        None,
        &AgentRequest::RequestShare(ShareRequestCall {
            note: "the word list".into(),
            from: "me".into(),
        }),
    )
    .await
    .unwrap()
    {
        AgentResponse::ShareRequested { code, .. } => code,
        other => panic!("expected a request code, got {other:?}"),
    };
    let share = seal(
        &ShareRequest::decode(&code).unwrap(),
        &SharedSecret {
            name: "wordlist".into(),
            description: String::new(),
            value: SecretValue::file("C:\\Users\\alice\\con:words.bin", &bytes).unwrap(),
            allowed_hosts: Vec::new(),
            allow_plain_http: false,
            allowed_methods: Vec::new(),
            read_only: false,
            from: "alice".into(),
            note: String::new(),
        },
    )
    .unwrap();
    let received = client::agent(
        &daemon.paths,
        None,
        &AgentRequest::ReceiveShare(ReceiveShareCall { share, name: None }),
    )
    .await
    .unwrap();
    assert!(
        matches!(received, AgentResponse::ShareReceived { .. }),
        "{received:?}"
    );
    worker.model().await;
    desk.take();

    // Saved to the Downloads folder, which is made, under a name that is
    // safe to create, the bytes untouched. A second save never replaces it.
    for expected in ["con_words.bin", "con_words (1).bin"] {
        assert!(
            !worker
                .act(page(FromPage::SaveFile {
                    handle: "wordlist".into()
                }))
                .await
        );
        let pages = desk.take();
        let [ToPage::FileSaved { handle, path }] = pages.as_slice() else {
            panic!("expected the file saved, got {pages:?}");
        };
        assert_eq!(handle, "wordlist");
        let path = std::path::Path::new(path);
        assert_eq!(path.file_name().unwrap(), expected);
        assert_eq!(path.parent().unwrap(), downloads.path().join("Downloads"));
        assert_eq!(std::fs::read(path).unwrap(), bytes);
    }

    // Sending a file seals it to a file instead of showing text.
    let theirs = OpenRequest::new(
        "the word list".into(),
        "carol".into(),
        1_800_000_000,
        86_400,
    );
    assert!(
        !worker
            .act(page(FromPage::SendShare {
                request: theirs.code(),
                handle: "wordlist".into(),
                name: String::new(),
                from: "me".into(),
                note: String::new(),
            }))
            .await
    );
    let pages = desk.take();
    let [
        ToPage::ShareSaved {
            path,
            safety_code,
            to,
            asked_for,
        },
    ] = pages.as_slice()
    else {
        panic!("expected a share saved as a file, got {pages:?}");
    };
    assert_eq!(*safety_code, theirs.safety_code());
    assert_eq!(
        (to.as_str(), asked_for.as_str()),
        ("carol", "the word list")
    );
    let path = std::path::Path::new(path);
    assert_eq!(
        path.file_name().unwrap().to_string_lossy(),
        format!("wordlist-{}.kvshare", theirs.safety_code())
    );
    // Carol's vault opens it and gets the same file, name and all.
    let sealed = std::fs::read_to_string(path).unwrap();
    assert!(sealed.starts_with("kv-share:v1:") && !sealed.contains("correct-horse"));
    let (_, opened) = open(&sealed, std::slice::from_ref(&theirs)).unwrap();
    let (name, back) = opened.value.file_parts().unwrap();
    assert_eq!(name, "con:words.bin");
    assert_eq!(&back[..], &bytes[..]);
    assert!(
        !pages
            .iter()
            .any(|p| matches!(p, ToPage::Shared { .. } | ToPage::ShareError { .. }))
    );
    assert_eq!(desk.notes(), Vec::<String>::new());
}
