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
use kv::tray::window::{FormRequest, FromPage, Tab, ToPage};
use kv::tray::worker::{Desktop, Worker};
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

#[tokio::test(flavor = "multi_thread")]
async fn the_audit_log_goes_to_the_window_only_on_its_tab() {
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
