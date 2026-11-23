//! The tray's daemon side, on a tokio runtime of its own: reads the
//! daemon's status every second, holds the session the menu and the window
//! share, and carries out what they ask for. A failure is told where the
//! user asked: in the window, or as a notification for the menu.

use std::collections::BTreeMap;
use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use futures_util::future::BoxFuture;
use zeroize::Zeroizing;

use kv_core::proto::{
    AgentRequest, AgentResponse, ControlCommand, ControlRequest, ControlResponse, NoticeKind,
    Overview, ReceiveShareCall, SendShareCall, ShareRequestCall, Status,
};
use kv_core::secret::{Secret, SecretText, SecretValue};
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::task::JoinHandle;

use super::model::{Action, Model, View};
use super::notices::{self, Click, Notice};
use super::update::Updater;
use super::window::{FormRequest, FromPage, ImportVar, Tab, Theme, ToPage, UpdateKind};
use crate::client;
use crate::device::Device;
use crate::forms::{self, Form, Purpose};
use crate::importing;
use crate::paths::Paths;
use crate::sharefile;
use crate::tui::app::{Effect, Outcome, ShareDone};
use crate::tui::{DeviceAnswer, DevicePrompt, Driver, Proof};
use crate::update::install::Installed;
use crate::update::{self, Offer, UpdateError, check, state};
use kv_core::envvars;
use kv_core::import::{self, Format, Imported};
use kv_core::policy::Policy;

/// How often the tray asks the daemon for news.
const TICK: Duration = Duration::from_secs(1);

/// The longest share, in characters, that is shown as text to copy. A
/// longer one does not fit a chat message, so it is saved as a file.
const MAX_MESSAGE_SHARE: usize = 4000;

/// What a Touch ID prompt from the tray says kv is trying to do.
const REASON: &str = "open kv tray, where you approve agent requests";

/// A check for an update, under way.
type Check = BoxFuture<'static, Result<Option<Offer>, UpdateError>>;
/// An update downloading and swapping in, under way.
type Install = BoxFuture<'static, Result<Installed, UpdateError>>;

/// What the worker needs from the desktop around it.
pub trait Desktop: Send {
    fn notify(&self, text: &str);
    /// Opens kv's window on `tab`, or brings it to the front on `tab`.
    fn show_window(&self, tab: Tab);
    /// Hands a message to the window's page.
    fn page(&self, message: ToPage);
    fn login_is_on(&self) -> bool;
    fn set_login(&self, on: bool) -> io::Result<()>;
    /// Whether `post` shows a notification the user can answer from: the
    /// platform has them and the user allows kv's.
    fn can_notify(&self) -> bool {
        false
    }
    /// Shows a waiting request as a notification with its answers. They
    /// come back as `Action::Notice`.
    fn post(&self, _notice: &Notice) {}
    /// Takes down the notifications named by `keys`.
    fn withdraw(&self, _keys: &[String]) {}
    /// Puts a value shown in the window on the clipboard, for a while.
    fn copy(&self, _text: &SecretText) -> io::Result<()> {
        Err(io::ErrorKind::Unsupported.into())
    }
    /// Takes a value `copy` put on the clipboard off it now, unless
    /// something else was copied since. Called as the tray quits.
    fn clear_copied(&self) {}
    /// Opens `url` in the user's browser.
    fn open_url(&self, _url: &str) {}
}

/// Who asked for something, and so hears how it went.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Asker {
    Menu,
    Window,
}

/// What a device prompt is for.
enum Prompting {
    /// A session, for `Asker` to hear about.
    Unlock(Asker),
    /// Showing a handle's value in the window.
    Reveal(String),
}

/// What is left to do after an action.
enum Next {
    Done,
    /// A device prompt, then what it was for.
    Prompt(Prompting),
    Quit,
}

/// kv's window while it is open.
struct Window {
    tab: Tab,
    /// The open form, and what saving it means.
    form: Option<(Purpose, Form)>,
    /// Whether the update confirmation was asked for, so a page that loads
    /// late still shows it.
    asking_update: bool,
}

pub struct Worker<D> {
    paths: Paths,
    driver: Driver,
    desktop: D,
    window: Option<Window>,
    /// The overview of the last tick, which the forms open from.
    overview: Option<Overview>,
    /// What the device prompt `run` holds beside its loop is for.
    prompting: Option<Prompting>,
    /// How the window looks, as the user last picked it.
    theme: Theme,
    /// A file the window is importing, read but not yet saved.
    import: Option<Imported>,
    /// A file the window is keeping as a `file` handle, read but not yet
    /// saved.
    file: Option<SecretValue>,
    /// Where files the window saves go; the Downloads folder if not set.
    downloads: Option<PathBuf>,
    /// The file the window saved last, for it to show in the file manager.
    saved: Option<PathBuf>,
    /// The notification on show for each waiting request, by request id.
    posted: BTreeMap<u64, String>,
    /// The "unlock needed" notifications on show, taken down once the
    /// vault is unlocked.
    unlock_posted: Vec<String>,
    /// Checks for, and installs, a newer kv. Shared with the thread the
    /// handover to a new tray runs on.
    updater: Arc<dyn Updater>,
    /// The newer kv the last check found.
    offer: Option<Offer>,
    /// When the next background check is due.
    next_check: Instant,
    /// Whether the tray checks in the background: only a release build,
    /// which can update itself, and only with `KV_UPDATE_CHECK` not off.
    auto_checks: bool,
    /// Settings asked for a check that has not started yet.
    check_wanted: bool,
    /// Settings asked for the check under way or about to start, so its
    /// answer goes there.
    check_manual: bool,
    /// The update the user agreed to, not started yet.
    install_wanted: Option<Offer>,
    /// An update is under way, from download to handover: a second one is
    /// not started, and checks wait.
    installing: bool,
}

impl<D: Desktop> Worker<D> {
    pub fn new(
        paths: Paths,
        device: Option<Arc<dyn Device>>,
        desktop: D,
        updater: Box<dyn Updater>,
    ) -> Self {
        Self {
            driver: Driver::with_device(paths.clone(), device).with_reason(REASON),
            theme: Theme::load(&paths.tray_theme_file()),
            import: None,
            file: None,
            downloads: None,
            saved: None,
            paths,
            desktop,
            window: None,
            overview: None,
            prompting: None,
            posted: BTreeMap::new(),
            unlock_posted: Vec::new(),
            updater: Arc::from(updater),
            offer: None,
            next_check: Instant::now() + state::TRAY_FIRST,
            auto_checks: update::is_release_build()
                && update::checks_enabled(std::env::var_os("KV_UPDATE_CHECK").as_deref()),
            check_wanted: false,
            check_manual: false,
            install_wanted: None,
            installing: false,
        }
    }

    /// Saves what the window saves (received files, shares too long for a
    /// message) in `dir` rather than the Downloads folder.
    pub fn with_downloads(mut self, dir: PathBuf) -> Self {
        self.downloads = Some(dir);
        self
    }

    /// What the tray should show now, and the window brought up to date.
    /// Reading the status never starts the daemon; a session the daemon no
    /// longer knows is dropped, with any open form.
    pub async fn model(&mut self) -> Model {
        let notifying = self.desktop.can_notify();
        let (status, notices) = self.status(notifying).await;
        let mut ended = None;
        self.overview = match self.driver.refresh_for(notifying).await {
            Some(Outcome::Overview(overview)) => Some(overview),
            Some(Outcome::Ended(message)) => {
                ended = Some(message);
                None
            }
            _ => None,
        };
        if self.overview.is_none() {
            self.set_form(None);
        }
        self.sync_notices(notifying);
        self.post_daemon_notices(notices, status.as_ref());
        self.send_state();
        // After the locked state, so the reason shows on the unlock screen.
        if let Some(message) = ended {
            self.say(Asker::Window, &message, None);
        }
        if self.window.as_ref().is_some_and(|w| shows_audit(w.tab)) {
            self.send_audit().await;
        }
        Model::new(View {
            status: status.as_ref(),
            overview: self.overview.as_ref(),
            device: self.driver.device(),
            login: self.desktop.login_is_on(),
            update: self.offer.as_ref().map(|offer| &offer.version),
        })
    }

    /// The daemon's status, never starting it. Where kv.app posts
    /// notifications, also the notices the daemon holds for the tray to
    /// post under kv's name, which marks the tray as taking them, locked or
    /// not; an older daemon that does not know the command is asked the
    /// plain way.
    async fn status(&self, notifying: bool) -> (Option<Status>, Vec<kv_core::proto::Notice>) {
        if notifying {
            let request = ControlRequest {
                passphrase: None,
                device: None,
                token: None,
                command: ControlCommand::NotifyingStatus,
            };
            match client::control_if_running(&self.paths, &request).await {
                Ok(Some(ControlResponse::Notices { status, notices })) => {
                    return (Some(status), notices);
                }
                Ok(None) => return (None, Vec::new()),
                _ => {}
            }
        }
        let status = match client::agent_if_running(&self.paths, &AgentRequest::Status).await {
            Ok(Some(AgentResponse::Status { status })) => Some(status),
            _ => None,
        };
        (status, Vec::new())
    }

    /// Posts the daemon's notices under kv's name, each with a click that
    /// acts on it. A reminder of a request this tray shows brings that
    /// request's notification back, with its answers. "Unlock needed" ones
    /// go once the vault is unlocked.
    fn post_daemon_notices(
        &mut self,
        notices: Vec<kv_core::proto::Notice>,
        status: Option<&Status>,
    ) {
        if status.is_some_and(|status| !status.locked) && !self.unlock_posted.is_empty() {
            let keys = std::mem::take(&mut self.unlock_posted);
            self.desktop.withdraw(&keys);
        }
        for notice in notices {
            let approval = match notice.kind {
                NoticeKind::Reminder { id } => self.overview.as_ref().and_then(|overview| {
                    overview.approvals.iter().find(|approval| approval.id == id)
                }),
                _ => None,
            };
            if let Some(approval) = approval {
                let again = Notice::reminder(approval);
                if let Some(old) = self.posted.insert(approval.id, again.key.clone()) {
                    self.desktop.withdraw(&[old]);
                }
                self.desktop.post(&again);
                continue;
            }
            let posted = Notice::from_daemon(&notice);
            if notice.kind == NoticeKind::UnlockNeeded {
                // One on show is enough: a newer one replaces it.
                let old = std::mem::take(&mut self.unlock_posted);
                if !old.is_empty() {
                    self.desktop.withdraw(&old);
                }
                self.unlock_posted.push(posted.key.clone());
            }
            self.desktop.post(&posted);
        }
    }

    /// Carries out one action, a device prompt and a check for updates
    /// included. Returns true for Quit.
    pub async fn act(&mut self, action: Action) -> bool {
        let mut next = self.begin(action).await;
        if std::mem::take(&mut self.check_wanted) {
            let found = self.updater.check().await.map_err(|e| e.to_string());
            self.begin(Action::UpdateChecked(found)).await;
        }
        if let Some(offer) = self.install_wanted.take() {
            let result = self.updater.install(offer).await;
            if let Some(installed) = self.installed(result).await {
                let handed = self.updater.restart(&installed);
                if self.handed_over(handed) {
                    next = Next::Quit;
                }
            }
        }
        match next {
            Next::Done => false,
            Next::Prompt(purpose) => {
                let answer = self.ask(&purpose).await;
                self.finish_prompt(purpose, answer).await;
                false
            }
            Next::Quit => {
                self.withdraw_all();
                true
            }
        }
    }

    /// Shows a model every tick and after every action until Quit, or until
    /// the UI drops its sender. A device prompt and a check for updates run
    /// beside the loop, so the icon and the window stay current, and
    /// requests are answered, while they do.
    pub async fn run(
        mut self,
        mut actions: UnboundedReceiver<Action>,
        mut show: impl FnMut(Model),
    ) {
        let mut tick = tokio::time::interval(TICK);
        let mut prompt = None;
        // A check for an update, while one runs: in the background, or one
        // Settings asked for.
        let mut checking: Option<Check> = None;
        // An update the user agreed to, while it downloads and swaps in;
        // then the handover to a tray on the new kv, which waits and starts
        // processes, so it runs on a thread of its own.
        let mut installing: Option<Install> = None;
        let mut handing_over: Option<JoinHandle<Result<(), String>>> = None;
        loop {
            tokio::select! {
                answer = async { prompt.as_mut().expect("guarded").await }, if prompt.is_some() => {
                    prompt = None;
                    let purpose = self.prompting.take().unwrap_or(Prompting::Unlock(Asker::Menu));
                    self.finish_prompt(purpose, answer).await;
                }
                found = async { checking.as_mut().expect("guarded").await }, if checking.is_some() => {
                    checking = None;
                    let found = found.map_err(|e| e.to_string());
                    self.begin(Action::UpdateChecked(found)).await;
                }
                result = async { installing.as_mut().expect("guarded").await }, if installing.is_some() => {
                    installing = None;
                    if let Some(installed) = self.installed(result).await {
                        let updater = self.updater.clone();
                        handing_over = Some(tokio::task::spawn_blocking(move || {
                            updater.restart(&installed)
                        }));
                    }
                }
                handed = async { handing_over.as_mut().expect("guarded").await }, if handing_over.is_some() => {
                    handing_over = None;
                    let handed = handed.unwrap_or_else(|e| {
                        Err(format!("The handover to the new kv tray stopped: {e}"))
                    });
                    if self.handed_over(handed) {
                        self.withdraw_all();
                        return;
                    }
                }
                action = actions.recv() => {
                    let Some(action) = action else {
                        self.withdraw_all();
                        return;
                    };
                    match self.begin(action).await {
                        Next::Done => {}
                        Next::Prompt(purpose) => {
                            if prompt.is_none() {
                                prompt = Some(self.ask(&purpose));
                                self.prompting = Some(purpose);
                            } else if let Prompting::Reveal(handle) = purpose {
                                // One prompt at a time: the passphrase still works.
                                self.desktop.page(ToPage::RevealAsk {
                                    handle,
                                    message: Some("Another prompt is open. Answer it first, or type your passphrase.".into()),
                                });
                            }
                        }
                        Next::Quit => {
                            self.withdraw_all();
                            return;
                        }
                    }
                }
                _ = tick.tick() => {
                    if checking.is_none() && !self.installing {
                        checking = self.due_check();
                    }
                }
            }
            // Settings asked for a check: one already under way answers it.
            if std::mem::take(&mut self.check_wanted) && checking.is_none() {
                checking = Some(self.updater.check());
            }
            if let Some(offer) = self.install_wanted.take() {
                installing = Some(self.updater.install(offer));
            }
            show(self.model().await);
        }
    }

    /// Shows the device prompt `purpose` needs.
    fn ask(&self, purpose: &Prompting) -> DevicePrompt {
        match purpose {
            Prompting::Unlock(_) => self.driver.ask_device(),
            Prompting::Reveal(handle) => self
                .driver
                .confirm_device(format!("show the value of {handle}")),
        }
    }

    async fn finish_prompt(&mut self, purpose: Prompting, answer: DeviceAnswer) {
        match purpose {
            Prompting::Unlock(asker) => self.unlock(asker, answer).await,
            Prompting::Reveal(handle) => self.reveal(handle, Proof::Device(answer)).await,
        }
    }

    /// Does what `action` asks for, short of a device prompt.
    async fn begin(&mut self, action: Action) -> Next {
        match action {
            Action::Unlock => return Next::Prompt(Prompting::Unlock(Asker::Menu)),
            Action::Decide { id, verdict } => {
                let outcome = self.driver.run(Effect::Decide { id, verdict }).await;
                self.report(Asker::Menu, outcome, None);
            }
            Action::Lock => self.lock(Asker::Menu).await,
            Action::Open(tab) => return self.open(tab),
            // The notification that a new kv is out. One left from before
            // the tray restarted, with nothing on offer yet, opens kv.
            Action::Notice { key, verdict: None } if key.starts_with(notices::UPDATE_PREFIX) => {
                if self.offer.is_some() {
                    self.offer_update();
                } else {
                    self.open_window(Tab::Home);
                }
            }
            // One of the daemon's notices, its button or itself: Unlock
            // does what the menu's Unlock… does; the others open kv.
            Action::Notice { key, verdict: None } if notices::click(&key).is_some() => {
                self.unlock_posted.retain(|posted| *posted != key);
                match notices::click(&key) {
                    Some(Click::Unlock) if self.driver.has_session() => {
                        self.open_window(Tab::Home);
                    }
                    Some(Click::Unlock) if self.driver.device().is_some() => {
                        return Next::Prompt(Prompting::Unlock(Asker::Menu));
                    }
                    // No Touch ID: the window asks for the passphrase.
                    Some(Click::Unlock) => {
                        self.open_window(Tab::Home);
                    }
                    Some(Click::Open(tab)) => return self.open(tab),
                    None => {}
                }
            }
            Action::Notice { key, verdict } => {
                let id = self
                    .posted
                    .iter()
                    .find_map(|(id, posted)| (*posted == key).then_some(*id));
                match (verdict, id) {
                    (Some(verdict), Some(id)) => {
                        // The platform took it down when it was answered.
                        self.posted.remove(&id);
                        let outcome = self.driver.run(Effect::Decide { id, verdict }).await;
                        self.report(Asker::Menu, outcome, None);
                    }
                    (Some(_), None) => self
                        .desktop
                        .notify("That request is no longer waiting, so nothing was answered."),
                    // The notification itself: the request in full.
                    (None, _) => return self.open(Tab::Approvals),
                }
            }
            // The menu offers Unlock; it does not ask by itself.
            Action::Menu => {
                self.open_window(Tab::Home);
            }
            Action::Window(message) => return self.on_page(message).await,
            Action::WindowClosed => {
                self.window = None;
                self.import = None;
                self.file = None;
            }
            Action::Login(on) => {
                if let Err(e) = self.desktop.set_login(on) {
                    self.desktop
                        .notify(&format!("Could not change the login item: {e}"));
                }
            }
            Action::Quit => return Next::Quit,
            Action::OfferUpdate => self.offer_update(),
            Action::UpdateChecked(found) => {
                let manual = std::mem::take(&mut self.check_manual);
                self.checked(found, manual);
            }
        }
        Next::Done
    }

    /// Opens kv's window on `tab`. A window that was closed opens on its
    /// unlock screen, asking at once.
    fn open(&mut self, tab: Tab) -> Next {
        let opening = self.open_window(tab);
        if opening && !self.driver.has_session() && self.driver.device().is_some() {
            return Next::Prompt(Prompting::Unlock(Asker::Window));
        }
        Next::Done
    }

    /// Opens kv's window on `tab`, or moves it there; whether it was closed.
    fn open_window(&mut self, tab: Tab) -> bool {
        let opening = self.window.is_none();
        match &mut self.window {
            Some(window) => window.tab = tab,
            None => {
                self.window = Some(Window {
                    tab,
                    form: None,
                    asking_update: false,
                })
            }
        }
        self.desktop.show_window(tab);
        self.desktop.page(ToPage::Show { tab });
        self.send_state();
        opening
    }

    /// Does what the page asks for. A page that has just loaded means the
    /// window is open, even if the worker heard it close: an "Open kv…" and
    /// a close can cross on their way here. Any other page message while
    /// the window is closed is a leftover and is dropped.
    async fn on_page(&mut self, message: FromPage) -> Next {
        if self.window.is_none() && message == FromPage::Ready {
            self.window = Some(Window {
                tab: Tab::Approvals,
                form: None,
                asking_update: false,
            });
        }
        let Some(window) = &self.window else {
            return Next::Done;
        };
        let tab = window.tab;
        let asking_update = window.asking_update;
        match message {
            FromPage::Ready => {
                self.desktop.page(ToPage::Show { tab });
                self.send_state();
                if let Some((_, form)) = self.form() {
                    let view = forms::describe(form);
                    self.desktop.page(ToPage::Form { view });
                }
                if asking_update && let Some(offer) = &self.offer {
                    self.desktop.page(update_ask(offer));
                }
                if shows_audit(tab) {
                    self.send_audit().await;
                }
            }
            FromPage::Unlock { passphrase } => {
                let outcome = self.driver.run(Effect::OpenSession(passphrase)).await;
                self.report(Asker::Window, outcome, None);
            }
            FromPage::DeviceUnlock => return Next::Prompt(Prompting::Unlock(Asker::Window)),
            FromPage::Decide { id, verdict } => {
                let outcome = self.driver.run(Effect::Decide { id, verdict }).await;
                self.report(Asker::Window, outcome, Some(id));
            }
            FromPage::OpenForm { form } => match self.open_form(form) {
                Ok(opened) => {
                    let view = forms::describe(&opened.1);
                    self.set_form(Some(opened));
                    self.desktop.page(ToPage::Form { view });
                }
                Err(message) => self.say(Asker::Window, &message, None),
            },
            FromPage::SubmitForm { values } => self.submit(values).await,
            FromPage::CloseForm => self.set_form(None),
            FromPage::Dismiss { id } => {
                let outcome = self.driver.run(Effect::Dismiss(id)).await;
                self.report(Asker::Window, outcome, None);
            }
            FromPage::Remove { name } => {
                let outcome = self.driver.run(Effect::Remove(name)).await;
                self.report(Asker::Window, outcome, None);
            }
            FromPage::Reveal { handle } => match self.driver.run(Effect::Reveal(handle)).await {
                Outcome::Revealed { handle, fields } => {
                    self.desktop.page(ToPage::Revealed { handle, fields });
                }
                other => self.report(Asker::Window, other, None),
            },
            FromPage::RevealHandle { handle, passphrase } => match passphrase {
                Some(passphrase) => self.reveal(handle, Proof::Passphrase(passphrase)).await,
                None if self.driver.has_session() && self.driver.device().is_some() => {
                    return Next::Prompt(Prompting::Reveal(handle));
                }
                None => self.desktop.page(ToPage::RevealAsk {
                    handle,
                    message: None,
                }),
            },
            FromPage::Copy { text } => {
                let done = self.desktop.copy(&text).is_ok();
                self.desktop.page(ToPage::Copied { done });
            }
            FromPage::Forget { id } => {
                let outcome = self.driver.run(Effect::Forget(id)).await;
                self.report(Asker::Window, outcome, None);
            }
            FromPage::ImportFile { file_name, text } => self.read_import(&file_name, &text),
            FromPage::ImportSave { name, keep } => self.save_import(&name, &keep).await,
            FromPage::ImportCancel => self.import = None,
            FromPage::FileRead { file_name, data } => self.read_file(&file_name, &data),
            FromPage::FileSave { name, cmds } => self.save_file(&name, &cmds).await,
            FromPage::FileCancel => self.file = None,
            FromPage::SaveFile { handle } => self.save_received(handle).await,
            FromPage::ShowSaved => {
                if let Some(path) = &self.saved {
                    sharefile::reveal(path);
                }
            }
            FromPage::RequestShare { note, from } => {
                self.share(Effect::RequestShare(ShareRequestCall { note, from }))
                    .await;
            }
            FromPage::SendShare {
                request,
                handle,
                name,
                from,
                note,
            } => {
                let call = SendShareCall {
                    request,
                    handle,
                    name: Some(name),
                    from,
                    note,
                };
                self.share(Effect::SendShare(call)).await;
            }
            FromPage::ReceiveShare { share, name } => {
                let call = ReceiveShareCall {
                    share,
                    name: Some(name),
                };
                self.share(Effect::ReceiveShare(call)).await;
            }
            FromPage::Lock => self.lock(Asker::Window).await,
            FromPage::Tab { tab } => {
                if let Some(window) = &mut self.window {
                    window.tab = tab;
                }
                if shows_audit(tab) {
                    self.send_audit().await;
                }
            }
            // The window takes these before they get here.
            FromPage::Hide
            | FromPage::Expand
            | FromPage::Drag
            | FromPage::Picking
            | FromPage::Busy { .. } => {}
            FromPage::Theme { theme } => {
                self.theme = theme;
                if let Err(e) = theme.save(&self.paths.tray_theme_file()) {
                    self.say(
                        Asker::Window,
                        &format!("could not save the appearance: {e}"),
                        None,
                    );
                }
                self.send_state();
            }
            FromPage::Login { on } => {
                if let Err(e) = self.desktop.set_login(on) {
                    self.say(
                        Asker::Window,
                        &format!("could not change the login item: {e}"),
                        None,
                    );
                }
                self.send_state();
            }
            FromPage::Quit => return Next::Quit,
            FromPage::OfferUpdate => self.offer_update(),
            // Started by `run` beside its loop (or by `act`), not here: a
            // slow answer must not hold up anything else.
            FromPage::CheckUpdates if self.installing => {
                self.desktop.page(ToPage::UpdateResult {
                    kind: UpdateKind::Check,
                    ok: false,
                    message: "An update is being installed now.".into(),
                });
            }
            FromPage::CheckUpdates => {
                self.check_wanted = true;
                self.check_manual = true;
            }
            FromPage::InstallUpdate { version } => self.install_update(&version),
            // Only an https page on GitHub: the address came from GitHub's
            // answer, and the system opens whatever scheme it is given.
            FromPage::OpenNotes => {
                if let Some(offer) = &self.offer
                    && url::Url::parse(&offer.notes_url).is_ok_and(|u| check::allowed_url(&u))
                {
                    self.desktop.open_url(&offer.notes_url);
                }
            }
        }
        Next::Done
    }

    /// A background check, if one is due: the first a few minutes after
    /// the tray starts, then twice a day.
    fn due_check(&mut self) -> Option<Check> {
        let now = Instant::now();
        if now < self.next_check {
            return None;
        }
        self.next_check = now + state::TRAY_EVERY;
        self.auto_checks.then(|| self.updater.check())
    }

    /// Takes in what a check `found`, and remembers it. A newer kv found
    /// in the background is announced once per version; one found by hand
    /// (`manual`) is told in Settings instead. A failed check in the
    /// background says nothing and keeps what was found before.
    fn checked(&mut self, found: Result<Option<Offer>, String>, manual: bool) {
        let file = self.paths.update_state_file();
        let mut remembered = state::load(&file);
        remembered.last_check = Some(unix_now());
        if let Ok(offer) = &found {
            remembered.latest = offer.as_ref().map(|o| o.version.to_string());
            // One being installed decides what is left to offer.
            if !self.installing {
                self.offer = offer.clone();
            }
        }
        if let Ok(Some(offer)) = &found
            && !self.installing
        {
            let version = offer.version.to_string();
            if remembered.announced.as_deref() != Some(&version) {
                if !manual {
                    self.announce(&offer.version);
                }
                remembered.announced = Some(version);
            }
        }
        let _ = file.parent().map(std::fs::create_dir_all);
        let _ = state::save(&file, &remembered);
        // The page hears what is on offer first, then how the check went.
        self.send_state();
        if manual {
            let (ok, message) = match &found {
                Ok(Some(offer)) => (true, format!("kv {} is out.", offer.version)),
                Ok(None) => (
                    true,
                    format!("kv {} is the latest.", update::current_version()),
                ),
                Err(e) => (false, format!("{}.", sentence(e))),
            };
            self.desktop.page(ToPage::UpdateResult {
                kind: UpdateKind::Check,
                ok,
                message,
            });
        }
    }

    /// Tells the user kv `version` is out: as a notification whose click
    /// opens the confirmation where kv.app posts them, else a plain one.
    fn announce(&self, version: &semver::Version) {
        let notice = Notice::update(version);
        if self.desktop.can_notify() {
            self.desktop.post(&notice);
        } else {
            self.desktop
                .notify(&format!("{}. {}", notice.title, notice.body));
        }
    }

    /// Opens kv's window on Home with the confirmation for the update on
    /// offer. It does not ask to unlock: updating needs no session.
    fn offer_update(&mut self) {
        let Some(offer) = &self.offer else {
            return;
        };
        let ask = update_ask(offer);
        self.open_window(Tab::Home);
        if let Some(window) = &mut self.window {
            window.asking_update = true;
        }
        self.desktop.page(ask);
    }

    /// Starts installing the update on offer, which the user agreed to:
    /// only if it is still `confirmed`, the version the confirmation showed.
    /// The download and swap run beside the loop (see `run`), and
    /// [`installed`](Self::installed) takes over when they end. A second
    /// request while one runs is dropped: the page hears how the first went.
    fn install_update(&mut self, confirmed: &str) {
        if self.installing {
            return;
        }
        if let Some(window) = &mut self.window {
            window.asking_update = false;
        }
        let Some(offer) = self.offer.clone() else {
            self.install_result(false, "There is no update on offer now.".into());
            return;
        };
        if offer.version.to_string() != confirmed {
            // A check found another version while the confirmation was
            // open: ask again, about this one.
            self.offer_update();
            self.install_result(
                false,
                format!(
                    "The update on offer is kv {} now, not {confirmed}. Choose Update to \
                     install it.",
                    offer.version
                ),
            );
            return;
        }
        self.installing = true;
        self.install_wanted = Some(offer);
    }

    /// Takes in how the download and swap went. Once the new kv is in
    /// place the daemon stops (which locks the vault), and the answer is
    /// what to hand over to: a tray on the new binary, which then takes
    /// over while this one quits (see [`handed_over`](Self::handed_over)).
    /// If the install failed nothing has changed; if the daemon did not
    /// stop, this tray keeps running and says what to do.
    async fn installed(&mut self, result: Result<Installed, UpdateError>) -> Option<Installed> {
        let installed = match result {
            Ok(installed) => installed,
            // An earlier update from this tray went in, but its handover
            // did not: nothing is left to install.
            Err(UpdateError::AlreadyInstalled(version)) => {
                self.installing = false;
                self.offer = None;
                self.send_state();
                self.install_result(
                    false,
                    format!(
                        "kv {version} is already installed. Quit kv tray and start it again to \
                         finish the update."
                    ),
                );
                return None;
            }
            Err(e) => {
                self.installing = false;
                self.install_result(false, format!("{}.", sentence(&e.to_string())));
                return None;
            }
        };
        // The new kv is in place: nothing is left to offer.
        self.offer = None;
        // A daemon left running would stay on the old binary, perhaps
        // unlocked, beside a new tray: hand over only once it has stopped.
        if let Outcome::Failed(_) = self.driver.stop().await {
            let message = format!(
                "kv {} is installed, but the kv daemon didn't stop. Run `kv stop`, then quit kv \
                 tray and start it again. {}",
                installed.version,
                crate::update::swap::way_back(&installed.swapped)
            );
            self.installing = false;
            self.update_failed(message);
            return None;
        }
        Some(installed)
    }

    /// Takes in how the handover went: true if a tray on the new kv took
    /// over and this one should quit; otherwise it keeps running and says
    /// what to do.
    fn handed_over(&mut self, handed: Result<(), String>) -> bool {
        self.installing = false;
        match handed {
            Ok(()) => true,
            Err(message) => {
                self.update_failed(message);
                false
            }
        }
    }

    /// Tells the window and the user that an update went in but this tray
    /// could not hand over, and why; this tray keeps running.
    fn update_failed(&self, message: String) {
        // With nothing left to offer, and locked if the daemon stopped.
        self.send_state();
        self.install_result(false, message.clone());
        self.desktop.notify(&message);
    }

    /// Tells the confirmation how the update it asked for went.
    fn install_result(&self, ok: bool, message: String) {
        self.desktop.page(ToPage::UpdateResult {
            kind: UpdateKind::Install,
            ok,
            message,
        });
    }

    /// Saves the open form with what the page sent. The form stays open,
    /// with the error beside it, until the daemon has taken it.
    async fn submit(&mut self, values: BTreeMap<String, SecretText>) {
        let Some((purpose, mut form)) = self.window.as_mut().and_then(|w| w.form.take()) else {
            return;
        };
        let effect = forms::fill(&mut form, &values).and_then(|()| forms::submit(&purpose, &form));
        let failed = match effect {
            Err(message) => message,
            Ok(effect) => match self.driver.run(effect).await {
                Outcome::Done(warnings) => {
                    self.desktop.page(ToPage::FormDone);
                    for warning in warnings {
                        self.say(Asker::Window, &warning, None);
                    }
                    return;
                }
                Outcome::Failed(message) => message,
                // The session ended: the form goes with it.
                other => return self.report(Asker::Window, other, None),
            },
        };
        self.set_form(Some((purpose, form)));
        self.desktop.page(ToPage::FormError {
            message: sentence(&failed),
        });
    }

    /// Takes a share step from the share dialog, which hears how it went.
    /// A share too long for a chat message is saved as a `.kvshare` file
    /// for the user to send as an attachment, not shown as text.
    async fn share(&mut self, effect: Effect) {
        let sending = match &effect {
            Effect::SendShare(call) => Some(call.handle.clone()),
            _ => None,
        };
        match self.driver.run(effect).await {
            Outcome::Share(ShareDone::Sealed {
                share,
                safety_code,
                to,
                asked_for,
            }) if share.chars().count() > MAX_MESSAGE_SHARE => {
                let name = format!(
                    "{}-{safety_code}.{}",
                    sending.unwrap_or_else(|| "share".into()),
                    sharefile::EXTENSION
                );
                match sharefile::save_new(&self.downloads_dir(), &name, share.as_bytes()) {
                    Ok(path) => {
                        self.desktop.page(ToPage::ShareSaved {
                            path: path.display().to_string(),
                            safety_code,
                            to,
                            asked_for,
                        });
                        self.saved = Some(path);
                    }
                    Err(e) => self.desktop.page(ToPage::ShareError {
                        message: format!("Could not save the share as a file: {e}."),
                    }),
                }
            }
            Outcome::Share(result) => self.desktop.page(ToPage::Shared { result }),
            Outcome::Failed(message) => self.desktop.page(ToPage::ShareError {
                message: sentence(&message),
            }),
            other => self.report(Asker::Window, other, None),
        }
    }

    fn form(&self) -> Option<&(Purpose, Form)> {
        self.window.as_ref()?.form.as_ref()
    }

    fn set_form(&mut self, form: Option<(Purpose, Form)>) {
        if let Some(window) = &mut self.window {
            window.form = form;
        }
    }

    /// The form the page asked for. A new handle needs only a session; the
    /// others open from what the last overview showed.
    fn open_form(&self, request: FormRequest) -> Result<(Purpose, Form), String> {
        if !self.driver.has_session() {
            return Err("unlock first".into());
        }
        let overview = || self.overview.as_ref().ok_or("unlock first");
        let handle = |name: &str| {
            overview()?
                .handles
                .iter()
                .find(|handle| handle.name == name)
                .cloned()
                .ok_or(format!("there is no handle named {name}"))
        };
        Ok(match request {
            FormRequest::New => (Purpose::Add, forms::new_handle()),
            FormRequest::Request { id } => {
                let requested = overview()?
                    .handle_requests
                    .iter()
                    .find(|requested| requested.id == id)
                    .ok_or("that handle request is no longer waiting")?;
                (Purpose::Add, forms::requested_handle(requested))
            }
            FormRequest::Edit { name } => {
                let handle = handle(&name)?;
                let form = forms::edit_handle(&handle);
                (Purpose::Edit(handle), form)
            }
            FormRequest::Policy { name } => {
                let handle = handle(&name)?;
                let form = forms::edit_policy(&handle);
                (Purpose::Policy(handle), form)
            }
        })
    }

    async fn lock(&mut self, asker: Asker) {
        let outcome = self.driver.run(Effect::Lock).await;
        self.set_form(None);
        self.import = None;
        self.file = None;
        self.report(asker, outcome, None);
    }

    async fn unlock(&mut self, asker: Asker, answer: DeviceAnswer) {
        let outcome = self.driver.finish_device(answer).await;
        self.report(asker, outcome, None);
    }

    /// Shows `handle`'s value in the window, if the daemon takes `proof`;
    /// if not, the page asks for the passphrase and says why. Nothing is
    /// asked of the daemon once the window has closed: there is nowhere to
    /// show it.
    async fn reveal(&mut self, handle: String, proof: Proof) {
        if self.window.is_none() {
            return;
        }
        match self.driver.reveal_handle(handle.clone(), proof).await {
            Outcome::Revealed { handle, fields } => {
                self.desktop.page(ToPage::HandleRevealed { handle, fields });
            }
            Outcome::Failed(message) => self.desktop.page(ToPage::RevealAsk {
                handle,
                message: Some(sentence(&message)),
            }),
            other => self.report(Asker::Window, other, None),
        }
    }

    /// Brings the notifications on show in line with the waiting requests:
    /// a new request gets one when `notifying`, and one whose request is
    /// gone (answered anywhere, timed out, or the session ended) is taken
    /// down.
    fn sync_notices(&mut self, notifying: bool) {
        let waiting = self
            .overview
            .as_ref()
            .map(|overview| overview.approvals.as_slice())
            .unwrap_or_default();
        let gone: Vec<String> = self
            .posted
            .iter()
            .filter(|(id, _)| !waiting.iter().any(|approval| approval.id == **id))
            .map(|(_, key)| key.clone())
            .collect();
        if !gone.is_empty() {
            self.posted.retain(|_, key| !gone.contains(key));
            self.desktop.withdraw(&gone);
        }
        if !notifying {
            return;
        }
        for approval in waiting {
            if !self.posted.contains_key(&approval.id) {
                let notice = Notice::new(approval);
                self.desktop.post(&notice);
                self.posted.insert(approval.id, notice.key);
            }
        }
    }

    /// Takes down every notification on show, as the tray quits: an answer
    /// to one would have no one to hear it. A value copied from the window
    /// goes too, since no one would clear it later.
    fn withdraw_all(&mut self) {
        self.desktop.clear_copied();
        let mut keys: Vec<String> = std::mem::take(&mut self.posted).into_values().collect();
        keys.append(&mut self.unlock_posted);
        if !keys.is_empty() {
            self.desktop.withdraw(&keys);
        }
    }

    /// Reads a file the window picked and shows what it holds, by name.
    fn read_import(&mut self, file_name: &str, text: &SecretText) {
        let format = Format::guess(file_name, text.expose());
        match import::parse(format, text.expose().as_bytes()) {
            Ok(imported) => {
                let keep = importing::default_keep(&imported);
                let vars = imported
                    .names()
                    .into_iter()
                    .map(|name| ImportVar {
                        name: name.to_owned(),
                        risky: envvars::is_risky(name),
                        keep: keep.iter().any(|k| k == name),
                    })
                    .collect();
                self.desktop.page(ToPage::ImportPreview {
                    file_name: file_name.to_owned(),
                    name: importing::suggested_name(file_name),
                    format: format.label().to_owned(),
                    vars,
                    notes: importing::notes(&imported),
                });
                self.import = Some(imported);
            }
            Err(e) => {
                self.import = None;
                self.desktop.page(ToPage::ImportError {
                    message: sentence(&e.to_string()),
                });
            }
        }
    }

    fn downloads_dir(&self) -> PathBuf {
        self.downloads
            .clone()
            .unwrap_or_else(|| sharefile::downloads(&self.paths))
    }

    /// Reads a file the window picked, whatever it is, and shows what it is.
    fn read_file(&mut self, file_name: &str, data: &SecretText) {
        let bytes = match STANDARD.decode(data.expose()) {
            Ok(bytes) => Zeroizing::new(bytes),
            Err(_) => {
                self.file = None;
                self.desktop.page(ToPage::FileError {
                    message: "That file could not be read.".into(),
                });
                return;
            }
        };
        match SecretValue::file(file_name, &bytes) {
            Ok(value) => {
                let probe = Secret {
                    name: importing::suggested_file_name(file_name),
                    description: String::new(),
                    value: value.clone(),
                    policy: Policy::default(),
                    created_at: 0,
                    updated_at: 0,
                    from_share: None,
                };
                let scrubbed = !probe.sensitive_values().is_empty();
                let mut notes = Vec::new();
                if !scrubbed {
                    notes.push(
                        "kv cannot scrub this file's contents from a program's output: it is not \
                         text with lines of 8 characters or more. A program that prints the file \
                         would show it."
                            .to_owned(),
                    );
                }
                self.desktop.page(ToPage::FilePreview {
                    file_name: file_name.to_owned(),
                    name: probe.name,
                    size: bytes.len(),
                    fingerprint: value.file_fingerprint().unwrap_or_default(),
                    scrubbed,
                    notes,
                });
                self.file = Some(value);
            }
            Err(e) => {
                self.file = None;
                self.desktop.page(ToPage::FileError {
                    message: sentence(&e.to_string()),
                });
            }
        }
    }

    /// Saves the file being shown through the same Add as the New handle
    /// form. On a refusal the file stays read, for another name or choice.
    async fn save_file(&mut self, name: &str, cmds: &str) {
        let Some(value) = self.file.take() else {
            return;
        };
        let file_name = match &value {
            SecretValue::File { file_name, .. } => file_name.clone(),
            _ => String::new(),
        };
        let policy = Policy {
            allowed_cmds: cmds
                .split(',')
                .map(str::trim)
                .filter(|cmd| !cmd.is_empty())
                .map(str::to_owned)
                .collect(),
            ..Policy::default()
        };
        let secret = Secret {
            name: name.to_owned(),
            description: format!("the file {file_name}"),
            value: value.clone(),
            policy,
            created_at: 0,
            updated_at: 0,
            from_share: None,
        };
        match self.driver.run(Effect::Add(secret)).await {
            Outcome::Done(warnings) => {
                self.desktop.page(ToPage::FileAdded {
                    name: name.to_owned(),
                    warnings: warnings.iter().map(|w| sentence(w)).collect(),
                });
            }
            Outcome::Failed(message) => {
                self.file = Some(value);
                self.desktop.page(ToPage::FileError {
                    message: sentence(&message),
                });
            }
            other => {
                self.file = Some(value);
                self.report(Asker::Window, other, None);
            }
        }
    }

    /// Saves the file a received handle holds to the Downloads folder,
    /// exactly as it arrived, and tells the window where.
    async fn save_received(&mut self, handle: String) {
        match self.driver.run(Effect::ExportFile(handle)).await {
            Outcome::File {
                handle,
                file_name,
                sha256,
                data,
            } => {
                // Checked again here, so what is written is what was sent.
                let value = SecretValue::File {
                    file_name,
                    data,
                    sha256,
                };
                let Some((file_name, bytes)) =
                    value.verify_file().ok().and_then(|()| value.file_parts())
                else {
                    self.desktop.page(ToPage::Message {
                        text: "The file did not check out, so kv did not save it.".into(),
                        request: None,
                    });
                    return;
                };
                match sharefile::save_new(&self.downloads_dir(), &file_name, &bytes) {
                    Ok(path) => {
                        self.desktop.page(ToPage::FileSaved {
                            handle,
                            path: path.display().to_string(),
                        });
                        self.saved = Some(path);
                    }
                    Err(e) => self.say(
                        Asker::Window,
                        &format!("could not save the file: {e}"),
                        None,
                    ),
                }
            }
            other => self.report(Asker::Window, other, None),
        }
    }

    /// Saves the import being shown through the same Add as the New handle
    /// form. On a refusal the file stays read, for another name or choice.
    async fn save_import(&mut self, name: &str, keep: &[String]) {
        let Some(imported) = self.import.take() else {
            return;
        };
        let vars = imported.keep(keep);
        if vars.is_empty() {
            self.import = Some(imported);
            self.desktop.page(ToPage::ImportError {
                message: "Tick at least one variable to import.".into(),
            });
            return;
        }
        let description = format!("imported from a {} file", imported.format.label());
        let secret = importing::secret(name, &description, vars, Policy::default());
        match self.driver.run(Effect::Add(secret)).await {
            Outcome::Done(warnings) => {
                self.desktop.page(ToPage::Imported {
                    name: name.to_owned(),
                    warnings: warnings.iter().map(|w| sentence(w)).collect(),
                });
            }
            Outcome::Failed(message) => {
                self.import = Some(imported);
                self.desktop.page(ToPage::ImportError {
                    message: sentence(&message),
                });
            }
            other => {
                self.import = Some(imported);
                self.report(Asker::Window, other, None);
            }
        }
    }

    /// Tells `asker` how an action went, when it failed.
    fn report(&self, asker: Asker, outcome: Outcome, request: Option<u64>) {
        match outcome {
            Outcome::Failed(message) => self.say(asker, &message, request),
            // The page hears it is locked first, so the reason shows on
            // the unlock screen.
            Outcome::Ended(message) => {
                self.send_state();
                self.say(asker, &message, request);
            }
            _ => {}
        }
    }

    /// Tells `asker`; with the window closed, the window's news becomes a
    /// notification only if the menu asked.
    fn say(&self, asker: Asker, message: &str, request: Option<u64>) {
        match asker {
            Asker::Menu => self.desktop.notify(&sentence(message)),
            Asker::Window if self.window.is_some() => self.desktop.page(ToPage::Message {
                text: sentence(message),
                request,
            }),
            Asker::Window => {}
        }
    }

    fn send_state(&self) {
        if self.window.is_none() {
            return;
        }
        self.desktop.page(ToPage::State {
            locked: !self.driver.has_session(),
            device: self.driver.device().map(|kind| kind.label().to_owned()),
            waiting_for_device: self.prompting.is_some(),
            overview: self.overview.clone(),
            login: self.desktop.login_is_on(),
            theme: self.theme,
            version: update::current_version().to_string(),
            update: self.offer.as_ref().map(|offer| offer.version.to_string()),
        });
    }

    async fn send_audit(&self) {
        match self.driver.audit().await {
            Outcome::Audit(entries) => self.desktop.page(ToPage::Audit { entries }),
            other => self.report(Asker::Window, other, None),
        }
    }
}

/// The confirmation for `offer`.
fn update_ask(offer: &Offer) -> ToPage {
    ToPage::UpdateAsk {
        version: offer.version.to_string(),
        notes_url: offer.notes_url.clone(),
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Whether the window's `tab` shows audit entries: Home's latest
/// activity, or the Audit tab.
fn shows_audit(tab: Tab) -> bool {
    matches!(tab, Tab::Home | Tab::Audit)
}

/// The daemon's messages start in lower case, to follow other text; a
/// notification or the window shows one on its own.
fn sentence(message: &str) -> String {
    let mut chars = message.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}
