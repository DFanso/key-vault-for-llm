//! The tray's daemon side, on a tokio runtime of its own: reads the
//! daemon's status every second, holds the session the menu and the window
//! share, and carries out what they ask for. A failure is told where the
//! user asked: in the window, or as a notification for the menu.

use std::collections::BTreeMap;
use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use zeroize::Zeroizing;

use kv_core::proto::{
    AgentRequest, AgentResponse, Overview, ReceiveShareCall, SendShareCall, ShareRequestCall,
};
use kv_core::secret::{Secret, SecretText, SecretValue};
use tokio::sync::mpsc::UnboundedReceiver;

use super::model::{Action, Model, View};
use super::window::{FormRequest, FromPage, ImportVar, Tab, Theme, ToPage};
use crate::client;
use crate::device::Device;
use crate::forms::{self, Form, Purpose};
use crate::importing;
use crate::paths::Paths;
use crate::sharefile;
use crate::tui::app::{Effect, Outcome, ShareDone};
use crate::tui::{DeviceAnswer, Driver};
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

/// What the worker needs from the desktop around it.
pub trait Desktop: Send {
    fn notify(&self, text: &str);
    /// Opens kv's window on `tab`, or brings it to the front on `tab`.
    fn show_window(&self, tab: Tab);
    /// Hands a message to the window's page.
    fn page(&self, message: ToPage);
    fn login_is_on(&self) -> bool;
    fn set_login(&self, on: bool) -> io::Result<()>;
}

/// Who asked for something, and so hears how it went.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Asker {
    Menu,
    Window,
}

/// What is left to do after an action.
enum Next {
    Done,
    /// A device prompt, then a session.
    Prompt(Asker),
    Quit,
}

/// kv's window while it is open.
struct Window {
    tab: Tab,
    /// The open form, and what saving it means.
    form: Option<(Purpose, Form)>,
}

pub struct Worker<D> {
    paths: Paths,
    driver: Driver,
    desktop: D,
    window: Option<Window>,
    /// The overview of the last tick, which the forms open from.
    overview: Option<Overview>,
    /// Who is waiting on the device prompt `run` holds beside its loop.
    prompting: Option<Asker>,
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
}

impl<D: Desktop> Worker<D> {
    pub fn new(paths: Paths, device: Option<Arc<dyn Device>>, desktop: D) -> Self {
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
        let status = match client::agent_if_running(&self.paths, &AgentRequest::Status).await {
            Ok(Some(AgentResponse::Status { status })) => Some(status),
            _ => None,
        };
        let mut ended = None;
        self.overview = match self.driver.refresh().await {
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
        })
    }

    /// Carries out one action, a device prompt included. Returns true for
    /// Quit.
    pub async fn act(&mut self, action: Action) -> bool {
        match self.begin(action).await {
            Next::Done => false,
            Next::Prompt(asker) => {
                let answer = self.driver.ask_device().await;
                self.unlock(asker, answer).await;
                false
            }
            Next::Quit => true,
        }
    }

    /// Shows a model every tick and after every action until Quit, or until
    /// the UI drops its sender. A device prompt runs beside the loop, so the
    /// icon and the window stay current while the user decides.
    pub async fn run(
        mut self,
        mut actions: UnboundedReceiver<Action>,
        mut show: impl FnMut(Model),
    ) {
        let mut tick = tokio::time::interval(TICK);
        let mut prompt = None;
        loop {
            tokio::select! {
                answer = async { prompt.as_mut().expect("guarded").await }, if prompt.is_some() => {
                    prompt = None;
                    let asker = self.prompting.take().unwrap_or(Asker::Menu);
                    self.unlock(asker, answer).await;
                }
                action = actions.recv() => {
                    let Some(action) = action else { return };
                    match self.begin(action).await {
                        Next::Done => {}
                        Next::Prompt(asker) => {
                            if prompt.is_none() {
                                prompt = Some(self.driver.ask_device());
                                self.prompting = Some(asker);
                            }
                        }
                        Next::Quit => return,
                    }
                }
                _ = tick.tick() => {}
            }
            show(self.model().await);
        }
    }

    /// Does what `action` asks for, short of a device prompt.
    async fn begin(&mut self, action: Action) -> Next {
        match action {
            Action::Unlock => return Next::Prompt(Asker::Menu),
            Action::Decide { id, verdict } => {
                let outcome = self.driver.run(Effect::Decide { id, verdict }).await;
                self.report(Asker::Menu, outcome, None);
            }
            Action::Lock => self.lock(Asker::Menu).await,
            Action::Open(tab) => {
                let opening = self.open_window(tab);
                // The window opens on its unlock screen, asking at once.
                if opening && !self.driver.has_session() && self.driver.device().is_some() {
                    return Next::Prompt(Asker::Window);
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
        }
        Next::Done
    }

    /// Opens kv's window on `tab`, or moves it there; whether it was closed.
    fn open_window(&mut self, tab: Tab) -> bool {
        let opening = self.window.is_none();
        match &mut self.window {
            Some(window) => window.tab = tab,
            None => self.window = Some(Window { tab, form: None }),
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
            });
        }
        let Some(window) = &self.window else {
            return Next::Done;
        };
        let tab = window.tab;
        match message {
            FromPage::Ready => {
                self.desktop.page(ToPage::Show { tab });
                self.send_state();
                if let Some((_, form)) = self.form() {
                    let view = forms::describe(form);
                    self.desktop.page(ToPage::Form { view });
                }
                if shows_audit(tab) {
                    self.send_audit().await;
                }
            }
            FromPage::Unlock { passphrase } => {
                let outcome = self.driver.run(Effect::OpenSession(passphrase)).await;
                self.report(Asker::Window, outcome, None);
            }
            FromPage::DeviceUnlock => return Next::Prompt(Asker::Window),
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
            FromPage::Hide | FromPage::Expand => {}
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
        }
        Next::Done
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
        });
    }

    async fn send_audit(&self) {
        match self.driver.audit().await {
            Outcome::Audit(entries) => self.desktop.page(ToPage::Audit { entries }),
            other => self.report(Asker::Window, other, None),
        }
    }
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
