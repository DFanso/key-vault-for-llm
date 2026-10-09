//! `kv tui`'s state, free of the terminal and the daemon: keys come in and
//! become effects for the driver to carry out, and the driver's outcomes
//! update what is shown.

use kv_core::proto::{Overview, PolicyPatch, Verdict};

use crate::audit::Entry;
use kv_core::secret::{Secret, SecretText, SecretValue};
use kv_core::vault::DeviceKind;
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use zeroize::Zeroizing;

use super::edit::{self, Purpose};
use super::form::{Form, Reply};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Screen {
    Unlock,
    Main,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tab {
    Approvals,
    Handles,
    Audit,
}

/// Something only the daemon can do.
#[derive(Debug, PartialEq, Eq)]
pub enum Effect {
    OpenSession(SecretText),
    /// Opens a session with Touch ID or Windows Hello.
    DeviceUnlock,
    Decide {
        id: u64,
        verdict: Verdict,
    },
    Add(Secret),
    Update {
        name: String,
        description: Option<String>,
        value: Option<SecretValue>,
    },
    SetPolicy {
        name: String,
        patch: PolicyPatch,
    },
    Remove(String),
    /// Drops an agent's handle request.
    Dismiss(u64),
    Lock,
    Quit,
}

/// What came back from the daemon.
#[derive(Debug)]
pub enum Outcome {
    Opened,
    Overview(Overview),
    /// The session is over; back to the unlock screen, with the reason.
    Ended(String),
    /// The request failed; the message says why.
    Failed(String),
    /// Done, with any warnings the daemon gave.
    Done(Vec<String>),
    /// The end of the audit log, newest first.
    Audit(Vec<Entry>),
}

/// An open form and what saving it means.
struct Editor {
    form: Form,
    purpose: Purpose,
    /// Saved and waiting for the daemon's answer.
    saving: bool,
}

pub struct App {
    screen: Screen,
    tab: Tab,
    passphrase: Zeroizing<String>,
    overview: Option<Overview>,
    audit: Vec<Entry>,
    /// The id of the waiting request the decision keys act on. Kept by id,
    /// not position, so a request leaving the list never shifts a key press
    /// onto one the user has not read.
    selected: Option<u64>,
    /// Index into the handles tab's rows: the handle requests, then the
    /// handles.
    selected_handle: usize,
    editor: Option<Editor>,
    /// The handle waiting for a yes before it is removed.
    removing: Option<String>,
    message: Option<String>,
    /// The device the vault can be unlocked with, offered on Ctrl-T.
    device: Option<DeviceKind>,
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}

impl App {
    pub fn new() -> Self {
        Self {
            screen: Screen::Unlock,
            tab: Tab::Approvals,
            passphrase: Zeroizing::new(String::new()),
            overview: None,
            audit: Vec::new(),
            selected: None,
            selected_handle: 0,
            editor: None,
            removing: None,
            message: None,
            device: None,
        }
    }

    /// Offers `device` on the unlock screen.
    pub fn set_device(&mut self, device: Option<DeviceKind>) {
        self.device = device;
    }

    pub fn device(&self) -> Option<DeviceKind> {
        self.device
    }

    /// Asks the device to unlock, if there is one and the vault is locked.
    pub fn ask_device(&mut self) -> Option<Effect> {
        let device = self.device.filter(|_| self.screen == Screen::Unlock)?;
        self.message = Some(format!("asking {}…", device.label()));
        Some(Effect::DeviceUnlock)
    }

    pub fn screen(&self) -> Screen {
        self.screen
    }

    pub fn tab(&self) -> Tab {
        self.tab
    }

    pub fn message(&self) -> Option<&str> {
        self.message.as_deref()
    }

    pub fn overview(&self) -> Option<&Overview> {
        self.overview.as_ref()
    }

    /// The end of the audit log, newest first.
    pub fn audit(&self) -> &[Entry] {
        &self.audit
    }

    /// The open form, if any.
    pub fn form(&self) -> Option<&Form> {
        self.editor.as_ref().map(|e| &e.form)
    }

    /// The handle a yes would remove.
    pub fn removing(&self) -> Option<&str> {
        self.removing.as_deref()
    }

    /// How many characters of the passphrase are typed. The passphrase
    /// itself is never drawn.
    pub fn passphrase_len(&self) -> usize {
        self.passphrase.chars().count()
    }

    /// The id of the waiting request the decision keys act on.
    pub fn selected(&self) -> Option<u64> {
        self.selected
    }

    /// The row of the handles tab the keys act on: handle requests come
    /// first, then handles.
    pub fn selected_handle(&self) -> usize {
        self.selected_handle
    }

    pub fn handle_key(&mut self, key: KeyEvent) -> Option<Effect> {
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            return Some(Effect::Quit);
        }
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('t') {
            return self.ask_device();
        }
        // Ctrl and Alt letters are neither text nor commands: Ctrl+S must
        // not allow anything, and must not type an s into a secret.
        if matches!(key.code, KeyCode::Char(_))
            && key
                .modifiers
                .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
        {
            return None;
        }
        if self.editor.is_some() {
            return self.form_key(key);
        }
        if let Some(name) = self.removing.take() {
            return (key.code == KeyCode::Char('y')).then_some(Effect::Remove(name));
        }
        match self.screen {
            Screen::Unlock => self.unlock_key(key),
            Screen::Main => self.main_key(key),
        }
    }

    pub fn apply(&mut self, outcome: Outcome) {
        match outcome {
            Outcome::Opened => {
                self.screen = Screen::Main;
                self.tab = Tab::Approvals;
                self.message = None;
            }
            Outcome::Overview(overview) => {
                let was_empty = self
                    .overview
                    .as_ref()
                    .is_none_or(|o| o.approvals.is_empty());
                let ids: Vec<u64> = overview.approvals.iter().map(|a| a.id).collect();
                match self.selected {
                    Some(id) if !ids.contains(&id) => {
                        self.selected = None;
                        if !ids.is_empty() {
                            self.message = Some(
                                "the request you selected is no longer waiting; select one with ↑↓"
                                    .into(),
                            );
                        }
                    }
                    // Only a list that was empty gets a selection on its own;
                    // otherwise the user picks with ↑↓.
                    None if was_empty => self.selected = ids.first().copied(),
                    _ => {}
                }
                // Stay on the same request or handle when rows come and go
                // above it, so a key never lands on a row the user did not
                // pick; if it left, keep the place in the list.
                let row = self
                    .overview
                    .as_ref()
                    .and_then(|o| Row::at(o, self.selected_handle));
                let rows = overview.handle_requests.len() + overview.handles.len();
                self.selected_handle = row
                    .and_then(|row| row.index_in(&overview))
                    .unwrap_or(self.selected_handle)
                    .min(rows.saturating_sub(1));
                self.overview = Some(overview);
            }
            Outcome::Audit(entries) => self.audit = entries,
            Outcome::Ended(reason) => {
                self.screen = Screen::Unlock;
                self.overview = None;
                self.selected = None;
                self.audit.clear();
                self.editor = None;
                self.removing = None;
                self.message = Some(reason);
            }
            Outcome::Failed(message) => {
                if let Some(editor) = &mut self.editor {
                    editor.saving = false;
                }
                self.message = Some(message);
            }
            Outcome::Done(warnings) => {
                if self.editor.as_ref().is_some_and(|e| e.saving) {
                    self.editor = None;
                }
                self.message = (!warnings.is_empty()).then(|| warnings.join("; "));
            }
        }
    }

    /// A paste is one input: it goes into the passphrase or the focused
    /// form field, and is ignored everywhere else, so pasted text can never
    /// act as a run of commands.
    pub fn paste(&mut self, text: &str) {
        if let Some(editor) = &mut self.editor {
            if !editor.saving
                && let Reply::Message(message) = editor.form.paste(text)
            {
                self.message = Some(message);
            }
            return;
        }
        if self.screen == Screen::Unlock {
            self.passphrase
                .extend(text.chars().filter(|c| *c != '\n' && *c != '\r'));
        }
    }

    fn unlock_key(&mut self, key: KeyEvent) -> Option<Effect> {
        match key.code {
            KeyCode::Char(c) => self.passphrase.push(c),
            KeyCode::Backspace => {
                self.passphrase.pop();
            }
            KeyCode::Enter => {
                let passphrase = SecretText::new(self.passphrase.as_str());
                self.passphrase.clear();
                self.message = Some("unlocking…".into());
                return Some(Effect::OpenSession(passphrase));
            }
            KeyCode::Esc => return Some(Effect::Quit),
            _ => {}
        }
        None
    }

    fn main_key(&mut self, key: KeyEvent) -> Option<Effect> {
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => return Some(Effect::Quit),
            KeyCode::Char('L') => {
                self.screen = Screen::Unlock;
                self.overview = None;
                self.selected = None;
                self.audit.clear();
                self.message = Some("locked".into());
                return Some(Effect::Lock);
            }
            KeyCode::Char('1') => self.tab = Tab::Approvals,
            KeyCode::Char('2') => self.tab = Tab::Handles,
            KeyCode::Char('3') => self.tab = Tab::Audit,
            KeyCode::Tab => {
                self.tab = match self.tab {
                    Tab::Approvals => Tab::Handles,
                    Tab::Handles => Tab::Audit,
                    Tab::Audit => Tab::Approvals,
                }
            }
            _ => match self.tab {
                Tab::Approvals => return self.approvals_key(key),
                Tab::Handles => return self.handles_key(key),
                Tab::Audit => {}
            },
        }
        None
    }

    fn approvals_key(&mut self, key: KeyEvent) -> Option<Effect> {
        let ids: Vec<u64> = self
            .overview
            .as_ref()
            .map_or(Vec::new(), |o| o.approvals.iter().map(|a| a.id).collect());
        let at = self
            .selected
            .and_then(|id| ids.iter().position(|i| *i == id));
        let verdict = match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                let index = at.map_or(0, |i| i.saturating_sub(1));
                self.selected = ids.get(index).copied();
                return None;
            }
            KeyCode::Down | KeyCode::Char('j') => {
                let index = at.map_or(0, |i| (i + 1).min(ids.len().saturating_sub(1)));
                self.selected = ids.get(index).copied();
                return None;
            }
            KeyCode::Char('a') => Verdict::AllowOnce,
            KeyCode::Char('s') => Verdict::AllowSession,
            KeyCode::Char('d') => Verdict::Deny,
            KeyCode::Char('D') => Verdict::DenyAlways,
            _ => return None,
        };
        let selected = self.selected?;
        let approval = self
            .overview
            .as_ref()?
            .approvals
            .iter()
            .find(|a| a.id == selected)?;
        if verdict == Verdict::AllowSession && !approval.can_grant {
            self.message = Some(
                "this request did not name its agent session, so it can only be allowed once"
                    .into(),
            );
            return None;
        }
        Some(Effect::Decide {
            id: approval.id,
            verdict,
        })
    }

    fn handles_key(&mut self, key: KeyEvent) -> Option<Effect> {
        let (requests, handles) = self.overview.as_ref().map_or((&[][..], &[][..]), |o| {
            (&o.handle_requests[..], &o.handles[..])
        });
        let rows = requests.len() + handles.len();
        let request = requests.get(self.selected_handle);
        let handle = self
            .selected_handle
            .checked_sub(requests.len())
            .and_then(|i| handles.get(i));
        let (form, purpose) = match (key.code, request, handle) {
            (KeyCode::Up | KeyCode::Char('k'), ..) => {
                self.selected_handle = self.selected_handle.saturating_sub(1);
                return None;
            }
            (KeyCode::Down | KeyCode::Char('j'), ..) => {
                self.selected_handle = (self.selected_handle + 1).min(rows.saturating_sub(1));
                return None;
            }
            (KeyCode::Char('n'), ..) => (edit::new_handle(), Purpose::Add),
            (KeyCode::Enter | KeyCode::Char('e'), Some(request), _) => {
                (edit::requested_handle(request), Purpose::Add)
            }
            (KeyCode::Char('x'), Some(request), _) => return Some(Effect::Dismiss(request.id)),
            (KeyCode::Char('e'), _, Some(handle)) => {
                (edit::edit_handle(handle), Purpose::Edit(handle.clone()))
            }
            (KeyCode::Char('p'), _, Some(handle)) => {
                (edit::edit_policy(handle), Purpose::Policy(handle.clone()))
            }
            (KeyCode::Char('x'), _, Some(handle)) => {
                self.removing = Some(handle.name.clone());
                return None;
            }
            _ => return None,
        };
        self.message = None;
        self.editor = Some(Editor {
            form,
            purpose,
            saving: false,
        });
        None
    }

    fn form_key(&mut self, key: KeyEvent) -> Option<Effect> {
        let editor = self.editor.as_mut()?;
        if editor.saving {
            return None;
        }
        match editor.form.handle_key(key) {
            Reply::Nothing => None,
            Reply::Cancel => {
                self.editor = None;
                self.message = None;
                None
            }
            Reply::Message(message) => {
                self.message = Some(message);
                None
            }
            Reply::Submit => match edit::submit(&editor.purpose, &editor.form) {
                Ok(effect) => {
                    editor.saving = true;
                    self.message = Some("saving…".into());
                    Some(effect)
                }
                Err(message) => {
                    self.message = Some(message);
                    None
                }
            },
        }
    }
}

/// A row of the handles tab, by identity rather than position.
#[derive(PartialEq)]
enum Row {
    Request(u64),
    Handle(String),
}

impl Row {
    fn at(overview: &Overview, index: usize) -> Option<Row> {
        let requests = &overview.handle_requests;
        match requests.get(index) {
            Some(request) => Some(Row::Request(request.id)),
            None => overview
                .handles
                .get(index - requests.len())
                .map(|h| Row::Handle(h.name.clone())),
        }
    }

    fn index_in(&self, overview: &Overview) -> Option<usize> {
        let requests = &overview.handle_requests;
        match self {
            Row::Request(id) => requests.iter().position(|r| r.id == *id),
            Row::Handle(name) => overview
                .handles
                .iter()
                .position(|h| h.name == *name)
                .map(|i| requests.len() + i),
        }
    }
}
