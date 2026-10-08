//! `kv tui`'s state, free of the terminal and the daemon: keys come in and
//! become effects for the driver to carry out, and the driver's outcomes
//! update what is shown.

use kv_core::proto::{Overview, PolicyPatch, Verdict};

use crate::audit::Entry;
use kv_core::secret::{Secret, SecretText, SecretValue};
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
    /// Index into the waiting requests.
    selected: usize,
    /// Index into the handles.
    selected_handle: usize,
    editor: Option<Editor>,
    /// The handle waiting for a yes before it is removed.
    removing: Option<String>,
    message: Option<String>,
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
            selected: 0,
            selected_handle: 0,
            editor: None,
            removing: None,
            message: None,
        }
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

    /// The waiting request the decision keys act on.
    pub fn selected(&self) -> usize {
        self.selected
    }

    /// The handle the edit keys act on.
    pub fn selected_handle(&self) -> usize {
        self.selected_handle
    }

    pub fn handle_key(&mut self, key: KeyEvent) -> Option<Effect> {
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            return Some(Effect::Quit);
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
                let last = |n: usize| n.saturating_sub(1);
                self.selected = self.selected.min(last(overview.approvals.len()));
                self.selected_handle = self.selected_handle.min(last(overview.handles.len()));
                self.overview = Some(overview);
            }
            Outcome::Audit(entries) => self.audit = entries,
            Outcome::Ended(reason) => {
                self.screen = Screen::Unlock;
                self.overview = None;
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
                Tab::Handles => self.handles_key(key),
                Tab::Audit => {}
            },
        }
        None
    }

    fn approvals_key(&mut self, key: KeyEvent) -> Option<Effect> {
        let waiting = self.overview.as_ref().map_or(0, |o| o.approvals.len());
        let verdict = match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                self.selected = self.selected.saturating_sub(1);
                return None;
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.selected = (self.selected + 1).min(waiting.saturating_sub(1));
                return None;
            }
            KeyCode::Char('a') => Verdict::AllowOnce,
            KeyCode::Char('s') => Verdict::AllowSession,
            KeyCode::Char('d') => Verdict::Deny,
            KeyCode::Char('D') => Verdict::DenyAlways,
            _ => return None,
        };
        let approval = self.overview.as_ref()?.approvals.get(self.selected)?;
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

    fn handles_key(&mut self, key: KeyEvent) {
        let handles = self.overview.as_ref().map_or(&[][..], |o| &o.handles[..]);
        let selected = handles.get(self.selected_handle);
        let (form, purpose) = match (key.code, selected) {
            (KeyCode::Up | KeyCode::Char('k'), _) => {
                self.selected_handle = self.selected_handle.saturating_sub(1);
                return;
            }
            (KeyCode::Down | KeyCode::Char('j'), _) => {
                let last = handles.len().saturating_sub(1);
                self.selected_handle = (self.selected_handle + 1).min(last);
                return;
            }
            (KeyCode::Char('n'), _) => (edit::new_handle(), Purpose::Add),
            (KeyCode::Char('e'), Some(handle)) => {
                (edit::edit_handle(handle), Purpose::Edit(handle.clone()))
            }
            (KeyCode::Char('p'), Some(handle)) => {
                (edit::edit_policy(handle), Purpose::Policy(handle.clone()))
            }
            (KeyCode::Char('x'), Some(handle)) => {
                self.removing = Some(handle.name.clone());
                return;
            }
            _ => return,
        };
        self.message = None;
        self.editor = Some(Editor {
            form,
            purpose,
            saving: false,
        });
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
