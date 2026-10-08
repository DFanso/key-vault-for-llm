//! `kv tui`'s state, free of the terminal and the daemon: keys come in and
//! become effects for the driver to carry out, and the driver's outcomes
//! update what is shown.

use kv_core::proto::{Overview, Verdict};
use kv_core::secret::SecretText;
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Screen {
    Unlock,
    Main,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tab {
    Approvals,
    Handles,
}

/// Something only the daemon can do.
#[derive(Debug, PartialEq, Eq)]
pub enum Effect {
    OpenSession(SecretText),
    Decide { id: u64, verdict: Verdict },
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
}

pub struct App {
    screen: Screen,
    tab: Tab,
    passphrase: Zeroizing<String>,
    overview: Option<Overview>,
    /// Index into the waiting requests.
    selected: usize,
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
            selected: 0,
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

    /// How many characters of the passphrase are typed. The passphrase
    /// itself is never drawn.
    pub fn passphrase_len(&self) -> usize {
        self.passphrase.chars().count()
    }

    /// The waiting request the decision keys act on.
    pub fn selected(&self) -> usize {
        self.selected
    }

    pub fn handle_key(&mut self, key: KeyEvent) -> Option<Effect> {
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            return Some(Effect::Quit);
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
                let waiting = overview.approvals.len();
                self.selected = self.selected.min(waiting.saturating_sub(1));
                self.overview = Some(overview);
            }
            Outcome::Ended(reason) => {
                self.screen = Screen::Unlock;
                self.overview = None;
                self.message = Some(reason);
            }
            Outcome::Failed(message) => self.message = Some(message),
            Outcome::Done(warnings) => {
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
                self.message = Some("locked".into());
                return Some(Effect::Lock);
            }
            KeyCode::Char('1') => self.tab = Tab::Approvals,
            KeyCode::Char('2') => self.tab = Tab::Handles,
            KeyCode::Tab => {
                self.tab = match self.tab {
                    Tab::Approvals => Tab::Handles,
                    Tab::Handles => Tab::Approvals,
                }
            }
            _ if self.tab == Tab::Approvals => return self.approvals_key(key),
            _ => {}
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
}
