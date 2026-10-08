//! `kv tui`: approve waiting agent requests, edit handles, lock the vault.
//! Unlocking trades the passphrase for a session token held only in this
//! process; every later request uses the token.

pub mod app;
mod edit;
pub mod form;
pub mod view;

use std::io::{self, IsTerminal};
use std::time::Duration;

use kv_core::proto::{ControlCommand, ControlErrorCode, ControlRequest, ControlResponse};
use kv_core::secret::SecretText;
use ratatui::DefaultTerminal;
use ratatui::crossterm::event::{
    self, DisableBracketedPaste, EnableBracketedPaste, Event, KeyEventKind,
};
use ratatui::crossterm::execute;

use crate::paths::Paths;
use crate::{audit, client};
use app::{App, Effect, Outcome, Tab};

/// How often the screen asks the daemon for news.
const REFRESH: Duration = Duration::from_millis(500);

/// How many audit log lines the audit tab shows.
const AUDIT_LINES: usize = 200;

/// Carries out effects against the daemon and holds the session token.
pub struct Driver {
    paths: Paths,
    token: Option<SecretText>,
}

impl Driver {
    pub fn new(paths: Paths) -> Self {
        Self { paths, token: None }
    }

    pub async fn run(&mut self, effect: Effect) -> Outcome {
        match effect {
            Effect::OpenSession(passphrase) => {
                let request = ControlRequest {
                    passphrase: Some(passphrase),
                    token: None,
                    command: ControlCommand::OpenSession,
                };
                match client::control(&self.paths, &request, true).await {
                    Ok(ControlResponse::Session { token }) => {
                        self.token = Some(token);
                        Outcome::Opened
                    }
                    Ok(ControlResponse::Error { message, .. }) => Outcome::Failed(message),
                    Ok(other) => Outcome::Failed(format!("unexpected reply: {other:?}")),
                    Err(e) => Outcome::Failed(format!("could not reach the kv daemon: {e}")),
                }
            }
            Effect::Decide { id, verdict } => {
                self.send(ControlCommand::Decide { id, verdict }).await
            }
            Effect::Add(secret) => {
                self.send(ControlCommand::Add {
                    secret,
                    replace: false,
                })
                .await
            }
            Effect::Update {
                name,
                description,
                value,
            } => {
                self.send(ControlCommand::Update {
                    name,
                    description,
                    value,
                })
                .await
            }
            Effect::SetPolicy { name, patch } => {
                self.send(ControlCommand::SetPolicy { name, patch }).await
            }
            Effect::Remove(name) => self.send(ControlCommand::Remove { name }).await,
            Effect::Lock => {
                self.token = None;
                let request = ControlRequest {
                    passphrase: None,
                    token: None,
                    command: ControlCommand::Lock,
                };
                match client::control_if_running(&self.paths, &request).await {
                    Ok(None | Some(ControlResponse::Done { .. })) => Outcome::Done(Vec::new()),
                    Ok(Some(other)) => Outcome::Failed(format!("could not lock: {other:?}")),
                    Err(e) => Outcome::Failed(format!("could not lock: {e}")),
                }
            }
            Effect::Quit => Outcome::Done(Vec::new()),
        }
    }

    /// Fetches what the screen shows. `None` without a session.
    pub async fn refresh(&mut self) -> Option<Outcome> {
        self.token.as_ref()?;
        Some(self.send(ControlCommand::Overview).await)
    }

    /// Reads the end of the audit log. The log holds no secret values, so
    /// this needs no session.
    pub async fn audit(&self) -> Outcome {
        let path = self.paths.audit.clone();
        match tokio::task::spawn_blocking(move || audit::tail(&path, AUDIT_LINES)).await {
            Ok(Ok(entries)) => Outcome::Audit(entries),
            Ok(Err(e)) => Outcome::Failed(format!("could not read the audit log: {e}")),
            Err(e) => Outcome::Failed(format!("could not read the audit log: {e}")),
        }
    }

    async fn send(&mut self, command: ControlCommand) -> Outcome {
        let Some(token) = self.token.clone() else {
            return Outcome::Ended("unlock first".into());
        };
        let request = ControlRequest {
            passphrase: None,
            token: Some(token),
            command,
        };
        match client::control_if_running(&self.paths, &request).await {
            Ok(Some(ControlResponse::Overview { overview })) => Outcome::Overview(overview),
            Ok(Some(ControlResponse::Done { warnings })) => Outcome::Done(warnings),
            Ok(Some(ControlResponse::Error {
                code: ControlErrorCode::SessionEnded,
                message,
            })) => {
                self.token = None;
                Outcome::Ended(message)
            }
            Ok(Some(ControlResponse::Error { message, .. })) => Outcome::Failed(message),
            Ok(Some(other)) => Outcome::Failed(format!("unexpected reply: {other:?}")),
            Ok(None) | Err(_) => {
                self.token = None;
                Outcome::Ended("the kv daemon stopped; unlock again".into())
            }
        }
    }
}

/// Runs the terminal UI until the user quits.
pub async fn run(paths: Paths) -> io::Result<()> {
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        return Err(io::Error::other("kv tui needs a terminal"));
    }
    let mut terminal = ratatui::init();
    // A paste then arrives as one event instead of keystrokes. Terminals
    // without it still work: hidden fields ignore Enter, see `form`.
    let _ = execute!(io::stdout(), EnableBracketedPaste);
    let result = event_loop(&mut terminal, paths).await;
    let _ = execute!(io::stdout(), DisableBracketedPaste);
    ratatui::restore();
    result
}

async fn refresh(app: &mut App, driver: &mut Driver) {
    if let Some(outcome) = driver.refresh().await {
        app.apply(outcome);
    }
    if app.screen() == app::Screen::Main && app.tab() == Tab::Audit {
        app.apply(driver.audit().await);
    }
}

async fn event_loop(terminal: &mut DefaultTerminal, paths: Paths) -> io::Result<()> {
    let (events_tx, mut events) = tokio::sync::mpsc::unbounded_channel();
    // crossterm's reader blocks, so it gets a thread of its own.
    std::thread::spawn(move || {
        while let Ok(event) = event::read() {
            let wanted = match &event {
                Event::Key(key) => key.kind == KeyEventKind::Press,
                Event::Paste(_) => true,
                _ => false,
            };
            if wanted && events_tx.send(event).is_err() {
                break;
            }
        }
    });
    let mut app = App::new();
    let mut driver = Driver::new(paths);
    let mut tick = tokio::time::interval(REFRESH);
    loop {
        terminal.draw(|frame| view::draw(frame, &app))?;
        tokio::select! {
            event = events.recv() => {
                let key = match event {
                    Some(Event::Key(key)) => key,
                    Some(Event::Paste(text)) => {
                        app.paste(&text);
                        continue;
                    }
                    Some(_) => continue,
                    None => return Ok(()),
                };
                let Some(effect) = app.handle_key(key) else { continue };
                if effect == Effect::Quit {
                    return Ok(());
                }
                let outcome = driver.run(effect).await;
                app.apply(outcome);
                refresh(&mut app, &mut driver).await;
            }
            _ = tick.tick() => refresh(&mut app, &mut driver).await,
        }
    }
}
