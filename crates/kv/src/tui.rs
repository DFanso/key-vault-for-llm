//! `kv tui`: approve waiting agent requests, edit handles, lock the vault.
//! Unlocking trades the passphrase, or a key from Touch ID or Windows Hello,
//! for a session token held only in this process; every later request uses
//! the token.

pub mod app;
mod edit;
pub mod form;
pub mod view;

use std::future::Future;
use std::io::{self, IsTerminal};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use kv_core::proto::{
    ControlCommand, ControlErrorCode, ControlRequest, ControlResponse, DeviceCredential,
};
use kv_core::secret::SecretText;
use kv_core::vault::{DeviceKind, device_slots};
use ratatui::DefaultTerminal;
use ratatui::crossterm::event::{
    self, DisableBracketedPaste, EnableBracketedPaste, Event, KeyEventKind,
};
use ratatui::crossterm::execute;

use crate::device::{self, Device};
use crate::paths::Paths;
use crate::{audit, client};
use app::{App, Effect, Outcome, Tab};

/// How often the screen asks the daemon for news.
const REFRESH: Duration = Duration::from_millis(500);

/// How many audit log lines the audit tab shows.
const AUDIT_LINES: usize = 200;

/// What the TUI's Touch ID prompt says kv is trying to do.
const DEVICE_REASON: &str = "open kv tui, where you approve agent requests";

/// A Touch ID or Hello prompt waiting for the user. It runs on a thread of
/// its own, so the TUI keeps taking keys meanwhile and quitting does not
/// wait for it.
pub struct DevicePrompt(tokio::sync::oneshot::Receiver<DeviceAnswer>);

/// What came of a `DevicePrompt`, for `Driver::finish_device`.
pub struct DeviceAnswer(Answer);

enum Answer {
    NoDevice,
    Asked(&'static str, Option<Result<DeviceCredential, String>>),
    Lost,
}

impl Future for DevicePrompt {
    type Output = DeviceAnswer;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<DeviceAnswer> {
        Pin::new(&mut self.0)
            .poll(cx)
            .map(|answer| answer.unwrap_or(DeviceAnswer(Answer::Lost)))
    }
}

/// Carries out effects against the daemon and holds the session token.
pub struct Driver {
    paths: Paths,
    token: Option<SecretText>,
    device: Option<Arc<dyn Device>>,
}

impl Driver {
    /// A driver that unlocks with this platform's device when the vault has
    /// it set up.
    pub fn new(paths: Paths) -> Self {
        Self::with_device(paths, device::platform().map(Arc::from))
    }

    pub fn with_device(paths: Paths, device: Option<Arc<dyn Device>>) -> Self {
        Self {
            paths,
            token: None,
            device,
        }
    }

    /// The device to offer: this platform's, if the vault has a slot for it.
    pub fn device(&self) -> Option<DeviceKind> {
        let kind = self.device.as_ref()?.kind();
        device_slots(&self.paths.vault)
            .ok()?
            .iter()
            .any(|slot| slot.kind == kind)
            .then_some(kind)
    }

    pub async fn run(&mut self, effect: Effect) -> Outcome {
        match effect {
            Effect::OpenSession(passphrase) => self.open_session(Some(passphrase), None).await,
            Effect::DeviceUnlock => {
                let answer = self.ask_device().await;
                self.finish_device(answer).await
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
            Effect::Dismiss(id) => self.send(ControlCommand::DismissRequest { id }).await,
            Effect::Lock => {
                self.token = None;
                let request = ControlRequest {
                    passphrase: None,
                    device: None,
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

    /// Shows the device's prompt, if there is a device, and returns at once.
    pub fn ask_device(&self) -> DevicePrompt {
        let (tx, rx) = tokio::sync::oneshot::channel();
        match self.device.clone() {
            None => {
                let _ = tx.send(DeviceAnswer(Answer::NoDevice));
            }
            Some(chosen) => {
                let vault = self.paths.vault.clone();
                // A plain thread, not the runtime's blocking pool, which
                // would hold up quitting until the user answered.
                std::thread::spawn(move || {
                    let label = chosen.kind().label();
                    let asked = device::credential(&vault, chosen.as_ref(), DEVICE_REASON);
                    let _ = tx.send(DeviceAnswer(Answer::Asked(label, asked)));
                });
            }
        }
        DevicePrompt(rx)
    }

    /// Opens a session with what the prompt returned.
    pub async fn finish_device(&mut self, answer: DeviceAnswer) -> Outcome {
        match answer.0 {
            Answer::NoDevice => Outcome::Failed("there is no biometric unlock here".into()),
            Answer::Lost => {
                Outcome::Failed("the biometric prompt stopped; type the passphrase".into())
            }
            Answer::Asked(_, Some(Ok(credential))) => {
                self.open_session(None, Some(credential)).await
            }
            Answer::Asked(label, Some(Err(why))) => {
                Outcome::Failed(format!("{label}: {why}; type the passphrase"))
            }
            Answer::Asked(label, None) => Outcome::Failed(format!(
                "{label} unlock is not on for this vault: run `kv biometric enable`"
            )),
        }
    }

    async fn open_session(
        &mut self,
        passphrase: Option<SecretText>,
        device: Option<DeviceCredential>,
    ) -> Outcome {
        let request = ControlRequest {
            passphrase,
            device,
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
            device: None,
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
    app.set_device(driver.device());
    // With Touch ID or Hello set up, ask right away; Ctrl-T asks again.
    let mut prompt = app.ask_device().map(|_| driver.ask_device());
    let mut tick = tokio::time::interval(REFRESH);
    loop {
        terminal.draw(|frame| view::draw(frame, &app))?;
        tokio::select! {
            answer = async { prompt.as_mut().expect("guarded").await }, if prompt.is_some() => {
                prompt = None;
                // The passphrase may have unlocked it in the meantime.
                if app.screen() == app::Screen::Unlock {
                    app.apply(driver.finish_device(answer).await);
                    refresh(&mut app, &mut driver).await;
                }
            }
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
                if effect == Effect::DeviceUnlock {
                    prompt.get_or_insert_with(|| driver.ask_device());
                    continue;
                }
                let outcome = driver.run(effect).await;
                app.apply(outcome);
                refresh(&mut app, &mut driver).await;
            }
            _ = tick.tick() => refresh(&mut app, &mut driver).await,
        }
    }
}
