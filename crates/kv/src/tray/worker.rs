//! The tray's daemon side, on a tokio runtime of its own: reads the
//! daemon's status every second, holds the session, and carries out what
//! the menu asks for. Failures become notifications, since a menu cannot
//! show a message.

use std::io;
use std::sync::Arc;
use std::time::Duration;

use kv_core::proto::{AgentRequest, AgentResponse};
use tokio::sync::mpsc::UnboundedReceiver;

use super::model::{Action, Model, View};
use crate::client;
use crate::device::Device;
use crate::paths::Paths;
use crate::tui::app::{Effect, Outcome};
use crate::tui::{DeviceAnswer, Driver};

/// How often the tray asks the daemon for news.
const TICK: Duration = Duration::from_secs(1);

/// What a Touch ID prompt from the tray says kv is trying to do.
const REASON: &str = "open kv tray, where you approve agent requests";

/// What the worker needs from the desktop around it.
pub trait Desktop: Send {
    fn notify(&self, text: &str);
    /// Opens a terminal running `kv tui`.
    fn open_tui(&self) -> io::Result<()>;
    fn login_is_on(&self) -> bool;
    fn set_login(&self, on: bool) -> io::Result<()>;
}

pub struct Worker<D> {
    paths: Paths,
    driver: Driver,
    desktop: D,
}

impl<D: Desktop> Worker<D> {
    pub fn new(paths: Paths, device: Option<Arc<dyn Device>>, desktop: D) -> Self {
        Self {
            driver: Driver::with_device(paths.clone(), device).with_reason(REASON),
            paths,
            desktop,
        }
    }

    /// What the tray should show now. Reading the status never starts the
    /// daemon; a session the daemon no longer knows is dropped.
    pub async fn model(&mut self) -> Model {
        let status = match client::agent_if_running(&self.paths, &AgentRequest::Status).await {
            Ok(Some(AgentResponse::Status { status })) => Some(status),
            _ => None,
        };
        let overview = match self.driver.refresh().await {
            Some(Outcome::Overview(overview)) => Some(overview),
            _ => None,
        };
        Model::new(View {
            status: status.as_ref(),
            overview: overview.as_ref(),
            device: self.driver.device(),
            login: self.desktop.login_is_on(),
        })
    }

    /// Carries out one click. Returns true for Quit.
    pub async fn act(&mut self, action: Action) -> bool {
        match action {
            Action::Unlock => {
                let answer = self.driver.ask_device().await;
                self.unlock(answer).await;
            }
            Action::Decide { id, verdict } => {
                let outcome = self.driver.run(Effect::Decide { id, verdict }).await;
                self.report(outcome);
            }
            Action::Lock => {
                let outcome = self.driver.run(Effect::Lock).await;
                self.report(outcome);
            }
            Action::Open(_) => {
                if let Err(e) = self.desktop.open_tui() {
                    self.desktop.notify(&format!("Could not open kv tui: {e}"));
                }
            }
            Action::Login(on) => {
                if let Err(e) = self.desktop.set_login(on) {
                    self.desktop
                        .notify(&format!("Could not change the login item: {e}"));
                }
            }
            Action::Quit => return true,
        }
        false
    }

    /// Shows a model every tick and after every click until Quit, or until
    /// the UI drops its sender. A Touch ID prompt runs beside the loop, so
    /// the icon stays current while the user decides.
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
                    self.unlock(answer).await;
                }
                action = actions.recv() => match action {
                    None | Some(Action::Quit) => return,
                    Some(Action::Unlock) => {
                        prompt.get_or_insert_with(|| self.driver.ask_device());
                        continue;
                    }
                    Some(action) => {
                        self.act(action).await;
                    }
                },
                _ = tick.tick() => {}
            }
            show(self.model().await);
        }
    }

    async fn unlock(&mut self, answer: DeviceAnswer) {
        let outcome = self.driver.finish_device(answer).await;
        self.report(outcome);
    }

    fn report(&self, outcome: Outcome) {
        if let Outcome::Failed(message) | Outcome::Ended(message) = outcome {
            self.desktop.notify(&sentence(&message));
        }
    }
}

/// The daemon's messages start in lower case, to follow other text; a
/// notification shows one on its own.
fn sentence(message: &str) -> String {
    let mut chars = message.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}
