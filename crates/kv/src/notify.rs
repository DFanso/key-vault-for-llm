//! Desktop notifications, so the user learns that something is waiting for
//! them in `kv tui` even when it is not open, and, when they ask for it,
//! that an agent used one of their handles.

use std::collections::VecDeque;
use std::fmt;
use std::str::FromStr;

use kv_core::proto::SessionInfo;

/// What the daemon announces: `KV_NOTIFY`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Level {
    /// Nothing.
    Off,
    /// Requests waiting for approval, requested handles and received
    /// shares.
    #[default]
    Ask,
    /// Also each handle an agent uses without waiting for approval (mode
    /// auto, or allowed for the session), once per agent session.
    All,
}

impl Level {
    /// Whether requests waiting for the user are announced.
    pub fn approvals(self) -> bool {
        self != Level::Off
    }

    /// Whether uses that did not wait for the user are announced.
    pub fn uses(self) -> bool {
        self == Level::All
    }
}

impl FromStr for Level {
    type Err = ParseError;

    /// `ask`, `all` or `off`. `on` and `off` and the other boolean words
    /// are kept from when this was a switch.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "ask" | "on" | "true" | "1" | "yes" | "y" => Ok(Level::Ask),
            "all" => Ok(Level::All),
            "off" | "false" | "0" | "no" | "n" => Ok(Level::Off),
            _ => Err(ParseError("ask, all or off")),
        }
    }
}

/// The sound notifications play: `KV_NOTIFY_SOUND`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Sound {
    /// None.
    Off,
    /// The platform's usual notification sound for everything.
    Default,
    /// A louder one for requests waiting for approval, the usual one for
    /// the rest.
    #[default]
    Alarm,
}

impl Sound {
    /// The tone a notification plays, if any. `waiting` is true for a
    /// request waiting for the user.
    pub fn tone(self, waiting: bool) -> Option<Tone> {
        match self {
            Sound::Off => None,
            Sound::Alarm if waiting => Some(Tone::Alarm),
            Sound::Default | Sound::Alarm => Some(Tone::Default),
        }
    }

    /// `KV_NOTIFY_SOUND` as this process sees it; unset or not understood
    /// is the default.
    pub fn from_env() -> Self {
        std::env::var(SOUND_ENV)
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or_default()
    }
}

impl FromStr for Sound {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "alarm" => Ok(Sound::Alarm),
            "default" | "on" => Ok(Sound::Default),
            "off" | "none" | "false" | "0" | "no" => Ok(Sound::Off),
            _ => Err(ParseError("alarm, default or off")),
        }
    }
}

/// Where the notification sound is set.
pub const SOUND_ENV: &str = "KV_NOTIFY_SOUND";

/// A value `Level` or `Sound` cannot read; says what it takes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParseError(&'static str);

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "expected {}", self.0)
    }
}

impl std::error::Error for ParseError {}

/// The two sounds a notification can play.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tone {
    Default,
    Alarm,
}

/// The platform's name for `tone`. A name has to be given: without one a
/// Windows toast is silent.
pub fn sound_name(tone: Tone) -> &'static str {
    #[cfg(windows)]
    {
        match tone {
            Tone::Default => "Default",
            Tone::Alarm => "Reminder",
        }
    }
    #[cfg(target_os = "macos")]
    {
        match tone {
            Tone::Default => "Default",
            Tone::Alarm => "Sosumi",
        }
    }
    // Names from the freedesktop.org sound naming specification.
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        match tone {
            Tone::Default => "message-new-instant",
            Tone::Alarm => "alarm-clock-elapsed",
        }
    }
}

/// Handles already announced as used, per agent session, so that `all`
/// says each once rather than on every call.
#[derive(Debug, Default)]
pub struct FirstUses {
    /// Session id and handle, oldest first.
    seen: VecDeque<(String, String)>,
}

/// Pairs `FirstUses` keeps; the oldest are forgotten beyond this, so an
/// agent cannot grow the daemon's memory by naming new sessions.
pub const MAX_FIRST_USES: usize = 512;

impl FirstUses {
    /// The handles in `handles` not yet announced for `session`, each
    /// once, now counted as announced. Agents that name no session share
    /// one.
    pub fn first(&mut self, session: Option<&SessionInfo>, handles: &[String]) -> Vec<String> {
        let id = session.map(|s| s.id.as_str()).unwrap_or_default();
        let mut new = Vec::new();
        for handle in handles {
            let known = new.contains(handle)
                || self
                    .seen
                    .iter()
                    .any(|(seen_id, seen)| seen_id == id && seen == handle);
            if known {
                continue;
            }
            if self.seen.len() == MAX_FIRST_USES {
                self.seen.pop_front();
            }
            self.seen.push_back((id.to_owned(), handle.clone()));
            new.push(handle.clone());
        }
        new
    }

    pub fn len(&self) -> usize {
        self.seen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

pub fn approval_needed(text: String, sound: Sound) {
    show("kv: approval needed", text, sound.tone(true), true);
}

pub fn handle_requested(text: String, sound: Sound) {
    show("kv: handle requested", text, sound.tone(false), false);
}

pub fn share_received(text: String, sound: Sound) {
    show("kv: shared secret received", text, sound.tone(false), false);
}

/// An agent used a handle without waiting for the user (`KV_NOTIFY=all`).
pub fn handle_used(text: String, sound: Sound) {
    show("kv: handle used", text, sound.tone(false), false);
}

/// Shows `text` from a thread of its own, so a slow or missing notification
/// service never holds up the daemon. Failures are ignored. `waiting` keeps
/// a request waiting for the user on screen where the platform allows it.
fn show(summary: &'static str, text: String, tone: Option<Tone>, waiting: bool) {
    std::thread::spawn(move || {
        let mut notification = notify_rust::Notification::new();
        notification.summary(summary).body(&text);
        if let Some(tone) = tone {
            notification.sound_name(sound_name(tone));
        }
        #[cfg(not(target_os = "macos"))]
        if waiting {
            notification.urgency(notify_rust::Urgency::Critical);
        }
        #[cfg(target_os = "macos")]
        let _ = waiting;
        let _ = notification.show();
    });
}

/// Something `kv tray` could not do, since its menu cannot say so.
pub fn tray(text: String) {
    show("kv tray", text, Sound::from_env().tone(false), false);
}
