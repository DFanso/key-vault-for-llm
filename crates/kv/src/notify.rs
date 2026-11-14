//! Desktop notifications, so the user learns that something is waiting for
//! them in `kv tui` even when it is not open, and, when they ask for it,
//! that an agent used one of their handles.

use std::collections::VecDeque;
use std::fmt;
use std::str::FromStr;
use std::time::{Duration, Instant};

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
            "default" | "on" | "true" | "1" | "yes" | "y" => Ok(Sound::Default),
            "off" | "none" | "false" | "0" | "no" => Ok(Sound::Off),
            _ => Err(ParseError("alarm, default or off")),
        }
    }
}

/// Where the notification sound is set.
pub const SOUND_ENV: &str = "KV_NOTIFY_SOUND";

/// `value` as a `T`, or `T`'s default when it is not understood, so that a
/// typo in `KV_NOTIFY` or `KV_NOTIFY_SOUND` cannot stop the daemon from
/// starting: one started on demand has nowhere to say why. Says so on
/// standard error, which `kv daemon` run by hand shows.
pub fn or_default<T>(name: &str, value: &str) -> T
where
    T: FromStr<Err = ParseError> + Default + fmt::Debug,
{
    value.parse().unwrap_or_else(|e: ParseError| {
        let fallback = T::default();
        eprintln!("kv: {name}={value:?} is not understood ({e}); using {fallback:?}");
        fallback
    })
}

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

/// Notices of one kind shown in one minute at most. Past it they are held
/// back and counted, so an agent that names a new session on every call, or
/// hangs up and asks again, cannot flood the screen.
pub const MAX_NOTICES_PER_MINUTE: usize = 10;
const MINUTE: Duration = Duration::from_secs(60);

/// Lets `MAX_NOTICES_PER_MINUTE` notices through a minute and counts the
/// rest.
#[derive(Debug, Default)]
pub struct RateCap {
    /// When the current minute began.
    window: Option<Instant>,
    /// Notices shown in it.
    shown: usize,
    /// Notices held back since the last one shown.
    held: usize,
}

impl RateCap {
    /// Whether a notice may show at `now`: `Some` with how many were held
    /// back since the last one shown, or `None` when this minute's are used
    /// up (and this one is counted as held).
    pub fn admit(&mut self, now: Instant) -> Option<usize> {
        if self
            .window
            .is_none_or(|start| now.saturating_duration_since(start) >= MINUTE)
        {
            self.window = Some(now);
            self.shown = 0;
        }
        if self.shown == MAX_NOTICES_PER_MINUTE {
            self.held += 1;
            return None;
        }
        self.shown += 1;
        Some(std::mem::take(&mut self.held))
    }
}

/// What `KV_NOTIFY=all` announces: each handle once per agent session, and
/// no more than `MAX_NOTICES_PER_MINUTE` notices a minute.
#[derive(Debug, Default)]
pub struct UseNotices {
    first: FirstUses,
    rate: RateCap,
}

impl UseNotices {
    /// The notice for `handles` used through `tool` by `session`, if one
    /// is due: none when every handle was announced for the session before,
    /// or when this minute's notices are used up.
    pub fn notice(
        &mut self,
        session: Option<&SessionInfo>,
        handles: &[String],
        tool: &str,
        now: Instant,
    ) -> Option<String> {
        let new = self.first.first(session, handles);
        if new.is_empty() {
            return None;
        }
        let held = self.rate.admit(now)?;
        let mut text = use_notice(session.map(|s| s.client.as_str()), &new, tool);
        if held > 0 {
            text.push_str(&format!(
                " {held} more not shown; kv's Audit tab lists every use."
            ));
        }
        Some(text)
    }
}

/// One line saying `client` used `handles` through `tool`. The client name
/// is whatever the agent said, so it goes through the same cleaning as the
/// approval notice: one line, no bidi or zero-width characters, at most 64
/// characters. Never holds a value.
pub fn use_notice(client: Option<&str>, handles: &[String], tool: &str) -> String {
    let client = client
        .map(|c| crate::daemon::printable(c, 64))
        .filter(|c| !c.trim().is_empty())
        .unwrap_or_else(|| "An agent".into());
    format!(
        "{client} used {} ({tool}).",
        crate::daemon::printable(&handles.join(", "), 120)
    )
}

pub fn approval_needed(text: String, sound: Sound) {
    show("kv: approval needed", text, sound.tone(true), true);
}

/// The approval notice to show for `notice`, if this minute allows one,
/// with how many were held back before it. Requests held back still wait in
/// kv's window and `kv tui`.
pub fn approval_notice(rate: &mut RateCap, notice: &str, now: Instant) -> Option<String> {
    let held = rate.admit(now)?;
    Some(if held > 0 {
        format!("{notice} {held} more requests asked meanwhile; open kv to see them.")
    } else {
        notice.to_owned()
    })
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
/// service never holds up the daemon. Failures are ignored. On Windows,
/// `waiting` keeps a request waiting for the user on screen until it is
/// dismissed (a reminder toast). Elsewhere it is left alone: some Linux
/// notification daemons would keep a critical one after the request timed
/// out.
fn show(summary: &'static str, text: String, tone: Option<Tone>, waiting: bool) {
    std::thread::spawn(move || {
        let mut notification = notify_rust::Notification::new();
        notification.summary(summary).body(&text);
        if let Some(tone) = tone {
            notification.sound_name(sound_name(tone));
        }
        #[cfg(windows)]
        if waiting {
            notification.urgency(notify_rust::Urgency::Critical);
        }
        #[cfg(not(windows))]
        let _ = waiting;
        let _ = notification.show();
    });
}

/// Something `kv tray` could not do, since its menu cannot say so.
pub fn tray(text: String) {
    show("kv tray", text, Sound::from_env().tone(false), false);
}
