//! What the daemon tells the user about things waiting on them, besides
//! the approval notices themselves: an agent refused because the vault is
//! locked, a request still waiting halfway through its time, requests that
//! timed out unanswered, a requested handle and a received share.
//!
//! Each notice goes one of two ways. While a client that posts notices
//! under kv's own name (`kv tray` on macOS, through kv.app) keeps asking
//! for them with `notifying_status`, they wait for it in an outbox. Without
//! one, the server posts them as plain notifications. An outbox its client
//! stopped emptying is handed to the server, so nothing is lost and nothing
//! shows twice.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use kv_core::proto::{Notice, NoticeKind};

use crate::notify::Level;

/// How long after its last `notifying_status` a client still counts as
/// the one posting notices. `kv tray` asks every second.
pub const TAKER_FRESH: Duration = Duration::from_secs(5);
/// Notices the outbox keeps; the oldest go first.
pub const MAX_OUTBOX: usize = 32;
/// After the first refused call of a locked period, how long before the
/// next "unlock needed" notice.
pub const LOCKED_EVERY: Duration = Duration::from_secs(10 * 60);
/// How long timeouts gather after the first before one notice tells of
/// them all.
pub const MISSED_GATHER: Duration = Duration::from_secs(10);
/// The shortest time between two notices of missed requests.
pub const MISSED_EVERY: Duration = Duration::from_secs(5 * 60);
/// Missed requests named in a notice; the rest are counted.
const MISSED_NAMED: usize = 8;

/// A notice for the server to post itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Plain {
    pub kind: NoticeKind,
    pub title: String,
    pub body: String,
}

impl Plain {
    /// Whether it tells of something waiting on the user now, which gets
    /// the louder sound.
    pub fn waiting(&self) -> bool {
        matches!(
            self.kind,
            NoticeKind::UnlockNeeded | NoticeKind::Reminder { .. }
        )
    }
}

/// A notice in the outbox, with the words for either way it may go out.
#[derive(Clone, Debug)]
struct Queued {
    notice: Notice,
    plain_body: String,
}

/// One request that timed out unanswered.
#[derive(Clone, Debug)]
struct Missed {
    client: String,
    handles: Vec<String>,
}

#[derive(Debug)]
pub struct Notices {
    level: Level,
    outbox: VecDeque<Queued>,
    plain: Vec<Plain>,
    /// When a client last asked for the outbox.
    taker_seen: Option<Instant>,
    /// When the last "unlock needed" notice went out in this locked
    /// period, and the refused calls since.
    locked_noticed: Option<Instant>,
    locked_calls: usize,
    /// Timeouts not yet told of, when the first came, and when the last
    /// notice of them went out.
    missed: Vec<Missed>,
    missed_since: Option<Instant>,
    missed_noticed: Option<Instant>,
}

impl Notices {
    pub fn new(level: Level) -> Self {
        Self {
            level,
            outbox: VecDeque::new(),
            plain: Vec::new(),
            taker_seen: None,
            locked_noticed: None,
            locked_calls: 0,
            missed: Vec::new(),
            missed_since: None,
            missed_noticed: None,
        }
    }

    /// Whether a client asked for the outbox within `TAKER_FRESH`.
    pub fn has_taker(&self, now: Instant) -> bool {
        self.taker_seen
            .is_some_and(|seen| now.saturating_duration_since(seen) < TAKER_FRESH)
    }

    /// The outbox, emptied, for the client asking at `now`, which counts as
    /// posting notices from here on.
    pub fn take_outbox(&mut self, now: Instant) -> Vec<Notice> {
        self.taker_seen = Some(now);
        self.outbox.drain(..).map(|queued| queued.notice).collect()
    }

    /// The notices for the server to post now.
    pub fn take_plain(&mut self) -> Vec<Plain> {
        std::mem::take(&mut self.plain)
    }

    /// Queues a notice for the client posting them, or for the server to
    /// post when there is none. `tray_body` is what kv's own notification
    /// says, with a click on it to act; `plain_body` says where to go.
    /// Nothing at all with `KV_NOTIFY=off`.
    pub fn announce(
        &mut self,
        kind: NoticeKind,
        title: &str,
        tray_body: String,
        plain_body: String,
        now: Instant,
    ) {
        if !self.level.approvals() {
            return;
        }
        if self.has_taker(now) {
            if self.outbox.len() == MAX_OUTBOX {
                self.outbox.pop_front();
            }
            self.outbox.push_back(Queued {
                notice: Notice {
                    kind,
                    title: title.to_owned(),
                    body: tray_body,
                },
                plain_body,
            });
        } else {
            self.plain.push(Plain {
                kind,
                title: title.to_owned(),
                body: plain_body,
            });
        }
    }

    /// An agent's call was refused because the vault is locked. The first
    /// in a locked period is announced at once, and later ones at most
    /// every `LOCKED_EVERY`, counted. `client` is already made safe to
    /// show.
    pub fn locked_call(&mut self, client: Option<&str>, tool: &str, now: Instant) {
        if !self.level.approvals() {
            return;
        }
        self.locked_calls += 1;
        if self
            .locked_noticed
            .is_some_and(|last| now.saturating_duration_since(last) < LOCKED_EVERY)
        {
            return;
        }
        let mut body = match client.filter(|c| !c.trim().is_empty()) {
            Some(client) => format!("{client} is waiting ({tool}): unlock kv."),
            None => "An agent is waiting: unlock kv.".to_owned(),
        };
        let calls = std::mem::take(&mut self.locked_calls);
        if calls > 1 {
            body.push_str(&format!(" {calls} calls since the last notice."));
        }
        self.locked_noticed = Some(now);
        let plain = format!("{body} Run `kv unlock`, or unlock it from kv tray.");
        self.announce(
            NoticeKind::UnlockNeeded,
            "kv: unlock needed",
            body,
            plain,
            now,
        );
    }

    /// The vault unlocked: the next refused call starts a new locked
    /// period, announced at once.
    pub fn unlocked(&mut self) {
        self.locked_noticed = None;
        self.locked_calls = 0;
    }

    /// A request timed out with no answer. Told of, with any others, once
    /// `MISSED_GATHER` has passed and at most every `MISSED_EVERY` (see
    /// `tick`).
    pub fn missed(&mut self, client: Option<&str>, handles: &[String], now: Instant) {
        if !self.level.approvals() {
            return;
        }
        if self.missed.is_empty() {
            self.missed_since = Some(now);
        }
        self.missed.push(Missed {
            client: client
                .filter(|c| !c.trim().is_empty())
                .unwrap_or("an agent")
                .to_owned(),
            handles: handles.to_vec(),
        });
    }

    /// Hands what no client took in time to the server, and tells of the
    /// missed requests once they are due.
    pub fn tick(&mut self, now: Instant) {
        if !self.has_taker(now) && !self.outbox.is_empty() {
            for queued in self.outbox.drain(..) {
                self.plain.push(Plain {
                    kind: queued.notice.kind,
                    title: queued.notice.title,
                    body: queued.plain_body,
                });
            }
        }
        let gathered = self
            .missed_since
            .is_some_and(|since| now.saturating_duration_since(since) >= MISSED_GATHER);
        let allowed = self
            .missed_noticed
            .is_none_or(|last| now.saturating_duration_since(last) >= MISSED_EVERY);
        if self.missed.is_empty() || !gathered || !allowed {
            return;
        }
        let missed = std::mem::take(&mut self.missed);
        self.missed_since = None;
        self.missed_noticed = Some(now);
        let said = missed_text(&missed);
        self.announce(
            NoticeKind::Missed,
            "kv: requests timed out",
            format!("{said} Open kv's Audit tab to see them."),
            format!("{said} Open kv tui's Audit tab to see them."),
            now,
        );
    }
}

/// "You missed 3 requests (claude-code: github, prod-db; cursor:
/// openrouter)." Each agent once, with its handles once each, in the order
/// they first came.
fn missed_text(missed: &[Missed]) -> String {
    let count = missed.len();
    let mut by_client: Vec<(&str, Vec<&str>)> = Vec::new();
    for entry in missed.iter().take(MISSED_NAMED) {
        let at = match by_client.iter().position(|(c, _)| *c == entry.client) {
            Some(at) => at,
            None => {
                by_client.push((&entry.client, Vec::new()));
                by_client.len() - 1
            }
        };
        for handle in &entry.handles {
            if !by_client[at].1.contains(&handle.as_str()) {
                by_client[at].1.push(handle);
            }
        }
    }
    let named = by_client
        .iter()
        .map(|(client, handles)| format!("{client}: {}", handles.join(", ")))
        .collect::<Vec<_>>()
        .join("; ");
    let named = super::printable(&named, 120);
    let requests = if count == 1 { "request" } else { "requests" };
    format!("You missed {count} {requests} ({named}).")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(t0: Instant, secs: u64) -> Instant {
        t0 + Duration::from_secs(secs)
    }

    fn bodies(plain: &[Plain]) -> Vec<&str> {
        plain.iter().map(|p| p.body.as_str()).collect()
    }

    #[test]
    fn the_first_locked_call_is_told_at_once_then_at_most_every_ten_minutes() {
        let t0 = Instant::now();
        let mut n = Notices::new(Level::Ask);
        n.locked_call(Some("claude-code"), "http_request", t0);
        let first = n.take_plain();
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].title, "kv: unlock needed");
        assert!(
            first[0]
                .body
                .starts_with("claude-code is waiting (http_request): unlock kv."),
            "{}",
            first[0].body
        );
        assert!(first[0].waiting());
        for secs in [1, 60, 599] {
            n.locked_call(Some("cursor"), "exec", at(t0, secs));
        }
        assert!(n.take_plain().is_empty());
        n.locked_call(None, "exec", at(t0, 600));
        let again = n.take_plain();
        assert_eq!(
            again[0].body,
            "An agent is waiting: unlock kv. 4 calls since the last notice. \
             Run `kv unlock`, or unlock it from kv tray."
        );
    }

    #[test]
    fn an_unlock_starts_a_new_locked_period() {
        let t0 = Instant::now();
        let mut n = Notices::new(Level::Ask);
        n.locked_call(None, "exec", t0);
        n.unlocked();
        n.locked_call(None, "exec", at(t0, 5));
        let plain = n.take_plain();
        assert_eq!(plain.len(), 2);
        assert!(!plain[1].body.contains("calls since"), "{}", plain[1].body);
    }

    #[test]
    fn nothing_at_all_with_notifications_off() {
        let t0 = Instant::now();
        let mut n = Notices::new(Level::Off);
        n.locked_call(None, "exec", t0);
        n.missed(None, &["api".into()], t0);
        n.announce(NoticeKind::ShareReceived, "t", "a".into(), "b".into(), t0);
        n.tick(at(t0, 3600));
        assert!(n.take_plain().is_empty());
        assert!(n.take_outbox(t0).is_empty());
    }

    #[test]
    fn a_fresh_taker_gets_the_notice_and_the_server_posts_nothing() {
        let t0 = Instant::now();
        let mut n = Notices::new(Level::Ask);
        assert!(n.take_outbox(t0).is_empty());
        n.locked_call(Some("claude-code"), "exec", at(t0, 1));
        assert!(n.take_plain().is_empty());
        let taken = n.take_outbox(at(t0, 2));
        assert_eq!(taken.len(), 1);
        assert_eq!(taken[0].kind, NoticeKind::UnlockNeeded);
        // kv's own notice offers Unlock; it does not say how by hand.
        assert_eq!(taken[0].body, "claude-code is waiting (exec): unlock kv.");
        n.tick(at(t0, 3));
        assert!(n.take_plain().is_empty());
    }

    #[test]
    fn an_outbox_no_one_empties_goes_to_the_server_after_five_seconds() {
        let t0 = Instant::now();
        let mut n = Notices::new(Level::Ask);
        n.take_outbox(t0);
        n.announce(
            NoticeKind::HandleRequested,
            "kv: handle requested",
            "tray".into(),
            "plain".into(),
            at(t0, 1),
        );
        n.tick(at(t0, 4));
        assert!(n.take_plain().is_empty(), "the taker is still fresh");
        n.tick(at(t0, 5));
        assert_eq!(bodies(&n.take_plain()), ["plain"]);
        assert!(n.take_outbox(at(t0, 6)).is_empty(), "nothing shows twice");
        // A stale taker: new notices go straight to the server.
        n.announce(
            NoticeKind::ShareReceived,
            "t",
            "tray".into(),
            "plain".into(),
            at(t0, 20),
        );
        assert_eq!(bodies(&n.take_plain()), ["plain"]);
    }

    #[test]
    fn the_outbox_keeps_the_newest() {
        let t0 = Instant::now();
        let mut n = Notices::new(Level::Ask);
        n.take_outbox(t0);
        for i in 0..MAX_OUTBOX + 5 {
            n.announce(
                NoticeKind::HandleRequested,
                "t",
                i.to_string(),
                String::new(),
                t0,
            );
        }
        let taken = n.take_outbox(t0);
        assert_eq!(taken.len(), MAX_OUTBOX);
        assert_eq!(taken[0].body, "5");
    }

    #[test]
    fn missed_requests_gather_for_ten_seconds_into_one_notice() {
        let t0 = Instant::now();
        let mut n = Notices::new(Level::Ask);
        n.missed(Some("claude-code"), &["github".into()], t0);
        n.missed(Some("claude-code"), &["prod-db".into()], at(t0, 3));
        n.missed(Some("cursor"), &["openrouter".into()], at(t0, 6));
        n.missed(Some("claude-code"), &["github".into()], at(t0, 8));
        n.tick(at(t0, 9));
        assert!(n.take_plain().is_empty());
        n.tick(at(t0, 10));
        let plain = n.take_plain();
        assert_eq!(plain.len(), 1);
        assert_eq!(plain[0].title, "kv: requests timed out");
        assert_eq!(
            plain[0].body,
            "You missed 4 requests (claude-code: github, prod-db; cursor: openrouter). \
             Open kv tui's Audit tab to see them."
        );
        assert!(!plain[0].waiting());
    }

    #[test]
    fn missed_notices_come_at_most_every_five_minutes_and_lose_nothing() {
        let t0 = Instant::now();
        let mut n = Notices::new(Level::Ask);
        n.missed(None, &["a".into()], t0);
        n.tick(at(t0, 10));
        assert_eq!(n.take_plain().len(), 1);
        n.missed(None, &["b".into()], at(t0, 20));
        n.missed(None, &["c".into()], at(t0, 200));
        n.tick(at(t0, 309));
        assert!(n.take_plain().is_empty());
        n.tick(at(t0, 310));
        let plain = n.take_plain();
        assert_eq!(plain.len(), 1);
        assert!(
            plain[0]
                .body
                .starts_with("You missed 2 requests (an agent: b, c)."),
            "{}",
            plain[0].body
        );
    }

    #[test]
    fn a_tray_hears_of_missed_requests_with_its_own_words() {
        let t0 = Instant::now();
        let mut n = Notices::new(Level::Ask);
        n.take_outbox(t0);
        n.missed(Some("claude-code"), &["github".into()], t0);
        n.take_outbox(at(t0, 8));
        n.tick(at(t0, 10));
        let taken = n.take_outbox(at(t0, 10));
        assert_eq!(taken.len(), 1);
        assert_eq!(taken[0].kind, NoticeKind::Missed);
        assert_eq!(
            taken[0].body,
            "You missed 1 request (claude-code: github). Open kv's Audit tab to see them."
        );
    }
}
