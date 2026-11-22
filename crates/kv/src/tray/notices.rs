//! Waiting requests as notifications the user can answer where they are,
//! with the same answers as the tray menu, free of the platform. The tray
//! posts one per request while it holds a session, and takes it down once
//! the request is answered anywhere, times out or the vault locks.
//!
//! On macOS a helper process posts them (see `ui::notices`), and this is
//! also what the tray and the helper say to each other: one JSON message a
//! line, over the helper's standard input and output. No secret is in it.

use std::io::BufRead;
use std::sync::atomic::{AtomicBool, Ordering};

use kv_core::crypto::fill_random;
use kv_core::proto::{self, Approval, NoticeKind, Verdict};
use serde::{Deserialize, Serialize};

use super::model::flat;
use super::window::Tab;

/// How long a notification's title may be.
const TITLE_LEN: usize = 80;
/// How long its body may be. Notification Center cuts it short anyway.
const BODY_LEN: usize = 240;

/// The answers a notification offers, in order: the id the platform hands
/// back when one is picked, the button's label, and the verdict. Allow for
/// this session is left out where it could grant nothing.
pub const ANSWERS: [(&str, &str, Verdict); 3] = [
    ("allow_once", "Allow once", Verdict::AllowOnce),
    (
        "allow_session",
        "Allow for this session",
        Verdict::AllowSession,
    ),
    ("deny", "Deny", Verdict::Deny),
];

/// One waiting request's notification.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Notice {
    /// Names the notification, to take it down and to tell which one the
    /// user answered: `kv-request-<id>-<nonce>`. The nonce is new for each
    /// notification, so one left over from before the daemon restarted,
    /// when request ids start again, never answers a different request.
    pub key: String,
    pub title: String,
    pub subtitle: String,
    pub body: String,
    /// Whether it offers Allow for this session: the request named its
    /// agent session.
    pub can_grant: bool,
    /// Whether it offers answers at all. One that only tells the user
    /// something (a new kv is out) has none; a click on it still comes
    /// back.
    #[serde(default = "with_answers")]
    pub answers: bool,
    /// The one button a notice without answers offers, if any. It does
    /// what a click on the notice does.
    #[serde(default)]
    pub button: Option<Button>,
}

/// The button of a notice that is not a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Button {
    /// "Unlock": Touch ID where it is set up, else kv's window asks for
    /// the passphrase.
    Unlock,
    /// "Open kv", on the tab the notice is about.
    Open,
}

impl Button {
    /// The id the platform hands back when it is picked, and its label.
    pub const ALL: [(Button, &'static str, &'static str); 2] = [
        (Button::Unlock, "unlock", "Unlock"),
        (Button::Open, "open", "Open kv"),
    ];

    pub fn id(self) -> &'static str {
        Self::ALL
            .iter()
            .find(|(button, ..)| *button == self)
            .map(|(_, id, _)| *id)
            .expect("every button is listed")
    }
}

/// Whether `answer`, an id the platform handed back, is one of the
/// buttons of a notice that is not a request.
pub fn is_button(answer: &str) -> bool {
    Button::ALL.iter().any(|(_, id, _)| *id == answer)
}

/// What a click on a notice that is not a request does, by its key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Click {
    Unlock,
    Open(Tab),
}

/// How the key of an "unlock needed" notice starts.
pub const UNLOCK_PREFIX: &str = "kv-unlock-";
/// How the key of a notice that opens kv's window on a tab starts; the
/// tab's name follows.
const OPEN_PREFIX: &str = "kv-open-";

/// What a click on the notice `key` does, if it is one of the daemon's
/// notices rather than a request or an update.
pub fn click(key: &str) -> Option<Click> {
    if key.starts_with(UNLOCK_PREFIX) {
        return Some(Click::Unlock);
    }
    let rest = key.strip_prefix(OPEN_PREFIX)?;
    let tab = rest.split('-').next()?;
    TABS.iter()
        .find(|(_, name)| *name == tab)
        .map(|(tab, _)| Click::Open(*tab))
}

const TABS: [(Tab, &str); 5] = [
    (Tab::Home, "home"),
    (Tab::Approvals, "approvals"),
    (Tab::Handles, "handles"),
    (Tab::Shares, "shares"),
    (Tab::Audit, "audit"),
];

fn nonce() -> String {
    let mut nonce = [0u8; 8];
    fill_random(&mut nonce);
    hex::encode(nonce)
}

fn with_answers() -> bool {
    true
}

impl Notice {
    /// The notification for `approval`, under a fresh key.
    pub fn new(approval: &Approval) -> Notice {
        Notice::with_key(approval, format!("kv-request-{}-{}", approval.id, nonce()))
    }

    /// The notification for `approval` again, under a fresh key, saying
    /// it is a reminder and how long is left.
    pub fn reminder(approval: &Approval) -> Notice {
        let mut notice = Notice::new(approval);
        notice.subtitle = format!(
            "Reminder: about {} s left · {}",
            approval.expires_in_secs, notice.subtitle
        );
        notice
    }

    /// One of the daemon's notices, under a fresh key that says what a
    /// click does: unlock kv, or open its window where the notice points.
    /// A reminder whose request this tray shows no notification for (it
    /// has no session) opens the Approvals tab.
    pub fn from_daemon(notice: &proto::Notice) -> Notice {
        let (key, button) = match notice.kind {
            NoticeKind::UnlockNeeded => (format!("{UNLOCK_PREFIX}{}", nonce()), Button::Unlock),
            other => {
                let tab = match other {
                    NoticeKind::Missed => "audit",
                    NoticeKind::HandleRequested => "handles",
                    NoticeKind::ShareReceived => "shares",
                    NoticeKind::Reminder { .. } | NoticeKind::UnlockNeeded => "approvals",
                };
                (format!("{OPEN_PREFIX}{tab}-{}", nonce()), Button::Open)
            }
        };
        Notice {
            key,
            title: flat(notice.title.trim_start_matches("kv: "), TITLE_LEN),
            subtitle: String::new(),
            body: flat(&notice.body, BODY_LEN),
            can_grant: false,
            answers: false,
            button: Some(button),
        }
    }

    pub fn with_key(approval: &Approval, key: String) -> Notice {
        let client = approval.client.as_deref().unwrap_or("An agent");
        let handles = approval.handles.join(", ");
        let mut body = flat(&approval.detail, BODY_LEN);
        if let Some(cwd) = &approval.cwd {
            body.push('\n');
            body.push_str(&flat(&format!("in {cwd}"), BODY_LEN));
        }
        if let Some(headers) = &approval.headers {
            body.push('\n');
            body.push_str(&flat(&format!("headers {headers}"), BODY_LEN));
        }
        if let Some(sent) = &approval.body {
            body.push('\n');
            body.push_str(&flat(&format!("body {sent}"), BODY_LEN));
        }
        Notice {
            key,
            title: flat(&format!("{client} wants {handles}"), TITLE_LEN),
            subtitle: tool_words(&approval.tool).to_owned(),
            body,
            can_grant: approval.can_grant,
            answers: true,
            button: None,
        }
    }

    /// The notification that kv `version` is out, under the key
    /// `update-<version>`. It has no answers: a click on it opens the
    /// confirmation in kv's window.
    pub fn update(version: &semver::Version) -> Notice {
        Notice {
            key: format!("{UPDATE_PREFIX}{version}"),
            title: format!("kv {version} is out"),
            subtitle: String::new(),
            body: UPDATE_BODY.to_owned(),
            can_grant: false,
            answers: false,
            button: None,
        }
    }
}

/// How the key of an update's notification starts.
pub const UPDATE_PREFIX: &str = "update-";
/// What an update's notification says, after its title.
pub const UPDATE_BODY: &str = "Open kv's menu to update.";

/// What the tray tells the notification helper.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ToHelper {
    Post(Notice),
    Withdraw { keys: Vec<String> },
}

/// What the notification helper tells the tray.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum FromHelper {
    /// Whether the user lets kv post notifications, sent at the start and
    /// whenever it changes.
    Allowed { on: bool },
    /// The user picked `verdict` on the notification `key`, or clicked the
    /// notification itself (`None`).
    Answer {
        key: String,
        verdict: Option<Verdict>,
    },
}

/// Reads what the helper says until it stops, keeping `allowed` up to date
/// and handing each answer to `answer`. A line that is not a message is
/// skipped; once the helper is gone nothing can be posted, so `allowed`
/// ends false.
pub fn read_helper(
    reader: impl BufRead,
    allowed: &AtomicBool,
    mut answer: impl FnMut(String, Option<Verdict>),
) {
    for line in reader.lines() {
        let Ok(line) = line else { break };
        match serde_json::from_str(&line) {
            Ok(FromHelper::Allowed { on }) => allowed.store(on, Ordering::Relaxed),
            Ok(FromHelper::Answer { key, verdict }) => answer(key, verdict),
            Err(_) => {}
        }
    }
    allowed.store(false, Ordering::Relaxed);
}

/// The verdict behind the answer the platform handed back, by its id.
pub fn verdict(answer: &str) -> Option<Verdict> {
    ANSWERS
        .iter()
        .find(|(id, ..)| *id == answer)
        .map(|(.., verdict)| *verdict)
}

/// What a tool does, in words, as the window's request cards say it.
fn tool_words(tool: &str) -> &str {
    match tool {
        "http_request" => "HTTP request",
        "exec" => "Run a command",
        "run" => "Run a program",
        "db_query" => "Database query",
        "db_connect" => "Database lease",
        "send_share" => "Send a share",
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn approval() -> Approval {
        Approval {
            id: 7,
            client: Some("claude-code".into()),
            tool: "exec".into(),
            handles: vec!["aws".into(), "gh & co".into()],
            detail: "[\"terraform\",\n\"plan\"]".into(),
            cwd: Some("/work/infra".into()),
            env_vars: vec!["AWS_ACCESS_KEY_ID".into()],
            headers: None,
            body: None,
            can_grant: false,
            expires_in_secs: 60,
        }
    }

    #[test]
    fn a_notice_says_who_wants_what_on_plain_lines() {
        let notice = Notice::with_key(&approval(), "kv-request-7-00".into());
        assert_eq!(notice.title, "claude-code wants aws, gh & co");
        assert_eq!(notice.subtitle, "Run a command");
        assert_eq!(notice.body, "[\"terraform\", \"plan\"]\nin /work/infra");
        assert!(!notice.can_grant);
    }

    #[test]
    fn a_notice_shows_what_a_request_sends() {
        let approval = Approval {
            tool: "http_request".into(),
            detail: "POST https://api.example.com/items".into(),
            cwd: None,
            env_vars: Vec::new(),
            headers: Some("Content-Type, X-Title".into()),
            body: Some("15 bytes: {\"model\": \"x\"}".into()),
            ..approval()
        };
        let notice = Notice::with_key(&approval, "kv-request-7-00".into());
        assert_eq!(
            notice.body,
            "POST https://api.example.com/items\nheaders Content-Type, X-Title\nbody 15 bytes: {\"model\": \"x\"}"
        );
    }

    #[test]
    fn each_notice_gets_a_key_of_its_own() {
        let a = Notice::new(&approval());
        let b = Notice::new(&approval());
        assert!(a.key.starts_with("kv-request-7-"), "{}", a.key);
        assert_ne!(a.key, b.key);
    }

    #[test]
    fn the_helpers_messages_are_read_until_it_stops() {
        let said = [
            r#"{"type":"allowed","on":true}"#,
            r#"{"type":"answer","key":"kv-request-7-00","verdict":"allow_once"}"#,
            "not a message",
            r#"{"type":"answer","key":"kv-request-8-00","verdict":null}"#,
        ]
        .join("\n");
        let allowed = AtomicBool::new(false);
        let mut answers = Vec::new();
        read_helper(said.as_bytes(), &allowed, |key, verdict| {
            answers.push((key, verdict));
        });
        assert_eq!(
            answers,
            [
                ("kv-request-7-00".to_owned(), Some(Verdict::AllowOnce)),
                ("kv-request-8-00".to_owned(), None),
            ]
        );
        // The helper is gone: nothing can be posted any more.
        assert!(!allowed.load(Ordering::Relaxed));
    }

    #[test]
    fn what_the_tray_sends_reads_back_the_same() {
        let post = ToHelper::Post(Notice::with_key(&approval(), "kv-request-7-00".into()));
        let withdraw = ToHelper::Withdraw {
            keys: vec!["kv-request-7-00".into()],
        };
        for message in [post, withdraw] {
            let line = serde_json::to_string(&message).unwrap();
            assert!(!line.contains('\n'), "{line}");
            assert_eq!(serde_json::from_str::<ToHelper>(&line).unwrap(), message);
        }
    }

    fn daemon_notice(kind: NoticeKind) -> proto::Notice {
        proto::Notice {
            kind,
            title: "kv: unlock needed".into(),
            body: "claude-code is waiting (exec): unlock kv.".into(),
        }
    }

    #[test]
    fn an_unlock_notice_offers_unlock_and_a_click_unlocks() {
        let notice = Notice::from_daemon(&daemon_notice(NoticeKind::UnlockNeeded));
        assert_eq!(notice.title, "unlock needed");
        assert_eq!(notice.body, "claude-code is waiting (exec): unlock kv.");
        assert_eq!(notice.button, Some(Button::Unlock));
        assert!(!notice.answers);
        assert_eq!(click(&notice.key), Some(Click::Unlock));
    }

    #[test]
    fn other_daemon_notices_open_kv_where_they_point() {
        for (kind, tab) in [
            (NoticeKind::Missed, Tab::Audit),
            (NoticeKind::HandleRequested, Tab::Handles),
            (NoticeKind::ShareReceived, Tab::Shares),
            (NoticeKind::Reminder { id: 3 }, Tab::Approvals),
        ] {
            let notice = Notice::from_daemon(&daemon_notice(kind));
            assert_eq!(notice.button, Some(Button::Open), "{kind:?}");
            assert_eq!(click(&notice.key), Some(Click::Open(tab)), "{kind:?}");
        }
        assert_eq!(click("kv-request-7-00"), None);
        assert_eq!(click("update-1.2.3"), None);
        assert_eq!(click("kv-open-nowhere-00"), None);
    }

    #[test]
    fn a_reminder_is_the_request_again_under_a_new_key() {
        let first = Notice::new(&approval());
        let again = Notice::reminder(&Approval {
            expires_in_secs: 29,
            ..approval()
        });
        assert_ne!(first.key, again.key);
        assert!(again.key.starts_with("kv-request-7-"), "{}", again.key);
        assert_eq!(again.subtitle, "Reminder: about 29 s left · Run a command");
        assert!(again.answers);
        assert_eq!(again.title, first.title);
    }

    #[test]
    fn buttons_are_told_from_answers() {
        assert!(is_button("unlock"));
        assert!(is_button("open"));
        assert!(!is_button("allow_once"));
        assert_eq!(Button::Unlock.id(), "unlock");
    }

    #[test]
    fn answers_map_back_to_verdicts_and_nothing_else_does() {
        assert_eq!(verdict("allow_once"), Some(Verdict::AllowOnce));
        assert_eq!(verdict("allow_session"), Some(Verdict::AllowSession));
        assert_eq!(verdict("deny"), Some(Verdict::Deny));
        assert_eq!(verdict("deny_always"), None);
        assert_eq!(
            verdict("com.apple.UNNotificationDefaultActionIdentifier"),
            None
        );
    }
}
