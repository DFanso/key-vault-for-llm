//! Waiting requests as notifications the user can answer where they are,
//! with the same answers as the tray menu, free of the platform. The tray
//! posts one per request while it holds a session, and takes it down once
//! the request is answered anywhere, times out or the vault locks.

use kv_core::crypto::fill_random;
use kv_core::proto::{Approval, Verdict};

use super::model::flat;

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
#[derive(Clone, Debug, PartialEq, Eq)]
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
}

impl Notice {
    /// The notification for `approval`, under a fresh key.
    pub fn new(approval: &Approval) -> Notice {
        let mut nonce = [0u8; 8];
        fill_random(&mut nonce);
        Notice::with_key(
            approval,
            format!("kv-request-{}-{}", approval.id, hex::encode(nonce)),
        )
    }

    pub fn with_key(approval: &Approval, key: String) -> Notice {
        let client = approval.client.as_deref().unwrap_or("An agent");
        let handles = approval.handles.join(", ");
        let mut body = flat(&approval.detail, BODY_LEN);
        if let Some(cwd) = &approval.cwd {
            body.push('\n');
            body.push_str(&flat(&format!("in {cwd}"), BODY_LEN));
        }
        Notice {
            key,
            title: flat(&format!("{client} wants {handles}"), TITLE_LEN),
            subtitle: tool_words(&approval.tool).to_owned(),
            body,
            can_grant: approval.can_grant,
        }
    }
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
    fn each_notice_gets_a_key_of_its_own() {
        let a = Notice::new(&approval());
        let b = Notice::new(&approval());
        assert!(a.key.starts_with("kv-request-7-"), "{}", a.key);
        assert_ne!(a.key, b.key);
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
