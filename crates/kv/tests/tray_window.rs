//! What the `kv tray` window's page and the tray say to each other: the
//! JSON the page sends is read into `FromPage` or dropped, and `ToPage`
//! becomes the script the window runs.

use std::collections::BTreeMap;

use kv::audit::Entry;
use kv::tray::window::{FormRequest, FromPage, Tab, ToPage};
use kv_core::proto::Verdict;
use kv_core::secret::SecretText;

#[test]
fn what_the_page_sends_is_read() {
    let cases = [
        (r#"{"type":"ready"}"#, FromPage::Ready),
        (
            r#"{"type":"unlock","passphrase":"correct horse"}"#,
            FromPage::Unlock {
                passphrase: SecretText::new("correct horse"),
            },
        ),
        (r#"{"type":"device_unlock"}"#, FromPage::DeviceUnlock),
        (
            r#"{"type":"decide","id":7,"verdict":"allow_session"}"#,
            FromPage::Decide {
                id: 7,
                verdict: Verdict::AllowSession,
            },
        ),
        (
            r#"{"type":"open_form","form":{"kind":"new"}}"#,
            FromPage::OpenForm {
                form: FormRequest::New,
            },
        ),
        (
            r#"{"type":"open_form","form":{"kind":"request","id":3}}"#,
            FromPage::OpenForm {
                form: FormRequest::Request { id: 3 },
            },
        ),
        (
            r#"{"type":"open_form","form":{"kind":"edit","name":"github"}}"#,
            FromPage::OpenForm {
                form: FormRequest::Edit {
                    name: "github".into(),
                },
            },
        ),
        (
            r#"{"type":"open_form","form":{"kind":"policy","name":"github"}}"#,
            FromPage::OpenForm {
                form: FormRequest::Policy {
                    name: "github".into(),
                },
            },
        ),
        (
            r#"{"type":"submit_form","values":{"name":"a","token":"t"}}"#,
            FromPage::SubmitForm {
                values: BTreeMap::from([
                    ("name".to_owned(), SecretText::new("a")),
                    ("token".to_owned(), SecretText::new("t")),
                ]),
            },
        ),
        (r#"{"type":"close_form"}"#, FromPage::CloseForm),
        (r#"{"type":"dismiss","id":2}"#, FromPage::Dismiss { id: 2 }),
        (
            r#"{"type":"remove","name":"github"}"#,
            FromPage::Remove {
                name: "github".into(),
            },
        ),
        (r#"{"type":"lock"}"#, FromPage::Lock),
        (
            r#"{"type":"tab","tab":"audit"}"#,
            FromPage::Tab { tab: Tab::Audit },
        ),
    ];
    for (json, expected) in cases {
        assert_eq!(FromPage::parse(json), Some(expected), "{json}");
    }
}

#[test]
fn anything_else_is_dropped() {
    for json in [
        "",
        "{",
        "null",
        r#"{"type":"nope"}"#,
        r#"{"type":"decide","id":"7","verdict":"allow_once"}"#,
        r#"{"type":"decide","id":7,"verdict":"allow_forever"}"#,
        r#"{"type":"tab","tab":"settings"}"#,
        r#"{"type":"dismiss","id":2,"extra":1}"#,
        r#"{"type":"open_form","form":{"kind":"edit"}}"#,
        r#"{"passphrase":"x"}"#,
    ] {
        assert_eq!(FromPage::parse(json), None, "{json}");
    }
}

#[test]
fn a_passphrase_never_shows_in_debug_output() {
    let unlock = FromPage::parse(r#"{"type":"unlock","passphrase":"hunter2-secret"}"#).unwrap();
    assert!(!format!("{unlock:?}").contains("hunter2"), "{unlock:?}");
    let form = FromPage::parse(r#"{"type":"submit_form","values":{"token":"sk-12345"}}"#).unwrap();
    assert!(!format!("{form:?}").contains("sk-12345"), "{form:?}");
}

#[test]
fn what_the_tray_sends_is_a_call_to_kv_receive() {
    let show = ToPage::Show { tab: Tab::Handles };
    assert_eq!(
        show.script(),
        r#"kv.receive({"type":"show","tab":"handles"})"#
    );
    let message = ToPage::Message {
        text: "that request is no longer waiting for approval".into(),
        request: Some(4),
    };
    assert_eq!(
        message.script(),
        r#"kv.receive({"type":"message","text":"that request is no longer waiting for approval","request":4})"#
    );
    let audit = ToPage::Audit {
        entries: vec![Entry {
            ts: "2026-10-12T10:00:00Z".into(),
            socket: "agent".into(),
            action: "http_request".into(),
            handle: Some("github".into()),
            decision: Some("approved".into()),
            summary: Some("GET https://api.github.com/user".into()),
            outcome: "ok".into(),
            duration_ms: Some(12),
        }],
    };
    let script = audit.script();
    assert!(
        script.starts_with(r#"kv.receive({"type":"audit","entries":[{"ts":"#),
        "{script}"
    );
    let locked = ToPage::State {
        locked: true,
        device: Some("Touch ID".into()),
        waiting_for_device: false,
        overview: None,
    };
    assert_eq!(
        locked.script(),
        r#"kv.receive({"type":"state","locked":true,"device":"Touch ID","waiting_for_device":false,"overview":null})"#
    );
}

/// Agent text is only ever data inside the JSON, however it is written.
#[test]
fn agent_text_cannot_end_the_call() {
    let message = ToPage::Message {
        text: "\"});alert(1);({\"a\":\"\u{2028}</script>".into(),
        request: None,
    };
    let script = message.script();
    let json = script
        .strip_prefix("kv.receive(")
        .and_then(|s| s.strip_suffix(')'))
        .unwrap();
    let back: serde_json::Value = serde_json::from_str(json).unwrap();
    assert_eq!(back["text"], "\"});alert(1);({\"a\":\"\u{2028}</script>");
}
