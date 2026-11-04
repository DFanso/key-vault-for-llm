//! What the `kv tray` window's page and the tray say to each other: the
//! JSON the page sends is read into `FromPage` or dropped, and `ToPage`
//! becomes the script the window runs.

use std::collections::BTreeMap;

use kv::audit::Entry;
use kv::tray::window::{FormRequest, FromPage, Stays, Tab, Theme, ToPage};
use kv::tui::app::ShareDone;
use kv_core::proto::Verdict;
use kv_core::secret::{SecretKind, SecretText};

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
        (
            r#"{"type":"tab","tab":"shares"}"#,
            FromPage::Tab { tab: Tab::Shares },
        ),
        (
            r#"{"type":"tab","tab":"home"}"#,
            FromPage::Tab { tab: Tab::Home },
        ),
        (r#"{"type":"hide"}"#, FromPage::Hide),
        (r#"{"type":"expand"}"#, FromPage::Expand),
        (
            r#"{"type":"theme","theme":"dark"}"#,
            FromPage::Theme { theme: Theme::Dark },
        ),
        (
            r#"{"type":"theme","theme":"system"}"#,
            FromPage::Theme {
                theme: Theme::System,
            },
        ),
        (
            r#"{"type":"login","on":true}"#,
            FromPage::Login { on: true },
        ),
        (r#"{"type":"quit"}"#, FromPage::Quit),
        (
            r#"{"type":"reveal","handle":"openrouter"}"#,
            FromPage::Reveal {
                handle: "openrouter".into(),
            },
        ),
        (
            r#"{"type":"forget","id":"0a1b2c3d4e5f6071"}"#,
            FromPage::Forget {
                id: "0a1b2c3d4e5f6071".into(),
            },
        ),
        (
            r#"{"type":"request_share","note":"the staging key","from":"bob"}"#,
            FromPage::RequestShare {
                note: "the staging key".into(),
                from: "bob".into(),
            },
        ),
        (
            r#"{"type":"send_share","request":"kv-request:v1:abc","handle":"staging","name":"","from":"alice","note":""}"#,
            FromPage::SendShare {
                request: "kv-request:v1:abc".into(),
                handle: "staging".into(),
                name: String::new(),
                from: "alice".into(),
                note: String::new(),
            },
        ),
        (
            r#"{"type":"receive_share","share":"kv-share:v1:abc","name":"staging-2"}"#,
            FromPage::ReceiveShare {
                share: "kv-share:v1:abc".into(),
                name: "staging-2".into(),
            },
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
        r#"{"type":"theme","theme":"sepia"}"#,
        r#"{"type":"login","on":"yes"}"#,
        r#"{"type":"dismiss","id":2,"extra":1}"#,
        r#"{"type":"open_form","form":{"kind":"edit"}}"#,
        r#"{"passphrase":"x"}"#,
        r#"{"type":"reveal"}"#,
        r#"{"type":"reveal","handle":"a","value":"x"}"#,
        r#"{"type":"forget","id":7}"#,
        r#"{"type":"request_share","note":"x"}"#,
        r#"{"type":"send_share","request":"kv-request:v1:abc","handle":"a","name":"","from":"","note":"","value":"x"}"#,
        r#"{"type":"receive_share","share":"kv-share:v1:abc"}"#,
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
        login: false,
        theme: Theme::Light,
    };
    assert_eq!(
        locked.script(),
        r#"kv.receive({"type":"state","locked":true,"device":"Touch ID","waiting_for_device":false,"overview":null,"login":false,"theme":"light"})"#
    );
    assert_eq!(ToPage::Hidden.script(), r#"kv.receive({"type":"hidden"})"#);
    assert_eq!(
        ToPage::Menu { on: true }.script(),
        r#"kv.receive({"type":"menu","on":true})"#
    );
}

/// The share dialog reads each step's result by `step`.
#[test]
fn share_results_reach_the_dialog_as_steps() {
    let cases = [
        (
            ShareDone::Requested {
                code: "kv-request:v1:abc".into(),
                safety_code: "7KQ2-M9XD".into(),
            },
            r#"kv.receive({"type":"shared","result":{"step":"requested","code":"kv-request:v1:abc","safety_code":"7KQ2-M9XD"}})"#,
        ),
        (
            ShareDone::Sealed {
                share: "kv-share:v1:xyz".into(),
                safety_code: "7KQ2-M9XD".into(),
                to: "bob".into(),
                asked_for: "the staging key".into(),
            },
            r#"kv.receive({"type":"shared","result":{"step":"sealed","share":"kv-share:v1:xyz","safety_code":"7KQ2-M9XD","to":"bob","asked_for":"the staging key"}})"#,
        ),
        (
            ShareDone::Received {
                handle: "staging".into(),
                kind: SecretKind::Http,
                from: "alice".into(),
                safety_code: "7KQ2-M9XD".into(),
            },
            r#"kv.receive({"type":"shared","result":{"step":"received","handle":"staging","kind":"http","from":"alice","safety_code":"7KQ2-M9XD"}})"#,
        ),
    ];
    for (result, script) in cases {
        assert_eq!(ToPage::Shared { result }.script(), script);
    }
    let error = ToPage::ShareError {
        message: "That is not a kv share".into(),
    };
    assert_eq!(
        error.script(),
        r#"kv.receive({"type":"share_error","message":"That is not a kv share"})"#
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

#[test]
fn a_revealed_value_reaches_the_page_only_as_json_data() {
    use kv_core::proto::RevealedField;
    let revealed = ToPage::Revealed {
        handle: "openrouter".into(),
        fields: vec![RevealedField {
            label: "Token".into(),
            value: SecretText::new("sk-or-v1-\")</script>"),
        }],
    };
    let script = revealed.script();
    assert!(script.starts_with("kv.receive({"), "{script}");
    assert!(script.ends_with("})"), "{script}");
    let json = &script["kv.receive(".len()..script.len() - 1];
    let parsed: serde_json::Value = serde_json::from_str(json).unwrap();
    assert_eq!(parsed["type"], "revealed");
    assert_eq!(parsed["fields"][0]["value"], "sk-or-v1-\")</script>");
    assert!(
        !format!("{revealed:?}").contains("sk-or-v1"),
        "{revealed:?}"
    );
}

/// The appearance the user picked is kept in a file of its own; anything
/// else in it reads as following the system.
#[test]
fn the_theme_is_saved_and_read_back() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("tray-theme");
    assert_eq!(Theme::load(&path), Theme::System, "no file yet");
    for theme in [Theme::Dark, Theme::Light, Theme::System] {
        theme.save(&path).unwrap();
        assert_eq!(Theme::load(&path), theme);
    }
    std::fs::write(&path, "sepia").unwrap();
    assert_eq!(Theme::load(&path), Theme::System);
}

#[test]
fn the_file_messages_are_read_and_their_bytes_stay_out_of_debug_output() {
    let cases = [
        (
            r#"{"type":"file_read","file_name":"passwords.txt","data":"b25lCg=="}"#,
            FromPage::FileRead {
                file_name: "passwords.txt".into(),
                data: SecretText::new("b25lCg=="),
            },
        ),
        (
            r#"{"type":"file_save","name":"wordlist","cmds":"hydra, ssh"}"#,
            FromPage::FileSave {
                name: "wordlist".into(),
                cmds: "hydra, ssh".into(),
            },
        ),
        (r#"{"type":"file_cancel"}"#, FromPage::FileCancel),
        (
            r#"{"type":"save_file","handle":"wordlist"}"#,
            FromPage::SaveFile {
                handle: "wordlist".into(),
            },
        ),
        (r#"{"type":"show_saved"}"#, FromPage::ShowSaved),
    ];
    for (json, expected) in cases {
        assert_eq!(FromPage::parse(json), Some(expected), "{json}");
    }
    // The page cannot name the file to show: the message has no field for a
    // path, so one sent along is dropped and the tray shows only what it saved.
    assert_eq!(
        FromPage::parse(r#"{"type":"show_saved","path":"/etc/passwd"}"#),
        Some(FromPage::ShowSaved)
    );
    let read = FromPage::parse(r#"{"type":"file_read","file_name":"k.pem","data":"c2VjcmV0"}"#);
    assert!(!format!("{read:?}").contains("c2VjcmV0"));
}

#[test]
fn the_file_results_reach_the_page_as_json_data() {
    let preview = ToPage::FilePreview {
        file_name: "passwords.txt".into(),
        name: "passwords".into(),
        size: 44,
        fingerprint: "A1B2-C3D4-E5F6".into(),
        scrubbed: true,
        notes: vec!["a note".into()],
    };
    let script = preview.script();
    assert!(script.starts_with("kv.receive({"), "{script}");
    assert!(script.contains(r#""type":"file_preview""#), "{script}");
    assert!(
        script.contains(r#""fingerprint":"A1B2-C3D4-E5F6""#),
        "{script}"
    );
    let saved = ToPage::ShareSaved {
        path: "/Users/me/Downloads/wordlist-7KQ2-M9XD.kvshare".into(),
        safety_code: "7KQ2-M9XD".into(),
        to: "carol".into(),
        asked_for: "the list".into(),
    };
    assert!(saved.script().contains(r#""type":"share_saved""#));
    // Text that closes the call early stays inside the JSON string.
    let hostile = ToPage::FileSaved {
        handle: "wordlist".into(),
        path: "x\"});alert(1);kv.receive({\"".into(),
    };
    let script = hostile.script();
    let argument = script
        .strip_prefix("kv.receive(")
        .and_then(|rest| rest.strip_suffix(')'))
        .unwrap_or_else(|| panic!("not one call: {script}"));
    let data: serde_json::Value = serde_json::from_str(argument)
        .unwrap_or_else(|e| panic!("the argument is not one JSON value ({e}): {script}"));
    assert_eq!(data["path"], "x\"});alert(1);kv.receive({\"");
    assert_eq!(data["handle"], "wordlist");
}

#[test]
fn the_move_and_focus_messages_are_read() {
    let cases = [
        (r#"{"type":"drag"}"#, FromPage::Drag),
        (r#"{"type":"picking"}"#, FromPage::Picking),
        (r#"{"type":"busy","on":true}"#, FromPage::Busy { on: true }),
        (
            r#"{"type":"busy","on":false}"#,
            FromPage::Busy { on: false },
        ),
    ];
    for (json, expected) in cases {
        assert_eq!(FromPage::parse(json), Some(expected), "{json}");
    }
    // Whether a dialog is open has to be said either way.
    assert_eq!(FromPage::parse(r#"{"type":"busy"}"#), None);
    assert_eq!(FromPage::parse(r#"{"type":"busy","on":"yes"}"#), None);
}

#[test]
fn a_loss_of_focus_hides_the_window_unless_something_keeps_it_up() {
    assert!(!Stays::default().any(), "a plain click elsewhere hides it");
    // Any one of these keeps it: the device prompt, the file panel, a form
    // open in the page, a window the user moved.
    for stays in [
        Stays {
            prompting: true,
            ..Stays::default()
        },
        Stays {
            picking: true,
            ..Stays::default()
        },
        Stays {
            busy: true,
            ..Stays::default()
        },
        Stays {
            moved: true,
            ..Stays::default()
        },
    ] {
        assert!(stays.any(), "{stays:?}");
    }
}

#[test]
fn the_file_panel_closing_lets_the_window_hide_again() {
    let mut stays = Stays {
        picking: true,
        busy: true,
        ..Stays::default()
    };
    // The panel closed and the window has the focus again: the page's own
    // dialog still keeps it up, the panel no longer does.
    stays.gained_focus();
    assert!(!stays.picking && stays.busy);
    stays.busy = false;
    assert!(!stays.any());
}

#[test]
fn hiding_or_showing_the_menu_takes_the_window_back_to_a_flyout() {
    let mut stays = Stays {
        prompting: true,
        picking: true,
        busy: true,
        moved: true,
    };
    // The user hid it: what they moved and any file panel are over, while a
    // dialog still open in the page and a device prompt are not theirs to end.
    stays.hidden();
    assert!(!stays.picking && !stays.moved);
    assert!(stays.busy && stays.prompting);
    let mut moved = Stays {
        moved: true,
        ..Stays::default()
    };
    moved.shown_as_menu();
    assert!(!moved.any(), "the small menu is a flyout again");
}
