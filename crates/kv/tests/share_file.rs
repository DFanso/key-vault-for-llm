//! A file goes from one vault to another through the daemon: sealed on
//! one side, saved as a `file` handle on the other, and given back to the
//! user as exactly the bytes that left.

mod common;

use common::*;
use kv::daemon::Prepared;
use kv_core::policy::{Mode, Policy};
use kv_core::proto::{
    AgentRequest, AgentResponse, ControlCommand, ControlErrorCode, ControlResponse,
    ReceiveShareCall, SendShareCall, ShareRequestCall, Verdict,
};
use kv_core::secret::{SecretKind, SecretText, SecretValue};

/// Bytes that a text pipeline would damage: CRLF, a BOM, a NUL, bytes that
/// are not UTF-8 and no newline at the end.
fn awkward_bytes() -> Vec<u8> {
    let mut bytes = b"\xEF\xBB\xBFcorrect-horse-battery\r\nsecond-line-here\r\n".to_vec();
    bytes.extend([0, 159, 146, 150, 255, 254, 13, 10, 0]);
    bytes.extend((0..200_000u32).map(|i| (i.wrapping_mul(2_654_435_761) >> 24) as u8));
    bytes.extend(b"no newline at the end");
    bytes
}

fn file_secret(bytes: &[u8]) -> kv_core::secret::Secret {
    secret(
        "wordlist",
        SecretValue::file("C:\\Users\\leo\\words.bin", bytes).unwrap(),
        Policy {
            mode: Mode::Auto,
            allowed_cmds: vec!["cat".into()],
            ..Policy::default()
        },
    )
}

fn request_code(bob: &mut Fixture) -> String {
    match bob.prepare(AgentRequest::RequestShare(ShareRequestCall {
        note: "the word list".into(),
        from: "bob".into(),
    })) {
        Prepared::Reply(AgentResponse::ShareRequested { code, .. }) => code,
        _ => panic!("expected a request code"),
    }
}

#[test]
fn a_file_arrives_exactly_and_only_the_user_can_save_it() {
    let bytes = awkward_bytes();
    let mut alice = Fixture::new();
    alice.add(file_secret(&bytes));
    let mut bob = Fixture::new();
    let bob_token = bob.token();
    let code = request_code(&mut bob);

    // Alice's approval names the file, its size and its fingerprint.
    let alice_token = alice.token();
    let agent = session("alice-agent");
    let call = AgentRequest::SendShare(SendShareCall {
        request: code,
        handle: "wordlist".into(),
        name: None,
        from: "alice".into(),
        note: String::new(),
    });
    let waiting = alice.wait(Some(&agent), call, alice.t0);
    let approval = alice.overview(&alice_token).approvals.remove(0);
    let fingerprint = SecretValue::file("words.bin", &bytes)
        .unwrap()
        .file_fingerprint()
        .unwrap();
    assert!(approval.detail.contains("words.bin"), "{}", approval.detail);
    assert!(
        approval.detail.contains(&format!("{} bytes", bytes.len())),
        "{}",
        approval.detail
    );
    assert!(
        approval.detail.contains(&fingerprint),
        "{}",
        approval.detail
    );
    alice.decide(&alice_token, waiting.id, Verdict::AllowOnce);
    let share = match waiting.then {
        Prepared::Reply(AgentResponse::ShareSealed { share, .. }) => share,
        _ => panic!("expected sealed text"),
    };
    assert!(!share.contains("correct-horse"));

    // Bob's vault keeps it as a file handle in ask mode; the agent sees
    // the handle and nothing of the file.
    let handle = match bob.prepare(AgentRequest::ReceiveShare(ReceiveShareCall {
        share: share.clone(),
        name: None,
    })) {
        Prepared::Reply(AgentResponse::ShareReceived { handle, .. }) => handle,
        _ => panic!("expected a saved share"),
    };
    assert_eq!(handle.name, "wordlist");
    assert_eq!(handle.kind, SecretKind::File);
    assert_eq!(handle.mode, Mode::Ask);
    assert_eq!(handle.env_vars, ["KV_FILE_WORDLIST"]);
    assert!(
        !serde_json::to_string(&handle)
            .unwrap()
            .contains("Y29ycmVjdC")
    );

    // The user saves it from kv's window: the same bytes under the base name.
    match bob.send(
        None,
        Some(&bob_token),
        ControlCommand::ExportFile {
            handle: "wordlist".into(),
        },
    ) {
        ControlResponse::File {
            handle,
            file_name,
            sha256,
            data,
        } => {
            assert_eq!(handle, "wordlist");
            assert_eq!(file_name, "words.bin");
            // Same base64 and same checksum as the original: nothing changed.
            let value = SecretValue::File {
                file_name,
                data,
                sha256,
            };
            assert_eq!(value.verify_file(), Ok(()));
            assert_eq!(value, SecretValue::file("words.bin", &bytes).unwrap());
            assert_eq!(&value.file_parts().unwrap().1[..], &bytes[..]);
        }
        other => panic!("expected the file, got {other:?}"),
    }
}

#[test]
fn a_file_the_user_added_is_never_handed_back() {
    let mut alice = Fixture::new();
    alice.add(file_secret(b"a file the user typed in, not received"));
    let token = alice.token();
    match alice.send(
        None,
        Some(&token),
        ControlCommand::ExportFile {
            handle: "wordlist".into(),
        },
    ) {
        ControlResponse::Error { code, message } => {
            assert_eq!(code, ControlErrorCode::Invalid);
            assert!(message.contains("received through a share"), "{message}");
        }
        other => panic!("a file nobody sent was handed back: {other:?}"),
    }
}

#[test]
fn a_handle_that_is_not_a_file_cannot_be_exported() {
    let mut alice = Fixture::new();
    alice.add(openrouter(Mode::Auto));
    let token = alice.token();
    assert!(matches!(
        alice.send(
            None,
            Some(&token),
            ControlCommand::ExportFile {
                handle: "openrouter".into()
            }
        ),
        ControlResponse::Error { .. }
    ));
    let _ = SecretText::new("");
}
