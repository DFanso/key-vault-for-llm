//! Showing a handle's value to the user, which needs the session and, each
//! time, the passphrase or a device key; and a client that shows waiting
//! requests as notifications of its own, which keeps the daemon from
//! posting one too.

mod common;

use std::time::Duration;

use common::*;
use kv_core::crypto::SymmetricKey;
use kv_core::policy::{Mode, Policy};
use kv_core::proto::{
    ControlCommand, ControlErrorCode, ControlRequest, ControlResponse, DeviceCredential,
    RevealedField,
};
use kv_core::secret::{SecretText, SecretValue};
use kv_core::vault::DeviceKind;

fn reveal(name: &str) -> ControlCommand {
    ControlCommand::RevealHandle {
        handle: name.into(),
    }
}

fn error_code(response: ControlResponse) -> ControlErrorCode {
    match response {
        ControlResponse::Error { code, .. } => code,
        other => panic!("expected an error, got {other:?}"),
    }
}

fn fields(response: ControlResponse) -> Vec<(String, String)> {
    match response {
        ControlResponse::Revealed { fields, .. } => fields
            .into_iter()
            .map(|RevealedField { label, value }| (label, value.expose().to_owned()))
            .collect(),
        other => panic!("expected a value, got {other:?}"),
    }
}

#[test]
fn a_value_shows_only_with_the_session_and_the_passphrase_together() {
    let mut f = Fixture::new();
    f.add(openrouter(Mode::Ask));
    let token = f.token();

    // An unlocked vault and an open session are not enough.
    assert_eq!(
        error_code(f.send(None, Some(&token), reveal("openrouter"))),
        ControlErrorCode::PassphraseRequired
    );
    // Nor is the passphrase without the session.
    assert_eq!(
        error_code(f.send(Some(PASS), None, reveal("openrouter"))),
        ControlErrorCode::SessionEnded
    );
    assert_eq!(
        error_code(f.send(Some("not it"), Some(&token), reveal("openrouter"))),
        ControlErrorCode::WrongPassphrase
    );
    assert_eq!(
        fields(f.send(Some(PASS), Some(&token), reveal("openrouter"))),
        [("Token".to_owned(), TOKEN.to_owned())]
    );
    assert_eq!(
        error_code(f.send(Some(PASS), Some(&token), reveal("missing"))),
        ControlErrorCode::UnknownHandle
    );

    // Each one is in the audit log, by handle, and no value is.
    let log = std::fs::read_to_string(f.dir.path().join("audit.jsonl")).unwrap();
    assert!(!log.contains(TOKEN), "{log}");
    let shown: Vec<_> = f
        .audit_lines()
        .into_iter()
        .filter(|line| line["action"] == "reveal_handle")
        .map(|line| (line["handle"].clone(), line["outcome"].clone()))
        .collect();
    assert_eq!(shown.len(), 5, "{shown:?}");
    assert_eq!(shown[3], ("openrouter".into(), "done".into()));
}

#[test]
fn wrong_passphrases_here_count_toward_the_backoff() {
    let mut f = Fixture::new();
    f.add(openrouter(Mode::Ask));
    let token = f.token();
    let mut codes = Vec::new();
    for _ in 0..10 {
        codes.push(error_code(f.send(
            Some("not it"),
            Some(&token),
            reveal("openrouter"),
        )));
    }
    assert!(
        codes.contains(&ControlErrorCode::TooManyAttempts),
        "{codes:?}"
    );
}

#[test]
fn a_device_key_stands_in_for_the_passphrase() {
    let mut f = Fixture::new();
    f.add(openrouter(Mode::Ask));
    let key = SymmetricKey::generate();
    f.control(ControlCommand::EnrollDevice {
        kind: DeviceKind::TouchId,
        id: "kv-test".into(),
        data: hex::encode(b"fingerprints"),
        key: SecretText::new(hex::encode(key.as_bytes())),
    });
    let token = f.token();
    let with_key = |key: &SymmetricKey| ControlRequest {
        passphrase: None,
        device: Some(DeviceCredential {
            id: "kv-test".into(),
            key: SecretText::new(hex::encode(key.as_bytes())),
        }),
        token: Some(token.clone()),
        command: reveal("openrouter"),
    };
    let (response, _) = f.daemon.handle_control(with_key(&key), f.t0);
    assert_eq!(fields(response), [("Token".to_owned(), TOKEN.to_owned())]);
    let (response, _) = f
        .daemon
        .handle_control(with_key(&SymmetricKey::generate()), f.t0);
    assert_eq!(error_code(response), ControlErrorCode::WrongDeviceKey);
}

#[test]
fn every_kind_shows_whole_and_a_text_file_shows_what_it_holds() {
    let mut f = Fixture::new();
    f.add(env_secret(
        "aws",
        &[
            ("AWS_ACCESS_KEY_ID", AWS_KEY),
            ("AWS_SECRET_ACCESS_KEY", "aws-secret-for-tests-only"),
        ],
        &["terraform"],
        Mode::Ask,
    ));
    let text = SecretValue::file("passwords.txt", b"hunter2-hunter2\nswordfish-1\n").unwrap();
    f.add(secret("passwords", text, Policy::default()));
    let binary = SecretValue::file("key.der", &[0xff, 0xfe, 0x00, 0x81]).unwrap();
    f.add(secret("der", binary, Policy::default()));
    let token = f.token();

    assert_eq!(
        fields(f.send(Some(PASS), Some(&token), reveal("aws"))),
        [
            ("AWS_ACCESS_KEY_ID".to_owned(), AWS_KEY.to_owned()),
            (
                "AWS_SECRET_ACCESS_KEY".to_owned(),
                "aws-secret-for-tests-only".to_owned()
            ),
        ]
    );
    let shown = fields(f.send(Some(PASS), Some(&token), reveal("passwords")));
    assert_eq!(shown[0], ("File".to_owned(), "passwords.txt".to_owned()));
    assert_eq!(
        shown.last().unwrap(),
        &(
            "Contents".to_owned(),
            "hunter2-hunter2\nswordfish-1\n".to_owned()
        )
    );
    let shown = fields(f.send(Some(PASS), Some(&token), reveal("der")));
    assert!(
        shown.iter().all(|(label, _)| label != "Contents"),
        "{shown:?}"
    );
}

#[test]
fn a_notifying_client_keeps_the_daemons_own_notification_back_while_it_polls() {
    let mut f = Fixture::new();
    let token = f.token();
    assert!(!f.daemon.has_notifier(f.t0));

    // `kv tui` polls without showing notifications.
    f.overview(&token);
    assert!(!f.daemon.has_notifier(f.t0));

    // Without a session, a client hears nothing and counts for nothing.
    let stranger = SecretText::new("ab".repeat(32));
    assert_eq!(
        error_code(f.send(None, Some(&stranger), ControlCommand::NotifyingOverview)),
        ControlErrorCode::SessionEnded
    );
    assert!(!f.daemon.has_notifier(f.t0));

    match f.send(None, Some(&token), ControlCommand::NotifyingOverview) {
        ControlResponse::Overview { .. } => {}
        other => panic!("expected an overview, got {other:?}"),
    }
    assert!(f.daemon.has_notifier(f.t0));
    assert!(f.daemon.has_notifier(f.t0 + Duration::from_secs(4)));
    // It stopped asking: the daemon posts its own again.
    assert!(!f.daemon.has_notifier(f.t0 + Duration::from_secs(6)));

    f.send(None, Some(&token), ControlCommand::NotifyingOverview);
    f.send(None, None, ControlCommand::Lock);
    assert!(!f.daemon.has_notifier(f.t0));
}
