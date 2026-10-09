//! Touch ID and Windows Hello as the daemon sees them: a key the CLI got
//! from the platform, sent in place of the passphrase. The platform side is
//! in `kv::device`.

mod common;

use common::*;
use kv_core::crypto::SymmetricKey;
use kv_core::proto::{
    ControlCommand, ControlErrorCode, ControlRequest, ControlResponse, DeviceCredential,
};
use kv_core::secret::SecretText;
use kv_core::vault::DeviceKind;

const ID: &str = "kv-0123456789abcdef";

fn send(f: &mut Fixture, request: ControlRequest) -> ControlResponse {
    f.daemon.handle_control(request, f.t0).0
}

fn with_passphrase(command: ControlCommand) -> ControlRequest {
    ControlRequest {
        passphrase: Some(SecretText::new(PASS)),
        device: None,
        token: None,
        command,
    }
}

fn with_device(key: &SymmetricKey, command: ControlCommand) -> ControlRequest {
    ControlRequest {
        passphrase: None,
        device: Some(DeviceCredential {
            id: ID.into(),
            key: SecretText::new(hex::encode(key.as_bytes())),
        }),
        token: None,
        command,
    }
}

fn enroll(key: &SymmetricKey) -> ControlCommand {
    ControlCommand::EnrollDevice {
        kind: DeviceKind::TouchId,
        id: ID.into(),
        data: hex::encode(b"fingerprints"),
        key: SecretText::new(hex::encode(key.as_bytes())),
    }
}

fn error(response: ControlResponse) -> (ControlErrorCode, String) {
    match response {
        ControlResponse::Error { code, message } => (code, message),
        other => panic!("expected an error, got {other:?}"),
    }
}

fn done(response: ControlResponse) -> Vec<String> {
    match response {
        ControlResponse::Done { warnings } => warnings,
        other => panic!("expected done, got {other:?}"),
    }
}

#[test]
fn an_enrolled_device_unlocks_and_opens_sessions() {
    let mut f = Fixture::new();
    let key = SymmetricKey::generate();
    done(send(&mut f, with_passphrase(enroll(&key))));
    f.control(ControlCommand::Lock);

    done(send(&mut f, with_device(&key, ControlCommand::Unlock)));
    assert!(!f.status().locked);
    assert_eq!(f.status().devices, [DeviceKind::TouchId]);
    f.control(ControlCommand::Lock);
    assert_eq!(
        f.status().devices,
        [DeviceKind::TouchId],
        "read while locked"
    );
    assert!(matches!(
        send(&mut f, with_device(&key, ControlCommand::OpenSession)),
        ControlResponse::Session { .. }
    ));
    // Like the passphrase, it is enough to change handles.
    f.add(openrouter(kv_core::policy::Mode::Auto));
    done(send(
        &mut f,
        with_device(
            &key,
            ControlCommand::Remove {
                name: "openrouter".into(),
            },
        ),
    ));
}

#[test]
fn a_wrong_device_key_is_refused_and_counts_toward_the_backoff() {
    let mut f = Fixture::new();
    done(send(
        &mut f,
        with_passphrase(enroll(&SymmetricKey::generate())),
    ));
    f.control(ControlCommand::Lock);
    let wrong = SymmetricKey::generate();
    // Five free attempts, as for the passphrase.
    for _ in 0..5 {
        let (code, _) = error(send(&mut f, with_device(&wrong, ControlCommand::Unlock)));
        assert_eq!(code, ControlErrorCode::WrongDeviceKey);
    }
    let (code, _) = error(send(&mut f, with_device(&wrong, ControlCommand::Unlock)));
    assert_eq!(code, ControlErrorCode::TooManyAttempts);
}

#[test]
fn enrolling_and_changing_the_passphrase_need_the_passphrase() {
    let mut f = Fixture::new();
    let key = SymmetricKey::generate();
    done(send(&mut f, with_passphrase(enroll(&key))));
    let (code, _) = error(send(&mut f, with_device(&key, enroll(&key))));
    assert_eq!(code, ControlErrorCode::PassphraseRequired);
    let change = || ControlCommand::ChangePassphrase {
        new_passphrase: SecretText::new("a brand new passphrase"),
    };
    let (code, _) = error(send(&mut f, with_device(&key, change())));
    assert_eq!(code, ControlErrorCode::PassphraseRequired);

    let warnings = done(send(&mut f, with_passphrase(change())));
    assert!(warnings[0].contains("Touch ID"), "{warnings:?}");
    assert!(f.status().devices.is_empty());
    let (code, _) = error(send(&mut f, with_device(&key, ControlCommand::Unlock)));
    assert_eq!(code, ControlErrorCode::WrongDeviceKey);
}

#[test]
fn removing_a_device_ends_its_unlock() {
    let mut f = Fixture::new();
    let key = SymmetricKey::generate();
    done(send(&mut f, with_passphrase(enroll(&key))));
    let remove = || ControlCommand::RemoveDevice {
        kind: DeviceKind::TouchId,
    };
    done(send(&mut f, with_device(&key, remove())));
    let (code, message) = error(send(&mut f, with_passphrase(remove())));
    assert_eq!(code, ControlErrorCode::Invalid);
    assert!(message.contains("Touch ID is not set up"), "{message}");
    let (code, _) = error(send(&mut f, with_device(&key, ControlCommand::Unlock)));
    assert_eq!(code, ControlErrorCode::WrongDeviceKey);
}

#[test]
fn enrolment_is_audited_without_the_key() {
    let mut f = Fixture::new();
    let key = SymmetricKey::generate();
    done(send(&mut f, with_passphrase(enroll(&key))));
    let (code, _) = error(send(
        &mut f,
        with_passphrase(ControlCommand::EnrollDevice {
            kind: DeviceKind::TouchId,
            id: ID.into(),
            data: String::new(),
            key: SecretText::new("not hex"),
        }),
    ));
    assert_eq!(code, ControlErrorCode::Invalid);
    let audit = std::fs::read_to_string(f.dir.path().join("audit.jsonl")).unwrap();
    assert!(audit.contains("enroll_device"), "{audit}");
    assert!(!audit.contains(&hex::encode(key.as_bytes())));
}
