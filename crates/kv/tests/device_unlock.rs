//! The client side of Touch ID and Windows Hello: finding the vault's slot
//! for this platform's device and turning what the device returns into a
//! credential for the daemon. A fake device stands in for the platform.

mod fake;

use fake::Fake;
use kv::device::{self, Device};
use kv_core::crypto::{KdfParams, SymmetricKey};
use kv_core::vault::{DeviceKind, DeviceSlot, Vault};
use tempfile::TempDir;

const UNLOCK: &str = "unlock the kv vault";

const FAST: KdfParams = KdfParams {
    m_kib: 8,
    t: 1,
    p: 1,
};

#[test]
fn an_enrolled_device_gives_a_credential_that_opens_the_vault() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("vault.kv");
    let mut vault = Vault::create(&path, "correct horse battery", FAST).unwrap();
    let fake = Fake::default();
    assert!(
        device::credential(&path, &fake, UNLOCK).is_none(),
        "nothing enrolled"
    );

    let (slot, key) = device::enroll(&fake).unwrap();
    assert_eq!(slot.kind, DeviceKind::TouchId);
    assert_eq!(slot.data, b"fingerprints");
    vault.enroll_device(slot.clone(), &key).unwrap();

    let credential = device::credential(&path, &fake, UNLOCK).unwrap().unwrap();
    assert_eq!(credential.id, slot.id);
    assert_eq!(credential.key.expose(), hex::encode(key.as_bytes()));
    Vault::unlock_with_device(&path, &slot.id, &key).unwrap();

    fake.forget(&slot.id);
    let error = device::credential(&path, &fake, UNLOCK)
        .unwrap()
        .unwrap_err();
    assert!(error.contains("no key"), "{error}");
}

#[test]
fn a_device_that_is_not_available_says_why() {
    let fake = Fake {
        refuse: Some("Touch ID is not set up on this Mac"),
        ..Fake::default()
    };
    let error = device::enroll(&fake).unwrap_err();
    assert!(error.contains("not set up"), "{error}");
}

#[test]
fn ids_are_random_and_safe_for_the_platform() {
    let (a, b) = (device::new_id(), device::new_id());
    assert_ne!(a, b);
    assert!(a.starts_with("kv-") && a.len() == 35, "{a}");
    assert!(a[3..].bytes().all(|b| b.is_ascii_hexdigit()));
}

#[test]
fn kv_biometric_off_turns_device_unlock_off() {
    assert!(device::enabled(None));
    assert!(device::enabled(Some("on".as_ref())));
    for off in ["off", "0", "false", "OFF"] {
        assert!(!device::enabled(Some(off.as_ref())), "{off}");
    }
}

#[test]
fn the_enroll_command_carries_the_slot_and_key_as_hex() {
    let slot = DeviceSlot {
        kind: DeviceKind::WindowsHello,
        id: "kv-1".into(),
        data: vec![1, 2, 255],
    };
    let key = SymmetricKey::from_slice(&[7; 32]).unwrap();
    match device::enroll_command(slot, &key) {
        kv_core::proto::ControlCommand::EnrollDevice {
            kind,
            id,
            data,
            key,
        } => {
            assert_eq!(
                (kind, id.as_str(), data.as_str()),
                (DeviceKind::WindowsHello, "kv-1", "0102ff")
            );
            assert_eq!(key.expose(), "07".repeat(32));
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn the_prompt_says_what_it_is_for() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("vault.kv");
    let mut vault = Vault::create(&path, "correct horse battery", FAST).unwrap();
    let fake = Fake::default();
    let (slot, key) = device::enroll(&fake).unwrap();
    vault.enroll_device(slot, &key).unwrap();
    let reason = "remove the handle prod-db from the kv vault";
    device::credential(&path, &fake, reason).unwrap().unwrap();
    assert_eq!(*fake.reasons.lock().unwrap(), vec![reason.to_owned()]);
}

/// Anything can listen where the daemon's socket should be (after `kv
/// stop`, or under another `KV_HOME`). A device key is a lasting key to the
/// vault, so the client sends it only to a process running this same kv.
#[cfg(unix)]
#[tokio::test]
async fn a_device_key_goes_only_to_this_kv() {
    use std::process::Command;
    use std::time::{Duration, Instant};

    use kv::client;
    use kv::paths::Paths;
    use kv_core::proto::{ControlCommand, ControlRequest, DeviceCredential};
    use kv_core::secret::SecretText;

    let dir = TempDir::new().unwrap();
    let paths = Paths::under(dir.path());
    let socket = paths.control_endpoint().path;
    std::fs::create_dir_all(socket.parent().unwrap()).unwrap();
    let caught = dir.path().join("caught");
    let listener = r#"
import socket, sys
s = socket.socket(socket.AF_UNIX)
s.bind(sys.argv[1])
s.listen(1)
c, _ = s.accept()
c.settimeout(5)
data = b""
try:
    while True:
        chunk = c.recv(65536)
        if not chunk:
            break
        data += chunk
except OSError:
    pass
open(sys.argv[2], "wb").write(data)
"#;
    let mut fake_daemon = Command::new("python3")
        .args(["-I", "-c", listener])
        .arg(&socket)
        .arg(&caught)
        .spawn()
        .expect("python3 plays the process at the socket");
    let deadline = Instant::now() + Duration::from_secs(10);
    while !socket.exists() {
        assert!(Instant::now() < deadline, "the listener never started");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    let key = "ab".repeat(32);
    let request = ControlRequest {
        passphrase: None,
        device: Some(DeviceCredential {
            id: "kv-0123456789abcdef".into(),
            key: SecretText::new(&key),
        }),
        token: None,
        command: ControlCommand::Unlock,
    };
    let error = client::control(&paths, &request, false).await.unwrap_err();
    assert_eq!(
        error.kind(),
        std::io::ErrorKind::PermissionDenied,
        "{error}"
    );
    assert!(error.to_string().contains("kv stop"), "{error}");

    fake_daemon.wait().unwrap();
    let sent = std::fs::read(&caught).unwrap();
    assert!(
        !String::from_utf8_lossy(&sent).contains(&key),
        "the key reached the listener"
    );
}
