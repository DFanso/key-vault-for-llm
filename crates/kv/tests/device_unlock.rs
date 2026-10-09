//! The client side of Touch ID and Windows Hello: finding the vault's slot
//! for this platform's device and turning what the device returns into a
//! credential for the daemon. A fake device stands in for the platform.

use std::collections::HashMap;
use std::sync::Mutex;

use kv::device::{self, Device};
use kv_core::crypto::{KdfParams, SymmetricKey};
use kv_core::vault::{DeviceKind, DeviceSlot, Vault};
use tempfile::TempDir;

const FAST: KdfParams = KdfParams {
    m_kib: 8,
    t: 1,
    p: 1,
};

#[derive(Default)]
struct Fake {
    keys: Mutex<HashMap<String, [u8; 32]>>,
    refuse: Option<&'static str>,
}

impl Device for Fake {
    fn kind(&self) -> DeviceKind {
        DeviceKind::TouchId
    }

    fn available(&self) -> Result<(), String> {
        self.refuse.map_or(Ok(()), |why| Err(why.into()))
    }

    fn enroll(&self, id: &str) -> Result<(Vec<u8>, SymmetricKey), String> {
        self.available()?;
        let key = SymmetricKey::generate();
        self.keys.lock().unwrap().insert(id.into(), *key.as_bytes());
        Ok((b"fingerprints".to_vec(), key))
    }

    fn unlock(&self, slot: &DeviceSlot) -> Result<SymmetricKey, String> {
        self.available()?;
        let keys = self.keys.lock().unwrap();
        let key = keys.get(&slot.id).ok_or("no key for this slot")?;
        Ok(SymmetricKey::from_slice(key).unwrap())
    }

    fn forget(&self, id: &str) {
        self.keys.lock().unwrap().remove(id);
    }
}

#[test]
fn an_enrolled_device_gives_a_credential_that_opens_the_vault() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("vault.kv");
    let mut vault = Vault::create(&path, "correct horse battery", FAST).unwrap();
    let fake = Fake::default();
    assert!(
        device::credential(&path, &fake).is_none(),
        "nothing enrolled"
    );

    let (slot, key) = device::enroll(&fake).unwrap();
    assert_eq!(slot.kind, DeviceKind::TouchId);
    assert_eq!(slot.data, b"fingerprints");
    vault.enroll_device(slot.clone(), &key).unwrap();

    let credential = device::credential(&path, &fake).unwrap().unwrap();
    assert_eq!(credential.id, slot.id);
    assert_eq!(credential.key.expose(), hex::encode(key.as_bytes()));
    Vault::unlock_with_device(&path, &slot.id, &key).unwrap();

    fake.forget(&slot.id);
    let error = device::credential(&path, &fake).unwrap().unwrap_err();
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
