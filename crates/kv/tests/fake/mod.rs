//! A stand-in for Touch ID: keys live in memory, and `refuse` plays a
//! device the user cannot use right now.
#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::Mutex;

use kv::device::Device;
use kv_core::crypto::SymmetricKey;
use kv_core::vault::{DeviceKind, DeviceSlot};

#[derive(Default)]
pub struct Fake {
    pub keys: Mutex<HashMap<String, [u8; 32]>>,
    pub refuse: Option<&'static str>,
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
