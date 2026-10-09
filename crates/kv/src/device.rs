//! Unlocking with Touch ID (macOS) or Windows Hello. The client asks the
//! user through the platform and gets a 256-bit key, which it sends to the
//! daemon in place of the passphrase; the vault keeps the vault key wrapped
//! under it (see `kv_core::vault`). The daemon never talks to the platform.
//!
//! Touch ID: a random key in the login keychain, read only after macOS
//! confirms a fingerprint. The keychain lets only the `kv` binary that
//! saved the item read it without asking for the login password, and kv
//! refuses the key if the Mac's enrolled fingerprints changed since. Windows
//! Hello: a key derived from the Hello credential's signature over a random
//! challenge kept in the vault.
//!
//! Set `KV_BIOMETRIC=off` to never use either.

use std::ffi::OsStr;
use std::path::Path;

use kv_core::crypto::{SymmetricKey, fill_random};
use kv_core::proto::{ControlCommand, DeviceCredential};
use kv_core::secret::SecretText;
use kv_core::vault::{DeviceKind, DeviceSlot, device_slots};
use zeroize::Zeroizing;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(windows)]
mod windows;

/// A platform's way to get a key from the user.
pub trait Device: Send + Sync {
    fn kind(&self) -> DeviceKind;
    /// `Err` says why the user cannot use it now.
    fn available(&self) -> Result<(), String>;
    /// Sets the device up under `id`, asking the user once, and returns what
    /// the vault should keep for it and the key.
    fn enroll(&self, id: &str) -> Result<(Vec<u8>, SymmetricKey), String>;
    /// Asks the user and returns the key for `slot`.
    fn unlock(&self, slot: &DeviceSlot) -> Result<SymmetricKey, String>;
    /// Deletes what the platform keeps for `id`, if anything.
    fn forget(&self, id: &str);
}

/// This platform's device, unless `KV_BIOMETRIC` turns it off.
pub fn platform() -> Option<Box<dyn Device>> {
    if !enabled(std::env::var_os("KV_BIOMETRIC").as_deref()) {
        return None;
    }
    native()
}

/// This platform's device whatever `KV_BIOMETRIC` says, for turning it off.
#[cfg(target_os = "macos")]
pub fn native() -> Option<Box<dyn Device>> {
    Some(Box::new(macos::TouchId))
}

#[cfg(windows)]
pub fn native() -> Option<Box<dyn Device>> {
    Some(Box::new(windows::Hello))
}

#[cfg(not(any(target_os = "macos", windows)))]
pub fn native() -> Option<Box<dyn Device>> {
    None
}

/// Whether a `KV_BIOMETRIC` value leaves device unlock on.
pub fn enabled(setting: Option<&OsStr>) -> bool {
    let Some(setting) = setting.and_then(OsStr::to_str) else {
        return true;
    };
    !["off", "0", "false", "no"]
        .iter()
        .any(|off| setting.eq_ignore_ascii_case(off))
}

/// A fresh name for the platform to keep a device key under.
pub fn new_id() -> String {
    let mut bytes = [0u8; 16];
    fill_random(&mut bytes);
    format!("kv-{}", hex::encode(bytes))
}

/// Sets `device` up under a new id. The caller enrolls the slot with the
/// daemon, and forgets the id if that fails.
pub fn enroll(device: &dyn Device) -> Result<(DeviceSlot, SymmetricKey), String> {
    device.available()?;
    let id = new_id();
    let (data, key) = device.enroll(&id)?;
    let slot = DeviceSlot {
        kind: device.kind(),
        id,
        data,
    };
    Ok((slot, key))
}

pub fn enroll_command(slot: DeviceSlot, key: &SymmetricKey) -> ControlCommand {
    ControlCommand::EnrollDevice {
        kind: slot.kind,
        id: slot.id,
        data: hex::encode(slot.data),
        key: hex_secret(key),
    }
}

/// Asks `device` for the key to the vault's slot of its kind. `None` if the
/// vault has no such slot (or cannot be read: the daemon will say why).
pub fn credential(vault: &Path, device: &dyn Device) -> Option<Result<DeviceCredential, String>> {
    let slot = device_slots(vault)
        .ok()?
        .into_iter()
        .find(|slot| slot.kind == device.kind())?;
    Some(device.unlock(&slot).map(|key| DeviceCredential {
        id: slot.id,
        key: hex_secret(&key),
    }))
}

fn hex_secret(key: &SymmetricKey) -> SecretText {
    let text = Zeroizing::new(hex::encode(key.as_bytes()));
    SecretText::new(text.as_str())
}
