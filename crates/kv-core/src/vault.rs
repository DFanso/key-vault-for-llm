//! The encrypted vault file.
//!
//! Layout: `MAGIC | version (u16 LE) | header length (u32 LE) | header JSON |
//! payload ciphertext`. A random vault key encrypts the payload; the vault
//! key is stored wrapped once per unlock method. Everything before the
//! payload is the payload's associated data, so header edits are detected.
//!
//! Unlock methods are the passphrase and devices (Touch ID, Windows Hello),
//! whose keys come from the platform. A wrapped key of a method this version
//! does not know is kept as it is and skipped, so a vault a newer kv wrote
//! still opens with the passphrase.

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::crypto::{self, KdfParams, SymmetricKey};
use crate::error::VaultError;
use crate::secret::{Secret, validate_handle};

const MAGIC: &[u8; 4] = b"KVLT";
const FORMAT_VERSION: u16 = 1;
const PREFIX_LEN: usize = 4 + 2 + 4;
const WRAP_AAD: &[u8] = b"kv-wrap-v1";
const MIN_PASSPHRASE_CHARS: usize = 8;
/// More wrapped keys than this, or more passphrase wraps, mark a tampered
/// header: each passphrase wrap costs an Argon2 derivation to try.
const MAX_WRAPPED_KEYS: usize = 8;
const MAX_PASSPHRASE_WRAPS: usize = 2;

#[derive(Serialize, Deserialize)]
struct Header {
    wrapped_keys: Vec<Slot>,
    #[serde(with = "b64")]
    payload_nonce: Vec<u8>,
}

/// A device that can unlock the vault in place of the passphrase.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceKind {
    TouchId,
    WindowsHello,
}

impl DeviceKind {
    const NAMES: [&str; 2] = ["touch_id", "windows_hello"];

    pub fn label(self) -> &'static str {
        match self {
            Self::TouchId => "Touch ID",
            Self::WindowsHello => "Windows Hello",
        }
    }
}

/// What a device needs, besides the user, to produce the key that opens its
/// slot: the platform's name for its key (`id`) and anything else it keeps
/// in the vault header (`data`: Windows Hello's challenge, or the Touch ID
/// fingerprint set it was enrolled with). None of it is secret.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceSlot {
    pub kind: DeviceKind,
    pub id: String,
    pub data: Vec<u8>,
}

#[derive(Clone)]
enum Slot {
    Known(WrappedKey),
    /// A method this version does not know, kept as it was read.
    Unknown(serde_json::Value),
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "method", rename_all = "lowercase")]
enum WrappedKey {
    Passphrase {
        kdf: KdfParams,
        #[serde(with = "b64")]
        salt: Vec<u8>,
        #[serde(with = "b64")]
        nonce: Vec<u8>,
        #[serde(with = "b64")]
        ciphertext: Vec<u8>,
    },
    Device {
        device: DeviceKind,
        id: String,
        #[serde(with = "b64")]
        data: Vec<u8>,
        #[serde(with = "b64")]
        nonce: Vec<u8>,
        #[serde(with = "b64")]
        ciphertext: Vec<u8>,
    },
}

impl WrappedKey {
    fn device(&self) -> Option<DeviceSlot> {
        match self {
            Self::Device {
                device, id, data, ..
            } => Some(DeviceSlot {
                kind: *device,
                id: id.clone(),
                data: data.clone(),
            }),
            Self::Passphrase { .. } => None,
        }
    }
}

impl Serialize for Slot {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Known(key) => key.serialize(s),
            Self::Unknown(value) => value.serialize(s),
        }
    }
}

impl<'de> Deserialize<'de> for Slot {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        use serde::de::Error;
        let value = serde_json::Value::deserialize(d)?;
        let known = match value.get("method").and_then(serde_json::Value::as_str) {
            Some("passphrase") => true,
            Some("device") => value
                .get("device")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|kind| DeviceKind::NAMES.contains(&kind)),
            Some(_) => false,
            None => return Err(D::Error::custom("a wrapped key names no method")),
        };
        if !known {
            return Ok(Self::Unknown(value));
        }
        WrappedKey::deserialize(value)
            .map(Self::Known)
            .map_err(D::Error::custom)
    }
}

#[derive(Default, Serialize, Deserialize)]
struct VaultData {
    secrets: Vec<Secret>,
}

pub struct Vault {
    path: PathBuf,
    key: SymmetricKey,
    slots: Vec<Slot>,
    data: VaultData,
}

impl fmt::Debug for Vault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Vault")
            .field("path", &self.path)
            .field("secrets", &self.data.secrets.len())
            .finish_non_exhaustive()
    }
}

impl Vault {
    /// Creates a new empty vault and writes it to `path`.
    pub fn create(path: &Path, passphrase: &str, kdf: KdfParams) -> Result<Self, VaultError> {
        if path.exists() {
            return Err(VaultError::AlreadyExists(path.to_owned()));
        }
        check_passphrase(passphrase)?;
        let key = SymmetricKey::generate();
        let wrapped = wrap_with_passphrase(&key, passphrase, kdf)?;
        let vault = Self {
            path: path.to_owned(),
            key,
            slots: vec![Slot::Known(wrapped)],
            data: VaultData::default(),
        };
        vault.save()?;
        Ok(vault)
    }

    pub fn unlock(path: &Path, passphrase: &str) -> Result<Self, VaultError> {
        let bytes = read(path)?;
        let (header, aad, payload) = parse(&bytes)?;
        let key = unwrap_with_passphrase(&header.wrapped_keys, passphrase)?;
        Self::open(path, key, header, aad, payload)
    }

    /// Unlocks with the key a device produced for the slot `id`.
    pub fn unlock_with_device(
        path: &Path,
        id: &str,
        wrapping_key: &SymmetricKey,
    ) -> Result<Self, VaultError> {
        let bytes = read(path)?;
        let (header, aad, payload) = parse(&bytes)?;
        let key = unwrap_with_device(&header.wrapped_keys, id, wrapping_key)?;
        Self::open(path, key, header, aad, payload)
    }

    fn open(
        path: &Path,
        key: SymmetricKey,
        header: Header,
        aad: &[u8],
        payload: &[u8],
    ) -> Result<Self, VaultError> {
        let plaintext =
            crypto::open(&key, &header.payload_nonce, aad, payload).ok_or(VaultError::Corrupted)?;
        let data: VaultData =
            serde_json::from_slice(&plaintext).map_err(|_| VaultError::Corrupted)?;
        Ok(Self {
            path: path.to_owned(),
            key,
            slots: header.wrapped_keys,
            data,
        })
    }

    /// Encrypts with a fresh nonce and atomically replaces the file, keeping
    /// the previous version as `<path>.bak`.
    pub fn save(&self) -> Result<(), VaultError> {
        let bytes = self.encode(&self.key, &self.slots);
        write_atomic(&self.path, &bytes, Backup::KeepPrevious)?;
        Ok(())
    }

    /// Serializes and encrypts the vault under `key` with a fresh nonce.
    fn encode(&self, key: &SymmetricKey, slots: &[Slot]) -> Vec<u8> {
        let nonce = crypto::random_nonce();
        let header = Header {
            wrapped_keys: slots.to_vec(),
            payload_nonce: nonce.to_vec(),
        };
        let header_json = serde_json::to_vec(&header).expect("header serializes");
        let header_len = u32::try_from(header_json.len()).expect("header fits in u32");

        let mut out = Vec::with_capacity(PREFIX_LEN + header_json.len());
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
        out.extend_from_slice(&header_len.to_le_bytes());
        out.extend_from_slice(&header_json);

        let plaintext = Zeroizing::new(serde_json::to_vec(&self.data).expect("secrets serialize"));
        let ciphertext = crypto::seal(key, &nonce, &out, &plaintext);
        out.extend_from_slice(&ciphertext);
        out
    }

    /// Checks `passphrase` against the vault's passphrase wrap without reading
    /// the file. Costs one Argon2 derivation, like `unlock`.
    pub fn verify_passphrase(&self, passphrase: &str) -> Result<(), VaultError> {
        let key = unwrap_with_passphrase(&self.slots, passphrase)?;
        if key.as_bytes() == self.key.as_bytes() {
            Ok(())
        } else {
            Err(VaultError::WrongPassphrase)
        }
    }

    /// Checks a device's key against its slot without reading the file.
    pub fn verify_device(&self, id: &str, wrapping_key: &SymmetricKey) -> Result<(), VaultError> {
        let key = unwrap_with_device(&self.slots, id, wrapping_key)?;
        if key.as_bytes() == self.key.as_bytes() {
            Ok(())
        } else {
            Err(VaultError::DeviceKeyRejected)
        }
    }

    /// The devices that can unlock the vault.
    pub fn devices(&self) -> Vec<DeviceSlot> {
        devices(&self.slots)
    }

    /// Lets the device's key unlock the vault, replacing any slot of the
    /// same kind, and saves. If the save fails, nothing changes.
    pub fn enroll_device(
        &mut self,
        slot: DeviceSlot,
        wrapping_key: &SymmetricKey,
    ) -> Result<(), VaultError> {
        let nonce = crypto::random_nonce();
        let wrapped = WrappedKey::Device {
            device: slot.kind,
            id: slot.id,
            data: slot.data,
            nonce: nonce.to_vec(),
            ciphertext: crypto::seal(wrapping_key, &nonce, WRAP_AAD, self.key.as_bytes()),
        };
        let mut slots = without_device(&self.slots, slot.kind);
        slots.push(Slot::Known(wrapped));
        self.replace_slots(slots)
    }

    /// Removes the slot of `kind`, if there is one, and saves.
    pub fn remove_device(&mut self, kind: DeviceKind) -> Result<Option<DeviceSlot>, VaultError> {
        let Some(removed) = self.devices().into_iter().find(|slot| slot.kind == kind) else {
            return Ok(None);
        };
        self.replace_slots(without_device(&self.slots, kind))?;
        Ok(Some(removed))
    }

    fn replace_slots(&mut self, slots: Vec<Slot>) -> Result<(), VaultError> {
        let bytes = self.encode(&self.key, &slots);
        write_atomic(&self.path, &bytes, Backup::KeepPrevious)?;
        self.slots = slots;
        Ok(())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn secrets(&self) -> &[Secret] {
        &self.data.secrets
    }

    pub fn get(&self, name: &str) -> Option<&Secret> {
        self.data.secrets.iter().find(|s| s.name == name)
    }

    /// Inserts or replaces by name and sets the timestamps. Call `save` to
    /// persist.
    pub fn upsert(&mut self, mut secret: Secret) -> Result<(), VaultError> {
        validate_handle(&secret.name)?;
        let now = unix_now();
        secret.updated_at = now;
        match self.data.secrets.iter_mut().find(|s| s.name == secret.name) {
            Some(existing) => {
                secret.created_at = existing.created_at;
                *existing = secret;
            }
            None => {
                secret.created_at = now;
                self.data.secrets.push(secret);
            }
        }
        Ok(())
    }

    /// Returns whether a secret was removed. Call `save` to persist.
    pub fn remove(&mut self, name: &str) -> bool {
        let before = self.data.secrets.len();
        self.data.secrets.retain(|s| s.name != name);
        self.data.secrets.len() != before
    }

    /// Generates a new vault key, wraps it under the new passphrase and
    /// re-encrypts everything, so the old passphrase opens neither the new
    /// file nor `.bak`. Other unlock methods are dropped and must be enrolled
    /// again. If the save fails, nothing changes.
    pub fn change_passphrase(
        &mut self,
        new_passphrase: &str,
        kdf: KdfParams,
    ) -> Result<(), VaultError> {
        check_passphrase(new_passphrase)?;
        let key = SymmetricKey::generate();
        let slots = vec![Slot::Known(wrap_with_passphrase(
            &key,
            new_passphrase,
            kdf,
        )?)];
        let bytes = self.encode(&key, &slots);
        write_atomic(&self.path, &bytes, Backup::Replace)?;
        self.key = key;
        self.slots = slots;
        Ok(())
    }
}

/// The device slots of the vault at `path`, read from its header: no key is
/// needed to know which devices can unlock it.
pub fn device_slots(path: &Path) -> Result<Vec<DeviceSlot>, VaultError> {
    let bytes = read(path)?;
    let (header, _, _) = parse(&bytes)?;
    Ok(devices(&header.wrapped_keys))
}

fn read(path: &Path) -> Result<Vec<u8>, VaultError> {
    match fs::read(path) {
        Ok(bytes) => Ok(bytes),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Err(VaultError::NotFound(path.to_owned())),
        Err(e) => Err(e.into()),
    }
}

fn devices(slots: &[Slot]) -> Vec<DeviceSlot> {
    slots
        .iter()
        .filter_map(|slot| match slot {
            Slot::Known(key) => key.device(),
            Slot::Unknown(_) => None,
        })
        .collect()
}

fn without_device(slots: &[Slot], kind: DeviceKind) -> Vec<Slot> {
    slots
        .iter()
        .filter(|slot| !matches!(slot, Slot::Known(key) if key.device().is_some_and(|d| d.kind == kind)))
        .cloned()
        .collect()
}

fn unwrap_with_passphrase(slots: &[Slot], passphrase: &str) -> Result<SymmetricKey, VaultError> {
    for slot in slots {
        let Slot::Known(WrappedKey::Passphrase {
            kdf,
            salt,
            nonce,
            ciphertext,
        }) = slot
        else {
            continue;
        };
        let wrapping_key = crypto::derive_key(passphrase.as_bytes(), salt, *kdf)?;
        if let Some(raw) = crypto::open(&wrapping_key, nonce, WRAP_AAD, ciphertext) {
            return SymmetricKey::from_slice(&raw);
        }
    }
    Err(VaultError::WrongPassphrase)
}

fn unwrap_with_device(
    slots: &[Slot],
    wanted: &str,
    wrapping_key: &SymmetricKey,
) -> Result<SymmetricKey, VaultError> {
    for slot in slots {
        if let Slot::Known(WrappedKey::Device {
            id,
            nonce,
            ciphertext,
            ..
        }) = slot
            && id == wanted
            && let Some(raw) = crypto::open(wrapping_key, nonce, WRAP_AAD, ciphertext)
        {
            return SymmetricKey::from_slice(&raw);
        }
    }
    Err(VaultError::DeviceKeyRejected)
}

fn check_passphrase(passphrase: &str) -> Result<(), VaultError> {
    if passphrase.chars().count() < MIN_PASSPHRASE_CHARS {
        return Err(VaultError::WeakPassphrase);
    }
    Ok(())
}

fn wrap_with_passphrase(
    key: &SymmetricKey,
    passphrase: &str,
    kdf: KdfParams,
) -> Result<WrappedKey, VaultError> {
    let salt = crypto::random_salt();
    let nonce = crypto::random_nonce();
    let wrapping_key = crypto::derive_key(passphrase.as_bytes(), &salt, kdf)?;
    Ok(WrappedKey::Passphrase {
        kdf,
        salt: salt.to_vec(),
        nonce: nonce.to_vec(),
        ciphertext: crypto::seal(&wrapping_key, &nonce, WRAP_AAD, key.as_bytes()),
    })
}

/// Splits a vault file into (header, associated data, payload ciphertext).
fn parse(bytes: &[u8]) -> Result<(Header, &[u8], &[u8]), VaultError> {
    if bytes.len() < PREFIX_LEN || &bytes[..4] != MAGIC {
        return Err(VaultError::Corrupted);
    }
    let version = u16::from_le_bytes([bytes[4], bytes[5]]);
    if version != FORMAT_VERSION {
        return Err(VaultError::UnsupportedVersion(version));
    }
    let header_len = u32::from_le_bytes([bytes[6], bytes[7], bytes[8], bytes[9]]) as usize;
    let header_end = PREFIX_LEN
        .checked_add(header_len)
        .filter(|&end| end <= bytes.len())
        .ok_or(VaultError::Corrupted)?;
    let header: Header = serde_json::from_slice(&bytes[PREFIX_LEN..header_end])
        .map_err(|_| VaultError::Corrupted)?;
    let passphrase_wraps = header
        .wrapped_keys
        .iter()
        .filter(|slot| matches!(slot, Slot::Known(WrappedKey::Passphrase { .. })))
        .count();
    if header.wrapped_keys.len() > MAX_WRAPPED_KEYS || passphrase_wraps > MAX_PASSPHRASE_WRAPS {
        return Err(VaultError::Corrupted);
    }
    Ok((header, &bytes[..header_end], &bytes[header_end..]))
}

/// What `.bak` holds after a write.
enum Backup {
    /// The version being replaced, for recovering from a bad edit.
    KeepPrevious,
    /// The new version too, so no older copy (for example one that opens with
    /// a retired passphrase) is left beside the vault.
    Replace,
}

fn write_atomic(path: &Path, bytes: &[u8], backup: Backup) -> io::Result<()> {
    let dir = path
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    if !dir.exists() {
        fs::create_dir_all(dir)?;
        // Only a directory kv creates is made private; an existing one keeps
        // the permissions its owner chose.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
        }
    }
    let tmp = with_suffix(path, ".tmp");
    write_new_file(&tmp, bytes)?;
    let bak = with_suffix(path, ".bak");
    match backup {
        Backup::KeepPrevious => {
            if path.exists() {
                fs::copy(path, &bak)?;
            }
        }
        Backup::Replace => {
            let bak_tmp = with_suffix(path, ".bak.tmp");
            write_new_file(&bak_tmp, bytes)?;
            fs::rename(&bak_tmp, &bak)?;
        }
    }
    fs::rename(&tmp, path)?;
    #[cfg(unix)]
    File::open(dir)?.sync_all()?;
    Ok(())
}

fn write_new_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let _ = fs::remove_file(path);
    let mut file = open_private(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

fn open_private(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

mod b64 {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(d)?;
        STANDARD.decode(text).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FAST: KdfParams = KdfParams {
        m_kib: 8,
        t: 1,
        p: 1,
    };

    #[test]
    fn change_passphrase_rotates_the_vault_key() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("vault.kv");
        let mut vault = Vault::create(&path, "correct horse battery", FAST).unwrap();
        let old_key = SymmetricKey::from_slice(vault.key.as_bytes()).unwrap();

        vault
            .change_passphrase("a brand new passphrase", FAST)
            .unwrap();

        assert_ne!(old_key.as_bytes(), vault.key.as_bytes());
        let bytes = fs::read(&path).unwrap();
        let (header, aad, payload) = parse(&bytes).unwrap();
        assert!(crypto::open(&old_key, &header.payload_nonce, aad, payload).is_none());
    }

    fn slot(method: &str) -> serde_json::Value {
        serde_json::json!({ "method": method, "nonce": "", "ciphertext": "" })
    }

    /// Rewrites the vault with `extra` wrapped keys appended to its header,
    /// re-encrypted so the file stays valid.
    fn with_extra_slots(vault: &Vault, extra: Vec<serde_json::Value>) {
        let mut slots = vault.slots.clone();
        slots.extend(extra.into_iter().map(Slot::Unknown));
        let bytes = vault.encode(&vault.key, &slots);
        write_atomic(&vault.path, &bytes, Backup::KeepPrevious).unwrap();
    }

    #[test]
    fn an_unknown_unlock_method_is_kept_and_skipped() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("vault.kv");
        let vault = Vault::create(&path, "correct horse battery", FAST).unwrap();
        let future = serde_json::json!({ "method": "passkey", "credential": "abc" });
        with_extra_slots(&vault, vec![future.clone()]);

        let unlocked = Vault::unlock(&path, "correct horse battery").unwrap();
        unlocked.save().unwrap();
        let bytes = fs::read(&path).unwrap();
        let (header, _, _) = parse(&bytes).unwrap();
        assert!(
            header
                .wrapped_keys
                .iter()
                .any(|slot| matches!(slot, Slot::Unknown(v) if *v == future))
        );
    }

    #[test]
    fn a_device_slot_of_an_unknown_kind_is_kept_too() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("vault.kv");
        let vault = Vault::create(&path, "correct horse battery", FAST).unwrap();
        let mut other = slot("device");
        other["device"] = "android".into();
        other["id"] = "x".into();
        other["data"] = "".into();
        with_extra_slots(&vault, vec![other]);
        let unlocked = Vault::unlock(&path, "correct horse battery").unwrap();
        assert!(unlocked.devices().is_empty());
    }

    #[test]
    fn a_header_with_too_many_wrapped_keys_is_refused_before_any_key_derivation() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("vault.kv");
        let vault = Vault::create(&path, "correct horse battery", FAST).unwrap();
        with_extra_slots(
            &vault,
            (0..MAX_WRAPPED_KEYS).map(|_| slot("passkey")).collect(),
        );
        let bytes = fs::read(&path).unwrap();
        assert!(matches!(parse(&bytes), Err(VaultError::Corrupted)));

        let passphrase = vault.slots[0].clone();
        let vault =
            Vault::create(&dir.path().join("two.kv"), "correct horse battery", FAST).unwrap();
        let mut slots = vault.slots.clone();
        slots.extend((0..MAX_PASSPHRASE_WRAPS).map(|_| passphrase.clone()));
        let bytes = vault.encode(&vault.key, &slots);
        assert!(matches!(parse(&bytes), Err(VaultError::Corrupted)));
    }

    #[test]
    fn a_wrapped_key_without_a_method_is_corrupt() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("vault.kv");
        let vault = Vault::create(&path, "correct horse battery", FAST).unwrap();
        with_extra_slots(&vault, vec![serde_json::json!({ "nonce": "" })]);
        assert!(matches!(
            Vault::unlock(&path, "correct horse battery"),
            Err(VaultError::Corrupted)
        ));
    }
}
