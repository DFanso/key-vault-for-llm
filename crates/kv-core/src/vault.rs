//! The encrypted vault file.
//!
//! Layout: `MAGIC | version (u16 LE) | header length (u32 LE) | header JSON |
//! payload ciphertext`. A random vault key encrypts the payload; the vault
//! key is stored wrapped once per unlock method. Everything before the
//! payload is the payload's associated data, so header edits are detected.

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

#[derive(Serialize, Deserialize)]
struct Header {
    wrapped_keys: Vec<WrappedKey>,
    #[serde(with = "b64")]
    payload_nonce: Vec<u8>,
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
}

#[derive(Default, Serialize, Deserialize)]
struct VaultData {
    secrets: Vec<Secret>,
}

pub struct Vault {
    path: PathBuf,
    key: SymmetricKey,
    wrapped_keys: Vec<WrappedKey>,
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
            wrapped_keys: vec![wrapped],
            data: VaultData::default(),
        };
        vault.save()?;
        Ok(vault)
    }

    pub fn unlock(path: &Path, passphrase: &str) -> Result<Self, VaultError> {
        let bytes = match fs::read(path) {
            Ok(b) => b,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Err(VaultError::NotFound(path.to_owned()));
            }
            Err(e) => return Err(e.into()),
        };
        let (header, aad, payload) = parse(&bytes)?;

        let mut key = None;
        for wrapped in &header.wrapped_keys {
            let WrappedKey::Passphrase {
                kdf,
                salt,
                nonce,
                ciphertext,
            } = wrapped;
            let wrapping_key = crypto::derive_key(passphrase.as_bytes(), salt, *kdf)?;
            if let Some(raw) = crypto::open(&wrapping_key, nonce, WRAP_AAD, ciphertext) {
                key = Some(SymmetricKey::from_slice(&raw)?);
                break;
            }
        }
        let key = key.ok_or(VaultError::WrongPassphrase)?;

        let plaintext =
            crypto::open(&key, &header.payload_nonce, aad, payload).ok_or(VaultError::Corrupted)?;
        let data: VaultData =
            serde_json::from_slice(&plaintext).map_err(|_| VaultError::Corrupted)?;
        Ok(Self {
            path: path.to_owned(),
            key,
            wrapped_keys: header.wrapped_keys,
            data,
        })
    }

    /// Encrypts with a fresh nonce and atomically replaces the file, keeping
    /// the previous version as `<path>.bak`.
    pub fn save(&self) -> Result<(), VaultError> {
        self.write(&self.wrapped_keys)
    }

    fn write(&self, wrapped_keys: &[WrappedKey]) -> Result<(), VaultError> {
        let nonce = crypto::random_nonce();
        let header = Header {
            wrapped_keys: wrapped_keys.to_vec(),
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
        let ciphertext = crypto::seal(&self.key, &nonce, &out, &plaintext);
        out.extend_from_slice(&ciphertext);
        write_atomic(&self.path, &out)?;
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

    /// Re-wraps the vault key under a new passphrase and saves. If the save
    /// fails, the old passphrase stays in effect.
    pub fn change_passphrase(
        &mut self,
        new_passphrase: &str,
        kdf: KdfParams,
    ) -> Result<(), VaultError> {
        check_passphrase(new_passphrase)?;
        let mut wrapped_keys: Vec<WrappedKey> = self
            .wrapped_keys
            .iter()
            .filter(|w| !matches!(w, WrappedKey::Passphrase { .. }))
            .cloned()
            .collect();
        wrapped_keys.push(wrap_with_passphrase(&self.key, new_passphrase, kdf)?);
        self.write(&wrapped_keys)?;
        self.wrapped_keys = wrapped_keys;
        Ok(())
    }
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
    Ok((header, &bytes[..header_end], &bytes[header_end..]))
}

fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let dir = path
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(dir)?;
    let tmp = with_suffix(path, ".tmp");
    let _ = fs::remove_file(&tmp);
    {
        let mut file = open_private(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    if path.exists() {
        fs::copy(path, with_suffix(path, ".bak"))?;
    }
    fs::rename(&tmp, path)?;
    #[cfg(unix)]
    File::open(dir)?.sync_all()?;
    Ok(())
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
