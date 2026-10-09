//! Random bytes, Argon2id key derivation and XChaCha20-Poly1305 sealing.

use std::fmt;

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::VaultError;

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 24;
pub const SALT_LEN: usize = 16;

/// Upper bound on Argon2 memory read from a vault header (1 GiB), so a
/// tampered header cannot make unlock allocate unbounded memory.
const MAX_KDF_MEMORY_KIB: u32 = 1024 * 1024;
/// Upper bounds on Argon2 passes and lanes read from a vault header, so a
/// tampered header cannot make unlock run for hours.
pub const MAX_KDF_PASSES: u32 = 16;
pub const MAX_KDF_LANES: u32 = 8;

/// A 256-bit symmetric key. Zeroed on drop and never printed. Lives in its
/// own heap allocation, which is locked into RAM where the OS allows it so
/// the key is not written to swap.
pub struct SymmetricKey(Box<Zeroizing<[u8; KEY_LEN]>>);

impl SymmetricKey {
    pub fn generate() -> Self {
        let mut key = Self::zeroed();
        fill_random(key.0.as_mut_slice());
        key
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self, VaultError> {
        if bytes.len() != KEY_LEN {
            return Err(VaultError::Corrupted);
        }
        let mut key = Self::zeroed();
        key.0.copy_from_slice(bytes);
        Ok(key)
    }

    /// Allocates and memory-locks the key before any secret byte is written
    /// to it. Locking is best effort: it can fail under a low `RLIMIT_MEMLOCK`,
    /// and locked pages stay locked for the life of the process.
    fn zeroed() -> Self {
        let key = Box::new(Zeroizing::new([0u8; KEY_LEN]));
        if let Ok(guard) = region::lock(key.as_ptr(), KEY_LEN) {
            std::mem::forget(guard);
        }
        Self(key)
    }

    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

impl fmt::Debug for SymmetricKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SymmetricKey([REDACTED])")
    }
}

/// Argon2id cost parameters, stored in the vault header next to each salt.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
}

impl KdfParams {
    /// 64 MiB, 3 passes, 1 lane.
    pub const RECOMMENDED: Self = Self {
        m_kib: 64 * 1024,
        t: 3,
        p: 1,
    };
}

pub fn fill_random(buf: &mut [u8]) {
    getrandom::fill(buf).expect("the OS random number generator is unavailable");
}

pub fn random_nonce() -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    fill_random(&mut nonce);
    nonce
}

pub fn random_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    fill_random(&mut salt);
    salt
}

pub fn derive_key(
    passphrase: &[u8],
    salt: &[u8],
    params: KdfParams,
) -> Result<SymmetricKey, VaultError> {
    if params.m_kib > MAX_KDF_MEMORY_KIB || params.t > MAX_KDF_PASSES || params.p > MAX_KDF_LANES {
        return Err(VaultError::Corrupted);
    }
    let argon_params = Params::new(params.m_kib, params.t, params.p, Some(KEY_LEN))
        .map_err(|_| VaultError::Corrupted)?;
    let mut out = SymmetricKey::zeroed();
    Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params)
        .hash_password_into(passphrase, salt, out.0.as_mut_slice())
        .map_err(|_| VaultError::Corrupted)?;
    Ok(out)
}

pub fn seal(key: &SymmetricKey, nonce: &[u8; NONCE_LEN], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    cipher(key)
        .encrypt(
            &XNonce::from(*nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .expect("XChaCha20-Poly1305 encryption of an in-memory buffer cannot fail")
}

/// Returns `None` when the key is wrong or the ciphertext, nonce or AAD were
/// modified.
pub fn open(
    key: &SymmetricKey,
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> Option<Zeroizing<Vec<u8>>> {
    let nonce: [u8; NONCE_LEN] = nonce.try_into().ok()?;
    cipher(key)
        .decrypt(
            &XNonce::from(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .ok()
        .map(Zeroizing::new)
}

fn cipher(key: &SymmetricKey) -> XChaCha20Poly1305 {
    XChaCha20Poly1305::new_from_slice(key.as_bytes()).expect("key is 32 bytes")
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
    fn seal_then_open_round_trips() {
        let key = SymmetricKey::generate();
        let nonce = random_nonce();
        let ct = seal(&key, &nonce, b"aad", b"hello");
        assert_eq!(
            open(&key, &nonce, b"aad", &ct).unwrap().as_slice(),
            b"hello"
        );
    }

    #[test]
    fn open_fails_with_wrong_key_aad_or_modified_ciphertext() {
        let key = SymmetricKey::generate();
        let nonce = random_nonce();
        let mut ct = seal(&key, &nonce, b"aad", b"hello");
        assert!(open(&SymmetricKey::generate(), &nonce, b"aad", &ct).is_none());
        assert!(open(&key, &nonce, b"other", &ct).is_none());
        assert!(open(&key, &nonce[..10], b"aad", &ct).is_none());
        ct[0] ^= 1;
        assert!(open(&key, &nonce, b"aad", &ct).is_none());
    }

    #[test]
    fn derive_key_is_deterministic_per_salt() {
        let a = derive_key(b"passphrase", b"salt-salt-salt-1", FAST).unwrap();
        let b = derive_key(b"passphrase", b"salt-salt-salt-1", FAST).unwrap();
        let c = derive_key(b"passphrase", b"salt-salt-salt-2", FAST).unwrap();
        assert_eq!(a.as_bytes(), b.as_bytes());
        assert_ne!(a.as_bytes(), c.as_bytes());
    }

    #[test]
    fn derive_key_rejects_oversized_memory_cost() {
        let huge = KdfParams {
            m_kib: MAX_KDF_MEMORY_KIB + 1,
            t: 1,
            p: 1,
        };
        assert!(matches!(
            derive_key(b"passphrase", b"salt-salt-salt-1", huge),
            Err(VaultError::Corrupted)
        ));
    }

    #[test]
    fn debug_output_hides_key_bytes() {
        let key = SymmetricKey::from_slice(&[7u8; KEY_LEN]).unwrap();
        assert_eq!(format!("{key:?}"), "SymmetricKey([REDACTED])");
    }

    #[test]
    fn derive_key_rejects_excessive_passes_or_lanes() {
        for params in [
            KdfParams {
                m_kib: 8,
                t: MAX_KDF_PASSES + 1,
                p: 1,
            },
            KdfParams {
                m_kib: 64,
                t: 1,
                p: MAX_KDF_LANES + 1,
            },
        ] {
            assert!(matches!(
                derive_key(b"passphrase", b"salt-salt-salt-1", params),
                Err(VaultError::Corrupted)
            ));
        }
        let most = KdfParams {
            m_kib: 8 * MAX_KDF_LANES,
            t: MAX_KDF_PASSES,
            p: MAX_KDF_LANES,
        };
        assert!(derive_key(b"passphrase", b"salt-salt-salt-1", most).is_ok());
    }
}
