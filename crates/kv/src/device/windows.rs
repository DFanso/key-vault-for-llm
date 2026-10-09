//! Windows Hello through `KeyCredentialManager`. The credential's RSA
//! signature (PKCS #1 v1.5, so the same every time) over a random challenge
//! kept in the vault is turned into the key with HKDF-SHA256.

use hkdf::Hkdf;
use kv_core::crypto::{KEY_LEN, SymmetricKey};
use kv_core::vault::{DeviceKind, DeviceSlot};
use sha2::Sha256;
use windows::Security::Credentials::{
    KeyCredential, KeyCredentialCreationOption, KeyCredentialManager, KeyCredentialStatus,
};
use windows::Security::Cryptography::CryptographicBuffer;
use windows::core::{Array, HSTRING};
use zeroize::Zeroizing;

use super::Device;

const SALT: &[u8] = b"kv-windows-hello-v1";
const CHALLENGE_LEN: usize = 32;

pub struct Hello;

impl Device for Hello {
    fn kind(&self) -> DeviceKind {
        DeviceKind::WindowsHello
    }

    fn available(&self) -> Result<(), String> {
        let supported = KeyCredentialManager::IsSupportedAsync()
            .and_then(|op| op.join())
            .map_err(|e| format!("Windows Hello is not available: {}", e.message()))?;
        if supported {
            Ok(())
        } else {
            Err("Windows Hello is not set up on this computer".into())
        }
    }

    fn enroll(&self, id: &str) -> Result<(Vec<u8>, SymmetricKey), String> {
        let result = KeyCredentialManager::RequestCreateAsync(
            &HSTRING::from(id),
            KeyCredentialCreationOption::ReplaceExisting,
        )
        .and_then(|op| op.join())
        .map_err(|e| e.message())?;
        check(result.Status())?;
        let credential = result.Credential().map_err(|e| e.message())?;
        let mut challenge = vec![0u8; CHALLENGE_LEN];
        kv_core::crypto::fill_random(&mut challenge);
        let key = derive(&credential, &challenge)?;
        Ok((challenge, key))
    }

    fn unlock(&self, slot: &DeviceSlot) -> Result<SymmetricKey, String> {
        let result = KeyCredentialManager::OpenAsync(&HSTRING::from(slot.id.as_str()))
            .and_then(|op| op.join())
            .map_err(|e| e.message())?;
        check(result.Status())?;
        let credential = result.Credential().map_err(|e| e.message())?;
        derive(&credential, &slot.data)
    }

    fn forget(&self, id: &str) {
        let _ = KeyCredentialManager::DeleteAsync(&HSTRING::from(id)).and_then(|op| op.join());
    }
}

fn derive(credential: &KeyCredential, challenge: &[u8]) -> Result<SymmetricKey, String> {
    let data = CryptographicBuffer::CreateFromByteArray(challenge).map_err(|e| e.message())?;
    let result = credential
        .RequestSignAsync(&data)
        .and_then(|op| op.join())
        .map_err(|e| e.message())?;
    check(result.Status())?;
    let signature = result.Result().map_err(|e| e.message())?;
    let mut bytes = Array::<u8>::new();
    CryptographicBuffer::CopyToByteArray(&signature, &mut bytes).map_err(|e| e.message())?;
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    Hkdf::<Sha256>::new(Some(SALT), &bytes)
        .expand(b"vault wrapping key", key.as_mut_slice())
        .map_err(|_| "could not derive the key".to_owned())?;
    SymmetricKey::from_slice(key.as_slice()).map_err(|e| e.to_string())
}

fn check(status: windows::core::Result<KeyCredentialStatus>) -> Result<(), String> {
    match status.map_err(|e| e.message())? {
        KeyCredentialStatus::Success => Ok(()),
        KeyCredentialStatus::UserCanceled => Err("Windows Hello was cancelled".into()),
        KeyCredentialStatus::NotFound => {
            Err("the Windows Hello key for kv is gone; run `kv biometric enable` again".into())
        }
        KeyCredentialStatus::UserPrefersPassword => {
            Err("Windows Hello was declined; use the passphrase".into())
        }
        other => Err(format!("Windows Hello failed (status {})", other.0)),
    }
}
