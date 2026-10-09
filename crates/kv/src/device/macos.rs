//! Touch ID through LocalAuthentication, with the key in the login keychain.

use std::sync::mpsc;
use std::time::Duration;

use block2::RcBlock;
use kv_core::crypto::SymmetricKey;
use kv_core::vault::{DeviceKind, DeviceSlot};
use objc2::rc::Retained;
use objc2::runtime::Bool;
use objc2_foundation::{NSError, NSString};
use objc2_local_authentication::{LAContext, LAPolicy};
use security_framework::passwords::{
    delete_generic_password, get_generic_password, set_generic_password,
};
use zeroize::Zeroizing;

use super::Device;

const SERVICE: &str = "kv vault";
const POLICY: LAPolicy = LAPolicy::DeviceOwnerAuthenticationWithBiometrics;
/// How long kv waits for a fingerprint.
const PROMPT_TIMEOUT: Duration = Duration::from_secs(120);

pub struct TouchId;

impl Device for TouchId {
    fn kind(&self) -> DeviceKind {
        DeviceKind::TouchId
    }

    fn available(&self) -> Result<(), String> {
        context().map(drop)
    }

    fn enroll(&self, id: &str) -> Result<(Vec<u8>, SymmetricKey), String> {
        let context = context()?;
        let fingerprints = fingerprints(&context)?;
        ask(&context, "turn on Touch ID unlock for kv")?;
        let key = SymmetricKey::generate();
        set_generic_password(SERVICE, id, key.as_bytes())
            .map_err(|e| format!("could not save the key in the login keychain: {e}"))?;
        Ok((fingerprints, key))
    }

    fn unlock(&self, slot: &DeviceSlot, reason: &str) -> Result<SymmetricKey, String> {
        let context = context()?;
        if fingerprints(&context)? != slot.data {
            return Err(
                "the fingerprints on this Mac changed since Touch ID unlock was turned \
                        on; run `kv biometric enable` again"
                    .into(),
            );
        }
        ask(&context, reason)?;
        let raw = get_generic_password(SERVICE, &slot.id)
            .map(Zeroizing::new)
            .map_err(|e| {
                format!(
                    "could not read the key from the login keychain ({e}); run `kv biometric \
                     enable` again"
                )
            })?;
        SymmetricKey::from_slice(&raw).map_err(|_| "the keychain item is damaged".into())
    }

    fn forget(&self, id: &str) {
        let _ = delete_generic_password(SERVICE, id);
    }
}

fn context() -> Result<Retained<LAContext>, String> {
    let context = unsafe { LAContext::new() };
    unsafe { context.canEvaluatePolicy_error(POLICY) }
        .map_err(|e| format!("Touch ID is not available: {}", e.localizedDescription()))?;
    Ok(context)
}

/// The set of enrolled fingerprints, as an opaque value that changes when a
/// finger is added or removed.
#[allow(deprecated)]
fn fingerprints(context: &LAContext) -> Result<Vec<u8>, String> {
    unsafe { context.evaluatedPolicyDomainState() }
        .map(|state| state.to_vec())
        .ok_or_else(|| "macOS did not report the enrolled fingerprints".into())
}

/// Shows the Touch ID prompt and waits for the answer.
fn ask(context: &LAContext, reason: &str) -> Result<(), String> {
    let (tx, rx) = mpsc::channel();
    let reply = RcBlock::new(move |ok: Bool, error: *mut NSError| {
        let why = match unsafe { error.as_ref() } {
            Some(error) => error.localizedDescription().to_string(),
            None => "Touch ID failed".to_owned(),
        };
        let _ = tx.send(if ok.as_bool() { Ok(()) } else { Err(why) });
    });
    unsafe {
        context.evaluatePolicy_localizedReason_reply(POLICY, &NSString::from_str(reason), &reply);
    }
    match rx.recv_timeout(PROMPT_TIMEOUT) {
        Ok(answer) => answer,
        Err(_) => {
            // Takes the sheet down; otherwise it stays up after kv moved on.
            unsafe { context.invalidate() };
            Err("no answer from Touch ID in time".into())
        }
    }
}
