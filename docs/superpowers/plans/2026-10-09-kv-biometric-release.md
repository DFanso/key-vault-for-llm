# kv Plan 6: Touch ID, Windows Hello and prebuilt binaries Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let Touch ID (macOS) and Windows Hello stand in for the vault passphrase, ship prebuilt binaries for macOS, Linux and Windows, and close the deferred vault-header and CI items from earlier plans.

**Architecture:** The vault header gains device slots: the vault key wrapped under a 256-bit key that only the platform hands back after the user proves presence. Platform code runs only in the CLI and TUI processes (`kv::device`); they send the daemon a `DeviceCredential` (slot id + key) in place of the passphrase, so the daemon never talks to the platform and treats a wrong key like a wrong passphrase. Touch ID keeps its key in the login keychain and reads it after `LAContext` confirms a fingerprint; Windows Hello derives its key from a `KeyCredentialManager` signature. Releases are built by cargo-dist on version tags.

**Tech Stack:** Rust 2024 (MSRV 1.89), objc2 0.6 + objc2-local-authentication 0.3 + block2 0.6, security-framework 3, windows 0.62 (`Security_Credentials`, `Security_Cryptography`, `Storage_Streams`), hkdf 0.13 + sha2 0.11, hex 0.4, cargo-dist 0.33.0.

**Spec:** `docs/superpowers/specs/2026-10-08-kv-llm-secrets-broker-design.md` (section 3 "File format", section 5 "Unlock", sections 6 and 7). Task 7 writes the decisions below into it.

## Decisions this plan makes

Each is a choice for you to confirm or change.

- **Touch ID through LocalAuthentication and the login keychain, not `kSecAccessControlBiometryCurrentSet`.** The spec's keychain item with biometric access control (and any data-protection keychain item) fails with `errSecMissingEntitlement` (-34018) for unsigned `cargo install` builds; a spike confirmed it, and that `LAContext` works unsigned. kv keeps a random key in a legacy login keychain item (service `kv vault`, account the slot id), reads it only after `LAContext.evaluatePolicy(DeviceOwnerAuthenticationWithBiometrics)` succeeds, and stores the Mac's `evaluatedPolicyDomainState` in the slot so it refuses the key once fingerprints are added or removed, as `BiometryCurrentSet` would. The item's ACL trusts only the `kv` binary that saved it, so a new build asks for the login password once. Code injected into the `kv` binary (`DYLD_INSERT_LIBRARIES`; no hardened runtime) can skip the fingerprint: that is the threat model's same-user process, which can attack the daemon the same way.
- **Windows Hello:** a `KeyCredentialManager` credential named after the slot id signs a random 32-byte challenge kept in the slot; HKDF-SHA256 (salt `kv-windows-hello-v1`, info `vault wrapping key`) turns the RSA PKCS#1 v1.5 signature, which is deterministic, into the key.
- **The daemon stays platform-free.** `ControlRequest.device` carries the key; the daemon accepts it wherever it accepts the passphrase except `init`, `passwd` and enrolment, which always take the passphrase.
- **One slot per device kind.** Enrolling again replaces the slot (and the CLI forgets the old keychain item or credential). `kv passwd` drops every device slot (the spec already said so) and the CLI forgets this platform's keys.
- **Device first, passphrase as fallback.** Commands that take the passphrase ask the device first only when stdin is a terminal (scripts keep piping the passphrase), and ask for the passphrase if the user cancels or the daemon answers `WrongDeviceKey`. `kv tui` asks at start and on Ctrl-T. `KV_BIOMETRIC=off` turns it all off.
- **Command name:** `kv biometric enable|disable`; `kv status` says which device is on.
- **Deferred header items:** at most 8 wrapped keys and 2 passphrase keys, KDF passes at most 16 and lanes at most 8 (memory was already capped at 1 GiB), all refused as `Corrupted` before any key derivation. A wrapped key of a method or device kind this version does not know is kept and skipped, so an older kv still opens a newer vault with the passphrase; a wrapped key with no `method` is corrupt.
- **Distribution:** cargo-dist 0.33.0 on GitHub Releases for tags like `v0.1.0`: macOS arm64 and x86_64, Linux x86_64 and arm64 (glibc), Windows x86_64 MSVC; shell and PowerShell installers into `~/.cargo/bin`; no updater, Homebrew or MSI; binaries are not signed or notarized. Pushing the first tag is left to you after merge.
- **CI:** every action pinned to a commit (cargo-dist's `github-action-commits` for the generated release workflow), and a `msrv` job running `cargo check --workspace --all-targets --locked` on Rust 1.89.

## Global Constraints

- Every cargo command runs with `export DEVELOPER_DIR=/Library/Developer/CommandLineTools KV_REQUIRE_DB_TESTS=1 KV_TEST_POSTGRES_URL=postgres://postgres:kv-test-password-123@127.0.0.1:54417/postgres KV_TEST_REDIS_URL=redis://127.0.0.1:63799/0` set. Servers: `docker run --rm -d --name kv-test-pg17 -p 54417:5432 -e POSTGRES_PASSWORD=kv-test-password-123 postgres:17` and `docker run --rm -d --name kv-test-redis -p 63799:6379 redis:7`.
- Rust 1.89 is the minimum supported version (`rust-version` in `Cargo.toml`); new code must build on it.
- The daemon never calls a platform authentication API; only `kv::device`, used by the CLI and TUI, does.
- A device key is a `SymmetricKey` or a `SecretText` holding 64 hex characters; it is never printed, logged, audited, or put on the agent socket.
- `KV_BIOMETRIC=off` (also `0`, `false`, `no`, any case) means no platform prompt is ever shown.
- Commits as DFanso <leogavin123@outlook.com>, no AI attribution.
- `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings` and `cargo test --workspace` stay clean after every task. Windows-only code is checked by CI's windows-latest job.

## Review Focus

None of these can run in CI or in this plan's tests; each is a manual check before release.

- A real Touch ID prompt: `kv biometric enable`, then `kv unlock`, `kv add` and `kv tui` show the system sheet (in the TUI, over the alternate screen); a fingerprint unlocks, and Cancel falls back to the passphrase prompt with a one-line reason.
- A new kv build (`cargo install` again): the first device unlock shows a keychain dialog for the login password; Always Allow works from then on, and Deny falls back to the passphrase rather than failing the command.
- Adding or removing a fingerprint in System Settings: the next unlock says the fingerprints changed and asks for the passphrase; `kv biometric enable` turns it on again.
- Windows Hello on a real machine: `kv biometric enable` from Windows Terminal brings the Hello dialog to the front, a PIN or face unlocks, Cancel falls back, and `kv biometric disable` deletes the credential.
- The release workflow on the first tag: all five builds pass (aws-lc-sys on Linux arm64 and Windows), and both installers install a `kv` that runs `kv --version`.

---

### Task 1: Vault header limits, unknown unlock methods, and device slots

**Files:**
- Modify: `crates/kv-core/src/crypto.rs`
- Modify: `crates/kv-core/src/vault.rs`
- Modify: `crates/kv-core/tests/vault.rs`
- Modify: `crates/kv-core/src/error.rs`

**Interfaces:**
- Consumes: nothing new.
- Produces: `kv_core::crypto::{MAX_KDF_PASSES = 16, MAX_KDF_LANES = 8}` (`derive_key` refuses more, as `Corrupted`); `VaultError::DeviceKeyRejected`; `kv_core::vault::{DeviceKind { TouchId, WindowsHello }` (serde `touch_id`/`windows_hello`, `label() -> &'static str` = "Touch ID"/"Windows Hello"), `DeviceSlot { kind: DeviceKind, id: String, data: Vec<u8> }`, `device_slots(&Path) -> Result<Vec<DeviceSlot>, VaultError>`}`; `Vault::{unlock_with_device(&Path, id: &str, &SymmetricKey) -> Result<Vault, VaultError>, verify_device(&self, id, &SymmetricKey) -> Result<(), VaultError>, devices(&self) -> Vec<DeviceSlot>, enroll_device(&mut self, DeviceSlot, &SymmetricKey) -> Result<(), VaultError>` (replaces a slot of the same kind and saves), `remove_device(&mut self, DeviceKind) -> Result<Option<DeviceSlot>, VaultError>}`. A header with more than 8 wrapped keys or more than 2 passphrase keys is `Corrupted`; a wrapped key whose `method` (or device `kind`) is unknown is kept and skipped; one with no `method` is `Corrupted`. `change_passphrase` keeps only the new passphrase slot.

- [ ] **Step 1: Write the failing tests**

Apply with `git apply` from the repository root:

```diff
diff --git a/crates/kv-core/src/crypto.rs b/crates/kv-core/src/crypto.rs
index c5d31a5179f970b61d715d5eb132e3df26e70483..809ad6d0be9f14ad8b889fcea785daa6162b7baa 100644
--- a/crates/kv-core/src/crypto.rs
+++ b/crates/kv-core/src/crypto.rs
@@ -208,4 +208,31 @@ mod tests {
         let key = SymmetricKey::from_slice(&[7u8; KEY_LEN]).unwrap();
         assert_eq!(format!("{key:?}"), "SymmetricKey([REDACTED])");
     }
+
+    #[test]
+    fn derive_key_rejects_excessive_passes_or_lanes() {
+        for params in [
+            KdfParams {
+                m_kib: 8,
+                t: MAX_KDF_PASSES + 1,
+                p: 1,
+            },
+            KdfParams {
+                m_kib: 64,
+                t: 1,
+                p: MAX_KDF_LANES + 1,
+            },
+        ] {
+            assert!(matches!(
+                derive_key(b"passphrase", b"salt-salt-salt-1", params),
+                Err(VaultError::Corrupted)
+            ));
+        }
+        let most = KdfParams {
+            m_kib: 8 * MAX_KDF_LANES,
+            t: MAX_KDF_PASSES,
+            p: MAX_KDF_LANES,
+        };
+        assert!(derive_key(b"passphrase", b"salt-salt-salt-1", most).is_ok());
+    }
 }
diff --git a/crates/kv-core/src/vault.rs b/crates/kv-core/src/vault.rs
index 5dac7b7fa9bb65f681f80ddcbd9fc08ffc7390a7..568e9e365af533984588cf63c6b8a9edfae9f8eb 100644
--- a/crates/kv-core/src/vault.rs
+++ b/crates/kv-core/src/vault.rs
@@ -385,4 +385,84 @@ mod tests {
         let (header, aad, payload) = parse(&bytes).unwrap();
         assert!(crypto::open(&old_key, &header.payload_nonce, aad, payload).is_none());
     }
+
+    fn slot(method: &str) -> serde_json::Value {
+        serde_json::json!({ "method": method, "nonce": "", "ciphertext": "" })
+    }
+
+    /// Rewrites the vault with `extra` wrapped keys appended to its header,
+    /// re-encrypted so the file stays valid.
+    fn with_extra_slots(vault: &Vault, extra: Vec<serde_json::Value>) {
+        let mut slots = vault.slots.clone();
+        slots.extend(extra.into_iter().map(Slot::Unknown));
+        let bytes = vault.encode(&vault.key, &slots);
+        write_atomic(&vault.path, &bytes, Backup::KeepPrevious).unwrap();
+    }
+
+    #[test]
+    fn an_unknown_unlock_method_is_kept_and_skipped() {
+        let dir = tempfile::TempDir::new().unwrap();
+        let path = dir.path().join("vault.kv");
+        let vault = Vault::create(&path, "correct horse battery", FAST).unwrap();
+        let future = serde_json::json!({ "method": "passkey", "credential": "abc" });
+        with_extra_slots(&vault, vec![future.clone()]);
+
+        let unlocked = Vault::unlock(&path, "correct horse battery").unwrap();
+        unlocked.save().unwrap();
+        let bytes = fs::read(&path).unwrap();
+        let (header, _, _) = parse(&bytes).unwrap();
+        assert!(
+            header
+                .wrapped_keys
+                .iter()
+                .any(|slot| matches!(slot, Slot::Unknown(v) if *v == future))
+        );
+    }
+
+    #[test]
+    fn a_device_slot_of_an_unknown_kind_is_kept_too() {
+        let dir = tempfile::TempDir::new().unwrap();
+        let path = dir.path().join("vault.kv");
+        let vault = Vault::create(&path, "correct horse battery", FAST).unwrap();
+        let mut other = slot("device");
+        other["device"] = "android".into();
+        other["id"] = "x".into();
+        other["data"] = "".into();
+        with_extra_slots(&vault, vec![other]);
+        let unlocked = Vault::unlock(&path, "correct horse battery").unwrap();
+        assert!(unlocked.devices().is_empty());
+    }
+
+    #[test]
+    fn a_header_with_too_many_wrapped_keys_is_refused_before_any_key_derivation() {
+        let dir = tempfile::TempDir::new().unwrap();
+        let path = dir.path().join("vault.kv");
+        let vault = Vault::create(&path, "correct horse battery", FAST).unwrap();
+        with_extra_slots(
+            &vault,
+            (0..MAX_WRAPPED_KEYS).map(|_| slot("passkey")).collect(),
+        );
+        let bytes = fs::read(&path).unwrap();
+        assert!(matches!(parse(&bytes), Err(VaultError::Corrupted)));
+
+        let passphrase = vault.slots[0].clone();
+        let vault =
+            Vault::create(&dir.path().join("two.kv"), "correct horse battery", FAST).unwrap();
+        let mut slots = vault.slots.clone();
+        slots.extend((0..MAX_PASSPHRASE_WRAPS).map(|_| passphrase.clone()));
+        let bytes = vault.encode(&vault.key, &slots);
+        assert!(matches!(parse(&bytes), Err(VaultError::Corrupted)));
+    }
+
+    #[test]
+    fn a_wrapped_key_without_a_method_is_corrupt() {
+        let dir = tempfile::TempDir::new().unwrap();
+        let path = dir.path().join("vault.kv");
+        let vault = Vault::create(&path, "correct horse battery", FAST).unwrap();
+        with_extra_slots(&vault, vec![serde_json::json!({ "nonce": "" })]);
+        assert!(matches!(
+            Vault::unlock(&path, "correct horse battery"),
+            Err(VaultError::Corrupted)
+        ));
+    }
 }
diff --git a/crates/kv-core/tests/vault.rs b/crates/kv-core/tests/vault.rs
index 8c4b845a54d7950fa5016c634bf0186d860d28ee..679b6cc6d45c1b9f3ed1e42b22aa5c8d79c54553 100644
--- a/crates/kv-core/tests/vault.rs
+++ b/crates/kv-core/tests/vault.rs
@@ -353,3 +353,80 @@ fn vault_directory_is_private_to_the_user() {
         & 0o777;
     assert_eq!(mode, 0o700);
 }
+
+use kv_core::crypto::SymmetricKey;
+use kv_core::vault::{DeviceKind, DeviceSlot, device_slots};
+
+fn touch_id(id: &str) -> DeviceSlot {
+    DeviceSlot {
+        kind: DeviceKind::TouchId,
+        id: id.into(),
+        data: b"fingerprint set".to_vec(),
+    }
+}
+
+#[test]
+fn a_device_slot_unlocks_the_vault_with_its_key_only() {
+    let (_dir, path) = setup();
+    let mut vault = Vault::create(&path, PASS, FAST).unwrap();
+    vault
+        .upsert(redis("cache", "redis://:pw-0123456789@cache:6379"))
+        .unwrap();
+    vault.save().unwrap();
+    let key = SymmetricKey::generate();
+    vault.enroll_device(touch_id("kv-1"), &key).unwrap();
+
+    assert_eq!(device_slots(&path).unwrap(), [touch_id("kv-1")]);
+    let unlocked = Vault::unlock_with_device(&path, "kv-1", &key).unwrap();
+    assert_eq!(unlocked.secrets().len(), 1);
+    unlocked.verify_device("kv-1", &key).unwrap();
+    assert!(matches!(
+        Vault::unlock_with_device(&path, "kv-1", &SymmetricKey::generate()),
+        Err(VaultError::DeviceKeyRejected)
+    ));
+    assert!(matches!(
+        Vault::unlock_with_device(&path, "kv-2", &key),
+        Err(VaultError::DeviceKeyRejected)
+    ));
+    // The passphrase still works.
+    Vault::unlock(&path, PASS).unwrap();
+}
+
+#[test]
+fn enrolling_again_replaces_the_slot_and_removing_it_ends_device_unlock() {
+    let (_dir, path) = setup();
+    let mut vault = Vault::create(&path, PASS, FAST).unwrap();
+    let (old, new) = (SymmetricKey::generate(), SymmetricKey::generate());
+    vault.enroll_device(touch_id("kv-old"), &old).unwrap();
+    vault.enroll_device(touch_id("kv-new"), &new).unwrap();
+    assert_eq!(vault.devices(), [touch_id("kv-new")]);
+    assert!(Vault::unlock_with_device(&path, "kv-old", &old).is_err());
+
+    assert_eq!(
+        vault.remove_device(DeviceKind::TouchId).unwrap(),
+        Some(touch_id("kv-new"))
+    );
+    assert_eq!(vault.remove_device(DeviceKind::TouchId).unwrap(), None);
+    assert!(device_slots(&path).unwrap().is_empty());
+    assert!(Vault::unlock_with_device(&path, "kv-new", &new).is_err());
+}
+
+#[test]
+fn changing_the_passphrase_drops_device_slots() {
+    let (_dir, path) = setup();
+    let mut vault = Vault::create(&path, PASS, FAST).unwrap();
+    let key = SymmetricKey::generate();
+    vault.enroll_device(touch_id("kv-1"), &key).unwrap();
+    vault
+        .change_passphrase("a brand new passphrase", FAST)
+        .unwrap();
+    assert!(vault.devices().is_empty());
+    assert!(device_slots(&path).unwrap().is_empty());
+    assert!(Vault::unlock_with_device(&path, "kv-1", &key).is_err());
+}
+
+#[test]
+fn device_slots_of_a_missing_vault_are_not_found() {
+    let (_dir, path) = setup();
+    assert!(matches!(device_slots(&path), Err(VaultError::NotFound(_))));
+}
```

- [ ] **Step 2: Run the tests to watch them fail**

Run: `cargo test -p kv-core --lib --test vault`
Expected: FAIL to compile: `cannot find value MAX_KDF_PASSES` / `MAX_KDF_LANES` / `MAX_WRAPPED_KEYS` / `MAX_PASSPHRASE_WRAPS`, `cannot find type Slot`, `no field slots on type vault::Vault`, `no method named devices`.

- [ ] **Step 3: Implement**

Apply with `git apply`:

```diff
diff --git a/crates/kv-core/src/crypto.rs b/crates/kv-core/src/crypto.rs
index 809ad6d0be9f14ad8b889fcea785daa6162b7baa..c82b559a0417a9568326e540e95c5a49b37227cd 100644
--- a/crates/kv-core/src/crypto.rs
+++ b/crates/kv-core/src/crypto.rs
@@ -17,6 +17,10 @@ pub const SALT_LEN: usize = 16;
 /// Upper bound on Argon2 memory read from a vault header (1 GiB), so a
 /// tampered header cannot make unlock allocate unbounded memory.
 const MAX_KDF_MEMORY_KIB: u32 = 1024 * 1024;
+/// Upper bounds on Argon2 passes and lanes read from a vault header, so a
+/// tampered header cannot make unlock run for hours.
+pub const MAX_KDF_PASSES: u32 = 16;
+pub const MAX_KDF_LANES: u32 = 8;
 
 /// A 256-bit symmetric key. Zeroed on drop and never printed. Lives in its
 /// own heap allocation, which is locked into RAM where the OS allows it so
@@ -99,7 +103,7 @@ pub fn derive_key(
     salt: &[u8],
     params: KdfParams,
 ) -> Result<SymmetricKey, VaultError> {
-    if params.m_kib > MAX_KDF_MEMORY_KIB {
+    if params.m_kib > MAX_KDF_MEMORY_KIB || params.t > MAX_KDF_PASSES || params.p > MAX_KDF_LANES {
         return Err(VaultError::Corrupted);
     }
     let argon_params = Params::new(params.m_kib, params.t, params.p, Some(KEY_LEN))
diff --git a/crates/kv-core/src/error.rs b/crates/kv-core/src/error.rs
index 79565e6ff99f58cd6a0ee868840ca9e8220b83a2..14714466fc1815c2dfcb91707ade0590b71571b9 100644
--- a/crates/kv-core/src/error.rs
+++ b/crates/kv-core/src/error.rs
@@ -8,6 +8,8 @@ pub enum VaultError {
     NotFound(PathBuf),
     #[error("wrong passphrase")]
     WrongPassphrase,
+    #[error("this unlock method is not set up for the vault, or no longer matches it")]
+    DeviceKeyRejected,
     #[error("the vault file is corrupted or has been tampered with")]
     Corrupted,
     #[error("unsupported vault format version {0}")]
diff --git a/crates/kv-core/src/vault.rs b/crates/kv-core/src/vault.rs
index 568e9e365af533984588cf63c6b8a9edfae9f8eb..55902a9df64fb42f82f2aad6f28eac1e9cddf92f 100644
--- a/crates/kv-core/src/vault.rs
+++ b/crates/kv-core/src/vault.rs
@@ -4,6 +4,11 @@
 //! payload ciphertext`. A random vault key encrypts the payload; the vault
 //! key is stored wrapped once per unlock method. Everything before the
 //! payload is the payload's associated data, so header edits are detected.
+//!
+//! Unlock methods are the passphrase and devices (Touch ID, Windows Hello),
+//! whose keys come from the platform. A wrapped key of a method this version
+//! does not know is kept as it is and skipped, so a vault a newer kv wrote
+//! still opens with the passphrase.
 
 use std::fmt;
 use std::fs::{self, File, OpenOptions};
@@ -23,14 +28,55 @@ const FORMAT_VERSION: u16 = 1;
 const PREFIX_LEN: usize = 4 + 2 + 4;
 const WRAP_AAD: &[u8] = b"kv-wrap-v1";
 const MIN_PASSPHRASE_CHARS: usize = 8;
+/// More wrapped keys than this, or more passphrase wraps, mark a tampered
+/// header: each passphrase wrap costs an Argon2 derivation to try.
+const MAX_WRAPPED_KEYS: usize = 8;
+const MAX_PASSPHRASE_WRAPS: usize = 2;
 
 #[derive(Serialize, Deserialize)]
 struct Header {
-    wrapped_keys: Vec<WrappedKey>,
+    wrapped_keys: Vec<Slot>,
     #[serde(with = "b64")]
     payload_nonce: Vec<u8>,
 }
 
+/// A device that can unlock the vault in place of the passphrase.
+#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
+#[serde(rename_all = "snake_case")]
+pub enum DeviceKind {
+    TouchId,
+    WindowsHello,
+}
+
+impl DeviceKind {
+    const NAMES: [&str; 2] = ["touch_id", "windows_hello"];
+
+    pub fn label(self) -> &'static str {
+        match self {
+            Self::TouchId => "Touch ID",
+            Self::WindowsHello => "Windows Hello",
+        }
+    }
+}
+
+/// What a device needs, besides the user, to produce the key that opens its
+/// slot: the platform's name for its key (`id`) and anything else it keeps
+/// in the vault header (`data`: Windows Hello's challenge, or the Touch ID
+/// fingerprint set it was enrolled with). None of it is secret.
+#[derive(Clone, Debug, PartialEq, Eq)]
+pub struct DeviceSlot {
+    pub kind: DeviceKind,
+    pub id: String,
+    pub data: Vec<u8>,
+}
+
+#[derive(Clone)]
+enum Slot {
+    Known(WrappedKey),
+    /// A method this version does not know, kept as it was read.
+    Unknown(serde_json::Value),
+}
+
 #[derive(Clone, Serialize, Deserialize)]
 #[serde(tag = "method", rename_all = "lowercase")]
 enum WrappedKey {
@@ -43,6 +89,62 @@ enum WrappedKey {
         #[serde(with = "b64")]
         ciphertext: Vec<u8>,
     },
+    Device {
+        device: DeviceKind,
+        id: String,
+        #[serde(with = "b64")]
+        data: Vec<u8>,
+        #[serde(with = "b64")]
+        nonce: Vec<u8>,
+        #[serde(with = "b64")]
+        ciphertext: Vec<u8>,
+    },
+}
+
+impl WrappedKey {
+    fn device(&self) -> Option<DeviceSlot> {
+        match self {
+            Self::Device {
+                device, id, data, ..
+            } => Some(DeviceSlot {
+                kind: *device,
+                id: id.clone(),
+                data: data.clone(),
+            }),
+            Self::Passphrase { .. } => None,
+        }
+    }
+}
+
+impl Serialize for Slot {
+    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
+        match self {
+            Self::Known(key) => key.serialize(s),
+            Self::Unknown(value) => value.serialize(s),
+        }
+    }
+}
+
+impl<'de> Deserialize<'de> for Slot {
+    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
+        use serde::de::Error;
+        let value = serde_json::Value::deserialize(d)?;
+        let known = match value.get("method").and_then(serde_json::Value::as_str) {
+            Some("passphrase") => true,
+            Some("device") => value
+                .get("device")
+                .and_then(serde_json::Value::as_str)
+                .is_some_and(|kind| DeviceKind::NAMES.contains(&kind)),
+            Some(_) => false,
+            None => return Err(D::Error::custom("a wrapped key names no method")),
+        };
+        if !known {
+            return Ok(Self::Unknown(value));
+        }
+        WrappedKey::deserialize(value)
+            .map(Self::Known)
+            .map_err(D::Error::custom)
+    }
 }
 
 #[derive(Default, Serialize, Deserialize)]
@@ -53,7 +155,7 @@ struct VaultData {
 pub struct Vault {
     path: PathBuf,
     key: SymmetricKey,
-    wrapped_keys: Vec<WrappedKey>,
+    slots: Vec<Slot>,
     data: VaultData,
 }
 
@@ -78,7 +180,7 @@ impl Vault {
         let vault = Self {
             path: path.to_owned(),
             key,
-            wrapped_keys: vec![wrapped],
+            slots: vec![Slot::Known(wrapped)],
             data: VaultData::default(),
         };
         vault.save()?;
@@ -86,16 +188,31 @@ impl Vault {
     }
 
     pub fn unlock(path: &Path, passphrase: &str) -> Result<Self, VaultError> {
-        let bytes = match fs::read(path) {
-            Ok(b) => b,
-            Err(e) if e.kind() == io::ErrorKind::NotFound => {
-                return Err(VaultError::NotFound(path.to_owned()));
-            }
-            Err(e) => return Err(e.into()),
-        };
+        let bytes = read(path)?;
         let (header, aad, payload) = parse(&bytes)?;
         let key = unwrap_with_passphrase(&header.wrapped_keys, passphrase)?;
+        Self::open(path, key, header, aad, payload)
+    }
+
+    /// Unlocks with the key a device produced for the slot `id`.
+    pub fn unlock_with_device(
+        path: &Path,
+        id: &str,
+        wrapping_key: &SymmetricKey,
+    ) -> Result<Self, VaultError> {
+        let bytes = read(path)?;
+        let (header, aad, payload) = parse(&bytes)?;
+        let key = unwrap_with_device(&header.wrapped_keys, id, wrapping_key)?;
+        Self::open(path, key, header, aad, payload)
+    }
 
+    fn open(
+        path: &Path,
+        key: SymmetricKey,
+        header: Header,
+        aad: &[u8],
+        payload: &[u8],
+    ) -> Result<Self, VaultError> {
         let plaintext =
             crypto::open(&key, &header.payload_nonce, aad, payload).ok_or(VaultError::Corrupted)?;
         let data: VaultData =
@@ -103,7 +220,7 @@ impl Vault {
         Ok(Self {
             path: path.to_owned(),
             key,
-            wrapped_keys: header.wrapped_keys,
+            slots: header.wrapped_keys,
             data,
         })
     }
@@ -111,16 +228,16 @@ impl Vault {
     /// Encrypts with a fresh nonce and atomically replaces the file, keeping
     /// the previous version as `<path>.bak`.
     pub fn save(&self) -> Result<(), VaultError> {
-        let bytes = self.encode(&self.key, &self.wrapped_keys);
+        let bytes = self.encode(&self.key, &self.slots);
         write_atomic(&self.path, &bytes, Backup::KeepPrevious)?;
         Ok(())
     }
 
     /// Serializes and encrypts the vault under `key` with a fresh nonce.
-    fn encode(&self, key: &SymmetricKey, wrapped_keys: &[WrappedKey]) -> Vec<u8> {
+    fn encode(&self, key: &SymmetricKey, slots: &[Slot]) -> Vec<u8> {
         let nonce = crypto::random_nonce();
         let header = Header {
-            wrapped_keys: wrapped_keys.to_vec(),
+            wrapped_keys: slots.to_vec(),
             payload_nonce: nonce.to_vec(),
         };
         let header_json = serde_json::to_vec(&header).expect("header serializes");
@@ -141,7 +258,7 @@ impl Vault {
     /// Checks `passphrase` against the vault's passphrase wrap without reading
     /// the file. Costs one Argon2 derivation, like `unlock`.
     pub fn verify_passphrase(&self, passphrase: &str) -> Result<(), VaultError> {
-        let key = unwrap_with_passphrase(&self.wrapped_keys, passphrase)?;
+        let key = unwrap_with_passphrase(&self.slots, passphrase)?;
         if key.as_bytes() == self.key.as_bytes() {
             Ok(())
         } else {
@@ -149,6 +266,57 @@ impl Vault {
         }
     }
 
+    /// Checks a device's key against its slot without reading the file.
+    pub fn verify_device(&self, id: &str, wrapping_key: &SymmetricKey) -> Result<(), VaultError> {
+        let key = unwrap_with_device(&self.slots, id, wrapping_key)?;
+        if key.as_bytes() == self.key.as_bytes() {
+            Ok(())
+        } else {
+            Err(VaultError::DeviceKeyRejected)
+        }
+    }
+
+    /// The devices that can unlock the vault.
+    pub fn devices(&self) -> Vec<DeviceSlot> {
+        devices(&self.slots)
+    }
+
+    /// Lets the device's key unlock the vault, replacing any slot of the
+    /// same kind, and saves. If the save fails, nothing changes.
+    pub fn enroll_device(
+        &mut self,
+        slot: DeviceSlot,
+        wrapping_key: &SymmetricKey,
+    ) -> Result<(), VaultError> {
+        let nonce = crypto::random_nonce();
+        let wrapped = WrappedKey::Device {
+            device: slot.kind,
+            id: slot.id,
+            data: slot.data,
+            nonce: nonce.to_vec(),
+            ciphertext: crypto::seal(wrapping_key, &nonce, WRAP_AAD, self.key.as_bytes()),
+        };
+        let mut slots = without_device(&self.slots, slot.kind);
+        slots.push(Slot::Known(wrapped));
+        self.replace_slots(slots)
+    }
+
+    /// Removes the slot of `kind`, if there is one, and saves.
+    pub fn remove_device(&mut self, kind: DeviceKind) -> Result<Option<DeviceSlot>, VaultError> {
+        let Some(removed) = self.devices().into_iter().find(|slot| slot.kind == kind) else {
+            return Ok(None);
+        };
+        self.replace_slots(without_device(&self.slots, kind))?;
+        Ok(Some(removed))
+    }
+
+    fn replace_slots(&mut self, slots: Vec<Slot>) -> Result<(), VaultError> {
+        let bytes = self.encode(&self.key, &slots);
+        write_atomic(&self.path, &bytes, Backup::KeepPrevious)?;
+        self.slots = slots;
+        Ok(())
+    }
+
     pub fn path(&self) -> &Path {
         &self.path
     }
@@ -198,26 +366,64 @@ impl Vault {
     ) -> Result<(), VaultError> {
         check_passphrase(new_passphrase)?;
         let key = SymmetricKey::generate();
-        let wrapped_keys = vec![wrap_with_passphrase(&key, new_passphrase, kdf)?];
-        let bytes = self.encode(&key, &wrapped_keys);
+        let slots = vec![Slot::Known(wrap_with_passphrase(
+            &key,
+            new_passphrase,
+            kdf,
+        )?)];
+        let bytes = self.encode(&key, &slots);
         write_atomic(&self.path, &bytes, Backup::Replace)?;
         self.key = key;
-        self.wrapped_keys = wrapped_keys;
+        self.slots = slots;
         Ok(())
     }
 }
 
-fn unwrap_with_passphrase(
-    wrapped_keys: &[WrappedKey],
-    passphrase: &str,
-) -> Result<SymmetricKey, VaultError> {
-    for wrapped in wrapped_keys {
-        let WrappedKey::Passphrase {
+/// The device slots of the vault at `path`, read from its header: no key is
+/// needed to know which devices can unlock it.
+pub fn device_slots(path: &Path) -> Result<Vec<DeviceSlot>, VaultError> {
+    let bytes = read(path)?;
+    let (header, _, _) = parse(&bytes)?;
+    Ok(devices(&header.wrapped_keys))
+}
+
+fn read(path: &Path) -> Result<Vec<u8>, VaultError> {
+    match fs::read(path) {
+        Ok(bytes) => Ok(bytes),
+        Err(e) if e.kind() == io::ErrorKind::NotFound => Err(VaultError::NotFound(path.to_owned())),
+        Err(e) => Err(e.into()),
+    }
+}
+
+fn devices(slots: &[Slot]) -> Vec<DeviceSlot> {
+    slots
+        .iter()
+        .filter_map(|slot| match slot {
+            Slot::Known(key) => key.device(),
+            Slot::Unknown(_) => None,
+        })
+        .collect()
+}
+
+fn without_device(slots: &[Slot], kind: DeviceKind) -> Vec<Slot> {
+    slots
+        .iter()
+        .filter(|slot| !matches!(slot, Slot::Known(key) if key.device().is_some_and(|d| d.kind == kind)))
+        .cloned()
+        .collect()
+}
+
+fn unwrap_with_passphrase(slots: &[Slot], passphrase: &str) -> Result<SymmetricKey, VaultError> {
+    for slot in slots {
+        let Slot::Known(WrappedKey::Passphrase {
             kdf,
             salt,
             nonce,
             ciphertext,
-        } = wrapped;
+        }) = slot
+        else {
+            continue;
+        };
         let wrapping_key = crypto::derive_key(passphrase.as_bytes(), salt, *kdf)?;
         if let Some(raw) = crypto::open(&wrapping_key, nonce, WRAP_AAD, ciphertext) {
             return SymmetricKey::from_slice(&raw);
@@ -226,6 +432,27 @@ fn unwrap_with_passphrase(
     Err(VaultError::WrongPassphrase)
 }
 
+fn unwrap_with_device(
+    slots: &[Slot],
+    wanted: &str,
+    wrapping_key: &SymmetricKey,
+) -> Result<SymmetricKey, VaultError> {
+    for slot in slots {
+        if let Slot::Known(WrappedKey::Device {
+            id,
+            nonce,
+            ciphertext,
+            ..
+        }) = slot
+            && id == wanted
+            && let Some(raw) = crypto::open(wrapping_key, nonce, WRAP_AAD, ciphertext)
+        {
+            return SymmetricKey::from_slice(&raw);
+        }
+    }
+    Err(VaultError::DeviceKeyRejected)
+}
+
 fn check_passphrase(passphrase: &str) -> Result<(), VaultError> {
     if passphrase.chars().count() < MIN_PASSPHRASE_CHARS {
         return Err(VaultError::WeakPassphrase);
@@ -265,6 +492,14 @@ fn parse(bytes: &[u8]) -> Result<(Header, &[u8], &[u8]), VaultError> {
         .ok_or(VaultError::Corrupted)?;
     let header: Header = serde_json::from_slice(&bytes[PREFIX_LEN..header_end])
         .map_err(|_| VaultError::Corrupted)?;
+    let passphrase_wraps = header
+        .wrapped_keys
+        .iter()
+        .filter(|slot| matches!(slot, Slot::Known(WrappedKey::Passphrase { .. })))
+        .count();
+    if header.wrapped_keys.len() > MAX_WRAPPED_KEYS || passphrase_wraps > MAX_PASSPHRASE_WRAPS {
+        return Err(VaultError::Corrupted);
+    }
     Ok((header, &bytes[..header_end], &bytes[header_end..]))
 }
 
```

- [ ] **Step 4: Run the tests to watch them pass**

Run: `cargo test -p kv-core`
Expected: PASS, every kv-core test.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "Cap the vault header, keep unknown unlock methods, and add device slots"
```

### Task 2: Device credentials in the control protocol and the daemon

**Files:**
- Modify: `crates/kv-core/tests/proto.rs`
- Modify: `crates/kv/Cargo.toml`
- Modify: `crates/kv/tests/cli.rs`
- Modify: `crates/kv/tests/common/mod.rs`
- Create: `crates/kv/tests/device.rs`
- Modify: `crates/kv/tests/live/mod.rs`
- Modify: `crates/kv/tests/mcp.rs`
- Modify: `crates/kv/tests/session.rs`
- Modify: `crates/kv/tests/state.rs`
- Modify: `crates/kv/tests/tui.rs`
- Modify: `crates/kv/tests/tui_edit.rs`
- Modify: `crates/kv/tests/tui_requests.rs`
- Modify: `crates/kv-core/src/proto.rs`
- Modify: `crates/kv/src/cli.rs`
- Modify: `crates/kv/src/daemon/state.rs`
- Modify: `crates/kv/src/tui.rs`

**Interfaces:**
- Consumes: Task 1 `Vault::{unlock_with_device, verify_device, enroll_device, remove_device, devices}`, `device_slots`, `DeviceKind`, `DeviceSlot`, `VaultError::DeviceKeyRejected`.
- Produces: `kv_core::proto::{DeviceCredential { id: String, key: SecretText /* 64 hex */ }, ControlRequest.device: Option<DeviceCredential>` (serde default), `Status.devices: Vec<DeviceKind>` (serde default), `ControlCommand::EnrollDevice { kind: DeviceKind, id: String, data: String /* hex */, key: SecretText /* hex */ }`, `ControlCommand::RemoveDevice { kind: DeviceKind }`, `ControlErrorCode::WrongDeviceKey}`. The daemon takes a device credential anywhere it takes the passphrase except `Init`, `ChangePassphrase` and `EnrollDevice`; a wrong device key counts toward the unlock backoff. `ChangePassphrase` warns "<label> unlock is off: a new passphrase drops it. Run `kv biometric enable` to turn it on again". Enrolment ids are 1 to 128 of `[A-Za-z0-9_-]`, data at most 4096 bytes, keys 32 bytes; the audit log records the kind, never the key. Test helper `Fixture::status()` in `tests/common`.

- [ ] **Step 1: Write the failing tests**

Apply with `git apply` from the repository root:

```diff
diff --git a/Cargo.lock b/Cargo.lock
index 91fe99571f7cd452aa7674f390382a0e396b94f8..09fe9fc952df0722759dd954cfbb1c7b504970a6 100644
--- a/Cargo.lock
+++ b/Cargo.lock
@@ -1820,6 +1820,7 @@ dependencies = [
  "clap",
  "dirs",
  "futures-util",
+ "hex",
  "humantime",
  "kv-core",
  "notify-rust",
diff --git a/crates/kv-core/tests/proto.rs b/crates/kv-core/tests/proto.rs
index c00cf8dd79a9c1a283656a28b1ce5ef3b2429ba3..32a79904630e2aa3bea837beec0554c6f413b0d2 100644
--- a/crates/kv-core/tests/proto.rs
+++ b/crates/kv-core/tests/proto.rs
@@ -66,6 +66,7 @@ fn agent_responses_never_contain_secret_values() {
                 handle_count: Some(secrets.len()),
                 locks_in_secs: Some(60),
                 pending_approvals: 0,
+                devices: Vec::new(),
             },
         },
     ];
@@ -96,6 +97,7 @@ fn agent_requests_use_a_type_tag() {
 fn a_control_request_is_not_a_valid_agent_request() {
     let control = ControlRequest {
         passphrase: Some(SecretText::new("correct horse battery")),
+        device: None,
         token: None,
         command: ControlCommand::Unlock,
     };
@@ -107,6 +109,7 @@ fn a_control_request_is_not_a_valid_agent_request() {
 fn control_request_debug_hides_the_passphrase() {
     let control = ControlRequest {
         passphrase: Some(SecretText::new("correct horse battery")),
+        device: None,
         token: None,
         command: ControlCommand::ChangePassphrase {
             new_passphrase: SecretText::new("a brand new passphrase"),
@@ -254,6 +257,7 @@ fn session_tokens_never_show_in_debug_output() {
     let token = "ab".repeat(32);
     let request = ControlRequest {
         passphrase: None,
+        device: None,
         token: Some(SecretText::new(token.clone())),
         command: ControlCommand::Overview,
     };
@@ -407,3 +411,15 @@ fn an_overview_from_before_role_warnings_still_parses() {
     .unwrap();
     assert!(overview.role_warnings.is_empty());
 }
+
+#[test]
+fn a_control_request_without_a_device_credential_still_parses() {
+    let request: ControlRequest =
+        serde_json::from_str(r#"{"passphrase":"pw","command":{"type":"unlock"}}"#).unwrap();
+    assert!(request.device.is_none());
+    let status: Status = serde_json::from_str(
+        r#"{"vault_exists":true,"locked":true,"handle_count":null,"locks_in_secs":null}"#,
+    )
+    .unwrap();
+    assert!(status.devices.is_empty());
+}
diff --git a/crates/kv/Cargo.toml b/crates/kv/Cargo.toml
index 15c19398da95c9a9f175834fea0a82bad9937091..9bfb429f7dfa3236c40f3bd4ea2d205f614b23fe 100644
--- a/crates/kv/Cargo.toml
+++ b/crates/kv/Cargo.toml
@@ -9,6 +9,7 @@ description = "Local secrets broker that lets AI agents use secrets without seei
 clap = { version = "4.6", features = ["derive", "env"] }
 dirs = "7.0"
 futures-util = { version = "0.3", default-features = false }
+hex = "0.4"
 humantime = "2"
 kv-core = { path = "../kv-core" }
 notify-rust = "4.18"
diff --git a/crates/kv/tests/cli.rs b/crates/kv/tests/cli.rs
index 97f8a792446ad3149b9fd5be4a846155be52e9d3..51d38dab7335c6a1c17814f2388a67920de090d1 100644
--- a/crates/kv/tests/cli.rs
+++ b/crates/kv/tests/cli.rs
@@ -283,6 +283,7 @@ fn agent_socket_rejects_control_requests() {
         let mut stream = ipc::connect(&kv.paths().agent_endpoint()).await.unwrap();
         let request = ControlRequest {
             passphrase: Some(SecretText::new(PASS)),
+            device: None,
             token: None,
             command: ControlCommand::Unlock,
         };
diff --git a/crates/kv/tests/common/mod.rs b/crates/kv/tests/common/mod.rs
index 5ff520f194433e65b4c54ae303fc7ff6bd324bb1..15d0159c9eeddeda756f89849491d7119fc77820 100644
--- a/crates/kv/tests/common/mod.rs
+++ b/crates/kv/tests/common/mod.rs
@@ -48,6 +48,7 @@ impl Fixture {
         let (response, _) = self.daemon.handle_control(
             ControlRequest {
                 passphrase: Some(SecretText::new(PASS)),
+                device: None,
                 token: None,
                 command,
             },
@@ -59,6 +60,13 @@ impl Fixture {
         );
     }
 
+    pub fn status(&mut self) -> kv_core::proto::Status {
+        match self.daemon.prepare(AgentRequest::Status, self.t0) {
+            Prepared::Reply(AgentResponse::Status { status }) => status,
+            _ => panic!("expected a status"),
+        }
+    }
+
     pub fn add(&mut self, secret: Secret) {
         self.control(ControlCommand::Add {
             secret,
@@ -155,6 +163,7 @@ impl Fixture {
     ) -> ControlResponse {
         let request = ControlRequest {
             passphrase: passphrase.map(SecretText::new),
+            device: None,
             token: token.cloned(),
             command,
         };
diff --git a/crates/kv/tests/device.rs b/crates/kv/tests/device.rs
new file mode 100644
index 0000000000000000000000000000000000000000..3842246e9276575c1cf2575d581acff90f704ef6
--- /dev/null
+++ b/crates/kv/tests/device.rs
@@ -0,0 +1,170 @@
+//! Touch ID and Windows Hello as the daemon sees them: a key the CLI got
+//! from the platform, sent in place of the passphrase. The platform side is
+//! in `kv::device`.
+
+mod common;
+
+use common::*;
+use kv_core::crypto::SymmetricKey;
+use kv_core::proto::{
+    ControlCommand, ControlErrorCode, ControlRequest, ControlResponse, DeviceCredential,
+};
+use kv_core::secret::SecretText;
+use kv_core::vault::DeviceKind;
+
+const ID: &str = "kv-0123456789abcdef";
+
+fn send(f: &mut Fixture, request: ControlRequest) -> ControlResponse {
+    f.daemon.handle_control(request, f.t0).0
+}
+
+fn with_passphrase(command: ControlCommand) -> ControlRequest {
+    ControlRequest {
+        passphrase: Some(SecretText::new(PASS)),
+        device: None,
+        token: None,
+        command,
+    }
+}
+
+fn with_device(key: &SymmetricKey, command: ControlCommand) -> ControlRequest {
+    ControlRequest {
+        passphrase: None,
+        device: Some(DeviceCredential {
+            id: ID.into(),
+            key: SecretText::new(hex::encode(key.as_bytes())),
+        }),
+        token: None,
+        command,
+    }
+}
+
+fn enroll(key: &SymmetricKey) -> ControlCommand {
+    ControlCommand::EnrollDevice {
+        kind: DeviceKind::TouchId,
+        id: ID.into(),
+        data: hex::encode(b"fingerprints"),
+        key: SecretText::new(hex::encode(key.as_bytes())),
+    }
+}
+
+fn error(response: ControlResponse) -> (ControlErrorCode, String) {
+    match response {
+        ControlResponse::Error { code, message } => (code, message),
+        other => panic!("expected an error, got {other:?}"),
+    }
+}
+
+fn done(response: ControlResponse) -> Vec<String> {
+    match response {
+        ControlResponse::Done { warnings } => warnings,
+        other => panic!("expected done, got {other:?}"),
+    }
+}
+
+#[test]
+fn an_enrolled_device_unlocks_and_opens_sessions() {
+    let mut f = Fixture::new();
+    let key = SymmetricKey::generate();
+    done(send(&mut f, with_passphrase(enroll(&key))));
+    f.control(ControlCommand::Lock);
+
+    done(send(&mut f, with_device(&key, ControlCommand::Unlock)));
+    assert!(!f.status().locked);
+    assert_eq!(f.status().devices, [DeviceKind::TouchId]);
+    f.control(ControlCommand::Lock);
+    assert_eq!(
+        f.status().devices,
+        [DeviceKind::TouchId],
+        "read while locked"
+    );
+    assert!(matches!(
+        send(&mut f, with_device(&key, ControlCommand::OpenSession)),
+        ControlResponse::Session { .. }
+    ));
+    // Like the passphrase, it is enough to change handles.
+    f.add(openrouter(kv_core::policy::Mode::Auto));
+    done(send(
+        &mut f,
+        with_device(
+            &key,
+            ControlCommand::Remove {
+                name: "openrouter".into(),
+            },
+        ),
+    ));
+}
+
+#[test]
+fn a_wrong_device_key_is_refused_and_counts_toward_the_backoff() {
+    let mut f = Fixture::new();
+    done(send(
+        &mut f,
+        with_passphrase(enroll(&SymmetricKey::generate())),
+    ));
+    f.control(ControlCommand::Lock);
+    let wrong = SymmetricKey::generate();
+    // Five free attempts, as for the passphrase.
+    for _ in 0..5 {
+        let (code, _) = error(send(&mut f, with_device(&wrong, ControlCommand::Unlock)));
+        assert_eq!(code, ControlErrorCode::WrongDeviceKey);
+    }
+    let (code, _) = error(send(&mut f, with_device(&wrong, ControlCommand::Unlock)));
+    assert_eq!(code, ControlErrorCode::TooManyAttempts);
+}
+
+#[test]
+fn enrolling_and_changing_the_passphrase_need_the_passphrase() {
+    let mut f = Fixture::new();
+    let key = SymmetricKey::generate();
+    done(send(&mut f, with_passphrase(enroll(&key))));
+    let (code, _) = error(send(&mut f, with_device(&key, enroll(&key))));
+    assert_eq!(code, ControlErrorCode::PassphraseRequired);
+    let change = || ControlCommand::ChangePassphrase {
+        new_passphrase: SecretText::new("a brand new passphrase"),
+    };
+    let (code, _) = error(send(&mut f, with_device(&key, change())));
+    assert_eq!(code, ControlErrorCode::PassphraseRequired);
+
+    let warnings = done(send(&mut f, with_passphrase(change())));
+    assert!(warnings[0].contains("Touch ID"), "{warnings:?}");
+    assert!(f.status().devices.is_empty());
+    let (code, _) = error(send(&mut f, with_device(&key, ControlCommand::Unlock)));
+    assert_eq!(code, ControlErrorCode::WrongDeviceKey);
+}
+
+#[test]
+fn removing_a_device_ends_its_unlock() {
+    let mut f = Fixture::new();
+    let key = SymmetricKey::generate();
+    done(send(&mut f, with_passphrase(enroll(&key))));
+    let remove = || ControlCommand::RemoveDevice {
+        kind: DeviceKind::TouchId,
+    };
+    done(send(&mut f, with_device(&key, remove())));
+    let (code, message) = error(send(&mut f, with_passphrase(remove())));
+    assert_eq!(code, ControlErrorCode::Invalid);
+    assert!(message.contains("Touch ID is not set up"), "{message}");
+    let (code, _) = error(send(&mut f, with_device(&key, ControlCommand::Unlock)));
+    assert_eq!(code, ControlErrorCode::WrongDeviceKey);
+}
+
+#[test]
+fn enrolment_is_audited_without_the_key() {
+    let mut f = Fixture::new();
+    let key = SymmetricKey::generate();
+    done(send(&mut f, with_passphrase(enroll(&key))));
+    let (code, _) = error(send(
+        &mut f,
+        with_passphrase(ControlCommand::EnrollDevice {
+            kind: DeviceKind::TouchId,
+            id: ID.into(),
+            data: String::new(),
+            key: SecretText::new("not hex"),
+        }),
+    ));
+    assert_eq!(code, ControlErrorCode::Invalid);
+    let audit = std::fs::read_to_string(f.dir.path().join("audit.jsonl")).unwrap();
+    assert!(audit.contains("enroll_device"), "{audit}");
+    assert!(!audit.contains(&hex::encode(key.as_bytes())));
+}
diff --git a/crates/kv/tests/live/mod.rs b/crates/kv/tests/live/mod.rs
index f0edb996f9382805ee10f582c657ae8b5535207f..3d7adb6fa11b5af307c981d411baf6a8391c8b36 100644
--- a/crates/kv/tests/live/mod.rs
+++ b/crates/kv/tests/live/mod.rs
@@ -188,6 +188,7 @@ pub fn request(
 ) -> ControlRequest {
     ControlRequest {
         passphrase: passphrase.map(SecretText::new),
+        device: None,
         token: token.cloned(),
         command,
     }
diff --git a/crates/kv/tests/mcp.rs b/crates/kv/tests/mcp.rs
index fa0e35d8f6a03b821fa1961ddecc29dcadb92593..86170d3a60bffe5ea32bfad06830bd192942fadf 100644
--- a/crates/kv/tests/mcp.rs
+++ b/crates/kv/tests/mcp.rs
@@ -303,6 +303,7 @@ async fn an_ask_handle_waits_for_approval_and_shows_the_client() {
     let control = |token: Option<SecretText>, passphrase: Option<&str>, command| {
         let request = ControlRequest {
             passphrase: passphrase.map(SecretText::new),
+            device: None,
             token,
             command,
         };
@@ -377,6 +378,7 @@ async fn an_agent_asks_for_a_handle_it_does_not_have() {
     let send = |token: Option<SecretText>, passphrase: Option<&str>, command| {
         let request = ControlRequest {
             passphrase: passphrase.map(SecretText::new),
+            device: None,
             token,
             command,
         };
diff --git a/crates/kv/tests/session.rs b/crates/kv/tests/session.rs
index bf6fa2d8917858bc796c80c23ffde82b344e786b..e3fcf00f77ccce272bb65d8b1e10d23eb8bc9589 100644
--- a/crates/kv/tests/session.rs
+++ b/crates/kv/tests/session.rs
@@ -20,6 +20,7 @@ fn request(
 ) -> ControlRequest {
     ControlRequest {
         passphrase: passphrase.map(SecretText::new),
+        device: None,
         token: token.cloned(),
         command,
     }
diff --git a/crates/kv/tests/state.rs b/crates/kv/tests/state.rs
index 2e1928cf0dd44bea55cdeb4fe41b10ee8eddb46b..83e2267ddb6d53932aa40d48d911e7847dfdf232 100644
--- a/crates/kv/tests/state.rs
+++ b/crates/kv/tests/state.rs
@@ -69,6 +69,7 @@ impl Fixture {
         self.daemon.handle_control(
             ControlRequest {
                 passphrase: passphrase.map(SecretText::new),
+                device: None,
                 token: None,
                 command,
             },
diff --git a/crates/kv/tests/tui.rs b/crates/kv/tests/tui.rs
index 27245284dea3ec8d016950ef7b76396edf3efb7a..0aa696b95824bf1a0613247a18eb394109a87bc0 100644
--- a/crates/kv/tests/tui.rs
+++ b/crates/kv/tests/tui.rs
@@ -81,6 +81,7 @@ fn overview(approvals: Vec<Approval>) -> Overview {
             handle_count: Some(1),
             locks_in_secs: Some(8 * 3600),
             pending_approvals: approvals.len(),
+            devices: Vec::new(),
         },
         handles: vec![handle("openrouter", Mode::Ask)],
         approvals,
diff --git a/crates/kv/tests/tui_edit.rs b/crates/kv/tests/tui_edit.rs
index 25a2260bd04b34c6e92c2110258d3a8528878a00..6d158f9b53fc753ed86acb5ee90964155548f63d 100644
--- a/crates/kv/tests/tui_edit.rs
+++ b/crates/kv/tests/tui_edit.rs
@@ -115,6 +115,7 @@ fn handles(handles: Vec<HandleInfo>) -> App {
             handle_count: Some(handles.len()),
             locks_in_secs: Some(8 * 3600),
             pending_approvals: 0,
+            devices: Vec::new(),
         },
         handles,
         approvals: Vec::new(),
@@ -672,6 +673,7 @@ fn a_read_only_handle_whose_role_can_write_is_flagged() {
             handle_count: Some(2),
             locks_in_secs: None,
             pending_approvals: 0,
+            devices: Vec::new(),
         },
         handles: vec![pg, http_handle("openrouter")],
         approvals: Vec::new(),
diff --git a/crates/kv/tests/tui_requests.rs b/crates/kv/tests/tui_requests.rs
index 87739be0ddb7d0a5db44078d13b7d3eccbf5a9d3..8f050660d17708988b860fae7baf89fb64cc1d1f 100644
--- a/crates/kv/tests/tui_requests.rs
+++ b/crates/kv/tests/tui_requests.rs
@@ -107,6 +107,7 @@ fn overview(requests: Vec<HandleRequest>, handles: Vec<HandleInfo>) -> Overview
             handle_count: Some(handles.len()),
             locks_in_secs: None,
             pending_approvals: 0,
+            devices: Vec::new(),
         },
         handles,
         approvals: Vec::new(),
```

- [ ] **Step 2: Run the tests to watch them fail**

Run: `cargo test -p kv-core --test proto; cargo test -p kv --test device`
Expected: FAIL to compile: `struct ControlRequest has no field named device`, `no field devices on type kv_core::proto::Status`, `no variant ... named WrongDeviceKey`, `no variant named EnrollDevice` / `RemoveDevice`, `unresolved import kv_core::proto::DeviceCredential`.

- [ ] **Step 3: Implement**

Apply with `git apply`:

```diff
diff --git a/crates/kv-core/src/proto.rs b/crates/kv-core/src/proto.rs
index b851e9622631ca68492e990e2fcf04351705f27a..3db57a523409d2b11e3afd9f396d89dc8bb2e14f 100644
--- a/crates/kv-core/src/proto.rs
+++ b/crates/kv-core/src/proto.rs
@@ -14,6 +14,7 @@ use serde::{Deserialize, Serialize};
 
 use crate::policy::{Mode, Policy};
 use crate::secret::{AuthPlacement, HandleInfo, Secret, SecretKind, SecretText, SecretValue};
+use crate::vault::DeviceKind;
 
 /// Largest frame either side accepts, in bytes. Room for the output caps
 /// below even when every byte is JSON-escaped as `\u00XX`.
@@ -224,6 +225,9 @@ pub struct Status {
     /// Agent requests waiting for a decision in `kv tui`.
     #[serde(default)]
     pub pending_approvals: usize,
+    /// Devices that can unlock the vault besides the passphrase.
+    #[serde(default)]
+    pub devices: Vec<DeviceKind>,
 }
 
 #[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
@@ -256,11 +260,23 @@ impl AgentErrorCode {
     }
 }
 
+/// The key a device produced for its slot in the vault, as hex.
+#[derive(Debug, Serialize, Deserialize)]
+pub struct DeviceCredential {
+    pub id: String,
+    pub key: SecretText,
+}
+
 #[derive(Debug, Serialize, Deserialize)]
 pub struct ControlRequest {
     /// Required by every command except `lock` and `stop`. For `init` it is
     /// the new passphrase.
     pub passphrase: Option<SecretText>,
+    /// A key from Touch ID or Windows Hello, accepted instead of the
+    /// passphrase by every command except `init`, `change_passphrase` and
+    /// `enroll_device`.
+    #[serde(default)]
+    pub device: Option<DeviceCredential>,
     /// A token from `open_session`, accepted instead of the passphrase by
     /// every command except `init`, `open_session` and `change_passphrase`.
     /// `overview` accepts only a token.
@@ -322,6 +338,18 @@ pub enum ControlCommand {
     DismissRequest {
         id: u64,
     },
+    /// Lets a device unlock the vault, replacing any of the same kind. Needs
+    /// the passphrase. `data` and `key` are hex: what the device keeps in
+    /// the vault header, and the key it produced.
+    EnrollDevice {
+        kind: DeviceKind,
+        id: String,
+        data: String,
+        key: SecretText,
+    },
+    RemoveDevice {
+        kind: DeviceKind,
+    },
 }
 
 /// The user's answer to a request waiting for approval.
@@ -363,6 +391,9 @@ pub enum ControlErrorCode {
     VaultExists,
     PassphraseRequired,
     WrongPassphrase,
+    /// The device key does not open the vault: the device was set up again
+    /// elsewhere, removed, or the passphrase changed since.
+    WrongDeviceKey,
     TooManyAttempts,
     UnknownHandle,
     HandleExists,
diff --git a/crates/kv/src/cli.rs b/crates/kv/src/cli.rs
index 43bcd0e6da7c4c4d8d61138af11e08e7733a2366..5fd19e2559a31c1c95865217810a749ca19cbcc6 100644
--- a/crates/kv/src/cli.rs
+++ b/crates/kv/src/cli.rs
@@ -414,6 +414,7 @@ async fn control(
 ) -> Result<()> {
     let request = ControlRequest {
         passphrase,
+        device: None,
         token: None,
         command,
     };
@@ -435,6 +436,7 @@ async fn control(
 async fn stop_or_lock(paths: &Paths, command: ControlCommand) -> Result<()> {
     let request = ControlRequest {
         passphrase: None,
+        device: None,
         token: None,
         command,
     };
diff --git a/crates/kv/src/daemon/state.rs b/crates/kv/src/daemon/state.rs
index affaa2d777ee7e502d80fa3f051209ea88753142..38ca448ef2daf4bebba47a8cc3c0616e942057db 100644
--- a/crates/kv/src/daemon/state.rs
+++ b/crates/kv/src/daemon/state.rs
@@ -7,22 +7,21 @@ use std::sync::Arc;
 use std::time::{Duration, Instant, SystemTime};
 
 use kv_core::VaultError;
-use kv_core::crypto::KdfParams;
-use kv_core::crypto::fill_random;
+use kv_core::crypto::{KdfParams, SymmetricKey, fill_random};
 use kv_core::db::{RedisRefusal, check_redis, pg_read_only_violation, split_command};
 use kv_core::policy::{
     Decision, DenyReason, Mode, Operation, evaluate, http_target, is_host_entry,
 };
 use kv_core::proto::{
     AgentErrorCode, AgentRequest, AgentResponse, Approval, ConnectCall, ControlCommand,
-    ControlErrorCode, ControlRequest, ControlResponse, DbCall, ExecCall, HandleRequest, HttpCall,
-    Overview, PolicyPatch, RequestedHandle, SessionInfo, Status, Verdict,
+    ControlErrorCode, ControlRequest, ControlResponse, DbCall, DeviceCredential, ExecCall,
+    HandleRequest, HttpCall, Overview, PolicyPatch, RequestedHandle, SessionInfo, Status, Verdict,
 };
 use kv_core::scrub::{MIN_SECRET_LEN, Scrubber};
 use kv_core::secret::{
     AuthPlacement, Secret, SecretKind, SecretText, SecretValue, validate_handle,
 };
-use kv_core::vault::Vault;
+use kv_core::vault::{DeviceKind, DeviceSlot, Vault, device_slots};
 use tokio::sync::oneshot;
 use zeroize::Zeroizing;
 
@@ -1057,9 +1056,11 @@ impl Daemon {
         self.last_request = now;
         let ControlRequest {
             passphrase,
+            device,
             token,
             command,
         } = request;
+        let device = device.as_ref();
         // Polled by `kv tui` several times a second: not use of the vault,
         // not audited, and it leaves the cached scrubber alone.
         if let ControlCommand::Overview = command {
@@ -1083,25 +1084,43 @@ impl Daemon {
                 .init(passphrase.as_ref(), insecure_fast_kdf, now)
                 .map(done),
             ControlCommand::OpenSession => self
-                .authenticate(passphrase.as_ref(), None, now)
+                .authenticate(passphrase.as_ref(), device, None, now)
                 .map(drop)
                 .map(|()| self.open_session()),
             ControlCommand::Decide { id, verdict } => self
-                .authenticate(passphrase.as_ref(), token.as_ref(), now)
+                .authenticate(passphrase.as_ref(), device, token.as_ref(), now)
                 .map(drop)
                 .and_then(|()| self.decide(id, verdict, now))
                 .map(done),
-            // A session token is not enough to change the passphrase, and
-            // the change ends every session.
+            // Neither a session token nor a device is enough to change the
+            // passphrase or set up a device, and a new passphrase ends every
+            // session and drops every device.
             command @ ControlCommand::ChangePassphrase { .. } => self
-                .authenticate(passphrase.as_ref(), None, now)
-                .and_then(|vault| run_authenticated(vault, command))
+                .authenticate(passphrase.as_ref(), None, None, now)
+                .and_then(|vault| {
+                    let devices = vault.devices();
+                    run_authenticated(vault, command)?;
+                    Ok(devices
+                        .iter()
+                        .map(|slot| {
+                            format!(
+                                "{} unlock is off: a new passphrase drops it. Run `kv biometric \
+                                 enable` to turn it on again",
+                                slot.kind.label()
+                            )
+                        })
+                        .collect())
+                })
                 .map(|warnings| {
                     self.sessions.clear();
                     done(warnings)
                 }),
+            command @ ControlCommand::EnrollDevice { .. } => self
+                .authenticate(passphrase.as_ref(), None, None, now)
+                .and_then(|vault| run_authenticated(vault, command))
+                .map(done),
             ControlCommand::DismissRequest { id } => self
-                .authenticate(passphrase.as_ref(), token.as_ref(), now)
+                .authenticate(passphrase.as_ref(), device, token.as_ref(), now)
                 .map(drop)
                 .and_then(|()| self.dismiss_request(id))
                 .map(|name| {
@@ -1114,7 +1133,7 @@ impl Daemon {
                     ControlCommand::Add { secret, .. } => Some(secret.name.clone()),
                     _ => None,
                 };
-                self.authenticate(passphrase.as_ref(), token.as_ref(), now)
+                self.authenticate(passphrase.as_ref(), device, token.as_ref(), now)
                     .and_then(|vault| run_authenticated(vault, command))
                     .map(|warnings| {
                         if let Some(name) = added {
@@ -1254,6 +1273,13 @@ impl Daemon {
                     .as_secs()
             }),
             pending_approvals: self.approvals.len(),
+            devices: match &self.vault {
+                Some(vault) => vault.devices(),
+                None => device_slots(&self.vault_path).unwrap_or_default(),
+            }
+            .into_iter()
+            .map(|slot| slot.kind)
+            .collect(),
         }
     }
 
@@ -1306,12 +1332,14 @@ impl Daemon {
         }
     }
 
-    /// Checks the passphrase, unlocking the vault if it is locked, or else
-    /// a session token, and returns the unlocked vault. Wrong passphrases
-    /// count toward the backoff; a token is too long to guess.
+    /// Checks the passphrase or a device key, unlocking the vault if it is
+    /// locked, or else a session token, and returns the unlocked vault.
+    /// Wrong passphrases and device keys count toward the backoff; a token is
+    /// too long to guess.
     fn authenticate(
         &mut self,
         passphrase: Option<&SecretText>,
+        device: Option<&DeviceCredential>,
         token: Option<&SecretText>,
         now: Instant,
     ) -> Result<&mut Vault, Failure> {
@@ -1325,12 +1353,12 @@ impl Daemon {
                 .as_mut()
                 .expect("a session needs the vault unlocked"));
         }
-        let passphrase = passphrase.ok_or_else(|| {
-            fail(
+        if passphrase.is_none() && device.is_none() {
+            return Err(fail(
                 ControlErrorCode::PassphraseRequired,
                 "this command needs the vault passphrase",
-            )
-        })?;
+            ));
+        }
         if let Err(wait) = self.throttle.check(now) {
             return Err(fail(
                 ControlErrorCode::TooManyAttempts,
@@ -1340,12 +1368,21 @@ impl Daemon {
                 ),
             ));
         }
-        let result = if let Some(vault) = &self.vault {
-            vault.verify_passphrase(passphrase.expose())
-        } else {
-            Vault::unlock(&self.vault_path, passphrase.expose()).map(|vault| {
-                self.vault = Some(vault);
-            })
+        let result = match (passphrase, device) {
+            (Some(passphrase), _) => match &self.vault {
+                Some(vault) => vault.verify_passphrase(passphrase.expose()),
+                None => Vault::unlock(&self.vault_path, passphrase.expose())
+                    .map(|vault| self.vault = Some(vault)),
+            },
+            (None, Some(device)) => match device_key(&device.key) {
+                None => Err(VaultError::DeviceKeyRejected),
+                Some(key) => match &self.vault {
+                    Some(vault) => vault.verify_device(&device.id, &key),
+                    None => Vault::unlock_with_device(&self.vault_path, &device.id, &key)
+                        .map(|vault| self.vault = Some(vault)),
+                },
+            },
+            (None, None) => unreachable!("checked above"),
         };
         match result {
             Ok(()) => {
@@ -1360,6 +1397,13 @@ impl Daemon {
                 self.throttle.record_failure(now);
                 Err(fail(ControlErrorCode::WrongPassphrase, "wrong passphrase"))
             }
+            Err(VaultError::DeviceKeyRejected) => {
+                self.throttle.record_failure(now);
+                Err(fail(
+                    ControlErrorCode::WrongDeviceKey,
+                    VaultError::DeviceKeyRejected.to_string(),
+                ))
+            }
             Err(VaultError::NotFound(_)) => Err(fail(
                 ControlErrorCode::NoVault,
                 "there is no vault yet; run `kv init`",
@@ -1389,6 +1433,20 @@ fn run_authenticated(vault: &mut Vault, command: ControlCommand) -> Result<Vec<S
                 Err(e) => Err(internal(e)),
             }
         }
+        ControlCommand::EnrollDevice {
+            kind,
+            id,
+            data,
+            key,
+        } => enroll_device(vault, kind, id, &data, &key),
+        ControlCommand::RemoveDevice { kind } => match vault.remove_device(kind) {
+            Ok(Some(_)) => Ok(Vec::new()),
+            Ok(None) => Err(fail(
+                ControlErrorCode::Invalid,
+                format!("{} is not set up for this vault", kind.label()),
+            )),
+            Err(e) => Err(internal(e)),
+        },
         ControlCommand::Unlock
         | ControlCommand::Init { .. }
         | ControlCommand::Lock
@@ -1646,7 +1704,42 @@ fn describe(command: &ControlCommand) -> (&'static str, Option<String>) {
         ControlCommand::Overview => ("overview", None),
         ControlCommand::Decide { .. } => ("decide", None),
         ControlCommand::DismissRequest { .. } => ("dismiss_request", None),
+        ControlCommand::EnrollDevice { .. } => ("enroll_device", None),
+        ControlCommand::RemoveDevice { .. } => ("remove_device", None),
+    }
+}
+
+/// A device key as sent: 32 bytes in hex.
+fn device_key(hex_key: &SecretText) -> Option<SymmetricKey> {
+    let bytes = Zeroizing::new(hex::decode(hex_key.expose()).ok()?);
+    SymmetricKey::from_slice(&bytes).ok()
+}
+
+fn enroll_device(
+    vault: &mut Vault,
+    kind: DeviceKind,
+    id: String,
+    data: &str,
+    key: &SecretText,
+) -> Result<Vec<String>, Failure> {
+    let invalid = |message: &str| fail(ControlErrorCode::Invalid, message);
+    let id_ok = !id.is_empty()
+        && id.len() <= 128
+        && id
+            .bytes()
+            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
+    if !id_ok {
+        return Err(invalid("a device id is 1-128 letters, digits, '-' or '_'"));
     }
+    let data = hex::decode(data).map_err(|_| invalid("device data must be hex"))?;
+    if data.len() > 4096 {
+        return Err(invalid("device data is larger than kv keeps"));
+    }
+    let key = device_key(key).ok_or_else(|| invalid("a device key is 32 bytes as hex"))?;
+    vault
+        .enroll_device(DeviceSlot { kind, id, data }, &key)
+        .map(|()| Vec::new())
+        .map_err(internal)
 }
 
 const SESSION_ENDED: &str = "the kv tui session has ended because the vault locked; unlock again";
diff --git a/crates/kv/src/tui.rs b/crates/kv/src/tui.rs
index 7059c3072c521884da88b19b5fcc48f82f141fdf..30387659ab65ade40386024897d3570b275d92d0 100644
--- a/crates/kv/src/tui.rs
+++ b/crates/kv/src/tui.rs
@@ -44,6 +44,7 @@ impl Driver {
             Effect::OpenSession(passphrase) => {
                 let request = ControlRequest {
                     passphrase: Some(passphrase),
+                    device: None,
                     token: None,
                     command: ControlCommand::OpenSession,
                 };
@@ -88,6 +89,7 @@ impl Driver {
                 self.token = None;
                 let request = ControlRequest {
                     passphrase: None,
+                    device: None,
                     token: None,
                     command: ControlCommand::Lock,
                 };
@@ -124,6 +126,7 @@ impl Driver {
         };
         let request = ControlRequest {
             passphrase: None,
+            device: None,
             token: Some(token),
             command,
         };
```

- [ ] **Step 4: Run the tests to watch them pass**

Run: `cargo test -p kv-core --test proto && cargo test -p kv`
Expected: PASS, including the five new `device` tests.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "Let the daemon unlock with a device key and enroll or remove devices"
```

### Task 3: The client side: Touch ID and Windows Hello

**Files:**
- Create: `crates/kv/tests/device_unlock.rs`
- Modify: `crates/kv/Cargo.toml`
- Create: `crates/kv/src/device.rs`
- Create: `crates/kv/src/device/macos.rs`
- Create: `crates/kv/src/device/windows.rs`
- Modify: `crates/kv/src/lib.rs`

**Interfaces:**
- Consumes: Task 1 `DeviceKind`, `DeviceSlot`, `device_slots`; Task 2 `DeviceCredential`, `ControlCommand::EnrollDevice`.
- Produces: `kv::device::{Device` trait (`kind() -> DeviceKind`, `available() -> Result<(), String>`, `enroll(&self, id: &str) -> Result<(Vec<u8>, SymmetricKey), String>`, `unlock(&self, &DeviceSlot) -> Result<SymmetricKey, String>`, `forget(&self, id: &str)`; `Send + Sync`), `platform() -> Option<Box<dyn Device>>` (honours `KV_BIOMETRIC`), `native() -> Option<Box<dyn Device>>` (ignores it), `enabled(Option<&OsStr>) -> bool` (`off`/`0`/`false`/`no`, any case, turn it off), `new_id() -> String` ("kv-" + 32 hex), `enroll(&dyn Device) -> Result<(DeviceSlot, SymmetricKey), String>`, `enroll_command(DeviceSlot, &SymmetricKey) -> ControlCommand`, `credential(&Path, &dyn Device) -> Option<Result<DeviceCredential, String>>` (`None` without a slot of the device's kind)}`. `device::macos::TouchId` (LocalAuthentication + login keychain, service `kv vault`, account = slot id, slot data = `evaluatedPolicyDomainState`) and `device::windows::Hello` (`KeyCredentialManager`, HKDF-SHA256 salt `kv-windows-hello-v1`, info `vault wrapping key`, slot data = 32-byte challenge). New dependencies: macOS `block2 0.6`, `objc2 0.6`, `objc2-foundation 0.3`, `objc2-local-authentication 0.3`, `security-framework 3`; Windows `windows 0.62`, `hkdf 0.13`, `sha2 0.11`.

- [ ] **Step 1: Write the failing tests**

Apply with `git apply` from the repository root:

```diff
diff --git a/crates/kv/tests/device_unlock.rs b/crates/kv/tests/device_unlock.rs
new file mode 100644
index 0000000000000000000000000000000000000000..46b718c8ba171efe95a207a91648e3f7f2e00f49
--- /dev/null
+++ b/crates/kv/tests/device_unlock.rs
@@ -0,0 +1,129 @@
+//! The client side of Touch ID and Windows Hello: finding the vault's slot
+//! for this platform's device and turning what the device returns into a
+//! credential for the daemon. A fake device stands in for the platform.
+
+use std::collections::HashMap;
+use std::sync::Mutex;
+
+use kv::device::{self, Device};
+use kv_core::crypto::{KdfParams, SymmetricKey};
+use kv_core::vault::{DeviceKind, DeviceSlot, Vault};
+use tempfile::TempDir;
+
+const FAST: KdfParams = KdfParams {
+    m_kib: 8,
+    t: 1,
+    p: 1,
+};
+
+#[derive(Default)]
+struct Fake {
+    keys: Mutex<HashMap<String, [u8; 32]>>,
+    refuse: Option<&'static str>,
+}
+
+impl Device for Fake {
+    fn kind(&self) -> DeviceKind {
+        DeviceKind::TouchId
+    }
+
+    fn available(&self) -> Result<(), String> {
+        self.refuse.map_or(Ok(()), |why| Err(why.into()))
+    }
+
+    fn enroll(&self, id: &str) -> Result<(Vec<u8>, SymmetricKey), String> {
+        self.available()?;
+        let key = SymmetricKey::generate();
+        self.keys.lock().unwrap().insert(id.into(), *key.as_bytes());
+        Ok((b"fingerprints".to_vec(), key))
+    }
+
+    fn unlock(&self, slot: &DeviceSlot) -> Result<SymmetricKey, String> {
+        self.available()?;
+        let keys = self.keys.lock().unwrap();
+        let key = keys.get(&slot.id).ok_or("no key for this slot")?;
+        Ok(SymmetricKey::from_slice(key).unwrap())
+    }
+
+    fn forget(&self, id: &str) {
+        self.keys.lock().unwrap().remove(id);
+    }
+}
+
+#[test]
+fn an_enrolled_device_gives_a_credential_that_opens_the_vault() {
+    let dir = TempDir::new().unwrap();
+    let path = dir.path().join("vault.kv");
+    let mut vault = Vault::create(&path, "correct horse battery", FAST).unwrap();
+    let fake = Fake::default();
+    assert!(
+        device::credential(&path, &fake).is_none(),
+        "nothing enrolled"
+    );
+
+    let (slot, key) = device::enroll(&fake).unwrap();
+    assert_eq!(slot.kind, DeviceKind::TouchId);
+    assert_eq!(slot.data, b"fingerprints");
+    vault.enroll_device(slot.clone(), &key).unwrap();
+
+    let credential = device::credential(&path, &fake).unwrap().unwrap();
+    assert_eq!(credential.id, slot.id);
+    assert_eq!(credential.key.expose(), hex::encode(key.as_bytes()));
+    Vault::unlock_with_device(&path, &slot.id, &key).unwrap();
+
+    fake.forget(&slot.id);
+    let error = device::credential(&path, &fake).unwrap().unwrap_err();
+    assert!(error.contains("no key"), "{error}");
+}
+
+#[test]
+fn a_device_that_is_not_available_says_why() {
+    let fake = Fake {
+        refuse: Some("Touch ID is not set up on this Mac"),
+        ..Fake::default()
+    };
+    let error = device::enroll(&fake).unwrap_err();
+    assert!(error.contains("not set up"), "{error}");
+}
+
+#[test]
+fn ids_are_random_and_safe_for_the_platform() {
+    let (a, b) = (device::new_id(), device::new_id());
+    assert_ne!(a, b);
+    assert!(a.starts_with("kv-") && a.len() == 35, "{a}");
+    assert!(a[3..].bytes().all(|b| b.is_ascii_hexdigit()));
+}
+
+#[test]
+fn kv_biometric_off_turns_device_unlock_off() {
+    assert!(device::enabled(None));
+    assert!(device::enabled(Some("on".as_ref())));
+    for off in ["off", "0", "false", "OFF"] {
+        assert!(!device::enabled(Some(off.as_ref())), "{off}");
+    }
+}
+
+#[test]
+fn the_enroll_command_carries_the_slot_and_key_as_hex() {
+    let slot = DeviceSlot {
+        kind: DeviceKind::WindowsHello,
+        id: "kv-1".into(),
+        data: vec![1, 2, 255],
+    };
+    let key = SymmetricKey::from_slice(&[7; 32]).unwrap();
+    match device::enroll_command(slot, &key) {
+        kv_core::proto::ControlCommand::EnrollDevice {
+            kind,
+            id,
+            data,
+            key,
+        } => {
+            assert_eq!(
+                (kind, id.as_str(), data.as_str()),
+                (DeviceKind::WindowsHello, "kv-1", "0102ff")
+            );
+            assert_eq!(key.expose(), "07".repeat(32));
+        }
+        other => panic!("{other:?}"),
+    }
+}
```

- [ ] **Step 2: Run the tests to watch them fail**

Run: `cargo test -p kv --test device_unlock`
Expected: FAIL to compile: `error[E0432]: unresolved import kv::device`.

- [ ] **Step 3: Implement**

Apply with `git apply` (the `Cargo.lock` hunks pin the versions this plan was tested with):

```diff
diff --git a/Cargo.lock b/Cargo.lock
index 09fe9fc952df0722759dd954cfbb1c7b504970a6..be42acea702ec2e754763c14bef51508c7e1159f 100644
--- a/Cargo.lock
+++ b/Cargo.lock
@@ -1388,6 +1388,15 @@ version = "0.4.3"
 source = "registry+https://github.com/rust-lang/crates.io-index"
 checksum = "7f24254aa9a54b5c858eaee2f5bccdb46aaf0e486a595ed5fd8f86ba55232a70"
 
+[[package]]
+name = "hkdf"
+version = "0.13.0"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "4aaa26c720c68b866f2c96ef5c1264b3e6f473fe5d4ce61cd44bbe913e553018"
+dependencies = [
+ "hmac",
+]
+
 [[package]]
 name = "hmac"
 version = "0.13.0"
@@ -1817,13 +1826,18 @@ dependencies = [
 name = "kv"
 version = "0.1.0"
 dependencies = [
+ "block2",
  "clap",
  "dirs",
  "futures-util",
  "hex",
+ "hkdf",
  "humantime",
  "kv-core",
  "notify-rust",
+ "objc2",
+ "objc2-foundation",
+ "objc2-local-authentication",
  "percent-encoding",
  "postgres-protocol",
  "ratatui",
@@ -1835,14 +1849,17 @@ dependencies = [
  "rustix",
  "rustls",
  "rustls-platform-verifier",
+ "security-framework",
  "serde",
  "serde_json",
+ "sha2 0.11.0",
  "tempfile",
  "tokio",
  "tokio-postgres",
  "tokio-postgres-rustls",
  "tokio-rustls",
  "url",
+ "windows",
  "windows-sys 0.61.2",
  "wiremock",
  "zeroize",
@@ -2203,6 +2220,29 @@ dependencies = [
  "objc2-core-foundation",
 ]
 
+[[package]]
+name = "objc2-local-authentication"
+version = "0.3.2"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "e48e0b8b339e0d9d2ed4416b7f93f9d4daadff7d4dd797f89867cde11aeac607"
+dependencies = [
+ "block2",
+ "objc2",
+ "objc2-foundation",
+ "objc2-security",
+]
+
+[[package]]
+name = "objc2-security"
+version = "0.3.2"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "709fe137109bd1e8b5a99390f77a7d8b2961dafc1a1c5db8f2e60329ad6d895a"
+dependencies = [
+ "bitflags 2.13.2",
+ "objc2",
+ "objc2-core-foundation",
+]
+
 [[package]]
 name = "objc2-system-configuration"
 version = "0.3.2"
diff --git a/crates/kv/Cargo.toml b/crates/kv/Cargo.toml
index 9bfb429f7dfa3236c40f3bd4ea2d205f614b23fe..987a54d0ba7a45cd7288a3f406214e81493ce55f 100644
--- a/crates/kv/Cargo.toml
+++ b/crates/kv/Cargo.toml
@@ -30,10 +30,25 @@ tokio-rustls = { version = "0.26", default-features = false }
 url = "2.5"
 zeroize = "1.9"
 
+[target.'cfg(target_os = "macos")'.dependencies]
+block2 = "0.6"
+objc2 = "0.6"
+objc2-foundation = { version = "0.3", features = ["NSData", "NSError", "NSString"] }
+objc2-local-authentication = { version = "0.3", features = ["LAContext", "block2"] }
+security-framework = "3"
+
 [target.'cfg(unix)'.dependencies]
 rustix = { version = "1.1", features = ["process"] }
 
 [target.'cfg(windows)'.dependencies]
+hkdf = "0.13"
+sha2 = "0.11"
+windows = { version = "0.62", features = [
+    "Foundation",
+    "Security_Credentials",
+    "Security_Cryptography",
+    "Storage_Streams",
+] }
 windows-sys = { version = "0.61", features = [
     "Win32_Foundation",
     "Win32_Security",
diff --git a/crates/kv/src/device.rs b/crates/kv/src/device.rs
new file mode 100644
index 0000000000000000000000000000000000000000..d5e4801c307a9465b3ae148f8f30a30128840114
--- /dev/null
+++ b/crates/kv/src/device.rs
@@ -0,0 +1,123 @@
+//! Unlocking with Touch ID (macOS) or Windows Hello. The client asks the
+//! user through the platform and gets a 256-bit key, which it sends to the
+//! daemon in place of the passphrase; the vault keeps the vault key wrapped
+//! under it (see `kv_core::vault`). The daemon never talks to the platform.
+//!
+//! Touch ID: a random key in the login keychain, read only after macOS
+//! confirms a fingerprint. The keychain lets only the `kv` binary that
+//! saved the item read it without asking for the login password, and kv
+//! refuses the key if the Mac's enrolled fingerprints changed since. Windows
+//! Hello: a key derived from the Hello credential's signature over a random
+//! challenge kept in the vault.
+//!
+//! Set `KV_BIOMETRIC=off` to never use either.
+
+use std::ffi::OsStr;
+use std::path::Path;
+
+use kv_core::crypto::{SymmetricKey, fill_random};
+use kv_core::proto::{ControlCommand, DeviceCredential};
+use kv_core::secret::SecretText;
+use kv_core::vault::{DeviceKind, DeviceSlot, device_slots};
+use zeroize::Zeroizing;
+
+#[cfg(target_os = "macos")]
+mod macos;
+#[cfg(windows)]
+mod windows;
+
+/// A platform's way to get a key from the user.
+pub trait Device: Send + Sync {
+    fn kind(&self) -> DeviceKind;
+    /// `Err` says why the user cannot use it now.
+    fn available(&self) -> Result<(), String>;
+    /// Sets the device up under `id`, asking the user once, and returns what
+    /// the vault should keep for it and the key.
+    fn enroll(&self, id: &str) -> Result<(Vec<u8>, SymmetricKey), String>;
+    /// Asks the user and returns the key for `slot`.
+    fn unlock(&self, slot: &DeviceSlot) -> Result<SymmetricKey, String>;
+    /// Deletes what the platform keeps for `id`, if anything.
+    fn forget(&self, id: &str);
+}
+
+/// This platform's device, unless `KV_BIOMETRIC` turns it off.
+pub fn platform() -> Option<Box<dyn Device>> {
+    if !enabled(std::env::var_os("KV_BIOMETRIC").as_deref()) {
+        return None;
+    }
+    native()
+}
+
+/// This platform's device whatever `KV_BIOMETRIC` says, for turning it off.
+#[cfg(target_os = "macos")]
+pub fn native() -> Option<Box<dyn Device>> {
+    Some(Box::new(macos::TouchId))
+}
+
+#[cfg(windows)]
+pub fn native() -> Option<Box<dyn Device>> {
+    Some(Box::new(windows::Hello))
+}
+
+#[cfg(not(any(target_os = "macos", windows)))]
+pub fn native() -> Option<Box<dyn Device>> {
+    None
+}
+
+/// Whether a `KV_BIOMETRIC` value leaves device unlock on.
+pub fn enabled(setting: Option<&OsStr>) -> bool {
+    let Some(setting) = setting.and_then(OsStr::to_str) else {
+        return true;
+    };
+    !["off", "0", "false", "no"]
+        .iter()
+        .any(|off| setting.eq_ignore_ascii_case(off))
+}
+
+/// A fresh name for the platform to keep a device key under.
+pub fn new_id() -> String {
+    let mut bytes = [0u8; 16];
+    fill_random(&mut bytes);
+    format!("kv-{}", hex::encode(bytes))
+}
+
+/// Sets `device` up under a new id. The caller enrolls the slot with the
+/// daemon, and forgets the id if that fails.
+pub fn enroll(device: &dyn Device) -> Result<(DeviceSlot, SymmetricKey), String> {
+    device.available()?;
+    let id = new_id();
+    let (data, key) = device.enroll(&id)?;
+    let slot = DeviceSlot {
+        kind: device.kind(),
+        id,
+        data,
+    };
+    Ok((slot, key))
+}
+
+pub fn enroll_command(slot: DeviceSlot, key: &SymmetricKey) -> ControlCommand {
+    ControlCommand::EnrollDevice {
+        kind: slot.kind,
+        id: slot.id,
+        data: hex::encode(slot.data),
+        key: hex_secret(key),
+    }
+}
+
+/// Asks `device` for the key to the vault's slot of its kind. `None` if the
+/// vault has no such slot (or cannot be read: the daemon will say why).
+pub fn credential(vault: &Path, device: &dyn Device) -> Option<Result<DeviceCredential, String>> {
+    let slot = device_slots(vault)
+        .ok()?
+        .into_iter()
+        .find(|slot| slot.kind == device.kind())?;
+    Some(device.unlock(&slot).map(|key| DeviceCredential {
+        id: slot.id,
+        key: hex_secret(&key),
+    }))
+}
+
+fn hex_secret(key: &SymmetricKey) -> SecretText {
+    let text = Zeroizing::new(hex::encode(key.as_bytes()));
+    SecretText::new(text.as_str())
+}
diff --git a/crates/kv/src/device/macos.rs b/crates/kv/src/device/macos.rs
new file mode 100644
index 0000000000000000000000000000000000000000..77f5eaa7e872dcd5380794d1e7469c334bf3513e
--- /dev/null
+++ b/crates/kv/src/device/macos.rs
@@ -0,0 +1,103 @@
+//! Touch ID through LocalAuthentication, with the key in the login keychain.
+
+use std::sync::mpsc;
+use std::time::Duration;
+
+use block2::RcBlock;
+use kv_core::crypto::SymmetricKey;
+use kv_core::vault::{DeviceKind, DeviceSlot};
+use objc2::rc::Retained;
+use objc2::runtime::Bool;
+use objc2_foundation::{NSError, NSString};
+use objc2_local_authentication::{LAContext, LAPolicy};
+use security_framework::passwords::{
+    delete_generic_password, get_generic_password, set_generic_password,
+};
+use zeroize::Zeroizing;
+
+use super::Device;
+
+const SERVICE: &str = "kv vault";
+const POLICY: LAPolicy = LAPolicy::DeviceOwnerAuthenticationWithBiometrics;
+/// How long kv waits for a fingerprint.
+const PROMPT_TIMEOUT: Duration = Duration::from_secs(120);
+
+pub struct TouchId;
+
+impl Device for TouchId {
+    fn kind(&self) -> DeviceKind {
+        DeviceKind::TouchId
+    }
+
+    fn available(&self) -> Result<(), String> {
+        context().map(drop)
+    }
+
+    fn enroll(&self, id: &str) -> Result<(Vec<u8>, SymmetricKey), String> {
+        let context = context()?;
+        let fingerprints = fingerprints(&context)?;
+        ask(&context, "turn on Touch ID unlock for kv")?;
+        let key = SymmetricKey::generate();
+        set_generic_password(SERVICE, id, key.as_bytes())
+            .map_err(|e| format!("could not save the key in the login keychain: {e}"))?;
+        Ok((fingerprints, key))
+    }
+
+    fn unlock(&self, slot: &DeviceSlot) -> Result<SymmetricKey, String> {
+        let context = context()?;
+        if fingerprints(&context)? != slot.data {
+            return Err(
+                "the fingerprints on this Mac changed since Touch ID unlock was turned \
+                        on; run `kv biometric enable` again"
+                    .into(),
+            );
+        }
+        ask(&context, "unlock the kv vault")?;
+        let raw = get_generic_password(SERVICE, &slot.id)
+            .map(Zeroizing::new)
+            .map_err(|e| {
+                format!(
+                    "could not read the key from the login keychain ({e}); run `kv biometric \
+                     enable` again"
+                )
+            })?;
+        SymmetricKey::from_slice(&raw).map_err(|_| "the keychain item is damaged".into())
+    }
+
+    fn forget(&self, id: &str) {
+        let _ = delete_generic_password(SERVICE, id);
+    }
+}
+
+fn context() -> Result<Retained<LAContext>, String> {
+    let context = unsafe { LAContext::new() };
+    unsafe { context.canEvaluatePolicy_error(POLICY) }
+        .map_err(|e| format!("Touch ID is not available: {}", e.localizedDescription()))?;
+    Ok(context)
+}
+
+/// The set of enrolled fingerprints, as an opaque value that changes when a
+/// finger is added or removed.
+#[allow(deprecated)]
+fn fingerprints(context: &LAContext) -> Result<Vec<u8>, String> {
+    unsafe { context.evaluatedPolicyDomainState() }
+        .map(|state| state.to_vec())
+        .ok_or_else(|| "macOS did not report the enrolled fingerprints".into())
+}
+
+/// Shows the Touch ID prompt and waits for the answer.
+fn ask(context: &LAContext, reason: &str) -> Result<(), String> {
+    let (tx, rx) = mpsc::channel();
+    let reply = RcBlock::new(move |ok: Bool, error: *mut NSError| {
+        let why = match unsafe { error.as_ref() } {
+            Some(error) => error.localizedDescription().to_string(),
+            None => "Touch ID failed".to_owned(),
+        };
+        let _ = tx.send(if ok.as_bool() { Ok(()) } else { Err(why) });
+    });
+    unsafe {
+        context.evaluatePolicy_localizedReason_reply(POLICY, &NSString::from_str(reason), &reply);
+    }
+    rx.recv_timeout(PROMPT_TIMEOUT)
+        .map_err(|_| "no answer from Touch ID in time".to_owned())?
+}
diff --git a/crates/kv/src/device/windows.rs b/crates/kv/src/device/windows.rs
new file mode 100644
index 0000000000000000000000000000000000000000..a4ba392980412f03cc8e63979f05d1b3eeb3b081
--- /dev/null
+++ b/crates/kv/src/device/windows.rs
@@ -0,0 +1,97 @@
+//! Windows Hello through `KeyCredentialManager`. The credential's RSA
+//! signature (PKCS #1 v1.5, so the same every time) over a random challenge
+//! kept in the vault is turned into the key with HKDF-SHA256.
+
+use hkdf::Hkdf;
+use kv_core::crypto::{KEY_LEN, SymmetricKey};
+use kv_core::vault::{DeviceKind, DeviceSlot};
+use sha2::Sha256;
+use windows::Security::Credentials::{
+    KeyCredential, KeyCredentialCreationOption, KeyCredentialManager, KeyCredentialStatus,
+};
+use windows::Security::Cryptography::CryptographicBuffer;
+use windows::core::{Array, HSTRING};
+use zeroize::Zeroizing;
+
+use super::Device;
+
+const SALT: &[u8] = b"kv-windows-hello-v1";
+const CHALLENGE_LEN: usize = 32;
+
+pub struct Hello;
+
+impl Device for Hello {
+    fn kind(&self) -> DeviceKind {
+        DeviceKind::WindowsHello
+    }
+
+    fn available(&self) -> Result<(), String> {
+        let supported = KeyCredentialManager::IsSupportedAsync()
+            .and_then(|op| op.join())
+            .map_err(|e| format!("Windows Hello is not available: {}", e.message()))?;
+        if supported {
+            Ok(())
+        } else {
+            Err("Windows Hello is not set up on this computer".into())
+        }
+    }
+
+    fn enroll(&self, id: &str) -> Result<(Vec<u8>, SymmetricKey), String> {
+        let result = KeyCredentialManager::RequestCreateAsync(
+            &HSTRING::from(id),
+            KeyCredentialCreationOption::ReplaceExisting,
+        )
+        .and_then(|op| op.join())
+        .map_err(|e| e.message())?;
+        check(result.Status())?;
+        let credential = result.Credential().map_err(|e| e.message())?;
+        let mut challenge = vec![0u8; CHALLENGE_LEN];
+        kv_core::crypto::fill_random(&mut challenge);
+        let key = derive(&credential, &challenge)?;
+        Ok((challenge, key))
+    }
+
+    fn unlock(&self, slot: &DeviceSlot) -> Result<SymmetricKey, String> {
+        let result = KeyCredentialManager::OpenAsync(&HSTRING::from(slot.id.as_str()))
+            .and_then(|op| op.join())
+            .map_err(|e| e.message())?;
+        check(result.Status())?;
+        let credential = result.Credential().map_err(|e| e.message())?;
+        derive(&credential, &slot.data)
+    }
+
+    fn forget(&self, id: &str) {
+        let _ = KeyCredentialManager::DeleteAsync(&HSTRING::from(id)).and_then(|op| op.join());
+    }
+}
+
+fn derive(credential: &KeyCredential, challenge: &[u8]) -> Result<SymmetricKey, String> {
+    let data = CryptographicBuffer::CreateFromByteArray(challenge).map_err(|e| e.message())?;
+    let result = credential
+        .RequestSignAsync(&data)
+        .and_then(|op| op.join())
+        .map_err(|e| e.message())?;
+    check(result.Status())?;
+    let signature = result.Result().map_err(|e| e.message())?;
+    let mut bytes = Array::<u8>::new();
+    CryptographicBuffer::CopyToByteArray(&signature, &mut bytes).map_err(|e| e.message())?;
+    let mut key = Zeroizing::new([0u8; KEY_LEN]);
+    Hkdf::<Sha256>::new(Some(SALT), &bytes)
+        .expand(b"vault wrapping key", key.as_mut_slice())
+        .map_err(|_| "could not derive the key".to_owned())?;
+    SymmetricKey::from_slice(key.as_slice()).map_err(|e| e.to_string())
+}
+
+fn check(status: windows::core::Result<KeyCredentialStatus>) -> Result<(), String> {
+    match status.map_err(|e| e.message())? {
+        KeyCredentialStatus::Success => Ok(()),
+        KeyCredentialStatus::UserCanceled => Err("Windows Hello was cancelled".into()),
+        KeyCredentialStatus::NotFound => {
+            Err("the Windows Hello key for kv is gone; run `kv biometric enable` again".into())
+        }
+        KeyCredentialStatus::UserPrefersPassword => {
+            Err("Windows Hello was declined; use the passphrase".into())
+        }
+        other => Err(format!("Windows Hello failed (status {})", other.0)),
+    }
+}
diff --git a/crates/kv/src/lib.rs b/crates/kv/src/lib.rs
index 8070a25b79b6c5a6a79c0421aecf3aac6e522c95..a2fe05509198c9a8a1cd9eb52309b6e41ed9c3de 100644
--- a/crates/kv/src/lib.rs
+++ b/crates/kv/src/lib.rs
@@ -5,6 +5,7 @@ pub mod broker;
 pub mod cli;
 pub mod client;
 pub mod daemon;
+pub mod device;
 pub mod frame;
 pub mod ipc;
 pub mod mcp;
```

- [ ] **Step 4: Run the tests to watch them pass**

Run: `cargo test -p kv --test device_unlock && cargo clippy -p kv --all-targets -- -D warnings`
Expected: PASS, 5 tests; clippy clean. `device/windows.rs` is compiled by CI on windows-latest only (aws-lc-sys does not cross-compile from macOS).

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "Ask Touch ID or Windows Hello for the vault key on the client"
```

### Task 4: `kv biometric` and device-first CLI commands

**Files:**
- Modify: `crates/kv/src/cli.rs`
- Modify: `crates/kv/tests/cli.rs`
- Modify: `crates/kv-core/src/proto.rs`

**Interfaces:**
- Consumes: Task 2 protocol; Task 3 `device::{platform, native, enroll, enroll_command, credential}`.
- Produces: `kv biometric enable` (passphrase, then the device; forgets the new id if the daemon refuses, and the old slot's id on success; prints "<label> unlock is on") and `kv biometric disable` ("<label> unlock is not on" without a slot; prints "<label> unlock is off"). `kv unlock`, `add`, `rm`, `policy` and `biometric disable` ask the device first when stdin is a terminal, and ask for the passphrase when the device fails or the daemon answers `WrongDeviceKey`. `kv passwd` forgets this platform's device keys after the change. `kv status` adds a "<label> unlock is on" line per device. `ControlCommand` derives `Clone`.

- [ ] **Step 1: Write the failing tests**

Apply with `git apply` from the repository root:

```diff
diff --git a/crates/kv/src/cli.rs b/crates/kv/src/cli.rs
index 5fd19e2559a31c1c95865217810a749ca19cbcc6..a4954ed570a2830a755d36bf19634232899b55a9 100644
--- a/crates/kv/src/cli.rs
+++ b/crates/kv/src/cli.rs
@@ -700,6 +700,30 @@ mod tests {
         assert_eq!(patch.read_only, Some(true));
     }
 
+    #[test]
+    fn status_says_which_devices_can_unlock() {
+        let status = |locked, devices| Status {
+            vault_exists: true,
+            locked,
+            handle_count: (!locked).then_some(2),
+            locks_in_secs: None,
+            pending_approvals: 0,
+            devices,
+        };
+        assert_eq!(
+            describe_status(&status(true, vec![])),
+            "locked: run `kv unlock`"
+        );
+        assert_eq!(
+            describe_status(&status(true, vec![DeviceKind::TouchId])),
+            "locked: run `kv unlock`\nTouch ID unlock is on"
+        );
+        assert_eq!(
+            describe_status(&status(false, vec![DeviceKind::WindowsHello])),
+            "unlocked: 2 handles\nWindows Hello unlock is on"
+        );
+    }
+
     #[test]
     fn cli_definition_is_valid() {
         use clap::CommandFactory;
diff --git a/crates/kv/tests/cli.rs b/crates/kv/tests/cli.rs
index 51d38dab7335c6a1c17814f2388a67920de090d1..95f364017e7cd43ffbbbb834d0b82fb24c36baba 100644
--- a/crates/kv/tests/cli.rs
+++ b/crates/kv/tests/cli.rs
@@ -542,3 +542,28 @@ fn a_base_url_handle_lists_as_paths_only_without_its_address() {
     );
     assert!(!json.contains("dokploy.internal"), "{json}");
 }
+
+#[test]
+fn biometric_unlock_stays_off_when_kv_biometric_says_so() {
+    let kv = Kv::initialized();
+    let mut command = kv.command(&["biometric", "enable"]);
+    command.env("KV_BIOMETRIC", "off");
+    let output = run_kv(command, &format!("{PASS}\n"));
+    assert!(!output.status.success());
+    let stderr = String::from_utf8_lossy(&output.stderr);
+    assert!(
+        stderr.contains("KV_BIOMETRIC") || stderr.contains("no biometric unlock"),
+        "{stderr}"
+    );
+    assert!(!kv.ok(&["status"], "").contains("unlock is on"));
+}
+
+#[test]
+fn turning_off_biometric_unlock_that_is_not_on_says_so() {
+    let kv = Kv::initialized();
+    let stderr = kv.fails(&["biometric", "disable"], &format!("{PASS}\n"));
+    assert!(
+        stderr.contains("is not on") || stderr.contains("no biometric unlock"),
+        "{stderr}"
+    );
+}
```

- [ ] **Step 2: Run the tests to watch them fail**

Run: `cargo test -p kv --lib cli; cargo test -p kv --test cli`
Expected: FAIL: the lib test does not compile (`cannot find type DeviceKind in this scope`), and `biometric_unlock_stays_off_when_kv_biometric_says_so` and `turning_off_biometric_unlock_that_is_not_on_says_so` fail with `error: unrecognized subcommand 'biometric'`.

- [ ] **Step 3: Implement**

Apply with `git apply`:

```diff
diff --git a/crates/kv-core/src/proto.rs b/crates/kv-core/src/proto.rs
index 3db57a523409d2b11e3afd9f396d89dc8bb2e14f..f2fb62b7a6c50f01bcbc1bb5a82ebdc0122c7bb1 100644
--- a/crates/kv-core/src/proto.rs
+++ b/crates/kv-core/src/proto.rs
@@ -285,7 +285,7 @@ pub struct ControlRequest {
     pub command: ControlCommand,
 }
 
-#[derive(Debug, Serialize, Deserialize)]
+#[derive(Clone, Debug, Serialize, Deserialize)]
 #[serde(tag = "type", rename_all = "snake_case")]
 pub enum ControlCommand {
     /// Creates the vault. `insecure_fast_kdf` uses cheap Argon2 settings and
diff --git a/crates/kv/src/cli.rs b/crates/kv/src/cli.rs
index a4954ed570a2830a755d36bf19634232899b55a9..92c62dd0a41c69de449db7c45898f66c369183a7 100644
--- a/crates/kv/src/cli.rs
+++ b/crates/kv/src/cli.rs
@@ -8,14 +8,16 @@ use std::time::Duration;
 use clap::{Args, Parser, Subcommand, ValueEnum};
 use kv_core::policy::{Mode, Policy};
 use kv_core::proto::{
-    AgentRequest, AgentResponse, ControlCommand, ControlRequest, ControlResponse, PolicyPatch,
-    Status,
+    AgentRequest, AgentResponse, ControlCommand, ControlErrorCode, ControlRequest, ControlResponse,
+    DeviceCredential, PolicyPatch, Status,
 };
 use kv_core::secret::{AuthPlacement, HandleInfo, Secret, SecretText, SecretValue};
+use kv_core::vault::device_slots;
 use zeroize::Zeroizing;
 
 use crate::client;
 use crate::daemon::{self, Outcome, Settings};
+use crate::device;
 use crate::paths::Paths;
 
 #[derive(Parser)]
@@ -62,6 +64,11 @@ enum Command {
     },
     /// Change the vault passphrase
     Passwd,
+    /// Unlock with Touch ID (macOS) or Windows Hello instead of the passphrase
+    Biometric {
+        #[command(subcommand)]
+        action: BiometricAction,
+    },
     /// Serve MCP on stdin and stdout, for agents such as Claude Code
     Mcp,
     /// Approve agent requests, see handles and lock the vault in a terminal UI
@@ -95,6 +102,14 @@ enum Command {
     },
 }
 
+#[derive(Subcommand)]
+enum BiometricAction {
+    /// Turn it on: asks for the passphrase, then a fingerprint or Hello
+    Enable,
+    /// Turn it off
+    Disable,
+}
+
 #[derive(Args)]
 struct AddArgs {
     /// Handle name agents use, e.g. openrouter or prod-db
@@ -275,8 +290,7 @@ async fn run(cli: Cli) -> Result<()> {
             Ok(())
         }
         Command::Unlock => {
-            let passphrase = input.secret("Vault passphrase: ")?;
-            control(&paths, Some(passphrase), ControlCommand::Unlock).await?;
+            authorized(&paths, &mut input, ControlCommand::Unlock).await?;
             println!("unlocked");
             Ok(())
         }
@@ -313,7 +327,7 @@ async fn run(cli: Cli) -> Result<()> {
             Ok(())
         }
         Command::Add(args) => {
-            let passphrase = input.secret("Vault passphrase: ")?;
+            let credential = input.credential(&paths).await?;
             let value = read_value(&args, &mut input)?;
             let mut policy = Policy::default();
             args.policy.patch().apply(&mut policy);
@@ -331,15 +345,11 @@ async fn run(cli: Cli) -> Result<()> {
                 created_at: 0,
                 updated_at: 0,
             };
-            control(
-                &paths,
-                Some(passphrase),
-                ControlCommand::Add {
-                    secret,
-                    replace: args.replace,
-                },
-            )
-            .await?;
+            let command = ControlCommand::Add {
+                secret,
+                replace: args.replace,
+            };
+            send_as(&paths, &mut input, credential, command).await?;
             println!("added {}", args.name);
             if let Some(url) = role_url {
                 match crate::broker::db::check_role(&args.name, url.expose()).await {
@@ -353,13 +363,8 @@ async fn run(cli: Cli) -> Result<()> {
             Ok(())
         }
         Command::Rm { name } => {
-            let passphrase = input.secret("Vault passphrase: ")?;
-            control(
-                &paths,
-                Some(passphrase),
-                ControlCommand::Remove { name: name.clone() },
-            )
-            .await?;
+            let command = ControlCommand::Remove { name: name.clone() };
+            authorized(&paths, &mut input, command).await?;
             println!("removed {name}");
             Ok(())
         }
@@ -370,16 +375,11 @@ async fn run(cli: Cli) -> Result<()> {
                     "nothing to change; pass at least one policy flag".into(),
                 ));
             }
-            let passphrase = input.secret("Vault passphrase: ")?;
-            control(
-                &paths,
-                Some(passphrase),
-                ControlCommand::SetPolicy {
-                    name: name.clone(),
-                    patch,
-                },
-            )
-            .await?;
+            let command = ControlCommand::SetPolicy {
+                name: name.clone(),
+                patch,
+            };
+            authorized(&paths, &mut input, command).await?;
             println!("updated {name}");
             Ok(())
         }
@@ -394,15 +394,125 @@ async fn run(cli: Cli) -> Result<()> {
         Command::Passwd => {
             let passphrase = input.secret("Current passphrase: ")?;
             let new_passphrase = input.new_passphrase("New passphrase: ")?;
+            let enrolled = device_slots(&paths.vault).unwrap_or_default();
             control(
                 &paths,
                 Some(passphrase),
                 ControlCommand::ChangePassphrase { new_passphrase },
             )
             .await?;
+            // The new vault key has no device slots: their keys open nothing.
+            if let Some(native) = device::native() {
+                for slot in enrolled.iter().filter(|slot| slot.kind == native.kind()) {
+                    native.forget(&slot.id);
+                }
+            }
             println!("passphrase changed");
             Ok(())
         }
+        Command::Biometric {
+            action: BiometricAction::Enable,
+        } => enable_device(&paths, &mut input).await,
+        Command::Biometric {
+            action: BiometricAction::Disable,
+        } => disable_device(&paths, &mut input).await,
+    }
+}
+
+async fn enable_device(paths: &Paths, input: &mut Input) -> Result<()> {
+    let Some(device) = device::platform() else {
+        return Err(CliError(no_device()));
+    };
+    device.available().map_err(CliError)?;
+    let passphrase = input.secret("Vault passphrase: ")?;
+    let previous = device_slots(&paths.vault)
+        .unwrap_or_default()
+        .into_iter()
+        .find(|slot| slot.kind == device.kind());
+    let (enrolled, device) = tokio::task::spawn_blocking(move || {
+        let enrolled = device::enroll(device.as_ref());
+        (enrolled, device)
+    })
+    .await
+    .map_err(|e| CliError(e.to_string()))?;
+    let (slot, key) = enrolled.map_err(CliError)?;
+    let id = slot.id.clone();
+    if let Err(e) = control(paths, Some(passphrase), device::enroll_command(slot, &key)).await {
+        device.forget(&id);
+        return Err(e);
+    }
+    if let Some(previous) = previous {
+        device.forget(&previous.id);
+    }
+    println!("{} unlock is on", device.kind().label());
+    Ok(())
+}
+
+async fn disable_device(paths: &Paths, input: &mut Input) -> Result<()> {
+    let Some(device) = device::native() else {
+        return Err(CliError(no_device()));
+    };
+    let kind = device.kind();
+    let Some(slot) = device_slots(&paths.vault)
+        .map_err(|e| CliError(e.to_string()))?
+        .into_iter()
+        .find(|slot| slot.kind == kind)
+    else {
+        return Err(CliError(format!("{} unlock is not on", kind.label())));
+    };
+    authorized(paths, input, ControlCommand::RemoveDevice { kind }).await?;
+    device.forget(&slot.id);
+    println!("{} unlock is off", kind.label());
+    Ok(())
+}
+
+fn no_device() -> String {
+    match device::native() {
+        Some(device) => format!(
+            "{} unlock is turned off by KV_BIOMETRIC; unset it to use it",
+            device.kind().label()
+        ),
+        None => "there is no biometric unlock kv can use on this platform (it uses Touch ID on \
+                 macOS and Windows Hello on Windows)"
+            .into(),
+    }
+}
+
+/// How a command proves it comes from the user.
+enum Credential {
+    Passphrase(SecretText),
+    Device(DeviceCredential),
+}
+
+/// Sends `command` with the credential `Input::credential` picks.
+async fn authorized(paths: &Paths, input: &mut Input, command: ControlCommand) -> Result<()> {
+    let credential = input.credential(paths).await?;
+    send_as(paths, input, credential, command).await
+}
+
+/// Sends `command` with `credential`. If the daemon turns down a device key
+/// (the vault changed since it was set up), asks for the passphrase and
+/// sends it again.
+async fn send_as(
+    paths: &Paths,
+    input: &mut Input,
+    credential: Credential,
+    command: ControlCommand,
+) -> Result<()> {
+    let device = match credential {
+        Credential::Passphrase(passphrase) => {
+            return control(paths, Some(passphrase), command).await;
+        }
+        Credential::Device(device) => device,
+    };
+    match send(paths, None, Some(device), command.clone()).await? {
+        Ok(()) => Ok(()),
+        Err((ControlErrorCode::WrongDeviceKey, message)) => {
+            eprintln!("{message}; run `kv biometric enable` to set it up again");
+            let passphrase = input.secret("Vault passphrase: ")?;
+            control(paths, Some(passphrase), command).await
+        }
+        Err((_, message)) => Err(CliError(message)),
     }
 }
 
@@ -412,9 +522,22 @@ async fn control(
     passphrase: Option<SecretText>,
     command: ControlCommand,
 ) -> Result<()> {
+    send(paths, passphrase, None, command)
+        .await?
+        .map_err(|(_, message)| CliError(message))
+}
+
+/// Sends a control command and prints its warnings; the outer `Err` is a
+/// failure to reach the daemon, the inner one the daemon's refusal.
+async fn send(
+    paths: &Paths,
+    passphrase: Option<SecretText>,
+    device: Option<DeviceCredential>,
+    command: ControlCommand,
+) -> Result<std::result::Result<(), (ControlErrorCode, String)>> {
     let request = ControlRequest {
         passphrase,
-        device: None,
+        device,
         token: None,
         command,
     };
@@ -423,9 +546,9 @@ async fn control(
             for warning in warnings {
                 eprintln!("warning: {warning}");
             }
-            Ok(())
+            Ok(Ok(()))
         }
-        ControlResponse::Error { message, .. } => Err(CliError(message)),
+        ControlResponse::Error { code, message } => Ok(Err((code, message))),
         other => Err(CliError(format!(
             "unexpected reply from the daemon: {other:?}"
         ))),
@@ -521,6 +644,29 @@ impl Input {
         }
     }
 
+    /// Touch ID or Windows Hello when the vault has a slot for this
+    /// platform's device and stdin is a terminal (so scripts keep reading
+    /// the passphrase from stdin), or else the passphrase.
+    async fn credential(&mut self, paths: &Paths) -> io::Result<Credential> {
+        if self.interactive
+            && let Some(device) = device::platform()
+        {
+            let label = device.kind().label();
+            let vault = paths.vault.clone();
+            let asked =
+                tokio::task::spawn_blocking(move || device::credential(&vault, device.as_ref()))
+                    .await
+                    .map_err(io::Error::other)?;
+            match asked {
+                Some(Ok(credential)) => return Ok(Credential::Device(credential)),
+                Some(Err(why)) => eprintln!("{label}: {why}"),
+                None => {}
+            }
+        }
+        self.secret("Vault passphrase: ")
+            .map(Credential::Passphrase)
+    }
+
     fn secret(&mut self, prompt: &str) -> io::Result<SecretText> {
         if self.interactive {
             return rpassword::prompt_password(prompt).map(SecretText::new);
@@ -557,18 +703,22 @@ fn describe_status(status: &Status) -> String {
     if !status.vault_exists {
         return "no vault yet: run `kv init`".into();
     }
-    if status.locked {
-        return "locked: run `kv unlock`".into();
-    }
-    let count = status.handle_count.unwrap_or(0);
-    let plural = if count == 1 { "" } else { "s" };
-    let mut line = match status.locks_in_secs {
-        Some(secs) => format!(
-            "unlocked: {count} handle{plural}, locks after {} unused",
-            humantime::format_duration(Duration::from_secs(secs))
-        ),
-        None => format!("unlocked: {count} handle{plural}"),
+    let mut line = if status.locked {
+        "locked: run `kv unlock`".to_owned()
+    } else {
+        let count = status.handle_count.unwrap_or(0);
+        let plural = if count == 1 { "" } else { "s" };
+        match status.locks_in_secs {
+            Some(secs) => format!(
+                "unlocked: {count} handle{plural}, locks after {} unused",
+                humantime::format_duration(Duration::from_secs(secs))
+            ),
+            None => format!("unlocked: {count} handle{plural}"),
+        }
     };
+    for kind in &status.devices {
+        line.push_str(&format!("\n{} unlock is on", kind.label()));
+    }
     match status.pending_approvals {
         0 => {}
         1 => line.push_str("\n1 request is waiting for approval: run `kv tui`"),
@@ -655,6 +805,7 @@ fn unexpected(response: &AgentResponse) -> CliError {
 #[cfg(test)]
 mod tests {
     use super::*;
+    use kv_core::vault::DeviceKind;
 
     #[test]
     fn notify_takes_on_or_off() {
```

- [ ] **Step 4: Run the tests to watch them pass**

Run: `cargo test -p kv --lib cli && cargo test -p kv --test cli`
Expected: PASS, 5 lib `cli` tests and 25 `cli` tests.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "Add kv biometric and ask the device before the passphrase"
```

### Task 5: Touch ID and Hello in `kv tui`

**Files:**
- Modify: `crates/kv/tests/device_unlock.rs`
- Create: `crates/kv/tests/fake/mod.rs`
- Modify: `crates/kv/tests/tui.rs`
- Create: `crates/kv/tests/tui_device.rs`
- Modify: `crates/kv/src/tui.rs`
- Modify: `crates/kv/src/tui/app.rs`
- Modify: `crates/kv/src/tui/view.rs`

**Interfaces:**
- Consumes: Task 2 `DeviceCredential`, `Status.devices`; Task 3 `Device`, `device::{platform, credential}`.
- Produces: `kv::tui::Driver::{with_device(Paths, Option<Arc<dyn Device>>) -> Driver, device(&self) -> Option<DeviceKind>}` (the device's kind when the vault has a slot for it); `Driver::new` uses `device::platform()`. `Effect::DeviceUnlock`; `App::{set_device(Option<DeviceKind>), device() -> Option<DeviceKind>, ask_device(&mut self) -> Option<Effect>}`. Ctrl-T on the unlock screen asks the device; `kv tui` asks once at start when the vault has a slot. Failures read "<label>: <why>; type the passphrase" or "<label> unlock is not on for this vault: run `kv biometric enable`". Test helper `tests/fake/mod.rs` (`Fake { keys, refuse }`), now shared with `device_unlock.rs`.

- [ ] **Step 1: Write the failing tests**

Apply with `git apply` from the repository root:

```diff
diff --git a/crates/kv/tests/device_unlock.rs b/crates/kv/tests/device_unlock.rs
index 46b718c8ba171efe95a207a91648e3f7f2e00f49..ed511290ce2b892eeae8d4ce877aa92908ad01d9 100644
--- a/crates/kv/tests/device_unlock.rs
+++ b/crates/kv/tests/device_unlock.rs
@@ -2,9 +2,9 @@
 //! for this platform's device and turning what the device returns into a
 //! credential for the daemon. A fake device stands in for the platform.
 
-use std::collections::HashMap;
-use std::sync::Mutex;
+mod fake;
 
+use fake::Fake;
 use kv::device::{self, Device};
 use kv_core::crypto::{KdfParams, SymmetricKey};
 use kv_core::vault::{DeviceKind, DeviceSlot, Vault};
@@ -16,40 +16,6 @@ const FAST: KdfParams = KdfParams {
     p: 1,
 };
 
-#[derive(Default)]
-struct Fake {
-    keys: Mutex<HashMap<String, [u8; 32]>>,
-    refuse: Option<&'static str>,
-}
-
-impl Device for Fake {
-    fn kind(&self) -> DeviceKind {
-        DeviceKind::TouchId
-    }
-
-    fn available(&self) -> Result<(), String> {
-        self.refuse.map_or(Ok(()), |why| Err(why.into()))
-    }
-
-    fn enroll(&self, id: &str) -> Result<(Vec<u8>, SymmetricKey), String> {
-        self.available()?;
-        let key = SymmetricKey::generate();
-        self.keys.lock().unwrap().insert(id.into(), *key.as_bytes());
-        Ok((b"fingerprints".to_vec(), key))
-    }
-
-    fn unlock(&self, slot: &DeviceSlot) -> Result<SymmetricKey, String> {
-        self.available()?;
-        let keys = self.keys.lock().unwrap();
-        let key = keys.get(&slot.id).ok_or("no key for this slot")?;
-        Ok(SymmetricKey::from_slice(key).unwrap())
-    }
-
-    fn forget(&self, id: &str) {
-        self.keys.lock().unwrap().remove(id);
-    }
-}
-
 #[test]
 fn an_enrolled_device_gives_a_credential_that_opens_the_vault() {
     let dir = TempDir::new().unwrap();
diff --git a/crates/kv/tests/fake/mod.rs b/crates/kv/tests/fake/mod.rs
new file mode 100644
index 0000000000000000000000000000000000000000..85220a08a073ae139b0a86189c8b3040d4ce7b6f
--- /dev/null
+++ b/crates/kv/tests/fake/mod.rs
@@ -0,0 +1,44 @@
+//! A stand-in for Touch ID: keys live in memory, and `refuse` plays a
+//! device the user cannot use right now.
+#![allow(dead_code)]
+
+use std::collections::HashMap;
+use std::sync::Mutex;
+
+use kv::device::Device;
+use kv_core::crypto::SymmetricKey;
+use kv_core::vault::{DeviceKind, DeviceSlot};
+
+#[derive(Default)]
+pub struct Fake {
+    pub keys: Mutex<HashMap<String, [u8; 32]>>,
+    pub refuse: Option<&'static str>,
+}
+
+impl Device for Fake {
+    fn kind(&self) -> DeviceKind {
+        DeviceKind::TouchId
+    }
+
+    fn available(&self) -> Result<(), String> {
+        self.refuse.map_or(Ok(()), |why| Err(why.into()))
+    }
+
+    fn enroll(&self, id: &str) -> Result<(Vec<u8>, SymmetricKey), String> {
+        self.available()?;
+        let key = SymmetricKey::generate();
+        self.keys.lock().unwrap().insert(id.into(), *key.as_bytes());
+        Ok((b"fingerprints".to_vec(), key))
+    }
+
+    fn unlock(&self, slot: &DeviceSlot) -> Result<SymmetricKey, String> {
+        self.available()?;
+        let keys = self.keys.lock().unwrap();
+        let key = keys.get(&slot.id).ok_or("no key for this slot")?;
+        Ok(SymmetricKey::from_slice(key).unwrap())
+    }
+
+    fn forget(&self, id: &str) {
+        self.keys.lock().unwrap().remove(id);
+    }
+}
diff --git a/crates/kv/tests/tui.rs b/crates/kv/tests/tui.rs
index 0aa696b95824bf1a0613247a18eb394109a87bc0..e7f2904cd871c8a0b62a03700ade7d222fbd158b 100644
--- a/crates/kv/tests/tui.rs
+++ b/crates/kv/tests/tui.rs
@@ -9,6 +9,7 @@ use kv::tui::view;
 use kv_core::policy::Mode;
 use kv_core::proto::{Approval, Overview, Status, Verdict};
 use kv_core::secret::{HandleInfo, SecretKind};
+use kv_core::vault::DeviceKind;
 use ratatui::Terminal;
 use ratatui::backend::TestBackend;
 use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
@@ -354,3 +355,33 @@ fn a_pasted_passphrase_is_one_input() {
         other => panic!("{other:?}"),
     }
 }
+
+#[test]
+fn the_unlock_screen_offers_touch_id_only_when_it_is_set_up() {
+    let mut app = App::new();
+    let ctrl_t = KeyEvent::new(KeyCode::Char('t'), KeyModifiers::CONTROL);
+    assert_eq!(app.handle_key(ctrl_t), None, "no device, no Ctrl-T");
+    assert!(!screen(&app).contains("Touch ID"));
+
+    app.set_device(Some(DeviceKind::TouchId));
+    assert!(screen(&app).contains("Ctrl-T Touch ID"), "{}", screen(&app));
+    type_text(&mut app, "half");
+    assert_eq!(app.handle_key(ctrl_t), Some(Effect::DeviceUnlock));
+    assert!(screen(&app).contains("asking Touch ID"), "{}", screen(&app));
+
+    // A refusal leaves the passphrase to type, and Ctrl-T to try again.
+    app.apply(Outcome::Failed(
+        "Touch ID: canceled; type the passphrase".into(),
+    ));
+    assert_eq!(app.screen(), Screen::Unlock);
+    assert!(screen(&app).contains("canceled"));
+    assert_eq!(app.handle_key(ctrl_t), Some(Effect::DeviceUnlock));
+}
+
+#[test]
+fn ctrl_t_does_nothing_once_unlocked() {
+    let mut app = unlocked(Vec::new());
+    app.set_device(Some(DeviceKind::TouchId));
+    let ctrl_t = KeyEvent::new(KeyCode::Char('t'), KeyModifiers::CONTROL);
+    assert_eq!(app.handle_key(ctrl_t), None);
+}
diff --git a/crates/kv/tests/tui_device.rs b/crates/kv/tests/tui_device.rs
new file mode 100644
index 0000000000000000000000000000000000000000..d5d57aae0bfae26ae81bdc0d1b4c986830fa1840
--- /dev/null
+++ b/crates/kv/tests/tui_device.rs
@@ -0,0 +1,90 @@
+//! `kv tui` unlocking with Touch ID or Windows Hello, against a real daemon
+//! in this process and a fake device.
+
+mod fake;
+mod live;
+
+use std::sync::Arc;
+
+use fake::Fake;
+use kv::device::{self, Device};
+use kv::tui::Driver;
+use kv::tui::app::{Effect, Outcome};
+use kv_core::proto::ControlCommand;
+use kv_core::vault::DeviceKind;
+use live::{Daemon, PASS};
+
+async fn enrolled(daemon: &Daemon) -> Arc<Fake> {
+    let fake = Arc::new(Fake::default());
+    let (slot, key) = device::enroll(fake.as_ref()).unwrap();
+    daemon
+        .control(Some(PASS), device::enroll_command(slot, &key))
+        .await;
+    daemon.control(None, ControlCommand::Lock).await;
+    fake
+}
+
+#[tokio::test(flavor = "multi_thread")]
+async fn an_enrolled_device_opens_the_tui_session() {
+    let daemon = Daemon::start().await;
+    let fake = enrolled(&daemon).await;
+    let mut driver = Driver::with_device(daemon.paths.clone(), Some(fake as Arc<dyn Device>));
+    assert_eq!(driver.device(), Some(DeviceKind::TouchId));
+    assert!(matches!(
+        driver.run(Effect::DeviceUnlock).await,
+        Outcome::Opened
+    ));
+    match driver.refresh().await {
+        Some(Outcome::Overview(overview)) => {
+            assert!(!overview.status.locked);
+            assert_eq!(overview.status.devices, vec![DeviceKind::TouchId]);
+        }
+        other => panic!("{other:?}"),
+    }
+}
+
+#[tokio::test(flavor = "multi_thread")]
+async fn without_a_slot_the_tui_does_not_offer_the_device() {
+    let daemon = Daemon::start().await;
+    let fake: Arc<dyn Device> = Arc::new(Fake::default());
+    let mut driver = Driver::with_device(daemon.paths.clone(), Some(fake));
+    assert_eq!(driver.device(), None);
+    match driver.run(Effect::DeviceUnlock).await {
+        Outcome::Failed(message) => assert!(message.contains("kv biometric enable"), "{message}"),
+        other => panic!("{other:?}"),
+    }
+    let mut driver = Driver::with_device(daemon.paths.clone(), None);
+    assert_eq!(driver.device(), None);
+    assert!(matches!(
+        driver.run(Effect::DeviceUnlock).await,
+        Outcome::Failed(_)
+    ));
+}
+
+#[tokio::test(flavor = "multi_thread")]
+async fn a_refused_or_wrong_device_key_leaves_the_tui_locked() {
+    let daemon = Daemon::start().await;
+    let fake = enrolled(&daemon).await;
+    let mut driver =
+        Driver::with_device(daemon.paths.clone(), Some(fake.clone() as Arc<dyn Device>));
+
+    // The key the platform hands back no longer matches the vault.
+    for key in fake.keys.lock().unwrap().values_mut() {
+        *key = [7; 32];
+    }
+    match driver.run(Effect::DeviceUnlock).await {
+        Outcome::Failed(message) => assert!(message.contains("not set up"), "{message}"),
+        other => panic!("{other:?}"),
+    }
+    assert!(driver.refresh().await.is_none(), "no session");
+
+    // The user cancels the prompt.
+    fake.keys.lock().unwrap().clear();
+    match driver.run(Effect::DeviceUnlock).await {
+        Outcome::Failed(message) => {
+            assert!(message.starts_with("Touch ID: "), "{message}");
+            assert!(message.contains("passphrase"), "{message}");
+        }
+        other => panic!("{other:?}"),
+    }
+}
```

- [ ] **Step 2: Run the tests to watch them fail**

Run: `cargo test -p kv --test tui --test tui_device`
Expected: FAIL to compile: `no variant ... named DeviceUnlock found for enum Effect`, `no associated function ... named with_device found for struct Driver`, `no method named set_device found for struct App`.

- [ ] **Step 3: Implement**

Apply with `git apply`:

```diff
diff --git a/crates/kv/src/tui.rs b/crates/kv/src/tui.rs
index 30387659ab65ade40386024897d3570b275d92d0..9462323df868b5f691d0d1bcaa9accae6291751d 100644
--- a/crates/kv/src/tui.rs
+++ b/crates/kv/src/tui.rs
@@ -1,6 +1,7 @@
 //! `kv tui`: approve waiting agent requests, edit handles, lock the vault.
-//! Unlocking trades the passphrase for a session token held only in this
-//! process; every later request uses the token.
+//! Unlocking trades the passphrase, or a key from Touch ID or Windows Hello,
+//! for a session token held only in this process; every later request uses
+//! the token.
 
 pub mod app;
 mod edit;
@@ -8,16 +9,21 @@ pub mod form;
 pub mod view;
 
 use std::io::{self, IsTerminal};
+use std::sync::Arc;
 use std::time::Duration;
 
-use kv_core::proto::{ControlCommand, ControlErrorCode, ControlRequest, ControlResponse};
+use kv_core::proto::{
+    ControlCommand, ControlErrorCode, ControlRequest, ControlResponse, DeviceCredential,
+};
 use kv_core::secret::SecretText;
+use kv_core::vault::{DeviceKind, device_slots};
 use ratatui::DefaultTerminal;
 use ratatui::crossterm::event::{
     self, DisableBracketedPaste, EnableBracketedPaste, Event, KeyEventKind,
 };
 use ratatui::crossterm::execute;
 
+use crate::device::{self, Device};
 use crate::paths::Paths;
 use crate::{audit, client};
 use app::{App, Effect, Outcome, Tab};
@@ -32,32 +38,38 @@ const AUDIT_LINES: usize = 200;
 pub struct Driver {
     paths: Paths,
     token: Option<SecretText>,
+    device: Option<Arc<dyn Device>>,
 }
 
 impl Driver {
+    /// A driver that unlocks with this platform's device when the vault has
+    /// it set up.
     pub fn new(paths: Paths) -> Self {
-        Self { paths, token: None }
+        Self::with_device(paths, device::platform().map(Arc::from))
+    }
+
+    pub fn with_device(paths: Paths, device: Option<Arc<dyn Device>>) -> Self {
+        Self {
+            paths,
+            token: None,
+            device,
+        }
+    }
+
+    /// The device to offer: this platform's, if the vault has a slot for it.
+    pub fn device(&self) -> Option<DeviceKind> {
+        let kind = self.device.as_ref()?.kind();
+        device_slots(&self.paths.vault)
+            .ok()?
+            .iter()
+            .any(|slot| slot.kind == kind)
+            .then_some(kind)
     }
 
     pub async fn run(&mut self, effect: Effect) -> Outcome {
         match effect {
-            Effect::OpenSession(passphrase) => {
-                let request = ControlRequest {
-                    passphrase: Some(passphrase),
-                    device: None,
-                    token: None,
-                    command: ControlCommand::OpenSession,
-                };
-                match client::control(&self.paths, &request, true).await {
-                    Ok(ControlResponse::Session { token }) => {
-                        self.token = Some(token);
-                        Outcome::Opened
-                    }
-                    Ok(ControlResponse::Error { message, .. }) => Outcome::Failed(message),
-                    Ok(other) => Outcome::Failed(format!("unexpected reply: {other:?}")),
-                    Err(e) => Outcome::Failed(format!("could not reach the kv daemon: {e}")),
-                }
-            }
+            Effect::OpenSession(passphrase) => self.open_session(Some(passphrase), None).await,
+            Effect::DeviceUnlock => self.device_unlock().await,
             Effect::Decide { id, verdict } => {
                 self.send(ControlCommand::Decide { id, verdict }).await
             }
@@ -103,6 +115,47 @@ impl Driver {
         }
     }
 
+    async fn device_unlock(&mut self) -> Outcome {
+        let Some(chosen) = self.device.clone() else {
+            return Outcome::Failed("there is no biometric unlock here".into());
+        };
+        let label = chosen.kind().label();
+        let vault = self.paths.vault.clone();
+        // The prompt blocks until the user answers.
+        let asked =
+            tokio::task::spawn_blocking(move || device::credential(&vault, chosen.as_ref())).await;
+        match asked {
+            Ok(Some(Ok(credential))) => self.open_session(None, Some(credential)).await,
+            Ok(Some(Err(why))) => Outcome::Failed(format!("{label}: {why}; type the passphrase")),
+            Ok(None) => Outcome::Failed(format!(
+                "{label} unlock is not on for this vault: run `kv biometric enable`"
+            )),
+            Err(e) => Outcome::Failed(format!("{label}: {e}")),
+        }
+    }
+
+    async fn open_session(
+        &mut self,
+        passphrase: Option<SecretText>,
+        device: Option<DeviceCredential>,
+    ) -> Outcome {
+        let request = ControlRequest {
+            passphrase,
+            device,
+            token: None,
+            command: ControlCommand::OpenSession,
+        };
+        match client::control(&self.paths, &request, true).await {
+            Ok(ControlResponse::Session { token }) => {
+                self.token = Some(token);
+                Outcome::Opened
+            }
+            Ok(ControlResponse::Error { message, .. }) => Outcome::Failed(message),
+            Ok(other) => Outcome::Failed(format!("unexpected reply: {other:?}")),
+            Err(e) => Outcome::Failed(format!("could not reach the kv daemon: {e}")),
+        }
+    }
+
     /// Fetches what the screen shows. `None` without a session.
     pub async fn refresh(&mut self) -> Option<Outcome> {
         self.token.as_ref()?;
@@ -191,6 +244,12 @@ async fn event_loop(terminal: &mut DefaultTerminal, paths: Paths) -> io::Result<
     });
     let mut app = App::new();
     let mut driver = Driver::new(paths);
+    app.set_device(driver.device());
+    // With Touch ID or Hello set up, ask right away; Ctrl-T asks again.
+    if let Some(effect) = app.ask_device() {
+        terminal.draw(|frame| view::draw(frame, &app))?;
+        app.apply(driver.run(effect).await);
+    }
     let mut tick = tokio::time::interval(REFRESH);
     loop {
         terminal.draw(|frame| view::draw(frame, &app))?;
diff --git a/crates/kv/src/tui/app.rs b/crates/kv/src/tui/app.rs
index a6739302950abd2f6a7842424245e854477413de..ce62377de343c9350b4aa2f321f504de1fe9c120 100644
--- a/crates/kv/src/tui/app.rs
+++ b/crates/kv/src/tui/app.rs
@@ -6,6 +6,7 @@ use kv_core::proto::{Overview, PolicyPatch, Verdict};
 
 use crate::audit::Entry;
 use kv_core::secret::{Secret, SecretText, SecretValue};
+use kv_core::vault::DeviceKind;
 use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
 use zeroize::Zeroizing;
 
@@ -29,6 +30,8 @@ pub enum Tab {
 #[derive(Debug, PartialEq, Eq)]
 pub enum Effect {
     OpenSession(SecretText),
+    /// Opens a session with Touch ID or Windows Hello.
+    DeviceUnlock,
     Decide {
         id: u64,
         verdict: Verdict,
@@ -90,6 +93,8 @@ pub struct App {
     /// The handle waiting for a yes before it is removed.
     removing: Option<String>,
     message: Option<String>,
+    /// The device the vault can be unlocked with, offered on Ctrl-T.
+    device: Option<DeviceKind>,
 }
 
 impl Default for App {
@@ -111,9 +116,26 @@ impl App {
             editor: None,
             removing: None,
             message: None,
+            device: None,
         }
     }
 
+    /// Offers `device` on the unlock screen.
+    pub fn set_device(&mut self, device: Option<DeviceKind>) {
+        self.device = device;
+    }
+
+    pub fn device(&self) -> Option<DeviceKind> {
+        self.device
+    }
+
+    /// Asks the device to unlock, if there is one and the vault is locked.
+    pub fn ask_device(&mut self) -> Option<Effect> {
+        let device = self.device.filter(|_| self.screen == Screen::Unlock)?;
+        self.message = Some(format!("asking {}…", device.label()));
+        Some(Effect::DeviceUnlock)
+    }
+
     pub fn screen(&self) -> Screen {
         self.screen
     }
@@ -166,6 +188,9 @@ impl App {
         if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
             return Some(Effect::Quit);
         }
+        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('t') {
+            return self.ask_device();
+        }
         // Ctrl and Alt letters are neither text nor commands: Ctrl+S must
         // not allow anything, and must not type an s into a secret.
         if matches!(key.code, KeyCode::Char(_))
diff --git a/crates/kv/src/tui/view.rs b/crates/kv/src/tui/view.rs
index dd0371399663b597081b539984967ffad9507aee..d716f39a04bd5eade1b872f2850fa8c6c8fdc28a 100644
--- a/crates/kv/src/tui/view.rs
+++ b/crates/kv/src/tui/view.rs
@@ -48,7 +48,11 @@ fn draw_unlock(frame: &mut Frame, app: &App) {
             Style::new().fg(Color::Yellow),
         ));
     }
-    lines.push(Line::styled("Enter unlock · Esc quit", dim()));
+    let hint = match app.device() {
+        Some(device) => format!("Enter unlock · Ctrl-T {} · Esc quit", device.label()),
+        None => "Enter unlock · Esc quit".into(),
+    };
+    lines.push(Line::styled(hint, dim()));
     let block = Block::bordered().title(" kv: unlock ");
     frame.render_widget(
         Paragraph::new(lines)
```

- [ ] **Step 4: Run the tests to watch them pass**

Run: `cargo test -p kv --test tui --test tui_device --test tui_session --test device_unlock`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "Unlock kv tui with Touch ID or Windows Hello"
```

### Task 6: Prebuilt binaries, pinned actions and the MSRV job

**Files:**
- Modify: `.github/workflows/ci.yml`
- Create: `.github/workflows/release.yml`
- Modify: `Cargo.toml`
- Modify: `crates/kv-core/Cargo.toml`
- Modify: `crates/kv/Cargo.toml`
- Create: `dist-workspace.toml`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: `dist-workspace.toml` (cargo-dist 0.33.0; targets `aarch64-apple-darwin`, `x86_64-apple-darwin`, `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`, `x86_64-pc-windows-msvc`; shell and PowerShell installers into `CARGO_HOME`; no updater; `[dist.github-action-commits]`), `[profile.dist]` in `Cargo.toml`, `repository` in `workspace.package`, the generated `.github/workflows/release.yml`, and a `msrv` CI job. Every `uses:` in `.github/workflows` names a 40-hex commit.

- [ ] **Step 1: Watch the check fail**

Run:

```bash
grep -nE 'uses: [^ ]+@' .github/workflows/*.yml | grep -vE '@[0-9a-f]{40}( |$)' | wc -l; grep -c msrv .github/workflows/ci.yml
```

Expected: `22` (no action is pinned yet) and `0` (no MSRV job).

- [ ] **Step 2: Get cargo-dist 0.33.0**

Into a scratch directory, not onto the PATH:

```bash
mkdir -p /tmp/kv-dist && cd /tmp/kv-dist
gh release download v0.33.0 -R axodotdev/cargo-dist -p 'cargo-dist-aarch64-apple-darwin.tar.xz*'
shasum -a 256 -c cargo-dist-aarch64-apple-darwin.tar.xz.sha256
tar xf cargo-dist-aarch64-apple-darwin.tar.xz
cd -
DIST=/tmp/kv-dist/cargo-dist-aarch64-apple-darwin/dist
```

Expected: `cargo-dist-aarch64-apple-darwin.tar.xz: OK`.

- [ ] **Step 3: Configure dist, pin the actions, add the MSRV job**

Apply with `git apply`. The commits in `dist-workspace.toml` and `ci.yml` are the tags noted beside them, resolved with `gh api repos/<owner>/<repo>/commits/<tag> --jq .sha`; `dtolnay/rust-toolchain` is pinned to its `stable` branch, whose `toolchain` input defaults to stable and takes `"1.89"` in the MSRV job:

```diff
diff --git a/.github/workflows/ci.yml b/.github/workflows/ci.yml
index 17272f97eb00b56d035255dd4cc22f5f6298410b..2ba71d1d7a65dfaaa7464f0b1e580b732d3c0775 100644
--- a/.github/workflows/ci.yml
+++ b/.github/workflows/ci.yml
@@ -17,17 +17,31 @@ jobs:
     runs-on: ${{ matrix.os }}
     timeout-minutes: 20
     steps:
-      - uses: actions/checkout@v5
+      - uses: actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09 # v5.1.0
         with:
           persist-credentials: false
-      - uses: dtolnay/rust-toolchain@stable
+      - uses: dtolnay/rust-toolchain@686976e191b89faba57d3206551f0f330d8cb249 # stable
         with:
           components: rustfmt, clippy
-      - uses: Swatinem/rust-cache@v2
+      - uses: Swatinem/rust-cache@6323deb102c322ba6fcbdcafc7e3dddab59af2b6 # v2.9.2
       - run: cargo fmt --all --check
       - run: cargo clippy --workspace --all-targets -- -D warnings
       - run: cargo test --workspace
 
+  msrv:
+    # rust-version in Cargo.toml is a promise; this keeps it.
+    runs-on: ubuntu-latest
+    timeout-minutes: 20
+    steps:
+      - uses: actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09 # v5.1.0
+        with:
+          persist-credentials: false
+      - uses: dtolnay/rust-toolchain@686976e191b89faba57d3206551f0f330d8cb249 # stable
+        with:
+          toolchain: "1.89"
+      - uses: Swatinem/rust-cache@6323deb102c322ba6fcbdcafc7e3dddab59af2b6 # v2.9.2
+      - run: cargo check --workspace --all-targets --locked
+
   databases:
     # db_query and db_connect against real servers; service containers run on
     # Linux only.
@@ -51,9 +65,9 @@ jobs:
       KV_TEST_REDIS_URL: redis://localhost:6379/0
       KV_REQUIRE_DB_TESTS: "1"
     steps:
-      - uses: actions/checkout@v5
+      - uses: actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09 # v5.1.0
         with:
           persist-credentials: false
-      - uses: dtolnay/rust-toolchain@stable
-      - uses: Swatinem/rust-cache@v2
+      - uses: dtolnay/rust-toolchain@686976e191b89faba57d3206551f0f330d8cb249 # stable
+      - uses: Swatinem/rust-cache@6323deb102c322ba6fcbdcafc7e3dddab59af2b6 # v2.9.2
       - run: cargo test -p kv --test db_live --test lease_live
diff --git a/Cargo.toml b/Cargo.toml
index 1ecea040d776054d048f33aded53ae665ea40084..23775858726dad84f01583f9aa8dded7f2630559 100644
--- a/Cargo.toml
+++ b/Cargo.toml
@@ -5,3 +5,9 @@ members = ["crates/kv-core", "crates/kv"]
 [workspace.package]
 edition = "2024"
 rust-version = "1.89"
+repository = "https://github.com/DFanso/key-vault-for-llm"
+
+# The profile that 'dist' will build with
+[profile.dist]
+inherits = "release"
+lto = "thin"
diff --git a/crates/kv-core/Cargo.toml b/crates/kv-core/Cargo.toml
index d17b671e7feff433dd2b4af3ae52c5b57dbff581..bbb29af3b51a6c88eea03d0d2a3e9dfe07bdc8ab 100644
--- a/crates/kv-core/Cargo.toml
+++ b/crates/kv-core/Cargo.toml
@@ -3,6 +3,7 @@ name = "kv-core"
 version = "0.1.0"
 edition.workspace = true
 rust-version.workspace = true
+repository.workspace = true
 description = "Vault, policy and output scrubbing for the kv secrets broker"
 
 [dependencies]
diff --git a/crates/kv/Cargo.toml b/crates/kv/Cargo.toml
index 987a54d0ba7a45cd7288a3f406214e81493ce55f..a6e0965b7c39891e01cb1ae6c11dde7af8d6ca18 100644
--- a/crates/kv/Cargo.toml
+++ b/crates/kv/Cargo.toml
@@ -3,6 +3,7 @@ name = "kv"
 version = "0.1.0"
 edition.workspace = true
 rust-version.workspace = true
+repository.workspace = true
 description = "Local secrets broker that lets AI agents use secrets without seeing them"
 
 [dependencies]
diff --git a/dist-workspace.toml b/dist-workspace.toml
new file mode 100644
index 0000000000000000000000000000000000000000..547b2ea4cc62722a9b2fb6d15e04bb0e5fb3f3d7
--- /dev/null
+++ b/dist-workspace.toml
@@ -0,0 +1,26 @@
+[workspace]
+members = ["cargo:."]
+
+# Config for 'dist'
+[dist]
+# The preferred dist version to use in CI (Cargo.toml SemVer syntax)
+cargo-dist-version = "0.33.0"
+# CI backends to support
+ci = "github"
+# The installers to generate for each app
+installers = ["shell", "powershell"]
+# Target platforms to build apps for (Rust target-triple syntax)
+targets = ["aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "x86_64-apple-darwin", "x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc"]
+# Path that installers should place binaries in
+install-path = "CARGO_HOME"
+# Where to host releases
+hosting = "github"
+# Whether to install an updater program
+install-updater = false
+
+# Actions in the generated release workflow, pinned to the commits of the
+# tags dist uses. Update them together with cargo-dist-version.
+[dist.github-action-commits]
+"actions/checkout" = "d23441a48e516b6c34aea4fa41551a30e30af803" # v6.1.0
+"actions/upload-artifact" = "cf430e030ddbb5b0abf93d22962f4752f3646cd9" # v7.0.2
+"actions/download-artifact" = "9000827ccba6bdab643e8b6fd33ac0654aef8333" # v8.0.2
```

- [ ] **Step 4: Generate the release workflow**

Run: `"$DIST" generate && "$DIST" generate --check && "$DIST" plan`

Expected: `generated Github CI to .../.github/workflows/release.yml`, no output from `--check`, and a plan announcing `kv 0.1.0` with `kv-installer.sh`, `kv-installer.ps1` and archives for the five targets. The workflow runs `dist plan` on pull requests and builds and publishes only for version tags.

- [ ] **Step 5: Watch the check pass**

Run:

```bash
grep -nE 'uses: [^ ]+@' .github/workflows/*.yml | grep -vE '@[0-9a-f]{40}( |$)' | wc -l; grep -c msrv .github/workflows/ci.yml
rustup toolchain install 1.89 --profile minimal
cargo +1.89 check --workspace --all-targets --locked
```

Expected: `0`, `1`, and the 1.89 check finishes without errors.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "Release prebuilt binaries with cargo-dist, pin CI actions, and check the MSRV"
```

### Task 7: README and spec

**Files:**
- Modify: `README.md`
- Modify: `docs/superpowers/specs/2026-10-08-kv-llm-secrets-broker-design.md`

**Interfaces:**
- Consumes: Tasks 1 to 6.
- Produces: README "Setup" (installers), "Touch ID and Windows Hello", and the status line; spec sections 2 (dependencies), 3 (file format, keyring note), 5 (unlock), 6 (CI) and 7 (distribution).

- [ ] **Step 1: Update the README and spec**

Apply with `git apply`:

````diff
diff --git a/README.md b/README.md
index ae2acb048d921458a2d6b0cd1df041611e9f40b8..0d3ee27a83df83fb3d948bc8c6aa67ac892b23e2 100644
--- a/README.md
+++ b/README.md
@@ -6,14 +6,25 @@ authenticated work, so API keys, database URLs and other credentials never
 show up in a chat transcript or in the model's context.
 
 Status: agents can make HTTP requests, run programs, and query or connect to
-Postgres and Redis with your secrets over MCP, and `kv tui` approves
-`--mode ask` requests as they arrive. Touch ID and Windows Hello unlock and
-prebuilt binaries come next.
+Postgres and Redis with your secrets over MCP, `kv tui` approves
+`--mode ask` requests as they arrive, and Touch ID or Windows Hello can stand
+in for the passphrase.
 
 ## Setup
 
+Install a prebuilt binary (macOS, Linux, Windows) into `~/.cargo/bin`:
+
+```sh
+curl --proto '=https' --tlsv1.2 -LsSf https://github.com/DFanso/key-vault-for-llm/releases/latest/download/kv-installer.sh | sh
+```
+
+```powershell
+powershell -ExecutionPolicy Bypass -c "irm https://github.com/DFanso/key-vault-for-llm/releases/latest/download/kv-installer.ps1 | iex"
+```
+
+or build it with `cargo install --path crates/kv` (Rust 1.89 or later). Then:
+
 ```sh
-cargo install --path crates/kv
 
 kv init                       # create the vault and choose a passphrase
 kv add openrouter --kind http --host openrouter.ai --mode auto
@@ -153,9 +164,9 @@ arguments, where they would end up in shell history.
 `X-HTTP-Method-Override`, but kv cannot see a `_method` field inside a request
 body, so for a strictly read-only key prefer one the service itself limits.
 
-Every command that changes the vault asks for the passphrase, or runs inside
-an unlocked `kv tui`, so an agent running commands as you cannot add, remove
-or loosen secrets. The vault locks
+Every command that changes the vault asks for the passphrase (or Touch ID
+or Windows Hello, below), or runs inside an unlocked `kv tui`, so an agent
+running commands as you cannot add, remove or loosen secrets. The vault locks
 itself after 8 hours without use. To change that, set `KV_IDLE_LOCK=2h` (any
 duration) in your shell profile and run `kv stop` so the next command picks it
 up.
@@ -169,9 +180,25 @@ Set `KV_HOME` to keep the vault, audit log and sockets in one directory
 instead of the platform defaults. Every use of a handle is recorded in the
 audit log (`audit.jsonl`), without values.
 
-## Planned for v1
+## Touch ID and Windows Hello
+
+```sh
+kv biometric enable           # asks for the passphrase, then a fingerprint or Hello
+kv biometric disable
+```
 
-- Touch ID and Windows Hello unlock, and prebuilt binaries
+Once it is on, `kv unlock`, `kv add`, `kv rm`, `kv policy` and `kv tui` ask
+for a fingerprint or Hello instead of the passphrase (Ctrl-T asks again on
+the TUI's unlock screen). Cancel the prompt to type the passphrase instead;
+commands that read stdin from a pipe always read the passphrase. `kv status`
+says which is on. `kv passwd` turns it off, since the new vault key has no
+copy for the device; run `kv biometric enable` again. Adding or removing a
+fingerprint on the Mac also turns Touch ID off until you enable it again.
+
+kv keeps the Touch ID key in your login keychain, where only the `kv` binary
+that saved it can read it without your login password. After you install a
+new kv, macOS asks for that password once; choose Always Allow. Set
+`KV_BIOMETRIC=off` to never use either method.
 
 ## What kv protects against
 
diff --git a/docs/superpowers/specs/2026-10-08-kv-llm-secrets-broker-design.md b/docs/superpowers/specs/2026-10-08-kv-llm-secrets-broker-design.md
index 7238ef47a8bba00d9ca8f81216ce99202bc8afad..6181ec0ee2643e2180278260bc35375b5bc4f8a5 100644
--- a/docs/superpowers/specs/2026-10-08-kv-llm-secrets-broker-design.md
+++ b/docs/superpowers/specs/2026-10-08-kv-llm-secrets-broker-design.md
@@ -72,8 +72,9 @@ Cargo workspace, Rust stable:
 Key dependencies: `tokio`, `rmcp` (MCP), `ratatui` + `crossterm` (TUI),
 `clap`, `serde`, `chacha20poly1305`, `argon2`, `zeroize`, `secrecy`,
 `aho-corasick`, `reqwest` (rustls), `tokio-postgres`, `redis`,
-`interprocess` (local sockets / named pipes), `keyring` and
-`security-framework` (biometric unlock), `notify-rust`, `dirs`.
+`interprocess` (local sockets / named pipes), `objc2-local-authentication`
+and `security-framework` (Touch ID), `windows` (Windows Hello),
+`notify-rust`, `dirs`.
 
 ### IPC
 
@@ -137,12 +138,28 @@ Path: `<config dir>/kv/vault.kv` (from `dirs::config_dir()`).
 - The vault key is stored wrapped once per unlock method:
   - **Passphrase** (always present, the only method on Linux): wrapping key
     from Argon2id.
-  - **Touch ID** (macOS): wrapping key stored as a Keychain item with
-    `kSecAccessControlBiometryCurrentSet`.
-  - **Windows Hello**: wrapping key derived via HKDF from a
-    `KeyCredentialManager` signature over a fixed per-vault challenge.
+  - **Touch ID** (macOS): a random wrapping key in a login keychain item
+    (service `kv vault`, account the slot id), read only after
+    `LAContext` confirms a fingerprint. The slot keeps the Mac's
+    `evaluatedPolicyDomainState`, and kv refuses the key once the enrolled
+    fingerprints change, as `kSecAccessControlBiometryCurrentSet` would.
+    That access control, and the data-protection keychain, need an
+    entitlement only a signed binary can carry (`errSecMissingEntitlement`,
+    -34018, for `cargo install` builds), hence the legacy keychain. The
+    item's ACL lets only the `kv` binary that saved it read it without the
+    login password, so a new build asks for it once.
+  - **Windows Hello**: wrapping key derived with HKDF-SHA256 (salt
+    `kv-windows-hello-v1`, info `vault wrapping key`) from a
+    `KeyCredentialManager` RSA signature over a random 32-byte challenge
+    kept in the slot. PKCS#1 v1.5 signatures are deterministic, so the same
+    credential and challenge give the same key.
 - Layout: header (magic, format version, KDF params, list of wrapped keys),
-  then nonce + AEAD ciphertext of the serialized secrets.
+  then nonce + AEAD ciphertext of the serialized secrets. A header with more
+  than 8 wrapped keys, more than 2 passphrase keys, or KDF parameters above
+  1 GiB of memory, 16 passes or 8 lanes is corrupt and refused before any
+  key derivation. A wrapped key of a method (or device kind) this version
+  does not know is kept on save and skipped on unlock, so a vault set up by
+  a newer kv still opens with the passphrase; one with no method is corrupt.
 - Writes are atomic (temp file, fsync, rename) and keep one `.bak` holding
   the previous version.
 - Changing the passphrase generates a new vault key, re-encrypts everything
@@ -155,7 +172,12 @@ Path: `<config dir>/kv/vault.kv` (from `dirs::config_dir()`).
 
 The OS keyring never holds anything that can decrypt the vault without user
 presence. On Windows and Linux any same-user process can read keyring items,
-which would let an agent bypass kv entirely.
+which would let an agent bypass kv entirely. On macOS the Touch ID key is
+readable without a prompt only by the `kv` binary that saved it, which reads
+it only after a fingerprint. Code that loads itself into that binary (for
+example with `DYLD_INSERT_LIBRARIES`, which binaries without the hardened
+runtime honor) skips the fingerprint; that is the same-user process of the
+threat model, which can attack the daemon the same way.
 
 ### Secret model
 
@@ -423,7 +445,16 @@ A notification announces each request.
 ### Unlock
 
 - `kv unlock` (or any control command) and, from Plan 4, `kv tui` prompt for
-  the passphrase, or a biometric from Plan 6. The daemon unwraps the vault key
+  the passphrase. From Plan 6, once `kv biometric enable` has added a slot
+  for this platform's device, `kv unlock`, `add`, `rm`, `policy` and
+  `biometric disable` ask Touch ID or Windows Hello first when stdin is a
+  terminal, and fall back to the passphrase if the user cancels or the
+  daemon turns the key down; `kv tui` asks at start and on Ctrl-T. The
+  client asks the platform and sends the daemon the slot id and key in place
+  of the passphrase (`DeviceCredential`), so the daemon never talks to the
+  platform; a wrong key counts toward the unlock backoff like a wrong
+  passphrase. Enrolling a device and changing the passphrase always take the
+  passphrase. `KV_BIOMETRIC=off` turns device unlock off. The daemon unwraps the vault key
   and holds it in memory-locked (`mlock`/`VirtualLock`, best effort), zeroized
   memory. The TUI additionally receives a random 256-bit control session token
   held only in TUI memory.
@@ -526,13 +557,19 @@ or unscrubbed paths.
 - **MCP end to end**: `rmcp` client drives `kv mcp`. Manual check with
   `claude mcp add kv -- kv mcp`.
 - **CI**: GitHub Actions matrix (macOS, Ubuntu, Windows): `cargo fmt --check`,
-  `cargo clippy -- -D warnings`, `cargo test`.
+  `cargo clippy -- -D warnings`, `cargo test`; `cargo check --locked` on the
+  MSRV (1.89). Every action is pinned to a commit.
 - **Manual per release**: Touch ID and Windows Hello unlock.
 
 ## 7. Distribution
 
-`cargo install` first; prebuilt binaries for macOS, Linux and Windows via
-`cargo-dist` as the final v1 milestone.
+`cargo install --path crates/kv`, or prebuilt binaries built by
+`cargo-dist` (0.33) on GitHub Releases when a version tag (`v0.1.0`) is
+pushed: macOS (arm64, x86_64), Linux (x86_64, arm64, glibc) and Windows
+(x86_64, MSVC), with shell and PowerShell installers that put `kv` in
+`~/.cargo/bin` and no updater. The binaries are not code-signed or
+notarized; installers fetch with `curl`/`irm`, which macOS does not
+quarantine.
 
 ## 8. Out of scope for v1
 
````

- [ ] **Step 2: Run the tests to watch them pass**

Run: `cargo fmt --all --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace`
Expected: PASS, 397 tests with both servers set.

- [ ] **Step 3: Commit**

```bash
git add -A
git commit -m "Document Touch ID, Windows Hello and prebuilt binaries"
```
