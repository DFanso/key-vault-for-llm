# kv daemon and CLI Implementation Plan (Plan 2 of 6)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the `kv` binary: a background daemon that holds the unlocked vault and answers on an agent socket and a control socket, plus the CLI (`init`, `unlock`, `lock`, `stop`, `status`, `list`, `add`, `rm`, `policy`, `passwd`, `daemon`).

**Architecture:** A new `crates/kv` crate that is both a library (so tests reach the socket and framing code) and the `kv` binary. `kv-core` gains the wire protocol (`proto`) and passphrase verification. The daemon's request handling lives in `daemon::state`, free of sockets and clocks, so every rule is unit-tested with injected times. `daemon::server` binds the sockets (Unix sockets with a same-user peer check, Windows named pipes with a current-user-only access list) and runs blocking work (Argon2) off the async threads. The CLI starts the daemon on demand. Control commands carry the vault passphrase and are checked per command; read-only commands (`status`, `list`) use the agent socket.

**Tech Stack:** Rust 2024 (MSRV 1.89, for `std::fs::File::try_lock`), tokio 1.53, clap 4.6, rpassword 7.5, dirs 7, humantime 2, region 4 (memory locking), rustix 1.1 (Unix), windows-sys 0.61 (Windows).

**Spec:** `docs/superpowers/specs/2026-10-08-kv-llm-secrets-broker-design.md`. This plan implements sections 2 (IPC, daemon lifecycle) and 5 (unlock, backoff, idle lock, audit log). Approvals, MCP, HTTP, exec and the database tools are later plans.

## Global Constraints

- `rust-version = "1.89"`, edition 2024.
- New dependencies are limited to those in Task 1's `region` line and Task 3's `crates/kv/Cargo.toml`.
- Secret values and passphrases are never accepted as command-line arguments. They come from a hidden prompt, or one per line from stdin when stdin is not a terminal.
- No agent-socket message may carry a secret value. Control-socket error replies never echo request content.
- Wrong passphrases on any control command count toward the unlock backoff.
- Commits: author `DFanso <leogavin123@outlook.com>`, no AI attribution lines or `Co-Authored-By` trailers.
- **On this Mac**, prefix cargo commands with `DEVELOPER_DIR=/Library/Developer/CommandLineTools` (the Xcode license is not accepted). The commands below include it; drop it elsewhere and in CI.
- Windows and Linux code paths are type-checked locally with `rustup target add x86_64-pc-windows-msvc x86_64-unknown-linux-gnu` (once) and `cargo clippy --target <triple>`; CI runs them for real on all three operating systems.

## Review Focus

1. **A daemon that crashed** leaves its socket files and lock file behind; the next start must replace them and serve normally. Pinned by `stale_socket_files_from_a_crashed_daemon_are_replaced` (Task 6) and `bind_replaces_a_stale_socket_file_and_makes_it_private` (Task 4).
2. **Several commands starting the daemon at the same moment** must end with exactly one daemon that all of them reach. Pinned by `concurrent_commands_start_only_one_daemon` and `a_second_daemon_exits_while_one_is_running` (Task 6).
3. **Garbage, oversized length prefixes and half-sent frames** on either socket must not take the daemon down or allocate unbounded memory. Pinned by `garbage_on_a_socket_does_not_take_the_daemon_down` (Task 6) and the frame tests in Task 3.
4. **Passphrases with spaces, non-ASCII characters or CRLF line endings** piped on stdin must be used byte-for-byte apart from the line ending, while pasted tokens and URLs lose surrounding whitespace. Pinned by `passphrases_keep_every_character_but_the_line_ending` and `trimmed_strips_surrounding_whitespace_only` (Task 6).
5. **A `KV_HOME` deep enough to exceed the Unix socket path limit** (104 bytes on macOS) must fail with a `kv:` error, not a panic. Pinned by `an_overlong_socket_path_fails_cleanly` (Task 6).

## File Structure

```
Cargo.toml                          workspace: add crates/kv, MSRV 1.89
crates/kv-core/src/crypto.rs        SymmetricKey moves into its own memory-locked allocation
crates/kv-core/src/vault.rs         verify_passphrase; kv-created vault dir is 0700
crates/kv-core/src/secret.rs        HandleInfo gains allow_plain_http and grant_ttl
crates/kv-core/src/proto.rs         agent/control request and response types, PolicyPatch
crates/kv/Cargo.toml
crates/kv/src/lib.rs                module list
crates/kv/src/main.rs               calls cli::main
crates/kv/src/paths.rs              Paths (KV_HOME or platform dirs), Endpoint
crates/kv/src/frame.rs              length-prefixed JSON frames
crates/kv/src/throttle.rs           wrong-passphrase backoff
crates/kv/src/audit.rs              JSONL audit log with rotation
crates/kv/src/ipc.rs                platform switch
crates/kv/src/ipc/unix.rs           Unix sockets, same-user peer check
crates/kv/src/ipc/windows.rs        named pipes restricted to the current user
crates/kv/src/daemon.rs             module list
crates/kv/src/daemon/state.rs       Daemon: request handling, auth, idle lock
crates/kv/src/daemon/server.rs      socket accept loops, lock file, shutdown
crates/kv/src/daemon/harden.rs      no core dumps; non-dumpable on Linux
crates/kv/src/client.rs             connect, start the daemon on demand
crates/kv/src/cli.rs                clap commands, prompts, output
crates/kv/tests/ipc.rs, state.rs, cli.rs
crates/kv-core/tests/proto.rs
README.md                           usage
```

---

### Task 1: Memory-locked keys, passphrase verification, private vault directory

**Files:**
- Modify: `Cargo.toml` (MSRV), `crates/kv-core/Cargo.toml`, `crates/kv-core/src/crypto.rs`, `crates/kv-core/src/vault.rs`, `crates/kv-core/src/secret.rs`
- Test: `crates/kv-core/tests/vault.rs`, `crates/kv-core/tests/secret.rs`

**Interfaces:**
- Consumes: Plan 1's `Vault`, `SymmetricKey`, `HandleInfo`.
- Produces: `Vault::verify_passphrase(&self, passphrase: &str) -> Result<(), VaultError>` (`WrongPassphrase` on mismatch, no file access); `HandleInfo` gains `allow_plain_http: bool` and `grant_ttl: Duration` (humantime-serialized, e.g. `"15m"`). `SymmetricKey`'s public API is unchanged; it now lives in a boxed allocation that is `region::lock`ed (best effort, never unlocked).

- [ ] **Step 1: Raise the MSRV and add `region`**

In `Cargo.toml` change `rust-version = "1.88"` to `rust-version = "1.89"`. In `crates/kv-core/Cargo.toml` add `region = "4.0"` after `percent-encoding = "2.3"`.

- [ ] **Step 2: Write the failing tests**

Save as `task1-tests.patch` and run `git apply task1-tests.patch`:
```diff
diff --git a/crates/kv-core/tests/secret.rs b/crates/kv-core/tests/secret.rs
index 06252fa..5544044 100644
--- a/crates/kv-core/tests/secret.rs
+++ b/crates/kv-core/tests/secret.rs
@@ -96,6 +96,18 @@ fn handle_info_lists_env_var_names() {
     assert_eq!(info.env_vars, vec!["A_KEY", "B_KEY"]);
 }
 
+#[test]
+fn handle_info_carries_every_policy_constraint() {
+    let mut secret = http_secret();
+    secret.policy.allow_plain_http = true;
+    secret.policy.grant_ttl = std::time::Duration::from_secs(300);
+    let info = secret.info();
+    assert!(info.allow_plain_http);
+    assert_eq!(info.grant_ttl.as_secs(), 300);
+    let json = serde_json::to_string(&info).unwrap();
+    assert!(json.contains(r#""grant_ttl":"5m""#), "{json}");
+}
+
 #[test]
 fn sensitive_values_include_db_password_raw_and_decoded() {
     let secret = pg_secret("postgres://app:p%40ss%2Fw0rd@db.internal:5432/app");
diff --git a/crates/kv-core/tests/vault.rs b/crates/kv-core/tests/vault.rs
index 8b4805a..8c4b845 100644
--- a/crates/kv-core/tests/vault.rs
+++ b/crates/kv-core/tests/vault.rs
@@ -320,3 +320,36 @@ fn bak_does_not_open_with_the_old_passphrase_after_a_change() {
     assert_eq!(from_bak.secrets(), vault.secrets());
     assert!(!path.with_file_name("vault.kv.bak.tmp").exists());
 }
+
+#[test]
+fn verify_passphrase_accepts_only_the_current_passphrase() {
+    let (_dir, path) = setup();
+    let mut vault = Vault::create(&path, PASS, FAST).unwrap();
+    assert!(vault.verify_passphrase(PASS).is_ok());
+    assert!(matches!(
+        vault.verify_passphrase("wrong horse battery"),
+        Err(VaultError::WrongPassphrase)
+    ));
+    vault
+        .change_passphrase("a brand new passphrase", FAST)
+        .unwrap();
+    assert!(matches!(
+        vault.verify_passphrase(PASS),
+        Err(VaultError::WrongPassphrase)
+    ));
+    assert!(vault.verify_passphrase("a brand new passphrase").is_ok());
+}
+
+#[cfg(unix)]
+#[test]
+fn vault_directory_is_private_to_the_user() {
+    use std::os::unix::fs::PermissionsExt;
+    let (_dir, path) = setup();
+    Vault::create(&path, PASS, FAST).unwrap();
+    let mode = fs::metadata(path.parent().unwrap())
+        .unwrap()
+        .permissions()
+        .mode()
+        & 0o777;
+    assert_eq!(mode, 0o700);
+}
```

- [ ] **Step 3: Run the tests and confirm they fail**

Run: `DEVELOPER_DIR=/Library/Developer/CommandLineTools cargo test -p kv-core --test vault --test secret`
Expected: compile errors `no method named verify_passphrase` and `no field allow_plain_http`.

- [ ] **Step 4: Implement**

Save as `task1-src.patch` and run `git apply task1-src.patch`:
```diff
diff --git a/crates/kv-core/src/crypto.rs b/crates/kv-core/src/crypto.rs
index c0b253e..c5d31a5 100644
--- a/crates/kv-core/src/crypto.rs
+++ b/crates/kv-core/src/crypto.rs
@@ -18,19 +18,36 @@ pub const SALT_LEN: usize = 16;
 /// tampered header cannot make unlock allocate unbounded memory.
 const MAX_KDF_MEMORY_KIB: u32 = 1024 * 1024;
 
-/// A 256-bit symmetric key. Zeroed on drop and never printed.
-pub struct SymmetricKey(Zeroizing<[u8; KEY_LEN]>);
+/// A 256-bit symmetric key. Zeroed on drop and never printed. Lives in its
+/// own heap allocation, which is locked into RAM where the OS allows it so
+/// the key is not written to swap.
+pub struct SymmetricKey(Box<Zeroizing<[u8; KEY_LEN]>>);
 
 impl SymmetricKey {
     pub fn generate() -> Self {
-        let mut key = Zeroizing::new([0u8; KEY_LEN]);
-        fill_random(key.as_mut_slice());
-        Self(key)
+        let mut key = Self::zeroed();
+        fill_random(key.0.as_mut_slice());
+        key
     }
 
     pub fn from_slice(bytes: &[u8]) -> Result<Self, VaultError> {
-        let array: [u8; KEY_LEN] = bytes.try_into().map_err(|_| VaultError::Corrupted)?;
-        Ok(Self(Zeroizing::new(array)))
+        if bytes.len() != KEY_LEN {
+            return Err(VaultError::Corrupted);
+        }
+        let mut key = Self::zeroed();
+        key.0.copy_from_slice(bytes);
+        Ok(key)
+    }
+
+    /// Allocates and memory-locks the key before any secret byte is written
+    /// to it. Locking is best effort: it can fail under a low `RLIMIT_MEMLOCK`,
+    /// and locked pages stay locked for the life of the process.
+    fn zeroed() -> Self {
+        let key = Box::new(Zeroizing::new([0u8; KEY_LEN]));
+        if let Ok(guard) = region::lock(key.as_ptr(), KEY_LEN) {
+            std::mem::forget(guard);
+        }
+        Self(key)
     }
 
     pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
@@ -87,11 +104,11 @@ pub fn derive_key(
     }
     let argon_params = Params::new(params.m_kib, params.t, params.p, Some(KEY_LEN))
         .map_err(|_| VaultError::Corrupted)?;
-    let mut out = Zeroizing::new([0u8; KEY_LEN]);
+    let mut out = SymmetricKey::zeroed();
     Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params)
-        .hash_password_into(passphrase, salt, out.as_mut_slice())
+        .hash_password_into(passphrase, salt, out.0.as_mut_slice())
         .map_err(|_| VaultError::Corrupted)?;
-    Ok(SymmetricKey(out))
+    Ok(out)
 }
 
 pub fn seal(key: &SymmetricKey, nonce: &[u8; NONCE_LEN], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
diff --git a/crates/kv-core/src/secret.rs b/crates/kv-core/src/secret.rs
index 3510445..6e6ed13 100644
--- a/crates/kv-core/src/secret.rs
+++ b/crates/kv-core/src/secret.rs
@@ -3,6 +3,7 @@
 
 use std::collections::BTreeMap;
 use std::fmt;
+use std::time::Duration;
 
 use percent_encoding::percent_decode_str;
 use serde::{Deserialize, Serialize};
@@ -104,9 +105,12 @@ pub struct HandleInfo {
     pub description: String,
     pub mode: Mode,
     pub allowed_hosts: Vec<String>,
+    pub allow_plain_http: bool,
     pub allowed_methods: Vec<String>,
     pub read_only: bool,
     pub allowed_cmds: Vec<String>,
+    #[serde(with = "humantime_serde")]
+    pub grant_ttl: Duration,
     /// Names of the variables an `env` secret injects.
     pub env_vars: Vec<String>,
 }
@@ -127,9 +131,11 @@ impl Secret {
             description: self.description.clone(),
             mode: self.policy.mode,
             allowed_hosts: self.policy.allowed_hosts.clone(),
+            allow_plain_http: self.policy.allow_plain_http,
             allowed_methods: self.policy.allowed_methods.clone(),
             read_only: self.policy.read_only,
             allowed_cmds: self.policy.allowed_cmds.clone(),
+            grant_ttl: self.policy.grant_ttl,
             env_vars,
         }
     }
diff --git a/crates/kv-core/src/vault.rs b/crates/kv-core/src/vault.rs
index 0593b9c..5dac7b7 100644
--- a/crates/kv-core/src/vault.rs
+++ b/crates/kv-core/src/vault.rs
@@ -94,22 +94,7 @@ impl Vault {
             Err(e) => return Err(e.into()),
         };
         let (header, aad, payload) = parse(&bytes)?;
-
-        let mut key = None;
-        for wrapped in &header.wrapped_keys {
-            let WrappedKey::Passphrase {
-                kdf,
-                salt,
-                nonce,
-                ciphertext,
-            } = wrapped;
-            let wrapping_key = crypto::derive_key(passphrase.as_bytes(), salt, *kdf)?;
-            if let Some(raw) = crypto::open(&wrapping_key, nonce, WRAP_AAD, ciphertext) {
-                key = Some(SymmetricKey::from_slice(&raw)?);
-                break;
-            }
-        }
-        let key = key.ok_or(VaultError::WrongPassphrase)?;
+        let key = unwrap_with_passphrase(&header.wrapped_keys, passphrase)?;
 
         let plaintext =
             crypto::open(&key, &header.payload_nonce, aad, payload).ok_or(VaultError::Corrupted)?;
@@ -153,6 +138,17 @@ impl Vault {
         out
     }
 
+    /// Checks `passphrase` against the vault's passphrase wrap without reading
+    /// the file. Costs one Argon2 derivation, like `unlock`.
+    pub fn verify_passphrase(&self, passphrase: &str) -> Result<(), VaultError> {
+        let key = unwrap_with_passphrase(&self.wrapped_keys, passphrase)?;
+        if key.as_bytes() == self.key.as_bytes() {
+            Ok(())
+        } else {
+            Err(VaultError::WrongPassphrase)
+        }
+    }
+
     pub fn path(&self) -> &Path {
         &self.path
     }
@@ -211,6 +207,25 @@ impl Vault {
     }
 }
 
+fn unwrap_with_passphrase(
+    wrapped_keys: &[WrappedKey],
+    passphrase: &str,
+) -> Result<SymmetricKey, VaultError> {
+    for wrapped in wrapped_keys {
+        let WrappedKey::Passphrase {
+            kdf,
+            salt,
+            nonce,
+            ciphertext,
+        } = wrapped;
+        let wrapping_key = crypto::derive_key(passphrase.as_bytes(), salt, *kdf)?;
+        if let Some(raw) = crypto::open(&wrapping_key, nonce, WRAP_AAD, ciphertext) {
+            return SymmetricKey::from_slice(&raw);
+        }
+    }
+    Err(VaultError::WrongPassphrase)
+}
+
 fn check_passphrase(passphrase: &str) -> Result<(), VaultError> {
     if passphrase.chars().count() < MIN_PASSPHRASE_CHARS {
         return Err(VaultError::WeakPassphrase);
@@ -267,7 +282,16 @@ fn write_atomic(path: &Path, bytes: &[u8], backup: Backup) -> io::Result<()> {
         .parent()
         .filter(|d| !d.as_os_str().is_empty())
         .unwrap_or(Path::new("."));
-    fs::create_dir_all(dir)?;
+    if !dir.exists() {
+        fs::create_dir_all(dir)?;
+        // Only a directory kv creates is made private; an existing one keeps
+        // the permissions its owner chose.
+        #[cfg(unix)]
+        {
+            use std::os::unix::fs::PermissionsExt;
+            fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
+        }
+    }
     let tmp = with_suffix(path, ".tmp");
     write_new_file(&tmp, bytes)?;
     let bak = with_suffix(path, ".bak");
```

Notes on the patch:
- `write_atomic` only sets `0700` on a directory it creates. An existing directory (for example one chosen via `KV_HOME`) keeps its permissions, and the Plan 1 test that makes the directory read-only to force a failed save keeps working.
- `unwrap_with_passphrase` is shared by `unlock` and `verify_passphrase`.

- [ ] **Step 5: Run the tests and confirm they pass**

Run: `DEVELOPER_DIR=/Library/Developer/CommandLineTools cargo test -p kv-core`
Expected: all kv-core tests pass: lib 6, policy 14, scrub 14, secret 8, vault 22.

Run: `DEVELOPER_DIR=/Library/Developer/CommandLineTools cargo fmt --all --check && DEVELOPER_DIR=/Library/Developer/CommandLineTools cargo clippy --workspace --all-targets -- -D warnings`
Expected: no output, exit 0.

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml Cargo.lock crates/kv-core
git commit -m "Lock vault keys in memory, add passphrase verification, private vault dir"
```

---

### Task 2: Wire protocol

**Files:**
- Create: `crates/kv-core/src/proto.rs`, `crates/kv-core/tests/proto.rs`
- Modify: `crates/kv-core/src/lib.rs` (add `pub mod proto;` after `pub mod policy;`)

**Interfaces:**
- Consumes: `HandleInfo`, `Secret`, `SecretText`, `Policy`, `Mode`.
- Produces (`kv_core::proto`): `MAX_FRAME_LEN = 1 MiB`; `AgentRequest::{ListHandles, Status}`; `AgentResponse::{Handles { handles }, Status { status: Status }, Error { code: AgentErrorCode, message }}`; `Status { vault_exists, locked, handle_count: Option<usize>, locks_in_secs: Option<u64> }`; `AgentErrorCode::{NoVault, VaultLocked, BadRequest}`; `ControlRequest { passphrase: Option<SecretText>, command: ControlCommand }`; `ControlCommand::{Init { insecure_fast_kdf }, Unlock, Lock, Stop, Add { secret, replace }, Remove { name }, SetPolicy { name, patch }, ChangePassphrase { new_passphrase }}`; `ControlResponse::{Done { warnings }, Error { code: ControlErrorCode, message }}`; `ControlErrorCode::{NoVault, VaultExists, PassphraseRequired, WrongPassphrase, TooManyAttempts, UnknownHandle, HandleExists, Invalid, BadRequest, Internal}`; `PolicyPatch` (every `Policy` field as `Option`) with `apply(&self, &mut Policy)`. All enums are serde-tagged with `"type"` in snake_case.

- [ ] **Step 1: Write the failing tests**

`crates/kv-core/tests/proto.rs`:
```rust
use std::collections::BTreeMap;
use std::time::Duration;

use kv_core::policy::{Mode, Policy};
use kv_core::proto::{
    AgentErrorCode, AgentRequest, AgentResponse, ControlCommand, ControlRequest, PolicyPatch,
    Status,
};
use kv_core::secret::{AuthPlacement, Secret, SecretText, SecretValue};

fn secrets() -> Vec<Secret> {
    let mut vars = BTreeMap::new();
    vars.insert(
        "AWS_SECRET_ACCESS_KEY".to_string(),
        SecretText::new("wJalrXUtnFEMI-K7MDENG"),
    );
    let make = |name: &str, value| Secret {
        name: name.into(),
        description: format!("{name} handle"),
        value,
        policy: Policy::default(),
        created_at: 0,
        updated_at: 0,
    };
    vec![
        make(
            "openrouter",
            SecretValue::Http {
                token: SecretText::new("sk-or-v1-0123456789abcdef"),
                placement: AuthPlacement::Header {
                    name: "Authorization".into(),
                    template: "Bearer {}".into(),
                },
            },
        ),
        make(
            "prod-db",
            SecretValue::Postgres {
                url: SecretText::new("postgres://app:hunter2hunter2@db.internal:5432/app"),
            },
        ),
        make(
            "cache",
            SecretValue::Redis {
                url: SecretText::new("redis://:r3d1s-pass@cache.internal:6379"),
            },
        ),
        make("aws", SecretValue::Env { vars }),
    ]
}

#[test]
fn agent_responses_never_contain_secret_values() {
    let secrets = secrets();
    let responses = [
        AgentResponse::Handles {
            handles: secrets.iter().map(Secret::info).collect(),
        },
        AgentResponse::Status {
            status: Status {
                vault_exists: true,
                locked: false,
                handle_count: Some(secrets.len()),
                locks_in_secs: Some(60),
            },
        },
    ];
    for response in &responses {
        let json = serde_json::to_string(response).unwrap();
        for secret in &secrets {
            for value in secret.sensitive_values() {
                assert!(
                    !json.contains(value.as_str()),
                    "{json} leaks {}",
                    value.as_str()
                );
            }
        }
        assert!(!json.contains(".internal"), "{json} leaks a host");
    }
}

#[test]
fn agent_requests_use_a_type_tag() {
    let json = serde_json::to_string(&AgentRequest::ListHandles).unwrap();
    assert_eq!(json, r#"{"type":"list_handles"}"#);
    let back: AgentRequest = serde_json::from_str(r#"{"type":"status"}"#).unwrap();
    assert_eq!(back, AgentRequest::Status);
}

#[test]
fn a_control_request_is_not_a_valid_agent_request() {
    let control = ControlRequest {
        passphrase: Some(SecretText::new("correct horse battery")),
        command: ControlCommand::Unlock,
    };
    let json = serde_json::to_string(&control).unwrap();
    assert!(serde_json::from_str::<AgentRequest>(&json).is_err());
}

#[test]
fn control_request_debug_hides_the_passphrase() {
    let control = ControlRequest {
        passphrase: Some(SecretText::new("correct horse battery")),
        command: ControlCommand::ChangePassphrase {
            new_passphrase: SecretText::new("a brand new passphrase"),
        },
    };
    let printed = format!("{control:?}");
    assert!(!printed.contains("horse"), "{printed}");
    assert!(!printed.contains("brand new"), "{printed}");
}

#[test]
fn error_codes_serialize_in_snake_case() {
    let response = AgentResponse::Error {
        code: AgentErrorCode::VaultLocked,
        message: "locked".into(),
    };
    let json = serde_json::to_string(&response).unwrap();
    assert!(json.contains(r#""code":"vault_locked""#), "{json}");
}

#[test]
fn policy_patch_changes_only_the_given_fields() {
    let mut policy = Policy {
        allowed_hosts: vec!["a.example.com".into()],
        allowed_cmds: vec!["psql".into()],
        ..Policy::default()
    };
    let patch = PolicyPatch {
        mode: Some(Mode::Auto),
        allowed_hosts: Some(vec!["b.example.com".into()]),
        grant_ttl: Some(Duration::from_secs(60)),
        ..PolicyPatch::default()
    };
    patch.apply(&mut policy);
    assert_eq!(policy.mode, Mode::Auto);
    assert_eq!(policy.allowed_hosts, vec!["b.example.com"]);
    assert_eq!(policy.allowed_cmds, vec!["psql"]);
    assert_eq!(policy.grant_ttl, Duration::from_secs(60));
}

#[test]
fn policy_patch_json_accepts_missing_fields_and_humantime() {
    let patch: PolicyPatch =
        serde_json::from_str(r#"{"read_only":true,"grant_ttl":"2h"}"#).unwrap();
    assert_eq!(patch.read_only, Some(true));
    assert_eq!(patch.grant_ttl, Some(Duration::from_secs(7200)));
    assert_eq!(patch.mode, None);
}
```

- [ ] **Step 2: Run the tests and confirm they fail**

Run: `DEVELOPER_DIR=/Library/Developer/CommandLineTools cargo test -p kv-core --test proto`
Expected: compile error `unresolved import kv_core::proto`.

- [ ] **Step 3: Implement**

`crates/kv-core/src/proto.rs`:
```rust
//! Messages exchanged with the daemon over its two local sockets.
//!
//! Agent-socket responses are built only from `HandleInfo` and status data,
//! so no agent message can carry a secret value. Control requests carry the
//! vault passphrase, because every control command except `lock` and `stop`
//! must prove the user is present.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::policy::{Mode, Policy};
use crate::secret::{HandleInfo, Secret, SecretText};

/// Largest frame either side accepts, in bytes.
pub const MAX_FRAME_LEN: usize = 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AgentRequest {
    ListHandles,
    Status,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AgentResponse {
    Handles {
        handles: Vec<HandleInfo>,
    },
    Status {
        status: Status,
    },
    Error {
        code: AgentErrorCode,
        message: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Status {
    pub vault_exists: bool,
    pub locked: bool,
    /// Present only while unlocked.
    pub handle_count: Option<usize>,
    /// Seconds until the idle timeout locks the vault, while unlocked.
    pub locks_in_secs: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentErrorCode {
    NoVault,
    VaultLocked,
    BadRequest,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ControlRequest {
    /// Required by every command except `lock` and `stop`. For `init` it is
    /// the new passphrase.
    pub passphrase: Option<SecretText>,
    pub command: ControlCommand,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ControlCommand {
    /// Creates the vault. `insecure_fast_kdf` uses cheap Argon2 settings and
    /// exists only for tests.
    Init {
        #[serde(default)]
        insecure_fast_kdf: bool,
    },
    Unlock,
    Lock,
    /// Locks the vault and shuts the daemon down.
    Stop,
    Add {
        secret: Secret,
        #[serde(default)]
        replace: bool,
    },
    Remove {
        name: String,
    },
    SetPolicy {
        name: String,
        patch: PolicyPatch,
    },
    ChangePassphrase {
        new_passphrase: SecretText,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ControlResponse {
    Done {
        #[serde(default)]
        warnings: Vec<String>,
    },
    Error {
        code: ControlErrorCode,
        message: String,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlErrorCode {
    NoVault,
    VaultExists,
    PassphraseRequired,
    WrongPassphrase,
    TooManyAttempts,
    UnknownHandle,
    HandleExists,
    Invalid,
    BadRequest,
    Internal,
}

/// A partial policy update: only the fields that are `Some` change.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyPatch {
    #[serde(default)]
    pub mode: Option<Mode>,
    #[serde(default)]
    pub allowed_hosts: Option<Vec<String>>,
    #[serde(default)]
    pub allow_plain_http: Option<bool>,
    #[serde(default)]
    pub allowed_methods: Option<Vec<String>>,
    #[serde(default)]
    pub read_only: Option<bool>,
    #[serde(default)]
    pub allowed_cmds: Option<Vec<String>>,
    #[serde(default, with = "humantime_serde")]
    pub grant_ttl: Option<Duration>,
}

impl PolicyPatch {
    pub fn apply(&self, policy: &mut Policy) {
        if let Some(mode) = self.mode {
            policy.mode = mode;
        }
        if let Some(hosts) = &self.allowed_hosts {
            policy.allowed_hosts = hosts.clone();
        }
        if let Some(plain) = self.allow_plain_http {
            policy.allow_plain_http = plain;
        }
        if let Some(methods) = &self.allowed_methods {
            policy.allowed_methods = methods.clone();
        }
        if let Some(read_only) = self.read_only {
            policy.read_only = read_only;
        }
        if let Some(cmds) = &self.allowed_cmds {
            policy.allowed_cmds = cmds.clone();
        }
        if let Some(ttl) = self.grant_ttl {
            policy.grant_ttl = ttl;
        }
    }
}
```

Add `pub mod proto;` to `crates/kv-core/src/lib.rs` after `pub mod policy;`.

- [ ] **Step 4: Run the tests and confirm they pass**

Run: `DEVELOPER_DIR=/Library/Developer/CommandLineTools cargo test -p kv-core --test proto`
Expected: `test result: ok. 7 passed`.

Run: `DEVELOPER_DIR=/Library/Developer/CommandLineTools cargo fmt --all --check && DEVELOPER_DIR=/Library/Developer/CommandLineTools cargo clippy --workspace --all-targets -- -D warnings`
Expected: no output, exit 0.

- [ ] **Step 5: Commit**

```bash
git add crates/kv-core
git commit -m "Add the daemon wire protocol to kv-core"
```

---

### Task 3: `kv` crate with paths, framing, backoff and audit log

**Files:**
- Modify: `Cargo.toml` (members)
- Create: `crates/kv/Cargo.toml`, `crates/kv/src/lib.rs`, `crates/kv/src/paths.rs`, `crates/kv/src/frame.rs`, `crates/kv/src/throttle.rs`, `crates/kv/src/audit.rs`

**Interfaces:**
- Consumes: `kv_core::proto::MAX_FRAME_LEN`.
- Produces:
  - `kv::paths`: `HOME_ENV = "KV_HOME"`; `Paths { vault, audit, runtime: PathBuf }` with `from_env() -> io::Result<Paths>`, `under(&Path) -> Paths`, `lock_file()`, `agent_endpoint() -> Endpoint`, `control_endpoint() -> Endpoint`, `ensure_runtime_dir() -> io::Result<()>`; `Endpoint` (`path: PathBuf` on Unix, `name: String` on Windows; `Display`, `Eq`).
  - `kv::frame`: `write_frame<W, T: Serialize>(&mut W, &T) -> io::Result<()>`; `read_frame<R, T: DeserializeOwned>(&mut R) -> io::Result<Option<T>>` (`None` on a clean close; `InvalidData` for oversized or malformed frames).
  - `kv::throttle::Throttle` with `check(&self, Instant) -> Result<(), Duration>`, `record_failure(&mut self, Instant)`, `record_success(&mut self)`.
  - `kv::audit::Audit` with `new(PathBuf)`, `with_max_bytes(PathBuf, u64)`, `record(&self, socket: &str, action: &str, handle: Option<&str>, outcome: &str)`.

- [ ] **Step 1: Add the crate to the workspace**

In `Cargo.toml` change `members = ["crates/kv-core"]` to `members = ["crates/kv-core", "crates/kv"]`.

`crates/kv/Cargo.toml` (later tasks use the remaining dependencies):
```toml
[package]
name = "kv"
version = "0.1.0"
edition.workspace = true
rust-version.workspace = true
description = "Local secrets broker that lets AI agents use secrets without seeing them"

[dependencies]
clap = { version = "4.6", features = ["derive"] }
dirs = "7.0"
humantime = "2"
kv-core = { path = "../kv-core" }
rpassword = "7.5"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
tokio = { version = "1.53", features = ["io-util", "macros", "net", "rt-multi-thread", "sync", "time"] }
zeroize = "1.9"

[target.'cfg(unix)'.dependencies]
rustix = { version = "1.1", features = ["process"] }

[target.'cfg(windows)'.dependencies]
windows-sys = { version = "0.61", features = [
    "Win32_Foundation",
    "Win32_Security",
    "Win32_Security_Authorization",
    "Win32_System_Threading",
] }

[dev-dependencies]
tempfile = "3.27"
```

`crates/kv/src/lib.rs` (later tasks add `client`, `cli`, `daemon` and `ipc`):
```rust
//! The kv daemon, its CLI, and the socket plumbing they share.

pub mod audit;
pub mod frame;
pub mod paths;
pub mod throttle;
```

- [ ] **Step 2: Write the failing tests**

Create each file with only its test module for now.

`crates/kv/src/paths.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kv_home_puts_everything_under_one_directory() {
        let paths = Paths::under(Path::new("/tmp/kv-home"));
        assert_eq!(paths.vault, Path::new("/tmp/kv-home/vault.kv"));
        assert_eq!(paths.audit, Path::new("/tmp/kv-home/audit.jsonl"));
        assert_eq!(paths.lock_file(), Path::new("/tmp/kv-home/run/daemon.lock"));
    }

    #[test]
    fn endpoints_differ_by_kind_and_by_home() {
        let a = Paths::under(Path::new("/tmp/a"));
        let b = Paths::under(Path::new("/tmp/b"));
        assert_ne!(a.agent_endpoint(), a.control_endpoint());
        assert_ne!(a.agent_endpoint(), b.agent_endpoint());
        assert_eq!(a.agent_endpoint(), a.agent_endpoint());
    }
}
```

`crates/kv/src/frame.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use kv_core::proto::AgentRequest;

    #[tokio::test]
    async fn round_trips_messages_in_order() {
        let (mut a, mut b) = tokio::io::duplex(64);
        let writer = tokio::spawn(async move {
            write_frame(&mut a, &AgentRequest::Status).await.unwrap();
            write_frame(&mut a, &AgentRequest::ListHandles)
                .await
                .unwrap();
        });
        let first: Option<AgentRequest> = read_frame(&mut b).await.unwrap();
        let second: Option<AgentRequest> = read_frame(&mut b).await.unwrap();
        writer.await.unwrap();
        assert_eq!(first, Some(AgentRequest::Status));
        assert_eq!(second, Some(AgentRequest::ListHandles));
        let end: Option<AgentRequest> = read_frame(&mut b).await.unwrap();
        assert_eq!(end, None);
    }

    #[tokio::test]
    async fn rejects_oversized_length_prefix_without_allocating() {
        let (mut a, mut b) = tokio::io::duplex(64);
        a.write_all(&u32::MAX.to_be_bytes()).await.unwrap();
        let err = read_frame::<_, AgentRequest>(&mut b).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn rejects_malformed_json() {
        let (mut a, mut b) = tokio::io::duplex(64);
        a.write_all(&3u32.to_be_bytes()).await.unwrap();
        a.write_all(b"{x}").await.unwrap();
        let err = read_frame::<_, AgentRequest>(&mut b).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn truncated_frame_is_an_error_not_a_clean_close() {
        let (mut a, mut b) = tokio::io::duplex(64);
        a.write_all(&10u32.to_be_bytes()).await.unwrap();
        a.write_all(b"{\"ty").await.unwrap();
        drop(a);
        let err = read_frame::<_, AgentRequest>(&mut b).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }
}
```

`crates/kv/src/throttle.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn fail(throttle: &mut Throttle, now: Instant, times: u32) {
        for _ in 0..times {
            throttle.record_failure(now);
        }
    }

    #[test]
    fn first_four_failures_are_free() {
        let now = Instant::now();
        let mut throttle = Throttle::default();
        fail(&mut throttle, now, 4);
        assert_eq!(throttle.check(now), Ok(()));
    }

    #[test]
    fn delay_doubles_from_the_fifth_failure() {
        let now = Instant::now();
        let mut throttle = Throttle::default();
        fail(&mut throttle, now, 5);
        assert_eq!(throttle.check(now), Err(Duration::from_secs(1)));
        assert_eq!(throttle.check(now + Duration::from_secs(1)), Ok(()));
        throttle.record_failure(now);
        assert_eq!(throttle.check(now), Err(Duration::from_secs(2)));
        throttle.record_failure(now);
        assert_eq!(throttle.check(now), Err(Duration::from_secs(4)));
    }

    #[test]
    fn delay_is_capped_at_five_minutes() {
        let now = Instant::now();
        let mut throttle = Throttle::default();
        fail(&mut throttle, now, 100);
        assert_eq!(throttle.check(now), Err(MAX_DELAY));
    }

    #[test]
    fn success_resets_the_count() {
        let now = Instant::now();
        let mut throttle = Throttle::default();
        fail(&mut throttle, now, 7);
        throttle.record_success();
        fail(&mut throttle, now, 4);
        assert_eq!(throttle.check(now), Ok(()));
    }
}
```

`crates/kv/src/audit.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_one_json_object_per_line() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let audit = Audit::new(path.clone());
        audit.record("control", "add", Some("openrouter"), "done");
        audit.record("agent", "list_handles", None, "done");
        let text = fs::read_to_string(&path).unwrap();
        let lines: Vec<serde_json::Value> = text
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0]["action"], "add");
        assert_eq!(lines[0]["handle"], "openrouter");
        assert!(lines[1].get("handle").is_none());
        assert!(lines[0]["ts"].as_str().unwrap().ends_with('Z'));
    }

    #[test]
    fn rotation_keeps_five_old_files() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let audit = Audit::with_max_bytes(path.clone(), 1);
        for _ in 0..10 {
            audit.record("agent", "list_handles", None, "done");
        }
        for i in 1..=5 {
            assert!(rotated(&path, i).exists(), "missing .{i}");
        }
        assert!(!rotated(&path, 6).exists());
        assert!(path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn log_is_private_to_the_user() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        Audit::new(path.clone()).record("agent", "status", None, "done");
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}
```

- [ ] **Step 3: Run the tests and confirm they fail**

Run: `DEVELOPER_DIR=/Library/Developer/CommandLineTools cargo test -p kv --lib`
Expected: compile errors such as `cannot find type Paths`, `cannot find function write_frame`, `cannot find type Throttle`, `cannot find type Audit`.

- [ ] **Step 4: Implement**

Insert each block above the test module of its file.

`crates/kv/src/paths.rs`:
```rust
//! Where kv keeps its files and how clients reach the daemon.

use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

/// Set `KV_HOME` to keep the vault, audit log and sockets under one
/// directory instead of the platform defaults.
pub const HOME_ENV: &str = "KV_HOME";

#[derive(Clone, Debug)]
pub struct Paths {
    pub vault: PathBuf,
    pub audit: PathBuf,
    /// Sockets and the daemon lock file.
    pub runtime: PathBuf,
}

impl Paths {
    pub fn from_env() -> io::Result<Self> {
        if let Some(home) = std::env::var_os(HOME_ENV) {
            return Ok(Self::under(Path::new(&home)));
        }
        let missing = || {
            io::Error::new(
                io::ErrorKind::NotFound,
                "cannot find the user's config directory; set KV_HOME",
            )
        };
        let config = dirs::config_dir().ok_or_else(missing)?.join("kv");
        let data = dirs::data_local_dir().ok_or_else(missing)?.join("kv");
        let runtime = dirs::runtime_dir()
            .map(|d| d.join("kv"))
            .unwrap_or_else(|| data.join("run"));
        Ok(Self {
            vault: config.join("vault.kv"),
            audit: data.join("audit.jsonl"),
            runtime,
        })
    }

    pub fn under(home: &Path) -> Self {
        Self {
            vault: home.join("vault.kv"),
            audit: home.join("audit.jsonl"),
            runtime: home.join("run"),
        }
    }

    pub fn lock_file(&self) -> PathBuf {
        self.runtime.join("daemon.lock")
    }

    pub fn agent_endpoint(&self) -> Endpoint {
        Endpoint::new(&self.runtime, "agent")
    }

    pub fn control_endpoint(&self) -> Endpoint {
        Endpoint::new(&self.runtime, "control")
    }

    /// Creates the runtime directory, private to the user on Unix.
    pub fn ensure_runtime_dir(&self) -> io::Result<()> {
        std::fs::create_dir_all(&self.runtime)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&self.runtime, std::fs::Permissions::from_mode(0o700))?;
        }
        Ok(())
    }
}

/// A socket the daemon listens on: a socket file in the runtime directory on
/// Unix, or on Windows a named pipe whose name is derived from that directory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Endpoint {
    #[cfg(unix)]
    pub path: PathBuf,
    #[cfg(windows)]
    pub name: String,
}

impl Endpoint {
    fn new(runtime: &Path, kind: &str) -> Self {
        #[cfg(unix)]
        {
            Self {
                path: runtime.join(format!("{kind}.sock")),
            }
        }
        #[cfg(windows)]
        {
            use std::hash::{DefaultHasher, Hash, Hasher};
            let mut hasher = DefaultHasher::new();
            runtime.hash(&mut hasher);
            Self {
                name: format!(r"\\.\pipe\kv-{:016x}-{kind}", hasher.finish()),
            }
        }
    }
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        #[cfg(unix)]
        {
            write!(f, "{}", self.path.display())
        }
        #[cfg(windows)]
        {
            f.write_str(&self.name)
        }
    }
}
```

`crates/kv/src/frame.rs`:
```rust
//! Length-prefixed JSON messages: a 4-byte big-endian length, then that many
//! bytes of JSON. Buffers are zeroed after use because control messages
//! carry passphrases and secret values.

use std::io;

use kv_core::proto::MAX_FRAME_LEN;
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zeroize::Zeroizing;

pub async fn write_frame<W, T>(writer: &mut W, message: &T) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let body = Zeroizing::new(serde_json::to_vec(message).map_err(invalid_data)?);
    if body.len() > MAX_FRAME_LEN {
        return Err(invalid_data("message is larger than the frame limit"));
    }
    let len = u32::try_from(body.len()).expect("frame limit fits in u32");
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(&body).await?;
    writer.flush().await
}

/// Returns `Ok(None)` when the peer closed the connection between messages.
/// Oversized or malformed frames are `InvalidData` errors.
pub async fn read_frame<R, T>(reader: &mut R) -> io::Result<Option<T>>
where
    R: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    let mut len = [0u8; 4];
    match reader.read_exact(&mut len).await {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_FRAME_LEN {
        return Err(invalid_data("frame is larger than the frame limit"));
    }
    let mut body = Zeroizing::new(vec![0u8; len]);
    reader.read_exact(&mut body).await?;
    serde_json::from_slice(&body)
        .map(Some)
        .map_err(invalid_data)
}

fn invalid_data(error: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}
```

`crates/kv/src/throttle.rs`:
```rust
//! Backoff after wrong passphrases, so the control socket cannot be used to
//! guess the passphrase quickly.

use std::time::{Duration, Instant};

const FREE_ATTEMPTS: u32 = 5;
const MAX_DELAY: Duration = Duration::from_secs(300);

#[derive(Debug, Default)]
pub struct Throttle {
    failures: u32,
    blocked_until: Option<Instant>,
}

impl Throttle {
    /// `Err(wait)` while attempts are blocked.
    pub fn check(&self, now: Instant) -> Result<(), Duration> {
        match self.blocked_until {
            Some(until) if until > now => Err(until - now),
            _ => Ok(()),
        }
    }

    /// From the fifth consecutive failure on, each failure blocks further
    /// attempts for 1s, 2s, 4s and so on, up to 5 minutes.
    pub fn record_failure(&mut self, now: Instant) {
        self.failures += 1;
        if self.failures >= FREE_ATTEMPTS {
            let exponent = (self.failures - FREE_ATTEMPTS).min(16);
            let delay = Duration::from_secs(1 << exponent).min(MAX_DELAY);
            self.blocked_until = Some(now + delay);
        }
    }

    pub fn record_success(&mut self) {
        *self = Self::default();
    }
}
```

`crates/kv/src/audit.rs`:
```rust
//! Append-only JSON-lines audit log of what was done with which handle.
//! Records names and outcomes, never secret values.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use serde::Serialize;

const MAX_LOG_BYTES: u64 = 10 * 1024 * 1024;
const KEEP_ROTATED: usize = 5;

#[derive(Serialize)]
struct Record<'a> {
    ts: String,
    socket: &'a str,
    action: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    handle: Option<&'a str>,
    outcome: &'a str,
}

pub struct Audit {
    path: PathBuf,
    max_bytes: u64,
}

impl Audit {
    pub fn new(path: PathBuf) -> Self {
        Self::with_max_bytes(path, MAX_LOG_BYTES)
    }

    /// Rotates once the log reaches `max_bytes`, keeping 5 old files
    /// (`audit.jsonl.1` is the newest).
    pub fn with_max_bytes(path: PathBuf, max_bytes: u64) -> Self {
        Self { path, max_bytes }
    }

    /// Appends one record. A failure is reported on stderr and otherwise
    /// ignored, so a full disk never blocks the daemon.
    pub fn record(&self, socket: &str, action: &str, handle: Option<&str>, outcome: &str) {
        let record = Record {
            ts: humantime::format_rfc3339_millis(SystemTime::now()).to_string(),
            socket,
            action,
            handle,
            outcome,
        };
        if let Err(e) = self.append(&record) {
            eprintln!("kv: cannot write audit log {}: {e}", self.path.display());
        }
    }

    fn append(&self, record: &Record<'_>) -> io::Result<()> {
        if let Some(dir) = self.path.parent() {
            fs::create_dir_all(dir)?;
        }
        if fs::metadata(&self.path).is_ok_and(|m| m.len() >= self.max_bytes) {
            self.rotate()?;
        }
        let line = serde_json::to_string(record)?;
        let mut options = OpenOptions::new();
        options.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        writeln!(options.open(&self.path)?, "{line}")
    }

    fn rotate(&self) -> io::Result<()> {
        for i in (1..KEEP_ROTATED).rev() {
            let from = rotated(&self.path, i);
            if from.exists() {
                fs::rename(&from, rotated(&self.path, i + 1))?;
            }
        }
        fs::rename(&self.path, rotated(&self.path, 1))
    }
}

fn rotated(path: &Path, index: usize) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(format!(".{index}"));
    PathBuf::from(name)
}
```

- [ ] **Step 5: Run the tests and confirm they pass**

Run: `DEVELOPER_DIR=/Library/Developer/CommandLineTools cargo test -p kv --lib`
Expected: `test result: ok. 13 passed`.

Run: `DEVELOPER_DIR=/Library/Developer/CommandLineTools cargo fmt --all --check && DEVELOPER_DIR=/Library/Developer/CommandLineTools cargo clippy --workspace --all-targets -- -D warnings`
Expected: no output, exit 0.

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml Cargo.lock crates/kv
git commit -m "Add kv crate with paths, framing, passphrase backoff and audit log"
```

---

### Task 4: Local sockets

**Files:**
- Create: `crates/kv/src/ipc.rs`, `crates/kv/src/ipc/unix.rs`, `crates/kv/src/ipc/windows.rs`, `crates/kv/tests/ipc.rs`
- Modify: `crates/kv/src/lib.rs` (add `pub mod ipc;` after `pub mod frame;`)

**Interfaces:**
- Consumes: `Endpoint`, `Paths`, `read_frame`/`write_frame`.
- Produces (`kv::ipc`, same names on both platforms): `Listener` with `async fn accept(&mut self) -> io::Result<ServerStream>`; `bind(&Endpoint) -> io::Result<Listener>` (call inside a tokio runtime, after taking the daemon lock file); `async fn connect(&Endpoint) -> io::Result<ClientStream>`; `cleanup(&Endpoint)`; type aliases `ServerStream`, `ClientStream` (both `AsyncRead + AsyncWrite + Unpin`).

- [ ] **Step 1: Write the failing tests**

`crates/kv/tests/ipc.rs`:
```rust
use kv::frame::{read_frame, write_frame};
use kv::ipc;
use kv::paths::Paths;
use kv_core::proto::AgentRequest;

#[tokio::test]
async fn client_and_daemon_exchange_frames() {
    let home = tempfile::TempDir::new().unwrap();
    let paths = Paths::under(home.path());
    paths.ensure_runtime_dir().unwrap();
    let endpoint = paths.agent_endpoint();
    let mut listener = ipc::bind(&endpoint).unwrap();

    let server = tokio::spawn(async move {
        let mut stream = listener.accept().await.unwrap();
        let request: AgentRequest = read_frame(&mut stream).await.unwrap().unwrap();
        write_frame(&mut stream, &request).await.unwrap();
    });
    let mut client = ipc::connect(&endpoint).await.unwrap();
    write_frame(&mut client, &AgentRequest::ListHandles)
        .await
        .unwrap();
    let echoed: AgentRequest = read_frame(&mut client).await.unwrap().unwrap();
    server.await.unwrap();
    assert_eq!(echoed, AgentRequest::ListHandles);
    ipc::cleanup(&endpoint);
}

#[tokio::test]
async fn connect_fails_when_nothing_listens() {
    let home = tempfile::TempDir::new().unwrap();
    let paths = Paths::under(home.path());
    assert!(ipc::connect(&paths.agent_endpoint()).await.is_err());
}

#[cfg(unix)]
#[tokio::test]
async fn bind_replaces_a_stale_socket_file_and_makes_it_private() {
    use std::os::unix::fs::PermissionsExt;
    let home = tempfile::TempDir::new().unwrap();
    let paths = Paths::under(home.path());
    paths.ensure_runtime_dir().unwrap();
    let endpoint = paths.agent_endpoint();
    std::fs::write(&endpoint.path, b"stale").unwrap();
    let _listener = ipc::bind(&endpoint).unwrap();
    let mode = std::fs::metadata(&endpoint.path)
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600);
    let dir_mode = std::fs::metadata(&paths.runtime)
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(dir_mode, 0o700);
}
```

- [ ] **Step 2: Run the tests and confirm they fail**

Run: `DEVELOPER_DIR=/Library/Developer/CommandLineTools cargo test -p kv --test ipc`
Expected: compile error `unresolved import kv::ipc`.

- [ ] **Step 3: Implement**

`crates/kv/src/ipc.rs`:
```rust
//! Local sockets the daemon listens on: Unix domain sockets on Unix, named
//! pipes on Windows. Both accept connections only from the current user.
//!
//! Each platform module provides `Listener`, `ServerStream`, `ClientStream`,
//! `bind`, `connect` and `cleanup`.

#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub use unix::*;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::*;
```

`crates/kv/src/ipc/unix.rs`:
```rust
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;

use tokio::net::{UnixListener, UnixStream};

use crate::paths::Endpoint;

pub type ServerStream = UnixStream;
pub type ClientStream = UnixStream;

pub struct Listener {
    inner: UnixListener,
    uid: u32,
}

/// Binds the socket file, replacing a stale one left by a daemon that
/// crashed. The caller must already hold the daemon lock file, so a live
/// daemon's socket is never replaced.
pub fn bind(endpoint: &Endpoint) -> io::Result<Listener> {
    match fs::remove_file(&endpoint.path) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
        _ => {}
    }
    let inner = UnixListener::bind(&endpoint.path)?;
    fs::set_permissions(&endpoint.path, fs::Permissions::from_mode(0o600))?;
    Ok(Listener {
        inner,
        uid: rustix::process::getuid().as_raw(),
    })
}

impl Listener {
    /// Waits for a connection from a process running as the same user and
    /// drops connections from anyone else.
    pub async fn accept(&mut self) -> io::Result<ServerStream> {
        loop {
            let (stream, _) = self.inner.accept().await?;
            match stream.peer_cred() {
                Ok(cred) if cred.uid() == self.uid => return Ok(stream),
                _ => continue,
            }
        }
    }
}

pub async fn connect(endpoint: &Endpoint) -> io::Result<ClientStream> {
    UnixStream::connect(&endpoint.path).await
}

pub fn cleanup(endpoint: &Endpoint) {
    let _ = fs::remove_file(&endpoint.path);
}
```

`crates/kv/src/ipc/windows.rs`:
```rust
use std::ffi::c_void;
use std::io;
use std::time::Duration;

use tokio::net::windows::named_pipe::{
    ClientOptions, NamedPipeClient, NamedPipeServer, ServerOptions,
};
use windows_sys::Win32::Foundation::{CloseHandle, ERROR_PIPE_BUSY, HANDLE, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER,
    TokenUser,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use crate::paths::Endpoint;

pub type ServerStream = NamedPipeServer;
pub type ClientStream = NamedPipeClient;

pub struct Listener {
    name: String,
    /// Security descriptor granting access to the current user only, as a
    /// NUL-terminated UTF-16 SDDL string.
    sddl: Vec<u16>,
    next: NamedPipeServer,
}

/// Creates the first pipe instance. Fails if another process already owns
/// the name, which the daemon lock file should already have prevented.
pub fn bind(endpoint: &Endpoint) -> io::Result<Listener> {
    let sid = current_user_sid()?;
    let sddl: Vec<u16> = format!("D:P(A;;GA;;;{sid})")
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let next = create(&endpoint.name, &sddl, true)?;
    Ok(Listener {
        name: endpoint.name.clone(),
        sddl,
        next,
    })
}

impl Listener {
    pub async fn accept(&mut self) -> io::Result<ServerStream> {
        self.next.connect().await?;
        let fresh = create(&self.name, &self.sddl, false)?;
        Ok(std::mem::replace(&mut self.next, fresh))
    }
}

pub async fn connect(endpoint: &Endpoint) -> io::Result<ClientStream> {
    for _ in 0..40 {
        match ClientOptions::new().open(&endpoint.name) {
            Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY as i32) => {
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            result => return result,
        }
    }
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        "the kv daemon's pipe stayed busy",
    ))
}

pub fn cleanup(_endpoint: &Endpoint) {}

/// Creates one pipe instance that only the current user can open and that
/// refuses remote clients.
fn create(name: &str, sddl: &[u16], first: bool) -> io::Result<NamedPipeServer> {
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: `sddl` is NUL-terminated UTF-16. On success `descriptor` points
    // to a LocalAlloc'd buffer, freed below.
    let converted = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            std::ptr::null_mut(),
        )
    };
    if converted == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor,
        bInheritHandle: 0,
    };
    let mut options = ServerOptions::new();
    options
        .first_pipe_instance(first)
        .reject_remote_clients(true);
    // SAFETY: `attributes` is a valid SECURITY_ATTRIBUTES that outlives the call.
    let result = unsafe {
        options.create_with_security_attributes_raw(
            name,
            (&mut attributes as *mut SECURITY_ATTRIBUTES).cast::<c_void>(),
        )
    };
    // SAFETY: `descriptor` came from the conversion above and is freed once.
    unsafe { LocalFree(descriptor) };
    result
}

/// The current user's SID as a string such as `S-1-5-21-...`.
fn current_user_sid() -> io::Result<String> {
    // SAFETY: standard token query. Every handle and buffer is checked
    // before use and released before returning.
    unsafe {
        let mut token: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut len = 0u32;
        GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut len);
        let mut buffer = vec![0u8; len as usize];
        let queried =
            GetTokenInformation(token, TokenUser, buffer.as_mut_ptr().cast(), len, &mut len);
        CloseHandle(token);
        if queried == 0 {
            return Err(io::Error::last_os_error());
        }
        let user: TOKEN_USER = std::ptr::read_unaligned(buffer.as_ptr().cast());
        let mut sid: *mut u16 = std::ptr::null_mut();
        if ConvertSidToStringSidW(user.User.Sid, &mut sid) == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut sid_len = 0;
        while *sid.add(sid_len) != 0 {
            sid_len += 1;
        }
        let text = String::from_utf16_lossy(std::slice::from_raw_parts(sid, sid_len));
        LocalFree(sid.cast());
        Ok(text)
    }
}
```

Add `pub mod ipc;` to `crates/kv/src/lib.rs` after `pub mod frame;`.

- [ ] **Step 4: Run the tests and confirm they pass**

Run: `DEVELOPER_DIR=/Library/Developer/CommandLineTools cargo test -p kv --test ipc`
Expected: `test result: ok. 3 passed`.

Run: `DEVELOPER_DIR=/Library/Developer/CommandLineTools cargo fmt --all --check && DEVELOPER_DIR=/Library/Developer/CommandLineTools cargo clippy --workspace --all-targets -- -D warnings`
Expected: no output, exit 0.

Run: `for t in x86_64-pc-windows-msvc x86_64-unknown-linux-gnu; do DEVELOPER_DIR=/Library/Developer/CommandLineTools cargo clippy --workspace --target $t --all-targets -- -D warnings; done`
Expected: both finish with no warnings or errors (type-checks the Windows and Linux code paths; CI runs them for real).

- [ ] **Step 5: Commit**

```bash
git add crates/kv
git commit -m "Add same-user local sockets: Unix sockets and Windows named pipes"
```

---

### Task 5: Daemon request handling

**Files:**
- Create: `crates/kv/src/daemon.rs`, `crates/kv/src/daemon/state.rs`, `crates/kv/tests/state.rs`
- Modify: `crates/kv/src/lib.rs` (add `pub mod daemon;` after `pub mod audit;`)

**Interfaces:**
- Consumes: `Vault` (`create`, `unlock`, `verify_passphrase`, `upsert`, `remove`, `save`, `change_passphrase`), everything in `kv_core::proto`, `Throttle`, `Audit`, `MIN_SECRET_LEN`.
- Produces (`kv::daemon`): `Settings { idle_lock: Duration, locked_exit: Duration }` (default 8h / 10m); `After::{Continue, Stop}`; `Daemon::new(vault_path: PathBuf, audit: Audit, settings: Settings, now: Instant)`, `is_unlocked(&self) -> bool`, `handle_agent(&mut self, AgentRequest, Instant) -> AgentResponse`, `handle_control(&mut self, ControlRequest, Instant) -> (ControlResponse, After)`, `tick(&mut self, Instant) -> After`.

Rules:
- `lock` and `stop` need no passphrase.
- `init` takes the new passphrase.
- Every other control command authenticates first. If the vault is locked, authenticating unlocks it; if it is unlocked, it runs `verify_passphrase`. Wrong passphrases feed the throttle.
- Failed saves restore the previous state in memory.
- Only `list_handles` and successful control commands reset the idle timer; `status` does not.
- `tick` locks after `idle_lock` without use, and returns `Stop` after `locked_exit` with no requests while locked.

- [ ] **Step 1: Write the failing tests**

`crates/kv/tests/state.rs`:
```rust
use std::collections::BTreeMap;
use std::fs;
#[cfg(unix)]
use std::path::PathBuf;
use std::time::{Duration, Instant};

use kv::audit::Audit;
use kv::daemon::{After, Daemon, Settings};
use kv_core::policy::{Mode, Policy};
use kv_core::proto::{
    AgentErrorCode, AgentRequest, AgentResponse, ControlCommand, ControlErrorCode, ControlRequest,
    ControlResponse, PolicyPatch,
};
use kv_core::secret::{AuthPlacement, Secret, SecretText, SecretValue};
use tempfile::TempDir;

const PASS: &str = "correct horse battery";
const TOKEN: &str = "sk-or-v1-0123456789abcdef";

struct Fixture {
    dir: TempDir,
    daemon: Daemon,
    t0: Instant,
}

impl Fixture {
    fn new() -> Self {
        Self::with_settings(Settings::default())
    }

    fn with_settings(settings: Settings) -> Self {
        let dir = TempDir::new().unwrap();
        let t0 = Instant::now();
        let daemon = Daemon::new(
            dir.path().join("vault").join("vault.kv"),
            Audit::new(dir.path().join("audit.jsonl")),
            settings,
            t0,
        );
        Self { dir, daemon, t0 }
    }

    fn initialized() -> Self {
        let mut f = Self::new();
        f.init();
        f
    }

    fn init(&mut self) {
        let response = self.control(
            Some(PASS),
            ControlCommand::Init {
                insecure_fast_kdf: true,
            },
        );
        assert_done(&response);
    }

    fn control(&mut self, passphrase: Option<&str>, command: ControlCommand) -> ControlResponse {
        self.control_at(self.t0, passphrase, command).0
    }

    fn control_at(
        &mut self,
        now: Instant,
        passphrase: Option<&str>,
        command: ControlCommand,
    ) -> (ControlResponse, After) {
        self.daemon.handle_control(
            ControlRequest {
                passphrase: passphrase.map(SecretText::new),
                command,
            },
            now,
        )
    }

    fn agent(&mut self, request: AgentRequest) -> AgentResponse {
        self.daemon.handle_agent(request, self.t0)
    }

    fn handles(&mut self) -> Vec<String> {
        match self.agent(AgentRequest::ListHandles) {
            AgentResponse::Handles { handles } => handles.into_iter().map(|h| h.name).collect(),
            other => panic!("expected handles, got {other:?}"),
        }
    }

    #[cfg(unix)]
    fn vault_dir(&self) -> PathBuf {
        self.dir.path().join("vault")
    }
}

fn http_secret(name: &str) -> Secret {
    Secret {
        name: name.into(),
        description: "OpenRouter".into(),
        value: SecretValue::Http {
            token: SecretText::new(TOKEN),
            placement: AuthPlacement::Header {
                name: "Authorization".into(),
                template: "Bearer {}".into(),
            },
        },
        policy: Policy {
            allowed_hosts: vec!["openrouter.ai".into()],
            ..Policy::default()
        },
        created_at: 0,
        updated_at: 0,
    }
}

fn add(name: &str) -> ControlCommand {
    ControlCommand::Add {
        secret: http_secret(name),
        replace: false,
    }
}

fn assert_done(response: &ControlResponse) {
    assert!(
        matches!(response, ControlResponse::Done { .. }),
        "{response:?}"
    );
}

fn error_code(response: &ControlResponse) -> ControlErrorCode {
    match response {
        ControlResponse::Error { code, .. } => *code,
        other => panic!("expected an error, got {other:?}"),
    }
}

#[test]
fn list_before_init_reports_no_vault() {
    let mut f = Fixture::new();
    let response = f.agent(AgentRequest::ListHandles);
    assert!(matches!(
        response,
        AgentResponse::Error {
            code: AgentErrorCode::NoVault,
            ..
        }
    ));
}

#[test]
fn init_unlocks_and_add_shows_up_in_list() {
    let mut f = Fixture::initialized();
    assert!(f.daemon.is_unlocked());
    assert_done(&f.control(Some(PASS), add("openrouter")));
    assert_eq!(f.handles(), vec!["openrouter"]);
}

#[test]
fn init_refuses_an_existing_vault_and_a_short_passphrase() {
    let mut f = Fixture::initialized();
    let again = f.control(
        Some(PASS),
        ControlCommand::Init {
            insecure_fast_kdf: true,
        },
    );
    assert_eq!(error_code(&again), ControlErrorCode::VaultExists);

    let mut fresh = Fixture::new();
    let short = fresh.control(
        Some("short"),
        ControlCommand::Init {
            insecure_fast_kdf: true,
        },
    );
    assert_eq!(error_code(&short), ControlErrorCode::Invalid);
}

#[test]
fn control_commands_need_the_right_passphrase() {
    let mut f = Fixture::initialized();
    assert_eq!(
        error_code(&f.control(None, add("openrouter"))),
        ControlErrorCode::PassphraseRequired
    );
    assert_eq!(
        error_code(&f.control(Some("wrong horse battery"), add("openrouter"))),
        ControlErrorCode::WrongPassphrase
    );
    assert!(f.handles().is_empty());
}

#[test]
fn lock_needs_no_passphrase_and_unlock_needs_one() {
    let mut f = Fixture::initialized();
    assert_done(&f.control(None, ControlCommand::Lock));
    assert!(matches!(
        f.agent(AgentRequest::ListHandles),
        AgentResponse::Error {
            code: AgentErrorCode::VaultLocked,
            ..
        }
    ));
    assert_eq!(
        error_code(&f.control(None, ControlCommand::Unlock)),
        ControlErrorCode::PassphraseRequired
    );
    assert_done(&f.control(Some(PASS), ControlCommand::Unlock));
    assert!(f.daemon.is_unlocked());
}

#[test]
fn a_control_command_with_the_passphrase_unlocks_a_locked_vault() {
    let mut f = Fixture::initialized();
    assert_done(&f.control(None, ControlCommand::Lock));
    assert_done(&f.control(Some(PASS), add("openrouter")));
    assert!(f.daemon.is_unlocked());
}

#[test]
fn wrong_passphrases_back_off_even_for_the_right_one() {
    let mut f = Fixture::initialized();
    assert_done(&f.control(None, ControlCommand::Lock));
    for _ in 0..5 {
        let (response, _) = f.control_at(f.t0, Some("wrong horse battery"), ControlCommand::Unlock);
        assert_eq!(error_code(&response), ControlErrorCode::WrongPassphrase);
    }
    let (blocked, _) = f.control_at(f.t0, Some(PASS), ControlCommand::Unlock);
    assert_eq!(error_code(&blocked), ControlErrorCode::TooManyAttempts);
    assert!(!f.daemon.is_unlocked());

    let later = f.t0 + Duration::from_secs(2);
    let (allowed, _) = f.control_at(later, Some(PASS), ControlCommand::Unlock);
    assert_done(&allowed);
}

#[test]
fn add_needs_replace_to_overwrite() {
    let mut f = Fixture::initialized();
    assert_done(&f.control(Some(PASS), add("openrouter")));
    assert_eq!(
        error_code(&f.control(Some(PASS), add("openrouter"))),
        ControlErrorCode::HandleExists
    );
    let replace = ControlCommand::Add {
        secret: http_secret("openrouter"),
        replace: true,
    };
    assert_done(&f.control(Some(PASS), replace));
}

#[test]
fn add_rejects_unusable_values() {
    let mut f = Fixture::initialized();
    let mut no_placeholder = http_secret("bad-template");
    no_placeholder.value = SecretValue::Http {
        token: SecretText::new(TOKEN),
        placement: AuthPlacement::Header {
            name: "Authorization".into(),
            template: "Bearer".into(),
        },
    };
    let mut no_vars = http_secret("no-vars");
    no_vars.value = SecretValue::Env {
        vars: BTreeMap::new(),
    };
    let mut bad_name = http_secret("Bad Name");
    bad_name.policy = Policy::default();
    for secret in [no_placeholder, no_vars, bad_name] {
        let response = f.control(
            Some(PASS),
            ControlCommand::Add {
                secret,
                replace: false,
            },
        );
        assert_eq!(error_code(&response), ControlErrorCode::Invalid);
    }
    assert!(f.handles().is_empty());
}

#[test]
fn add_warns_about_short_values_and_empty_allow_lists() {
    let mut f = Fixture::initialized();
    let mut secret = http_secret("tiny");
    secret.value = SecretValue::Http {
        token: SecretText::new("abc"),
        placement: AuthPlacement::Query {
            param: "key".into(),
        },
    };
    secret.policy = Policy::default();
    let response = f.control(
        Some(PASS),
        ControlCommand::Add {
            secret,
            replace: false,
        },
    );
    let ControlResponse::Done { warnings } = response else {
        panic!("expected done, got {response:?}");
    };
    assert_eq!(warnings.len(), 2, "{warnings:?}");
    assert!(warnings[0].contains("shorter than 8"));
    assert!(warnings[1].contains("no allowed hosts"));
}

#[test]
fn set_policy_and_remove_change_the_vault() {
    let mut f = Fixture::initialized();
    assert_done(&f.control(Some(PASS), add("openrouter")));
    let patch = PolicyPatch {
        mode: Some(Mode::Deny),
        ..PolicyPatch::default()
    };
    assert_done(&f.control(
        Some(PASS),
        ControlCommand::SetPolicy {
            name: "openrouter".into(),
            patch,
        },
    ));
    match f.agent(AgentRequest::ListHandles) {
        AgentResponse::Handles { handles } => assert_eq!(handles[0].mode, Mode::Deny),
        other => panic!("{other:?}"),
    }
    assert_done(&f.control(
        Some(PASS),
        ControlCommand::Remove {
            name: "openrouter".into(),
        },
    ));
    assert!(f.handles().is_empty());
    assert_eq!(
        error_code(&f.control(
            Some(PASS),
            ControlCommand::Remove {
                name: "openrouter".into()
            }
        )),
        ControlErrorCode::UnknownHandle
    );
}

#[test]
fn change_passphrase_takes_effect() {
    let mut f = Fixture::initialized();
    assert_done(&f.control(
        Some(PASS),
        ControlCommand::ChangePassphrase {
            new_passphrase: SecretText::new("a brand new passphrase"),
        },
    ));
    assert_eq!(
        error_code(&f.control(Some(PASS), ControlCommand::Unlock)),
        ControlErrorCode::WrongPassphrase
    );
    assert_done(&f.control(Some("a brand new passphrase"), ControlCommand::Unlock));
}

#[cfg(unix)]
#[test]
fn a_failed_save_leaves_the_vault_as_it_was() {
    use std::os::unix::fs::PermissionsExt;
    let mut f = Fixture::initialized();
    assert_done(&f.control(Some(PASS), add("keep")));
    let dir = f.vault_dir();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o500)).unwrap();
    let added = f.control(Some(PASS), add("new-one"));
    let removed = f.control(
        Some(PASS),
        ControlCommand::Remove {
            name: "keep".into(),
        },
    );
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(error_code(&added), ControlErrorCode::Internal);
    assert_eq!(error_code(&removed), ControlErrorCode::Internal);
    assert_eq!(f.handles(), vec!["keep"]);
}

#[test]
fn idle_vault_locks_and_status_polls_do_not_keep_it_open() {
    let mut f = Fixture::with_settings(Settings {
        idle_lock: Duration::from_secs(10),
        locked_exit: Duration::from_secs(600),
    });
    f.init();
    let status_at = f.t0 + Duration::from_secs(9);
    match f.daemon.handle_agent(AgentRequest::Status, status_at) {
        AgentResponse::Status { status } => {
            assert!(!status.locked);
            assert_eq!(status.locks_in_secs, Some(1));
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(
        f.daemon.tick(f.t0 + Duration::from_secs(11)),
        After::Continue
    );
    assert!(!f.daemon.is_unlocked());
}

#[test]
fn locked_daemon_exits_after_a_quiet_period() {
    let mut f = Fixture::with_settings(Settings {
        idle_lock: Duration::from_secs(10),
        locked_exit: Duration::from_secs(60),
    });
    assert_eq!(
        f.daemon.tick(f.t0 + Duration::from_secs(59)),
        After::Continue
    );
    f.daemon
        .handle_agent(AgentRequest::Status, f.t0 + Duration::from_secs(59));
    assert_eq!(
        f.daemon.tick(f.t0 + Duration::from_secs(100)),
        After::Continue
    );
    assert_eq!(f.daemon.tick(f.t0 + Duration::from_secs(120)), After::Stop);
}

#[test]
fn stop_locks_and_asks_the_server_to_exit() {
    let mut f = Fixture::initialized();
    let (response, after) = f.control_at(f.t0, None, ControlCommand::Stop);
    assert_done(&response);
    assert_eq!(after, After::Stop);
    assert!(!f.daemon.is_unlocked());
}

#[test]
fn audit_log_records_actions_without_secret_values() {
    let mut f = Fixture::initialized();
    assert_done(&f.control(Some(PASS), add("openrouter")));
    f.handles();
    let log = fs::read_to_string(f.dir.path().join("audit.jsonl")).unwrap();
    assert!(log.contains(r#""action":"add""#), "{log}");
    assert!(log.contains(r#""handle":"openrouter""#), "{log}");
    assert!(log.contains(r#""action":"list_handles""#), "{log}");
    assert!(!log.contains(TOKEN), "{log}");
    assert!(!log.contains(PASS), "{log}");
}
```

- [ ] **Step 2: Run the tests and confirm they fail**

Run: `DEVELOPER_DIR=/Library/Developer/CommandLineTools cargo test -p kv --test state`
Expected: compile error `unresolved import kv::daemon`.

- [ ] **Step 3: Implement**

`crates/kv/src/daemon.rs` (Task 6 adds the server and hardening modules):
```rust
//! The daemon: request handling (`state`), the socket server (`server`) and
//! process hardening (`harden`).

mod state;

pub use state::{After, Daemon, Settings};
```

`crates/kv/src/daemon/state.rs`:
```rust
//! Daemon state and request handling, kept free of sockets and clocks so it
//! can be tested directly.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use kv_core::VaultError;
use kv_core::crypto::KdfParams;
use kv_core::proto::{
    AgentErrorCode, AgentRequest, AgentResponse, ControlCommand, ControlErrorCode, ControlRequest,
    ControlResponse, PolicyPatch, Status,
};
use kv_core::scrub::MIN_SECRET_LEN;
use kv_core::secret::{AuthPlacement, Secret, SecretText, SecretValue};
use kv_core::vault::Vault;

use crate::audit::Audit;
use crate::throttle::Throttle;

/// Argon2 settings for `kv init --insecure-fast-kdf`. Tests only.
const TEST_KDF: KdfParams = KdfParams {
    m_kib: 8,
    t: 1,
    p: 1,
};

#[derive(Clone, Copy, Debug)]
pub struct Settings {
    /// Lock the vault after it has not been used for this long.
    pub idle_lock: Duration,
    /// Exit after receiving no requests for this long while locked.
    pub locked_exit: Duration,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            idle_lock: Duration::from_secs(8 * 60 * 60),
            locked_exit: Duration::from_secs(10 * 60),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum After {
    Continue,
    Stop,
}

pub struct Daemon {
    vault_path: PathBuf,
    vault: Option<Vault>,
    throttle: Throttle,
    audit: Audit,
    settings: Settings,
    /// Last use of the unlocked vault. Drives the idle lock.
    last_used: Instant,
    /// Last request of any kind. Drives the exit while locked.
    last_request: Instant,
}

struct Failure {
    code: ControlErrorCode,
    message: String,
}

fn fail(code: ControlErrorCode, message: impl Into<String>) -> Failure {
    Failure {
        code,
        message: message.into(),
    }
}

fn internal(error: impl std::fmt::Display) -> Failure {
    fail(ControlErrorCode::Internal, error.to_string())
}

impl Daemon {
    pub fn new(vault_path: PathBuf, audit: Audit, settings: Settings, now: Instant) -> Self {
        Self {
            vault_path,
            vault: None,
            throttle: Throttle::default(),
            audit,
            settings,
            last_used: now,
            last_request: now,
        }
    }

    pub fn is_unlocked(&self) -> bool {
        self.vault.is_some()
    }

    pub fn handle_agent(&mut self, request: AgentRequest, now: Instant) -> AgentResponse {
        self.last_request = now;
        match request {
            AgentRequest::Status => AgentResponse::Status {
                status: self.status(now),
            },
            AgentRequest::ListHandles => {
                let response = match &self.vault {
                    Some(vault) => {
                        self.last_used = now;
                        AgentResponse::Handles {
                            handles: vault.secrets().iter().map(Secret::info).collect(),
                        }
                    }
                    None => self.locked_error(),
                };
                self.audit
                    .record("agent", "list_handles", None, agent_outcome(&response));
                response
            }
        }
    }

    pub fn handle_control(
        &mut self,
        request: ControlRequest,
        now: Instant,
    ) -> (ControlResponse, After) {
        self.last_request = now;
        let ControlRequest {
            passphrase,
            command,
        } = request;
        let (action, handle) = describe(&command);
        let mut after = After::Continue;
        let result = match command {
            ControlCommand::Lock => {
                self.vault = None;
                Ok(Vec::new())
            }
            ControlCommand::Stop => {
                self.vault = None;
                after = After::Stop;
                Ok(Vec::new())
            }
            ControlCommand::Init { insecure_fast_kdf } => {
                self.init(passphrase.as_ref(), insecure_fast_kdf, now)
            }
            command => self
                .authenticate(passphrase.as_ref(), now)
                .and_then(|vault| run_authenticated(vault, command)),
        };
        let response = match result {
            Ok(warnings) => ControlResponse::Done { warnings },
            Err(failure) => ControlResponse::Error {
                code: failure.code,
                message: failure.message,
            },
        };
        let outcome = match &response {
            ControlResponse::Done { .. } => "done",
            ControlResponse::Error { .. } => "error",
        };
        self.audit
            .record("control", action, handle.as_deref(), outcome);
        (response, after)
    }

    /// Runs the idle lock and decides whether the daemon should exit.
    pub fn tick(&mut self, now: Instant) -> After {
        if self.vault.is_some() && now.duration_since(self.last_used) >= self.settings.idle_lock {
            self.vault = None;
            self.audit.record("daemon", "idle_lock", None, "locked");
        }
        if self.vault.is_none()
            && now.duration_since(self.last_request) >= self.settings.locked_exit
        {
            return After::Stop;
        }
        After::Continue
    }

    fn status(&self, now: Instant) -> Status {
        Status {
            vault_exists: self.vault.is_some() || self.vault_path.exists(),
            locked: self.vault.is_none(),
            handle_count: self.vault.as_ref().map(|v| v.secrets().len()),
            locks_in_secs: self.vault.as_ref().map(|_| {
                self.settings
                    .idle_lock
                    .saturating_sub(now.duration_since(self.last_used))
                    .as_secs()
            }),
        }
    }

    fn locked_error(&self) -> AgentResponse {
        if self.vault_path.exists() {
            AgentResponse::Error {
                code: AgentErrorCode::VaultLocked,
                message: "the vault is locked; ask the user to run `kv unlock`".into(),
            }
        } else {
            AgentResponse::Error {
                code: AgentErrorCode::NoVault,
                message: "there is no vault yet; ask the user to run `kv init`".into(),
            }
        }
    }

    fn init(
        &mut self,
        passphrase: Option<&SecretText>,
        insecure_fast_kdf: bool,
        now: Instant,
    ) -> Result<Vec<String>, Failure> {
        let passphrase = passphrase.ok_or_else(|| {
            fail(
                ControlErrorCode::PassphraseRequired,
                "init needs the new passphrase",
            )
        })?;
        let kdf = if insecure_fast_kdf {
            TEST_KDF
        } else {
            KdfParams::RECOMMENDED
        };
        match Vault::create(&self.vault_path, passphrase.expose(), kdf) {
            Ok(vault) => {
                self.vault = Some(vault);
                self.last_used = now;
                Ok(Vec::new())
            }
            Err(VaultError::AlreadyExists(_)) => Err(fail(
                ControlErrorCode::VaultExists,
                "a vault already exists",
            )),
            Err(VaultError::WeakPassphrase) => Err(fail(
                ControlErrorCode::Invalid,
                "the passphrase must be at least 8 characters",
            )),
            Err(e) => Err(internal(e)),
        }
    }

    /// Checks the passphrase, unlocking the vault if it is locked, and
    /// returns the unlocked vault. Wrong passphrases count toward the backoff.
    fn authenticate(
        &mut self,
        passphrase: Option<&SecretText>,
        now: Instant,
    ) -> Result<&mut Vault, Failure> {
        let passphrase = passphrase.ok_or_else(|| {
            fail(
                ControlErrorCode::PassphraseRequired,
                "this command needs the vault passphrase",
            )
        })?;
        if let Err(wait) = self.throttle.check(now) {
            return Err(fail(
                ControlErrorCode::TooManyAttempts,
                format!(
                    "too many wrong passphrases; try again in {}s",
                    wait.as_secs().max(1)
                ),
            ));
        }
        let result = if let Some(vault) = &self.vault {
            vault.verify_passphrase(passphrase.expose())
        } else {
            Vault::unlock(&self.vault_path, passphrase.expose()).map(|vault| {
                self.vault = Some(vault);
            })
        };
        match result {
            Ok(()) => {
                self.throttle.record_success();
                self.last_used = now;
                Ok(self
                    .vault
                    .as_mut()
                    .expect("authenticated vault is unlocked"))
            }
            Err(VaultError::WrongPassphrase) => {
                self.throttle.record_failure(now);
                Err(fail(ControlErrorCode::WrongPassphrase, "wrong passphrase"))
            }
            Err(VaultError::NotFound(_)) => Err(fail(
                ControlErrorCode::NoVault,
                "there is no vault yet; run `kv init`",
            )),
            Err(e) => Err(internal(e)),
        }
    }
}

fn run_authenticated(vault: &mut Vault, command: ControlCommand) -> Result<Vec<String>, Failure> {
    match command {
        ControlCommand::Add { secret, replace } => add(vault, secret, replace),
        ControlCommand::Remove { name } => remove(vault, &name),
        ControlCommand::SetPolicy { name, patch } => set_policy(vault, &name, &patch),
        ControlCommand::ChangePassphrase { new_passphrase } => {
            match vault.change_passphrase(new_passphrase.expose(), KdfParams::RECOMMENDED) {
                Ok(()) => Ok(Vec::new()),
                Err(VaultError::WeakPassphrase) => Err(fail(
                    ControlErrorCode::Invalid,
                    "the passphrase must be at least 8 characters",
                )),
                Err(e) => Err(internal(e)),
            }
        }
        ControlCommand::Unlock
        | ControlCommand::Init { .. }
        | ControlCommand::Lock
        | ControlCommand::Stop => Ok(Vec::new()),
    }
}

fn add(vault: &mut Vault, secret: Secret, replace: bool) -> Result<Vec<String>, Failure> {
    validate_value(&secret.value)?;
    let previous = vault.get(&secret.name).cloned();
    if previous.is_some() && !replace {
        return Err(fail(
            ControlErrorCode::HandleExists,
            format!(
                "{} already exists; use --replace to overwrite it",
                secret.name
            ),
        ));
    }
    let warnings = warnings_for(&secret);
    let name = secret.name.clone();
    vault
        .upsert(secret)
        .map_err(|e| fail(ControlErrorCode::Invalid, e.to_string()))?;
    save_or_restore(vault, &name, previous)?;
    Ok(warnings)
}

fn remove(vault: &mut Vault, name: &str) -> Result<Vec<String>, Failure> {
    let previous = vault.get(name).cloned().ok_or_else(|| unknown(name))?;
    vault.remove(name);
    save_or_restore(vault, name, Some(previous))?;
    Ok(Vec::new())
}

fn set_policy(vault: &mut Vault, name: &str, patch: &PolicyPatch) -> Result<Vec<String>, Failure> {
    let previous = vault.get(name).cloned().ok_or_else(|| unknown(name))?;
    let mut updated = previous.clone();
    patch.apply(&mut updated.policy);
    let warnings = warnings_for(&updated);
    vault
        .upsert(updated)
        .map_err(|e| fail(ControlErrorCode::Invalid, e.to_string()))?;
    save_or_restore(vault, name, Some(previous))?;
    Ok(warnings)
}

/// Saves, or puts `name` back the way it was if the save fails, so memory
/// never holds changes that are not on disk.
fn save_or_restore(vault: &mut Vault, name: &str, previous: Option<Secret>) -> Result<(), Failure> {
    let Err(error) = vault.save() else {
        return Ok(());
    };
    match previous {
        Some(secret) => {
            let _ = vault.upsert(secret);
        }
        None => {
            vault.remove(name);
        }
    }
    Err(internal(format!("could not save the vault: {error}")))
}

fn unknown(name: &str) -> Failure {
    fail(
        ControlErrorCode::UnknownHandle,
        format!("there is no handle named {name}"),
    )
}

fn validate_value(value: &SecretValue) -> Result<(), Failure> {
    let invalid = |message: &str| Err(fail(ControlErrorCode::Invalid, message));
    match value {
        SecretValue::Http { token, placement } => {
            if token.expose().is_empty() {
                return invalid("the token is empty");
            }
            match placement {
                AuthPlacement::Header { name, template } => {
                    if name.is_empty() {
                        return invalid("the header name is empty");
                    }
                    if !template.contains("{}") {
                        return invalid("the header template must contain {} where the token goes");
                    }
                }
                AuthPlacement::Query { param } => {
                    if param.is_empty() {
                        return invalid("the query parameter name is empty");
                    }
                }
            }
        }
        SecretValue::Postgres { url } | SecretValue::Redis { url } => {
            if url.expose().is_empty() {
                return invalid("the connection URL is empty");
            }
        }
        SecretValue::Env { vars } => {
            if vars.is_empty() {
                return invalid("an env secret needs at least one variable");
            }
            if vars.keys().any(|k| k.is_empty() || k.contains(['=', '\0'])) {
                return invalid("variable names must be non-empty and contain no '=' or NUL");
            }
        }
    }
    Ok(())
}

fn warnings_for(secret: &Secret) -> Vec<String> {
    let name = &secret.name;
    let mut warnings = Vec::new();
    let short = |value: &SecretText| value.expose().chars().count() < MIN_SECRET_LEN;
    let mut short_values: Vec<String> = Vec::new();
    match &secret.value {
        SecretValue::Http { token, .. } if short(token) => short_values.push(name.clone()),
        SecretValue::Postgres { url } | SecretValue::Redis { url } if short(url) => {
            short_values.push(name.clone())
        }
        SecretValue::Env { vars } => short_values.extend(
            vars.iter()
                .filter(|(_, v)| short(v))
                .map(|(k, _)| k.clone()),
        ),
        _ => {}
    }
    for value_name in short_values {
        warnings.push(format!(
            "the value of {value_name} is shorter than {MIN_SECRET_LEN} characters, so kv cannot scrub it from output"
        ));
    }
    match &secret.value {
        SecretValue::Http { .. } if secret.policy.allowed_hosts.is_empty() => {
            warnings.push(format!(
                "{name} has no allowed hosts, so every request with it is denied; add one with `kv policy {name} --host <host>`"
            ));
        }
        SecretValue::Env { .. } if secret.policy.allowed_cmds.is_empty() => {
            warnings.push(format!(
                "{name} has no allowed commands, so every exec with it is denied; add one with `kv policy {name} --cmd <program>`"
            ));
        }
        _ => {}
    }
    warnings
}

fn describe(command: &ControlCommand) -> (&'static str, Option<String>) {
    match command {
        ControlCommand::Init { .. } => ("init", None),
        ControlCommand::Unlock => ("unlock", None),
        ControlCommand::Lock => ("lock", None),
        ControlCommand::Stop => ("stop", None),
        ControlCommand::Add { secret, .. } => ("add", Some(secret.name.clone())),
        ControlCommand::Remove { name } => ("remove", Some(name.clone())),
        ControlCommand::SetPolicy { name, .. } => ("set_policy", Some(name.clone())),
        ControlCommand::ChangePassphrase { .. } => ("change_passphrase", None),
    }
}

fn agent_outcome(response: &AgentResponse) -> &'static str {
    match response {
        AgentResponse::Error { .. } => "error",
        _ => "done",
    }
}
```

Add `pub mod daemon;` to `crates/kv/src/lib.rs` after `pub mod audit;`.

- [ ] **Step 4: Run the tests and confirm they pass**

Run: `DEVELOPER_DIR=/Library/Developer/CommandLineTools cargo test -p kv --test state`
Expected: `test result: ok. 17 passed`. This takes a few seconds, because `change_passphrase` uses the recommended Argon2 settings.

Run: `DEVELOPER_DIR=/Library/Developer/CommandLineTools cargo fmt --all --check && DEVELOPER_DIR=/Library/Developer/CommandLineTools cargo clippy --workspace --all-targets -- -D warnings`
Expected: no output, exit 0.

Run: `for t in x86_64-pc-windows-msvc x86_64-unknown-linux-gnu; do DEVELOPER_DIR=/Library/Developer/CommandLineTools cargo clippy --workspace --target $t --all-targets -- -D warnings; done`
Expected: both finish with no warnings or errors (type-checks the Windows and Linux code paths; CI runs them for real).

- [ ] **Step 5: Commit**

```bash
git add crates/kv
git commit -m "Add daemon request handling with per-command passphrase checks and idle lock"
```

---

### Task 6: Socket server, hardening, client and CLI

**Files:**
- Modify: `crates/kv/src/daemon.rs`, `crates/kv/src/lib.rs`, `README.md`
- Create: `crates/kv/src/daemon/server.rs`, `crates/kv/src/daemon/harden.rs`, `crates/kv/src/client.rs`, `crates/kv/src/cli.rs`, `crates/kv/src/main.rs`, `crates/kv/tests/cli.rs`

**Interfaces:**
- Consumes: everything from Tasks 2-5.
- Produces:
  - `kv::daemon::run(paths: Paths, settings: Settings) -> io::Result<()>` (returns `Ok` at once if another daemon holds the lock file).
  - `kv::client::{connect(&Endpoint, autostart: bool), agent(&Paths, &AgentRequest), control(&Paths, &ControlRequest, autostart: bool)}`.
  - `kv::cli::main() -> ExitCode` and the `kv` binary.

- [ ] **Step 1: Write the failing end-to-end tests**

`crates/kv/tests/cli.rs`:
```rust
//! End-to-end tests that drive the real `kv` binary against a daemon in a
//! temporary KV_HOME.

use std::io::Write;
#[cfg(unix)]
use std::path::PathBuf;
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use kv::frame::{read_frame, write_frame};
use kv::ipc;
use kv::paths::Paths;
use kv_core::proto::{AgentErrorCode, AgentResponse, ControlCommand, ControlRequest};
use kv_core::secret::SecretText;
use tempfile::TempDir;

const PASS: &str = "correct horse battery";
const TOKEN: &str = "sk-test-0123456789abcdef";

struct Kv {
    home: TempDir,
    daemon: Option<Child>,
}

impl Kv {
    /// A KV_HOME with no daemon running; commands start one on demand.
    fn new() -> Self {
        Self {
            home: TempDir::new().unwrap(),
            daemon: None,
        }
    }

    /// Starts `kv daemon` in the foreground with the given extra arguments
    /// and waits until it accepts connections.
    fn with_daemon(args: &[&str]) -> Self {
        let mut kv = Self::new();
        let child = kv
            .command(&[&["daemon"], args].concat())
            .stdin(Stdio::null())
            .spawn()
            .unwrap();
        kv.daemon = Some(child);
        kv.wait_until_listening();
        kv
    }

    fn initialized() -> Self {
        let kv = Self::with_daemon(&[]);
        kv.ok(&["init", "--insecure-fast-kdf"], &format!("{PASS}\n"));
        kv
    }

    fn paths(&self) -> Paths {
        Paths::under(self.home.path())
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_kv"));
        command.args(args).env("KV_HOME", self.home.path());
        command
    }

    fn run(&self, args: &[&str], stdin: &str) -> Output {
        run_kv(self.command(args), stdin)
    }

    fn ok(&self, args: &[&str], stdin: &str) -> String {
        let output = self.run(args, stdin);
        assert!(
            output.status.success(),
            "kv {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap()
    }

    fn fails(&self, args: &[&str], stdin: &str) -> String {
        let output = self.run(args, stdin);
        assert!(
            !output.status.success(),
            "kv {args:?} unexpectedly succeeded"
        );
        String::from_utf8(output.stderr).unwrap()
    }

    fn add_openrouter(&self) {
        self.ok(
            &[
                "add",
                "openrouter",
                "--kind",
                "http",
                "--host",
                "openrouter.ai",
                "--mode",
                "auto",
            ],
            &format!("{PASS}\n{TOKEN}\n"),
        );
    }

    fn wait_until_listening(&self) {
        let endpoint = self.paths().agent_endpoint();
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while runtime.block_on(ipc::connect(&endpoint)).is_err() {
            assert!(Instant::now() < deadline, "daemon did not start listening");
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    fn audit_log(&self) -> String {
        std::fs::read_to_string(self.home.path().join("audit.jsonl")).unwrap_or_default()
    }
}

impl Drop for Kv {
    fn drop(&mut self) {
        let _ = self.run(&["stop"], "");
        if let Some(mut child) = self.daemon.take()
            && wait_with_timeout(&mut child, Duration::from_secs(5)).is_none()
        {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn run_kv(mut command: Command, stdin: &str) -> Output {
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

fn wait_with_timeout(child: &mut Child, timeout: Duration) -> Option<std::process::ExitStatus> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait().unwrap() {
            return Some(status);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    None
}

#[test]
fn init_add_list_and_status() {
    let kv = Kv::initialized();
    kv.add_openrouter();
    let table = kv.ok(&["list"], "");
    assert!(table.contains("openrouter"), "{table}");
    assert!(table.contains("hosts=openrouter.ai"), "{table}");
    let json: serde_json::Value = serde_json::from_str(&kv.ok(&["list", "--json"], "")).unwrap();
    assert_eq!(json[0]["name"], "openrouter");
    assert_eq!(json[0]["mode"], "auto");
    let status = kv.ok(&["status"], "");
    assert!(status.starts_with("unlocked: 1 handle"), "{status}");
    for output in [table, json.to_string(), status] {
        assert!(!output.contains(TOKEN));
    }
}

#[test]
fn control_commands_need_the_right_passphrase() {
    let kv = Kv::initialized();
    let error = kv.fails(
        &[
            "add",
            "openrouter",
            "--kind",
            "http",
            "--host",
            "openrouter.ai",
        ],
        &format!("wrong horse battery\n{TOKEN}\n"),
    );
    assert!(error.contains("wrong passphrase"), "{error}");
    assert!(kv.ok(&["list"], "").contains("no handles yet"));
}

#[test]
fn lock_and_unlock() {
    let kv = Kv::initialized();
    kv.add_openrouter();
    kv.ok(&["lock"], "");
    let error = kv.fails(&["list"], "");
    assert!(error.contains("locked"), "{error}");
    assert!(kv.ok(&["status"], "").starts_with("locked"));
    kv.ok(&["unlock"], &format!("{PASS}\n"));
    assert!(kv.ok(&["list"], "").contains("openrouter"));
}

#[test]
fn wrong_passphrases_back_off() {
    let kv = Kv::initialized();
    kv.ok(&["lock"], "");
    for _ in 0..5 {
        let error = kv.fails(&["unlock"], "wrong horse battery\n");
        assert!(error.contains("wrong passphrase"), "{error}");
    }
    let error = kv.fails(&["unlock"], &format!("{PASS}\n"));
    assert!(error.contains("too many wrong passphrases"), "{error}");
}

#[test]
fn idle_vault_locks_itself() {
    let kv = Kv::with_daemon(&["--idle-lock", "1s"]);
    kv.ok(&["init", "--insecure-fast-kdf"], &format!("{PASS}\n"));
    std::thread::sleep(Duration::from_millis(2500));
    let status = kv.ok(&["status"], "");
    assert!(status.starts_with("locked"), "{status}");
}

#[test]
fn rm_policy_and_passwd() {
    let kv = Kv::initialized();
    kv.add_openrouter();
    kv.ok(
        &["policy", "openrouter", "--mode", "deny", "--method", "GET"],
        &format!("{PASS}\n"),
    );
    let json: serde_json::Value = serde_json::from_str(&kv.ok(&["list", "--json"], "")).unwrap();
    assert_eq!(json[0]["mode"], "deny");
    assert_eq!(json[0]["allowed_methods"][0], "GET");
    assert_eq!(json[0]["allowed_hosts"][0], "openrouter.ai");

    kv.ok(&["rm", "openrouter"], &format!("{PASS}\n"));
    assert!(kv.ok(&["list"], "").contains("no handles yet"));

    kv.ok(&["passwd"], &format!("{PASS}\na brand new passphrase\n"));
    kv.ok(&["lock"], "");
    assert!(
        kv.fails(&["unlock"], &format!("{PASS}\n"))
            .contains("wrong passphrase")
    );
    kv.ok(&["unlock"], "a brand new passphrase\n");
}

#[test]
fn add_prints_warnings_for_unusable_policies() {
    let kv = Kv::initialized();
    let output = kv.run(
        &["add", "loose", "--kind", "http"],
        &format!("{PASS}\n{TOKEN}\n"),
    );
    assert!(output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("warning: loose has no allowed hosts"),
        "{stderr}"
    );
}

#[test]
fn audit_log_has_actions_but_no_values() {
    let kv = Kv::initialized();
    kv.add_openrouter();
    kv.ok(&["list"], "");
    let log = kv.audit_log();
    assert!(log.contains(r#""action":"add""#), "{log}");
    assert!(log.contains(r#""action":"list_handles""#), "{log}");
    assert!(!log.contains(TOKEN), "{log}");
    assert!(!log.contains(PASS), "{log}");
}

#[test]
fn agent_socket_rejects_control_requests() {
    let kv = Kv::initialized();
    kv.ok(&["lock"], "");
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let response: AgentResponse = runtime.block_on(async {
        let mut stream = ipc::connect(&kv.paths().agent_endpoint()).await.unwrap();
        let request = ControlRequest {
            passphrase: Some(SecretText::new(PASS)),
            command: ControlCommand::Unlock,
        };
        write_frame(&mut stream, &request).await.unwrap();
        read_frame(&mut stream).await.unwrap().unwrap()
    });
    assert!(
        matches!(
            response,
            AgentResponse::Error {
                code: AgentErrorCode::BadRequest,
                ..
            }
        ),
        "{response:?}"
    );
    assert!(kv.ok(&["status"], "").starts_with("locked"));
}

#[test]
fn garbage_on_a_socket_does_not_take_the_daemon_down() {
    let kv = Kv::initialized();
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        use tokio::io::AsyncWriteExt;
        for endpoint in [kv.paths().agent_endpoint(), kv.paths().control_endpoint()] {
            let mut stream = ipc::connect(&endpoint).await.unwrap();
            stream.write_all(&[0xff, 0xff, 0xff, 0xff]).await.unwrap();
            stream.write_all(b"not json at all").await.unwrap();
            let mut half = ipc::connect(&endpoint).await.unwrap();
            half.write_all(&[0, 0, 0, 50, b'{']).await.unwrap();
            drop(half);
        }
    });
    assert!(kv.ok(&["status"], "").starts_with("unlocked"));
}

#[test]
fn commands_start_the_daemon_and_stop_ends_it() {
    let kv = Kv::new();
    let status = kv.ok(&["status"], "");
    assert!(status.contains("no vault yet"), "{status}");
    kv.ok(&["init", "--insecure-fast-kdf"], &format!("{PASS}\n"));
    kv.ok(&["stop"], "");
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while runtime
        .block_on(ipc::connect(&kv.paths().agent_endpoint()))
        .is_ok()
    {
        assert!(
            Instant::now() < deadline,
            "daemon still listening after stop"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn lock_and_stop_succeed_when_no_daemon_runs() {
    let kv = Kv::new();
    kv.ok(&["lock"], "");
    kv.ok(&["stop"], "");
}

#[test]
fn concurrent_commands_start_only_one_daemon() {
    let kv = Kv::new();
    let outputs: Vec<Output> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..4)
            .map(|_| scope.spawn(|| kv.run(&["status"], "")))
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });
    for output in outputs {
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    kv.ok(&["init", "--insecure-fast-kdf"], &format!("{PASS}\n"));
    assert!(kv.ok(&["status"], "").starts_with("unlocked"));
}

#[test]
fn a_second_daemon_exits_while_one_is_running() {
    let kv = Kv::with_daemon(&[]);
    let mut second = kv
        .command(&["daemon"])
        .stdin(Stdio::null())
        .spawn()
        .unwrap();
    let status = wait_with_timeout(&mut second, Duration::from_secs(5));
    assert!(status.is_some_and(|s| s.success()), "{status:?}");
    kv.ok(&["status"], "");
}

#[cfg(unix)]
#[test]
fn stale_socket_files_from_a_crashed_daemon_are_replaced() {
    let kv = Kv::new();
    let paths = kv.paths();
    std::fs::create_dir_all(&paths.runtime).unwrap();
    for endpoint in [paths.agent_endpoint(), paths.control_endpoint()] {
        std::fs::write(&endpoint.path, b"left over").unwrap();
    }
    std::fs::write(paths.lock_file(), b"").unwrap();
    let status = kv.ok(&["status"], "");
    assert!(status.contains("no vault yet"), "{status}");
}

#[test]
fn passphrases_keep_every_character_but_the_line_ending() {
    let kv = Kv::with_daemon(&[]);
    let passphrase = "  pässwörd 🔑 with spaces  ";
    kv.ok(
        &["init", "--insecure-fast-kdf"],
        &format!("{passphrase}\r\n"),
    );
    kv.ok(&["lock"], "");
    let error = kv.fails(&["unlock"], &format!("{}\n", passphrase.trim()));
    assert!(error.contains("wrong passphrase"), "{error}");
    kv.ok(&["unlock"], &format!("{passphrase}\n"));
}

#[test]
fn missing_stdin_lines_fail_with_a_clear_message() {
    let kv = Kv::initialized();
    let error = kv.fails(
        &["add", "openrouter", "--kind", "http"],
        &format!("{PASS}\n"),
    );
    assert!(
        error.contains("stdin ended before: Token for openrouter"),
        "{error}"
    );
}

#[cfg(unix)]
#[test]
fn an_overlong_socket_path_fails_cleanly() {
    let base = TempDir::new().unwrap();
    let home: PathBuf = base.path().join("a".repeat(120));
    std::fs::create_dir_all(&home).unwrap();
    let output = run_kv(
        {
            let mut command = Command::new(env!("CARGO_BIN_EXE_kv"));
            command.args(["daemon"]).env("KV_HOME", &home);
            command
        },
        "",
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success());
    assert!(!stderr.contains("panicked"), "{stderr}");
    assert!(stderr.starts_with("kv: "), "{stderr}");
}
```

- [ ] **Step 2: Run the tests and confirm they fail**

Run: `DEVELOPER_DIR=/Library/Developer/CommandLineTools cargo test -p kv --test cli`
Expected: compile error `environment variable CARGO_BIN_EXE_kv not defined` (there is no binary yet).

- [ ] **Step 3: Implement the server and hardening**

`crates/kv/src/daemon.rs` becomes:
```rust
//! The daemon: request handling (`state`), the socket server (`server`) and
//! process hardening (`harden`).

mod harden;
mod server;
mod state;

pub use server::run;
pub use state::{After, Daemon, Settings};
```

`crates/kv/src/daemon/harden.rs`:
```rust
//! Keeps secrets out of core dumps and, on Linux, stops other processes
//! running as the same user from attaching a debugger or reading the
//! daemon's memory through /proc.

pub fn apply() {
    #[cfg(unix)]
    {
        use rustix::process::{Resource, Rlimit, setrlimit};
        let _ = setrlimit(
            Resource::Core,
            Rlimit {
                current: Some(0),
                maximum: Some(0),
            },
        );
    }
    #[cfg(target_os = "linux")]
    {
        use rustix::process::{DumpableBehavior, set_dumpable_behavior};
        let _ = set_dumpable_behavior(DumpableBehavior::NotDumpable);
    }
}
```

`crates/kv/src/daemon/server.rs`:
```rust
//! Accepts connections on the agent and control sockets and feeds requests
//! to `Daemon`.

use std::fs::{File, TryLockError};
use std::io;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use kv_core::proto::{
    AgentErrorCode, AgentRequest, AgentResponse, ControlErrorCode, ControlRequest, ControlResponse,
};
use tokio::sync::watch;

use super::harden;
use super::state::{After, Daemon, Settings};
use crate::audit::Audit;
use crate::frame::{read_frame, write_frame};
use crate::ipc::{self, ServerStream};
use crate::paths::Paths;

type Shared = Arc<Mutex<Daemon>>;

/// Runs until `kv stop`, or until the daemon has been locked and idle for
/// `settings.locked_exit`. Returns immediately if another daemon already
/// holds the lock file.
pub async fn run(paths: Paths, settings: Settings) -> io::Result<()> {
    harden::apply();
    paths.ensure_runtime_dir()?;
    let lock_file = File::options()
        .create(true)
        .truncate(false)
        .write(true)
        .open(paths.lock_file())?;
    match lock_file.try_lock() {
        Ok(()) => {}
        Err(TryLockError::WouldBlock) => return Ok(()),
        Err(TryLockError::Error(e)) => return Err(e),
    }

    let agent_endpoint = paths.agent_endpoint();
    let control_endpoint = paths.control_endpoint();
    let mut agent = ipc::bind(&agent_endpoint)?;
    let mut control = ipc::bind(&control_endpoint)?;

    let daemon: Shared = Arc::new(Mutex::new(Daemon::new(
        paths.vault.clone(),
        Audit::new(paths.audit.clone()),
        settings,
        Instant::now(),
    )));
    let (stop_tx, mut stop_rx) = watch::channel(false);
    let check_every = (settings.idle_lock.min(settings.locked_exit) / 4)
        .clamp(Duration::from_millis(100), Duration::from_secs(30));
    let mut ticker = tokio::time::interval(check_every);

    loop {
        tokio::select! {
            accepted = agent.accept() => match accepted {
                Ok(stream) => {
                    tokio::spawn(serve_agent(stream, daemon.clone()));
                }
                Err(e) => accept_failed("agent", e).await,
            },
            accepted = control.accept() => match accepted {
                Ok(stream) => {
                    tokio::spawn(serve_control(stream, daemon.clone(), stop_tx.clone()));
                }
                Err(e) => accept_failed("control", e).await,
            },
            _ = ticker.tick() => {
                if lock(&daemon).tick(Instant::now()) == After::Stop {
                    break;
                }
            }
            _ = stop_rx.changed() => break,
        }
    }

    ipc::cleanup(&agent_endpoint);
    ipc::cleanup(&control_endpoint);
    drop(lock_file);
    Ok(())
}

async fn serve_agent(mut stream: ServerStream, daemon: Shared) {
    loop {
        let request: AgentRequest = match read_frame(&mut stream).await {
            Ok(Some(request)) => request,
            Ok(None) => return,
            Err(e) if e.kind() == io::ErrorKind::InvalidData => {
                let response = AgentResponse::Error {
                    code: AgentErrorCode::BadRequest,
                    message: format!("malformed request: {e}"),
                };
                let _ = write_frame(&mut stream, &response).await;
                return;
            }
            Err(_) => return,
        };
        let daemon = daemon.clone();
        let handled = tokio::task::spawn_blocking(move || {
            lock(&daemon).handle_agent(request, Instant::now())
        })
        .await;
        let Ok(response) = handled else { return };
        if write_frame(&mut stream, &response).await.is_err() {
            return;
        }
    }
}

async fn serve_control(mut stream: ServerStream, daemon: Shared, stop: watch::Sender<bool>) {
    loop {
        let request: ControlRequest = match read_frame(&mut stream).await {
            Ok(Some(request)) => request,
            Ok(None) => return,
            Err(e) if e.kind() == io::ErrorKind::InvalidData => {
                // No detail: the parse error could quote part of the request,
                // which may contain the passphrase.
                let response = ControlResponse::Error {
                    code: ControlErrorCode::BadRequest,
                    message: "malformed request".into(),
                };
                let _ = write_frame(&mut stream, &response).await;
                return;
            }
            Err(_) => return,
        };
        let daemon = daemon.clone();
        // Argon2 takes a noticeable fraction of a second, so it runs off the
        // async worker threads.
        let handled = tokio::task::spawn_blocking(move || {
            lock(&daemon).handle_control(request, Instant::now())
        })
        .await;
        let Ok((response, after)) = handled else {
            return;
        };
        let written = write_frame(&mut stream, &response).await;
        if after == After::Stop {
            let _ = stop.send(true);
            return;
        }
        if written.is_err() {
            return;
        }
    }
}

async fn accept_failed(socket: &str, error: io::Error) {
    eprintln!("kv daemon: accepting on the {socket} socket failed: {error}");
    tokio::time::sleep(Duration::from_millis(100)).await;
}

fn lock(daemon: &Shared) -> MutexGuard<'_, Daemon> {
    daemon.lock().unwrap_or_else(PoisonError::into_inner)
}
```

- [ ] **Step 4: Implement the client**

`crates/kv/src/client.rs`:
```rust
//! Talking to the daemon from the CLI, starting it on demand.

use std::io;
use std::process::{Command, Stdio};
use std::time::Duration;

use kv_core::proto::{AgentRequest, AgentResponse, ControlRequest, ControlResponse};
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::frame::{read_frame, write_frame};
use crate::ipc::{self, ClientStream};
use crate::paths::{Endpoint, Paths};

/// Connects to the endpoint. With `autostart`, a missing daemon is started
/// in the background and waited for, up to 5 seconds.
pub async fn connect(endpoint: &Endpoint, autostart: bool) -> io::Result<ClientStream> {
    match ipc::connect(endpoint).await {
        Ok(stream) => Ok(stream),
        Err(_) if autostart => {
            spawn_daemon()?;
            wait_for(endpoint).await
        }
        Err(e) => Err(e),
    }
}

pub async fn agent(paths: &Paths, request: &AgentRequest) -> io::Result<AgentResponse> {
    let mut stream = connect(&paths.agent_endpoint(), true).await?;
    exchange(&mut stream, request).await
}

/// `autostart` is false for `lock` and `stop`, which have nothing to do when
/// no daemon is running.
pub async fn control(
    paths: &Paths,
    request: &ControlRequest,
    autostart: bool,
) -> io::Result<ControlResponse> {
    let mut stream = connect(&paths.control_endpoint(), autostart).await?;
    exchange(&mut stream, request).await
}

async fn exchange<Req: Serialize, Resp: DeserializeOwned>(
    stream: &mut ClientStream,
    request: &Req,
) -> io::Result<Resp> {
    write_frame(stream, request).await?;
    read_frame(stream).await?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "the kv daemon closed the connection",
        )
    })
}

async fn wait_for(endpoint: &Endpoint) -> io::Result<ClientStream> {
    let mut last_error = None;
    for _ in 0..100 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        match ipc::connect(endpoint).await {
            Ok(stream) => return Ok(stream),
            Err(e) => last_error = Some(e),
        }
    }
    let detail = last_error.map(|e| e.to_string()).unwrap_or_default();
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        format!("the kv daemon did not start ({endpoint}): {detail}"),
    ))
}

/// Starts `kv daemon` detached from this process. If another client starts
/// one at the same moment, the loser exits when it finds the lock file held.
fn spawn_daemon() -> io::Result<()> {
    let mut command = Command::new(std::env::current_exe()?);
    command
        .arg("daemon")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const DETACHED_PROCESS: u32 = 0x0000_0008;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        command.creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP);
    }
    command.spawn().map(drop)
}
```

- [ ] **Step 5: Write the CLI unit tests, then the CLI**

Create `crates/kv/src/cli.rs` with its test module first:
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trimmed_strips_surrounding_whitespace_only() {
        assert_eq!(
            trimmed(SecretText::new("  sk-abc def \n")).expose(),
            "sk-abc def"
        );
        assert_eq!(trimmed(SecretText::new("sk-abc")).expose(), "sk-abc");
    }

    #[test]
    fn policy_flags_build_a_patch_and_empty_string_clears_a_list() {
        let args = PolicyArgs {
            mode: Some(ModeArg::Auto),
            hosts: vec![String::new()],
            allow_plain_http: None,
            methods: vec!["GET".into()],
            read_only: Some(true),
            cmds: Vec::new(),
            grant_ttl: None,
        };
        let patch = args.patch();
        assert_eq!(patch.mode, Some(Mode::Auto));
        assert_eq!(patch.allowed_hosts, Some(Vec::new()));
        assert_eq!(patch.allowed_methods, Some(vec!["GET".to_string()]));
        assert_eq!(patch.allowed_cmds, None);
        assert_eq!(patch.read_only, Some(true));
    }

    #[test]
    fn cli_definition_is_valid() {
        use clap::CommandFactory;
        Cli::command().debug_assert();
    }
}
```

Then insert the implementation above it:
```rust
//! The `kv` command line.

use std::fmt;
use std::io::{self, BufRead, IsTerminal};
use std::process::ExitCode;
use std::time::Duration;

use clap::{Args, Parser, Subcommand, ValueEnum};
use kv_core::policy::{Mode, Policy};
use kv_core::proto::{
    AgentRequest, AgentResponse, ControlCommand, ControlRequest, ControlResponse, PolicyPatch,
    Status,
};
use kv_core::secret::{AuthPlacement, HandleInfo, Secret, SecretText, SecretValue};
use zeroize::Zeroizing;

use crate::client;
use crate::daemon::{self, Settings};
use crate::paths::Paths;

#[derive(Parser)]
#[command(
    name = "kv",
    version,
    about = "Lets AI agents use your secrets without seeing them"
)]
pub struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create a new vault
    Init {
        #[arg(long, hide = true)]
        insecure_fast_kdf: bool,
    },
    /// Unlock the vault so agents can use its handles
    Unlock,
    /// Lock the vault
    Lock,
    /// Lock the vault and stop the daemon
    Stop,
    /// Show whether the vault is locked
    Status,
    /// List handles and their policies (never values)
    List {
        /// Print JSON instead of a table
        #[arg(long)]
        json: bool,
    },
    /// Add a secret
    Add(AddArgs),
    /// Remove a secret
    Rm { name: String },
    /// Change a secret's policy
    Policy {
        name: String,
        #[command(flatten)]
        policy: PolicyArgs,
    },
    /// Change the vault passphrase
    Passwd,
    /// Run the daemon in the foreground (other commands start it on demand)
    Daemon {
        /// Lock the vault after it has gone unused for this long
        #[arg(long, default_value = "8h", value_parser = humantime::parse_duration)]
        idle_lock: Duration,
        /// Exit after this long with no requests while locked
        #[arg(long, default_value = "10m", value_parser = humantime::parse_duration, hide = true)]
        locked_exit: Duration,
    },
}

#[derive(Args)]
struct AddArgs {
    /// Handle name agents use, e.g. openrouter or prod-db
    name: String,
    #[arg(long, value_enum)]
    kind: Kind,
    #[arg(long, default_value = "")]
    description: String,
    /// http: header that carries the token
    #[arg(long, default_value = "Authorization")]
    header: String,
    /// http: header value, with {} where the token goes
    #[arg(long, default_value = "Bearer {}")]
    template: String,
    /// http: send the token as this query parameter instead of a header
    #[arg(long, conflicts_with_all = ["header", "template"])]
    query_param: Option<String>,
    /// env: variable to inject (repeat for several); each value is prompted for
    #[arg(long = "var", value_name = "NAME")]
    vars: Vec<String>,
    /// Overwrite an existing handle with this name
    #[arg(long)]
    replace: bool,
    #[command(flatten)]
    policy: PolicyArgs,
}

#[derive(Clone, Copy, ValueEnum)]
enum Kind {
    Http,
    Postgres,
    Redis,
    Env,
}

#[derive(Args)]
struct PolicyArgs {
    #[arg(long, value_enum)]
    mode: Option<ModeArg>,
    /// http: host or host:port the token may be sent to (repeat; "" clears)
    #[arg(long = "host", value_name = "HOST")]
    hosts: Vec<String>,
    /// http: allow plain http:// URLs
    #[arg(long, value_name = "BOOL")]
    allow_plain_http: Option<bool>,
    /// http: allowed method (repeat; "" clears, meaning any method)
    #[arg(long = "method", value_name = "METHOD")]
    methods: Vec<String>,
    /// postgres/redis: refuse writes
    #[arg(long, value_name = "BOOL")]
    read_only: Option<bool>,
    /// env: program allowed to receive the variables, a bare name or an
    /// absolute path (repeat; "" clears)
    #[arg(long = "cmd", value_name = "PROGRAM")]
    cmds: Vec<String>,
    /// How long "allow for session" approvals last
    #[arg(long, value_parser = humantime::parse_duration)]
    grant_ttl: Option<Duration>,
}

#[derive(Clone, Copy, ValueEnum)]
enum ModeArg {
    Auto,
    Ask,
    Deny,
}

impl From<ModeArg> for Mode {
    fn from(mode: ModeArg) -> Self {
        match mode {
            ModeArg::Auto => Mode::Auto,
            ModeArg::Ask => Mode::Ask,
            ModeArg::Deny => Mode::Deny,
        }
    }
}

impl PolicyArgs {
    fn patch(&self) -> PolicyPatch {
        let list = |values: &[String]| {
            (!values.is_empty()).then(|| {
                values
                    .iter()
                    .filter(|v| !v.is_empty())
                    .cloned()
                    .collect::<Vec<_>>()
            })
        };
        PolicyPatch {
            mode: self.mode.map(Mode::from),
            allowed_hosts: list(&self.hosts),
            allow_plain_http: self.allow_plain_http,
            allowed_methods: list(&self.methods),
            read_only: self.read_only,
            allowed_cmds: list(&self.cmds),
            grant_ttl: self.grant_ttl,
        }
    }
}

struct CliError(String);

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<io::Error> for CliError {
    fn from(error: io::Error) -> Self {
        Self(error.to_string())
    }
}

type Result<T> = std::result::Result<T, CliError>;

pub fn main() -> ExitCode {
    let cli = Cli::parse();
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(e) => {
            eprintln!("kv: cannot start the async runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(run(cli)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("kv: {e}");
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> Result<()> {
    let paths = Paths::from_env()?;
    let mut input = Input::new();
    match cli.command {
        Command::Daemon {
            idle_lock,
            locked_exit,
        } => {
            daemon::run(
                paths,
                Settings {
                    idle_lock,
                    locked_exit,
                },
            )
            .await?;
            Ok(())
        }
        Command::Init { insecure_fast_kdf } => {
            let passphrase = input.new_passphrase("New vault passphrase: ")?;
            control(
                &paths,
                Some(passphrase),
                ControlCommand::Init { insecure_fast_kdf },
            )
            .await?;
            println!("vault created and unlocked");
            Ok(())
        }
        Command::Unlock => {
            let passphrase = input.secret("Vault passphrase: ")?;
            control(&paths, Some(passphrase), ControlCommand::Unlock).await?;
            println!("unlocked");
            Ok(())
        }
        Command::Lock => {
            stop_or_lock(&paths, ControlCommand::Lock).await?;
            println!("locked");
            Ok(())
        }
        Command::Stop => {
            stop_or_lock(&paths, ControlCommand::Stop).await?;
            println!("stopped");
            Ok(())
        }
        Command::Status => {
            match client::agent(&paths, &AgentRequest::Status).await? {
                AgentResponse::Status { status } => println!("{}", describe_status(&status)),
                other => return Err(unexpected(&other)),
            }
            Ok(())
        }
        Command::List { json } => {
            let handles = match client::agent(&paths, &AgentRequest::ListHandles).await? {
                AgentResponse::Handles { handles } => handles,
                AgentResponse::Error { message, .. } => return Err(CliError(message)),
                other => return Err(unexpected(&other)),
            };
            if json {
                let text =
                    serde_json::to_string_pretty(&handles).map_err(|e| CliError(e.to_string()))?;
                println!("{text}");
            } else {
                print!("{}", handle_table(&handles));
            }
            Ok(())
        }
        Command::Add(args) => {
            let passphrase = input.secret("Vault passphrase: ")?;
            let value = read_value(&args, &mut input)?;
            let mut policy = Policy::default();
            args.policy.patch().apply(&mut policy);
            let secret = Secret {
                name: args.name.clone(),
                description: args.description.clone(),
                value,
                policy,
                created_at: 0,
                updated_at: 0,
            };
            control(
                &paths,
                Some(passphrase),
                ControlCommand::Add {
                    secret,
                    replace: args.replace,
                },
            )
            .await?;
            println!("added {}", args.name);
            Ok(())
        }
        Command::Rm { name } => {
            let passphrase = input.secret("Vault passphrase: ")?;
            control(
                &paths,
                Some(passphrase),
                ControlCommand::Remove { name: name.clone() },
            )
            .await?;
            println!("removed {name}");
            Ok(())
        }
        Command::Policy { name, policy } => {
            let patch = policy.patch();
            if patch == PolicyPatch::default() {
                return Err(CliError(
                    "nothing to change; pass at least one policy flag".into(),
                ));
            }
            let passphrase = input.secret("Vault passphrase: ")?;
            control(
                &paths,
                Some(passphrase),
                ControlCommand::SetPolicy {
                    name: name.clone(),
                    patch,
                },
            )
            .await?;
            println!("updated {name}");
            Ok(())
        }
        Command::Passwd => {
            let passphrase = input.secret("Current passphrase: ")?;
            let new_passphrase = input.new_passphrase("New passphrase: ")?;
            control(
                &paths,
                Some(passphrase),
                ControlCommand::ChangePassphrase { new_passphrase },
            )
            .await?;
            println!("passphrase changed");
            Ok(())
        }
    }
}

/// Sends a control command and prints its warnings. Errors become `CliError`.
async fn control(
    paths: &Paths,
    passphrase: Option<SecretText>,
    command: ControlCommand,
) -> Result<()> {
    let request = ControlRequest {
        passphrase,
        command,
    };
    match client::control(paths, &request, true).await? {
        ControlResponse::Done { warnings } => {
            for warning in warnings {
                eprintln!("warning: {warning}");
            }
            Ok(())
        }
        ControlResponse::Error { message, .. } => Err(CliError(message)),
    }
}

/// `lock` and `stop` succeed without doing anything when no daemon runs.
async fn stop_or_lock(paths: &Paths, command: ControlCommand) -> Result<()> {
    let request = ControlRequest {
        passphrase: None,
        command,
    };
    match client::control(paths, &request, false).await {
        Ok(ControlResponse::Done { .. }) => Ok(()),
        Ok(ControlResponse::Error { message, .. }) => Err(CliError(message)),
        Err(_) => Ok(()),
    }
}

fn read_value(args: &AddArgs, input: &mut Input) -> Result<SecretValue> {
    let name = &args.name;
    Ok(match args.kind {
        Kind::Http => {
            let placement = match &args.query_param {
                Some(param) => AuthPlacement::Query {
                    param: param.clone(),
                },
                None => AuthPlacement::Header {
                    name: args.header.clone(),
                    template: args.template.clone(),
                },
            };
            SecretValue::Http {
                token: trimmed(input.secret(&format!("Token for {name}: "))?),
                placement,
            }
        }
        Kind::Postgres => SecretValue::Postgres {
            url: trimmed(input.secret(&format!("Connection URL for {name}: "))?),
        },
        Kind::Redis => SecretValue::Redis {
            url: trimmed(input.secret(&format!("Connection URL for {name}: "))?),
        },
        Kind::Env => {
            if args.vars.is_empty() {
                return Err(CliError(
                    "an env secret needs at least one --var NAME".into(),
                ));
            }
            let mut vars = std::collections::BTreeMap::new();
            for var in &args.vars {
                vars.insert(var.clone(), input.secret(&format!("Value for {var}: "))?);
            }
            SecretValue::Env { vars }
        }
    })
}

/// Tokens and connection URLs never mean anything with surrounding
/// whitespace, which is easy to pick up when pasting.
fn trimmed(value: SecretText) -> SecretText {
    let trimmed = value.expose().trim();
    if trimmed.len() == value.expose().len() {
        value
    } else {
        SecretText::new(trimmed)
    }
}

/// Reads secrets from the terminal without echo, or one line each from stdin
/// when stdin is not a terminal (scripts and tests). Passphrases keep every
/// character except the line ending.
struct Input {
    interactive: bool,
}

impl Input {
    fn new() -> Self {
        Self {
            interactive: io::stdin().is_terminal(),
        }
    }

    fn secret(&mut self, prompt: &str) -> io::Result<SecretText> {
        if self.interactive {
            return rpassword::prompt_password(prompt).map(SecretText::new);
        }
        let mut line = Zeroizing::new(String::new());
        if io::stdin().lock().read_line(&mut line)? == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!(
                    "stdin ended before: {}",
                    prompt.trim_end_matches([' ', ':'])
                ),
            ));
        }
        let end = line.trim_end_matches(['\n', '\r']).len();
        line.truncate(end);
        Ok(SecretText::new(std::mem::take(&mut *line)))
    }

    /// Asks twice on a terminal so a typo does not lock the user out.
    fn new_passphrase(&mut self, prompt: &str) -> Result<SecretText> {
        let first = self.secret(prompt)?;
        if self.interactive {
            let second = self.secret("Repeat it: ")?;
            if first.expose() != second.expose() {
                return Err(CliError("the passphrases do not match".into()));
            }
        }
        Ok(first)
    }
}

fn describe_status(status: &Status) -> String {
    if !status.vault_exists {
        return "no vault yet: run `kv init`".into();
    }
    if status.locked {
        return "locked: run `kv unlock`".into();
    }
    let count = status.handle_count.unwrap_or(0);
    let plural = if count == 1 { "" } else { "s" };
    match status.locks_in_secs {
        Some(secs) => format!(
            "unlocked: {count} handle{plural}, locks after {} unused",
            humantime::format_duration(Duration::from_secs(secs))
        ),
        None => format!("unlocked: {count} handle{plural}"),
    }
}

fn handle_table(handles: &[HandleInfo]) -> String {
    if handles.is_empty() {
        return "no handles yet: add one with `kv add`\n".into();
    }
    let rows: Vec<[String; 5]> = handles
        .iter()
        .map(|h| {
            [
                h.name.clone(),
                format!("{:?}", h.kind).to_lowercase(),
                format!("{:?}", h.mode).to_lowercase(),
                constraints(h),
                h.description.clone(),
            ]
        })
        .collect();
    let header = ["NAME", "KIND", "MODE", "ALLOWS", "DESCRIPTION"].map(String::from);
    let mut widths = header.clone().map(|h| h.len());
    for row in &rows {
        for (width, cell) in widths.iter_mut().zip(row) {
            *width = (*width).max(cell.chars().count());
        }
    }
    let mut out = String::new();
    for row in std::iter::once(&header).chain(&rows) {
        let cells: Vec<String> = row
            .iter()
            .zip(widths)
            .map(|(cell, width)| format!("{cell:width$}"))
            .collect();
        out.push_str(cells.join("  ").trim_end());
        out.push('\n');
    }
    out
}

fn constraints(handle: &HandleInfo) -> String {
    let mut parts = Vec::new();
    if !handle.allowed_hosts.is_empty() {
        parts.push(format!("hosts={}", handle.allowed_hosts.join(",")));
    }
    if handle.allow_plain_http {
        parts.push("plain-http".into());
    }
    if !handle.allowed_methods.is_empty() {
        parts.push(format!("methods={}", handle.allowed_methods.join(",")));
    }
    if !handle.allowed_cmds.is_empty() {
        parts.push(format!("cmds={}", handle.allowed_cmds.join(",")));
    }
    if !handle.env_vars.is_empty() {
        parts.push(format!("vars={}", handle.env_vars.join(",")));
    }
    if handle.read_only {
        parts.push("read-only".into());
    }
    if parts.is_empty() {
        "-".into()
    } else {
        parts.join(" ")
    }
}

fn unexpected(response: &AgentResponse) -> CliError {
    match response {
        AgentResponse::Error { message, .. } => CliError(message.clone()),
        other => CliError(format!("unexpected reply from the daemon: {other:?}")),
    }
}
```

`crates/kv/src/main.rs`:
```rust
fn main() -> std::process::ExitCode {
    kv::cli::main()
}
```

`crates/kv/src/lib.rs` becomes:
```rust
//! The kv daemon, its CLI, and the socket plumbing they share.

pub mod audit;
pub mod cli;
pub mod client;
pub mod daemon;
pub mod frame;
pub mod ipc;
pub mod paths;
pub mod throttle;
```

- [ ] **Step 6: Run the tests and confirm they pass**

Run: `DEVELOPER_DIR=/Library/Developer/CommandLineTools cargo test -p kv`
Expected: lib 16, cli 18, ipc 3, state 17, all passing. Afterwards `pgrep -f "kv daemon"` lists no daemons left running by the tests.

- [ ] **Step 7: Check the backoff test can fail**

In `crates/kv/src/throttle.rs`, temporarily change `if self.failures >= FREE_ATTEMPTS {` to `if false && self.failures >= FREE_ATTEMPTS {`. Then run `DEVELOPER_DIR=/Library/Developer/CommandLineTools cargo test -p kv --test cli wrong_passphrases_back_off`.
Expected: FAIL. Revert, and confirm it passes again.

- [ ] **Step 8: Update the README**

Replace `README.md` with:
````markdown
# key-vault-for-llm

A local secrets broker for AI coding agents. Agents get named handles to
secrets (`prod-db`, `openrouter`, `github`) and the broker does the
authenticated work, so API keys, database URLs and other credentials never
show up in a chat transcript or in the model's context.

Status: the vault, daemon and CLI work. Agents cannot use handles yet; the MCP
server, HTTP requests and secret-injecting `exec` come next.

## What works today

```sh
cargo install --path crates/kv

kv init                       # create the vault and choose a passphrase
kv add openrouter --kind http --host openrouter.ai --mode auto
kv add prod-db --kind postgres --read-only true
kv add aws --kind env --var AWS_ACCESS_KEY_ID --var AWS_SECRET_ACCESS_KEY --cmd terraform
kv list                       # names and policies, never values
kv policy openrouter --method GET --method POST
kv lock                       # agents get "vault locked" until you unlock
kv unlock
kv passwd                     # also rotates the vault key
kv stop                       # lock and stop the daemon
```

Secret values and passphrases are read from a hidden prompt, or one per line
from stdin when stdin is not a terminal. They are never taken as command-line
arguments, where they would end up in shell history.

Every command that changes the vault asks for the passphrase, so an agent
running commands as you cannot add, remove or loosen secrets. The vault locks
itself after 8 hours without use (`kv daemon --idle-lock 2h` to change that).

Set `KV_HOME` to keep the vault, audit log and sockets in one directory
instead of the platform defaults.

## Planned for v1

- HTTP API proxy that adds auth headers for allow-listed hosts
- Local database proxy (Postgres, Redis) that connects upstream with the real
  credentials, with optional read-only enforcement
- Running CLI tools with secrets injected as env vars, with output scrubbed
- Exposed to agents over MCP

## What kv protects against

kv keeps secrets out of the model's context and transcripts, and limits what
an agent can do with a handle through per-secret policy and approvals. It is
not a sandbox: a malicious process running as your own user can still attack
it (for example by reading process memory on platforms that allow it).

Single-user, for macOS, Linux and Windows, written in Rust.
````

- [ ] **Step 9: Full verification**

Run: `DEVELOPER_DIR=/Library/Developer/CommandLineTools cargo fmt --all --check && DEVELOPER_DIR=/Library/Developer/CommandLineTools cargo clippy --workspace --all-targets -- -D warnings && DEVELOPER_DIR=/Library/Developer/CommandLineTools cargo test --workspace`
Expected: 125 tests pass.

Run: `for t in x86_64-pc-windows-msvc x86_64-unknown-linux-gnu; do DEVELOPER_DIR=/Library/Developer/CommandLineTools cargo clippy --workspace --target $t --all-targets -- -D warnings; done`
Expected: both finish with no warnings or errors (type-checks the Windows and Linux code paths; CI runs them for real).

- [ ] **Step 10: Commit**

```bash
git add README.md crates/kv
git commit -m "Add the kv daemon server, client and CLI"
```

---

## After Plan 2

The approved spec section 4 and the roadmap in Plan 1 cover the next plan. Plan 3 adds `kv mcp` over `rmcp`, plus `http_request` (with `base_url`) and `exec` on the agent socket. It inherits these notes:
- `evaluate` should take or return the parsed `Url` that is actually sent.
- Scrub `reqwest` error strings, since they include the URL and any query token.
- Resolve bare program names through a PATH with no relative entries, not the agent-inherited environment.
