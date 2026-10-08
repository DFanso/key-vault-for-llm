use std::fs;

use kv_core::VaultError;
use kv_core::crypto::KdfParams;
use kv_core::policy::Policy;
use kv_core::secret::{Secret, SecretText, SecretValue};
use kv_core::vault::Vault;
use tempfile::TempDir;

/// Cheap Argon2 settings so tests run fast. Never use outside tests.
const FAST: KdfParams = KdfParams {
    m_kib: 8,
    t: 1,
    p: 1,
};
const PASS: &str = "correct horse battery";

fn setup() -> (TempDir, std::path::PathBuf) {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("kv").join("vault.kv");
    (dir, path)
}

fn redis(name: &str, url: &str) -> Secret {
    Secret {
        name: name.into(),
        description: "cache".into(),
        value: SecretValue::Redis {
            url: SecretText::new(url),
        },
        policy: Policy::default(),
        created_at: 0,
        updated_at: 0,
    }
}

#[test]
fn create_then_unlock_round_trips_secrets() {
    let (_dir, path) = setup();
    let mut vault = Vault::create(&path, PASS, FAST).unwrap();
    vault
        .upsert(redis("cache", "redis://:s3cretpass@cache:6379"))
        .unwrap();
    vault.save().unwrap();

    let reopened = Vault::unlock(&path, PASS).unwrap();
    assert_eq!(reopened.secrets(), vault.secrets());
    assert!(reopened.get("cache").unwrap().created_at > 0);
}

#[test]
fn file_does_not_contain_plaintext_secrets() {
    let (_dir, path) = setup();
    let mut vault = Vault::create(&path, PASS, FAST).unwrap();
    vault
        .upsert(redis("cache", "redis://:s3cretpass@cache:6379"))
        .unwrap();
    vault.save().unwrap();
    let bytes = fs::read(&path).unwrap();
    let text = String::from_utf8_lossy(&bytes);
    assert!(!text.contains("s3cretpass"));
    assert!(!text.contains("cache:6379"));
}

#[test]
fn wrong_passphrase_is_rejected() {
    let (_dir, path) = setup();
    Vault::create(&path, PASS, FAST).unwrap();
    assert!(matches!(
        Vault::unlock(&path, "wrong horse battery"),
        Err(VaultError::WrongPassphrase)
    ));
}

#[test]
fn passphrase_bytes_are_used_exactly() {
    let (_dir, path) = setup();
    let unicode = "pässwörd 🔑 ";
    Vault::create(&path, unicode, FAST).unwrap();
    assert!(Vault::unlock(&path, unicode).is_ok());
    assert!(matches!(
        Vault::unlock(&path, unicode.trim()),
        Err(VaultError::WrongPassphrase)
    ));
}

#[test]
fn short_passphrase_is_rejected() {
    let (_dir, path) = setup();
    assert!(matches!(
        Vault::create(&path, "1234567", FAST),
        Err(VaultError::WeakPassphrase)
    ));
    assert!(!path.exists());
}

#[test]
fn create_refuses_to_overwrite() {
    let (_dir, path) = setup();
    Vault::create(&path, PASS, FAST).unwrap();
    assert!(matches!(
        Vault::create(&path, PASS, FAST),
        Err(VaultError::AlreadyExists(_))
    ));
}

#[test]
fn unlock_missing_file_is_not_found() {
    let (_dir, path) = setup();
    assert!(matches!(
        Vault::unlock(&path, PASS),
        Err(VaultError::NotFound(_))
    ));
}

#[test]
fn tampered_payload_is_detected() {
    let (_dir, path) = setup();
    Vault::create(&path, PASS, FAST).unwrap();
    let mut bytes = fs::read(&path).unwrap();
    *bytes.last_mut().unwrap() ^= 1;
    fs::write(&path, &bytes).unwrap();
    assert!(matches!(
        Vault::unlock(&path, PASS),
        Err(VaultError::Corrupted)
    ));
}

#[test]
fn tampered_header_is_detected() {
    let (_dir, path) = setup();
    Vault::create(&path, PASS, FAST).unwrap();
    let bytes = fs::read(&path).unwrap();
    // Re-serialize the header with an extra field: still valid JSON, still
    // the right keys, but the payload AAD no longer matches.
    let header_len = u32::from_le_bytes(bytes[6..10].try_into().unwrap()) as usize;
    let header = &bytes[10..10 + header_len];
    let mut edited = header[..header.len() - 1].to_vec();
    edited.extend_from_slice(br#","extra":1}"#);
    let mut out = bytes[..6].to_vec();
    out.extend_from_slice(&(edited.len() as u32).to_le_bytes());
    out.extend_from_slice(&edited);
    out.extend_from_slice(&bytes[10 + header_len..]);
    fs::write(&path, &out).unwrap();
    assert!(matches!(
        Vault::unlock(&path, PASS),
        Err(VaultError::Corrupted)
    ));
}

#[test]
fn truncated_or_garbage_files_are_corrupted_not_panics() {
    let (_dir, path) = setup();
    Vault::create(&path, PASS, FAST).unwrap();
    let bytes = fs::read(&path).unwrap();
    for len in [0, 3, 9, 10, 20, bytes.len() / 2, bytes.len() - 1] {
        fs::write(&path, &bytes[..len]).unwrap();
        let result = Vault::unlock(&path, PASS);
        assert!(
            matches!(
                result,
                Err(VaultError::Corrupted | VaultError::WrongPassphrase)
            ),
            "len {len}: {result:?}"
        );
    }
    fs::write(&path, b"not a vault at all").unwrap();
    assert!(matches!(
        Vault::unlock(&path, PASS),
        Err(VaultError::Corrupted)
    ));
}

#[test]
fn unknown_version_is_reported() {
    let (_dir, path) = setup();
    Vault::create(&path, PASS, FAST).unwrap();
    let mut bytes = fs::read(&path).unwrap();
    bytes[4..6].copy_from_slice(&2u16.to_le_bytes());
    fs::write(&path, &bytes).unwrap();
    assert!(matches!(
        Vault::unlock(&path, PASS),
        Err(VaultError::UnsupportedVersion(2))
    ));
}

#[test]
fn save_keeps_previous_version_as_bak() {
    let (_dir, path) = setup();
    let mut vault = Vault::create(&path, PASS, FAST).unwrap();
    vault
        .upsert(redis("cache", "redis://:s3cretpass@cache:6379"))
        .unwrap();
    vault.save().unwrap();

    let bak = path.with_file_name("vault.kv.bak");
    let previous = Vault::unlock(&bak, PASS).unwrap();
    assert!(previous.secrets().is_empty());
    assert!(!path.with_file_name("vault.kv.tmp").exists());
}

#[cfg(unix)]
#[test]
fn vault_file_is_private_to_the_user() {
    use std::os::unix::fs::PermissionsExt;
    let (_dir, path) = setup();
    let vault = Vault::create(&path, PASS, FAST).unwrap();
    vault.save().unwrap();
    for p in [path.clone(), path.with_file_name("vault.kv.bak")] {
        let mode = fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "{}", p.display());
    }
}

#[test]
fn upsert_replaces_by_name_and_keeps_created_at() {
    let (_dir, path) = setup();
    let mut vault = Vault::create(&path, PASS, FAST).unwrap();
    vault
        .upsert(redis("cache", "redis://:aaaaaaaa@a:6379"))
        .unwrap();
    let created = vault.get("cache").unwrap().created_at;
    vault
        .upsert(redis("cache", "redis://:bbbbbbbb@b:6379"))
        .unwrap();
    assert_eq!(vault.secrets().len(), 1);
    let s = vault.get("cache").unwrap();
    assert_eq!(s.created_at, created);
    assert!(matches!(&s.value, SecretValue::Redis { url } if url.expose().contains("bbbbbbbb")));
}

#[test]
fn upsert_rejects_invalid_handles() {
    let (_dir, path) = setup();
    let mut vault = Vault::create(&path, PASS, FAST).unwrap();
    assert!(matches!(
        vault.upsert(redis("Bad Name", "redis://h")),
        Err(VaultError::InvalidHandle(_))
    ));
}

#[test]
fn remove_deletes_by_name() {
    let (_dir, path) = setup();
    let mut vault = Vault::create(&path, PASS, FAST).unwrap();
    vault.upsert(redis("cache", "redis://h")).unwrap();
    assert!(vault.remove("cache"));
    assert!(!vault.remove("cache"));
    assert!(vault.secrets().is_empty());
}

#[test]
fn change_passphrase_rewraps_without_losing_secrets() {
    let (_dir, path) = setup();
    let mut vault = Vault::create(&path, PASS, FAST).unwrap();
    vault
        .upsert(redis("cache", "redis://:s3cretpass@cache:6379"))
        .unwrap();
    vault
        .change_passphrase("a brand new passphrase", FAST)
        .unwrap();

    assert!(matches!(
        Vault::unlock(&path, PASS),
        Err(VaultError::WrongPassphrase)
    ));
    let reopened = Vault::unlock(&path, "a brand new passphrase").unwrap();
    assert_eq!(reopened.secrets(), vault.secrets());
}

#[test]
fn debug_output_hides_contents() {
    let (_dir, path) = setup();
    let mut vault = Vault::create(&path, PASS, FAST).unwrap();
    vault
        .upsert(redis("cache", "redis://:s3cretpass@cache:6379"))
        .unwrap();
    let printed = format!("{vault:?}");
    assert!(!printed.contains("s3cretpass"), "{printed}");
}

#[cfg(unix)]
#[test]
fn failed_passphrase_change_leaves_the_old_passphrase_in_effect() {
    use std::os::unix::fs::PermissionsExt;
    let (_dir, path) = setup();
    let mut vault = Vault::create(&path, PASS, FAST).unwrap();
    let dir = path.parent().unwrap();
    fs::set_permissions(dir, fs::Permissions::from_mode(0o500)).unwrap();
    let result = vault.change_passphrase("a brand new passphrase", FAST);
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(result.is_err());

    vault.save().unwrap();
    assert!(Vault::unlock(&path, PASS).is_ok());
    assert!(matches!(
        Vault::unlock(&path, "a brand new passphrase"),
        Err(VaultError::WrongPassphrase)
    ));
}

#[test]
fn bak_does_not_open_with_the_old_passphrase_after_a_change() {
    let (_dir, path) = setup();
    let mut vault = Vault::create(&path, PASS, FAST).unwrap();
    vault
        .upsert(redis("cache", "redis://:s3cretpass@cache:6379"))
        .unwrap();
    vault.save().unwrap();
    vault
        .change_passphrase("a brand new passphrase", FAST)
        .unwrap();

    let bak = path.with_file_name("vault.kv.bak");
    assert!(matches!(
        Vault::unlock(&bak, PASS),
        Err(VaultError::WrongPassphrase)
    ));
    let from_bak = Vault::unlock(&bak, "a brand new passphrase").unwrap();
    assert_eq!(from_bak.secrets(), vault.secrets());
    assert!(!path.with_file_name("vault.kv.bak.tmp").exists());
}
