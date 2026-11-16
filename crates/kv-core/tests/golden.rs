//! Files a released kv wrote, kept so a format change cannot silently stop
//! today's code opening them.
//!
//! The files in `tests/fixtures/` were written by kv 1.7.0. Never write
//! them again to make a failing test pass: a failure means today's code no
//! longer opens what 1.7.0 wrote. To add files for a later version, first
//! change the version in `VAULT`, `REQUEST` and `SHARE` (so the 1.7.0 files
//! stay), then run:
//!
//! ```sh
//! cargo test -p kv-core --test golden -- --ignored write_golden_fixtures
//! ```
//!
//! and commit the new files next to the old ones. The test refuses to
//! overwrite a file that is already there.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use kv_core::VaultError;
use kv_core::crypto::KdfParams;
use kv_core::policy::{Mode, Policy};
use kv_core::secret::{AuthPlacement, Secret, SecretKind, SecretText, SecretValue};
use kv_core::share::{self, OpenRequest, ShareRequest, SharedSecret};
use kv_core::vault::Vault;
use tempfile::TempDir;

/// Cheap Argon2 settings, as the other tests use. Never use outside tests.
const FAST: KdfParams = KdfParams {
    m_kib: 8,
    t: 1,
    p: 1,
};
/// The passphrase of the golden vault. It guards only fake values.
const PASS: &str = "golden fixture passphrase";
const VAULT: &str = "vault-1.7.0.kv";
const REQUEST: &str = "request-1.7.0.txt";
const SHARE: &str = "share-1.7.0.txt";
/// When the golden request was made, in Unix seconds.
const MADE_AT: u64 = 1_800_000_000;
const DAY: u64 = 24 * 60 * 60;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

/// Every handle the golden vault holds, one of each kind, with fake values.
fn expected_secrets() -> Vec<Secret> {
    let handle = |name: &str, description: &str, value: SecretValue, policy: Policy| Secret {
        name: name.into(),
        description: description.into(),
        value,
        policy,
        created_at: 0,
        updated_at: 0,
        from_share: None,
    };
    let mut vars = BTreeMap::new();
    vars.insert(
        "API_KEY".to_owned(),
        SecretText::new("env-test-golden-0005"),
    );
    vars.insert(
        "API_SECRET".to_owned(),
        SecretText::new("env-test-golden-0006"),
    );
    vec![
        handle(
            "openrouter",
            "golden http header token",
            SecretValue::Http {
                token: SecretText::new("sk-test-golden-0001"),
                placement: AuthPlacement::Header {
                    name: "Authorization".into(),
                    template: "Bearer {}".into(),
                },
                base_url: None,
            },
            Policy {
                mode: Mode::Auto,
                allowed_hosts: vec!["openrouter.example.invalid".into()],
                allowed_methods: vec!["POST".into()],
                grant_ttl: Duration::from_secs(30 * 60),
                ..Policy::default()
            },
        ),
        handle(
            "dokploy",
            "golden http query token with a base url",
            SecretValue::Http {
                token: SecretText::new("dk-test-golden-0002"),
                placement: AuthPlacement::Query {
                    param: "api_key".into(),
                },
                base_url: Some("https://dokploy.example.invalid/api".into()),
            },
            Policy {
                allowed_hosts: vec!["dokploy.example.invalid:8443".into()],
                allow_plain_http: true,
                ..Policy::default()
            },
        ),
        handle(
            "prod-db",
            "golden postgres url",
            SecretValue::Postgres {
                url: SecretText::new(
                    "postgres://golden:pg-test-golden-0003@db.example.invalid:5432/app",
                ),
            },
            Policy {
                read_only: true,
                ..Policy::default()
            },
        ),
        handle(
            "cache",
            "golden redis url",
            SecretValue::Redis {
                url: SecretText::new("redis://:rd-test-golden-0004@cache.example.invalid:6379/0"),
            },
            Policy {
                mode: Mode::Deny,
                ..Policy::default()
            },
        ),
        handle(
            "deploy-env",
            "golden env vars with a run command",
            SecretValue::Env { vars },
            Policy {
                allowed_cmds: vec!["deploy".into(), "/usr/local/bin/deploy-golden".into()],
                run: Some(vec!["deploy-mcp".into(), "--stdio".into()]),
                ..Policy::default()
            },
        ),
        handle(
            "service-account",
            "golden login",
            SecretValue::Login {
                username: SecretText::new("golden-user"),
                password: SecretText::new("pw-test-golden-0007"),
            },
            Policy {
                allowed_hosts: vec!["login.example.invalid".into()],
                allowed_cmds: vec!["golden-cli".into()],
                ..Policy::default()
            },
        ),
        handle(
            "tls-cert",
            "golden file",
            SecretValue::file(
                "golden-cert.pem",
                b"-----BEGIN FAKE TEST CERT-----\r\ngolden-0008 \x00\xff\n-----END FAKE TEST CERT-----\n",
            )
            .unwrap(),
            Policy::default(),
        ),
    ]
}

/// What the golden share carries.
fn expected_shared() -> SharedSecret {
    SharedSecret {
        name: "golden-shared".into(),
        description: "golden shared token".into(),
        value: SecretValue::Http {
            token: SecretText::new("sk-test-golden-share-0009"),
            placement: AuthPlacement::Header {
                name: "X-Api-Key".into(),
                template: "{}".into(),
            },
            base_url: Some("https://shared.example.invalid/v1".into()),
        },
        allowed_hosts: vec!["shared.example.invalid".into()],
        allow_plain_http: false,
        allowed_methods: vec!["GET".into(), "POST".into()],
        read_only: true,
        from: "golden-sender".into(),
        note: "golden share note".into(),
    }
}

fn read_text(name: &str) -> String {
    fs::read_to_string(fixture(name)).unwrap()
}

/// Opens a copy of the golden vault, so no test can change the committed
/// file.
fn open_golden(passphrase: &str) -> (TempDir, Result<Vault, VaultError>) {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join(VAULT);
    fs::copy(fixture(VAULT), &path).unwrap();
    let vault = Vault::unlock(&path, passphrase);
    (dir, vault)
}

/// Writes the fixtures. Ignored: run it by hand as the module comment says.
#[test]
#[ignore = "writes the golden fixtures; run by hand for a new format version"]
fn write_golden_fixtures() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join(VAULT);
    let mut vault = Vault::create(&path, PASS, FAST).unwrap();
    for secret in expected_secrets() {
        vault.upsert(secret).unwrap();
    }
    let request = OpenRequest::new(
        "golden test request".into(),
        "golden-requester".into(),
        MADE_AT,
        DAY,
    );
    vault.shares_mut().requests.push(request.clone());
    vault.save().unwrap();
    let sealed = share::seal(&request.request(), &expected_shared()).unwrap();

    fs::create_dir_all(fixture("")).unwrap();
    for name in [VAULT, REQUEST, SHARE] {
        assert!(
            !fixture(name).exists(),
            "{name} is already there; change the version in its name first"
        );
    }
    fs::copy(&path, fixture(VAULT)).unwrap();
    fs::write(fixture(REQUEST), request.code()).unwrap();
    fs::write(fixture(SHARE), sealed).unwrap();
}

#[test]
fn the_golden_vault_opens_with_its_passphrase_and_holds_every_handle() {
    let (_dir, vault) = open_golden(PASS);
    let vault = vault.unwrap();
    let expected = expected_secrets();
    let names: Vec<&str> = vault.secrets().iter().map(|s| s.name.as_str()).collect();
    let wanted: Vec<&str> = expected.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(names, wanted);
    for want in &expected {
        let got = vault.get(&want.name).unwrap();
        assert_eq!(got.kind(), want.kind(), "{}", want.name);
        assert_eq!(got.description, want.description, "{}", want.name);
        assert_eq!(got.value, want.value, "{}", want.name);
        assert_eq!(got.policy, want.policy, "{}", want.name);
        assert_eq!(got.from_share, Some(false), "{}", want.name);
        assert!(got.created_at > 0 && got.updated_at >= got.created_at);
    }
}

#[test]
fn the_golden_vault_holds_one_of_each_kind() {
    let (_dir, vault) = open_golden(PASS);
    let mut kinds: Vec<SecretKind> = vault.unwrap().secrets().iter().map(Secret::kind).collect();
    kinds.dedup();
    assert_eq!(
        kinds,
        [
            SecretKind::Http,
            SecretKind::Postgres,
            SecretKind::Redis,
            SecretKind::Env,
            SecretKind::Login,
            SecretKind::File,
        ]
    );
}

#[test]
fn the_golden_file_handle_still_matches_its_checksum() {
    let (_dir, vault) = open_golden(PASS);
    let vault = vault.unwrap();
    let file = &vault.get("tls-cert").unwrap().value;
    file.verify_file().unwrap();
    let (name, bytes) = file.file_parts().unwrap();
    assert_eq!(name, "golden-cert.pem");
    // The CR, NUL and 0xFF bytes would not survive a line-ending rewrite.
    assert_eq!(
        bytes.as_slice(),
        b"-----BEGIN FAKE TEST CERT-----\r\ngolden-0008 \x00\xff\n-----END FAKE TEST CERT-----\n"
    );
}

#[test]
fn the_golden_vault_refuses_a_wrong_passphrase() {
    let (_dir, vault) = open_golden("not the golden passphrase");
    assert!(matches!(vault, Err(VaultError::WrongPassphrase)));
}

#[test]
fn the_golden_request_code_decodes_to_the_request_the_vault_keeps() {
    let (_dir, vault) = open_golden(PASS);
    let vault = vault.unwrap();
    let requests = &vault.shares().requests;
    assert_eq!(requests.len(), 1);
    let kept = &requests[0];
    assert_eq!(kept.note, "golden test request");
    assert_eq!(kept.from, "golden-requester");
    assert_eq!(kept.created_at, MADE_AT);
    assert_eq!(kept.expires_at, MADE_AT + DAY);
    let code = read_text(REQUEST);
    assert_eq!(code, kept.code());
    assert_eq!(ShareRequest::decode(&code).unwrap(), kept.request());
}

#[test]
fn the_golden_share_opens_with_the_golden_requests_key() {
    let (_dir, vault) = open_golden(PASS);
    let vault = vault.unwrap();
    let (index, shared) = share::open(&read_text(SHARE), &vault.shares().requests).unwrap();
    assert_eq!(index, 0);
    assert_eq!(shared, expected_shared());
}

#[test]
fn the_golden_share_does_not_open_with_another_request() {
    let other = OpenRequest::new(String::new(), String::new(), MADE_AT, DAY);
    assert_eq!(
        share::open(&read_text(SHARE), &[other]).unwrap_err(),
        share::ShareError::NoMatchingRequest
    );
}
