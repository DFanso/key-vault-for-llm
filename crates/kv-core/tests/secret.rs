use std::collections::BTreeMap;

use kv_core::VaultError;
use kv_core::policy::Policy;
use kv_core::secret::{
    AuthPlacement, Secret, SecretKind, SecretText, SecretValue, validate_handle,
};

fn file_secret(name: &str, bytes: &[u8]) -> Secret {
    Secret {
        name: name.into(),
        description: "a file".into(),
        value: SecretValue::file("passwords.txt", bytes).unwrap(),
        policy: Policy::default(),
        created_at: 0,
        updated_at: 0,
        from_share: None,
    }
}

#[test]
fn a_file_value_keeps_every_byte_and_its_name() {
    // Binary, CRLF, a BOM, no trailing newline: nothing is normalised.
    let bytes: Vec<u8> = [
        &b"\xEF\xBB\xBFhunter2hunter\r\n"[..],
        &[0, 255, 10, 13, 128],
    ]
    .concat();
    let value = SecretValue::file("a/b\\passwords.txt", &bytes).unwrap();
    assert_eq!(value.kind(), SecretKind::File);
    let (name, back) = value.file_parts().unwrap();
    assert_eq!(name, "passwords.txt", "only the base name is kept");
    assert_eq!(&back[..], &bytes[..]);
    assert_eq!(value.file_len(), Some(bytes.len()));
    let json = serde_json::to_string(&value).unwrap();
    let again: SecretValue = serde_json::from_str(&json).unwrap();
    assert_eq!(again, value);
    assert_eq!(&again.file_parts().unwrap().1[..], &bytes[..]);
}

#[test]
fn a_file_value_checks_that_it_is_what_it_says() {
    let bytes = b"one\ntwo\n";
    let value = SecretValue::file("list.txt", bytes).unwrap();
    assert_eq!(value.verify_file(), Ok(()));
    let fingerprint = value.file_fingerprint().unwrap();
    assert_eq!(fingerprint.len(), 14);
    assert_eq!(fingerprint, fingerprint.to_ascii_uppercase());
    // The same bytes make the same fingerprint, other bytes another.
    assert_eq!(
        SecretValue::file("other.txt", bytes)
            .unwrap()
            .file_fingerprint(),
        Some(fingerprint.clone())
    );
    assert_ne!(
        SecretValue::file("list.txt", b"one\ntwo")
            .unwrap()
            .file_fingerprint(),
        Some(fingerprint)
    );

    // Contents changed under the checksum, a missing checksum, a name
    // with a path in it, and bytes that are not base64 are all refused.
    let SecretValue::File {
        file_name, sha256, ..
    } = value.clone()
    else {
        unreachable!()
    };
    let with = |name: &str, data: &str, sum: &str| SecretValue::File {
        file_name: name.into(),
        data: SecretText::new(data),
        sha256: sum.into(),
    };
    let good = "b25lCnR3bwo="; // "one\ntwo\n"
    assert_eq!(with(&file_name, good, &sha256).verify_file(), Ok(()));
    assert_eq!(
        with(&file_name, "b25lCnR3bwA=", &sha256).verify_file(),
        Err(kv_core::secret::FileError::Altered)
    );
    assert_eq!(
        with(&file_name, good, "").verify_file(),
        Err(kv_core::secret::FileError::Altered)
    );
    assert_eq!(
        with("../list.txt", good, &sha256).verify_file(),
        Err(kv_core::secret::FileError::BadName)
    );
    assert_eq!(
        with(&file_name, "!!not base64!!", &sha256).verify_file(),
        Err(kv_core::secret::FileError::Altered)
    );
}

#[test]
fn a_file_value_refuses_a_bad_name_or_too_many_bytes() {
    assert!(SecretValue::file("", b"x").is_err());
    assert!(SecretValue::file("..", b"x").is_err());
    assert!(SecretValue::file("a\0b", b"x").is_err());
    let big = vec![0u8; kv_core::secret::MAX_FILE_LEN + 1];
    assert!(SecretValue::file("big.bin", &big).is_err());
    assert!(SecretValue::file("ok.bin", &big[..kv_core::secret::MAX_FILE_LEN]).is_ok());
}

#[test]
fn a_file_never_shows_in_debug_or_handle_info() {
    let secret = file_secret("passwords", b"correct horse battery staple\n");
    assert!(!format!("{secret:?}").contains("correct horse"));
    let info = secret.info();
    assert_eq!(info.kind, SecretKind::File);
    let json = serde_json::to_string(&info).unwrap();
    assert!(!json.contains("correct horse"));
    assert!(!json.contains("Y29ycmVjdC")); // its base64
    assert_eq!(info.env_vars, vec!["KV_FILE_PASSWORDS".to_owned()]);
}

#[test]
fn a_text_files_lines_are_scrubbed_and_a_binary_file_is_not() {
    let text = file_secret(
        "passwords",
        b"short\r\ncorrect-horse-battery\n\n  trustno1trustno1  \ncorrect-horse-battery\n",
    );
    let mut lines: Vec<String> = text
        .sensitive_values()
        .iter()
        .map(|v| v.to_string())
        .collect();
    lines.sort();
    // Lines too short for the scrubber are left to it; repeats are kept once.
    assert_eq!(lines, vec!["correct-horse-battery", "trustno1trustno1"]);
    let binary = file_secret("key", &[0u8, 159, 146, 150, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
    assert!(binary.sensitive_values().is_empty());
}

fn http_secret() -> Secret {
    Secret {
        name: "openrouter".into(),
        description: "OpenRouter API key".into(),
        value: SecretValue::Http {
            token: SecretText::new("sk-or-v1-0123456789abcdef"),
            placement: AuthPlacement::Header {
                name: "Authorization".into(),
                template: "Bearer {}".into(),
            },
            base_url: None,
        },
        policy: Policy {
            allowed_hosts: vec!["openrouter.ai".into()],
            ..Policy::default()
        },
        created_at: 0,
        updated_at: 0,
        from_share: None,
    }
}

fn pg_secret(url: &str) -> Secret {
    Secret {
        name: "prod-db".into(),
        description: "Prod Postgres".into(),
        value: SecretValue::Postgres {
            url: SecretText::new(url),
        },
        policy: Policy::default(),
        created_at: 0,
        updated_at: 0,
        from_share: None,
    }
}

#[test]
fn debug_never_prints_secret_values() {
    let printed = format!("{:?}", http_secret());
    assert!(!printed.contains("sk-or-v1"), "{printed}");
    assert!(printed.contains("[REDACTED]"));
}

#[test]
fn handle_info_carries_no_secret_values() {
    let mut vars = BTreeMap::new();
    vars.insert(
        "AWS_SECRET_ACCESS_KEY".to_string(),
        SecretText::new("wJalrXUtnFEMI-secret"),
    );
    let env = Secret {
        name: "aws".into(),
        description: "AWS deploy creds".into(),
        value: SecretValue::Env { vars },
        policy: Policy::default(),
        created_at: 0,
        updated_at: 0,
        from_share: None,
    };
    for secret in [
        http_secret(),
        pg_secret("postgres://app:hunter2hunter2@db.internal:5432/app"),
        env,
    ] {
        let json = serde_json::to_string(&secret.info()).unwrap();
        for value in secret.sensitive_values() {
            assert!(
                !json.contains(value.as_str()),
                "{json} leaks {}",
                value.as_str()
            );
        }
        assert!(!json.contains("db.internal"), "{json} leaks the DB host");
    }
}

#[test]
fn handle_info_lists_env_var_names() {
    let mut vars = BTreeMap::new();
    vars.insert("A_KEY".to_string(), SecretText::new("aaaaaaaaaa"));
    vars.insert("B_KEY".to_string(), SecretText::new("bbbbbbbbbb"));
    let secret = Secret {
        name: "env".into(),
        description: String::new(),
        value: SecretValue::Env { vars },
        policy: Policy::default(),
        created_at: 0,
        updated_at: 0,
        from_share: None,
    };
    let info = secret.info();
    assert_eq!(info.kind, SecretKind::Env);
    assert_eq!(info.env_vars, vec!["A_KEY", "B_KEY"]);
}

#[test]
fn handle_info_carries_every_policy_constraint() {
    let mut secret = http_secret();
    secret.policy.allow_plain_http = true;
    secret.policy.grant_ttl = std::time::Duration::from_secs(300);
    let info = secret.info();
    assert!(info.allow_plain_http);
    assert_eq!(info.grant_ttl.as_secs(), 300);
    let json = serde_json::to_string(&info).unwrap();
    assert!(json.contains(r#""grant_ttl":"5m""#), "{json}");
}

#[test]
fn sensitive_values_include_db_password_raw_and_decoded() {
    let secret = pg_secret("postgres://app:p%40ss%2Fw0rd@db.internal:5432/app");
    let values: Vec<String> = secret
        .sensitive_values()
        .iter()
        .map(|v| v.to_string())
        .collect();
    assert!(values.contains(&"postgres://app:p%40ss%2Fw0rd@db.internal:5432/app".to_string()));
    assert!(values.contains(&"p%40ss%2Fw0rd".to_string()));
    assert!(values.contains(&"p@ss/w0rd".to_string()));
}

#[test]
fn secret_json_round_trips_with_kind_tag() {
    let secret = http_secret();
    let json = serde_json::to_string(&secret).unwrap();
    assert!(json.contains(r#""kind":"http""#), "{json}");
    let back: Secret = serde_json::from_str(&json).unwrap();
    assert_eq!(back, secret);
}

#[test]
fn policy_defaults_to_ask_with_empty_allow_lists() {
    let policy: Policy = serde_json::from_str("{}").unwrap();
    assert_eq!(policy, Policy::default());
    assert_eq!(policy.mode, kv_core::policy::Mode::Ask);
    assert_eq!(policy.grant_ttl.as_secs(), 15 * 60);
}

#[test]
fn handle_names_are_validated() {
    for ok in ["prod-db", "openrouter", "a", "db_2", "0x"] {
        assert!(validate_handle(ok).is_ok(), "{ok}");
    }
    let too_long = "a".repeat(64);
    for bad in [
        "",
        "Prod",
        "-db",
        "_db",
        "prod db",
        "prod.db",
        "pröd",
        too_long.as_str(),
    ] {
        assert!(
            matches!(validate_handle(bad), Err(VaultError::InvalidHandle(_))),
            "{bad}"
        );
    }
}

#[test]
fn a_base_url_is_scrubbed_and_never_shown_to_agents() {
    let mut secret = http_secret();
    secret.value = SecretValue::Http {
        token: SecretText::new("sk-or-v1-0123456789abcdef"),
        placement: AuthPlacement::Header {
            name: "Authorization".into(),
            template: "Bearer {}".into(),
        },
        base_url: Some("https://dokploy.internal.example/api/".into()),
    };
    let values: Vec<String> = secret
        .sensitive_values()
        .iter()
        .map(|v| v.to_string())
        .collect();
    assert!(values.contains(&"https://dokploy.internal.example/api".to_owned()));
    assert!(values.contains(&"dokploy.internal.example".to_owned()));
    let info = secret.info();
    assert!(info.takes_path);
    let json = serde_json::to_string(&info).unwrap();
    assert!(!json.contains("dokploy"), "{json}");
    assert!(!http_secret().info().takes_path);
}

#[test]
fn a_database_host_is_scrubbed_unless_it_is_loopback() {
    let values = |url: &str| -> Vec<String> {
        pg_secret(url)
            .sensitive_values()
            .iter()
            .map(|v| v.to_string())
            .collect()
    };
    assert!(
        values(&format!(
            "postgres://app:{}@db.example.com/app",
            "pw-0123456789"
        ))
        .contains(&"db.example.com".to_string())
    );
    for url in [
        "postgres://app:pw-0123456789@localhost/app",
        "postgres://app:pw-0123456789@127.0.0.1:5432/app",
        "postgres://app:pw-0123456789@[::1]/app",
    ] {
        let host = url::Url::parse(url).unwrap().host_str().unwrap().to_owned();
        assert!(!values(url).contains(&host), "{url}");
    }
    let all = values(
        "postgres://app:pw-0123456789@db1.example.com,db2.example.com/app?hostaddr=10.1.2.3&password=pw-second-0123",
    );
    for value in [
        "db1.example.com",
        "db2.example.com",
        "10.1.2.3",
        "pw-0123456789",
        "pw-second-0123",
    ] {
        assert!(all.contains(&value.to_string()), "{value} in {all:?}");
    }
}

#[test]
fn handle_info_shows_only_the_program_a_handle_runs() {
    let secret = Secret {
        name: "ssh-kycdev".into(),
        description: String::new(),
        value: SecretValue::Env {
            vars: BTreeMap::from([(
                "SSH_MCP_PASSWORD".to_string(),
                SecretText::new("hunter2-hunter2"),
            )]),
        },
        policy: Policy {
            run: Some(vec![
                "/usr/local/bin/bunx".into(),
                "-y".into(),
                "ssh-mcp@1.2.3".into(),
                "--host=10.0.0.5".into(),
            ]),
            ..Policy::default()
        },
        created_at: 0,
        updated_at: 0,
        from_share: None,
    };
    let info = secret.info();
    assert_eq!(info.runs.as_deref(), Some("bunx"));
    let json = serde_json::to_string(&info).unwrap();
    assert!(!json.contains("10.0.0.5"), "{json}");
    assert!(!json.contains("ssh-mcp"), "{json}");
}
