use std::collections::BTreeMap;

use kv_core::VaultError;
use kv_core::policy::Policy;
use kv_core::secret::{
    AuthPlacement, Secret, SecretKind, SecretText, SecretValue, validate_handle,
};

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
        values("postgres://app:pw-0123456789@kyc.postgres.database.azure.com/app")
            .contains(&"kyc.postgres.database.azure.com".to_string())
    );
    for url in [
        "postgres://app:pw-0123456789@localhost/app",
        "postgres://app:pw-0123456789@127.0.0.1:5432/app",
        "postgres://app:pw-0123456789@[::1]/app",
    ] {
        let host = url::Url::parse(url).unwrap().host_str().unwrap().to_owned();
        assert!(!values(url).contains(&host), "{url}");
    }
}
