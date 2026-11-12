//! The `login` kind: a username and password that agents use as HTTP Basic
//! auth or as two variables for a program, and never see.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use kv_core::policy::{Decision, DenyReason, Mode, Operation, Policy, evaluate};
use kv_core::secret::{AuthPlacement, Secret, SecretKind, SecretText, SecretValue, login_env_vars};

fn login(name: &str, policy: Policy) -> Secret {
    Secret {
        name: name.into(),
        description: "Jira service account".into(),
        value: SecretValue::Login {
            username: SecretText::new("svc-reports@example.com"),
            password: SecretText::new("correct horse battery"),
        },
        policy,
        created_at: 0,
        updated_at: 0,
        from_share: None,
    }
}

fn allowing(hosts: &[&str], cmds: &[&str]) -> Policy {
    Policy {
        mode: Mode::Auto,
        allowed_hosts: hosts.iter().map(|h| (*h).to_owned()).collect(),
        allowed_cmds: cmds.iter().map(|c| (*c).to_owned()).collect(),
        ..Policy::default()
    }
}

#[test]
fn a_login_is_its_own_kind_and_keeps_both_halves_through_json() {
    let value = login("jira", Policy::default()).value;
    assert_eq!(value.kind(), SecretKind::Login);
    let json = serde_json::to_string(&value).unwrap();
    assert!(json.contains(r#""kind":"login""#), "{json}");
    let again: SecretValue = serde_json::from_str(&json).unwrap();
    assert_eq!(again, value);
    assert_eq!(
        serde_json::to_string(&SecretKind::Login).unwrap(),
        r#""login""#
    );
}

#[test]
fn a_login_goes_on_a_request_as_basic_auth() {
    let (credential, placement) = login("jira", Policy::default()).value.http_auth().unwrap();
    assert_eq!(
        credential.expose(),
        STANDARD.encode("svc-reports@example.com:correct horse battery")
    );
    assert_eq!(
        placement,
        AuthPlacement::Header {
            name: "Authorization".into(),
            template: "Basic {}".into(),
        }
    );
}

#[test]
fn a_login_gives_a_program_two_variables_named_after_the_handle() {
    assert_eq!(
        login_env_vars("jira-prod"),
        [
            "JIRA_PROD_USERNAME".to_owned(),
            "JIRA_PROD_PASSWORD".to_owned()
        ]
    );
    // A variable cannot start with a digit.
    assert_eq!(
        login_env_vars("1password"),
        [
            "KV_1PASSWORD_USERNAME".to_owned(),
            "KV_1PASSWORD_PASSWORD".to_owned()
        ]
    );
    let secret = login("jira", Policy::default());
    let vars: Vec<(String, String)> = secret
        .value
        .exec_vars(&secret.name)
        .into_iter()
        .map(|(name, value)| (name, value.expose().to_owned()))
        .collect();
    assert_eq!(
        vars,
        [
            (
                "JIRA_USERNAME".to_owned(),
                "svc-reports@example.com".to_owned()
            ),
            (
                "JIRA_PASSWORD".to_owned(),
                "correct horse battery".to_owned()
            ),
        ]
    );
}

#[test]
fn an_agent_learns_how_to_use_a_login_but_not_what_it_is() {
    let info = login("jira", allowing(&["jira.example.com"], &["curl"])).info();
    assert_eq!(info.kind, SecretKind::Login);
    assert_eq!(info.env_vars, ["JIRA_USERNAME", "JIRA_PASSWORD"]);
    assert!(matches!(
        info.auth,
        Some(AuthPlacement::Header { ref name, ref template })
            if name == "Authorization" && template == "Basic {}"
    ));
    let shown = serde_json::to_string(&info).unwrap();
    assert!(!shown.contains("svc-reports"), "{shown}");
    assert!(!shown.contains("correct horse"), "{shown}");
}

#[test]
fn the_scrubber_hides_the_username_the_password_and_the_basic_value() {
    let secret = login("jira", Policy::default());
    let hidden: Vec<String> = secret
        .sensitive_values()
        .iter()
        .map(|v| v.as_str().to_owned())
        .collect();
    let basic = STANDARD.encode("svc-reports@example.com:correct horse battery");
    for value in [
        "svc-reports@example.com",
        "correct horse battery",
        basic.as_str(),
    ] {
        assert!(hidden.iter().any(|h| h == value), "{value} is not scrubbed");
    }
}

#[test]
fn a_login_is_used_with_http_request_to_its_hosts_and_exec_with_its_programs() {
    let secret = login("jira", allowing(&["jira.example.com"], &["curl"]));
    let get = |url| evaluate(&secret, &Operation::Http { method: "GET", url });
    assert_eq!(
        get("https://jira.example.com/rest/api/2/myself"),
        Decision::Allow
    );
    assert!(matches!(
        get("https://evil.example.net/"),
        Decision::Deny(DenyReason::HostNotAllowed { .. })
    ));
    assert_eq!(
        evaluate(&secret, &Operation::Exec { program: "curl" }),
        Decision::Allow
    );
    assert!(matches!(
        evaluate(&secret, &Operation::Exec { program: "bash" }),
        Decision::Deny(DenyReason::CommandNotAllowed { .. })
    ));
    for op in [Operation::DbQuery, Operation::DbConnect, Operation::Run] {
        assert!(matches!(
            evaluate(&secret, &op),
            Decision::Deny(DenyReason::WrongKind {
                kind: SecretKind::Login,
                ..
            })
        ));
    }
}

#[test]
fn a_login_with_nothing_allowed_is_never_used() {
    let secret = login("jira", allowing(&[], &[]));
    assert!(matches!(
        evaluate(
            &secret,
            &Operation::Http {
                method: "GET",
                url: "https://jira.example.com/"
            }
        ),
        Decision::Deny(DenyReason::HostNotAllowed { .. })
    ));
    assert!(matches!(
        evaluate(&secret, &Operation::Exec { program: "curl" }),
        Decision::Deny(DenyReason::CommandNotAllowed { .. })
    ));
}
