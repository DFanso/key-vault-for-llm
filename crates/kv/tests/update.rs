//! `update`: change a handle's description or value and keep its policy,
//! which `kv tui` uses for editing.

mod common;

use common::*;
use kv_core::policy::Mode;
use kv_core::proto::{ControlCommand, ControlErrorCode, ControlResponse};
use kv_core::secret::{AuthPlacement, SecretText, SecretValue};

fn update(name: &str, description: Option<&str>, value: Option<SecretValue>) -> ControlCommand {
    ControlCommand::Update {
        name: name.into(),
        description: description.map(Into::into),
        value,
    }
}

fn bearer(token: &str) -> SecretValue {
    SecretValue::Http {
        token: SecretText::new(token),
        placement: AuthPlacement::Header {
            name: "Authorization".into(),
            template: "Bearer {}".into(),
        },
        base_url: None,
    }
}

fn error(response: ControlResponse) -> (ControlErrorCode, String) {
    match response {
        ControlResponse::Error { code, message } => (code, message),
        other => panic!("expected an error, got {other:?}"),
    }
}

#[test]
fn a_new_description_keeps_the_value_and_policy() {
    let mut f = Fixture::new();
    f.add(openrouter(Mode::Auto));
    let token = f.token();
    let response = f.send(
        None,
        Some(&token),
        update("openrouter", Some("Models"), None),
    );
    assert!(
        matches!(response, ControlResponse::Done { .. }),
        "{response:?}"
    );
    let handle = f.overview(&token).handles.remove(0);
    assert_eq!(handle.description, "Models");
    assert_eq!(handle.mode, Mode::Auto);
    assert_eq!(handle.allowed_hosts, ["openrouter.ai"]);
    let job = f
        .http(get("openrouter", "https://openrouter.ai/api/v1/models"))
        .unwrap();
    assert_eq!(job.secret.value, openrouter(Mode::Auto).value);
    assert_eq!(f.audit_lines().last().unwrap()["action"], "update");
}

#[test]
fn a_new_value_replaces_the_token_and_keeps_the_policy() {
    let mut f = Fixture::new();
    f.add(openrouter(Mode::Auto));
    let token = f.token();
    let new = "sk-or-v1-fedcba9876543210";
    f.send(
        None,
        Some(&token),
        update("openrouter", None, Some(bearer(new))),
    );
    let job = f
        .http(get("openrouter", "https://openrouter.ai/api/v1/models"))
        .unwrap();
    assert_eq!(job.secret.value, bearer(new));
    assert_eq!(job.secret.description, openrouter(Mode::Auto).description);
}

#[test]
fn an_http_value_without_a_base_url_keeps_the_one_the_handle_has() {
    let mut f = Fixture::new();
    f.add(dokploy());
    let token = f.token();
    let value = SecretValue::Http {
        token: SecretText::new("dokploy-token-new-0123456789"),
        placement: AuthPlacement::Header {
            name: "x-api-key".into(),
            template: "{}".into(),
        },
        base_url: None,
    };
    f.send(None, Some(&token), update("dokploy", None, Some(value)));
    let job = f.http(get("dokploy", "/projects")).unwrap();
    assert_eq!(
        job.url.as_str(),
        "https://dokploy.internal.example/api/projects"
    );
}

#[test]
fn a_value_of_another_kind_is_refused() {
    let mut f = Fixture::new();
    f.add(openrouter(Mode::Auto));
    let token = f.token();
    let postgres = SecretValue::Postgres {
        url: SecretText::new("postgres://u:p@db/app"),
    };
    let (code, message) = error(f.send(
        None,
        Some(&token),
        update("openrouter", None, Some(postgres)),
    ));
    assert_eq!(code, ControlErrorCode::Invalid);
    assert!(message.contains("http"), "{message}");
}

#[test]
fn an_invalid_value_or_unknown_handle_is_refused() {
    let mut f = Fixture::new();
    f.add(openrouter(Mode::Auto));
    let token = f.token();
    let (code, _) = error(f.send(
        None,
        Some(&token),
        update("openrouter", None, Some(bearer(""))),
    ));
    assert_eq!(code, ControlErrorCode::Invalid);
    let (code, _) = error(f.send(None, Some(&token), update("nope", Some("x"), None)));
    assert_eq!(code, ControlErrorCode::UnknownHandle);
}

#[test]
fn a_short_value_is_saved_with_a_warning() {
    let mut f = Fixture::new();
    f.add(openrouter(Mode::Auto));
    let token = f.token();
    match f.send(
        None,
        Some(&token),
        update("openrouter", None, Some(bearer("short"))),
    ) {
        ControlResponse::Done { warnings } => {
            assert!(warnings.iter().any(|w| w.contains("scrub")), "{warnings:?}")
        }
        other => panic!("{other:?}"),
    }
}
