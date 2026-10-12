//! The handle forms `kv tui` and the `kv tray` window share: a form turned
//! into what the window draws, and what the window sends back turned into
//! the same effect as typing it into the TUI.

use std::collections::BTreeMap;

use kv::forms::{self, FieldKind, FormView, Purpose};
use kv::tui::app::{App, Effect};
use kv_core::policy::Mode;
use kv_core::proto::{Overview, RequestedHandle, Status};
use kv_core::secret::{AuthPlacement, SecretText, SecretValue};
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

const TOKEN: &str = "sk-or-v1-0123456789abcdef";

fn values(pairs: &[(&str, &str)]) -> BTreeMap<String, SecretText> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_owned(), SecretText::new(*v)))
        .collect()
}

fn field<'a>(view: &'a FormView, key: &str) -> &'a forms::FieldView {
    view.fields
        .iter()
        .find(|f| f.key == key)
        .unwrap_or_else(|| panic!("no field {key} in {view:?}"))
}

#[test]
fn a_described_form_never_carries_a_secret() {
    let mut form = forms::new_handle();
    forms::fill(
        &mut form,
        &values(&[("name", "openrouter"), ("token", TOKEN)]),
    )
    .unwrap();
    let view = forms::describe(&form);
    assert_eq!(view.title, "New handle");
    let token = field(&view, "token");
    assert_eq!(token.kind, FieldKind::Secret);
    assert_eq!(token.value, "");
    assert_eq!(field(&view, "name").value, "openrouter");
    assert!(!serde_json::to_string(&view).unwrap().contains("0123456789"));

    let kind = field(&view, "kind");
    assert_eq!(kind.kind, FieldKind::Choice);
    assert_eq!(kind.options, ["http", "env", "postgres", "redis"]);
    assert_eq!(kind.value, "http");
    let header = field(&view, "header");
    assert_eq!(header.value, "Authorization");
    let when = header.when.as_ref().unwrap();
    assert_eq!(
        (when.key.as_str(), when.options.as_slice()),
        ("placement", &["header".to_owned()][..])
    );
    assert_eq!(field(&view, "vars").kind, FieldKind::Pairs);
}

/// What the window sends gives the same effect as the same values typed
/// into `kv tui`.
#[test]
fn filled_values_save_as_the_tui_would() {
    let mut form = forms::new_handle();
    forms::fill(
        &mut form,
        &values(&[
            ("name", "openrouter"),
            ("description", "Models"),
            ("token", TOKEN),
            ("hosts", "openrouter.ai, api.openrouter.ai"),
        ]),
    )
    .unwrap();
    let from_window = forms::submit(&Purpose::Add, &form).unwrap();

    let mut app = App::new();
    app.apply(kv::tui::app::Outcome::Opened);
    app.apply(kv::tui::app::Outcome::Overview(Overview {
        status: Status {
            vault_exists: true,
            locked: false,
            handle_count: Some(0),
            locks_in_secs: None,
            pending_approvals: 0,
            devices: Vec::new(),
        },
        handles: Vec::new(),
        approvals: Vec::new(),
        handle_requests: Vec::new(),
        role_warnings: Default::default(),
    }));
    let press = |app: &mut App, code| app.handle_key(KeyEvent::new(code, KeyModifiers::NONE));
    press(&mut app, KeyCode::Char('2'));
    press(&mut app, KeyCode::Char('n'));
    let type_into = |app: &mut App, key: &str, text: &str| {
        while app.form().unwrap().focused() != Some(key) {
            press(app, KeyCode::Tab);
        }
        for c in text.chars() {
            press(app, KeyCode::Char(c));
        }
    };
    type_into(&mut app, "name", "openrouter");
    type_into(&mut app, "description", "Models");
    type_into(&mut app, "token", TOKEN);
    type_into(&mut app, "hosts", "openrouter.ai, api.openrouter.ai");
    while app.form().unwrap().focused().is_some() {
        press(&mut app, KeyCode::Tab);
    }
    let from_tui = press(&mut app, KeyCode::Enter).unwrap();
    assert_eq!(from_window, from_tui);
    let Effect::Add(secret) = from_window else {
        panic!("{from_window:?}");
    };
    assert_eq!(secret.policy.mode, Mode::Ask);
    assert_eq!(
        secret.value,
        SecretValue::Http {
            token: SecretText::new(TOKEN),
            placement: AuthPlacement::Header {
                name: "Authorization".into(),
                template: "Bearer {}".into(),
            },
            base_url: None,
        }
    );
}

#[test]
fn variables_come_one_per_line() {
    let mut form = forms::new_handle();
    forms::fill(
        &mut form,
        &values(&[
            ("kind", "env"),
            ("name", "aws"),
            (
                "vars",
                "AWS_ACCESS_KEY_ID=AKIA0\n\n  AWS_SECRET_ACCESS_KEY=s3cret  \n",
            ),
            ("cmds", "terraform"),
        ]),
    )
    .unwrap();
    let Effect::Add(secret) = forms::submit(&Purpose::Add, &form).unwrap() else {
        panic!();
    };
    let SecretValue::Env { vars } = secret.value else {
        panic!();
    };
    assert_eq!(
        vars.keys().collect::<Vec<_>>(),
        ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"]
    );
    assert_eq!(vars["AWS_SECRET_ACCESS_KEY"], SecretText::new("s3cret"));

    let error = forms::fill(&mut form, &values(&[("vars", "not a pair")])).unwrap_err();
    assert!(error.contains("NAME=value"), "{error}");
}

#[test]
fn unknown_keys_are_ignored_and_unknown_options_refused() {
    let mut form = forms::new_handle();
    forms::fill(&mut form, &values(&[("no_such_field", "x"), ("name", "a")])).unwrap();
    assert_eq!(form.text("name"), "a");
    let error = forms::fill(&mut form, &values(&[("kind", "ftp")])).unwrap_err();
    assert!(error.contains("Kind"), "{error}");
    assert_eq!(
        form.chosen("kind"),
        "http",
        "a refused value changes nothing"
    );
}

#[test]
fn a_requested_handle_puts_the_cursor_on_its_secret() {
    let requested = RequestedHandle {
        id: 3,
        client: None,
        request: serde_json::from_str(
            r#"{"name":"github","kind":"http","allowed_hosts":["api.github.com"]}"#,
        )
        .unwrap(),
    };
    let view = forms::describe(&forms::requested_handle(&requested));
    assert_eq!(view.focus.as_deref(), Some("token"));
    assert_eq!(field(&view, "name").value, "github");
    assert_eq!(field(&view, "hosts").value, "api.github.com");
}
