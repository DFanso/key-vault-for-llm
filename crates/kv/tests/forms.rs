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
    assert_eq!(field(&view, "vars").kind, FieldKind::Pairs);
}

fn conditions(view: &FormView, key: &str) -> Vec<(String, Vec<String>)> {
    field(view, key)
        .when
        .iter()
        .map(|when| (when.key.clone(), when.options.clone()))
        .collect()
}

/// A field is shown only while the field it depends on is shown too, so
/// its conditions include that field's: the header fields belong to http
/// handles, whatever the hidden "Token goes in" still holds.
#[test]
fn a_fields_conditions_include_those_of_the_field_it_depends_on() {
    let view = forms::describe(&forms::new_handle());
    let strings = |options: &[&str]| options.iter().map(|o| (*o).to_owned()).collect();
    assert_eq!(
        conditions(&view, "header"),
        [
            ("placement".to_owned(), strings(&["header"])),
            ("kind".to_owned(), strings(&["http"])),
        ]
    );
    assert_eq!(
        conditions(&view, "placement"),
        [("kind".to_owned(), strings(&["http"]))]
    );
    assert!(conditions(&view, "name").is_empty());
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
        shares: Default::default(),
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

#[test]
fn a_requested_env_handle_offers_its_variables_and_commands_but_fills_no_value() {
    let requested = RequestedHandle {
        id: 4,
        client: Some("claude-code".into()),
        request: serde_json::from_str(
            r#"{"name":"demo-admin","kind":"env","description":"Demo admin API key",
                "env_vars":["DEMO_ADMIN_TOKEN","DEMO_URL"],"allowed_cmds":["python3"]}"#,
        )
        .unwrap(),
    };
    let form = forms::requested_handle(&requested);
    let view = forms::describe(&form);
    assert_eq!(view.focus.as_deref(), Some("vars"));
    // A row each, with the name in: the user types only the values.
    let vars = field(&view, "vars");
    assert_eq!(vars.kind, FieldKind::Pairs);
    assert_eq!(vars.suggested, ["DEMO_ADMIN_TOKEN", "DEMO_URL"]);
    assert_eq!(vars.value, "");
    // A program is offered, never allowed for the user.
    let cmds = field(&view, "cmds");
    assert_eq!(cmds.suggested, ["python3"]);
    assert_eq!(cmds.value, "", "nothing is allowed until the user picks it");
    // What the page sends with the names it drew and the value typed saves
    // those variables, and only the commands the user chose.
    let mut form = form;
    forms::fill(
        &mut form,
        &values(&[
            ("kind", "env"),
            ("name", "demo-admin"),
            ("description", "Demo admin API key"),
            (
                "vars",
                "DEMO_ADMIN_TOKEN=demo-value-1\nDEMO_URL=https://demo.example.test",
            ),
            ("cmds", ""),
            ("mode", "ask"),
        ]),
    )
    .unwrap();
    let Effect::Add(secret) = forms::submit(&Purpose::Add, &form).unwrap() else {
        panic!("not an add");
    };
    let SecretValue::Env { vars } = &secret.value else {
        panic!("not env: {:?}", secret.value.kind());
    };
    assert_eq!(
        vars.keys().collect::<Vec<_>>(),
        ["DEMO_ADMIN_TOKEN", "DEMO_URL"]
    );
    assert!(secret.policy.allowed_cmds.is_empty());
}

/// Every kind the new handle form offers is explained, in the order the
/// options come, and no other field carries explanations.
#[test]
fn every_kind_on_offer_is_explained() {
    let view = forms::describe(&forms::new_handle());
    let kind = field(&view, "kind");
    let explained: Vec<&str> = kind.explained.iter().map(|e| e.value.as_str()).collect();
    assert_eq!(explained, kind.options);
    for option in &kind.explained {
        assert!(
            !option.title.is_empty() && !option.detail.is_empty(),
            "{option:?}"
        );
    }
    assert!(kind.hint.contains("can't be changed"), "{}", kind.hint);
    for other in view.fields.iter().filter(|f| f.key != "kind") {
        assert!(other.explained.is_empty(), "{}", other.key);
    }
}

#[test]
fn a_form_without_suggestions_sends_none_to_the_page() {
    let view = forms::describe(&forms::new_handle());
    let json = serde_json::to_string(&view).unwrap();
    assert!(!json.contains("suggested"), "{json}");
}

/// The edit form of an env handle with demo variables A_TOKEN, B_URL and
/// C_KEY, and what the handle looks like to the form.
fn env_edit() -> (forms::Form, Purpose) {
    let secret = kv_core::secret::Secret {
        name: "demo-env".into(),
        description: "Demo env".into(),
        value: SecretValue::Env {
            vars: values(&[
                ("A_TOKEN", "demo-a-value"),
                ("B_URL", "https://demo.example.test"),
                ("C_KEY", "demo-c-value"),
            ]),
        },
        policy: kv_core::policy::Policy::default(),
        created_at: 0,
        updated_at: 0,
        from_share: None,
    };
    let info = secret.info();
    (forms::edit_handle(&info), Purpose::Edit(info))
}

/// An edit form names its handle, so the window can offer to show its
/// current value; other forms name none, and none carries a value.
#[test]
fn only_an_edit_form_names_its_handle() {
    let (form, _) = env_edit();
    let view = forms::describe(&form);
    assert_eq!(view.handle.as_deref(), Some("demo-env"));
    assert!(
        !serde_json::to_string(&view)
            .unwrap()
            .contains("demo-a-value")
    );

    let new = serde_json::to_string(&forms::describe(&forms::new_handle())).unwrap();
    assert!(!new.contains("\"handle\""), "{new}");
    let (_, Purpose::Edit(info)) = env_edit() else {
        panic!("not an edit");
    };
    assert_eq!(forms::describe(&forms::edit_policy(&info)).handle, None);
}

#[test]
fn editing_an_env_handle_shows_its_variables_by_name_only() {
    let (form, _) = env_edit();
    let view = forms::describe(&form);
    let vars = field(&view, "vars");
    assert_eq!(vars.existing, ["A_TOKEN", "B_URL", "C_KEY"]);
    // The window removes with each row's x, so it gets no Remove box.
    assert!(view.fields.iter().all(|f| f.key != "remove"), "{view:?}");
    let json = serde_json::to_string(&view).unwrap();
    for value in ["demo-a-value", "demo.example.test", "demo-c-value"] {
        assert!(!json.contains(value), "a value reached the form: {json}");
    }
}

#[test]
fn a_blank_row_keeps_a_variable_a_typed_one_replaces_it_and_a_missing_one_goes() {
    let (mut form, purpose) = env_edit();
    // A_TOKEN kept, B_URL changed, C_KEY's row taken out, D_NEW added.
    forms::fill(
        &mut form,
        &values(&[(
            "vars",
            "A_TOKEN=\nB_URL=https://new.example.test\nD_NEW=demo-d-value",
        )]),
    )
    .unwrap();
    let Effect::EditVars {
        name, set, remove, ..
    } = forms::submit(&purpose, &form).unwrap()
    else {
        panic!("not an edit of variables");
    };
    assert_eq!(name, "demo-env");
    assert_eq!(set.keys().collect::<Vec<_>>(), ["B_URL", "D_NEW"]);
    assert_eq!(set["B_URL"].expose(), "https://new.example.test");
    assert_eq!(remove, ["C_KEY"]);
}

#[test]
fn every_row_left_blank_changes_nothing() {
    let (mut form, purpose) = env_edit();
    forms::fill(&mut form, &values(&[("vars", "A_TOKEN=\nB_URL=\nC_KEY=")])).unwrap();
    assert_eq!(
        forms::submit(&purpose, &form).unwrap_err(),
        "nothing changed"
    );
}

#[test]
fn a_new_variable_needs_its_value() {
    let (mut form, _) = env_edit();
    let error = forms::fill(&mut form, &values(&[("vars", "A_TOKEN=\nD_NEW=")])).unwrap_err();
    assert!(error.contains("type a value for D_NEW"), "{error}");
    // As on a requested handle, where no name is one the handle has yet.
    let requested = RequestedHandle {
        id: 5,
        client: None,
        request: serde_json::from_str(
            r#"{"name":"demo-admin","kind":"env","env_vars":["DEMO_ADMIN_TOKEN"]}"#,
        )
        .unwrap(),
    };
    let mut form = forms::requested_handle(&requested);
    let error = forms::fill(&mut form, &values(&[("vars", "DEMO_ADMIN_TOKEN=")])).unwrap_err();
    assert!(
        error.contains("type a value for DEMO_ADMIN_TOKEN"),
        "{error}"
    );
}
