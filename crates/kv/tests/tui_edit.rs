//! Editing handles in `kv tui`: the forms for a new handle, a new
//! description or value, a policy, and removing a handle. Pure `App` tests;
//! `tui_session.rs` runs the same keys against a daemon.

use std::time::Duration;

use kv::tui::app::{App, Effect, Outcome};
use kv::tui::view;
use kv_core::policy::Mode;
use kv_core::proto::{Overview, PolicyPatch, Status};
use kv_core::secret::{AuthPlacement, HandleInfo, SecretKind, SecretText, SecretValue};
use ratatui::Terminal;
use ratatui::backend::TestBackend;
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

const TOKEN: &str = "sk-or-v1-0123456789abcdef";
const AWS_KEY: &str = "AKIAEXAMPLEKEY0123456";

fn press(app: &mut App, code: KeyCode) -> Option<Effect> {
    app.handle_key(KeyEvent::new(code, KeyModifiers::NONE))
}

fn key(app: &mut App, c: char) -> Option<Effect> {
    press(app, KeyCode::Char(c))
}

fn type_text(app: &mut App, text: &str) {
    for c in text.chars() {
        assert!(key(app, c).is_none(), "typing {c:?} did something");
    }
}

fn screen(app: &App) -> String {
    let mut terminal = Terminal::new(TestBackend::new(100, 40)).unwrap();
    terminal.draw(|frame| view::draw(frame, app)).unwrap();
    let buffer = terminal.backend().buffer();
    let width = buffer.area.width as usize;
    buffer
        .content
        .chunks(width)
        .map(|row| row.iter().map(|cell| cell.symbol()).collect::<String>())
        .collect::<Vec<_>>()
        .join("\n")
}

/// Moves the focus to the field with this key.
fn focus(app: &mut App, field: &str) {
    for _ in 0..30 {
        if app.form().unwrap().focused() == Some(field) {
            return;
        }
        press(app, KeyCode::Tab);
    }
    panic!("no field {field:?} in\n{}", screen(app));
}

/// Moves to the Save row and presses Enter.
fn save(app: &mut App) -> Option<Effect> {
    for _ in 0..30 {
        if app.form().unwrap().focused().is_none() {
            return press(app, KeyCode::Enter);
        }
        press(app, KeyCode::Tab);
    }
    panic!("no save row");
}

fn clear(app: &mut App) {
    for _ in 0..80 {
        press(app, KeyCode::Backspace);
    }
}

fn http_handle(name: &str) -> HandleInfo {
    HandleInfo {
        name: name.into(),
        kind: SecretKind::Http,
        description: "OpenRouter API".into(),
        mode: Mode::Ask,
        allowed_hosts: vec!["openrouter.ai".into()],
        allow_plain_http: false,
        allowed_methods: Vec::new(),
        read_only: false,
        allowed_cmds: Vec::new(),
        grant_ttl: Duration::from_secs(900),
        env_vars: Vec::new(),
        takes_path: false,
        auth: Some(AuthPlacement::Header {
            name: "Authorization".into(),
            template: "Bearer {}".into(),
        }),
    }
}

fn env_handle(name: &str) -> HandleInfo {
    HandleInfo {
        kind: SecretKind::Env,
        description: String::new(),
        allowed_hosts: Vec::new(),
        allowed_cmds: vec!["terraform".into()],
        env_vars: vec!["AWS_SECRET_ACCESS_KEY".into()],
        auth: None,
        ..http_handle(name)
    }
}

/// Unlocked, on the handles tab.
fn handles(handles: Vec<HandleInfo>) -> App {
    let mut app = App::new();
    app.apply(Outcome::Opened);
    app.apply(Outcome::Overview(Overview {
        status: Status {
            vault_exists: true,
            locked: false,
            handle_count: Some(handles.len()),
            locks_in_secs: Some(8 * 3600),
            pending_approvals: 0,
        },
        handles,
        approvals: Vec::new(),
        handle_requests: Vec::new(),
    }));
    key(&mut app, '2');
    app
}

fn added(effect: Option<Effect>) -> kv_core::secret::Secret {
    match effect {
        Some(Effect::Add(secret)) => secret,
        other => panic!("expected an add, got {other:?}"),
    }
}

#[test]
fn a_new_http_handle_never_shows_its_token() {
    let mut app = handles(Vec::new());
    assert!(key(&mut app, 'n').is_none());
    assert!(screen(&app).contains("New handle"), "{}", screen(&app));
    assert_eq!(app.form().unwrap().focused(), Some("kind"));
    focus(&mut app, "name");
    type_text(&mut app, "openrouter");
    focus(&mut app, "description");
    type_text(&mut app, "Models");
    focus(&mut app, "token");
    type_text(&mut app, TOKEN);
    focus(&mut app, "hosts");
    type_text(&mut app, "openrouter.ai, api.openrouter.ai");
    let drawn = screen(&app);
    assert!(!drawn.contains("0123456789"), "{drawn}");
    assert!(drawn.contains("Token"), "{drawn}");

    let secret = added(save(&mut app));
    assert_eq!(secret.name, "openrouter");
    assert_eq!(secret.description, "Models");
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
    assert_eq!(
        secret.policy.allowed_hosts,
        ["openrouter.ai", "api.openrouter.ai"]
    );
    assert_eq!(secret.policy.mode, Mode::Ask);
}

#[test]
fn a_query_token_hides_the_header_fields() {
    let mut app = handles(Vec::new());
    key(&mut app, 'n');
    focus(&mut app, "name");
    type_text(&mut app, "maps");
    focus(&mut app, "token");
    type_text(&mut app, TOKEN);
    focus(&mut app, "placement");
    press(&mut app, KeyCode::Right);
    assert!(!screen(&app).contains("Header name"), "{}", screen(&app));
    focus(&mut app, "param");
    type_text(&mut app, "key");
    focus(&mut app, "base_url");
    type_text(&mut app, "https://maps.example.com/v1");
    let secret = added(save(&mut app));
    assert_eq!(
        secret.value,
        SecretValue::Http {
            token: SecretText::new(TOKEN),
            placement: AuthPlacement::Query {
                param: "key".into()
            },
            base_url: Some("https://maps.example.com/v1".into()),
        }
    );
}

#[test]
fn an_env_handle_collects_variables_without_showing_values() {
    let mut app = handles(Vec::new());
    key(&mut app, 'n');
    press(&mut app, KeyCode::Right);
    focus(&mut app, "name");
    type_text(&mut app, "aws");
    focus(&mut app, "vars");
    type_text(&mut app, &format!("AWS_SECRET_ACCESS_KEY={AWS_KEY}"));
    assert!(press(&mut app, KeyCode::Enter).is_none());
    assert_eq!(
        app.form().unwrap().focused(),
        Some("vars"),
        "Enter adds, stays"
    );
    let drawn = screen(&app);
    assert!(drawn.contains("AWS_SECRET_ACCESS_KEY"), "{drawn}");
    assert!(!drawn.contains("EXAMPLE"), "{drawn}");

    type_text(&mut app, "NO_EQUALS");
    press(&mut app, KeyCode::Enter);
    assert!(app.message().unwrap().contains("NAME=value"));
    for _ in 0.."NO_EQUALS".len() {
        press(&mut app, KeyCode::Backspace);
    }
    focus(&mut app, "cmds");
    type_text(&mut app, "terraform, aws");
    focus(&mut app, "mode");
    press(&mut app, KeyCode::Right);

    let secret = added(save(&mut app));
    match &secret.value {
        SecretValue::Env { vars } => {
            assert_eq!(vars.len(), 1, "{vars:?}");
            assert_eq!(vars["AWS_SECRET_ACCESS_KEY"].expose(), AWS_KEY);
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(secret.policy.allowed_cmds, ["terraform", "aws"]);
    assert_eq!(secret.policy.mode, Mode::Auto);
}

#[test]
fn backspace_on_an_empty_variable_input_drops_the_last_variable() {
    let mut app = handles(Vec::new());
    key(&mut app, 'n');
    press(&mut app, KeyCode::Right);
    focus(&mut app, "name");
    type_text(&mut app, "aws");
    focus(&mut app, "vars");
    type_text(&mut app, "A=first-value");
    press(&mut app, KeyCode::Enter);
    type_text(&mut app, "B=second-value");
    press(&mut app, KeyCode::Enter);
    press(&mut app, KeyCode::Backspace);
    assert!(!screen(&app).contains(" B"), "{}", screen(&app));
    match added(save(&mut app)).value {
        SecretValue::Env { vars } => assert_eq!(vars.keys().collect::<Vec<_>>(), ["A"]),
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_new_postgres_handle_takes_a_url() {
    let mut app = handles(Vec::new());
    key(&mut app, 'n');
    press(&mut app, KeyCode::Right);
    press(&mut app, KeyCode::Right);
    focus(&mut app, "name");
    type_text(&mut app, "db");
    focus(&mut app, "url");
    type_text(&mut app, "postgres://app:hunter2hunter2@db/app");
    assert!(!screen(&app).contains("hunter2"));
    assert_eq!(
        added(save(&mut app)).value,
        SecretValue::Postgres {
            url: SecretText::new("postgres://app:hunter2hunter2@db/app")
        }
    );
}

#[test]
fn missing_fields_are_named_and_the_form_stays_open() {
    let mut app = handles(Vec::new());
    key(&mut app, 'n');
    assert!(save(&mut app).is_none());
    assert!(
        app.message().unwrap().contains("name"),
        "{:?}",
        app.message()
    );
    focus(&mut app, "name");
    type_text(&mut app, "api");
    assert!(save(&mut app).is_none());
    assert!(
        app.message().unwrap().contains("token"),
        "{:?}",
        app.message()
    );
    assert!(app.form().is_some());
}

#[test]
fn keys_in_a_form_are_text_and_esc_cancels() {
    let mut app = handles(Vec::new());
    key(&mut app, 'n');
    focus(&mut app, "name");
    type_text(&mut app, "qL12");
    assert!(screen(&app).contains("qL12"));
    assert!(press(&mut app, KeyCode::Esc).is_none());
    assert!(app.form().is_none());
    assert_eq!(key(&mut app, 'q'), Some(Effect::Quit));
}

#[test]
fn a_failed_save_keeps_the_form_and_done_closes_it() {
    let mut app = handles(Vec::new());
    key(&mut app, 'n');
    focus(&mut app, "name");
    type_text(&mut app, "api");
    focus(&mut app, "token");
    type_text(&mut app, TOKEN);
    added(save(&mut app));
    app.apply(Outcome::Failed("api already exists".into()));
    assert!(app.form().is_some());
    assert!(screen(&app).contains("api already exists"));
    added(save(&mut app));
    app.apply(Outcome::Done(Vec::new()));
    assert!(app.form().is_none());
}

#[test]
fn a_new_description_alone_is_an_update_without_a_value() {
    let mut app = handles(vec![http_handle("openrouter")]);
    key(&mut app, 'e');
    assert!(screen(&app).contains("Edit openrouter"), "{}", screen(&app));
    focus(&mut app, "description");
    for _ in 0.."API".len() {
        press(&mut app, KeyCode::Backspace);
    }
    type_text(&mut app, "keys");
    assert_eq!(
        save(&mut app),
        Some(Effect::Update {
            name: "openrouter".into(),
            description: Some("OpenRouter keys".into()),
            value: None,
        })
    );
}

#[test]
fn a_new_token_keeps_where_it_goes() {
    let mut app = handles(vec![http_handle("openrouter")]);
    key(&mut app, 'e');
    focus(&mut app, "token");
    type_text(&mut app, "sk-or-v1-new-token-0123");
    assert_eq!(
        save(&mut app),
        Some(Effect::Update {
            name: "openrouter".into(),
            description: None,
            value: Some(SecretValue::Http {
                token: SecretText::new("sk-or-v1-new-token-0123"),
                placement: AuthPlacement::Header {
                    name: "Authorization".into(),
                    template: "Bearer {}".into(),
                },
                base_url: None,
            }),
        })
    );
}

#[test]
fn moving_the_token_needs_the_token_again() {
    let mut app = handles(vec![http_handle("openrouter")]);
    key(&mut app, 'e');
    focus(&mut app, "placement");
    press(&mut app, KeyCode::Right);
    focus(&mut app, "param");
    type_text(&mut app, "key");
    assert!(save(&mut app).is_none());
    assert!(
        app.message().unwrap().contains("token"),
        "{:?}",
        app.message()
    );
}

#[test]
fn saving_an_unchanged_edit_does_nothing() {
    let mut app = handles(vec![http_handle("openrouter")]);
    key(&mut app, 'e');
    assert!(save(&mut app).is_none());
    assert!(
        app.message().unwrap().contains("nothing"),
        "{:?}",
        app.message()
    );
}

#[test]
fn new_variables_replace_an_env_handles_variables() {
    let mut app = handles(vec![env_handle("aws")]);
    key(&mut app, 'e');
    assert!(
        screen(&app).contains("AWS_SECRET_ACCESS_KEY"),
        "current names are shown"
    );
    focus(&mut app, "vars");
    type_text(&mut app, &format!("AWS_ACCESS_KEY_ID={AWS_KEY}"));
    press(&mut app, KeyCode::Enter);
    match save(&mut app) {
        Some(Effect::Update {
            value: Some(SecretValue::Env { vars }),
            description: None,
            ..
        }) => assert_eq!(vars.keys().collect::<Vec<_>>(), ["AWS_ACCESS_KEY_ID"]),
        other => panic!("{other:?}"),
    }
}

#[test]
fn the_policy_form_sends_only_what_changed() {
    let mut app = handles(vec![http_handle("openrouter")]);
    key(&mut app, 'p');
    assert!(
        screen(&app).contains("Policy for openrouter"),
        "{}",
        screen(&app)
    );
    focus(&mut app, "mode");
    press(&mut app, KeyCode::Right);
    focus(&mut app, "grant_ttl");
    clear(&mut app);
    type_text(&mut app, "1h");
    assert_eq!(
        save(&mut app),
        Some(Effect::SetPolicy {
            name: "openrouter".into(),
            patch: PolicyPatch {
                mode: Some(Mode::Auto),
                grant_ttl: Some(Duration::from_secs(3600)),
                ..PolicyPatch::default()
            },
        })
    );
}

#[test]
fn the_policy_form_reads_lists_and_switches() {
    let mut app = handles(vec![http_handle("openrouter")]);
    key(&mut app, 'p');
    focus(&mut app, "hosts");
    type_text(&mut app, ", api.openrouter.ai");
    focus(&mut app, "plain_http");
    press(&mut app, KeyCode::Right);
    focus(&mut app, "methods");
    type_text(&mut app, "get, post");
    assert_eq!(
        save(&mut app),
        Some(Effect::SetPolicy {
            name: "openrouter".into(),
            patch: PolicyPatch {
                allowed_hosts: Some(vec!["openrouter.ai".into(), "api.openrouter.ai".into()]),
                allow_plain_http: Some(true),
                allowed_methods: Some(vec!["GET".into(), "POST".into()]),
                ..PolicyPatch::default()
            },
        })
    );
}

#[test]
fn a_bad_grant_ttl_is_named() {
    let mut app = handles(vec![http_handle("openrouter")]);
    key(&mut app, 'p');
    focus(&mut app, "grant_ttl");
    clear(&mut app);
    type_text(&mut app, "soon");
    assert!(save(&mut app).is_none());
    assert!(
        app.message().unwrap().contains("grant"),
        "{:?}",
        app.message()
    );
}

#[test]
fn a_database_policy_form_has_read_only() {
    let mut app = handles(vec![HandleInfo {
        kind: SecretKind::Postgres,
        auth: None,
        ..http_handle("db")
    }]);
    key(&mut app, 'p');
    focus(&mut app, "read_only");
    press(&mut app, KeyCode::Right);
    assert_eq!(
        save(&mut app),
        Some(Effect::SetPolicy {
            name: "db".into(),
            patch: PolicyPatch {
                read_only: Some(true),
                ..PolicyPatch::default()
            },
        })
    );
}

#[test]
fn an_env_policy_form_has_commands_not_hosts() {
    let mut app = handles(vec![env_handle("aws")]);
    key(&mut app, 'p');
    let drawn = screen(&app);
    assert!(drawn.contains("Allowed commands"), "{drawn}");
    assert!(!drawn.contains("Allowed hosts"), "{drawn}");
}

#[test]
fn removing_asks_first_and_acts_on_the_selected_handle() {
    let mut app = handles(vec![http_handle("openrouter"), env_handle("aws")]);
    assert!(key(&mut app, 'x').is_none());
    assert!(
        screen(&app).contains("Remove openrouter?"),
        "{}",
        screen(&app)
    );
    assert!(key(&mut app, 'n').is_none());
    assert!(!screen(&app).contains("Remove openrouter?"));
    press(&mut app, KeyCode::Down);
    key(&mut app, 'x');
    assert_eq!(key(&mut app, 'y'), Some(Effect::Remove("aws".into())));
}

#[test]
fn edit_keys_need_a_handle_and_the_handles_tab() {
    let mut app = handles(Vec::new());
    assert!(key(&mut app, 'e').is_none());
    assert!(key(&mut app, 'x').is_none());
    assert!(app.form().is_none());
    let mut app = handles(vec![http_handle("openrouter")]);
    key(&mut app, '1');
    key(&mut app, 'n');
    assert!(app.form().is_none(), "n does nothing on the approvals tab");
}

#[test]
fn an_ended_session_closes_the_form() {
    let mut app = handles(Vec::new());
    key(&mut app, 'n');
    focus(&mut app, "token");
    type_text(&mut app, TOKEN);
    app.apply(Outcome::Ended("the vault locked".into()));
    assert!(app.form().is_none());
}

#[test]
fn a_value_pasted_before_its_name_is_not_shown() {
    let mut app = handles(Vec::new());
    key(&mut app, 'n');
    press(&mut app, KeyCode::Right);
    focus(&mut app, "vars");
    type_text(&mut app, AWS_KEY);
    assert!(!screen(&app).contains("EXAMPLE"), "{}", screen(&app));
}

#[test]
fn a_multi_line_paste_stays_in_the_hidden_field() {
    let mut app = handles(Vec::new());
    key(&mut app, 'n');
    focus(&mut app, "name");
    type_text(&mut app, "api");
    focus(&mut app, "token");
    app.paste("  line1\nline2\r\nSECRETVALUE \n");
    assert_eq!(app.form().unwrap().focused(), Some("token"));
    let drawn = screen(&app);
    assert!(
        !drawn.contains("SECRET") && !drawn.contains("line2"),
        "{drawn}"
    );
    match added(save(&mut app)).value {
        SecretValue::Http { token, .. } => assert_eq!(token.expose(), "line1line2SECRETVALUE"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn enter_never_leaves_a_hidden_field() {
    // Without bracketed paste a pasted newline arrives as Enter; moving on
    // would put the rest of the secret in the next, visible field.
    let mut app = handles(Vec::new());
    key(&mut app, 'n');
    focus(&mut app, "token");
    type_text(&mut app, "part-one");
    press(&mut app, KeyCode::Enter);
    type_text(&mut app, "part-two");
    assert_eq!(app.form().unwrap().focused(), Some("token"));
    assert!(!screen(&app).contains("part"), "{}", screen(&app));
}

#[test]
fn a_pasted_env_block_becomes_variables() {
    let mut app = handles(Vec::new());
    key(&mut app, 'n');
    press(&mut app, KeyCode::Right);
    focus(&mut app, "name");
    type_text(&mut app, "svc");
    focus(&mut app, "vars");
    app.paste("A_KEY=first-value\nB_KEY=second-value\n");
    let drawn = screen(&app);
    assert!(drawn.contains("A_KEY, B_KEY"), "{drawn}");
    assert!(
        !drawn.contains("first") && !drawn.contains("second"),
        "{drawn}"
    );
    match added(save(&mut app)).value {
        SecretValue::Env { vars } => {
            assert_eq!(vars["A_KEY"].expose(), "first-value");
            assert_eq!(vars["B_KEY"].expose(), "second-value");
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_value_with_equals_signs_typed_first_is_not_shown() {
    let mut app = handles(Vec::new());
    key(&mut app, 'n');
    press(&mut app, KeyCode::Right);
    focus(&mut app, "vars");
    for secret in [
        "postgres://app:pw-hunter2@db/app?sslmode=require",
        "c2Vj+cmV0/dmFs==",
    ] {
        type_text(&mut app, secret);
        let drawn = screen(&app);
        assert!(
            !drawn.contains("hunter2") && !drawn.contains("c2Vj"),
            "{drawn}"
        );
        press(&mut app, KeyCode::Enter);
        assert!(
            app.message().unwrap().contains("NAME=value"),
            "{:?}",
            app.message()
        );
        assert!(!screen(&app).contains("hunter2"), "{}", screen(&app));
        for _ in 0..secret.chars().count() {
            press(&mut app, KeyCode::Backspace);
        }
    }
}
