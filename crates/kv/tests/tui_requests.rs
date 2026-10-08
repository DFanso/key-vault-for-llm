//! Handle requests in `kv tui`: listed first on the handles tab, filled into
//! the New handle form, or dismissed. Pure `App` tests; `tui_session.rs`
//! runs them against a daemon.

use std::time::Duration;

use kv::tui::app::{App, Effect, Outcome};
use kv::tui::view;
use kv_core::policy::Mode;
use kv_core::proto::{HandleRequest, Overview, RequestedHandle, Status};
use kv_core::secret::{AuthPlacement, HandleInfo, SecretKind, SecretValue};
use ratatui::Terminal;
use ratatui::backend::TestBackend;
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

const TOKEN: &str = "dokploy-0123456789abcdef";

fn press(app: &mut App, code: KeyCode) -> Option<Effect> {
    app.handle_key(KeyEvent::new(code, KeyModifiers::NONE))
}

fn key(app: &mut App, c: char) -> Option<Effect> {
    press(app, KeyCode::Char(c))
}

fn screen(app: &App) -> String {
    screen_of_height(app, 30)
}

fn screen_of_height(app: &App, height: u16) -> String {
    let mut terminal = Terminal::new(TestBackend::new(100, height)).unwrap();
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

fn save(app: &mut App) -> Option<Effect> {
    for _ in 0..30 {
        if app.form().unwrap().focused().is_none() {
            return press(app, KeyCode::Enter);
        }
        press(app, KeyCode::Tab);
    }
    panic!("no save row");
}

fn dokploy() -> HandleRequest {
    HandleRequest {
        name: "dokploy".into(),
        kind: SecretKind::Http,
        description: "KYC dev Dokploy".into(),
        reason: "to list Dokploy projects".into(),
        auth: Some(AuthPlacement::Header {
            name: "x-api-key".into(),
            template: "{}".into(),
        }),
        base_url: true,
        allowed_hosts: vec!["dokploy.example.com".into()],
        env_vars: Vec::new(),
        allowed_cmds: Vec::new(),
    }
}

fn terraform() -> HandleRequest {
    HandleRequest {
        name: "aws".into(),
        kind: SecretKind::Env,
        description: "AWS for terraform".into(),
        reason: "to run terraform plan".into(),
        auth: None,
        base_url: false,
        allowed_hosts: Vec::new(),
        env_vars: vec!["AWS_ACCESS_KEY_ID".into(), "AWS_SECRET_ACCESS_KEY".into()],
        allowed_cmds: vec!["terraform".into()],
    }
}

fn handle(name: &str) -> HandleInfo {
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
        auth: None,
    }
}

fn overview(requests: Vec<HandleRequest>, handles: Vec<HandleInfo>) -> Overview {
    Overview {
        status: Status {
            vault_exists: true,
            locked: false,
            handle_count: Some(handles.len()),
            locks_in_secs: None,
            pending_approvals: 0,
        },
        handles,
        approvals: Vec::new(),
        handle_requests: requests
            .into_iter()
            .enumerate()
            .map(|(i, request)| RequestedHandle {
                id: i as u64 + 1,
                client: Some("claude-code".into()),
                request,
            })
            .collect(),
    }
}

/// Unlocked, on the handles tab.
fn app(requests: Vec<HandleRequest>, handles: Vec<HandleInfo>) -> App {
    let mut app = App::new();
    app.apply(Outcome::Opened);
    app.apply(Outcome::Overview(overview(requests, handles)));
    key(&mut app, '2');
    app
}

#[test]
fn requests_are_listed_first_with_who_asked_and_why() {
    let app = app(vec![dokploy()], vec![handle("openrouter")]);
    let shown = screen(&app);
    assert!(shown.contains("2 Handles (1 requested)"), "{shown}");
    assert!(shown.contains("1 requested"), "{shown}");
    let request = shown.find("dokploy").expect(&shown);
    let existing = shown.find("openrouter").expect(&shown);
    assert!(request < existing, "requests come first:\n{shown}");
    assert!(shown.contains("claude-code"), "{shown}");
    assert!(shown.contains("to list Dokploy projects"), "{shown}");
    assert!(shown.contains("Enter fill in"), "{shown}");
    assert!(shown.contains("x dismiss"), "{shown}");
}

#[test]
fn enter_fills_the_new_handle_form_and_only_the_token_is_left() {
    let mut app = app(vec![dokploy()], vec![handle("openrouter")]);
    assert!(press(&mut app, KeyCode::Enter).is_none());
    let form = app.form().expect("a form opened");
    assert_eq!(form.title(), "New handle");
    assert_eq!(form.chosen("kind"), "http");
    assert_eq!(form.text("name"), "dokploy");
    assert_eq!(form.text("description"), "KYC dev Dokploy");
    assert_eq!(form.chosen("placement"), "header");
    assert_eq!(form.text("header"), "x-api-key");
    assert_eq!(form.text("template"), "{}");
    assert_eq!(form.text("hosts"), "dokploy.example.com");
    assert_eq!(form.chosen("mode"), "ask");
    assert_eq!(form.focused(), Some("token"), "the secret is what is left");
    assert!(
        form.field("base_url").hint.contains("asked"),
        "{}",
        form.field("base_url").hint
    );

    for c in TOKEN.chars() {
        assert!(key(&mut app, c).is_none());
    }
    assert!(!screen(&app).contains(TOKEN), "the token is never drawn");
    let Some(Effect::Add(secret)) = save(&mut app) else {
        panic!("saving adds the handle: {:?}", app.message());
    };
    assert_eq!(secret.name, "dokploy");
    assert_eq!(secret.policy.mode, Mode::Ask);
    assert_eq!(secret.policy.allowed_hosts, ["dokploy.example.com"]);
    match secret.value {
        SecretValue::Http {
            token, placement, ..
        } => {
            assert_eq!(token.expose(), TOKEN);
            assert_eq!(
                placement,
                AuthPlacement::Header {
                    name: "x-api-key".into(),
                    template: "{}".into()
                }
            );
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_query_parameter_request_fills_the_query_field() {
    let request = HandleRequest {
        auth: Some(AuthPlacement::Query {
            param: "api_key".into(),
        }),
        ..dokploy()
    };
    let mut app = app(vec![request], Vec::new());
    key(&mut app, 'e');
    let form = app.form().expect("e opens the form too");
    assert_eq!(form.chosen("placement"), "query");
    assert_eq!(form.text("param"), "api_key");
}

#[test]
fn an_env_request_names_the_variables_to_add() {
    let mut app = app(vec![terraform()], Vec::new());
    press(&mut app, KeyCode::Enter);
    let form = app.form().unwrap();
    assert_eq!(form.chosen("kind"), "env");
    assert_eq!(form.text("cmds"), "", "the user names the programs");
    assert!(
        form.field("cmds").hint.contains("terraform"),
        "{}",
        form.field("cmds").hint
    );
    assert_eq!(form.focused(), Some("vars"));
    let hint = &form.field("vars").hint;
    assert!(
        hint.contains("AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY"),
        "{hint}"
    );
}

#[test]
fn x_dismisses_a_request_but_asks_before_removing_a_handle() {
    let mut app = app(vec![dokploy(), terraform()], vec![handle("openrouter")]);
    press(&mut app, KeyCode::Down);
    assert_eq!(key(&mut app, 'x'), Some(Effect::Dismiss(2)));

    press(&mut app, KeyCode::Down);
    assert_eq!(key(&mut app, 'x'), None);
    assert_eq!(app.removing(), Some("openrouter"));
}

#[test]
fn below_the_requests_the_keys_act_on_handles() {
    let mut app = app(vec![dokploy()], vec![handle("openrouter")]);
    press(&mut app, KeyCode::Down);
    key(&mut app, 'e');
    assert_eq!(app.form().unwrap().title(), "Edit openrouter");
    press(&mut app, KeyCode::Esc);
    assert!(
        screen(&app).contains("p policy"),
        "a handle's keys are offered"
    );
}

#[test]
fn the_selection_stays_on_the_list_when_requests_go() {
    let mut app = app(vec![dokploy(), terraform()], vec![handle("openrouter")]);
    for _ in 0..5 {
        press(&mut app, KeyCode::Down);
    }
    app.apply(Outcome::Overview(overview(
        Vec::new(),
        vec![handle("openrouter")],
    )));
    key(&mut app, 'e');
    assert_eq!(app.form().unwrap().title(), "Edit openrouter");
}

#[test]
fn a_new_request_does_not_move_the_cursor_off_a_handle() {
    let mut app = app(Vec::new(), vec![handle("alpha"), handle("beta")]);
    press(&mut app, KeyCode::Down);
    app.apply(Outcome::Overview(overview(
        vec![dokploy()],
        vec![handle("alpha"), handle("beta")],
    )));
    key(&mut app, 'e');
    assert_eq!(app.form().unwrap().title(), "Edit beta");
}

#[test]
fn a_long_form_scrolls_to_the_focused_field() {
    let mut request = dokploy();
    // The most a request may carry: 4 hosts of up to 253 characters.
    request.allowed_hosts = (0..3)
        .map(|i| format!("api-{i}.{}.example.com", "a".repeat(230)))
        .chain(["evil.example".to_owned()])
        .collect();
    let mut app = app(vec![request], Vec::new());
    press(&mut app, KeyCode::Enter);
    while app.form().unwrap().focused() != Some("hosts") {
        press(&mut app, KeyCode::Tab);
    }
    let shown = screen_of_height(&app, 20);
    assert!(shown.contains("evil.example"), "{shown}");
    while app.form().unwrap().focused().is_some() {
        press(&mut app, KeyCode::Tab);
    }
    let shown = screen_of_height(&app, 20);
    assert!(shown.contains(" Save "), "{shown}");
}

#[test]
fn the_handles_list_scrolls_to_the_selected_row() {
    let requests: Vec<HandleRequest> = (0..16)
        .map(|i| HandleRequest {
            name: format!("svc-{i:02}"),
            ..dokploy()
        })
        .collect();
    let mut app = app(requests, vec![handle("openrouter")]);
    for _ in 0..16 {
        press(&mut app, KeyCode::Down);
    }
    assert!(screen(&app).contains("▶ openrouter"), "{}", screen(&app));
    for _ in 0..2 {
        press(&mut app, KeyCode::Up);
    }
    assert!(screen(&app).contains("▶ svc-14"), "{}", screen(&app));
}
