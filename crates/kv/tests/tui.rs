//! `kv tui` without a terminal or a daemon: keys go into `App`, replies
//! from the daemon are applied to it, and the screen is drawn into a
//! `TestBackend` buffer.

use std::time::Duration;

use kv::tui::app::{App, Effect, Outcome, Screen, Tab};
use kv::tui::view;
use kv_core::policy::Mode;
use kv_core::proto::{Approval, Overview, Status, Verdict};
use kv_core::secret::{HandleInfo, SecretKind};
use ratatui::Terminal;
use ratatui::backend::TestBackend;
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

const PASS: &str = "correct horse battery";

fn press(app: &mut App, code: KeyCode) -> Option<Effect> {
    app.handle_key(KeyEvent::new(code, KeyModifiers::NONE))
}

fn key(app: &mut App, c: char) -> Option<Effect> {
    press(app, KeyCode::Char(c))
}

fn type_text(app: &mut App, text: &str) {
    for c in text.chars() {
        assert!(key(app, c).is_none());
    }
}

fn screen(app: &App) -> String {
    let mut terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();
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

fn handle(name: &str, mode: Mode) -> HandleInfo {
    HandleInfo {
        name: name.into(),
        kind: SecretKind::Http,
        description: "OpenRouter API".into(),
        mode,
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

fn approval(id: u64, can_grant: bool) -> Approval {
    Approval {
        id,
        client: Some("claude-code".into()),
        tool: "http_request".into(),
        handles: vec!["openrouter".into()],
        detail: format!("GET https://openrouter.ai/api/v1/models?page={id}"),
        cwd: None,
        can_grant,
        expires_in_secs: 42,
    }
}

fn overview(approvals: Vec<Approval>) -> Overview {
    Overview {
        status: Status {
            vault_exists: true,
            locked: false,
            handle_count: Some(1),
            locks_in_secs: Some(8 * 3600),
            pending_approvals: approvals.len(),
            devices: Vec::new(),
        },
        handles: vec![handle("openrouter", Mode::Ask)],
        approvals,
        handle_requests: Vec::new(),
        role_warnings: Default::default(),
    }
}

fn unlocked(approvals: Vec<Approval>) -> App {
    let mut app = App::new();
    app.apply(Outcome::Opened);
    app.apply(Outcome::Overview(overview(approvals)));
    app
}

#[test]
fn the_passphrase_is_never_drawn_and_enter_sends_it() {
    let mut app = App::new();
    assert_eq!(app.screen(), Screen::Unlock);
    type_text(&mut app, PASS);
    let drawn = screen(&app);
    assert!(!drawn.contains("horse"), "{drawn}");
    assert!(drawn.contains("Passphrase"), "{drawn}");
    match press(&mut app, KeyCode::Enter) {
        Some(Effect::OpenSession(passphrase)) => assert_eq!(passphrase.expose(), PASS),
        other => panic!("{other:?}"),
    }
    // A second Enter sends an empty passphrase, not the old one.
    match press(&mut app, KeyCode::Enter) {
        Some(Effect::OpenSession(passphrase)) => assert_eq!(passphrase.expose(), ""),
        other => panic!("{other:?}"),
    }
}

#[test]
fn backspace_edits_the_passphrase() {
    let mut app = App::new();
    type_text(&mut app, "abcx");
    press(&mut app, KeyCode::Backspace);
    match press(&mut app, KeyCode::Enter) {
        Some(Effect::OpenSession(passphrase)) => assert_eq!(passphrase.expose(), "abc"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_failed_unlock_says_why_and_stays_on_the_unlock_screen() {
    let mut app = App::new();
    type_text(&mut app, "wrong");
    press(&mut app, KeyCode::Enter);
    app.apply(Outcome::Failed("wrong passphrase".into()));
    assert_eq!(app.screen(), Screen::Unlock);
    assert!(screen(&app).contains("wrong passphrase"));
}

#[test]
fn a_waiting_request_shows_who_asks_and_what() {
    let mut app = unlocked(vec![approval(7, true)]);
    assert_eq!(app.screen(), Screen::Main);
    assert_eq!(app.tab(), Tab::Approvals);
    let drawn = screen(&app);
    for expected in [
        "claude-code (self-reported)",
        "http_request",
        "openrouter",
        "GET https://openrouter.ai/api/v1/models?page=7",
        "42s",
        "a allow once",
        "s allow for session",
        "d deny",
        "D deny always",
    ] {
        assert!(drawn.contains(expected), "missing {expected:?} in\n{drawn}");
    }
    assert_eq!(
        key(&mut app, 'a'),
        Some(Effect::Decide {
            id: 7,
            verdict: Verdict::AllowOnce
        })
    );
}

#[test]
fn decision_keys_act_on_the_selected_request() {
    let mut app = unlocked(vec![approval(1, true), approval(2, true)]);
    press(&mut app, KeyCode::Down);
    let decide = |verdict| Some(Effect::Decide { id: 2, verdict });
    assert_eq!(key(&mut app, 's'), decide(Verdict::AllowSession));
    assert_eq!(key(&mut app, 'd'), decide(Verdict::Deny));
    assert_eq!(key(&mut app, 'D'), decide(Verdict::DenyAlways));
    press(&mut app, KeyCode::Up);
    assert_eq!(
        key(&mut app, 'a'),
        Some(Effect::Decide {
            id: 1,
            verdict: Verdict::AllowOnce
        })
    );
}

#[test]
fn allow_for_session_needs_a_named_session() {
    let mut app = unlocked(vec![approval(3, false)]);
    assert!(!screen(&app).contains("s allow for session"));
    assert_eq!(key(&mut app, 's'), None);
    assert!(app.message().unwrap().contains("session"));
}

#[test]
fn no_waiting_requests_means_no_decisions() {
    let mut app = unlocked(Vec::new());
    assert_eq!(key(&mut app, 'a'), None);
    assert!(screen(&app).contains("Nothing is waiting"));
}

#[test]
fn the_handles_tab_lists_handles_and_waiting_requests_stay_visible() {
    let mut app = unlocked(vec![approval(1, true)]);
    key(&mut app, '2');
    assert_eq!(app.tab(), Tab::Handles);
    let drawn = screen(&app);
    assert!(drawn.contains("openrouter"), "{drawn}");
    assert!(drawn.contains("ask"), "{drawn}");
    assert!(drawn.contains("1 waiting"), "{drawn}");
    // Decision keys do nothing outside the approvals tab.
    assert_eq!(key(&mut app, 'a'), None);
    key(&mut app, '1');
    assert_eq!(app.tab(), Tab::Approvals);
}

#[test]
fn l_locks_and_q_quits() {
    let mut app = unlocked(Vec::new());
    assert_eq!(key(&mut app, 'L'), Some(Effect::Lock));
    assert_eq!(app.screen(), Screen::Unlock);
    let mut app = unlocked(Vec::new());
    assert_eq!(key(&mut app, 'q'), Some(Effect::Quit));
    let mut app = App::new();
    let ctrl_c = KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL);
    assert_eq!(app.handle_key(ctrl_c), Some(Effect::Quit));
    assert_eq!(press(&mut app, KeyCode::Esc), Some(Effect::Quit));
}

#[test]
fn an_ended_session_goes_back_to_unlock_and_says_why() {
    let mut app = unlocked(vec![approval(1, true)]);
    app.apply(Outcome::Ended("the vault locked".into()));
    assert_eq!(app.screen(), Screen::Unlock);
    let drawn = screen(&app);
    assert!(drawn.contains("the vault locked"), "{drawn}");
    assert!(!drawn.contains("claude-code"), "{drawn}");
}

#[test]
fn warnings_from_the_daemon_are_shown() {
    let mut app = unlocked(Vec::new());
    app.apply(Outcome::Done(vec!["openrouter: token is short".into()]));
    assert!(screen(&app).contains("token is short"));
}

fn overview_of(approvals: Vec<Approval>) -> Outcome {
    Outcome::Overview(overview(approvals))
}

#[test]
fn decisions_follow_the_request_not_its_place_in_the_list() {
    let mut app = unlocked(vec![
        approval(1, true),
        approval(2, true),
        approval(3, true),
    ]);
    press(&mut app, KeyCode::Down);
    app.apply(overview_of(vec![approval(2, true), approval(3, true)]));
    assert_eq!(
        key(&mut app, 'a'),
        Some(Effect::Decide {
            id: 2,
            verdict: Verdict::AllowOnce
        })
    );
}

#[test]
fn when_the_selected_request_goes_nothing_is_selected() {
    let mut app = unlocked(vec![
        approval(1, true),
        approval(2, true),
        approval(3, true),
    ]);
    press(&mut app, KeyCode::Down);
    app.apply(overview_of(vec![approval(1, true), approval(3, true)]));
    assert_eq!(key(&mut app, 'a'), None);
    assert!(
        app.message().unwrap().contains("no longer waiting"),
        "{:?}",
        app.message()
    );
    assert!(!screen(&app).contains("a allow once"), "{}", screen(&app));
    press(&mut app, KeyCode::Down);
    assert_eq!(
        key(&mut app, 'a'),
        Some(Effect::Decide {
            id: 1,
            verdict: Verdict::AllowOnce
        })
    );
}

#[test]
fn the_selected_request_is_numbered_and_stays_in_view() {
    let mut app = unlocked((1..=10).map(|id| approval(id, true)).collect());
    for _ in 0..9 {
        press(&mut app, KeyCode::Down);
    }
    let drawn = screen(&app);
    assert!(drawn.contains("page=10"), "{drawn}");
    assert!(drawn.contains("#10"), "{drawn}");
}

#[test]
fn control_and_alt_letters_are_not_commands() {
    let mut app = unlocked(vec![approval(7, true)]);
    for (c, modifiers) in [
        ('a', KeyModifiers::CONTROL),
        ('s', KeyModifiers::CONTROL),
        ('d', KeyModifiers::ALT),
        ('q', KeyModifiers::ALT),
    ] {
        assert_eq!(
            app.handle_key(KeyEvent::new(KeyCode::Char(c), modifiers)),
            None
        );
    }
    let mut app = App::new();
    app.handle_key(KeyEvent::new(KeyCode::Char('x'), KeyModifiers::CONTROL));
    match press(&mut app, KeyCode::Enter) {
        Some(Effect::OpenSession(passphrase)) => assert_eq!(passphrase.expose(), ""),
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_paste_is_not_a_string_of_commands() {
    let mut app = unlocked(vec![approval(7, true)]);
    app.paste("sk-abcDq2");
    assert_eq!(app.screen(), Screen::Main);
    assert_eq!(app.tab(), Tab::Approvals, "a pasted 2 is not a tab switch");
    key(&mut app, '2');
    app.paste("exn");
    assert!(app.form().is_none() && app.removing().is_none());
    key(&mut app, '1');
    assert!(app.message().is_none(), "{:?}", app.message());
    assert_eq!(
        key(&mut app, 'a'),
        Some(Effect::Decide {
            id: 7,
            verdict: Verdict::AllowOnce
        })
    );
}

#[test]
fn a_pasted_passphrase_is_one_input() {
    let mut app = App::new();
    app.paste("pass word\n");
    assert!(!screen(&app).contains("pass"), "{}", screen(&app));
    match press(&mut app, KeyCode::Enter) {
        Some(Effect::OpenSession(passphrase)) => assert_eq!(passphrase.expose(), "pass word"),
        other => panic!("{other:?}"),
    }
}
