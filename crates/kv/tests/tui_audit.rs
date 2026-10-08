//! The audit tab: `kv tui` reads the end of the audit log itself, newest
//! first, and shows what agents did and how each request was decided.

use std::fs;
use std::io::Write;
use std::time::Duration;

use kv::audit::{self, Audit, Use};
use kv::tui::app::{App, Outcome, Tab};
use kv::tui::view;
use ratatui::Terminal;
use ratatui::backend::TestBackend;
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

fn use_of<'a>(handle: &'a str, decision: &'a str) -> Use<'a> {
    Use {
        action: "http_request",
        handle,
        decision,
        summary: "GET https://openrouter.ai/api/v1/models",
        outcome: "200",
        duration: Duration::from_millis(85),
    }
}

fn screen(app: &App) -> String {
    let mut terminal = Terminal::new(TestBackend::new(120, 30)).unwrap();
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

#[test]
fn the_tail_is_newest_first_and_limited() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("audit.jsonl");
    let log = Audit::new(path.clone());
    log.record("control", "add", Some("h0"), "done");
    for i in 1..10 {
        log.record_use(&use_of(&format!("h{i}"), "approved"));
    }
    let entries = audit::tail(&path, 3).unwrap();
    let handles: Vec<_> = entries
        .iter()
        .map(|e| e.handle.as_deref().unwrap())
        .collect();
    assert_eq!(handles, ["h9", "h8", "h7"]);
    let newest = &entries[0];
    assert_eq!(newest.socket, "agent");
    assert_eq!(newest.action, "http_request");
    assert_eq!(newest.decision.as_deref(), Some("approved"));
    assert_eq!(
        newest.summary.as_deref(),
        Some("GET https://openrouter.ai/api/v1/models")
    );
    assert_eq!(newest.outcome, "200");
    assert_eq!(newest.duration_ms, Some(85));
    assert!(newest.ts.ends_with('Z'));

    let all = audit::tail(&path, 100).unwrap();
    assert_eq!(all.len(), 10);
    assert_eq!(all[9].action, "add");
    assert_eq!(all[9].decision, None);
}

#[test]
fn a_large_log_is_read_from_the_end() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("audit.jsonl");
    let log = Audit::new(path.clone());
    for i in 0..3000 {
        log.record(
            "agent",
            "list_handles",
            Some(&format!("handle-{i}")),
            "done",
        );
    }
    assert!(fs::metadata(&path).unwrap().len() > 200 * 1024);
    let entries = audit::tail(&path, 2).unwrap();
    let handles: Vec<_> = entries
        .iter()
        .map(|e| e.handle.as_deref().unwrap())
        .collect();
    assert_eq!(handles, ["handle-2999", "handle-2998"]);
}

#[test]
fn a_missing_log_is_empty_and_bad_lines_are_skipped() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("audit.jsonl");
    assert!(audit::tail(&path, 10).unwrap().is_empty());
    Audit::new(path.clone()).record("control", "lock", None, "done");
    writeln!(
        fs::OpenOptions::new().append(true).open(&path).unwrap(),
        "not json"
    )
    .unwrap();
    let entries = audit::tail(&path, 10).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].action, "lock");
}

#[test]
fn control_characters_in_the_log_are_made_safe() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("audit.jsonl");
    fs::write(
        &path,
        "{\"ts\":\"2026-10-08T12:00:00.000Z\",\"socket\":\"agent\",\"action\":\"exec\",\
         \"summary\":\"[\\\"echo\\\",\\\"\\u001b]52;c;x\\u0007\\\"]\",\"outcome\":\"0\"}\n",
    )
    .unwrap();
    let entries = audit::tail(&path, 10).unwrap();
    let summary = entries[0].summary.as_deref().unwrap();
    assert!(!summary.chars().any(char::is_control), "{summary:?}");
}

#[test]
fn the_audit_tab_shows_recent_uses() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("audit.jsonl");
    Audit::new(path.clone()).record_use(&use_of("openrouter", "approved"));
    let mut app = App::new();
    app.apply(Outcome::Opened);
    app.handle_key(KeyEvent::new(KeyCode::Char('3'), KeyModifiers::NONE));
    assert_eq!(app.tab(), Tab::Audit);
    assert!(
        screen(&app).contains("No audit entries yet"),
        "{}",
        screen(&app)
    );

    app.apply(Outcome::Audit(audit::tail(&path, 10).unwrap()));
    let drawn = screen(&app);
    for expected in [
        "http_request",
        "openrouter",
        "approved",
        "GET https://openrouter.ai/api/v1/models",
        "200",
        "85ms",
        "3 Audit",
    ] {
        assert!(drawn.contains(expected), "missing {expected:?} in\n{drawn}");
    }
}
