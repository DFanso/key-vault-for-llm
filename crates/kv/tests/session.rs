//! Control sessions: `kv tui` trades the passphrase for a token once, then
//! uses the token for everything it does until the vault locks.

mod common;

use std::time::{Duration, SystemTime};

use common::*;
use kv::daemon::After;
use kv_core::policy::Mode;
use kv_core::proto::{
    ControlCommand, ControlErrorCode, ControlRequest, ControlResponse, Overview, PolicyPatch,
};
use kv_core::secret::{AuthPlacement, SecretText};

fn request(
    passphrase: Option<&str>,
    token: Option<&SecretText>,
    command: ControlCommand,
) -> ControlRequest {
    ControlRequest {
        passphrase: passphrase.map(SecretText::new),
        device: None,
        token: token.cloned(),
        command,
    }
}

fn send(f: &mut Fixture, request: ControlRequest) -> ControlResponse {
    f.daemon.handle_control(request, f.t0).0
}

fn open(f: &mut Fixture) -> SecretText {
    match send(f, request(Some(PASS), None, ControlCommand::OpenSession)) {
        ControlResponse::Session { token } => token,
        other => panic!("expected a session, got {other:?}"),
    }
}

fn error_code(response: ControlResponse) -> ControlErrorCode {
    match response {
        ControlResponse::Error { code, .. } => code,
        other => panic!("expected an error, got {other:?}"),
    }
}

fn overview(f: &mut Fixture, token: &SecretText) -> ControlResponse {
    send(f, request(None, Some(token), ControlCommand::Overview))
}

fn expect_overview(response: ControlResponse) -> Overview {
    match response {
        ControlResponse::Overview { overview } => overview,
        other => panic!("expected an overview, got {other:?}"),
    }
}

#[test]
fn a_session_token_works_instead_of_the_passphrase() {
    let mut f = Fixture::new();
    f.add(openrouter(Mode::Ask));
    let token = open(&mut f);
    assert_eq!(token.expose().len(), 64, "256 bits, hex");
    let patch = PolicyPatch {
        mode: Some(Mode::Auto),
        ..PolicyPatch::default()
    };
    let response = send(
        &mut f,
        request(
            None,
            Some(&token),
            ControlCommand::SetPolicy {
                name: "openrouter".into(),
                patch,
            },
        ),
    );
    assert!(
        matches!(response, ControlResponse::Done { .. }),
        "{response:?}"
    );
    let audit = f.audit_lines();
    assert!(audit.iter().any(|l| l["action"] == "open_session"));
    assert_eq!(audit.last().unwrap()["action"], "set_policy");
}

#[test]
fn opening_a_session_needs_the_passphrase() {
    let mut f = Fixture::new();
    let token = open(&mut f);
    let wrong = send(
        &mut f,
        request(
            Some("not the passphrase"),
            None,
            ControlCommand::OpenSession,
        ),
    );
    assert_eq!(error_code(wrong), ControlErrorCode::WrongPassphrase);
    let with_token = send(
        &mut f,
        request(None, Some(&token), ControlCommand::OpenSession),
    );
    assert_eq!(error_code(with_token), ControlErrorCode::PassphraseRequired);
}

#[test]
fn changing_the_passphrase_needs_the_passphrase_and_ends_sessions() {
    let mut f = Fixture::new();
    let token = open(&mut f);
    let change = || ControlCommand::ChangePassphrase {
        new_passphrase: SecretText::new("a brand new passphrase"),
    };
    let with_token = send(&mut f, request(None, Some(&token), change()));
    assert_eq!(error_code(with_token), ControlErrorCode::PassphraseRequired);
    let done = send(&mut f, request(Some(PASS), None, change()));
    assert!(matches!(done, ControlResponse::Done { .. }), "{done:?}");
    assert_eq!(
        error_code(overview(&mut f, &token)),
        ControlErrorCode::SessionEnded
    );
}

#[test]
fn locking_ends_every_session() {
    let mut f = Fixture::new();
    let first = open(&mut f);
    let second = open(&mut f);
    assert_ne!(first, second);
    expect_overview(overview(&mut f, &first));
    send(&mut f, request(None, None, ControlCommand::Lock));
    for token in [&first, &second] {
        assert_eq!(
            error_code(overview(&mut f, token)),
            ControlErrorCode::SessionEnded
        );
    }
    // Unlocking again with the passphrase does not bring old tokens back.
    send(&mut f, request(Some(PASS), None, ControlCommand::Unlock));
    assert_eq!(
        error_code(overview(&mut f, &first)),
        ControlErrorCode::SessionEnded
    );
}

#[test]
fn the_idle_lock_ends_sessions_and_polling_does_not_count_as_use() {
    let mut f = Fixture::new();
    let token = open(&mut f);
    let idle_lock = Duration::from_secs(8 * 60 * 60);
    let nearly = f.t0 + idle_lock - Duration::from_secs(1);
    let (response, _) = f.daemon.handle_control(
        request(None, Some(&token), ControlCommand::Overview),
        nearly,
    );
    expect_overview(response);
    let wall = SystemTime::now() + idle_lock;
    assert_eq!(f.daemon.tick(f.t0 + idle_lock, wall), After::Continue);
    assert!(
        !f.daemon.is_unlocked(),
        "overview polls must not delay the idle lock"
    );
    assert_eq!(
        error_code(overview(&mut f, &token)),
        ControlErrorCode::SessionEnded
    );
}

#[test]
fn a_made_up_token_is_refused() {
    let mut f = Fixture::new();
    open(&mut f);
    let guess = SecretText::new("0".repeat(64));
    assert_eq!(
        error_code(overview(&mut f, &guess)),
        ControlErrorCode::SessionEnded
    );
    let edit = send(
        &mut f,
        request(
            None,
            Some(&guess),
            ControlCommand::Remove {
                name: "anything".into(),
            },
        ),
    );
    assert_eq!(error_code(edit), ControlErrorCode::SessionEnded);
}

#[test]
fn opening_a_session_unlocks_a_locked_vault() {
    let mut f = Fixture::new();
    send(&mut f, request(None, None, ControlCommand::Lock));
    assert!(!f.daemon.is_unlocked());
    let token = open(&mut f);
    assert!(f.daemon.is_unlocked());
    assert!(!expect_overview(overview(&mut f, &token)).status.locked);
}

#[test]
fn the_overview_shows_handles_with_their_placement_but_no_values() {
    let mut f = Fixture::new();
    f.add(openrouter(Mode::Auto));
    f.add(dokploy());
    let token = open(&mut f);
    let lines_before = f.audit_lines().len();
    let response = overview(&mut f, &token);
    assert_eq!(f.audit_lines().len(), lines_before, "polls are not audited");
    let json = serde_json::to_string(&response).unwrap();
    assert!(!json.contains(TOKEN), "{json}");
    assert!(!json.contains("dokploy.internal"), "{json}");
    let overview = expect_overview(response);
    assert_eq!(overview.status.handle_count, Some(2));
    let openrouter = overview
        .handles
        .iter()
        .find(|h| h.name == "openrouter")
        .unwrap();
    assert_eq!(
        openrouter.auth,
        Some(AuthPlacement::Header {
            name: "Authorization".into(),
            template: "Bearer {}".into(),
        })
    );
}
