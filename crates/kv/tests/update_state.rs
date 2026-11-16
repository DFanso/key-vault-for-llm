//! The remembered result of the last update check, and when the next one
//! is due.

use std::time::Duration;

use kv::paths::Paths;
use kv::update::state::{
    CLI_EVERY, TRAY_EVERY, TRAY_FIRST, UpdateState, due, load, newer_known, save,
};
use semver::Version;

fn v(s: &str) -> Version {
    Version::parse(s).unwrap()
}

#[test]
fn save_then_load_round_trips() {
    let dir = tempfile::tempdir().unwrap();
    let path = Paths::under(dir.path()).update_state_file();
    let state = UpdateState {
        last_check: Some(1_700_000_000),
        latest: Some("1.9.0".into()),
        announced: Some("1.9.0".into()),
    };
    save(&path, &state).unwrap();
    assert_eq!(load(&path), state);
}

#[test]
fn missing_or_corrupt_file_loads_as_default() {
    let dir = tempfile::tempdir().unwrap();
    let path = Paths::under(dir.path()).update_state_file();
    assert_eq!(load(&path), UpdateState::default());
    std::fs::write(&path, b"{ not json").unwrap();
    assert_eq!(load(&path), UpdateState::default());
}

#[test]
fn due_follows_the_interval() {
    let hour = 3600;
    assert!(due(&UpdateState::default(), 1_000, CLI_EVERY));
    let state = UpdateState {
        last_check: Some(1_000_000),
        ..Default::default()
    };
    assert!(!due(&state, 1_000_000 + hour, CLI_EVERY));
    assert!(due(&state, 1_000_000 + 25 * hour, CLI_EVERY));
    // A clock that went backwards does not wedge the check forever.
    assert!(!due(&state, 1_000_000 - hour, CLI_EVERY));
}

#[test]
fn cadence_constants() {
    assert_eq!(TRAY_FIRST, Duration::from_secs(3 * 60));
    assert_eq!(TRAY_EVERY, Duration::from_secs(12 * 3600));
    assert_eq!(CLI_EVERY, Duration::from_secs(24 * 3600));
}

#[test]
fn newer_known_only_when_latest_is_newer() {
    let with = |latest: Option<&str>| UpdateState {
        latest: latest.map(String::from),
        ..Default::default()
    };
    assert_eq!(
        newer_known(&with(Some("1.9.0")), &v("1.8.0")),
        Some(v("1.9.0"))
    );
    assert_eq!(newer_known(&with(Some("1.8.0")), &v("1.8.0")), None);
    assert_eq!(newer_known(&with(Some("1.7.0")), &v("1.8.0")), None);
    assert_eq!(newer_known(&with(Some("garbage")), &v("1.8.0")), None);
    assert_eq!(newer_known(&with(None), &v("1.8.0")), None);
}
