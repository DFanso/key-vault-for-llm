//! What the daemon announces as desktop notifications, and with which
//! sound. Posting itself is left to the platform and not tested here.

use kv::notify::{FirstUses, Level, MAX_FIRST_USES, Sound, Tone, sound_name};
use kv_core::proto::SessionInfo;

fn session(id: &str) -> SessionInfo {
    SessionInfo {
        id: id.into(),
        client: "claude-code".into(),
    }
}

fn names(handles: &[&str]) -> Vec<String> {
    handles.iter().map(|&h| h.to_owned()).collect()
}

#[test]
fn level_reads_ask_all_off_and_the_old_on_off() {
    for on in ["ask", "on", "true", "1", "yes", "ASK", " On "] {
        assert_eq!(on.parse::<Level>(), Ok(Level::Ask), "{on}");
    }
    for off in ["off", "false", "0", "no", "OFF"] {
        assert_eq!(off.parse::<Level>(), Ok(Level::Off), "{off}");
    }
    assert_eq!("all".parse::<Level>(), Ok(Level::All));
    assert!("loud".parse::<Level>().is_err());
    assert!("".parse::<Level>().is_err());
}

#[test]
fn sound_reads_alarm_default_off() {
    assert_eq!("alarm".parse::<Sound>(), Ok(Sound::Alarm));
    assert_eq!("default".parse::<Sound>(), Ok(Sound::Default));
    assert_eq!("on".parse::<Sound>(), Ok(Sound::Default));
    for off in ["off", "none", "false", "0"] {
        assert_eq!(off.parse::<Sound>(), Ok(Sound::Off), "{off}");
    }
    assert!("siren".parse::<Sound>().is_err());
}

#[test]
fn defaults_are_approvals_only_with_an_alarm() {
    assert_eq!(Level::default(), Level::Ask);
    assert_eq!(Sound::default(), Sound::Alarm);
}

#[test]
fn only_approvals_get_the_alarm() {
    assert_eq!(Sound::Alarm.tone(true), Some(Tone::Alarm));
    assert_eq!(Sound::Alarm.tone(false), Some(Tone::Default));
    assert_eq!(Sound::Default.tone(true), Some(Tone::Default));
    assert_eq!(Sound::Off.tone(true), None);
    assert_eq!(Sound::Off.tone(false), None);
}

#[test]
fn every_tone_has_a_sound_on_this_platform() {
    // Without a sound name, Windows toasts are silent: notify-rust passes
    // no sound to the toast unless one is named.
    let default = sound_name(Tone::Default);
    let alarm = sound_name(Tone::Alarm);
    assert!(!default.is_empty());
    assert!(!alarm.is_empty());
    assert_ne!(default, alarm);
}

#[cfg(windows)]
#[test]
fn windows_tones_are_toast_sounds() {
    assert_eq!(sound_name(Tone::Default), "Default");
    assert_eq!(sound_name(Tone::Alarm), "Reminder");
}

#[test]
fn level_says_what_it_announces() {
    assert!(!Level::Off.approvals());
    assert!(Level::Ask.approvals());
    assert!(Level::All.approvals());
    assert!(!Level::Off.uses());
    assert!(!Level::Ask.uses());
    assert!(Level::All.uses());
}

#[test]
fn a_handle_is_announced_once_per_agent_session() {
    let mut uses = FirstUses::default();
    let one = session("s1");
    assert_eq!(
        uses.first(Some(&one), &names(&["github"])),
        names(&["github"])
    );
    assert!(uses.first(Some(&one), &names(&["github"])).is_empty());
    // Another session using it is news again.
    assert_eq!(
        uses.first(Some(&session("s2")), &names(&["github"])),
        names(&["github"])
    );
    // Only the handles not yet announced come back.
    assert_eq!(
        uses.first(Some(&one), &names(&["github", "aws"])),
        names(&["aws"])
    );
}

#[test]
fn agents_without_a_session_share_one() {
    let mut uses = FirstUses::default();
    assert_eq!(uses.first(None, &names(&["github"])), names(&["github"]));
    assert!(uses.first(None, &names(&["github"])).is_empty());
}

#[test]
fn a_handle_named_twice_in_one_request_comes_back_once() {
    let mut uses = FirstUses::default();
    assert_eq!(uses.first(None, &names(&["aws", "aws"])), names(&["aws"]));
}

#[test]
fn the_oldest_are_forgotten_past_the_limit() {
    let mut uses = FirstUses::default();
    let one = session("s1");
    assert_eq!(
        uses.first(Some(&one), &names(&["first"])),
        names(&["first"])
    );
    for i in 0..MAX_FIRST_USES {
        uses.first(Some(&one), &[format!("h{i}")]);
    }
    assert_eq!(uses.len(), MAX_FIRST_USES);
    // "first" was the oldest, so it is news again.
    assert_eq!(
        uses.first(Some(&one), &names(&["first"])),
        names(&["first"])
    );
}
