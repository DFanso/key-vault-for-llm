//! What the daemon announces as desktop notifications, and with which
//! sound. Posting itself is left to the platform and not tested here.

use std::time::{Duration, Instant};

use kv::notify::{
    FirstUses, Level, MAX_FIRST_USES, MAX_NOTICES_PER_MINUTE, RateCap, Sound, Tone, UseNotices,
    approval_notice, or_default, sound_name, use_notice,
};
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

#[test]
fn an_agent_cannot_add_a_line_or_reorder_text_through_its_name() {
    let handles = names(&["github"]);
    for spoof in [
        "evil\nkv: approval needed",
        "evil\u{2028}kv: approval needed",
        "evil\u{202E}deppots",
        "ev\u{200B}il\u{0007}",
    ] {
        let text = use_notice(Some(spoof), &handles, "http_request");
        assert!(!text.contains('\n'), "{text:?}");
        assert!(!text.contains('\u{2028}'), "{text:?}");
        assert!(!text.contains('\u{202E}'), "{text:?}");
        assert!(!text.contains('\u{200B}'), "{text:?}");
        assert!(!text.contains('\u{0007}'), "{text:?}");
        assert!(text.ends_with(" used github (http_request)."), "{text:?}");
    }
}

#[test]
fn a_long_or_blank_name_is_cut_or_replaced() {
    let handles = names(&["github"]);
    let long = "a".repeat(2000);
    let text = use_notice(Some(&long), &handles, "exec");
    let client = text.split(" used ").next().unwrap();
    assert_eq!(client.chars().count(), 64);
    assert_eq!(
        use_notice(Some("   "), &handles, "exec"),
        "An agent used github (exec)."
    );
    assert_eq!(
        use_notice(None, &names(&["a", "b"]), "exec"),
        "An agent used a, b (exec)."
    );
}

#[test]
fn use_notices_say_each_handle_once_per_session() {
    let mut uses = UseNotices::default();
    let now = Instant::now();
    let one = session("s1");
    let text = uses.notice(Some(&one), &names(&["github"]), "http_request", now);
    assert_eq!(
        text.as_deref(),
        Some("claude-code used github (http_request).")
    );
    assert_eq!(
        uses.notice(Some(&one), &names(&["github"]), "http_request", now),
        None
    );
}

#[test]
fn use_notices_are_capped_per_minute_then_say_how_many_were_held() {
    let mut uses = UseNotices::default();
    let t0 = Instant::now();
    for i in 0..MAX_NOTICES_PER_MINUTE {
        let s = session(&format!("s{i}"));
        assert!(
            uses.notice(Some(&s), &names(&["github"]), "exec", t0)
                .is_some()
        );
    }
    // An agent naming a new session each call gets nothing more this minute.
    for i in 0..5 {
        let s = session(&format!("flood{i}"));
        assert_eq!(uses.notice(Some(&s), &names(&["github"]), "exec", t0), None);
    }
    let later = t0 + Duration::from_secs(61);
    let text = uses
        .notice(Some(&session("next")), &names(&["github"]), "exec", later)
        .unwrap();
    assert!(
        text.ends_with(" 5 more not shown; kv's Audit tab lists every use."),
        "{text}"
    );
    let text = uses
        .notice(Some(&session("after")), &names(&["github"]), "exec", later)
        .unwrap();
    assert!(!text.contains("more not shown"), "{text}");
}

#[test]
fn a_value_not_understood_falls_back_to_the_default() {
    assert_eq!(or_default::<Level>("KV_NOTIFY", "loud"), Level::Ask);
    assert_eq!(or_default::<Level>("KV_NOTIFY", "all"), Level::All);
    assert_eq!(
        or_default::<Sound>("KV_NOTIFY_SOUND", "siren"),
        Sound::Alarm
    );
    assert_eq!(
        or_default::<Sound>("KV_NOTIFY_SOUND", "yes"),
        Sound::Default
    );
}

#[test]
fn approval_notices_are_capped_per_minute_then_say_how_many_asked() {
    let mut rate = RateCap::default();
    let t0 = Instant::now();
    let notice = "claude-code wants to use github (http_request). Open kv tui to answer.";
    for _ in 0..MAX_NOTICES_PER_MINUTE {
        assert_eq!(
            approval_notice(&mut rate, notice, t0).as_deref(),
            Some(notice)
        );
    }
    assert_eq!(approval_notice(&mut rate, notice, t0), None);
    assert_eq!(approval_notice(&mut rate, notice, t0), None);
    let text = approval_notice(&mut rate, notice, t0 + Duration::from_secs(60)).unwrap();
    assert_eq!(
        text,
        format!("{notice} 2 more requests asked meanwhile; open kv to see them.")
    );
}
