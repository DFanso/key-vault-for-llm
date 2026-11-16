//! The parts of `kv tray` around its UI: the icon images and the
//! one-tray-at-a-time lock.

use kv::paths::Paths;
use kv::tray::icon::{SIZE, rgba};
use kv::tray::lock_single;
use kv::tray::model::IconState;
use tempfile::TempDir;

fn pixel(image: &[u8], x: u32, y: u32) -> [u8; 4] {
    let at = ((y * SIZE + x) * 4) as usize;
    image[at..at + 4].try_into().unwrap()
}

#[test]
fn every_state_has_an_image_of_the_same_size() {
    for state in [
        IconState::Off,
        IconState::Locked,
        IconState::Unlocked,
        IconState::Waiting(3),
    ] {
        let image = rgba(state);
        assert_eq!(image.len(), (SIZE * SIZE * 4) as usize, "{state:?}");
        assert!(image.chunks(4).any(|p| p[3] > 100), "{state:?} is blank");
        assert!(
            image.chunks(4).any(|p| p[3] == 0),
            "{state:?} has no background"
        );
    }
}

#[test]
fn locked_is_dimmer_than_unlocked_and_waiting_adds_a_badge() {
    assert_eq!(rgba(IconState::Off), rgba(IconState::Locked));
    let locked = rgba(IconState::Locked);
    let unlocked = rgba(IconState::Unlocked);
    let max_alpha = |image: &[u8]| image.chunks(4).map(|p| p[3]).max().unwrap();
    assert!(max_alpha(&locked) < max_alpha(&unlocked));

    let waiting = rgba(IconState::Waiting(1));
    assert_eq!(
        rgba(IconState::Waiting(7)),
        waiting,
        "the count is not drawn"
    );
    // macOS draws a template image, alpha only, and puts the count in the
    // title beside the icon, so there is no badge.
    if cfg!(target_os = "macos") {
        assert_eq!(waiting, unlocked);
        return;
    }
    // The badge sits in the top right corner; the rest is the plain key.
    let badge = pixel(&waiting, SIZE - 7, 6);
    assert_eq!(badge[3], 255);
    assert_ne!(badge, pixel(&unlocked, SIZE - 7, 6));
    for y in SIZE / 2..SIZE {
        for x in 0..SIZE / 2 {
            assert_eq!(pixel(&waiting, x, y), pixel(&unlocked, x, y), "({x}, {y})");
        }
    }
}

#[test]
fn only_one_tray_runs_at_a_time() {
    let home = TempDir::new().unwrap();
    let paths = Paths::under(home.path());
    let first = lock_single(&paths).unwrap();
    let error = lock_single(&paths).unwrap_err();
    assert_eq!(error.to_string(), "kv tray is already running");
    drop(first);
    lock_single(&paths).unwrap();
}

#[test]
fn the_window_icon_is_the_mark_in_colour() {
    use kv::tray::icon::{LOGO_SIZE, logo_rgba};
    let logo = logo_rgba();
    assert_eq!(logo.len(), (LOGO_SIZE * LOGO_SIZE * 4) as usize);
    let at = |x: u32, y: u32| {
        let i = ((y * LOGO_SIZE + x) * 4) as usize;
        [logo[i], logo[i + 1], logo[i + 2], logo[i + 3]]
    };
    assert_eq!(at(0, 0)[3], 0, "the corners are clear");
    let tile = at(LOGO_SIZE / 2, LOGO_SIZE - 8);
    assert_eq!(tile[3], 255);
    assert!(tile[2] > tile[1], "violet: {tile:?}");
    assert_eq!(
        at(LOGO_SIZE / 2 + 10, LOGO_SIZE / 2),
        [255, 255, 255, 255],
        "the key's shaft is white"
    );
}

#[test]
fn the_next_tray_waits_for_the_lock() {
    use kv::tray::lock_single_retry;
    use std::time::Duration;

    let home = TempDir::new().unwrap();
    let paths = Paths::under(home.path());
    let first = lock_single(&paths).unwrap();
    let error = lock_single_retry(&paths, Duration::from_millis(100)).unwrap_err();
    assert_eq!(error.to_string(), "kv tray is already running");
    let letting_go = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(200));
        drop(first);
    });
    lock_single_retry(&paths, Duration::from_secs(5)).unwrap();
    letting_go.join().unwrap();
}

/// A script standing in for the new kv: it writes down how it was started
/// and runs `body`.
#[cfg(unix)]
fn successor(dir: &std::path::Path, body: &str) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let script = dir.join("kv");
    let args = dir.join("args");
    std::fs::write(
        &script,
        format!("#!/bin/sh\necho \"$@\" >> '{}'\n{body}\n", args.display()),
    )
    .unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    script
}

#[cfg(unix)]
#[test]
fn a_successor_that_never_comes_up_leaves_the_old_tray_in_charge() {
    use kv::tray::update::restart_after_update;
    use std::sync::{Arc, Mutex};

    let home = TempDir::new().unwrap();
    let paths = Paths::under(home.path());
    let lock = Arc::new(Mutex::new(Some(lock_single(&paths).unwrap())));
    let exe = successor(home.path(), "exit 1");
    let error =
        restart_after_update(&lock, &exe, &semver::Version::new(1, 9, 0), &paths).unwrap_err();
    assert_eq!(
        error,
        "kv 1.9.0 is installed, but the new tray didn't start. Run `kv tray`, or log out and \
         back in."
    );
    let tried = std::fs::read_to_string(home.path().join("args")).unwrap();
    assert_eq!(tried, "tray --after-update 1.9.0\n".repeat(3));
    assert!(lock.lock().unwrap().is_some(), "the lock was taken back");
    assert!(kv::tray::is_running(&paths));
}

#[cfg(unix)]
#[test]
fn a_successor_that_takes_the_lock_is_the_tray_now() {
    use kv::tray::update::restart_after_update;
    use std::sync::{Arc, Mutex};

    let home = TempDir::new().unwrap();
    let paths = Paths::under(home.path());
    let lock = Arc::new(Mutex::new(Some(lock_single(&paths).unwrap())));
    // Holds the tray lock (flock, as kv's) for a moment, like a new tray.
    let body = format!(
        "exec perl -e 'use Fcntl qw(:flock); open(my $f, \">>\", $ARGV[0]) or die; \
         flock($f, LOCK_EX) or die; sleep 2' '{}'",
        paths.tray_lock_file().display()
    );
    let exe = successor(home.path(), &body);
    restart_after_update(&lock, &exe, &semver::Version::new(1, 9, 0), &paths).unwrap();
    assert!(lock.lock().unwrap().is_none(), "the old tray let go");
    let tried = std::fs::read_to_string(home.path().join("args")).unwrap();
    assert_eq!(tried, "tray --after-update 1.9.0\n");
}

#[test]
fn the_new_tray_says_it_was_updated() {
    let text = kv::tray::update::updated_text(&semver::Version::new(1, 9, 0));
    let mut expected = "Updated to kv 1.9.0. Unlock to continue.".to_owned();
    if cfg!(target_os = "macos") {
        expected.push_str(
            " macOS will ask for your login password once before Touch ID works again; choose \
             Always Allow.",
        );
    }
    assert_eq!(text, expected);
}
