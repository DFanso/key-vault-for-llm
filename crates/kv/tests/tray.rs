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
