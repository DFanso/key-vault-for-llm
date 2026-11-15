//! When a value copied from kv's window comes off the clipboard: after
//! `CLEAR_AFTER`, and only if nothing else was copied since.

use std::time::Duration;

use kv::tray::clipboard::{CLEAR_AFTER, Decision, decide};

#[test]
fn a_copy_is_cleared_after_twenty_seconds() {
    assert_eq!(CLEAR_AFTER, Duration::from_secs(20));
    assert_eq!(decide(41, 41, CLEAR_AFTER), Decision::Clear);
    assert_eq!(
        decide(41, 41, CLEAR_AFTER + Duration::from_secs(5)),
        Decision::Clear
    );
}

#[test]
fn before_then_it_waits_for_the_time_left() {
    assert_eq!(decide(41, 41, Duration::ZERO), Decision::Wait(CLEAR_AFTER));
    assert_eq!(
        decide(41, 41, Duration::from_secs(15)),
        Decision::Wait(Duration::from_secs(5))
    );
}

#[test]
fn something_copied_since_is_left_alone() {
    for elapsed in [Duration::ZERO, Duration::from_secs(19), CLEAR_AFTER] {
        assert_eq!(decide(41, 42, elapsed), Decision::Leave, "{elapsed:?}");
        assert_eq!(decide(41, 40, elapsed), Decision::Leave, "{elapsed:?}");
    }
}

/// Without a sequence number (the system gives 0) the value still goes.
#[test]
fn no_sequence_number_still_clears() {
    assert_eq!(decide(0, 0, CLEAR_AFTER), Decision::Clear);
}
