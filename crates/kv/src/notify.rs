//! Desktop notifications, so the user learns that a request is waiting for
//! approval even when `kv tui` is not open.

/// Shows `text` from a thread of its own, so a slow or missing notification
/// service never holds up the daemon. Failures are ignored.
pub fn approval_needed(text: String) {
    std::thread::spawn(move || {
        let _ = notify_rust::Notification::new()
            .summary("kv: approval needed")
            .body(&text)
            .show();
    });
}
