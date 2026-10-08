//! Desktop notifications, so the user learns that something is waiting for
//! them in `kv tui` even when it is not open.

pub fn approval_needed(text: String) {
    show("kv: approval needed", text);
}

pub fn handle_requested(text: String) {
    show("kv: handle requested", text);
}

/// Shows `text` from a thread of its own, so a slow or missing notification
/// service never holds up the daemon. Failures are ignored.
fn show(summary: &'static str, text: String) {
    std::thread::spawn(move || {
        let _ = notify_rust::Notification::new()
            .summary(summary)
            .body(&text)
            .show();
    });
}
