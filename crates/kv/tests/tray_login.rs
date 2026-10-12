//! `kv tray --login on|off`: a LaunchAgent under the user's home on macOS,
//! a value under the Run key on Windows. The Windows test only builds the
//! value, so running the tests never changes the login items of the
//! machine they run on.
#![cfg(any(target_os = "macos", windows))]

use std::path::Path;

use kv::tray::login;

#[cfg(target_os = "macos")]
#[test]
fn on_writes_a_launch_agent_that_starts_the_tray_and_off_removes_it() {
    let home = tempfile::TempDir::new().unwrap();
    let exe = Path::new("/Users/me/.cargo/bin/kv");
    let plist = home
        .path()
        .join("Library/LaunchAgents/dev.dfanso.kv.tray.plist");
    assert_eq!(login::plist_path(home.path()), plist);
    assert!(!login::is_on_at(home.path()));

    login::set_at(home.path(), exe, true).unwrap();
    assert!(login::is_on_at(home.path()));
    let text = std::fs::read_to_string(&plist).unwrap();
    assert!(
        text.contains("<string>dev.dfanso.kv.tray</string>"),
        "{text}"
    );
    assert!(
        text.contains(
            "<array>\n\t\t<string>/Users/me/.cargo/bin/kv</string>\n\t\t<string>tray</string>\n\t</array>"
        ),
        "{text}"
    );
    assert!(text.contains("<key>RunAtLoad</key>\n\t<true/>"), "{text}");
    assert!(text.contains("<string>Interactive</string>"), "{text}");

    // Turning it on twice is fine, and so is turning it off twice.
    login::set_at(home.path(), exe, true).unwrap();
    login::set_at(home.path(), exe, false).unwrap();
    assert!(!plist.exists());
    assert!(!login::is_on_at(home.path()));
    login::set_at(home.path(), exe, false).unwrap();
}

#[cfg(target_os = "macos")]
#[test]
fn the_exe_path_is_escaped_for_xml() {
    let text = login::plist(Path::new("/Users/a&b/<kv>/kv"));
    assert!(
        text.contains("<string>/Users/a&amp;b/&lt;kv&gt;/kv</string>"),
        "{text}"
    );
}

#[cfg(windows)]
#[test]
fn the_run_value_quotes_the_exe() {
    assert_eq!(
        login::command(Path::new(r"C:\Program Files\kv\kv.exe")),
        r#""C:\Program Files\kv\kv.exe" tray"#
    );
}
