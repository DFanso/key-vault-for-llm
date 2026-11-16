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

    login::set_at(home.path(), exe, None, true).unwrap();
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
    assert!(!text.contains("EnvironmentVariables"), "{text}");

    // Turning it on twice is fine, and so is turning it off twice.
    login::set_at(home.path(), exe, None, true).unwrap();
    login::set_at(home.path(), exe, None, false).unwrap();
    assert!(!plist.exists());
    assert!(!login::is_on_at(home.path()));
    login::set_at(home.path(), exe, None, false).unwrap();
}

#[cfg(target_os = "macos")]
#[test]
fn the_exe_path_is_escaped_for_xml() {
    let text = login::plist(Path::new("/Users/a&b/<kv>/kv"), None);
    assert!(
        text.contains("<string>/Users/a&amp;b/&lt;kv&gt;/kv</string>"),
        "{text}"
    );
}

/// `KV_UPDATE_CHECK=off kv tray --login on` carries the setting into the
/// login item, which does not see the shell profile.
#[cfg(target_os = "macos")]
#[test]
fn update_check_is_carried_into_the_launch_agent() {
    let home = tempfile::TempDir::new().unwrap();
    let exe = Path::new("/Users/me/.cargo/bin/kv");
    login::set_at(home.path(), exe, Some("off"), true).unwrap();
    let text = std::fs::read_to_string(login::plist_path(home.path())).unwrap();
    assert!(
        text.contains(
            "\t<string>Interactive</string>\n\t<key>EnvironmentVariables</key>\n\t<dict>\n\
             \t\t<key>KV_UPDATE_CHECK</key>\n\t\t<string>off</string>\n\t</dict>\n</dict>\n"
        ),
        "{text}"
    );

    let text = login::plist(exe, Some("<off&>"));
    assert!(text.contains("<string>&lt;off&amp;&gt;</string>"), "{text}");
}

#[cfg(windows)]
#[test]
fn the_run_value_quotes_the_exe() {
    assert_eq!(
        login::command(Path::new(r"C:\Program Files\kv\kv.exe")),
        r#""C:\Program Files\kv\kv.exe" tray"#
    );
}
