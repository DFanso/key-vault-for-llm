//! `kv tray`: a menu bar (macOS) or notification area (Windows) icon that
//! shows waiting agent requests and answers them from its menu, after
//! unlocking with Touch ID or Windows Hello.

pub mod icon;
pub mod login;
pub mod model;
#[cfg(any(target_os = "macos", windows))]
mod ui;
pub mod window;
pub mod worker;

use std::fs::{File, TryLockError};
use std::io;
#[cfg(any(target_os = "macos", windows))]
use std::path::Path;
#[cfg(any(target_os = "macos", windows))]
use std::process::Command;

use crate::paths::Paths;

/// Runs the tray until the user quits it.
pub fn run(paths: Paths) -> io::Result<()> {
    #[cfg(any(target_os = "macos", windows))]
    {
        let lock = lock_single(&paths)?;
        ui::run(paths, lock)
    }
    #[cfg(not(any(target_os = "macos", windows)))]
    {
        let _ = paths;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "kv tray runs on macOS and Windows only",
        ))
    }
}

/// Takes the lock that keeps a second `kv tray` from starting. Held until
/// the returned file is dropped or the process exits.
pub fn lock_single(paths: &Paths) -> io::Result<File> {
    paths.ensure_runtime_dir()?;
    let file = File::options()
        .create(true)
        .truncate(false)
        .write(true)
        .open(paths.tray_lock_file())?;
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(TryLockError::WouldBlock) => Err(io::Error::other("kv tray is already running")),
        Err(TryLockError::Error(e)) => Err(e),
    }
}

/// Opens a Terminal window running `<exe> tui`.
#[cfg(target_os = "macos")]
pub fn tui_command(exe: &Path) -> Command {
    let shell = format!("'{}' tui", exe.to_string_lossy().replace('\'', r"'\''"));
    let script = shell.replace('\\', r"\\").replace('"', r#"\""#);
    let mut command = Command::new("osascript");
    command.args([
        "-e",
        &format!(r#"tell application "Terminal" to do script "{script}""#),
        "-e",
        r#"tell application "Terminal" to activate"#,
    ]);
    command
}

/// Opens a console window running `<exe> tui`, in the user's default
/// terminal.
#[cfg(windows)]
pub fn tui_command(exe: &Path) -> Command {
    use std::os::windows::process::CommandExt;
    use windows_sys::Win32::System::Threading::CREATE_NO_WINDOW;

    let mut command = Command::new("cmd");
    command
        .args(["/c", "start", ""])
        .arg(exe)
        .arg("tui")
        // `start` opens the window; cmd itself needs none.
        .creation_flags(CREATE_NO_WINDOW);
    command
}
