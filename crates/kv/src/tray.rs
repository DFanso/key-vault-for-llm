//! `kv tray`: a menu bar (macOS) or notification area (Windows) icon that
//! shows waiting agent requests and answers them from its menu, and kv's
//! window, where the vault is unlocked and handles are managed without
//! `kv tui`.

pub mod icon;
pub mod login;
pub mod model;
#[cfg(any(target_os = "macos", windows))]
mod ui;
pub mod window;
pub mod worker;

use std::fs::{File, TryLockError};
use std::io;

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
