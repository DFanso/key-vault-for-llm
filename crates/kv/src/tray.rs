//! `kv tray`: a menu bar (macOS) or notification area (Windows) icon that
//! shows waiting agent requests and answers them from its menu, and kv's
//! window, where the vault is unlocked and handles are managed without
//! `kv tui`.

#[cfg(target_os = "macos")]
pub mod bundle;
pub mod clipboard;
pub mod icon;
pub mod login;
pub mod model;
pub mod notices;
#[cfg(any(target_os = "macos", windows))]
mod ui;
pub mod update;
pub mod window;
pub mod worker;

use std::fs::{File, TryLockError};
use std::io;
use std::time::{Duration, Instant};

use crate::paths::Paths;

/// How long a tray started by an update waits for the old one to let go of
/// the tray lock.
pub const AFTER_UPDATE_WAIT: Duration = Duration::from_secs(5);

/// Runs the tray until the user quits it. `after_update` is the version an
/// update just installed, when the old tray started this one: it waits for
/// the lock a little, and says the update is done.
pub fn run(paths: Paths, after_update: Option<semver::Version>) -> io::Result<()> {
    #[cfg(any(target_os = "macos", windows))]
    {
        let lock = match after_update {
            Some(_) => lock_single_retry(&paths, AFTER_UPDATE_WAIT)?,
            None => lock_single(&paths)?,
        };
        ui::run(paths, lock, after_update)
    }
    #[cfg(not(any(target_os = "macos", windows)))]
    {
        let _ = (paths, after_update);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "kv tray runs on macOS and Windows only",
        ))
    }
}

/// `kv tray-notices`: kv.app's notification helper, which `kv tray` starts.
pub fn run_notices() -> io::Result<()> {
    #[cfg(target_os = "macos")]
    {
        ui::run_notices()
    }
    #[cfg(not(target_os = "macos"))]
    {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "kv tray-notices runs on macOS only",
        ))
    }
}

/// Takes the lock that keeps a second `kv tray` from starting. Held until
/// the returned file is dropped or the process exits.
pub fn lock_single(paths: &Paths) -> io::Result<File> {
    lock_single_retry(paths, Duration::ZERO)
}

/// `lock_single`, trying again for up to `wait` while another tray holds
/// the lock, as a tray started by an update does while the old one quits.
pub fn lock_single_retry(paths: &Paths, wait: Duration) -> io::Result<File> {
    paths.ensure_runtime_dir()?;
    let file = File::options()
        .create(true)
        .truncate(false)
        .write(true)
        .open(paths.tray_lock_file())?;
    let deadline = Instant::now() + wait;
    loop {
        match file.try_lock() {
            Ok(()) => return Ok(file),
            Err(TryLockError::WouldBlock) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(TryLockError::WouldBlock) => {
                return Err(io::Error::other("kv tray is already running"));
            }
            Err(TryLockError::Error(e)) => return Err(e),
        }
    }
}

/// Whether a `kv tray` is running: its lock is held by someone else. If
/// this process can take the lock, it lets go again at once and the answer
/// is no.
pub fn is_running(paths: &Paths) -> bool {
    let Ok(file) = File::options()
        .read(true)
        .write(true)
        .open(paths.tray_lock_file())
    else {
        return false;
    };
    matches!(file.try_lock(), Err(TryLockError::WouldBlock))
}
