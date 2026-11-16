//! Putting a new kv binary where the old one is. Every step leaves the
//! installed file as it was until a single rename replaces it, so a
//! failure never leaves a broken kv behind.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use super::UpdateError;

/// Where the old binary went once the new one is in place.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Swapped {
    /// The binary that now holds the new version.
    pub installed: PathBuf,
    /// The old binary: `kv.previous` on unix, `kv.exe.old` on Windows.
    pub backup: PathBuf,
}

/// The path of the running kv, with symlinks resolved, so an update
/// replaces the real file and a link such as `~/.cargo/bin/kv` keeps
/// pointing at it.
pub fn installed_exe() -> io::Result<PathBuf> {
    std::env::current_exe()?.canonicalize()
}

/// The folder `installed` sits in.
fn folder(installed: &Path) -> Result<&Path, UpdateError> {
    installed
        .parent()
        .ok_or_else(|| UpdateError::Swap(format!("{} has no folder", installed.display())))
}

/// `NotWritable(folder)` when the system refused permission, otherwise
/// `Swap` naming what failed.
fn swap_error(folder: &Path, what: &str, e: io::Error) -> UpdateError {
    match e.kind() {
        io::ErrorKind::PermissionDenied | io::ErrorKind::ReadOnlyFilesystem => {
            UpdateError::NotWritable(folder.to_path_buf())
        }
        _ => UpdateError::Swap(format!("{what}: {e}")),
    }
}

/// Replaces `installed` with `new_binary`, which must be on the same
/// filesystem (in practice, in a folder beside it), and keeps the old one.
///
/// On unix the old binary is first linked or copied to `kv.previous`
/// (replacing an older one), then `new_binary` is renamed over
/// `installed`. On Windows, where a running program can be renamed but not
/// replaced, `installed` becomes `kv.exe.old` and `new_binary` takes its
/// name; if that second step fails the first is undone.
///
/// On any error `installed` is unchanged. The error is `NotWritable` with
/// the folder when permission was refused, otherwise `Swap`.
#[cfg(unix)]
pub fn swap(installed: &Path, new_binary: &Path) -> Result<Swapped, UpdateError> {
    let dir = folder(installed)?;
    let backup = installed.with_file_name("kv.previous");
    // Built under a temporary name and renamed into place, so the
    // installed file itself is never written to.
    let staging = dir.join(format!(".kv.previous.{}", std::process::id()));
    let _ = fs::remove_file(&staging);
    let backed_up = fs::hard_link(installed, &staging)
        .or_else(|_| fs::copy(installed, &staging).map(drop))
        .map_err(|e| swap_error(dir, "could not back up the old kv", e))
        .and_then(|()| {
            fs::rename(&staging, &backup)
                .map_err(|e| swap_error(dir, "could not back up the old kv", e))
        });
    if let Err(e) = backed_up {
        let _ = fs::remove_file(&staging);
        return Err(e);
    }
    fs::rename(new_binary, installed)
        .map_err(|e| swap_error(dir, "could not move the new kv into place", e))?;
    // Make the renames themselves durable. Best effort: the swap is done.
    if let Ok(folder) = fs::File::open(dir) {
        let _ = folder.sync_all();
    }
    Ok(Swapped {
        installed: installed.to_path_buf(),
        backup,
    })
}

/// Replaces `installed` with `new_binary`, which must be on the same
/// filesystem (in practice, in a folder beside it), and keeps the old one.
///
/// On unix the old binary is first linked or copied to `kv.previous`
/// (replacing an older one), then `new_binary` is renamed over
/// `installed`. On Windows, where a running program can be renamed but not
/// replaced, `installed` becomes `kv.exe.old` and `new_binary` takes its
/// name; if that second step fails the first is undone.
///
/// On any error `installed` is unchanged. The error is `NotWritable` with
/// the folder when permission was refused, otherwise `Swap`.
#[cfg(windows)]
pub fn swap(installed: &Path, new_binary: &Path) -> Result<Swapped, UpdateError> {
    let dir = folder(installed)?;
    let backup = installed.with_file_name("kv.exe.old");
    // An old one left by an earlier update; it may still be running, in
    // which case the rename below reports it.
    let _ = fs::remove_file(&backup);
    fs::rename(installed, &backup)
        .map_err(|e| swap_error(dir, "could not move the old kv aside", e))?;
    if let Err(e) = fs::rename(new_binary, installed) {
        if let Err(back) = fs::rename(&backup, installed) {
            return Err(UpdateError::Swap(format!(
                "could not move the new kv into place ({e}), nor the old one back ({back}); \
                 it is at {}",
                backup.display()
            )));
        }
        return Err(swap_error(dir, "could not move the new kv into place", e));
    }
    Ok(Swapped {
        installed: installed.to_path_buf(),
        backup,
    })
}

/// Removes the `kv.exe.old` an update left beside `installed` on Windows.
/// A failure is ignored: the old kv may still be running. On unix there is
/// nothing to do. Called as each kv command starts, so the first command
/// the new binary runs clears it.
pub fn clean_old(installed: &Path) {
    #[cfg(windows)]
    {
        let _ = fs::remove_file(installed.with_file_name("kv.exe.old"));
    }
    #[cfg(not(windows))]
    {
        let _ = installed;
    }
}
