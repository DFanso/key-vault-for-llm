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
    /// The old binary: `kv.previous` on unix, `kv.exe.old` (or
    /// `kv.exe.<n>.old`) on Windows.
    pub backup: PathBuf,
}

/// The path of the running kv, with symlinks resolved, so an update
/// replaces the real file and a link such as `~/.cargo/bin/kv` keeps
/// pointing at it.
pub fn installed_exe() -> io::Result<PathBuf> {
    running_exe()?.canonicalize()
}

/// The path this kv was started from, as [`std::env::current_exe`] gives
/// it, except after an update on Linux: once a new kv is renamed over the
/// running one, Linux reports the old path with " (deleted)" added. Then
/// the path without it is the answer, if a file is there: the new kv, which
/// a kv still running from before the update (`kv mcp`, say) starts the
/// daemon from and expects the daemon to run.
pub fn running_exe() -> io::Result<PathBuf> {
    let exe = std::env::current_exe()?;
    #[cfg(target_os = "linux")]
    let exe = without_deleted_mark(exe);
    Ok(exe)
}

/// `path` without the " (deleted)" Linux adds to the program path of a
/// process whose file was replaced, when a file is at the shorter path;
/// otherwise `path` as it is.
#[cfg(unix)]
pub fn without_deleted_mark(path: PathBuf) -> PathBuf {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;
    match path.as_os_str().as_bytes().strip_suffix(b" (deleted)") {
        Some(shorter) if Path::new(OsStr::from_bytes(shorter)).is_file() => {
            PathBuf::from(OsStr::from_bytes(shorter))
        }
        _ => path,
    }
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
/// replaced, `installed` becomes `kv.exe.old` (or `kv.exe.<n>.old`, when
/// an older one is still running and cannot be removed) and `new_binary`
/// takes its name; if that second step fails the first is undone.
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
/// replaced, `installed` becomes `kv.exe.old` (or `kv.exe.<n>.old`, when
/// an older one is still running and cannot be removed) and `new_binary`
/// takes its name; if that second step fails the first is undone.
///
/// On any error `installed` is unchanged. The error is `NotWritable` with
/// the folder when permission was refused, otherwise `Swap`.
#[cfg(windows)]
pub fn swap(installed: &Path, new_binary: &Path) -> Result<Swapped, UpdateError> {
    let dir = folder(installed)?;
    let backup = free_backup(installed);
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

/// Where the Windows swap moves the running kv: `kv.exe.old`, after
/// removing one an earlier update left. That one may still be running (an
/// agent session started before the earlier update), and then it cannot be
/// removed, so the first free `kv.exe.<n>.old` is used instead.
#[cfg(windows)]
fn free_backup(installed: &Path) -> PathBuf {
    let usable = |path: &Path| {
        let _ = fs::remove_file(path);
        fs::symlink_metadata(path).is_err()
    };
    let backup = installed.with_file_name("kv.exe.old");
    if usable(&backup) {
        return backup;
    }
    // Bounded, should every name be taken; the rename then says why.
    (1..=1000)
        .map(|n| installed.with_file_name(format!("kv.exe.{n}.old")))
        .find(|path| usable(path))
        .unwrap_or(backup)
}

/// How to go back to the old kv by hand, for the messages that say an
/// update went in but something after it failed: one sentence naming the
/// folder `installed` is in.
pub fn way_back(installed: &Path) -> String {
    let dir = installed.parent().unwrap_or(installed).display();
    if cfg!(windows) {
        format!("To go back, rename kv.exe.old to kv.exe in {dir}.")
    } else {
        format!("To go back, move kv.previous over kv in {dir}.")
    }
}

/// Whether `name` is an old binary a Windows update left behind:
/// `kv.exe.old`, or `kv.exe.<n>.old` when that was still running.
pub fn is_old_binary(name: &str) -> bool {
    name.strip_prefix("kv.exe.")
        .and_then(|rest| rest.strip_suffix("old"))
        .is_some_and(|middle| {
            middle.is_empty()
                || middle
                    .strip_suffix('.')
                    .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
        })
}

/// Removes the old binaries an update left beside `installed` on Windows
/// (see [`is_old_binary`]). A failure is ignored: an old kv may still be
/// running. On unix there is nothing to do: `kv.previous` stays, as the
/// way back. Called once the new kv has shown it works, after a command
/// succeeded or the tray came up, so the way back is there until then.
pub fn clean_old(installed: &Path) {
    #[cfg(windows)]
    if let Some(entries) = installed.parent().and_then(|dir| fs::read_dir(dir).ok()) {
        for entry in entries.flatten() {
            if entry.file_name().to_str().is_some_and(is_old_binary) {
                let _ = fs::remove_file(entry.path());
            }
        }
    }
    #[cfg(not(windows))]
    {
        let _ = installed;
    }
}
