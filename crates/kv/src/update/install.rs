//! Installing an offered release: download it, check it, and swap it in
//! for the running binary. Nothing touches the installed kv until every
//! check has passed, and the work folder is removed whatever happens.

use std::fs::{File, TryLockError};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use reqwest::Client;
use semver::Version;

use super::swap::{Swapped, swap};
use super::{Asset, Offer, UpdateError, archive};

/// The most of a `.sha256` file kv will read: 4 KiB.
const MAX_CHECKSUM: u64 = 4 * 1024;
/// The most of a release archive kv will download: 64 MiB.
const MAX_ARCHIVE: u64 = 64 * 1024 * 1024;
/// How long the new binary has to answer `--version`.
const VERSION_TIMEOUT: Duration = Duration::from_secs(10);

/// How the work folder's name starts.
const WORK_PREFIX: &str = ".kv-update-";

/// The binary's name in the work folder.
#[cfg(windows)]
const NEW_BINARY: &str = "kv.exe";
/// The binary's name in the work folder.
#[cfg(not(windows))]
const NEW_BINARY: &str = "kv";

/// What `install` needs to know about this kv.
#[derive(Clone, Debug)]
pub struct InstallOptions {
    /// The binary to replace, symlinks already resolved (see
    /// [`installed_exe`](super::swap::installed_exe)).
    pub installed: PathBuf,
    /// Whether this kv came from the release build. Only those update.
    pub release_build: bool,
}

/// A finished update.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Installed {
    /// The version now installed.
    pub version: Version,
    /// Where the new and the old binary are.
    pub swapped: Swapped,
}

/// The lock file in `dir`, the folder of the binary an update replaces.
const LOCK_NAME: &str = ".kv-update.lock";

/// Takes the lock that lets one update at a time replace the binary in
/// `dir`, its folder, so two kv using different `KV_HOME`s but the same
/// binary cannot both update it. It is held until the returned file is
/// dropped or the process exits. It does not wait: if another kv holds it,
/// the answer is `Busy` at once. The lock file stays in `dir`.
pub fn update_lock(dir: &Path) -> Result<File, UpdateError> {
    let file = File::options()
        .create(true)
        .truncate(false)
        .write(true)
        .open(dir.join(LOCK_NAME))
        .map_err(|e| match e.kind() {
            io::ErrorKind::PermissionDenied | io::ErrorKind::ReadOnlyFilesystem => {
                UpdateError::NotWritable(dir.to_path_buf())
            }
            _ => UpdateError::Swap(format!("could not take the update lock: {e}")),
        })?;
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(TryLockError::WouldBlock) => Err(UpdateError::Busy),
        Err(TryLockError::Error(e)) => Err(UpdateError::Swap(format!(
            "could not take the update lock: {e}"
        ))),
    }
}

/// Downloads `offer` and puts it in place of `opts.installed`, keeping the
/// old binary beside it.
///
/// In order: refuses a build that is not from the release build, takes the
/// update lock in the installed binary's folder (held until the swap is
/// done), stops with `AlreadyInstalled` if the installed binary already
/// answers `--version` with the offered version (an earlier update put it
/// there; nothing is downloaded and the backups stay as they are), removes
/// work folders an interrupted update left, makes a work folder beside the
/// installed binary, downloads
/// the checksum (at most 4 KiB) and the archive (at most 64 MiB, and no
/// more than the release announced), checks the archive against the
/// checksum, unpacks the binary, runs it with `--version` and expects
/// `kv <version>`, and only then swaps it in. The work folder is removed
/// on every outcome, and on any failure the installed binary is unchanged.
///
/// Pass [`download_client`](super::check::download_client): its longer
/// timeout leaves room for a large archive on a slow connection.
pub async fn install(
    client: &Client,
    offer: &Offer,
    opts: &InstallOptions,
) -> Result<Installed, UpdateError> {
    if !opts.release_build {
        return Err(UpdateError::NotReleaseBuild);
    }
    let dir = opts
        .installed
        .parent()
        .ok_or_else(|| UpdateError::Swap(format!("{} has no folder", opts.installed.display())))?;
    // Held through the swap below: dropped only when this returns.
    let _lock = update_lock(dir)?;
    // Installing it again would put the new kv in place of the backup too,
    // leaving no way back.
    if check_version(&opts.installed, &offer.version).await.is_ok() {
        return Err(UpdateError::AlreadyInstalled(offer.version.to_string()));
    }
    remove_stale_work(dir);
    // In the same folder, so the final rename stays on one filesystem.
    // Dropping it removes it and everything in it.
    let work = tempfile::Builder::new()
        .prefix(WORK_PREFIX)
        .tempdir_in(dir)
        .map_err(|e| match e.kind() {
            io::ErrorKind::PermissionDenied | io::ErrorKind::ReadOnlyFilesystem => {
                UpdateError::NotWritable(dir.to_path_buf())
            }
            _ => UpdateError::Swap(format!("could not make a folder in {}: {e}", dir.display())),
        })?;

    let checksum = download_checksum(client, &offer.checksum).await?;
    let archive_path = work.path().join("archive");
    download_archive(client, &offer.archive, &archive_path).await?;

    let new_binary = work.path().join(NEW_BINARY);
    let unpack = {
        let (archive_path, new_binary) = (archive_path.clone(), new_binary.clone());
        tokio::task::spawn_blocking(move || {
            archive::verify_sha256(&archive_path, &checksum)?;
            archive::extract_binary(&archive_path, &new_binary)
        })
    };
    unpack
        .await
        .map_err(|e| UpdateError::Swap(format!("unpacking stopped: {e}")))??;

    check_version(&new_binary, &offer.version).await?;
    sync_to_disk(&new_binary)?;
    let swapped = swap(&opts.installed, &new_binary)?;
    drop(work);
    Ok(Installed {
        version: offer.version.clone(),
        swapped,
    })
}

/// Removes the work folders an earlier update left in `dir`, as one
/// stopped with Ctrl-C does. Called with the update lock held, so no update
/// is using them; the lock file itself is not a work folder and stays.
/// Failures are ignored.
fn remove_stale_work(dir: &Path) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let stale = entry
            .file_name()
            .to_str()
            .is_some_and(|name| name.starts_with(WORK_PREFIX) && name != LOCK_NAME)
            && entry.file_type().is_ok_and(|kind| kind.is_dir());
        if stale {
            let _ = std::fs::remove_dir_all(entry.path());
        }
    }
}

fn network(e: reqwest::Error) -> UpdateError {
    UpdateError::Network(e.without_url().to_string())
}

/// Sends a GET for `asset` and hands each piece of the body to `sink`,
/// refusing the download once it passes `limit` bytes.
async fn download(
    client: &Client,
    asset: &Asset,
    limit: u64,
    what: &'static str,
    mut sink: impl FnMut(&[u8]) -> Result<(), UpdateError>,
) -> Result<(), UpdateError> {
    let too_large = || UpdateError::TooLarge(what);
    let mut response = client
        .get(asset.url.clone())
        .send()
        .await
        .map_err(network)?;
    let status = response.status();
    if !status.is_success() {
        return Err(UpdateError::Network(format!("GitHub answered {status}")));
    }
    if response.content_length().is_some_and(|len| len > limit) {
        return Err(too_large());
    }
    let mut received: u64 = 0;
    while let Some(chunk) = response.chunk().await.map_err(network)? {
        received += chunk.len() as u64;
        if received > limit {
            return Err(too_large());
        }
        sink(&chunk)?;
    }
    Ok(())
}

/// Downloads and reads the release's `.sha256` file.
async fn download_checksum(client: &Client, asset: &Asset) -> Result<[u8; 32], UpdateError> {
    let mut body = Vec::new();
    download(client, asset, MAX_CHECKSUM, "checksum file", |chunk| {
        body.extend_from_slice(chunk);
        Ok(())
    })
    .await?;
    let text = std::str::from_utf8(&body)
        .map_err(|_| UpdateError::Malformed("the checksum file is not text".to_string()))?;
    archive::parse_sha256(text)
}

/// Downloads the release archive to `out`: at most 64 MiB, and no more
/// than the size the release announced.
async fn download_archive(client: &Client, asset: &Asset, out: &Path) -> Result<(), UpdateError> {
    if asset.size > MAX_ARCHIVE {
        return Err(UpdateError::TooLarge("release archive"));
    }
    let write_err = |e: io::Error| UpdateError::Swap(format!("could not save the download: {e}"));
    let mut file = File::create(out).map_err(write_err)?;
    download(client, asset, asset.size, "release archive", |chunk| {
        file.write_all(chunk).map_err(write_err)
    })
    .await
}

/// Makes sure the new binary's bytes are on disk before it is renamed into
/// place, so a crash right after the swap cannot leave an empty or partly
/// written kv behind.
fn sync_to_disk(binary: &Path) -> Result<(), UpdateError> {
    let mut open = File::options();
    // Windows needs write access to flush a file; unix syncs a read-only
    // handle, and a writable one could make the new kv briefly "busy".
    open.read(true).write(cfg!(windows));
    open.open(binary)
        .and_then(|file| file.sync_all())
        .map_err(|e| UpdateError::Swap(format!("could not save the new kv to disk: {e}")))
}

/// Runs the new binary with `--version` and checks it prints
/// `kv <expected>`. It is killed if it takes longer than ten seconds. A
/// binary that cannot be started, fails, or prints nothing is `WontRun`;
/// one that prints another version is `WrongVersion`.
async fn check_version(binary: &Path, expected: &Version) -> Result<(), UpdateError> {
    let wont_run = |e: &dyn std::fmt::Display| UpdateError::WontRun(e.to_string());
    // A file written a moment ago can be briefly "busy" on Linux while a
    // child another thread is starting still holds it open.
    let mut tries = 0;
    let output = loop {
        let mut command = tokio::process::Command::new(binary);
        command
            .arg("--version")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true);
        // The tray has no console, so without this a console program it
        // starts flashes a window of its own.
        #[cfg(windows)]
        command.creation_flags(windows_sys::Win32::System::Threading::CREATE_NO_WINDOW);
        let run = command.output();
        match tokio::time::timeout(VERSION_TIMEOUT, run).await {
            Err(_) => return Err(wont_run(&"it did not answer --version in time")),
            Ok(Err(e)) if e.kind() == io::ErrorKind::ExecutableFileBusy && tries < 20 => {
                tries += 1;
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Ok(Err(e)) => return Err(wont_run(&e)),
            Ok(Ok(output)) => break output,
        }
    };
    if !output.status.success() {
        return Err(wont_run(&format!("--version ended with {}", output.status)));
    }
    let printed = String::from_utf8_lossy(&output.stdout);
    let printed = printed.trim();
    if printed == format!("kv {expected}") {
        return Ok(());
    }
    let found: String = printed
        .lines()
        .next()
        .map(|line| line.strip_prefix("kv ").unwrap_or(line))
        .unwrap_or("")
        .chars()
        .take(64)
        .collect();
    if found.is_empty() {
        return Err(wont_run(&"--version printed nothing"));
    }
    Err(UpdateError::WrongVersion {
        expected: expected.to_string(),
        found,
    })
}
