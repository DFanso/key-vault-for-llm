//! The tray's side of self-update: asking GitHub, installing what the user
//! agreed to, and handing over to a tray running the new binary.

use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::sleep;
use std::time::{Duration, Instant};

use futures_util::future::BoxFuture;
use semver::Version;

use crate::paths::Paths;
use crate::update::install::{self, InstallOptions, Installed};
use crate::update::{self as updating, LATEST_URL, Offer, UpdateError, check, swap};

/// How many times the tray starts its successor before giving up.
const ATTEMPTS: usize = 3;
/// How long each successor has to say it is up: to take the tray lock and
/// show its icon. Its own wait for the lock is 5 seconds of that.
pub const START_WAIT: Duration = Duration::from_secs(10);
/// How often the tray looks whether its successor is up.
const POLL: Duration = Duration::from_millis(50);
/// How long the tray tries to take its lock back when no successor came up.
const RELOCK_WAIT: Duration = Duration::from_secs(3);

/// What the tray's worker needs to update kv. The real one asks GitHub and
/// replaces the installed binary; tests script the answers.
pub trait Updater: Send + Sync {
    /// Asks GitHub for a newer release.
    fn check(&self) -> BoxFuture<'static, Result<Option<Offer>, UpdateError>>;
    /// Downloads, verifies and swaps in `offer`.
    fn install(&self, offer: Offer) -> BoxFuture<'static, Result<Installed, UpdateError>>;
    /// Starts a tray on the new binary and makes sure it came up: on `Ok`
    /// this tray quits. On `Err` this tray keeps running, and has taken its
    /// lock back unless the text says it could not; the text says what the
    /// user can do.
    fn restart(&self, installed: &Installed) -> Result<(), String>;
}

/// The updater `kv tray` runs with.
pub struct Release {
    paths: Paths,
    /// The tray lock, which the restart hands over to the new tray.
    lock: Arc<Mutex<Option<File>>>,
    /// The installed binary, found as the tray started: once it is
    /// replaced, the running one may no longer be found by its own path.
    installed: Result<PathBuf, String>,
}

impl Release {
    pub fn new(paths: Paths, lock: Arc<Mutex<Option<File>>>) -> Release {
        Release {
            paths,
            lock,
            installed: swap::installed_exe()
                .map_err(|e| format!("could not find the running kv: {e}")),
        }
    }
}

impl Updater for Release {
    fn check(&self) -> BoxFuture<'static, Result<Option<Offer>, UpdateError>> {
        Box::pin(async {
            let target = updating::target()
                .ok_or_else(|| UpdateError::NoAssetForTarget(std::env::consts::OS.into()))?;
            let client = check::client().map_err(|e| UpdateError::Network(e.to_string()))?;
            check::latest(&client, LATEST_URL, &updating::current_version(), target).await
        })
    }

    fn install(&self, offer: Offer) -> BoxFuture<'static, Result<Installed, UpdateError>> {
        let installed = self.installed.clone();
        Box::pin(async move {
            let opts = InstallOptions {
                installed: installed.map_err(UpdateError::Swap)?,
                release_build: updating::is_release_build(),
            };
            let client =
                check::download_client().map_err(|e| UpdateError::Network(e.to_string()))?;
            install::install(&client, &offer, &opts).await
        })
    }

    fn restart(&self, installed: &Installed) -> Result<(), String> {
        restart_after_update(&self.lock, installed, &self.paths, START_WAIT)
    }
}

/// Hands the tray over to the kv just `installed`: lets go of the tray
/// lock, then up to three times starts
/// `kv tray --after-update <version> --ready-file <file>` and waits up to
/// `wait` for it to say it is up, by creating that file once its icon
/// shows, while still running. A successor that exits, or does not say so
/// in time, does not count, and one still running when its time is up is
/// stopped.
///
/// If none comes up, this tray keeps running: it tries for a few seconds
/// to take its lock back, and the error says what the user can do, and
/// that the lock could not be taken back if so.
pub fn restart_after_update(
    lock: &Arc<Mutex<Option<File>>>,
    installed: &Installed,
    paths: &Paths,
    wait: Duration,
) -> Result<(), String> {
    let (exe, version) = (&installed.swapped.installed, &installed.version);
    let ready = paths.tray_ready_file();
    let mut held = lock.lock().unwrap_or_else(PoisonError::into_inner);
    drop(held.take());
    for _ in 0..ATTEMPTS {
        let up = successor_came_up(exe, version, &ready, wait);
        let _ = fs::remove_file(&ready);
        if up {
            return Ok(());
        }
    }
    let mut message = not_started_text(version);
    message.push(' ');
    message.push_str(&swap::way_back(&installed.swapped));
    match super::lock_single_retry(paths, RELOCK_WAIT) {
        Ok(file) => *held = Some(file),
        Err(e) => message.push_str(&format!(" (kv tray could not take its lock back: {e}.)")),
    }
    Err(message)
}

/// What the old tray says when no tray on the new kv came up, short of
/// how to go back.
pub fn not_started_text(version: &Version) -> String {
    let mut text = format!(
        "kv {version} is installed, but the new tray didn't start, so this kv tray is still \
         the old one. Quit kv tray and start it again, or log out and back in, to finish the \
         update."
    );
    if cfg!(target_os = "macos") {
        text.push_str(
            " macOS may ask for your login password once before Touch ID works again; choose \
             Always Allow.",
        );
    }
    text
}

/// Starts one successor and waits for it to create `ready`, which it does
/// once its icon is up, while it still runs.
fn successor_came_up(exe: &Path, version: &Version, ready: &Path, wait: Duration) -> bool {
    // One left from before would say a successor is up that is not.
    let _ = fs::remove_file(ready);
    let mut command = Command::new(exe);
    command
        .arg("tray")
        .arg("--after-update")
        .arg(version.to_string())
        .arg("--ready-file")
        .arg(ready)
        // It outlives this tray: it must not hold on to this one's output.
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // Out of a terminal's job control, should this tray have one. On
        // macOS it also keeps launchd from killing the successor when the
        // old tray, started by the LaunchAgent, exits: launchd stops the
        // job's whole process group then.
        command.process_group(0);
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        use windows_sys::Win32::System::Threading::CREATE_NO_WINDOW;
        // A console of its own that is never shown, as for the daemon.
        command.creation_flags(CREATE_NO_WINDOW);
    }
    // A file written a moment ago can be briefly "busy" on Linux while a
    // child another thread is starting still holds it open.
    let mut tries = 0;
    let mut child = loop {
        match command.spawn() {
            Ok(child) => break child,
            Err(e) if e.kind() == std::io::ErrorKind::ExecutableFileBusy && tries < 20 => {
                tries += 1;
                sleep(Duration::from_millis(50));
            }
            Err(_) => return false,
        }
    };
    let deadline = Instant::now() + wait;
    loop {
        // A successor that said it is up and then exited is not up.
        if !matches!(child.try_wait(), Ok(None)) {
            return false;
        }
        if ready.exists() && matches!(child.try_wait(), Ok(None)) {
            return true;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return false;
        }
        sleep(POLL);
    }
}

/// What the new tray says when it starts after an update.
pub fn updated_text(version: &Version) -> String {
    let mut text = format!("Updated to kv {version}. Unlock to continue.");
    if cfg!(target_os = "macos") {
        text.push_str(
            " macOS will ask for your login password once before Touch ID works again; choose \
             Always Allow.",
        );
    }
    text
}
