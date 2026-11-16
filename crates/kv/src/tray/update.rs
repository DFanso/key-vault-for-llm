//! The tray's side of self-update: asking GitHub, installing what the user
//! agreed to, and handing over to a tray running the new binary.

use std::fs::File;
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
/// How long each successor has to take the tray lock.
const START_WAIT: Duration = Duration::from_secs(5);
/// How often the tray looks whether its successor is up.
const POLL: Duration = Duration::from_millis(50);

/// What the tray's worker needs to update kv. The real one asks GitHub and
/// replaces the installed binary; tests script the answers.
pub trait Updater: Send + Sync {
    /// Asks GitHub for a newer release.
    fn check(&self) -> BoxFuture<'static, Result<Option<Offer>, UpdateError>>;
    /// Downloads, verifies and swaps in `offer`.
    fn install(&self, offer: Offer) -> BoxFuture<'static, Result<Installed, UpdateError>>;
    /// Starts a tray on the new binary and makes sure it came up. On `Err`
    /// this tray still holds its lock and keeps running; the text says what
    /// the user can do.
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
        restart_after_update(&self.lock, installed, &self.paths)
    }
}

/// Hands the tray over to the kv just `installed`: lets go of the tray
/// lock, then up to three times starts `kv tray --after-update <version>`
/// and waits up to 5 seconds for it to take the lock. A successor that
/// exits, or never takes the lock, does not count, and one still running
/// when its time is up is stopped. If none comes up this tray takes its
/// lock back, to keep running, and the error says what the user can do.
pub fn restart_after_update(
    lock: &Arc<Mutex<Option<File>>>,
    installed: &Installed,
    paths: &Paths,
) -> Result<(), String> {
    let (exe, version) = (&installed.swapped.installed, &installed.version);
    let mut held = lock.lock().unwrap_or_else(PoisonError::into_inner);
    drop(held.take());
    for _ in 0..ATTEMPTS {
        if successor_came_up(exe, version, paths) {
            return Ok(());
        }
    }
    *held = super::lock_single(paths).ok();
    Err(format!(
        "kv {version} is installed, but the new tray didn't start. Quit kv tray and start it \
         again, or log out and back in. {}",
        swap::way_back(&installed.swapped)
    ))
}

/// Starts one successor and waits for it to hold the tray lock.
fn successor_came_up(exe: &Path, version: &Version, paths: &Paths) -> bool {
    let mut command = Command::new(exe);
    command
        .arg("tray")
        .arg("--after-update")
        .arg(version.to_string())
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
    let Ok(mut child) = command.spawn() else {
        return false;
    };
    let deadline = Instant::now() + START_WAIT;
    loop {
        // The lock alone could be another tray's: the successor must also
        // still be running.
        if !matches!(child.try_wait(), Ok(None)) {
            return false;
        }
        if super::is_running(paths) && matches!(child.try_wait(), Ok(None)) {
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
