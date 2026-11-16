//! What kv remembers between update checks: when it last asked GitHub,
//! what it found, and which version it has already told the user about.
//! Nothing here is secret.

use std::fs;
use std::io;
use std::path::Path;
use std::time::Duration;

use semver::Version;
use serde::{Deserialize, Serialize};

/// How long after it starts the tray makes its first check.
pub const TRAY_FIRST: Duration = Duration::from_secs(3 * 60);
/// How often the tray checks after that.
pub const TRAY_EVERY: Duration = Duration::from_secs(12 * 60 * 60);
/// The least time between automatic checks by `kv status` and `kv tui`.
pub const CLI_EVERY: Duration = Duration::from_secs(24 * 60 * 60);

/// The remembered result of update checks. Times are unix seconds;
/// versions are written without the leading `v`.
#[derive(Serialize, Deserialize, Default, Clone, Debug, PartialEq)]
pub struct UpdateState {
    /// When the last successful check finished.
    pub last_check: Option<u64>,
    /// The newest version that check found.
    pub latest: Option<String>,
    /// The version the user was last notified about, so it is said once.
    pub announced: Option<String>,
}

/// Reads the state file. A missing or unreadable file means nothing is
/// remembered yet.
pub fn load(path: &Path) -> UpdateState {
    fs::read(path)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

/// Writes the state file by writing a temporary file beside it and
/// renaming it into place, so a crash never leaves half a file.
pub fn save(path: &Path, state: &UpdateState) -> io::Result<()> {
    let json = serde_json::to_vec_pretty(state).map_err(io::Error::other)?;
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = Path::new(&tmp);
    fs::write(tmp, json)?;
    fs::rename(tmp, path).inspect_err(|_| {
        let _ = fs::remove_file(tmp);
    })
}

/// Whether a check is due: nothing was checked yet, or at least `every`
/// has passed since the last one. A clock that moved backwards is not due.
pub fn due(state: &UpdateState, now: u64, every: Duration) -> bool {
    match state.last_check {
        None => true,
        Some(last) => now.saturating_sub(last) >= every.as_secs(),
    }
}

/// The remembered latest version, if it is newer than `current`. A
/// remembered version that does not parse counts as none.
pub fn newer_known(state: &UpdateState, current: &Version) -> Option<Version> {
    let latest = Version::parse(state.latest.as_deref()?).ok()?;
    (latest > *current).then_some(latest)
}
