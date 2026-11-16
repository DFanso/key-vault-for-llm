//! What kv remembers between update checks: when it last asked GitHub,
//! what it found, and which version it has already told the user about.
//! Nothing here is secret.

use std::fs;
use std::io::{self, Write};
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

/// Writes the state file by writing a temporary file of its own beside it
/// and renaming it into place, so a crash never leaves half a file and two
/// kv processes saving at once (`kv status` beside the tray, say) never
/// write into the same temporary file. The last rename wins.
pub fn save(path: &Path, state: &UpdateState) -> io::Result<()> {
    let json = serde_json::to_vec_pretty(state).map_err(io::Error::other)?;
    let dir = match path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir,
        _ => Path::new("."),
    };
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    // Removed if anything below fails.
    let mut tmp = tempfile::Builder::new()
        .prefix(&format!(".{name}."))
        .suffix(".tmp")
        .tempfile_in(dir)?;
    tmp.write_all(&json)?;
    tmp.persist(path).map(drop).map_err(|e| e.error)
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
