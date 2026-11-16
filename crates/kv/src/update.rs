//! Self-update: kv checks for a newer release, asks, and replaces itself.
//! This is the shared part: what a release looks like, where kv looks for
//! one, and the errors the steps can end in.

use std::ffi::OsStr;
use std::fmt;
use std::path::PathBuf;
use std::str::FromStr;

use semver::Version;

use crate::notify::Level;

pub mod archive;
pub mod check;
pub mod install;
pub mod state;
pub mod swap;

/// Where the latest release is described. Nothing can change it: not an
/// environment variable, a flag or a setting.
pub const LATEST_URL: &str =
    "https://api.github.com/repos/DFanso/key-vault-for-llm/releases/latest";

/// The version of this build.
pub fn current_version() -> Version {
    Version::parse(env!("CARGO_PKG_VERSION")).expect("CARGO_PKG_VERSION is semver")
}

/// The release target this build belongs to, or `None` on a platform kv
/// does not publish releases for.
pub fn target() -> Option<&'static str> {
    if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        Some("aarch64-apple-darwin")
    } else if cfg!(all(target_os = "macos", target_arch = "x86_64")) {
        Some("x86_64-apple-darwin")
    } else if cfg!(all(target_os = "linux", target_arch = "aarch64")) {
        Some("aarch64-unknown-linux-gnu")
    } else if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        Some("x86_64-unknown-linux-gnu")
    } else if cfg!(all(windows, target_arch = "x86_64")) {
        Some("x86_64-pc-windows-msvc")
    } else {
        None
    }
}

/// The release archive for `target`: a zip on Windows, a `.tar.xz`
/// elsewhere.
pub fn archive_name(target: &str) -> String {
    if target.contains("windows") {
        format!("kv-{target}.zip")
    } else {
        format!("kv-{target}.tar.xz")
    }
}

/// Whether this binary came from the release build. Only those update
/// themselves; a source build or `cargo install` does not.
pub fn is_release_build() -> bool {
    cfg!(feature = "release-build")
}

/// Whether automatic checks are on, given `KV_UPDATE_CHECK`. Unset or not
/// understood is on; `off` and kv's other boolean "off" words turn them
/// off. An explicit `kv update` checks regardless.
pub fn checks_enabled(value: Option<&OsStr>) -> bool {
    let Some(value) = value.and_then(OsStr::to_str) else {
        return true;
    };
    Level::from_str(value) != Ok(Level::Off)
}

/// The version a release tag names. The tag must be `v` followed by a
/// semantic version, and a pre-release is never offered.
pub fn parse_tag(tag: &str) -> Option<Version> {
    let version = Version::parse(tag.strip_prefix('v')?).ok()?;
    version.pre.is_empty().then_some(version)
}

/// One file attached to a release.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Asset {
    /// The file name.
    pub name: String,
    /// Where to download it.
    pub url: url::Url,
    /// Its size in bytes, as GitHub reports it.
    pub size: u64,
}

/// A newer release this build could update to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Offer {
    /// The version offered.
    pub version: Version,
    /// The release page, where the notes are.
    pub notes_url: String,
    /// The archive for this platform.
    pub archive: Asset,
    /// Its `.sha256` file.
    pub checksum: Asset,
}

/// Why checking for or installing an update did not finish.
#[derive(Debug, PartialEq, Eq)]
pub enum UpdateError {
    /// GitHub could not be reached or a download broke off.
    Network(String),
    /// What came back was not what a release looks like.
    Malformed(String),
    /// GitHub is limiting how often kv may ask.
    RateLimited,
    /// This build was not made by the release build.
    NotReleaseBuild,
    /// The folder holding kv cannot be written to.
    NotWritable(PathBuf),
    /// The release has no archive for this platform.
    NoAssetForTarget(String),
    /// The download does not match its checksum.
    ChecksumMismatch,
    /// A download or the file inside it is bigger than allowed.
    TooLarge(&'static str),
    /// The new binary is not the version the release announced.
    WrongVersion {
        /// The version the release announced.
        expected: String,
        /// The version the new binary reported.
        found: String,
    },
    /// Another update is already running.
    Busy,
    /// kv tray is running and has to be quit first.
    TrayRunning,
    /// Replacing the binary failed.
    Swap(String),
}

impl fmt::Display for UpdateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Network(e) => write!(f, "could not reach GitHub: {e}"),
            Self::Malformed(e) => write!(f, "GitHub's answer was not a release: {e}"),
            Self::RateLimited => write!(f, "GitHub is limiting requests; try again later"),
            Self::NotReleaseBuild => write!(
                f,
                "this kv was not installed from a release, so it cannot update itself"
            ),
            Self::NotWritable(dir) => write!(f, "cannot write to {}", dir.display()),
            Self::NoAssetForTarget(target) => {
                write!(f, "this release has no download for {target}")
            }
            Self::ChecksumMismatch => write!(f, "the download does not match its checksum"),
            Self::TooLarge(what) => write!(f, "the {what} is larger than allowed"),
            Self::WrongVersion { expected, found } => {
                write!(f, "the new kv reports version {found}, not {expected}")
            }
            Self::Busy => write!(f, "another kv update is running"),
            Self::TrayRunning => write!(f, "kv tray is running; quit it and try again"),
            Self::Swap(e) => write!(f, "could not replace kv: {e}"),
        }
    }
}

impl std::error::Error for UpdateError {}

/// The line `kv status` and `kv tui` print when a newer kv is out, or
/// `None`. It asks GitHub at most once a day (`now` is unix seconds), and
/// only in a release build, with checks on, and with no tray running (the
/// tray tells the user itself). The ask gives up after 3 seconds. Nothing
/// that goes wrong is reported.
pub async fn update_notice(paths: &crate::paths::Paths, now: u64) -> Option<String> {
    if !is_release_build() || !checks_enabled(std::env::var_os("KV_UPDATE_CHECK").as_deref()) {
        return None;
    }
    if crate::tray::is_running(paths) {
        return None;
    }
    let file = paths.update_state_file();
    let remembered = state::load(&file);
    if !state::due(&remembered, now, state::CLI_EVERY) {
        return None;
    }
    let current = current_version();
    let client = check::client().ok()?;
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        check::latest(&client, LATEST_URL, &current, target()?),
    )
    .await
    .unwrap_or_else(|_| Err(UpdateError::Network("timed out".into())));
    let (remembered, notice) = after_check(remembered, now, &current, result);
    let _ = file.parent().map(std::fs::create_dir_all);
    let _ = state::save(&file, &remembered);
    notice
}

/// What an automatic check leaves behind: the new state, and the notice to
/// print. The attempt is counted even when it failed (so an offline kv does
/// not ask again until tomorrow) and the remembered `latest` is kept then,
/// so a newer version found earlier is still announced. A success replaces
/// `latest`: with no newer release it is cleared.
fn after_check(
    mut state: state::UpdateState,
    now: u64,
    current: &semver::Version,
    result: Result<Option<Offer>, UpdateError>,
) -> (state::UpdateState, Option<String>) {
    state.last_check = Some(now);
    if let Ok(offer) = result {
        state.latest = offer.map(|o| o.version.to_string());
    }
    let notice = state::newer_known(&state, current)
        .map(|version| format!("kv {version} is out: run `kv update`."));
    (state, notice)
}

#[cfg(test)]
mod notice_tests {
    use super::*;

    fn offer(version: &str) -> Offer {
        let asset = |name: &str| Asset {
            name: name.into(),
            url: "https://github.com/x".parse().unwrap(),
            size: 1,
        };
        Offer {
            version: Version::parse(version).unwrap(),
            notes_url: "https://github.com/x".into(),
            archive: asset("a"),
            checksum: asset("a.sha256"),
        }
    }

    fn remembered(latest: &str) -> state::UpdateState {
        state::UpdateState {
            last_check: Some(1),
            latest: Some(latest.into()),
            announced: None,
        }
    }

    #[test]
    fn a_failed_check_is_counted_and_keeps_what_was_known() {
        let current = Version::parse("1.8.0").unwrap();
        let (state, notice) = after_check(
            remembered("1.9.0"),
            500,
            &current,
            Err(UpdateError::RateLimited),
        );
        assert_eq!(state.last_check, Some(500));
        assert_eq!(state.latest.as_deref(), Some("1.9.0"));
        assert_eq!(notice.as_deref(), Some("kv 1.9.0 is out: run `kv update`."));
    }

    #[test]
    fn a_failed_check_with_nothing_known_says_nothing() {
        let current = Version::parse("1.8.0").unwrap();
        let (state, notice) = after_check(
            state::UpdateState::default(),
            500,
            &current,
            Err(UpdateError::Network("down".into())),
        );
        assert_eq!(state.last_check, Some(500));
        assert_eq!(notice, None);
    }

    #[test]
    fn finding_nothing_newer_clears_latest() {
        let current = Version::parse("1.8.0").unwrap();
        let (state, notice) = after_check(remembered("1.9.0"), 500, &current, Ok(None));
        assert_eq!(state.latest, None);
        assert_eq!(notice, None);
    }

    #[test]
    fn finding_a_release_records_it_and_says_so() {
        let current = Version::parse("1.8.0").unwrap();
        let (state, notice) = after_check(
            state::UpdateState::default(),
            500,
            &current,
            Ok(Some(offer("1.9.1"))),
        );
        assert_eq!(state.latest.as_deref(), Some("1.9.1"));
        assert_eq!(state.last_check, Some(500));
        assert_eq!(notice.as_deref(), Some("kv 1.9.1 is out: run `kv update`."));
    }
}
