//! Self-update: kv checks for a newer release, asks, and replaces itself.
//! This is the shared part: what a release looks like, where kv looks for
//! one, and the errors the steps can end in.

use std::ffi::OsStr;
use std::fmt;
use std::path::PathBuf;
use std::str::FromStr;

use semver::Version;

use crate::notify::Level;

pub mod check;

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
