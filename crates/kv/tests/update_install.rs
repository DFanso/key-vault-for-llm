//! Installing a release over the binary: download, checks, swap, and that
//! the old binary is untouched whenever anything fails. The release is
//! served by a local stand-in for GitHub.

use std::path::{Path, PathBuf};

use kv::paths::Paths;
use kv::update::install::{InstallOptions, install, update_lock};
use kv::update::{Asset, Offer, UpdateError};
use semver::Version;
use sha2::{Digest, Sha256};
use wiremock::matchers::{any, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const OLD: &[u8] = b"#!/bin/sh\necho 'kv 1.0.0'\n";

/// A shell script that answers `--version` the way kv `version` would.
#[cfg(unix)]
fn script(version: &str) -> Vec<u8> {
    format!("#!/bin/sh\necho 'kv {version}'\n").into_bytes()
}

/// A `.tar.xz` release archive holding `kv-x/kv` with `binary` in it.
#[cfg(unix)]
fn archive(binary: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut builder = tar::Builder::new(Vec::new());
    let mut h = tar::Header::new_gnu();
    h.set_path("kv-x/kv").unwrap();
    h.set_size(binary.len() as u64);
    h.set_mode(0o755);
    h.set_cksum();
    builder.append(&h, binary).unwrap();
    let tar_bytes = builder.into_inner().unwrap();
    let mut xz = Vec::new();
    let mut writer =
        lzma_rust2::XzWriter::new(&mut xz, lzma_rust2::XzOptions::with_preset(0)).unwrap();
    writer.write_all(&tar_bytes).unwrap();
    writer.finish().unwrap();
    xz
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Serves `archive` and a checksum file holding `checksum`, and returns
/// the offer that points at them.
async fn serve(archive: Vec<u8>, checksum: String) -> (MockServer, Offer) {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/kv.tar.xz"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(archive.clone()))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/kv.tar.xz.sha256"))
        .respond_with(ResponseTemplate::new(200).set_body_string(checksum.clone()))
        .mount(&server)
        .await;
    let offer = offer_at(&server, archive.len() as u64, checksum.len() as u64);
    (server, offer)
}

fn offer_at(server: &MockServer, archive_size: u64, checksum_size: u64) -> Offer {
    let url = |name: &str| url::Url::parse(&format!("{}/{name}", server.uri())).unwrap();
    Offer {
        version: Version::new(99, 0, 0),
        notes_url: "https://github.com/DFanso/key-vault-for-llm/releases/tag/v99.0.0".into(),
        archive: Asset {
            name: "kv.tar.xz".into(),
            url: url("kv.tar.xz"),
            size: archive_size,
        },
        checksum: Asset {
            name: "kv.tar.xz.sha256".into(),
            url: url("kv.tar.xz.sha256"),
            size: checksum_size,
        },
    }
}

/// A folder holding an installed `kv` with the old bytes, and kv's home.
struct Setup {
    _root: tempfile::TempDir,
    bin: PathBuf,
    installed: PathBuf,
    paths: Paths,
}

fn setup() -> Setup {
    let root = tempfile::tempdir().unwrap();
    let base = root.path().canonicalize().unwrap();
    let bin = base.join("bin");
    std::fs::create_dir(&bin).unwrap();
    let installed = bin.join("kv");
    std::fs::write(&installed, OLD).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&installed, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let paths = Paths::under(&base.join("home"));
    Setup {
        _root: root,
        bin,
        installed,
        paths,
    }
}

fn options(installed: &Path) -> InstallOptions {
    InstallOptions {
        installed: installed.to_path_buf(),
        release_build: true,
    }
}

/// The names in `dir`, sorted.
fn names(dir: &Path) -> Vec<String> {
    let mut names: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    names
}

/// What `program --version` prints. A file written a moment ago can be
/// briefly "busy" on Linux while another test's child holds it open.
#[cfg(unix)]
fn version_of(program: &Path) -> String {
    for _ in 0..50 {
        match std::process::Command::new(program)
            .arg("--version")
            .output()
        {
            Ok(out) => return String::from_utf8(out.stdout).unwrap().trim().to_string(),
            Err(e) if e.kind() == std::io::ErrorKind::ExecutableFileBusy => {
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            Err(e) => panic!("could not run {}: {e}", program.display()),
        }
    }
    panic!("{} stayed busy", program.display());
}

#[cfg(unix)]
#[tokio::test]
async fn installs_and_keeps_a_backup() {
    let s = setup();
    let new = script("99.0.0");
    let archive = archive(&new);
    let (_server, offer) = serve(archive.clone(), sha256_hex(&archive)).await;
    let client = kv::update::check::download_client().unwrap();

    let done = install(&client, &offer, &options(&s.installed), &s.paths)
        .await
        .unwrap();

    assert_eq!(done.version, Version::new(99, 0, 0));
    assert_eq!(done.swapped.installed, s.installed);
    assert_eq!(done.swapped.backup, s.bin.join("kv.previous"));
    assert_eq!(version_of(&s.installed), "kv 99.0.0");
    assert_eq!(std::fs::read(&s.installed).unwrap(), new);
    assert_eq!(std::fs::read(s.bin.join("kv.previous")).unwrap(), OLD);
    assert_eq!(names(&s.bin), ["kv", "kv.previous"]);
}

#[cfg(unix)]
#[tokio::test]
async fn replaces_an_older_backup() {
    let s = setup();
    std::fs::write(s.bin.join("kv.previous"), b"older still").unwrap();
    let archive = archive(&script("99.0.0"));
    let (_server, offer) = serve(archive.clone(), sha256_hex(&archive)).await;
    let client = kv::update::check::download_client().unwrap();

    install(&client, &offer, &options(&s.installed), &s.paths)
        .await
        .unwrap();

    assert_eq!(std::fs::read(s.bin.join("kv.previous")).unwrap(), OLD);
    assert_eq!(names(&s.bin), ["kv", "kv.previous"]);
}

#[tokio::test]
async fn checksum_mismatch_leaves_old_binary() {
    let s = setup();
    // Checked before anything is unpacked, so the bytes need not be an
    // archive.
    let archive = b"not the archive the checksum describes".to_vec();
    let (_server, offer) = serve(archive, sha256_hex(b"something else")).await;
    let client = kv::update::check::download_client().unwrap();

    let err = install(&client, &offer, &options(&s.installed), &s.paths)
        .await
        .unwrap_err();

    assert_eq!(err, UpdateError::ChecksumMismatch);
    assert_eq!(std::fs::read(&s.installed).unwrap(), OLD);
    assert_eq!(names(&s.bin), ["kv"], "no temp folder or backup is left");
}

#[tokio::test]
async fn archive_larger_than_announced_is_refused() {
    let s = setup();
    let archive = vec![7u8; 4096];
    let (server, _) = serve(archive.clone(), sha256_hex(&archive)).await;
    let offer = offer_at(&server, 1000, 64);
    let client = kv::update::check::download_client().unwrap();

    let err = install(&client, &offer, &options(&s.installed), &s.paths)
        .await
        .unwrap_err();

    assert!(matches!(err, UpdateError::TooLarge(_)), "{err:?}");
    assert_eq!(std::fs::read(&s.installed).unwrap(), OLD);
    assert_eq!(names(&s.bin), ["kv"]);
}

#[tokio::test]
async fn oversized_checksum_file_is_refused() {
    let s = setup();
    let archive = b"archive".to_vec();
    let (_server, offer) = serve(archive, "0".repeat(5000)).await;
    let client = kv::update::check::download_client().unwrap();

    let err = install(&client, &offer, &options(&s.installed), &s.paths)
        .await
        .unwrap_err();

    assert!(matches!(err, UpdateError::TooLarge(_)), "{err:?}");
    assert_eq!(std::fs::read(&s.installed).unwrap(), OLD);
    assert_eq!(names(&s.bin), ["kv"]);
}

#[cfg(unix)]
#[tokio::test]
async fn wrong_version_inside_archive() {
    let s = setup();
    let archive = archive(&script("98.0.0"));
    let (_server, offer) = serve(archive.clone(), sha256_hex(&archive)).await;
    let client = kv::update::check::download_client().unwrap();

    let err = install(&client, &offer, &options(&s.installed), &s.paths)
        .await
        .unwrap_err();

    assert_eq!(
        err,
        UpdateError::WrongVersion {
            expected: "99.0.0".into(),
            found: "98.0.0".into(),
        }
    );
    assert_eq!(std::fs::read(&s.installed).unwrap(), OLD);
    assert_eq!(names(&s.bin), ["kv"]);
}

/// A new binary that fails or prints nothing does not run here; it has no
/// version to report.
#[cfg(unix)]
#[tokio::test]
async fn a_binary_that_fails_or_says_nothing_wont_run() {
    for (body, why) in [
        ("exit 3", "--version ended with exit status: 3"),
        ("true", "--version printed nothing"),
    ] {
        let s = setup();
        let archive = archive(format!("#!/bin/sh\n{body}\n").as_bytes());
        let (_server, offer) = serve(archive.clone(), sha256_hex(&archive)).await;
        let client = kv::update::check::download_client().unwrap();

        let err = install(&client, &offer, &options(&s.installed), &s.paths)
            .await
            .unwrap_err();

        assert_eq!(err, UpdateError::WontRun(why.into()));
        assert_eq!(
            err.to_string(),
            format!("the new kv does not run on this system: {why}")
        );
        assert_eq!(std::fs::read(&s.installed).unwrap(), OLD);
        assert_eq!(names(&s.bin), ["kv"]);
    }
}

/// An update stopped with Ctrl-C leaves its work folder; the next one
/// clears it.
#[tokio::test]
async fn a_work_folder_left_behind_is_removed() {
    let s = setup();
    let stale = s.bin.join(".kv-update-AbC123");
    std::fs::create_dir(&stale).unwrap();
    std::fs::write(stale.join("archive"), b"half a download").unwrap();
    // Not a work folder: kept.
    std::fs::write(s.bin.join(".kv-update-note"), b"a file").unwrap();
    let archive = b"not the archive the checksum describes".to_vec();
    let (_server, offer) = serve(archive, sha256_hex(b"something else")).await;
    let client = kv::update::check::download_client().unwrap();

    let err = install(&client, &offer, &options(&s.installed), &s.paths)
        .await
        .unwrap_err();

    assert_eq!(err, UpdateError::ChecksumMismatch);
    assert_eq!(names(&s.bin), [".kv-update-note", "kv"]);
}

#[tokio::test]
async fn not_release_build_refused() {
    let s = setup();
    let server = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&server)
        .await;
    let offer = offer_at(&server, 100, 64);
    let client = kv::update::check::download_client().unwrap();
    let opts = InstallOptions {
        installed: s.installed.clone(),
        release_build: false,
    };

    let err = install(&client, &offer, &opts, &s.paths).await.unwrap_err();

    assert_eq!(err, UpdateError::NotReleaseBuild);
    assert_eq!(std::fs::read(&s.installed).unwrap(), OLD);
    assert_eq!(names(&s.bin), ["kv"]);
}

#[cfg(unix)]
#[tokio::test]
async fn unwritable_folder() {
    use std::os::unix::fs::PermissionsExt;
    // Root can write to a 0555 folder, so there is nothing to see.
    if rustix::process::geteuid().is_root() {
        return;
    }
    let s = setup();
    let archive = archive(&script("99.0.0"));
    let (_server, offer) = serve(archive.clone(), sha256_hex(&archive)).await;
    let client = kv::update::check::download_client().unwrap();
    std::fs::set_permissions(&s.bin, std::fs::Permissions::from_mode(0o555)).unwrap();

    let result = install(&client, &offer, &options(&s.installed), &s.paths).await;

    std::fs::set_permissions(&s.bin, std::fs::Permissions::from_mode(0o755)).unwrap();
    let err = result.unwrap_err();
    assert_eq!(err, UpdateError::NotWritable(s.bin.clone()));
    assert_eq!(
        err.to_string(),
        format!(
            "cannot write to {}; reinstall kv into a folder you own, or run kv update as the \
             user who installed it",
            s.bin.display()
        )
    );
    assert_eq!(std::fs::read(&s.installed).unwrap(), OLD);
    assert_eq!(names(&s.bin), ["kv"]);
}

#[cfg(unix)]
#[tokio::test]
async fn symlinked_install_replaces_target() {
    let s = setup();
    // `~/.cargo/bin/kv` style: a link in another folder to the real file.
    let links = s.bin.parent().unwrap().join("links");
    std::fs::create_dir(&links).unwrap();
    let link = links.join("kv");
    std::os::unix::fs::symlink(&s.installed, &link).unwrap();
    let archive = archive(&script("99.0.0"));
    let (_server, offer) = serve(archive.clone(), sha256_hex(&archive)).await;
    let client = kv::update::check::download_client().unwrap();

    // What `installed_exe` does with the path it was run as.
    let installed = link.canonicalize().unwrap();
    assert_eq!(installed, s.installed);
    install(&client, &offer, &options(&installed), &s.paths)
        .await
        .unwrap();

    assert!(
        std::fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(version_of(&link), "kv 99.0.0");
    assert_eq!(version_of(&s.installed), "kv 99.0.0");
    assert_eq!(std::fs::read(s.bin.join("kv.previous")).unwrap(), OLD);
    assert_eq!(names(&links), ["kv"]);
}

#[tokio::test]
async fn second_install_is_busy() {
    let s = setup();
    let server = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&server)
        .await;
    let offer = offer_at(&server, 100, 64);
    let client = kv::update::check::download_client().unwrap();

    let _held = update_lock(&s.paths).unwrap();
    let err = install(&client, &offer, &options(&s.installed), &s.paths)
        .await
        .unwrap_err();

    assert_eq!(err, UpdateError::Busy);
    assert_eq!(err.to_string(), "another kv update is running");
    assert_eq!(std::fs::read(&s.installed).unwrap(), OLD);
    assert_eq!(names(&s.bin), ["kv"]);
}

#[test]
fn lock_is_released_when_dropped() {
    let s = setup();
    let first = update_lock(&s.paths).unwrap();
    assert_eq!(update_lock(&s.paths).unwrap_err(), UpdateError::Busy);
    drop(first);
    update_lock(&s.paths).unwrap();
}

#[cfg(unix)]
mod swap {
    use super::*;
    use kv::update::swap::swap;

    #[test]
    fn missing_new_binary_leaves_the_old_one() {
        let s = setup();
        let err = swap(&s.installed, &s.bin.join("nope")).unwrap_err();
        assert!(matches!(err, UpdateError::Swap(_)), "{err:?}");
        assert_eq!(std::fs::read(&s.installed).unwrap(), OLD);
    }

    #[test]
    fn unwritable_folder_names_it() {
        use std::os::unix::fs::PermissionsExt;
        if rustix::process::geteuid().is_root() {
            return;
        }
        let s = setup();
        let elsewhere = s.bin.parent().unwrap().join("new");
        std::fs::write(&elsewhere, b"NEW").unwrap();
        std::fs::set_permissions(&s.bin, std::fs::Permissions::from_mode(0o555)).unwrap();
        let result = swap(&s.installed, &elsewhere);
        std::fs::set_permissions(&s.bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(result.unwrap_err(), UpdateError::NotWritable(s.bin.clone()));
        assert_eq!(std::fs::read(&s.installed).unwrap(), OLD);
        assert_eq!(names(&s.bin), ["kv"]);
    }

    #[test]
    fn swaps_and_backs_up() {
        let s = setup();
        let new = s.bin.join("new");
        std::fs::write(&new, b"NEW").unwrap();
        let swapped = swap(&s.installed, &new).unwrap();
        assert_eq!(swapped.installed, s.installed);
        assert_eq!(swapped.backup, s.bin.join("kv.previous"));
        assert_eq!(std::fs::read(&s.installed).unwrap(), b"NEW");
        assert_eq!(std::fs::read(&swapped.backup).unwrap(), OLD);
        assert_eq!(names(&s.bin), ["kv", "kv.previous"]);
    }
}

#[test]
fn old_binaries_are_told_apart() {
    use kv::update::swap::is_old_binary;
    for name in ["kv.exe.old", "kv.exe.1.old", "kv.exe.42.old"] {
        assert!(is_old_binary(name), "{name}");
    }
    for name in [
        "kv.exe",
        "kv.previous",
        "kv.exe.x.old",
        "kv.exe..old",
        "kv.exe.old.old",
        "kv.old",
        "other.exe.old",
    ] {
        assert!(!is_old_binary(name), "{name}");
    }
}

/// The Windows swap: the running kv is renamed aside and the new one takes
/// its name. These run on Windows only.
#[cfg(windows)]
mod swap_windows {
    use super::*;
    use kv::update::swap::{clean_old, swap};

    /// A folder holding `kv.exe` with the old bytes, and a new binary
    /// beside it.
    fn installed_exe(s: &Setup) -> (PathBuf, PathBuf) {
        std::fs::remove_file(&s.installed).unwrap();
        let installed = s.bin.join("kv.exe");
        std::fs::write(&installed, OLD).unwrap();
        let new = s.bin.join("new.exe");
        std::fs::write(&new, b"NEW").unwrap();
        (installed, new)
    }

    #[test]
    fn swaps_and_keeps_the_old_one() {
        let s = setup();
        let (installed, new) = installed_exe(&s);
        let swapped = swap(&installed, &new).unwrap();
        assert_eq!(swapped.installed, installed);
        assert_eq!(swapped.backup, s.bin.join("kv.exe.old"));
        assert_eq!(std::fs::read(&installed).unwrap(), b"NEW");
        assert_eq!(std::fs::read(&swapped.backup).unwrap(), OLD);
        assert_eq!(names(&s.bin), ["kv.exe", "kv.exe.old"]);
    }

    #[test]
    fn missing_new_binary_puts_the_old_one_back() {
        let s = setup();
        let (installed, _) = installed_exe(&s);
        let err = swap(&installed, &s.bin.join("nope.exe")).unwrap_err();
        assert!(matches!(err, UpdateError::Swap(_)), "{err:?}");
        assert_eq!(std::fs::read(&installed).unwrap(), OLD);
        assert_eq!(names(&s.bin), ["kv.exe", "new.exe"]);
    }

    /// An old kv still running from `kv.exe.old` (an agent session started
    /// before the last update) cannot be removed: the swap moves the
    /// running kv to another name, and that is cleared once it is free.
    #[test]
    fn an_old_binary_in_use_gets_a_name_of_its_own() {
        use std::os::windows::fs::OpenOptionsExt;
        let s = setup();
        let (installed, new) = installed_exe(&s);
        let held = s.bin.join("kv.exe.old");
        std::fs::write(&held, b"OLDER").unwrap();
        // No sharing at all: it can be neither removed nor replaced.
        let handle = std::fs::File::options()
            .read(true)
            .share_mode(0)
            .open(&held)
            .unwrap();

        let swapped = swap(&installed, &new).unwrap();

        assert_eq!(swapped.backup, s.bin.join("kv.exe.1.old"));
        assert_eq!(std::fs::read(&installed).unwrap(), b"NEW");
        assert_eq!(std::fs::read(&swapped.backup).unwrap(), OLD);
        clean_old(&installed);
        assert_eq!(names(&s.bin), ["kv.exe", "kv.exe.old"], "still in use");
        drop(handle);
        clean_old(&installed);
        assert_eq!(names(&s.bin), ["kv.exe"]);
    }
}
