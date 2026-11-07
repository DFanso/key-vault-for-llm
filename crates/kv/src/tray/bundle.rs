//! macOS: kv.app, an app bundle kv makes for itself beside its other files,
//! which `kv tray` starts as its notification helper (see `ui::notices`).
//! macOS lets only an app post notifications with buttons, and only one
//! whose signature covers the bundle and that is not in a temporary folder,
//! so the tray copies its own binary into kv.app and signs the bundle (ad
//! hoc, as the linker signs kv). The tray itself stays the plain binary:
//! Touch ID and the keychain answer each app differently, and they were set
//! up for that binary.
//!
//! kv.app is made afresh, from the running binary, every time the tray
//! starts, never reused: it sits in a folder any program running as the user
//! can write to, and the tray acts on the answers it passes back. A copy
//! changed there (by an agent running commands as the user) would otherwise
//! answer every request with Allow, with no prompt to give it away; made
//! afresh, it runs at most until the tray next starts from the binary the
//! keychain knows. For the same reason kv.app started any other way than by
//! the tray runs nothing and starts no other binary (see `cli`): nothing in
//! that folder says what to trust.
//!
//! Set `KV_TRAY_APP=off` for plain notifications, without kv.app.

use std::ffi::c_void;
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use objc2::rc::Retained;
use objc2_foundation::{NSString, NSURL};

use super::icon;
use crate::paths::Paths;

/// kv.app's bundle identifier, which macOS keeps its notification settings
/// under.
pub const BUNDLE_ID: &str = "dev.dfanso.kv";

const OFF_ENV: &str = "KV_TRAY_APP";

#[link(name = "CoreServices", kind = "framework")]
unsafe extern "C" {
    fn LSRegisterURL(url: *const c_void, update: u8) -> i32;
}

/// Makes kv.app afresh from this binary and returns its executable, for the
/// tray to start as its notification helper. `None` when `KV_TRAY_APP=off`
/// says not to.
pub fn helper(paths: &Paths) -> io::Result<Option<PathBuf>> {
    if off(std::env::var(OFF_ENV).ok().as_deref()) {
        return Ok(None);
    }
    let exe = std::env::current_exe()?.canonicalize()?;
    let app = paths.tray_app();
    let bundled = update(&app, &exe, sign)?;
    register(&app);
    Ok(Some(bundled))
}

/// Whether this process runs from an app bundle's executable.
pub fn running_from_app() -> bool {
    std::env::current_exe().is_ok_and(|exe| contents(&exe).is_some())
}

fn off(setting: Option<&str>) -> bool {
    setting.is_some_and(|value| {
        ["off", "0", "false", "no"]
            .iter()
            .any(|off| value.eq_ignore_ascii_case(off))
    })
}

/// The `Contents` directory of the app bundle `exe` is the executable of.
fn contents(exe: &Path) -> Option<&Path> {
    let macos = exe.parent()?;
    let contents = macos.parent()?;
    let app = contents.parent()?;
    (macos.file_name()? == "MacOS"
        && contents.file_name()? == "Contents"
        && app.extension()? == "app")
        .then_some(contents)
}

/// Makes kv.app at `app` afresh from the binary `exe`, whatever is there
/// already, and returns the path of its executable. `sign` signs the bundle
/// once it is written.
pub fn update(
    app: &Path,
    exe: &Path,
    sign: impl FnOnce(&Path) -> io::Result<()>,
) -> io::Result<PathBuf> {
    let contents = app.join("Contents");
    let resources = contents.join("Resources");
    let bundled = contents.join("MacOS").join("kv");
    let binary = fs::read(exe)?;
    // Never reused, even when it looks current: what is there may have been
    // changed since (see the module's notes). A signature covers every file
    // in the bundle, so nothing from an older one may stay behind either.
    match fs::remove_dir_all(app) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
        _ => {}
    }
    fs::create_dir_all(contents.join("MacOS"))?;
    fs::create_dir_all(&resources)?;
    fs::write(&bundled, &binary)?;
    fs::set_permissions(&bundled, fs::Permissions::from_mode(0o755))?;
    fs::write(contents.join("Info.plist"), info_plist())?;
    fs::write(resources.join("kv.icns"), icns()?)?;
    sign(app)?;
    Ok(bundled)
}

/// Signs `app` ad hoc, which binds its Info.plist and resources to it.
pub fn sign(app: &Path) -> io::Result<()> {
    let output = Command::new("/usr/bin/codesign")
        .args(["--force", "--sign", "-"])
        .arg(app)
        .output()?;
    if output.status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "codesign failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )))
    }
}

/// Tells Launch Services about kv.app, which the notification system looks
/// the app up in. Failing is not fatal: the app is registered on its first
/// run anyway.
fn register(app: &Path) {
    let url = NSURL::fileURLWithPath(&NSString::from_str(&app.to_string_lossy()));
    // SAFETY: NSURL is toll-free bridged to the CFURLRef it takes, and the
    // URL outlives the call.
    unsafe { LSRegisterURL(Retained::as_ptr(&url).cast(), 1) };
}

fn info_plist() -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \
         \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
         <plist version=\"1.0\">\n\
         <dict>\n\
         \t<key>CFBundleIdentifier</key>\n\t<string>{BUNDLE_ID}</string>\n\
         \t<key>CFBundleName</key>\n\t<string>kv</string>\n\
         \t<key>CFBundleDisplayName</key>\n\t<string>kv</string>\n\
         \t<key>CFBundleExecutable</key>\n\t<string>kv</string>\n\
         \t<key>CFBundleIconFile</key>\n\t<string>kv</string>\n\
         \t<key>CFBundlePackageType</key>\n\t<string>APPL</string>\n\
         \t<key>CFBundleShortVersionString</key>\n\t<string>{version}</string>\n\
         \t<key>CFBundleVersion</key>\n\t<string>{version}</string>\n\
         \t<key>LSMinimumSystemVersion</key>\n\t<string>11.0</string>\n\
         \t<!-- A menu bar item only: no Dock icon, no app menu. -->\n\
         \t<key>LSUIElement</key>\n\t<true/>\n\
         \t<key>NSHighResolutionCapable</key>\n\t<true/>\n\
         </dict>\n\
         </plist>\n",
        version = env!("CARGO_PKG_VERSION"),
    )
}

/// kv's mark as an .icns file: PNGs of 128, 256 and 512 pixels.
fn icns() -> io::Result<Vec<u8>> {
    let mut body = Vec::new();
    for (kind, size) in [(b"ic07", 128), (b"ic08", 256), (b"ic09", 512)] {
        let png = png(size, &icon::app_icon_rgba(size))?;
        body.extend_from_slice(kind);
        body.extend_from_slice(&(png.len() as u32 + 8).to_be_bytes());
        body.extend_from_slice(&png);
    }
    let mut file = b"icns".to_vec();
    file.extend_from_slice(&(body.len() as u32 + 8).to_be_bytes());
    file.extend_from_slice(&body);
    Ok(file)
}

fn png(size: u32, rgba: &[u8]) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut encoder = png::Encoder::new(&mut out, size, size);
    encoder.set_color(png::ColorType::Rgba);
    encoder.set_depth(png::BitDepth::Eight);
    let mut writer = encoder.write_header().map_err(io::Error::other)?;
    writer.write_image_data(rgba).map_err(io::Error::other)?;
    writer.finish().map_err(io::Error::other)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_an_app_bundles_executable_is_in_an_app() {
        assert!(contents(Path::new("/x/kv.app/Contents/MacOS/kv")).is_some());
        assert!(contents(Path::new("/usr/local/bin/kv")).is_none());
        assert!(contents(Path::new("/x/kv/Contents/MacOS/kv")).is_none());
    }

    #[test]
    fn kv_tray_app_off_runs_in_place() {
        assert!(off(Some("off")));
        assert!(off(Some("0")));
        assert!(!off(Some("on")));
        assert!(!off(None));
    }

    #[test]
    fn the_app_is_made_afresh_each_time_so_a_changed_copy_never_runs_again() {
        let dir = tempfile::TempDir::new().unwrap();
        let exe = dir.path().join("kv");
        fs::write(&exe, b"first build").unwrap();
        let app = dir.path().join("kv.app");
        let signed = std::cell::Cell::new(0);
        let count = |_: &Path| {
            signed.set(signed.get() + 1);
            Ok(())
        };
        let bundled = update(&app, &exe, count).unwrap();
        assert_eq!(signed.get(), 1);
        assert_eq!(fs::read(&bundled).unwrap(), b"first build");
        let plist = fs::read_to_string(app.join("Contents/Info.plist")).unwrap();
        assert!(plist.contains(BUNDLE_ID), "{plist}");
        let icns = fs::read(app.join("Contents/Resources/kv.icns")).unwrap();
        assert_eq!(&icns[..4], b"icns");
        assert_eq!(
            u32::from_be_bytes(icns[4..8].try_into().unwrap()) as usize,
            icns.len()
        );

        // The copy was changed in place (an agent's binary, signed ad hoc)
        // and a file added, though the binary it came from is the same: the
        // next start makes it again from that binary, and nothing added
        // stays behind.
        fs::write(&bundled, b"someone else's binary").unwrap();
        fs::write(app.join("Contents/Resources/extra"), b"left behind").unwrap();
        let bundled = update(&app, &exe, count).unwrap();
        assert_eq!(fs::read(&bundled).unwrap(), b"first build");
        assert!(!app.join("Contents/Resources/extra").exists());
        assert_eq!(signed.get(), 2);

        fs::write(&exe, b"second build").unwrap();
        update(&app, &exe, count).unwrap();
        assert_eq!(fs::read(&bundled).unwrap(), b"second build");
        assert_eq!(signed.get(), 3);
    }
}
