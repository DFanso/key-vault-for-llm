//! Shares as files. A sealed share is text that only the vault it was
//! sealed to can open, so it can travel as an attachment as well as in a
//! message; a file is the only way a share of a file fits, since it is
//! larger than a chat message.

use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use kv_core::share::MAX_FILE_TEXT_LEN;

use crate::paths::Paths;

/// What a share's file name ends with.
pub const EXTENSION: &str = "kvshare";

/// How long a written share stays in the outbox. A request lasts seven
/// days, so a share that was not picked up by then is of no use.
const KEEP: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// Where shares kv wrote for an agent to send wait: beside the vault, so
/// it is private to the user and found without asking.
pub fn outbox(paths: &Paths) -> PathBuf {
    paths.vault.with_file_name("outbox")
}

/// Writes `share` to the outbox as `<handle>-<safety code>.kvshare` and
/// returns where. Older shares are cleared out first.
pub fn write_outbox(
    paths: &Paths,
    handle: &str,
    safety_code: &str,
    share: &str,
) -> io::Result<PathBuf> {
    let dir = outbox(paths);
    make_private_dir(&dir)?;
    clear_old(&dir);
    let name: String = format!("{handle}-{safety_code}.{EXTENSION}")
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c
            } else {
                '_'
            }
        })
        .collect();
    let path = dir.join(name);
    write_private(&path, share.as_bytes())?;
    Ok(path)
}

/// Reads a share from a `.kvshare` file someone sent. Only a file of that
/// name, of a size a share can be, is read: the text goes to kv's daemon,
/// which refuses anything that is not a share.
pub fn read(path: &Path) -> Result<String, String> {
    let shown = path.display();
    if path.extension().and_then(|e| e.to_str()) != Some(EXTENSION) {
        return Err(format!("{shown} is not a .{EXTENSION} file"));
    }
    let metadata = std::fs::metadata(path).map_err(|e| format!("cannot read {shown}: {e}"))?;
    if !metadata.is_file() {
        return Err(format!("{shown} is not a file"));
    }
    if metadata.len() > MAX_FILE_TEXT_LEN as u64 {
        return Err(format!("{shown} is too large to be a kv share"));
    }
    std::fs::read_to_string(path).map_err(|e| format!("cannot read {shown} as text: {e}"))
}

/// Where a file kv saves for the user goes: their Downloads folder, or
/// the outbox where there is none.
pub fn downloads(paths: &Paths) -> PathBuf {
    dirs::download_dir().unwrap_or_else(|| outbox(paths))
}

/// `name` as a file name that is safe to create on any system: no
/// separators, no control characters, nothing Windows reads specially (see
/// `kv_core::secret::windows_safe_name`), and never empty.
pub fn safe_file_name(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| {
            if c.is_control() || matches!(c, '/' | '\\') {
                '_'
            } else {
                c
            }
        })
        .collect();
    let safe = kv_core::secret::windows_safe_name(cleaned.trim_start());
    match safe.as_str() {
        "" | "." | ".." => "file".to_owned(),
        _ => safe,
    }
}

/// Writes `bytes` to a new file in `dir` named like `name`, made safe, and
/// returns where. An existing file is never replaced: the name gets a
/// number instead (`list (1).txt`). Readable by the user alone on Unix.
pub fn save_new(dir: &Path, name: &str, bytes: &[u8]) -> io::Result<PathBuf> {
    std::fs::create_dir_all(dir)?;
    let name = safe_file_name(name);
    let (stem, extension) = match name.rsplit_once('.') {
        Some((stem, extension)) if !stem.is_empty() => (stem.to_owned(), format!(".{extension}")),
        _ => (name.clone(), String::new()),
    };
    for attempt in 0..1000 {
        let candidate = if attempt == 0 {
            name.clone()
        } else {
            format!("{stem} ({attempt}){extension}")
        };
        let path = dir.join(candidate);
        match create_new_private(&path, bytes) {
            Ok(()) => return Ok(path),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        format!(
            "there are too many files named like {name} in {}",
            dir.display()
        ),
    ))
}

/// Shows `path` in the system's file manager, selected where it can.
pub fn reveal(path: &Path) {
    use std::process::Command;
    #[cfg(target_os = "macos")]
    let child = Command::new("open").arg("-R").arg(path).spawn();
    #[cfg(windows)]
    let child = {
        use std::os::windows::process::CommandExt;
        Command::new("explorer")
            .raw_arg(format!("/select,\"{}\"", path.display()))
            .spawn()
    };
    #[cfg(not(any(target_os = "macos", windows)))]
    let child = Command::new("xdg-open")
        .arg(path.parent().unwrap_or(path))
        .spawn();
    // Nobody waits for the file manager, so reap it off to the side.
    if let Ok(mut child) = child {
        std::thread::spawn(move || {
            let _ = child.wait();
        });
    }
}

fn clear_old(dir: &Path) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let old = entry
            .metadata()
            .and_then(|m| m.modified())
            .ok()
            .and_then(|modified| SystemTime::now().duration_since(modified).ok())
            .is_some_and(|age| age > KEEP);
        if old && path.extension().and_then(|e| e.to_str()) == Some(EXTENSION) {
            let _ = std::fs::remove_file(path);
        }
    }
}

#[cfg(unix)]
fn make_private_dir(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)
}

#[cfg(not(unix))]
fn make_private_dir(path: &Path) -> io::Result<()> {
    std::fs::create_dir_all(path)
}

/// Writes `bytes` to `path`, replacing it, readable by the user alone.
#[cfg(unix)]
fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)
}

#[cfg(not(unix))]
fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    std::fs::write(path, bytes)
}

/// Creates `path`, which must not exist, with `bytes`, readable by the
/// user alone on Unix.
#[cfg(unix)]
fn create_new_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)
}

#[cfg(not(unix))]
fn create_new_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_share_written_to_the_outbox_reads_back_exactly() {
        let home = tempfile::tempdir().unwrap();
        let paths = Paths::under(home.path());
        let share = format!("kv-share:v1:{}", "AbC-_123".repeat(50_000));
        let path = write_outbox(&paths, "wordlist", "7KQ2-M9XD", &share).unwrap();
        assert_eq!(path.file_name().unwrap(), "wordlist-7KQ2-M9XD.kvshare");
        assert_eq!(path.parent().unwrap(), outbox(&paths));
        assert_eq!(read(&path).unwrap(), share);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(&path), 0o600);
            assert_eq!(mode(&outbox(&paths)), 0o700);
        }
    }

    #[test]
    fn a_saved_file_is_never_written_over_and_keeps_its_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let bytes: Vec<u8> = vec![0, 255, 13, 10, 0xEF, 0xBB, 0xBF];
        let first = save_new(dir.path(), "list.txt", &bytes).unwrap();
        let second = save_new(dir.path(), "list.txt", b"other").unwrap();
        let third = save_new(dir.path(), "list.txt", b"third").unwrap();
        assert_eq!(first.file_name().unwrap(), "list.txt");
        assert_eq!(second.file_name().unwrap(), "list (1).txt");
        assert_eq!(third.file_name().unwrap(), "list (2).txt");
        assert_eq!(std::fs::read(&first).unwrap(), bytes);
        assert_eq!(std::fs::read(&second).unwrap(), b"other");
        // A folder that is not there yet is made.
        let nested = dir.path().join("a").join("b");
        let path = save_new(&nested, "x", b"1").unwrap();
        assert_eq!(std::fs::read(path).unwrap(), b"1");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&first).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn a_name_from_someone_else_is_made_safe_to_create() {
        assert_eq!(safe_file_name("passwords.txt"), "passwords.txt");
        assert_eq!(safe_file_name("a:b.txt"), "a_b.txt");
        assert_eq!(safe_file_name("what?*.txt"), "what__.txt");
        assert_eq!(safe_file_name("a/b\\c"), "a_b_c");
        assert_eq!(safe_file_name("bad.txt. . "), "bad.txt");
        assert_eq!(safe_file_name("CON"), "_CON");
        assert_eq!(safe_file_name("nul.txt"), "_nul.txt");
        assert_eq!(safe_file_name("com1.log"), "_com1.log");
        assert_eq!(safe_file_name("LPT9"), "_LPT9");
        assert_eq!(safe_file_name("console.txt"), "console.txt");
        assert_eq!(safe_file_name("com10"), "com10");
        assert_eq!(safe_file_name(".."), "file");
        assert_eq!(safe_file_name(""), "file");
        assert_eq!(safe_file_name("tab\there"), "tab_here");
        // A stem of four bytes that is not four letters once crashed the
        // device-name check, which cut it at a byte that is not a boundary.
        assert_eq!(safe_file_name("\u{e9}\u{e9}"), "\u{e9}\u{e9}");
        assert_eq!(safe_file_name("\u{e9}\u{e9}.txt"), "\u{e9}\u{e9}.txt");
        assert_eq!(safe_file_name("COM\u{b2}"), "_COM\u{b2}");
        assert_eq!(safe_file_name("\u{65e5}\u{672c}"), "\u{65e5}\u{672c}");
    }

    #[test]
    fn only_a_kvshare_file_of_a_sensible_size_is_read() {
        let dir = tempfile::tempdir().unwrap();
        let other = dir.path().join("notes.txt");
        std::fs::write(&other, "kv-share:v1:abc").unwrap();
        assert!(read(&other).unwrap_err().contains(".kvshare"));
        let big = dir.path().join("big.kvshare");
        std::fs::write(&big, vec![b'a'; MAX_FILE_TEXT_LEN + 1]).unwrap();
        assert!(read(&big).unwrap_err().contains("too large"));
        assert!(read(&dir.path().join("missing.kvshare")).is_err());
        assert!(read(dir.path()).is_err());
    }
}
