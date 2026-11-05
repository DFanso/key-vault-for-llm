//! The files of `file` handles, written where a program kv starts can read
//! them, and removed when it is done.
//!
//! Each job gets a folder of its own in the user's temp directory, made
//! readable by the user alone, with one sub-folder per handle so two files
//! with the same name do not meet. The program finds a file through the
//! `KV_FILE_<HANDLE>` variable or by `{file:<handle>}` in its arguments,
//! and keeps the file's own name, since some programs go by the extension.

use std::io;
use std::path::{Path, PathBuf};

use kv_core::crypto::fill_random;
use zeroize::Zeroizing;

use crate::sharefile::safe_file_name;

/// A file a job needs on disk.
pub struct JobFile {
    pub handle: String,
    pub file_name: String,
    pub bytes: Zeroizing<Vec<u8>>,
    /// The variable that carries the file's path.
    pub env_var: String,
}

/// The files of one job on disk. Dropping it removes them.
pub struct Staged {
    dir: PathBuf,
    files: Vec<(String, String, PathBuf)>,
}

impl Staged {
    /// Writes `files` under a new folder in the temp directory.
    pub fn write(files: &[JobFile]) -> io::Result<Self> {
        Self::write_in(&std::env::temp_dir(), files)
    }

    pub fn write_in(parent: &Path, files: &[JobFile]) -> io::Result<Self> {
        let mut id = [0u8; 8];
        fill_random(&mut id);
        let dir = parent.join(format!("kv-files-{}", hex::encode(id)));
        make_dir(&dir)?;
        let mut staged = Self {
            dir,
            files: Vec::new(),
        };
        // From here a failure drops `staged`, which removes what was written.
        for file in files {
            // A handle may be called `con` and a file `a:b`: both are made
            // safe to create, on Windows above all.
            let folder = staged.dir.join(safe_file_name(&file.handle));
            make_dir(&folder)?;
            let path = folder.join(safe_file_name(&file.file_name));
            write_private(&path, &file.bytes)?;
            staged
                .files
                .push((file.handle.clone(), file.env_var.clone(), path));
        }
        Ok(staged)
    }

    /// The variables to set: each file's variable and its path.
    pub fn env(&self) -> impl Iterator<Item = (&str, &Path)> {
        self.files
            .iter()
            .map(|(_, var, path)| (var.as_str(), path.as_path()))
    }

    /// `argument` with every `{file:<handle>}` replaced by that file's path.
    pub fn substitute(&self, argument: &str) -> String {
        let mut out = argument.to_owned();
        for (handle, _, path) in &self.files {
            out = out.replace(&placeholder(handle), &path.to_string_lossy());
        }
        out
    }
}

impl Drop for Staged {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// What an argument says to be replaced with a file's path.
pub fn placeholder(handle: &str) -> String {
    format!("{{file:{handle}}}")
}

/// The handles whose `{file:<handle>}` an argument holds. A handle's name
/// is lowercase letters, digits, `-` and `_`, so the text is easy to find.
pub fn placeholders(argument: &str) -> Vec<&str> {
    let mut found = Vec::new();
    let mut rest = argument;
    while let Some(start) = rest.find("{file:") {
        let after = &rest[start + "{file:".len()..];
        let Some(end) = after.find('}') else { break };
        found.push(&after[..end]);
        rest = &after[end + 1..];
    }
    found
}

#[cfg(unix)]
fn make_dir(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new().mode(0o700).create(path)
}

#[cfg(not(unix))]
fn make_dir(path: &Path) -> io::Result<()> {
    std::fs::create_dir(path)
}

/// Writes a new file the user alone may read, and nobody may change.
#[cfg(unix)]
fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .open(path)?;
    file.write_all(bytes)
}

#[cfg(not(unix))]
fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
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

    fn file(handle: &str, name: &str, bytes: &[u8]) -> JobFile {
        JobFile {
            handle: handle.into(),
            file_name: name.into(),
            bytes: Zeroizing::new(bytes.to_vec()),
            env_var: format!("KV_FILE_{}", handle.to_ascii_uppercase()),
        }
    }

    #[test]
    fn files_are_written_exactly_and_removed_when_dropped() {
        let parent = tempfile::tempdir().unwrap();
        let bytes: Vec<u8> = vec![0, 255, 13, 10, 0xEF, 0xBB, 0xBF, 1];
        let dir = {
            let staged = Staged::write_in(
                parent.path(),
                &[
                    file("a", "list.txt", &bytes),
                    file("b", "list.txt", b"other"),
                ],
            )
            .unwrap();
            let paths: Vec<_> = staged.env().map(|(_, path)| path.to_owned()).collect();
            assert_ne!(
                paths[0], paths[1],
                "the same name in two handles does not clash"
            );
            assert_eq!(std::fs::read(&paths[0]).unwrap(), bytes);
            assert_eq!(std::fs::read(&paths[1]).unwrap(), b"other");
            assert!(paths[0].ends_with("list.txt"));
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
                assert_eq!(mode(&paths[0]), 0o400);
                assert_eq!(mode(paths[0].parent().unwrap().parent().unwrap()), 0o700);
            }
            let argument = staged.substitute("-P={file:a} {file:b} {file:c}");
            assert!(argument.contains(&*paths[0].to_string_lossy()));
            assert!(argument.contains(&*paths[1].to_string_lossy()));
            assert!(
                argument.ends_with("{file:c}"),
                "other handles are left alone"
            );
            paths[0].parent().unwrap().parent().unwrap().to_owned()
        };
        assert!(!dir.exists(), "the folder is gone with the staged files");
    }

    #[test]
    fn a_name_windows_reads_specially_is_staged_under_a_safe_one() {
        let parent = tempfile::tempdir().unwrap();
        // A handle may be called `con`, and a stored name may hold a `:` or be a
        // device name: none of that may reach the file system as it is.
        let staged = Staged::write_in(
            parent.path(),
            &[
                file("con", "a:b.txt", b"one"),
                file("nul", "CON", b"two"),
                file("aux", "\u{e9}\u{e9}", b"three"),
            ],
        )
        .unwrap();
        let paths: Vec<_> = staged.env().map(|(_, path)| path.to_owned()).collect();
        let tail = |path: &Path| {
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            let folder = path
                .parent()
                .unwrap()
                .file_name()
                .unwrap()
                .to_string_lossy()
                .into_owned();
            (folder, name)
        };
        assert_eq!(tail(&paths[0]), ("_con".into(), "a_b.txt".into()));
        assert_eq!(tail(&paths[1]), ("_nul".into(), "_CON".into()));
        assert_eq!(tail(&paths[2]), ("_aux".into(), "\u{e9}\u{e9}".into()));
        assert_eq!(std::fs::read(&paths[0]).unwrap(), b"one");
        assert_eq!(std::fs::read(&paths[1]).unwrap(), b"two");
        assert_eq!(std::fs::read(&paths[2]).unwrap(), b"three");
        // The placeholder still names the path the program is given.
        assert!(
            staged
                .substitute("{file:con}")
                .ends_with(&*paths[0].to_string_lossy())
        );
    }

    #[test]
    fn placeholders_are_found_in_arguments() {
        assert_eq!(
            placeholders("-P={file:words} --x {file:a-b_1}"),
            ["words", "a-b_1"]
        );
        assert!(placeholders("no placeholder {file: broken").is_empty());
        assert!(placeholders("plain").is_empty());
    }
}
