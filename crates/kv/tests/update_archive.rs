//! Checking a release archive's checksum and unpacking the binary from it.

use kv::update::UpdateError;
use kv::update::archive::{extract_binary, parse_sha256, verify_sha256};

const HEX: &str = "152f4f8bc9bda7f572ca1a3cdb590ac676f74c9f816efc2c746073fd6ff3a756";

#[test]
fn parse_sha256_forms() {
    let want = parse_sha256(HEX).unwrap();
    assert_eq!(want[0], 0x15);
    assert_eq!(parse_sha256(&format!("  {HEX}\n")).unwrap(), want);
    assert_eq!(
        parse_sha256(&format!("{HEX} *kv-aarch64-apple-darwin.tar.xz\n")).unwrap(),
        want
    );
    assert_eq!(parse_sha256(&format!("{HEX}  kv.tar.xz")).unwrap(), want);
    assert!(matches!(
        parse_sha256("xyz"),
        Err(UpdateError::Malformed(_))
    ));
    assert!(matches!(parse_sha256(""), Err(UpdateError::Malformed(_))));
    assert!(matches!(
        parse_sha256(&HEX[..63]),
        Err(UpdateError::Malformed(_))
    ));
}

#[test]
fn checksum_mismatch() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("a");
    std::fs::write(&file, b"hello").unwrap();
    // sha256("hello")
    let good =
        parse_sha256("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824").unwrap();
    verify_sha256(&file, &good).unwrap();
    let bad = parse_sha256(HEX).unwrap();
    assert!(matches!(
        verify_sha256(&file, &bad),
        Err(UpdateError::ChecksumMismatch)
    ));
}

#[cfg(unix)]
mod tar_xz {
    use super::*;
    use std::io::Cursor;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    enum Item<'a> {
        File(&'a str, &'a [u8]),
        Symlink(&'a str, &'a str),
    }

    fn header(path: &str, kind: tar::EntryType, size: u64) -> tar::Header {
        let mut h = tar::Header::new_gnu();
        // `set_path` refuses `..`, so write the name bytes directly.
        h.as_old_mut().name[..path.len()].copy_from_slice(path.as_bytes());
        h.set_entry_type(kind);
        h.set_size(size);
        h.set_mode(0o644);
        h
    }

    fn build(dir: &Path, items: &[Item]) -> std::path::PathBuf {
        let mut builder = tar::Builder::new(Vec::new());
        for item in items {
            match item {
                Item::File(path, data) => {
                    let mut h = header(path, tar::EntryType::Regular, data.len() as u64);
                    h.set_cksum();
                    builder.append(&h, *data).unwrap();
                }
                Item::Symlink(path, target) => {
                    let mut h = header(path, tar::EntryType::Symlink, 0);
                    h.set_link_name(target).unwrap();
                    h.set_cksum();
                    builder.append(&h, std::io::empty()).unwrap();
                }
            }
        }
        let tar_bytes = builder.into_inner().unwrap();
        let mut xz = Vec::new();
        lzma_rs::xz_compress(&mut Cursor::new(tar_bytes), &mut xz).unwrap();
        let path = dir.join("kv-t.tar.xz");
        std::fs::write(&path, xz).unwrap();
        path
    }

    #[test]
    fn extracts_only_the_binary() {
        let dir = tempfile::tempdir().unwrap();
        let work = dir.path().join("work");
        std::fs::create_dir(&work).unwrap();
        let archive = build(
            &work,
            &[
                Item::File("kv-t/kv", b"BINARY"),
                Item::File("kv-t/README.md", b"docs"),
                Item::File("../evil", b"bad"),
            ],
        );
        let out = work.join("out");
        extract_binary(&archive, &out).unwrap();
        assert_eq!(std::fs::read(&out).unwrap(), b"BINARY");
        assert_eq!(
            std::fs::metadata(&out).unwrap().permissions().mode() & 0o777,
            0o755
        );
        assert!(!dir.path().join("evil").exists());
        assert!(!work.join("evil").exists());
        let mut names: Vec<_> = std::fs::read_dir(&work)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        assert_eq!(names, ["kv-t.tar.xz", "out"]);
    }

    #[test]
    fn symlink_entry_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let archive = build(dir.path(), &[Item::Symlink("kv-t/kv", "/bin/sh")]);
        let out = dir.path().join("out");
        assert!(matches!(
            extract_binary(&archive, &out),
            Err(UpdateError::Malformed(_))
        ));
        assert!(!out.exists());
    }

    #[test]
    fn unsafe_binary_path_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let archive = build(dir.path(), &[Item::File("../kv", b"x")]);
        let out = dir.path().join("out");
        assert!(matches!(
            extract_binary(&archive, &out),
            Err(UpdateError::Malformed(_))
        ));
        assert!(!out.exists());
    }

    #[test]
    fn archive_without_binary_is_malformed() {
        let dir = tempfile::tempdir().unwrap();
        let archive = build(dir.path(), &[Item::File("kv-t/README.md", b"docs")]);
        let out = dir.path().join("out");
        assert!(matches!(
            extract_binary(&archive, &out),
            Err(UpdateError::Malformed(_))
        ));
    }

    #[test]
    fn garbage_is_malformed() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("a.tar.xz");
        std::fs::write(&archive, b"not an archive").unwrap();
        assert!(matches!(
            extract_binary(&archive, &dir.path().join("out")),
            Err(UpdateError::Malformed(_))
        ));
    }
}

#[cfg(windows)]
mod zip_archive {
    use super::*;
    use std::io::Write;
    use std::path::Path;

    fn build(dir: &Path, files: &[(&str, &[u8])]) -> std::path::PathBuf {
        let path = dir.join("kv-t.zip");
        let mut zip = zip::ZipWriter::new(std::fs::File::create(&path).unwrap());
        let opts = zip::write::SimpleFileOptions::default();
        for (name, data) in files {
            zip.start_file(*name, opts).unwrap();
            zip.write_all(data).unwrap();
        }
        zip.finish().unwrap();
        path
    }

    #[test]
    fn extracts_only_the_binary() {
        let dir = tempfile::tempdir().unwrap();
        let archive = build(
            dir.path(),
            &[("kv-t/kv.exe", b"BINARY"), ("kv-t/README.md", b"docs")],
        );
        let out = dir.path().join("out.exe");
        extract_binary(&archive, &out).unwrap();
        assert_eq!(std::fs::read(&out).unwrap(), b"BINARY");
    }

    #[test]
    fn top_level_binary_is_found() {
        let dir = tempfile::tempdir().unwrap();
        let archive = build(dir.path(), &[("README.md", b"docs"), ("kv.exe", b"BIN")]);
        let out = dir.path().join("out.exe");
        extract_binary(&archive, &out).unwrap();
        assert_eq!(std::fs::read(&out).unwrap(), b"BIN");
    }

    #[test]
    fn archive_without_binary_is_malformed() {
        let dir = tempfile::tempdir().unwrap();
        let archive = build(dir.path(), &[("kv-t/README.md", b"docs")]);
        assert!(matches!(
            extract_binary(&archive, &dir.path().join("out.exe")),
            Err(UpdateError::Malformed(_))
        ));
    }

    #[test]
    fn parent_path_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let archive = build(dir.path(), &[("../kv.exe", b"x")]);
        assert!(matches!(
            extract_binary(&archive, &dir.path().join("out.exe")),
            Err(UpdateError::Malformed(_))
        ));
    }
}
