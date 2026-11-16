//! Checking a downloaded release archive and taking the `kv` binary out of
//! it. Archives are untrusted: nothing is written except the one binary,
//! and only after its path and type pass.

use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Component, Path};

use sha2::{Digest, Sha256};

use super::UpdateError;

/// The most the extracted binary may take: 256 MiB.
const MAX_BINARY: u64 = 256 * 1024 * 1024;

/// Room in the unpacked tar stream for headers and the other entries.
#[cfg(unix)]
const TAR_OVERHEAD: u64 = 1024 * 1024;

/// The name of the binary inside a release archive.
#[cfg(unix)]
const BINARY: &str = "kv";
/// The name of the binary inside a release archive.
#[cfg(windows)]
const BINARY: &str = "kv.exe";

/// Reads the SHA-256 out of a `.sha256` file. The file holds 64 hex digits,
/// optionally followed by a file name (`<hex> *name` or `<hex>  name`).
pub fn parse_sha256(text: &str) -> Result<[u8; 32], UpdateError> {
    let bad = || UpdateError::Malformed("the checksum file is not a SHA-256".to_string());
    let text = text.trim();
    if text.contains('\n') {
        return Err(bad());
    }
    let digest = text.split_whitespace().next().ok_or_else(bad)?;
    let mut out = [0u8; 32];
    if digest.len() != 64 {
        return Err(bad());
    }
    hex::decode_to_slice(digest, &mut out).map_err(|_| bad())?;
    Ok(out)
}

/// Hashes `file` and compares it with `expected`. A difference is
/// `ChecksumMismatch`.
pub fn verify_sha256(file: &Path, expected: &[u8; 32]) -> Result<(), UpdateError> {
    let read_err = |e: io::Error| UpdateError::Malformed(format!("could not read download: {e}"));
    let mut reader = File::open(file).map_err(read_err)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = reader.read(&mut buf).map_err(read_err)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    if hasher.finalize().as_slice() == expected {
        Ok(())
    } else {
        Err(UpdateError::ChecksumMismatch)
    }
}

/// Whether an archive entry is the binary. An entry with another name is
/// never written, wherever it sits. One named like the binary must be at
/// depth 2 or less and free of `..` and absolute parts, or the archive is
/// refused.
fn is_binary_entry(path: &Path) -> Result<bool, UpdateError> {
    if path.file_name().and_then(|n| n.to_str()) != Some(BINARY) {
        return Ok(false);
    }
    let mut depth = 0;
    for part in path.components() {
        match part {
            Component::CurDir => {}
            Component::Normal(_) => depth += 1,
            _ => {
                return Err(UpdateError::Malformed(format!(
                    "the archive has an unsafe path: {}",
                    path.display()
                )));
            }
        }
    }
    Ok(depth <= 2)
}

/// Copies `reader` to a new file at `out`, at most `limit` bytes, and
/// makes it executable. A failure removes the partial file.
fn write_binary(reader: &mut dyn Read, out: &Path, limit: u64) -> Result<(), UpdateError> {
    let result = copy_capped(reader, out, limit);
    if result.is_err() {
        let _ = fs::remove_file(out);
    }
    result
}

fn copy_capped(reader: &mut dyn Read, out: &Path, limit: u64) -> Result<(), UpdateError> {
    let write_err =
        |e: io::Error| UpdateError::Swap(format!("could not write {}: {e}", out.display()));
    let mut file = File::create(out).map_err(write_err)?;
    let copied = io::copy(&mut reader.take(limit.saturating_add(1)), &mut file)
        .map_err(|e| UpdateError::Malformed(format!("the archive is damaged: {e}")))?;
    if copied > limit {
        return Err(UpdateError::TooLarge("the unpacked kv binary"));
    }
    file.flush().map_err(write_err)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o755))
            .map_err(write_err)?;
    }
    Ok(())
}

fn no_binary() -> UpdateError {
    UpdateError::Malformed(format!("the archive has no {BINARY}"))
}

/// Unpacks the release binary from `archive` (a `.tar.xz`) into `out` and
/// makes it executable.
#[cfg(unix)]
pub fn extract_binary(archive: &Path, out: &Path) -> Result<(), UpdateError> {
    extract_binary_with_limit(archive, out, MAX_BINARY)
}

/// `extract_binary` with the size limit as a parameter, so tests can reach
/// the limit with a small archive.
#[cfg(unix)]
pub fn extract_binary_with_limit(
    archive: &Path,
    out: &Path,
    limit: u64,
) -> Result<(), UpdateError> {
    let file = File::open(archive)
        .map_err(|e| UpdateError::Malformed(format!("could not read download: {e}")))?;
    // Both the xz and the tar reader stream, so only small buffers are held.
    // The unpacked stream is capped too, so a crafted archive stops early
    // however its entries are laid out.
    let xz = lzma_rust2::XzReader::new(io::BufReader::new(file), false);
    let mut tar = tar::Archive::new(xz.take(limit.saturating_add(TAR_OVERHEAD)));

    let damaged = |e: io::Error| UpdateError::Malformed(format!("the archive is damaged: {e}"));
    for entry in tar.entries().map_err(damaged)? {
        let mut entry = entry.map_err(damaged)?;
        let kind = entry.header().entry_type();
        if kind.is_symlink()
            || kind.is_hard_link()
            || kind.is_character_special()
            || kind.is_block_special()
            || kind.is_fifo()
        {
            return Err(UpdateError::Malformed(
                "the archive has a link or device entry".to_string(),
            ));
        }
        let path = entry.path().map_err(damaged)?.into_owned();
        if kind.is_file() && is_binary_entry(&path)? {
            if entry.size() > limit {
                return Err(UpdateError::TooLarge("the unpacked kv binary"));
            }
            return write_binary(&mut entry, out, limit);
        }
    }
    Err(no_binary())
}

/// Unpacks the release binary from `archive` (a `.zip`) into `out`.
#[cfg(windows)]
pub fn extract_binary(archive: &Path, out: &Path) -> Result<(), UpdateError> {
    let damaged =
        |e: &dyn std::fmt::Display| UpdateError::Malformed(format!("the archive is damaged: {e}"));
    let file = File::open(archive)
        .map_err(|e| UpdateError::Malformed(format!("could not read download: {e}")))?;
    let mut zip = zip::ZipArchive::new(file).map_err(|e| damaged(&e))?;
    for i in 0..zip.len() {
        let mut entry = zip.by_index(i).map_err(|e| damaged(&e))?;
        // A zip made on unix can carry a symlink in its mode bits.
        if entry.unix_mode().is_some_and(|m| m & 0o170000 == 0o120000) {
            return Err(UpdateError::Malformed(
                "the archive has a link or device entry".to_string(),
            ));
        }
        if entry.is_file() && is_binary_entry(Path::new(entry.name()))? {
            if entry.size() > limit {
                return Err(UpdateError::TooLarge("the unpacked kv binary"));
            }
            return write_binary(&mut entry, out, limit);
        }
    }
    Err(no_binary())
}
