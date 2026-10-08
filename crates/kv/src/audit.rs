//! Append-only JSON-lines audit log of what was done with which handle.
//! Records names and outcomes, never secret values.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use serde::Serialize;

const MAX_LOG_BYTES: u64 = 10 * 1024 * 1024;
const KEEP_ROTATED: usize = 5;

#[derive(Serialize)]
struct Record<'a> {
    ts: String,
    socket: &'a str,
    action: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    handle: Option<&'a str>,
    outcome: &'a str,
}

pub struct Audit {
    path: PathBuf,
    max_bytes: u64,
}

impl Audit {
    pub fn new(path: PathBuf) -> Self {
        Self::with_max_bytes(path, MAX_LOG_BYTES)
    }

    /// Rotates once the log reaches `max_bytes`, keeping 5 old files
    /// (`audit.jsonl.1` is the newest).
    pub fn with_max_bytes(path: PathBuf, max_bytes: u64) -> Self {
        Self { path, max_bytes }
    }

    /// Appends one record. A failure is reported on stderr and otherwise
    /// ignored, so a full disk never blocks the daemon.
    pub fn record(&self, socket: &str, action: &str, handle: Option<&str>, outcome: &str) {
        let record = Record {
            ts: humantime::format_rfc3339_millis(SystemTime::now()).to_string(),
            socket,
            action,
            handle,
            outcome,
        };
        if let Err(e) = self.append(&record) {
            eprintln!("kv: cannot write audit log {}: {e}", self.path.display());
        }
    }

    fn append(&self, record: &Record<'_>) -> io::Result<()> {
        if let Some(dir) = self.path.parent() {
            fs::create_dir_all(dir)?;
        }
        if fs::metadata(&self.path).is_ok_and(|m| m.len() >= self.max_bytes) {
            self.rotate()?;
        }
        let line = serde_json::to_string(record)?;
        let mut options = OpenOptions::new();
        options.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        writeln!(options.open(&self.path)?, "{line}")
    }

    fn rotate(&self) -> io::Result<()> {
        for i in (1..KEEP_ROTATED).rev() {
            let from = rotated(&self.path, i);
            if from.exists() {
                fs::rename(&from, rotated(&self.path, i + 1))?;
            }
        }
        fs::rename(&self.path, rotated(&self.path, 1))
    }
}

fn rotated(path: &Path, index: usize) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(format!(".{index}"));
    PathBuf::from(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_one_json_object_per_line() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let audit = Audit::new(path.clone());
        audit.record("control", "add", Some("openrouter"), "done");
        audit.record("agent", "list_handles", None, "done");
        let text = fs::read_to_string(&path).unwrap();
        let lines: Vec<serde_json::Value> = text
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0]["action"], "add");
        assert_eq!(lines[0]["handle"], "openrouter");
        assert!(lines[1].get("handle").is_none());
        assert!(lines[0]["ts"].as_str().unwrap().ends_with('Z'));
    }

    #[test]
    fn rotation_keeps_five_old_files() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let audit = Audit::with_max_bytes(path.clone(), 1);
        for _ in 0..10 {
            audit.record("agent", "list_handles", None, "done");
        }
        for i in 1..=5 {
            assert!(rotated(&path, i).exists(), "missing .{i}");
        }
        assert!(!rotated(&path, 6).exists());
        assert!(path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn log_is_private_to_the_user() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        Audit::new(path.clone()).record("agent", "status", None, "done");
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}
