//! Append-only JSON-lines audit log of what was done with which handle.
//! Records names and outcomes, never secret values.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};

const MAX_LOG_BYTES: u64 = 10 * 1024 * 1024;
const KEEP_ROTATED: usize = 5;

#[derive(Serialize)]
struct Record<'a> {
    ts: String,
    socket: &'a str,
    action: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    handle: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    decision: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    summary: Option<&'a str>,
    outcome: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    duration_ms: Option<u128>,
}

/// One use of a handle by an agent.
pub struct Use<'a> {
    /// `http_request` or `exec`.
    pub action: &'a str,
    /// Handle name, or several joined with commas.
    pub handle: &'a str,
    /// `auto`, `approved`, `denied`, `policy` or `locked`.
    pub decision: &'a str,
    /// What was asked for, already scrubbed: method and URL, or the program.
    pub summary: &'a str,
    /// HTTP status, exit code or error code.
    pub outcome: &'a str,
    pub duration: Duration,
}

/// Cheap to clone; clones share one lock so their appends and rotations do
/// not interleave.
#[derive(Clone)]
pub struct Audit {
    path: PathBuf,
    max_bytes: u64,
    lock: Arc<Mutex<()>>,
}

impl Audit {
    pub fn new(path: PathBuf) -> Self {
        Self::with_max_bytes(path, MAX_LOG_BYTES)
    }

    /// Rotates once the log reaches `max_bytes`, keeping 5 old files
    /// (`audit.jsonl.1` is the newest).
    pub fn with_max_bytes(path: PathBuf, max_bytes: u64) -> Self {
        Self {
            path,
            max_bytes,
            lock: Arc::default(),
        }
    }

    /// Appends one record. A failure is reported on stderr and otherwise
    /// ignored, so a full disk never blocks the daemon.
    pub fn record(&self, socket: &str, action: &str, handle: Option<&str>, outcome: &str) {
        self.write(&Record {
            ts: now(),
            socket,
            action,
            handle,
            decision: None,
            summary: None,
            outcome,
            duration_ms: None,
        });
    }

    pub fn record_use(&self, entry: &Use<'_>) {
        self.write(&Record {
            ts: now(),
            socket: "agent",
            action: entry.action,
            handle: Some(entry.handle),
            decision: Some(entry.decision),
            summary: Some(entry.summary),
            outcome: entry.outcome,
            duration_ms: Some(entry.duration.as_millis()),
        });
    }

    fn write(&self, record: &Record<'_>) {
        let _guard = self.lock.lock().unwrap_or_else(PoisonError::into_inner);
        if let Err(e) = self.append(record) {
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

/// One line of the audit log, as `kv tui` shows it.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct Entry {
    pub ts: String,
    pub socket: String,
    pub action: String,
    #[serde(default)]
    pub handle: Option<String>,
    #[serde(default)]
    pub decision: Option<String>,
    #[serde(default)]
    pub summary: Option<String>,
    pub outcome: String,
    #[serde(default)]
    pub duration_ms: Option<u64>,
}

/// How much of the end of the log `tail` reads.
const TAIL_BYTES: u64 = 256 * 1024;

/// The last `max` entries of the log, newest first. Reads only the end of
/// the file; a missing log has no entries, and lines that do not parse are
/// skipped. Control characters are replaced, so the text is safe to draw.
pub fn tail(path: &Path, max: usize) -> io::Result<Vec<Entry>> {
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let start = file.metadata()?.len().saturating_sub(TAIL_BYTES);
    file.seek(SeekFrom::Start(start))?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    let text = String::from_utf8_lossy(&bytes);
    let mut lines = text.lines();
    if start > 0 {
        // The first line is most likely cut off.
        lines.next();
    }
    Ok(lines
        .rev()
        .filter_map(|line| serde_json::from_str::<Entry>(line).ok())
        .map(Entry::made_safe)
        .take(max)
        .collect())
}

impl Entry {
    fn made_safe(self) -> Self {
        let safe = |text: String| -> String {
            text.chars()
                .map(|c| if c.is_control() { '\u{fffd}' } else { c })
                .collect()
        };
        Self {
            ts: safe(self.ts),
            socket: safe(self.socket),
            action: safe(self.action),
            handle: self.handle.map(safe),
            decision: self.decision.map(safe),
            summary: self.summary.map(safe),
            outcome: safe(self.outcome),
            duration_ms: self.duration_ms,
        }
    }
}

fn now() -> String {
    humantime::format_rfc3339_millis(SystemTime::now()).to_string()
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

    #[test]
    fn uses_record_decision_summary_and_duration() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        Audit::new(path.clone()).record_use(&Use {
            action: "http_request",
            handle: "openrouter",
            decision: "auto",
            summary: "GET https://openrouter.ai/api/v1/models",
            outcome: "200",
            duration: Duration::from_millis(42),
        });
        let line: serde_json::Value =
            serde_json::from_str(fs::read_to_string(&path).unwrap().trim()).unwrap();
        assert_eq!(line["socket"], "agent");
        assert_eq!(line["decision"], "auto");
        assert_eq!(line["summary"], "GET https://openrouter.ai/api/v1/models");
        assert_eq!(line["outcome"], "200");
        assert_eq!(line["duration_ms"], 42);
    }

    #[test]
    fn clones_never_interleave_lines() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let audit = Audit::with_max_bytes(path.clone(), 4096);
        std::thread::scope(|scope| {
            for _ in 0..8 {
                let audit = audit.clone();
                scope.spawn(move || {
                    for _ in 0..50 {
                        audit.record(
                            "agent",
                            "list_handles",
                            Some("a-fairly-long-handle-name"),
                            "done",
                        );
                    }
                });
            }
        });
        for file in std::iter::once(path.clone()).chain((1..=5).map(|i| rotated(&path, i))) {
            let Ok(text) = fs::read_to_string(&file) else {
                continue;
            };
            for line in text.lines() {
                serde_json::from_str::<serde_json::Value>(line).unwrap();
            }
        }
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
