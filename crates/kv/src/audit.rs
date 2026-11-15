//! Append-only JSON-lines audit log of what was done with which handle.
//! Records names and outcomes, never secret values.

use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};

const MAX_LOG_BYTES: u64 = 10 * 1024 * 1024;
const KEEP_ROTATED: usize = 5;
/// Old files whose last record is older than this are deleted, and a log
/// whose first record is older is rotated when the daemon starts.
const MAX_AGE: Duration = Duration::from_secs(90 * 24 * 60 * 60);
/// How much of the log's first line `prune` reads to find its time.
const FIRST_LINE_BYTES: u64 = 64 * 1024;

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
    /// (`audit.jsonl.1` is the newest). Old files are deleted once they are
    /// 90 days old.
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

    /// Run when the daemon starts: rotates the log if its first record is
    /// more than 90 days old, and deletes old files last written more than
    /// 90 days ago. A failure is reported on stderr and otherwise ignored.
    pub fn prune(&self, now: SystemTime) {
        let _guard = self.lock.lock().unwrap_or_else(PoisonError::into_inner);
        let started = first_record_time(&self.path);
        let result = if started.is_some_and(|ts| older_than_max_age(ts, now)) {
            self.rotate(now)
        } else {
            self.delete_old(now);
            Ok(())
        };
        if let Err(e) = result {
            eprintln!("kv: cannot rotate audit log {}: {e}", self.path.display());
        }
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
            self.rotate(SystemTime::now())?;
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

    fn rotate(&self, now: SystemTime) -> io::Result<()> {
        for i in (1..KEEP_ROTATED).rev() {
            let from = rotated(&self.path, i);
            if from.exists() {
                fs::rename(&from, rotated(&self.path, i + 1))?;
            }
        }
        fs::rename(&self.path, rotated(&self.path, 1))?;
        self.delete_old(now);
        Ok(())
    }

    /// Deletes the old files last written more than 90 days before `now`.
    /// One that cannot be deleted is tried again next time.
    fn delete_old(&self, now: SystemTime) {
        for i in 1..=KEEP_ROTATED {
            let path = rotated(&self.path, i);
            let old = fs::metadata(&path)
                .and_then(|m| m.modified())
                .is_ok_and(|changed| older_than_max_age(changed, now));
            if old {
                let _ = fs::remove_file(&path);
            }
        }
    }
}

/// One line of the audit log, as `kv tui` shows it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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

/// The time of the log's first record, if it has one that parses.
fn first_record_time(path: &Path) -> Option<SystemTime> {
    let file = File::open(path).ok()?;
    let mut line = String::new();
    BufReader::new(file.take(FIRST_LINE_BYTES))
        .read_line(&mut line)
        .ok()?;
    let entry: Entry = serde_json::from_str(line.trim_end()).ok()?;
    humantime::parse_rfc3339(&entry.ts).ok()
}

fn older_than_max_age(time: SystemTime, now: SystemTime) -> bool {
    now.duration_since(time).is_ok_and(|age| age > MAX_AGE)
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

    fn set_modified(path: &Path, time: SystemTime) {
        File::options()
            .write(true)
            .open(path)
            .unwrap()
            .set_modified(time)
            .unwrap();
    }

    fn days(n: u64) -> Duration {
        Duration::from_secs(n * 24 * 60 * 60)
    }

    #[test]
    fn rotation_deletes_old_files_past_the_age_limit() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let audit = Audit::with_max_bytes(path.clone(), 1);
        for _ in 0..4 {
            audit.record("agent", "list_handles", None, "done");
        }
        // Now .1 to .3 exist; make .2 and .3 older than the limit.
        let now = SystemTime::now();
        set_modified(&rotated(&path, 2), now - days(91));
        set_modified(&rotated(&path, 3), now - days(100));
        audit.record("agent", "list_handles", None, "done");
        // The rotation moved them to .3 and .4 and deleted both.
        assert!(rotated(&path, 1).exists());
        assert!(rotated(&path, 2).exists());
        assert!(!rotated(&path, 3).exists());
        assert!(!rotated(&path, 4).exists());
        assert!(path.exists());
    }

    #[test]
    fn prune_rotates_a_log_whose_first_record_is_old() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let now = SystemTime::now();
        let old = humantime::format_rfc3339_millis(now - days(91)).to_string();
        let line =
            format!(r#"{{"ts":"{old}","socket":"agent","action":"status","outcome":"done"}}"#);
        fs::write(
            &path,
            format!(
                "{line}
"
            ),
        )
        .unwrap();
        let old_file = rotated(&path, 5);
        fs::write(
            &old_file, "x
",
        )
        .unwrap();
        set_modified(&old_file, now - days(200));

        Audit::new(path.clone()).prune(now);
        assert!(!path.exists(), "the live log was rotated");
        assert_eq!(
            fs::read_to_string(rotated(&path, 1)).unwrap(),
            format!(
                "{line}
"
            )
        );
        assert!(!old_file.exists(), "a file past the limit is deleted");
    }

    #[test]
    fn prune_keeps_a_recent_log_and_deletes_old_files() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let audit = Audit::new(path.clone());
        audit.record("agent", "status", None, "done");
        let now = SystemTime::now();
        fs::write(
            rotated(&path, 1),
            "x
",
        )
        .unwrap();
        fs::write(
            rotated(&path, 2),
            "x
",
        )
        .unwrap();
        set_modified(&rotated(&path, 2), now - days(91));

        audit.prune(now);
        assert!(path.exists(), "a recent log stays");
        assert!(rotated(&path, 1).exists(), "a recent old file stays");
        assert!(!rotated(&path, 2).exists());

        // A log that does not start with a record is left as it is.
        fs::write(
            &path,
            "not json
",
        )
        .unwrap();
        audit.prune(now + days(365));
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
