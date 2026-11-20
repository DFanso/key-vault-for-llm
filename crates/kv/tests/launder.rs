//! A listener made by another program and then vouched for by a real kv
//! process gets no passphrase from `kv unlock`.
//!
//! The kernel names a socket's peer by a pid: on Linux the process that
//! called listen(), on macOS the last process to touch the socket. A
//! program can listen, hand the socket to a child that accepts, and exec kv
//! itself, so that pid then runs kv. Each test plays one way of doing that,
//! with a copy of this test binary as the program and the real `kv` as both
//! the process exec'd and the client.
#![cfg(unix)]

use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixListener;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use std::io::{Read, Write};
use tempfile::TempDir;

const ROLE: &str = "KV_LAUNDER_ROLE";
const MODE: &str = "KV_LAUNDER_MODE";
const VICTIM: &str = "KV_LAUNDER_VICTIM";
const OTHER: &str = "KV_LAUNDER_OTHER";
const LOG: &str = "KV_LAUNDER_LOG";
const FD: &str = "KV_LAUNDER_FD";
const KV: &str = "KV_LAUNDER_KV";
const PASS: &str = "launder-test passphrase 3c81";

/// The program's two halves. Does nothing unless a test started it.
#[test]
#[ignore = "started by the other tests, from a copy of this binary"]
fn launder_role() {
    match std::env::var(ROLE).as_deref() {
        Ok("listen") => listen_then_exec_kv(),
        Ok("accept") => accept_and_record(),
        _ => {}
    }
}

fn endpoint(home: &Path) -> PathBuf {
    home.join("run").join("control.sock")
}

fn ready_file(log: &Path) -> PathBuf {
    log.with_extension("ready")
}

/// The process the kernel will name: it makes the listener, hands it to a
/// child, and becomes `kv daemon`. The child outlives it on purpose; the
/// test kills it.
#[allow(clippy::zombie_processes)]
fn listen_then_exec_kv() {
    let mode = std::env::var(MODE).unwrap();
    let victim = PathBuf::from(std::env::var_os(VICTIM).unwrap());
    let other = PathBuf::from(std::env::var_os(OTHER).unwrap());
    let run = victim.join("run");
    std::fs::create_dir_all(&run).unwrap();
    let path = match mode.as_str() {
        "rename" => run.join("made-elsewhere.sock"),
        _ => endpoint(&victim),
    };
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path).unwrap();
    rustix::io::fcntl_setfd(&listener, rustix::io::FdFlags::empty()).unwrap();
    Command::new(std::env::current_exe().unwrap())
        .args(["launder_role", "--exact", "--ignored", "--test-threads=1"])
        .env(ROLE, "accept")
        .env(FD, listener.as_raw_fd().to_string())
        .env("KV_LAUNDER_BOUND", &path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    // "relink" becomes the daemon for the victim's own home; the others a
    // daemon for another home, which leaves the listener where it is.
    let home = if mode == "relink" { &victim } else { &other };
    let error = Command::new(std::env::var_os(KV).unwrap())
        .arg("daemon")
        .env("KV_HOME", home)
        .env("KV_NOTIFY", "off")
        .exec();
    panic!("exec kv: {error}");
}

/// The child that holds the listener, puts it in place, and records what
/// clients send.
fn accept_and_record() {
    let mode = std::env::var(MODE).unwrap();
    let victim = PathBuf::from(std::env::var_os(VICTIM).unwrap());
    let other = PathBuf::from(std::env::var_os(OTHER).unwrap());
    let log = PathBuf::from(std::env::var_os(LOG).unwrap());
    let bound = PathBuf::from(std::env::var_os("KV_LAUNDER_BOUND").unwrap());
    let fd: i32 = std::env::var(FD).unwrap().parse().unwrap();
    // SAFETY: the parent passed this descriptor, a listening socket, open.
    let listener = unsafe { UnixListener::from_raw_fd(fd) };
    std::fs::write(log.with_extension("pid"), std::process::id().to_string()).unwrap();
    let target = endpoint(&victim);
    let deadline = Instant::now() + Duration::from_secs(10);
    match mode.as_str() {
        "relink" => {
            // Keep a second name for the listener, wait for the real daemon
            // to bind the path afresh, then put the listener back.
            let spare = victim.join("run").join("spare.sock");
            std::fs::hard_link(&target, &spare).unwrap();
            let ours = std::fs::metadata(&target).unwrap().ino();
            while std::fs::metadata(&target).map(|m| m.ino()).ok() == Some(ours)
                || !daemon_ready(&victim)
            {
                assert!(Instant::now() < deadline, "the daemon did not bind");
                std::thread::sleep(Duration::from_millis(10));
            }
            std::fs::rename(&spare, &target).unwrap();
        }
        _ => {
            // Wait until the parent runs kv: its daemon for the other home
            // is up.
            while !daemon_ready(&other) {
                assert!(Instant::now() < deadline, "kv did not start");
                std::thread::sleep(Duration::from_millis(10));
            }
            if bound != target {
                std::fs::rename(&bound, &target).unwrap();
            }
        }
    }
    std::fs::write(ready_file(&log), b"").unwrap();
    loop {
        // Late to accept, as a process that wants the client to see only
        // the kv process at first.
        std::thread::sleep(Duration::from_millis(300));
        let Ok((mut stream, _)) = listener.accept() else {
            return;
        };
        let mut len = [0u8; 4];
        if stream.read_exact(&mut len).is_err() {
            continue;
        }
        let mut body = vec![0u8; u32::from_be_bytes(len) as usize];
        if stream.read_exact(&mut body).is_err() {
            continue;
        }
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log)
            .unwrap();
        file.write_all(&body).unwrap();
        file.write_all(b"\n").unwrap();
        let done = br#"{"type":"done","warnings":[]}"#;
        let _ = stream.write_all(&(done.len() as u32).to_be_bytes());
        let _ = stream.write_all(done);
    }
}

fn daemon_ready(home: &Path) -> bool {
    home.join("run").join("agent.sock").exists() && endpoint(home).exists()
}

/// The copy of this test binary the program runs, made once.
fn program() -> &'static Path {
    static COPY: OnceLock<(TempDir, PathBuf)> = OnceLock::new();
    &COPY
        .get_or_init(|| {
            let bin = TempDir::new().unwrap();
            let copy = bin.path().join("not-kv");
            std::fs::copy(std::env::current_exe().unwrap(), &copy).unwrap();
            (bin, copy)
        })
        .1
}

struct Launder {
    listener_process: Child,
    victim: TempDir,
    other: TempDir,
    _logs: TempDir,
    log: PathBuf,
}

impl Launder {
    fn start(mode: &str) -> Self {
        let victim = TempDir::new().unwrap();
        let other = TempDir::new().unwrap();
        let logs = TempDir::new().unwrap();
        let log = logs.path().join("received.jsonl");
        let mut command = Command::new(program());
        command
            .args(["launder_role", "--exact", "--ignored", "--test-threads=1"])
            .env(ROLE, "listen")
            .env(MODE, mode)
            .env(VICTIM, victim.path())
            .env(OTHER, other.path())
            .env(LOG, &log)
            .env(KV, env!("CARGO_BIN_EXE_kv"))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        // A child another test thread forks while the copy is still open for
        // writing keeps it busy until that child execs.
        let mut tries = 0;
        let listener_process = loop {
            match command.spawn() {
                Err(e) if e.kind() == std::io::ErrorKind::ExecutableFileBusy && tries < 50 => {
                    tries += 1;
                    std::thread::sleep(Duration::from_millis(20));
                }
                result => break result.unwrap(),
            }
        };
        let launder = Self {
            listener_process,
            victim,
            other,
            _logs: logs,
            log,
        };
        let deadline = Instant::now() + Duration::from_secs(15);
        while !ready_file(&launder.log).exists() {
            assert!(Instant::now() < deadline, "the program did not get ready");
            std::thread::sleep(Duration::from_millis(20));
        }
        launder
    }

    fn received(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }

    /// `kv unlock` for the victim's home, as the user would run it.
    fn unlock(&self) -> (bool, String) {
        let mut child = Command::new(env!("CARGO_BIN_EXE_kv"))
            .arg("unlock")
            .env("KV_HOME", self.victim.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(format!("{PASS}\n").as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        (
            output.status.success(),
            String::from_utf8_lossy(&output.stderr).into_owned(),
        )
    }

    fn assert_refused(&self) {
        let (ok, stderr) = self.unlock();
        let received = self.received();
        assert!(
            !received.contains(PASS),
            "the program received the passphrase: {received}"
        );
        assert!(!ok, "kv unlock succeeded");
        assert!(stderr.contains("not this kv's daemon"), "{stderr}");
    }
}

impl Drop for Launder {
    fn drop(&mut self) {
        // The listening process is now a kv daemon; the child is the
        // program's other half.
        let _ = self.listener_process.kill();
        let _ = self.listener_process.wait();
        if let Ok(pid) = std::fs::read_to_string(self.log.with_extension("pid"))
            && let Some(pid) = pid
                .trim()
                .parse()
                .ok()
                .and_then(rustix::process::Pid::from_raw)
        {
            let _ = rustix::process::kill_process(pid, rustix::process::Signal::KILL);
        }
        let _ = Command::new(env!("CARGO_BIN_EXE_kv"))
            .arg("stop")
            .env("KV_HOME", self.other.path())
            .stdin(Stdio::null())
            .output();
    }
}

/// The listener is made at the control socket's own path; the process that
/// made it becomes `kv daemon` for another home.
#[test]
fn a_listener_whose_maker_execs_kv_gets_nothing() {
    Launder::start("direct").assert_refused();
}

/// The listener is made at another path and renamed into place once its
/// maker runs kv.
#[test]
fn a_listener_renamed_into_place_gets_nothing() {
    Launder::start("rename").assert_refused();
}

/// The listener's maker becomes the real daemon for the victim's home,
/// which binds the path afresh; the child links the old listener back.
#[test]
fn a_listener_linked_back_over_the_daemon_socket_gets_nothing() {
    Launder::start("relink").assert_refused();
}

/// A daemon started by hand, without `--runtime-dir`, starts itself again
/// with it, keeping its pid, and its clients accept it.
#[test]
fn a_daemon_started_by_hand_is_still_accepted() {
    let home = TempDir::new().unwrap();
    let mut daemon = Command::new(env!("CARGO_BIN_EXE_kv"))
        .arg("daemon")
        .env("KV_HOME", home.path())
        .env("KV_NOTIFY", "off")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while !daemon_ready(home.path()) {
        assert!(Instant::now() < deadline, "the daemon did not start");
        std::thread::sleep(Duration::from_millis(20));
    }
    #[cfg(target_os = "linux")]
    {
        let args = std::fs::read(format!("/proc/{}/cmdline", daemon.id())).unwrap();
        let args = String::from_utf8_lossy(&args).replace('\0', " ");
        assert!(args.contains(" daemon "), "{args}");
        assert!(args.contains("--runtime-dir"), "{args}");
    }
    let mut init = Command::new(env!("CARGO_BIN_EXE_kv"))
        .args(["init", "--insecure-fast-kdf"])
        .env("KV_HOME", home.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    init.stdin
        .take()
        .unwrap()
        .write_all(format!("{PASS}\n{PASS}\n").as_bytes())
        .unwrap();
    let output = init.wait_with_output().unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    let _ = daemon.kill();
    let _ = daemon.wait();
    assert!(output.status.success(), "kv init: {stderr}");
}

/// Linux: the daemon makes itself non-dumpable, which hides its program
/// from other processes of the same user. So a child of the daemon calls
/// listen() on the control socket, and the kernel names that child, whose
/// program clients can read. It dies with the daemon, releasing nothing the
/// next daemon needs.
#[cfg(target_os = "linux")]
#[test]
fn the_control_socket_is_listened_on_by_a_readable_child_that_dies_with_the_daemon() {
    use std::os::unix::net::UnixStream;

    let home = TempDir::new().unwrap();
    let start = || {
        Command::new(env!("CARGO_BIN_EXE_kv"))
            .arg("daemon")
            .env("KV_HOME", home.path())
            .env("KV_NOTIFY", "off")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap()
    };
    let wait_ready = || {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !daemon_ready(home.path()) {
            assert!(Instant::now() < deadline, "the daemon did not start");
            std::thread::sleep(Duration::from_millis(20));
        }
    };
    let listener_pid = || -> Option<i32> {
        let stream = UnixStream::connect(endpoint(home.path())).ok()?;
        let mut cred = libc::ucred {
            pid: 0,
            uid: 0,
            gid: 0,
        };
        let mut len = size_of::<libc::ucred>() as libc::socklen_t;
        // SAFETY: `cred` and `len` are valid for writes of the sizes given.
        let ok = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut cred as *mut libc::ucred).cast(),
                &mut len,
            )
        };
        assert_eq!(ok, 0);
        Some(cred.pid)
    };
    let parent_of = |pid: i32| -> i32 {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
        let after = &stat[stat.rfind(')').unwrap() + 2..];
        after.split(' ').nth(1).unwrap().parse().unwrap()
    };

    let mut daemon = start();
    wait_ready();
    let listener = listener_pid().unwrap();
    assert_ne!(listener as u32, daemon.id(), "the daemon listens itself");
    assert_eq!(parent_of(listener) as u32, daemon.id());
    let program = std::fs::read_link(format!("/proc/{listener}/exe")).unwrap();
    assert_eq!(
        program.canonicalize().unwrap(),
        Path::new(env!("CARGO_BIN_EXE_kv")).canonicalize().unwrap()
    );

    // Killed outright, the daemon leaves no listener behind, and a new one
    // starts with a listener of its own.
    daemon.kill().unwrap();
    daemon.wait().unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while Path::new(&format!("/proc/{listener}")).exists() {
        assert!(
            Instant::now() < deadline,
            "the listener outlived the daemon"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    let mut daemon = start();
    wait_ready();
    let deadline = Instant::now() + Duration::from_secs(5);
    let fresh = loop {
        // The dead daemon's socket file stays until the new one binds.
        if let Some(pid) = listener_pid()
            && pid != listener
            && parent_of(pid) as u32 == daemon.id()
        {
            break pid;
        }
        assert!(Instant::now() < deadline, "the new daemon has no listener");
        std::thread::sleep(Duration::from_millis(20));
    };
    assert_ne!(fresh, listener);
    let _ = daemon.kill();
    let _ = daemon.wait();
}
