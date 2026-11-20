use std::ffi::OsString;
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use tokio::net::{UnixListener, UnixStream};

use crate::paths::Endpoint;

pub type ServerStream = UnixStream;
pub type ClientStream = UnixStream;

pub struct Listener {
    inner: UnixListener,
    uid: u32,
}

/// Binds the socket file, replacing a stale one left by a daemon that
/// crashed. The caller must already hold the daemon lock file, so a live
/// daemon's socket is never replaced.
pub fn bind(endpoint: &Endpoint) -> io::Result<Listener> {
    match fs::remove_file(&endpoint.path) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
        _ => {}
    }
    let inner = UnixListener::bind(&endpoint.path)?;
    fs::set_permissions(&endpoint.path, fs::Permissions::from_mode(0o600))?;
    Ok(Listener {
        inner,
        uid: rustix::process::getuid().as_raw(),
    })
}

impl Listener {
    /// Waits for a connection from a process running as the same user and
    /// drops connections from anyone else.
    pub async fn accept(&mut self) -> io::Result<ServerStream> {
        loop {
            let (stream, _) = self.inner.accept().await?;
            match stream.peer_cred() {
                Ok(cred) if cred.uid() == self.uid => return Ok(stream),
                _ => continue,
            }
        }
    }
}

pub async fn connect(endpoint: &Endpoint) -> io::Result<ClientStream> {
    UnixStream::connect(&endpoint.path).await
}

pub fn cleanup(endpoint: &Endpoint) {
    let _ = fs::remove_file(&endpoint.path);
}

/// Checks that the process serving `stream` is the kv daemon for
/// `runtime`: this user's, running this same kv program as `kv daemon
/// --runtime-dir <runtime>`, and really the one holding the connection.
///
/// The pid the kernel names for a socket peer is not enough on its own. On
/// Linux it is the process that called listen(), recorded then: a program
/// can listen, hand the socket to a child, and exec kv. On macOS it is the
/// last process to touch the socket, read when asked. So each platform adds
/// what ties that pid to this connection (see `linux` and `macos`).
pub async fn check_server(
    stream: &ClientStream,
    endpoint: &Endpoint,
    runtime: &Path,
) -> io::Result<()> {
    platform::check_server(stream, endpoint, runtime).await
}

/// Refuses a peer that runs as another user.
fn ensure_same_user(uid: u32) -> io::Result<()> {
    let me = rustix::process::getuid().as_raw();
    if uid == me {
        Ok(())
    } else {
        Err(refused(format!(
            "the process at the socket runs as user {uid}, not as this user"
        )))
    }
}

fn refused(why: String) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, why)
}

/// Refuses `pid` unless it runs this same kv program as the daemon for
/// `runtime`.
fn ensure_daemon_process(pid: i32, runtime: &Path) -> io::Result<()> {
    let theirs = program_of(pid).map_err(|e| {
        refused(format!(
            "could not tell which program process {pid} at the socket runs ({e})"
        ))
    })?;
    if !super::same_file(&theirs, &crate::update::swap::running_exe()?) {
        return Err(refused(format!(
            "the process at the socket runs {}, not this kv",
            theirs.display()
        )));
    }
    let args = args_of(pid).map_err(|e| {
        refused(format!(
            "could not read the arguments of process {pid} at the socket ({e})"
        ))
    })?;
    if !super::is_daemon_for(&args, runtime) {
        return Err(refused(format!(
            "process {pid} at the socket runs this kv, but not as the daemon for {}",
            runtime.display()
        )));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
mod platform {
    use super::*;
    use std::os::unix::ffi::OsStrExt;

    pub async fn check_server(
        stream: &ClientStream,
        endpoint: &Endpoint,
        runtime: &Path,
    ) -> io::Result<()> {
        // SO_PEERCRED: the process that called listen(), as it was then.
        let cred = stream.peer_cred()?;
        ensure_same_user(cred.uid())?;
        let pid = cred.pid().filter(|&pid| pid > 0).ok_or_else(|| {
            refused("the system did not say which process is at the socket".into())
        })?;
        if pid as u32 == std::process::id() {
            // A daemon running inside this very process, as in tests.
            return Ok(());
        }
        // The listener must have been bound at this very path: one bound
        // elsewhere and renamed or linked into place is someone else's.
        let bound = stream.peer_addr()?;
        if bound.as_pathname() != Some(endpoint.path.as_path()) {
            return Err(refused(format!(
                "the socket at {} was made at another path ({:?})",
                endpoint.path.display(),
                bound.as_pathname()
            )));
        }
        // And it must be the only one bound there. A daemon starting binds a
        // fresh socket at the path, so a listener someone made earlier and
        // linked back into place leaves two.
        let listeners = listeners_at(&endpoint.path)?;
        if listeners != 1 {
            return Err(refused(format!(
                "{listeners} sockets are listening at {}, where only the kv daemon should be",
                endpoint.path.display()
            )));
        }
        // Then the process that made the listener must be the daemon for
        // this runtime directory now. With the checks above, a program that
        // listened and then exec'd kv fails here: exec'd as anything but this
        // daemon, its arguments say so; exec'd as this daemon, the daemon
        // either finds the lock taken and exits, or binds the path afresh.
        ensure_daemon_process(pid, runtime)
    }

    /// How many listening Unix sockets in this network namespace are bound at
    /// exactly `path`, from /proc/net/unix.
    pub fn listeners_at(path: &Path) -> io::Result<usize> {
        let table = fs::read("/proc/net/unix")?;
        Ok(count_listeners(&table, path.as_os_str().as_bytes()))
    }

    /// Lines look like `0000000000000000: 00000002 00000000 00010000 0001 01
    /// 12345 /path`: Num, RefCount, Protocol, Flags, Type, St, Inode and the
    /// bound path, which runs to the end of the line and may hold spaces.
    /// Flag 0x10000 (__SO_ACCEPTCON) marks a listener.
    pub fn count_listeners(table: &[u8], path: &[u8]) -> usize {
        const ACCEPTCON: u32 = 0x10000;
        table
            .split(|&b| b == b'\n')
            .skip(1)
            .filter(|line| {
                let mut rest = *line;
                let mut fields = Vec::with_capacity(7);
                for _ in 0..7 {
                    let start = rest.iter().position(|b| *b != b' ').unwrap_or(rest.len());
                    rest = &rest[start..];
                    let end = rest.iter().position(|b| *b == b' ').unwrap_or(rest.len());
                    fields.push(&rest[..end]);
                    rest = &rest[end..];
                }
                let Some(bound) = rest.strip_prefix(b" ") else {
                    return false;
                };
                let flags = std::str::from_utf8(fields[3])
                    .ok()
                    .and_then(|f| u32::from_str_radix(f, 16).ok())
                    .unwrap_or(0);
                flags & ACCEPTCON != 0 && bound == path
            })
            .count()
    }
}

#[cfg(target_os = "macos")]
mod platform {
    use super::*;
    use std::os::fd::AsRawFd;
    use std::time::Duration;

    pub async fn check_server(
        stream: &ClientStream,
        _endpoint: &Endpoint,
        runtime: &Path,
    ) -> io::Result<()> {
        ensure_same_user(stream.peer_cred()?.uid())?;
        let fd = stream.as_raw_fd();
        let peer = peer_socket(fd)?;
        // Until the daemon accepts the connection no process holds its end,
        // so wait a little for that.
        let mut waited = Duration::ZERO;
        loop {
            // LOCAL_PEERPID: the last process to touch the peer socket, or
            // before accept the listener.
            let pid = peer_pid(fd)?;
            if pid as u32 == std::process::id() {
                return Ok(());
            }
            ensure_daemon_process(pid, runtime)?;
            if holds_socket(pid, peer)? {
                // Still the same process: the pid cannot have been reused
                // while it held the socket.
                return ensure_daemon_process(pid, runtime);
            }
            if waited >= Duration::from_secs(3) {
                return Err(refused(format!(
                    "process {pid} at the socket does not hold this connection"
                )));
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
            waited += Duration::from_millis(10);
        }
    }

    fn peer_pid(fd: i32) -> io::Result<i32> {
        let mut pid: libc::pid_t = 0;
        let mut len = size_of::<libc::pid_t>() as libc::socklen_t;
        // SAFETY: `pid` and `len` are valid for writes of the sizes given.
        let ok = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_LOCAL,
                libc::LOCAL_PEERPID,
                (&mut pid as *mut libc::pid_t).cast(),
                &mut len,
            )
        };
        if ok != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(pid)
    }

    // From <sys/proc_info.h>. struct socket_fdinfo is a proc_fileinfo (24
    // bytes) then a socket_info, whose soi_so lies at 136, soi_family at
    // 160, soi_kind at 232 and the protocol union at 240; for a Unix socket
    // (SOCKINFO_UN) the union starts with unsi_conn_so, the handle of the
    // socket it is connected to. Handles are the kernel's hashed socket
    // addresses, the same for every caller.
    const PROC_PIDLISTFDS: libc::c_int = 1;
    const PROC_PIDFDSOCKETINFO: libc::c_int = 3;
    const PROX_FDTYPE_SOCKET: u32 = 2;
    const SOCKINFO_UN: i32 = 3;
    const SO_OFFSET: usize = 24 + 136;
    const FAMILY_OFFSET: usize = 24 + 160;
    const KIND_OFFSET: usize = 24 + 232;
    const CONN_SO_OFFSET: usize = 24 + 240;

    #[repr(C, align(8))]
    struct Buffer([u8; 4096]);

    struct SocketInfo {
        so: u64,
        conn_so: u64,
    }

    /// The socket info of `fd` in process `pid`, `None` if it is not a Unix
    /// socket.
    fn socket_info(pid: i32, fd: i32) -> io::Result<Option<SocketInfo>> {
        let mut buffer = Buffer([0; 4096]);
        // SAFETY: the buffer is as long as the size passed; the kernel
        // writes at most sizeof(struct socket_fdinfo) bytes into it.
        let len = unsafe {
            libc::proc_pidfdinfo(
                pid,
                fd,
                PROC_PIDFDSOCKETINFO,
                buffer.0.as_mut_ptr().cast(),
                buffer.0.len() as libc::c_int,
            )
        };
        if len <= 0 {
            return Err(io::Error::last_os_error());
        }
        if (len as usize) < CONN_SO_OFFSET + 8 {
            return Err(io::Error::other("proc_pidfdinfo returned too little"));
        }
        let bytes = &buffer.0;
        let read_u64 = |at: usize| u64::from_ne_bytes(bytes[at..at + 8].try_into().unwrap());
        let read_i32 = |at: usize| i32::from_ne_bytes(bytes[at..at + 4].try_into().unwrap());
        if read_i32(FAMILY_OFFSET) != libc::AF_UNIX || read_i32(KIND_OFFSET) != SOCKINFO_UN {
            return Ok(None);
        }
        Ok(Some(SocketInfo {
            so: read_u64(SO_OFFSET),
            conn_so: read_u64(CONN_SO_OFFSET),
        }))
    }

    /// The handle of the socket at the other end of our `fd`.
    fn peer_socket(fd: i32) -> io::Result<u64> {
        match socket_info(std::process::id() as i32, fd)? {
            Some(info) if info.conn_so != 0 => Ok(info.conn_so),
            _ => Err(io::Error::other(
                "could not identify the other end of the kv socket",
            )),
        }
    }

    /// Whether process `pid` has the socket `so` open.
    fn holds_socket(pid: i32, so: u64) -> io::Result<bool> {
        #[repr(C)]
        #[derive(Clone, Copy)]
        struct ProcFdInfo {
            proc_fd: i32,
            proc_fdtype: u32,
        }
        let mut fds = vec![
            ProcFdInfo {
                proc_fd: 0,
                proc_fdtype: 0
            };
            4096
        ];
        let size = (fds.len() * size_of::<ProcFdInfo>()) as libc::c_int;
        // SAFETY: the buffer holds `size` bytes of proc_fdinfo records.
        let len =
            unsafe { libc::proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fds.as_mut_ptr().cast(), size) };
        if len <= 0 {
            return Err(refused(format!(
                "could not list the open files of process {pid} at the socket ({})",
                io::Error::last_os_error()
            )));
        }
        let count = len as usize / size_of::<ProcFdInfo>();
        for entry in &fds[..count] {
            if entry.proc_fdtype != PROX_FDTYPE_SOCKET {
                continue;
            }
            // A descriptor closed since the listing is no match.
            if let Ok(Some(info)) = socket_info(pid, entry.proc_fd)
                && info.so == so
            {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

#[cfg(target_os = "macos")]
fn program_of(pid: i32) -> io::Result<PathBuf> {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    let mut buffer = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    // SAFETY: the buffer is as long as the size passed, and proc_pidpath
    // writes at most that many bytes.
    let len = unsafe { libc::proc_pidpath(pid, buffer.as_mut_ptr().cast(), buffer.len() as u32) };
    if len <= 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(PathBuf::from(OsStr::from_bytes(&buffer[..len as usize])))
}

#[cfg(not(target_os = "macos"))]
fn program_of(pid: i32) -> io::Result<PathBuf> {
    fs::read_link(format!("/proc/{pid}/exe"))
}

/// The arguments process `pid` was started with, its program first.
#[cfg(not(target_os = "macos"))]
fn args_of(pid: i32) -> io::Result<Vec<OsString>> {
    use std::os::unix::ffi::OsStrExt;
    let raw = fs::read(format!("/proc/{pid}/cmdline"))?;
    Ok(split_nul(raw.strip_suffix(&[0]).unwrap_or(&raw))
        .map(|arg| std::ffi::OsStr::from_bytes(arg).to_owned())
        .collect())
}

/// The arguments process `pid` was started with, its program first, from
/// KERN_PROCARGS2: argc, the executable path, NUL padding, then the
/// arguments, each ending in NUL.
#[cfg(target_os = "macos")]
fn args_of(pid: i32) -> io::Result<Vec<OsString>> {
    use std::os::unix::ffi::OsStrExt;
    let mut mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid];
    let mut size: libc::size_t = 0;
    // SAFETY: asks only for the size.
    if unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            3,
            std::ptr::null_mut(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    let mut buffer = vec![0u8; size];
    // SAFETY: the buffer is `size` bytes long and `size` says so.
    if unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            3,
            buffer.as_mut_ptr().cast(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    buffer.truncate(size);
    if buffer.len() < 4 {
        return Err(io::Error::other("short KERN_PROCARGS2 reply"));
    }
    let argc = i32::from_ne_bytes(buffer[..4].try_into().unwrap()).max(0) as usize;
    let rest = &buffer[4..];
    // Skip the executable path and the NULs after it.
    let path_end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
    let rest = &rest[path_end..];
    let start = rest.iter().position(|&b| b != 0).unwrap_or(rest.len());
    Ok(split_nul(&rest[start..])
        .take(argc)
        .map(|arg| std::ffi::OsStr::from_bytes(arg).to_owned())
        .collect())
}

fn split_nul(bytes: &[u8]) -> impl Iterator<Item = &[u8]> {
    bytes.split(|&b| b == 0)
}

/// For `kv daemon` on macOS: points stdin, stdout and stderr at /dev/null
/// where they are sockets, before anything touches them. macOS names as a
/// socket's peer the last process that read, wrote or polled it, so a
/// daemon writing to a socket it was handed as stderr would vouch for it.
#[cfg(target_os = "macos")]
pub fn detach_std_sockets() {
    for fd in 0..=2 {
        // SAFETY: fstat writes into `stat`; open and dup2 take valid
        // arguments, and a failure leaves the descriptor as it was.
        unsafe {
            let mut stat: libc::stat = std::mem::zeroed();
            if libc::fstat(fd, &mut stat) == 0 && (stat.st_mode & libc::S_IFMT) == libc::S_IFSOCK {
                let null = libc::open(c"/dev/null".as_ptr(), libc::O_RDWR);
                if null >= 0 {
                    libc::dup2(null, fd);
                    libc::close(null);
                }
            }
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::platform::count_listeners;

    const TABLE: &[u8] = b"Num       RefCount Protocol Flags    Type St Inode Path\n\
0000000000000000: 00000002 00000000 00010000 0001 01 101 /run/kv/control.sock\n\
0000000000000000: 00000002 00000000 00010000 0001 01   7 /run/kv/control.sock\n\
0000000000000000: 00000003 00000000 00000000 0001 03 102 /run/kv/control.sock\n\
0000000000000000: 00000002 00000000 00010000 0001 01 103 /run/kv/control.sock.old\n\
0000000000000000: 00000002 00000000 00010000 0001 01 104 /run/kv dir/control.sock\n\
0000000000000000: 00000002 00000000 00010000 0001 01 105\n";

    #[test]
    fn listeners_are_counted_by_exact_path_and_listening_flag() {
        // Two listeners, whatever the padding of the inode; the connected
        // socket and the longer path do not count.
        assert_eq!(count_listeners(TABLE, b"/run/kv/control.sock"), 2);
        assert_eq!(count_listeners(TABLE, b"/run/kv dir/control.sock"), 1);
        assert_eq!(count_listeners(TABLE, b"/run/kv/other.sock"), 0);
        assert_eq!(count_listeners(TABLE, b""), 0);
    }
}
