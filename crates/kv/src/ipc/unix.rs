use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;

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
