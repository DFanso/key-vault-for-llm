//! Local sockets the daemon listens on: Unix domain sockets on Unix, named
//! pipes on Windows. Both accept connections only from the current user.
//!
//! Each platform module provides `Listener`, `ServerStream`, `ClientStream`,
//! `bind`, `connect`, `cleanup` and `server_program`.

use std::io;
use std::path::Path;

#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub use unix::*;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::*;

/// Whether the process at the other end of `stream` runs this same program,
/// so a client can tell the kv daemon from anything else listening where
/// it should be.
pub fn runs_this_program(stream: &ClientStream) -> io::Result<bool> {
    let theirs = server_program(stream)?;
    Ok(same_file(&theirs, &std::env::current_exe()?))
}

fn same_file(a: &Path, b: &Path) -> bool {
    match (a.canonicalize(), b.canonicalize()) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}
