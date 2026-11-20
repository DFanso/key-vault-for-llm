//! Local sockets the daemon listens on: Unix domain sockets on Unix, named
//! pipes on Windows. Both accept connections only from the current user.
//!
//! Each platform module provides `Listener`, `ServerStream`, `ClientStream`,
//! `bind`, `connect`, `cleanup` and `server_program`.

use std::io;
use std::path::{Path, PathBuf};

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
/// it should be. `Ok(Err(program))` names the program it runs instead.
/// The process must also belong to the current user: `server_program`
/// checks that on Unix, and `connect` checks the pipe's owner on Windows.
pub fn server_is_this_program(stream: &ClientStream) -> io::Result<Result<(), PathBuf>> {
    let theirs = server_program(stream)?;
    if same_file(&theirs, &crate::update::swap::running_exe()?) {
        Ok(Ok(()))
    } else {
        Ok(Err(theirs))
    }
}

fn same_file(a: &Path, b: &Path) -> bool {
    match (a.canonicalize(), b.canonicalize()) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}
