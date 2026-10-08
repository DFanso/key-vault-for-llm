//! Local sockets the daemon listens on: Unix domain sockets on Unix, named
//! pipes on Windows. Both accept connections only from the current user.
//!
//! Each platform module provides `Listener`, `ServerStream`, `ClientStream`,
//! `bind`, `connect` and `cleanup`.

#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub use unix::*;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::*;
