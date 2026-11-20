//! Local sockets the daemon listens on: Unix domain sockets on Unix, named
//! pipes on Windows. Both accept connections only from the current user.
//!
//! Each platform module provides `Listener`, `ServerStream`, `ClientStream`,
//! `bind`, `connect`, `cleanup` and `check_server`.

use std::path::Path;

#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub use unix::*;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::*;

/// Whether `args` (a process's arguments, its program first) run `kv
/// daemon` for `runtime`: `daemon` first, then `--runtime-dir <dir>` or
/// `--runtime-dir=<dir>` naming the same directory. A daemon started without
/// that option starts itself again with it (see `cli`).
pub fn is_daemon_for(args: &[std::ffi::OsString], runtime: &Path) -> bool {
    if args.get(1).is_none_or(|arg| arg != "daemon") {
        return false;
    }
    let mut named = None;
    let mut rest = args[2..].iter();
    while let Some(arg) = rest.next() {
        if arg == "--" {
            break;
        }
        if arg == RUNTIME_DIR_FLAG {
            named = rest.next().cloned();
        } else if let Some(value) = arg
            .to_str()
            .and_then(|a| a.strip_prefix(RUNTIME_DIR_FLAG))
            .and_then(|a| a.strip_prefix('='))
        {
            named = Some(value.into());
        }
    }
    named.is_some_and(|dir| same_file(Path::new(&dir), runtime))
}

/// The `kv daemon` option naming the runtime directory it serves, so its
/// clients can read it from the process's arguments.
pub const RUNTIME_DIR_FLAG: &str = "--runtime-dir";

/// Whether `a` and `b` name the same existing file.
pub(crate) fn same_file(a: &Path, b: &Path) -> bool {
    match (a.canonicalize(), b.canonicalize()) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;

    fn args(list: &[&str]) -> Vec<OsString> {
        list.iter().map(OsString::from).collect()
    }

    #[test]
    fn only_kv_daemon_for_this_runtime_directory_counts() {
        let dir = tempfile::TempDir::new().unwrap();
        let other = tempfile::TempDir::new().unwrap();
        let runtime = dir.path();
        let named = runtime.to_str().unwrap();
        let flag = format!("--runtime-dir={named}");
        assert!(is_daemon_for(
            &args(&["kv", "daemon", "--runtime-dir", named]),
            runtime
        ));
        assert!(is_daemon_for(
            &args(&["kv", "daemon", "--autostart", &flag]),
            runtime
        ));
        // Another directory, no directory, or not the daemon.
        let elsewhere = other.path().to_str().unwrap();
        assert!(!is_daemon_for(
            &args(&["kv", "daemon", "--runtime-dir", elsewhere]),
            runtime
        ));
        assert!(!is_daemon_for(
            &args(&["kv", "daemon", "--autostart"]),
            runtime
        ));
        assert!(!is_daemon_for(
            &args(&["kv", "daemon", "--runtime-dir"]),
            runtime
        ));
        assert!(!is_daemon_for(
            &args(&["kv", "mcp", "--runtime-dir", named]),
            runtime
        ));
        assert!(!is_daemon_for(&args(&["kv"]), runtime));
        // The last one given is the one clap uses.
        assert!(!is_daemon_for(
            &args(&[
                "kv",
                "daemon",
                "--runtime-dir",
                named,
                "--runtime-dir",
                elsewhere
            ]),
            runtime
        ));
    }
}
