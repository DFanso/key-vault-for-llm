//! Where kv keeps its files and how clients reach the daemon.

use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

/// Set `KV_HOME` to keep the vault, audit log and sockets under one
/// directory instead of the platform defaults.
pub const HOME_ENV: &str = "KV_HOME";

#[derive(Clone, Debug)]
pub struct Paths {
    pub vault: PathBuf,
    pub audit: PathBuf,
    /// Sockets and the daemon lock file.
    pub runtime: PathBuf,
}

impl Paths {
    pub fn from_env() -> io::Result<Self> {
        if let Some(home) = std::env::var_os(HOME_ENV) {
            return Ok(Self::under(Path::new(&home)));
        }
        let missing = || {
            io::Error::new(
                io::ErrorKind::NotFound,
                "cannot find the user's config directory; set KV_HOME",
            )
        };
        let config = dirs::config_dir().ok_or_else(missing)?.join("kv");
        let data = dirs::data_local_dir().ok_or_else(missing)?.join("kv");
        let runtime = dirs::runtime_dir()
            .map(|d| d.join("kv"))
            .unwrap_or_else(|| data.join("run"));
        Ok(Self {
            vault: config.join("vault.kv"),
            audit: data.join("audit.jsonl"),
            runtime,
        })
    }

    pub fn under(home: &Path) -> Self {
        Self {
            vault: home.join("vault.kv"),
            audit: home.join("audit.jsonl"),
            runtime: home.join("run"),
        }
    }

    pub fn lock_file(&self) -> PathBuf {
        self.runtime.join("daemon.lock")
    }

    pub fn agent_endpoint(&self) -> Endpoint {
        Endpoint::new(&self.runtime, "agent")
    }

    pub fn control_endpoint(&self) -> Endpoint {
        Endpoint::new(&self.runtime, "control")
    }

    /// Creates the runtime directory, private to the user on Unix.
    pub fn ensure_runtime_dir(&self) -> io::Result<()> {
        std::fs::create_dir_all(&self.runtime)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&self.runtime, std::fs::Permissions::from_mode(0o700))?;
        }
        Ok(())
    }
}

/// A socket the daemon listens on: a socket file in the runtime directory on
/// Unix, or on Windows a named pipe whose name is derived from that directory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Endpoint {
    #[cfg(unix)]
    pub path: PathBuf,
    #[cfg(windows)]
    pub name: String,
}

impl Endpoint {
    fn new(runtime: &Path, kind: &str) -> Self {
        #[cfg(unix)]
        {
            Self {
                path: runtime.join(format!("{kind}.sock")),
            }
        }
        #[cfg(windows)]
        {
            use std::hash::{DefaultHasher, Hash, Hasher};
            let mut hasher = DefaultHasher::new();
            runtime.hash(&mut hasher);
            Self {
                name: format!(r"\\.\pipe\kv-{:016x}-{kind}", hasher.finish()),
            }
        }
    }
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        #[cfg(unix)]
        {
            write!(f, "{}", self.path.display())
        }
        #[cfg(windows)]
        {
            f.write_str(&self.name)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kv_home_puts_everything_under_one_directory() {
        let paths = Paths::under(Path::new("/tmp/kv-home"));
        assert_eq!(paths.vault, Path::new("/tmp/kv-home/vault.kv"));
        assert_eq!(paths.audit, Path::new("/tmp/kv-home/audit.jsonl"));
        assert_eq!(paths.lock_file(), Path::new("/tmp/kv-home/run/daemon.lock"));
    }

    #[test]
    fn endpoints_differ_by_kind_and_by_home() {
        let a = Paths::under(Path::new("/tmp/a"));
        let b = Paths::under(Path::new("/tmp/b"));
        assert_ne!(a.agent_endpoint(), a.control_endpoint());
        assert_ne!(a.agent_endpoint(), b.agent_endpoint());
        assert_eq!(a.agent_endpoint(), a.agent_endpoint());
    }
}
