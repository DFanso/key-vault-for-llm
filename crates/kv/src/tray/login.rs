//! The login item that starts `kv tray`: a LaunchAgent on macOS, a value
//! under the Run key on Windows. kv only writes or removes it; it takes
//! effect at the next login.

#[cfg(target_os = "macos")]
pub use macos::*;
#[cfg(windows)]
pub use windows::*;

#[cfg(not(any(target_os = "macos", windows)))]
pub fn is_on() -> bool {
    false
}

#[cfg(not(any(target_os = "macos", windows)))]
pub fn set(_on: bool) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "kv tray runs on macOS and Windows only",
    ))
}

#[cfg(target_os = "macos")]
mod macos {
    use std::io;
    use std::path::{Path, PathBuf};

    const LABEL: &str = "dev.dfanso.kv.tray";

    pub fn is_on() -> bool {
        dirs::home_dir().is_some_and(|home| is_on_at(&home))
    }

    pub fn set(on: bool) -> io::Result<()> {
        let home = dirs::home_dir()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no home directory"))?;
        set_at(&home, &std::env::current_exe()?, on)
    }

    pub fn plist_path(home: &Path) -> PathBuf {
        home.join("Library/LaunchAgents")
            .join(format!("{LABEL}.plist"))
    }

    pub fn is_on_at(home: &Path) -> bool {
        plist_path(home).exists()
    }

    pub fn set_at(home: &Path, exe: &Path, on: bool) -> io::Result<()> {
        let path = plist_path(home);
        if on {
            if let Some(dir) = path.parent() {
                std::fs::create_dir_all(dir)?;
            }
            std::fs::write(&path, plist(exe))
        } else {
            match std::fs::remove_file(&path) {
                Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
                other => other,
            }
        }
    }

    /// A LaunchAgent that runs `<exe> tray` at login.
    pub fn plist(exe: &Path) -> String {
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
             <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \
             \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
             <plist version=\"1.0\">\n\
             <dict>\n\
             \t<key>Label</key>\n\
             \t<string>{LABEL}</string>\n\
             \t<key>ProgramArguments</key>\n\
             \t<array>\n\
             \t\t<string>{}</string>\n\
             \t\t<string>tray</string>\n\
             \t</array>\n\
             \t<key>RunAtLoad</key>\n\
             \t<true/>\n\
             \t<key>ProcessType</key>\n\
             \t<string>Interactive</string>\n\
             </dict>\n\
             </plist>\n",
            escape(&exe.to_string_lossy())
        )
    }

    fn escape(text: &str) -> String {
        text.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
    }
}

#[cfg(windows)]
mod windows {
    use std::io;
    use std::path::Path;
    use std::ptr::null_mut;

    use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS};
    use windows_sys::Win32::System::Registry::{
        HKEY_CURRENT_USER, REG_SZ, RRF_RT_REG_SZ, RegDeleteKeyValueW, RegGetValueW, RegSetKeyValueW,
    };

    const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
    const VALUE: &str = "kv tray";

    pub fn is_on() -> bool {
        let (key, value) = (wide(RUN_KEY), wide(VALUE));
        // SAFETY: both names are NUL-terminated; no data is asked for.
        let status = unsafe {
            RegGetValueW(
                HKEY_CURRENT_USER,
                key.as_ptr(),
                value.as_ptr(),
                RRF_RT_REG_SZ,
                null_mut(),
                null_mut(),
                null_mut(),
            )
        };
        status == ERROR_SUCCESS
    }

    pub fn set(on: bool) -> io::Result<()> {
        let (key, value) = (wide(RUN_KEY), wide(VALUE));
        let status = if on {
            let data = wide(&command(&std::env::current_exe()?));
            // SAFETY: the names are NUL-terminated and `data` holds
            // `data.len()` UTF-16 units, NUL included.
            unsafe {
                RegSetKeyValueW(
                    HKEY_CURRENT_USER,
                    key.as_ptr(),
                    value.as_ptr(),
                    REG_SZ,
                    data.as_ptr().cast(),
                    (data.len() * 2) as u32,
                )
            }
        } else {
            // SAFETY: both names are NUL-terminated.
            match unsafe { RegDeleteKeyValueW(HKEY_CURRENT_USER, key.as_ptr(), value.as_ptr()) } {
                ERROR_FILE_NOT_FOUND => ERROR_SUCCESS,
                status => status,
            }
        };
        if status == ERROR_SUCCESS {
            Ok(())
        } else {
            Err(io::Error::from_raw_os_error(status as i32))
        }
    }

    /// The command line the Run key starts: `"<exe>" tray`.
    pub fn command(exe: &Path) -> String {
        format!("\"{}\" tray", exe.display())
    }

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain([0]).collect()
    }
}
