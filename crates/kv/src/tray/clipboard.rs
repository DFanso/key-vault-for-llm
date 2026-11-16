//! The Copy button in kv's window. On Windows the tray puts the value on
//! the clipboard itself, marked to stay out of clipboard history and the
//! cloud clipboard, and empties the clipboard after `CLEAR_AFTER` unless
//! something else was copied since. Elsewhere the page copies the value
//! and nothing clears it; clearing on macOS is a follow-up.

use std::time::Duration;

/// How long a copied value stays on the clipboard.
pub const CLEAR_AFTER: Duration = Duration::from_secs(20);

/// What to do with a value kv copied, some time after it copied it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    /// Not yet: look again after this long.
    Wait(Duration),
    /// Its time is up and it is still there: empty the clipboard.
    Clear,
    /// Something else was copied since: leave the clipboard alone.
    Leave,
}

/// Decides for a value copied `elapsed` ago, when the clipboard's sequence
/// number was `written` just after the copy and is `current` now. Every
/// change to the clipboard moves the number on, so an unchanged number
/// means the clipboard still holds kv's value. Where the system gives no
/// number (it gives 0), the value is cleared all the same.
pub fn decide(written: u32, current: u32, elapsed: Duration) -> Decision {
    if current != written {
        Decision::Leave
    } else if elapsed >= CLEAR_AFTER {
        Decision::Clear
    } else {
        Decision::Wait(CLEAR_AFTER - elapsed)
    }
}

#[cfg(windows)]
pub use self::windows::Clipboard;

#[cfg(windows)]
mod windows {
    use std::io;
    use std::ptr;
    use std::sync::{Arc, Mutex, PoisonError};
    use std::thread;
    use std::time::{Duration, Instant};

    use windows_sys::Win32::Foundation::{GlobalFree, HANDLE, HGLOBAL};
    use windows_sys::Win32::System::DataExchange::{
        CloseClipboard, EmptyClipboard, GetClipboardSequenceNumber, OpenClipboard,
        RegisterClipboardFormatW, SetClipboardData,
    };
    use windows_sys::Win32::System::Memory::{
        GMEM_MOVEABLE, GlobalAlloc, GlobalLock, GlobalUnlock,
    };
    use zeroize::Zeroizing;

    use super::{Decision, decide};

    /// The standard format for UTF-16 text (`CF_UNICODETEXT`).
    const UNICODE_TEXT: u32 = 13;

    /// Any data in this format keeps every format out of clipboard history
    /// and the cloud clipboard. kv puts a DWORD 0 there: Windows refuses a
    /// block of no bytes.
    const EXCLUDE_FROM_MONITORS: &str = "ExcludeClipboardContentFromMonitorProcessing";

    /// A DWORD 0 in this format keeps the copy out of clipboard history.
    const IN_HISTORY: &str = "CanIncludeInClipboardHistory";

    /// A DWORD 0 in this format keeps the copy out of the cloud clipboard.
    const TO_CLOUD: &str = "CanUploadToCloudClipboard";

    /// How many times to try to open the clipboard, which another program
    /// may hold for a moment.
    const OPEN_TRIES: u32 = 10;

    /// How long to wait between those tries.
    const OPEN_RETRY: Duration = Duration::from_millis(10);

    /// Puts values on the clipboard and takes them off again. It remembers
    /// the last value it copied, so the tray can clear it as it quits.
    #[derive(Default)]
    pub struct Clipboard {
        /// The clipboard's sequence number just after the last copy, until
        /// that copy is cleared or replaced.
        last: Arc<Mutex<Option<u32>>>,
    }

    impl Clipboard {
        /// Copies `text`, then clears it after `CLEAR_AFTER` on a thread
        /// of its own unless something else was copied since.
        pub fn copy(&self, text: &str) -> io::Result<()> {
            let written = write(text)?;
            *self.last.lock().unwrap_or_else(PoisonError::into_inner) = Some(written);
            let last = Arc::clone(&self.last);
            let spawned = thread::Builder::new()
                .name("kv-clipboard".into())
                .spawn(move || {
                    let copied = Instant::now();
                    loop {
                        // SAFETY: no arguments; reads a counter.
                        let current = unsafe { GetClipboardSequenceNumber() };
                        match decide(written, current, copied.elapsed()) {
                            Decision::Wait(left) => thread::sleep(left),
                            Decision::Clear => {
                                let _ = clear_if(written);
                                break;
                            }
                            Decision::Leave => break,
                        }
                    }
                    let mut slot = last.lock().unwrap_or_else(PoisonError::into_inner);
                    if *slot == Some(written) {
                        *slot = None;
                    }
                });
            if let Err(e) = spawned {
                // Nothing would clear it later, so it goes now.
                self.clear_now();
                return Err(e);
            }
            Ok(())
        }

        /// Clears the last value copied at once, if nothing replaced it.
        pub fn clear_now(&self) {
            let last = self
                .last
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .take();
            if let Some(written) = last {
                let _ = clear_if(written);
            }
        }
    }

    /// The clipboard, open until this is dropped.
    struct Open;

    impl Open {
        fn new() -> io::Result<Open> {
            for _ in 1..OPEN_TRIES {
                // SAFETY: a null owner is allowed; the clipboard is then
                // open for this thread.
                if unsafe { OpenClipboard(ptr::null_mut()) } != 0 {
                    return Ok(Open);
                }
                thread::sleep(OPEN_RETRY);
            }
            // SAFETY: as above.
            if unsafe { OpenClipboard(ptr::null_mut()) } != 0 {
                return Ok(Open);
            }
            Err(io::Error::last_os_error())
        }
    }

    impl Drop for Open {
        fn drop(&mut self) {
            // SAFETY: this thread opened the clipboard.
            unsafe { CloseClipboard() };
        }
    }

    /// Puts `text` on the clipboard, marked to stay out of history and the
    /// cloud, and returns the clipboard's sequence number after it. If a
    /// mark cannot be set, the text is not copied.
    fn write(text: &str) -> io::Result<u32> {
        let wide: Zeroizing<Vec<u16>> =
            Zeroizing::new(text.encode_utf16().chain(std::iter::once(0)).collect());
        // SAFETY: `wide` is live for the slice's lifetime, and u16s read
        // as twice as many bytes.
        let bytes =
            unsafe { std::slice::from_raw_parts(wide.as_ptr().cast::<u8>(), wide.len() * 2) };
        let no = 0u32.to_ne_bytes();
        {
            let _open = Open::new()?;
            // SAFETY: the clipboard is open.
            if unsafe { EmptyClipboard() } == 0 {
                return Err(io::Error::last_os_error());
            }
            // The marks go first, so the text is never there without them.
            set(format(EXCLUDE_FROM_MONITORS)?, &no)?;
            set(format(IN_HISTORY)?, &no)?;
            set(format(TO_CLOUD)?, &no)?;
            if let Err(e) = set(UNICODE_TEXT, bytes) {
                // SAFETY: the clipboard is open.
                unsafe { EmptyClipboard() };
                return Err(e);
            }
        }
        // SAFETY: no arguments; reads a counter.
        Ok(unsafe { GetClipboardSequenceNumber() })
    }

    /// Empties the clipboard if its sequence number is still `written`;
    /// whether it did. The check is made with the clipboard open, so
    /// nothing can be copied between the check and the clear.
    fn clear_if(written: u32) -> io::Result<bool> {
        let _open = Open::new()?;
        // SAFETY: no arguments; reads a counter.
        if unsafe { GetClipboardSequenceNumber() } != written {
            return Ok(false);
        }
        // SAFETY: the clipboard is open.
        if unsafe { EmptyClipboard() } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(true)
    }

    /// The id of the registered clipboard format `name`.
    fn format(name: &str) -> io::Result<u32> {
        let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        // SAFETY: `wide` is a NUL-terminated UTF-16 string.
        match unsafe { RegisterClipboardFormatW(wide.as_ptr()) } {
            0 => Err(io::Error::last_os_error()),
            id => Ok(id),
        }
    }

    /// Puts `data` on the open clipboard as `format`. The system owns the
    /// memory once it takes it; memory it refuses is zeroed and freed.
    fn set(format: u32, data: &[u8]) -> io::Result<()> {
        // SAFETY: a plain allocation; checked for null below.
        let memory: HGLOBAL = unsafe { GlobalAlloc(GMEM_MOVEABLE, data.len()) };
        if memory.is_null() {
            return Err(io::Error::last_os_error());
        }
        if !data.is_empty() {
            // SAFETY: `memory` is a live movable block of `data.len()` bytes.
            let at = unsafe { GlobalLock(memory) }.cast::<u8>();
            if at.is_null() {
                let e = io::Error::last_os_error();
                // SAFETY: `memory` is ours and unlocked.
                unsafe { GlobalFree(memory) };
                return Err(e);
            }
            // SAFETY: `at` has room for `data.len()` bytes and does not
            // overlap `data`.
            unsafe {
                ptr::copy_nonoverlapping(data.as_ptr(), at, data.len());
                GlobalUnlock(memory);
            }
        }
        // SAFETY: the clipboard is open and `memory` is a movable block.
        if unsafe { SetClipboardData(format, memory as HANDLE) }.is_null() {
            let e = io::Error::last_os_error();
            wipe(memory, data.len());
            // SAFETY: the system did not take `memory`, so it is still ours.
            unsafe { GlobalFree(memory) };
            return Err(e);
        }
        Ok(())
    }

    /// Zeroes the first `len` bytes of `memory`.
    fn wipe(memory: HGLOBAL, len: usize) {
        if len == 0 {
            return;
        }
        // SAFETY: `memory` is a live movable block of at least `len` bytes.
        let at = unsafe { GlobalLock(memory) }.cast::<u8>();
        if !at.is_null() {
            // SAFETY: as above; `at` points at `len` writable bytes.
            unsafe {
                ptr::write_bytes(at, 0, len);
                GlobalUnlock(memory);
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use windows_sys::Win32::System::DataExchange::{
            GetClipboardData, IsClipboardFormatAvailable,
        };

        use super::*;

        /// Uses the real clipboard and replaces what is on it, so it runs
        /// only when asked for: `cargo test -p kv --lib clipboard -- --ignored`.
        #[test]
        #[ignore = "replaces what is on the developer's clipboard"]
        fn a_copy_is_marked_and_cleared_only_while_still_there() {
            let text = "kv clipboard test, not a secret";
            let written = write(text).unwrap();
            {
                let _open = Open::new().unwrap();
                for name in [EXCLUDE_FROM_MONITORS, IN_HISTORY, TO_CLOUD] {
                    let id = format(name).unwrap();
                    // SAFETY: the clipboard is open.
                    assert_ne!(unsafe { IsClipboardFormatAvailable(id) }, 0, "{name}");
                }
                // SAFETY: the clipboard is open; the block holds the text
                // with its NUL, and stays locked while it is read.
                let read = unsafe {
                    let memory = GetClipboardData(UNICODE_TEXT);
                    assert!(!memory.is_null());
                    let at = GlobalLock(memory).cast::<u16>();
                    let len = (0..).take_while(|&i| *at.add(i) != 0).count();
                    let read = String::from_utf16(std::slice::from_raw_parts(at, len)).unwrap();
                    GlobalUnlock(memory);
                    read
                };
                assert_eq!(read, text);
            }
            // Something else copied since: left alone.
            assert!(!clear_if(written.wrapping_add(1)).unwrap());
            assert!(clear_if(written).unwrap());
            // SAFETY: no arguments; reads the clipboard's state.
            assert_eq!(unsafe { IsClipboardFormatAvailable(UNICODE_TEXT) }, 0);
        }
    }
}
