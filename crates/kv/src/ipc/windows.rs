use std::ffi::c_void;
use std::io;
use std::time::Duration;

use tokio::net::windows::named_pipe::{
    ClientOptions, NamedPipeClient, NamedPipeServer, ServerOptions,
};
use windows_sys::Win32::Foundation::{CloseHandle, ERROR_PIPE_BUSY, HANDLE, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER,
    TokenUser,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use crate::paths::Endpoint;

pub type ServerStream = NamedPipeServer;
pub type ClientStream = NamedPipeClient;

pub struct Listener {
    name: String,
    /// Security descriptor granting access to the current user only, as a
    /// NUL-terminated UTF-16 SDDL string.
    sddl: Vec<u16>,
    next: NamedPipeServer,
}

/// Creates the first pipe instance. Fails if another process already owns
/// the name, which the daemon lock file should already have prevented.
pub fn bind(endpoint: &Endpoint) -> io::Result<Listener> {
    let sid = current_user_sid()?;
    let sddl: Vec<u16> = format!("D:P(A;;GA;;;{sid})")
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let next = create(&endpoint.name, &sddl, true)?;
    Ok(Listener {
        name: endpoint.name.clone(),
        sddl,
        next,
    })
}

impl Listener {
    pub async fn accept(&mut self) -> io::Result<ServerStream> {
        self.next.connect().await?;
        let fresh = create(&self.name, &self.sddl, false)?;
        Ok(std::mem::replace(&mut self.next, fresh))
    }
}

pub async fn connect(endpoint: &Endpoint) -> io::Result<ClientStream> {
    for _ in 0..40 {
        match ClientOptions::new().open(&endpoint.name) {
            Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY as i32) => {
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            result => return result,
        }
    }
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        "the kv daemon's pipe stayed busy",
    ))
}

pub fn cleanup(_endpoint: &Endpoint) {}

/// Creates one pipe instance that only the current user can open and that
/// refuses remote clients.
fn create(name: &str, sddl: &[u16], first: bool) -> io::Result<NamedPipeServer> {
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: `sddl` is NUL-terminated UTF-16. On success `descriptor` points
    // to a LocalAlloc'd buffer, freed below.
    let converted = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            std::ptr::null_mut(),
        )
    };
    if converted == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor,
        bInheritHandle: 0,
    };
    let mut options = ServerOptions::new();
    options
        .first_pipe_instance(first)
        .reject_remote_clients(true);
    // SAFETY: `attributes` is a valid SECURITY_ATTRIBUTES that outlives the call.
    let result = unsafe {
        options.create_with_security_attributes_raw(
            name,
            (&mut attributes as *mut SECURITY_ATTRIBUTES).cast::<c_void>(),
        )
    };
    // SAFETY: `descriptor` came from the conversion above and is freed once.
    unsafe { LocalFree(descriptor) };
    result
}

/// The current user's SID as a string such as `S-1-5-21-...`.
fn current_user_sid() -> io::Result<String> {
    // SAFETY: standard token query. Every handle and buffer is checked
    // before use and released before returning.
    unsafe {
        let mut token: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut len = 0u32;
        GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut len);
        let mut buffer = vec![0u8; len as usize];
        let queried =
            GetTokenInformation(token, TokenUser, buffer.as_mut_ptr().cast(), len, &mut len);
        CloseHandle(token);
        if queried == 0 {
            return Err(io::Error::last_os_error());
        }
        let user: TOKEN_USER = std::ptr::read_unaligned(buffer.as_ptr().cast());
        let mut sid: *mut u16 = std::ptr::null_mut();
        if ConvertSidToStringSidW(user.User.Sid, &mut sid) == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut sid_len = 0;
        while *sid.add(sid_len) != 0 {
            sid_len += 1;
        }
        let text = String::from_utf16_lossy(std::slice::from_raw_parts(sid, sid_len));
        LocalFree(sid.cast());
        Ok(text)
    }
}
