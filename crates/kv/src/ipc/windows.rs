use std::ffi::{OsString, c_void};
use std::io;
use std::os::windows::ffi::OsStringExt;
use std::os::windows::io::AsRawHandle;
use std::path::PathBuf;
use std::time::Duration;

use tokio::net::windows::named_pipe::{
    ClientOptions, NamedPipeClient, NamedPipeServer, ServerOptions,
};
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_PIPE_BUSY, ERROR_SUCCESS, HANDLE, LocalFree,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo,
    SDDL_REVISION_1, SE_KERNEL_OBJECT,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
    SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows_sys::Win32::System::Pipes::GetNamedPipeServerProcessId;
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_NAME_WIN32,
    PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
};

use crate::paths::Endpoint;

pub type ServerStream = NamedPipeServer;
pub type ClientStream = NamedPipeClient;

pub struct Listener {
    name: String,
    /// Security descriptor owned by and granting access to the current user
    /// only, as a NUL-terminated UTF-16 SDDL string.
    sddl: Vec<u16>,
    next: NamedPipeServer,
}

/// Creates the first pipe instance. Fails if another process already owns
/// the name, which the daemon lock file should already have prevented.
pub fn bind(endpoint: &Endpoint) -> io::Result<Listener> {
    let sid = current_user_sid()?;
    let sddl: Vec<u16> = format!("O:{sid}D:P(A;;GA;;;{sid})")
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

/// Opens the pipe and checks that the current user created it. Pipe names
/// are machine-wide, so on a shared machine another account could create
/// the name first and collect whatever the client sends.
pub async fn connect(endpoint: &Endpoint) -> io::Result<ClientStream> {
    let client = open(endpoint).await?;
    ensure_owned_by(&client, &current_user_sid()?)?;
    Ok(client)
}

async fn open(endpoint: &Endpoint) -> io::Result<ClientStream> {
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

fn ensure_owned_by(pipe: &impl AsRawHandle, sid: &str) -> io::Result<()> {
    let owner = owner_sid(pipe.as_raw_handle())?;
    if owner == sid {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("the kv pipe belongs to another account ({owner}); refusing to use it"),
        ))
    }
}

fn owner_sid(handle: HANDLE) -> io::Result<String> {
    let mut owner: PSID = std::ptr::null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: `handle` is an open pipe handle. On success `owner` points into
    // `descriptor`, a LocalAlloc'd buffer freed below after the SID is copied.
    unsafe {
        let status = GetSecurityInfo(
            handle,
            SE_KERNEL_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut descriptor,
        );
        if status != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        let text = sid_to_string(owner);
        LocalFree(descriptor);
        text
    }
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
        sid_to_string(user.User.Sid)
    }
}

/// # Safety
/// `sid` must point to a valid SID.
unsafe fn sid_to_string(sid: PSID) -> io::Result<String> {
    let mut text: *mut u16 = std::ptr::null_mut();
    // SAFETY: the caller guarantees `sid`; `text` is LocalAlloc'd on success
    // and freed once after copying.
    unsafe {
        if ConvertSidToStringSidW(sid, &mut text) == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut len = 0;
        while *text.add(len) != 0 {
            len += 1;
        }
        let owned = String::from_utf16_lossy(std::slice::from_raw_parts(text, len));
        LocalFree(text.cast());
        Ok(owned)
    }
}

/// The program the process at the server end of `stream` runs.
pub fn server_program(stream: &ClientStream) -> io::Result<PathBuf> {
    let pipe = stream.as_raw_handle() as HANDLE;
    let mut pid = 0u32;
    // SAFETY: `pipe` is the client end of an open named pipe.
    if unsafe { GetNamedPipeServerProcessId(pipe, &mut pid) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a plain query; the handle is closed below.
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if process.is_null() {
        return Err(io::Error::last_os_error());
    }
    let mut buffer = vec![0u16; 32 * 1024];
    let mut len = buffer.len() as u32;
    // SAFETY: `len` is the buffer's length in UTF-16 units; the call sets it
    // to the number written.
    let ok = unsafe {
        QueryFullProcessImageNameW(process, PROCESS_NAME_WIN32, buffer.as_mut_ptr(), &mut len)
    };
    let error = io::Error::last_os_error();
    // SAFETY: `process` was opened above and is not used again.
    unsafe { CloseHandle(process) };
    if ok == 0 {
        return Err(error);
    }
    Ok(PathBuf::from(OsString::from_wide(&buffer[..len as usize])))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn pipes_owned_by_another_account_are_refused() {
        let endpoint = Endpoint {
            name: format!(r"\\.\pipe\kv-test-owner-{}", std::process::id()),
        };
        let _listener = bind(&endpoint).unwrap();
        let client = open(&endpoint).await.unwrap();
        let me = current_user_sid().unwrap();
        assert!(ensure_owned_by(&client, &me).is_ok());
        let error = ensure_owned_by(&client, "S-1-5-18").unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }
}
