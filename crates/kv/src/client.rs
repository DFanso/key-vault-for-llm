//! Talking to the daemon from the CLI, starting it on demand.

use std::io;
use std::process::{Command, Stdio};
use std::time::Duration;

use kv_core::proto::{AgentRequest, AgentResponse, ControlRequest, ControlResponse, SessionInfo};
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::frame::{read_frame, write_frame};
use crate::ipc::{self, ClientStream};
use crate::paths::{Endpoint, Paths};

/// Connects to the endpoint. With `autostart`, a missing daemon is started
/// in the background and waited for, up to 5 seconds.
pub async fn connect(endpoint: &Endpoint, autostart: bool) -> io::Result<ClientStream> {
    match ipc::connect(endpoint).await {
        Ok(stream) => Ok(stream),
        Err(_) if autostart => {
            spawn_daemon()?;
            wait_for(endpoint).await
        }
        Err(e) => Err(e),
    }
}

/// Sends one agent request, starting the daemon if needed. With a session,
/// the connection first says which agent session is asking.
pub async fn agent(
    paths: &Paths,
    session: Option<&SessionInfo>,
    request: &AgentRequest,
) -> io::Result<AgentResponse> {
    let mut stream = connect(&paths.agent_endpoint(), true).await?;
    if let Some(session) = session {
        write_frame(&mut stream, &AgentRequest::Hello(session.clone())).await?;
    }
    exchange(&mut stream, request).await
}

/// Sends one control request. One that carries a Touch ID or Windows Hello
/// key goes only to a daemon running this same kv: the key opens the vault
/// for as long as the device stays enrolled, and anything could be
/// listening at the socket (after `kv stop`, or under another `KV_HOME`).
pub async fn control(
    paths: &Paths,
    request: &ControlRequest,
    autostart: bool,
) -> io::Result<ControlResponse> {
    let mut stream = connect(&paths.control_endpoint(), autostart).await?;
    if request.device.is_some() {
        check_daemon(&stream)?;
    }
    exchange(&mut stream, request).await
}

fn check_daemon(stream: &ClientStream) -> io::Result<()> {
    let refused = |why: String| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("{why}, so kv did not send it the unlock key; run `kv stop` and try again"),
        )
    };
    match ipc::runs_this_program(stream) {
        Ok(true) => Ok(()),
        Ok(false) => Err(refused(
            "the process at the kv socket is not this kv program".into(),
        )),
        Err(e) => Err(refused(format!(
            "could not check the process at the kv socket ({e})"
        ))),
    }
}

/// For `lock` and `stop`: `Ok(None)` when no daemon is running, which is
/// the only connect failure that means there is nothing to do.
pub async fn control_if_running(
    paths: &Paths,
    request: &ControlRequest,
) -> io::Result<Option<ControlResponse>> {
    let mut stream = match ipc::connect(&paths.control_endpoint()).await {
        Ok(stream) => stream,
        Err(e)
            if matches!(
                e.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
            ) =>
        {
            return Ok(None);
        }
        Err(e) => return Err(e),
    };
    exchange(&mut stream, request).await.map(Some)
}

async fn exchange<Req: Serialize, Resp: DeserializeOwned>(
    stream: &mut ClientStream,
    request: &Req,
) -> io::Result<Resp> {
    write_frame(stream, request).await?;
    read_frame(stream).await?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "the kv daemon closed the connection",
        )
    })
}

async fn wait_for(endpoint: &Endpoint) -> io::Result<ClientStream> {
    let mut last_error = None;
    for _ in 0..100 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        match ipc::connect(endpoint).await {
            Ok(stream) => return Ok(stream),
            Err(e) => last_error = Some(e),
        }
    }
    let detail = last_error.map(|e| e.to_string()).unwrap_or_default();
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        format!("the kv daemon did not start ({endpoint}): {detail}"),
    ))
}

/// Starts `kv daemon` detached from this process. If another client starts
/// one at the same moment, the loser exits when it finds the lock file held.
fn spawn_daemon() -> io::Result<()> {
    let mut command = Command::new(std::env::current_exe()?);
    command
        .args(["daemon", "--autostart"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const DETACHED_PROCESS: u32 = 0x0000_0008;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        command.creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP);
        stop_inheriting_std_handles();
    }
    command.spawn().map(drop)
}

/// Windows gives a child every inheritable handle, including this process's
/// own stdin, stdout and stderr, which are often a caller's pipes. A daemon
/// holding them would keep the caller waiting for output until it exits.
#[cfg(windows)]
fn stop_inheriting_std_handles() {
    use windows_sys::Win32::Foundation::{
        HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE, SetHandleInformation,
    };
    use windows_sys::Win32::System::Console::{
        GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
    };
    for which in [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
        // SAFETY: GetStdHandle returns this process's own handle, or null or
        // INVALID_HANDLE_VALUE when there is none. Clearing the inherit flag
        // only changes what future children receive.
        unsafe {
            let handle = GetStdHandle(which);
            if !handle.is_null() && handle != INVALID_HANDLE_VALUE {
                SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0);
            }
        }
    }
}
