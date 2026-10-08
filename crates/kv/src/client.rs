//! Talking to the daemon from the CLI, starting it on demand.

use std::io;
use std::process::{Command, Stdio};
use std::time::Duration;

use kv_core::proto::{AgentRequest, AgentResponse, ControlRequest, ControlResponse};
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

pub async fn agent(paths: &Paths, request: &AgentRequest) -> io::Result<AgentResponse> {
    let mut stream = connect(&paths.agent_endpoint(), true).await?;
    exchange(&mut stream, request).await
}

/// `autostart` is false for `lock` and `stop`, which have nothing to do when
/// no daemon is running.
pub async fn control(
    paths: &Paths,
    request: &ControlRequest,
    autostart: bool,
) -> io::Result<ControlResponse> {
    let mut stream = connect(&paths.control_endpoint(), autostart).await?;
    exchange(&mut stream, request).await
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
        .arg("daemon")
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
    }
    command.spawn().map(drop)
}
