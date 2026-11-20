//! Control requests sent straight over the daemon's socket, for tests whose
//! daemon is the `kv` binary. `kv::client::control` sends credentials only
//! to a daemon running the same program as the caller, and the caller here
//! is the test binary, so these tests stand in for `kv tui` without it.
#![allow(dead_code)]

use std::io;

use kv::frame::{read_frame, write_frame};
use kv::paths::Paths;
use kv_core::proto::{ControlRequest, ControlResponse};

pub async fn control(paths: &Paths, request: &ControlRequest) -> io::Result<ControlResponse> {
    let mut stream = kv::ipc::connect(&paths.control_endpoint()).await?;
    write_frame(&mut stream, request).await?;
    read_frame(&mut stream)
        .await?
        .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "the daemon closed"))
}
