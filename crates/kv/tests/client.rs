//! Asking the daemon for its status without starting it, as `kv tray` does
//! every second.

mod live;

use kv::client;
use kv::paths::Paths;
use kv_core::proto::{AgentRequest, AgentResponse};
use live::Daemon;
use tempfile::TempDir;

#[tokio::test]
async fn without_a_daemon_status_is_none_and_none_is_started() {
    let dir = TempDir::new().unwrap();
    let paths = Paths::under(dir.path());
    let reply = client::agent_if_running(&paths, &AgentRequest::Status)
        .await
        .unwrap();
    assert!(reply.is_none());
    assert!(
        !paths.lock_file().exists(),
        "asking must not start a daemon"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_running_daemon_answers() {
    let daemon = Daemon::start().await;
    match client::agent_if_running(&daemon.paths, &AgentRequest::Status).await {
        Ok(Some(AgentResponse::Status { status })) => assert!(status.vault_exists),
        other => panic!("{other:?}"),
    }
}
