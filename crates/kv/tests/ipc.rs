use kv::frame::{read_frame, write_frame};
use kv::ipc;
use kv::paths::Paths;
use kv_core::proto::AgentRequest;

#[tokio::test]
async fn client_and_daemon_exchange_frames() {
    let home = tempfile::TempDir::new().unwrap();
    let paths = Paths::under(home.path());
    paths.ensure_runtime_dir().unwrap();
    let endpoint = paths.agent_endpoint();
    let mut listener = ipc::bind(&endpoint).unwrap();

    let server = tokio::spawn(async move {
        let mut stream = listener.accept().await.unwrap();
        let request: AgentRequest = read_frame(&mut stream).await.unwrap().unwrap();
        write_frame(&mut stream, &request).await.unwrap();
    });
    let mut client = ipc::connect(&endpoint).await.unwrap();
    write_frame(&mut client, &AgentRequest::ListHandles)
        .await
        .unwrap();
    let echoed: AgentRequest = read_frame(&mut client).await.unwrap().unwrap();
    server.await.unwrap();
    assert_eq!(echoed, AgentRequest::ListHandles);
    ipc::cleanup(&endpoint);
}

#[tokio::test]
async fn connect_fails_when_nothing_listens() {
    let home = tempfile::TempDir::new().unwrap();
    let paths = Paths::under(home.path());
    assert!(ipc::connect(&paths.agent_endpoint()).await.is_err());
}

#[cfg(unix)]
#[tokio::test]
async fn bind_replaces_a_stale_socket_file_and_makes_it_private() {
    use std::os::unix::fs::PermissionsExt;
    let home = tempfile::TempDir::new().unwrap();
    let paths = Paths::under(home.path());
    paths.ensure_runtime_dir().unwrap();
    let endpoint = paths.agent_endpoint();
    std::fs::write(&endpoint.path, b"stale").unwrap();
    let _listener = ipc::bind(&endpoint).unwrap();
    let mode = std::fs::metadata(&endpoint.path)
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600);
    let dir_mode = std::fs::metadata(&paths.runtime)
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(dir_mode, 0o700);
}
