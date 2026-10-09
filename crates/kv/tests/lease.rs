//! `db_connect` as the daemon authorizes it, and the parts of a lease that
//! need no database: the URL, logging in with the token, expiry, and ending
//! when the vault locks or the handle changes. `db_live.rs` relays real
//! traffic.

mod common;

use std::time::Duration;

use common::*;
use kv::broker::lease;
use kv_core::policy::Mode;
use kv_core::proto::{
    AgentErrorCode, AgentRequest, AgentResponse, ConnectCall, ControlCommand, LeaseReply,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const PG_URL: &str = "postgres://app:pg-password-0123456789@db.internal.example:5432/app";
const REDIS_URL: &str = "redis://:redis-password-0123456789@cache.internal.example:6380/2";

async fn start(f: &mut Fixture, call: ConnectCall) -> LeaseReply {
    match lease::start(f.connect(call).unwrap()).await {
        AgentResponse::Lease(reply) => reply,
        other => panic!("expected a lease, got {other:?}"),
    }
}

fn port(url: &str) -> u16 {
    url::Url::parse(url).unwrap().port().unwrap()
}

/// Waits for the lease's port to stop accepting, for at most 3 seconds.
async fn closes(port: u16) -> bool {
    for _ in 0..60 {
        if TcpStream::connect(("127.0.0.1", port)).await.is_err() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    false
}

#[test]
fn only_database_handles_get_leases_for_a_bounded_time() {
    let mut f = Fixture::new();
    f.add(openrouter(Mode::Auto));
    f.add(postgres("pg", PG_URL, false, Mode::Auto));
    let (code, _) = f.connect(lease("openrouter")).unwrap_err();
    assert_eq!(code, AgentErrorCode::PolicyDenied);
    let (code, _) = f.connect(lease("missing")).unwrap_err();
    assert_eq!(code, AgentErrorCode::UnknownHandle);
    assert_eq!(
        f.connect(lease("pg")).unwrap().ttl,
        Duration::from_secs(900)
    );
    for ttl in [0, 3601] {
        let (code, message) = f
            .connect(ConnectCall {
                ttl_secs: Some(ttl),
                ..lease("pg")
            })
            .unwrap_err();
        assert_eq!(code, AgentErrorCode::BadRequest);
        assert!(message.contains("3600"), "{message}");
    }
}

#[test]
fn a_lease_in_ask_mode_waits_and_says_for_how_long() {
    let mut f = Fixture::new();
    f.add(postgres("pg", PG_URL, false, Mode::Ask));
    let waiting = f.wait(
        Some(&session("s1")),
        AgentRequest::DbConnect(ConnectCall {
            ttl_secs: Some(600),
            ..lease("pg")
        }),
        f.t0,
    );
    let token = f.token();
    let approvals = f.overview(&token).approvals;
    assert_eq!(approvals[0].id, waiting.id);
    assert_eq!(approvals[0].tool, "db_connect");
    assert_eq!(approvals[0].detail, "a connection URL that works for 10m");
}

#[test]
fn leases_end_when_the_vault_locks_or_their_handle_changes() {
    let mut f = Fixture::new();
    f.add(postgres("pg", PG_URL, false, Mode::Auto));
    f.add(redis("cache", REDIS_URL, false, Mode::Auto));
    let pg = f.connect(lease("pg")).unwrap();
    let cache = f.connect(lease("cache")).unwrap();
    f.control(ControlCommand::Remove { name: "pg".into() });
    assert!(pg.ticket.has_ended());
    assert!(!cache.ticket.has_ended());
    f.control(ControlCommand::Lock);
    assert!(cache.ticket.has_ended());
}

#[test]
fn at_most_sixteen_leases_are_open_at_once() {
    let mut f = Fixture::new();
    f.add(postgres("pg", PG_URL, false, Mode::Auto));
    let mut open: Vec<_> = (0..16).map(|_| f.connect(lease("pg")).unwrap()).collect();
    let (code, message) = f.connect(lease("pg")).unwrap_err();
    assert_eq!(code, AgentErrorCode::PolicyDenied);
    assert!(message.contains("16 leases"), "{message}");
    open.pop();
    assert!(f.connect(lease("pg")).is_ok());
}

#[tokio::test]
async fn a_lease_approved_after_the_vault_locked_does_not_start() {
    let mut f = Fixture::new();
    f.add(postgres("pg", PG_URL, false, Mode::Auto));
    let job = f.connect(lease("pg")).unwrap();
    f.control(ControlCommand::Lock);
    match lease::start(job).await {
        AgentResponse::Error { code, .. } => assert_eq!(code, AgentErrorCode::PolicyDenied),
        other => panic!("expected an error, got {other:?}"),
    }
}

#[tokio::test]
async fn a_redis_lease_needs_the_token_before_any_command() {
    let mut f = Fixture::new();
    f.add(redis("cache", REDIS_URL, false, Mode::Auto));
    let reply = start(&mut f, lease("cache")).await;
    let url = url::Url::parse(&reply.url).unwrap();
    assert_eq!((url.scheme(), url.path()), ("redis", "/2"));
    let mut client = TcpStream::connect(("127.0.0.1", port(&reply.url)))
        .await
        .unwrap();
    client
        .write_all(b"*2\r\n$3\r\nGET\r\n$1\r\nk\r\n*2\r\n$4\r\nAUTH\r\n$5\r\nwrong\r\n")
        .await
        .unwrap();
    let mut answer = String::new();
    client.read_to_string(&mut answer).await.unwrap();
    assert_eq!(
        answer,
        "-NOAUTH Authentication required.\r\n\
         -WRONGPASS invalid username-password pair or user is disabled.\r\n"
    );
}

#[tokio::test]
async fn a_lease_stops_answering_when_it_expires_or_the_vault_locks() {
    let mut f = Fixture::new();
    f.add(redis("cache", REDIS_URL, false, Mode::Auto));
    let short = start(
        &mut f,
        ConnectCall {
            ttl_secs: Some(1),
            ..lease("cache")
        },
    )
    .await;
    let long = start(&mut f, lease("cache")).await;
    assert!(
        TcpStream::connect(("127.0.0.1", port(&long.url)))
            .await
            .is_ok()
    );
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert!(closes(port(&short.url)).await);
    assert!(
        TcpStream::connect(("127.0.0.1", port(&long.url)))
            .await
            .is_ok()
    );
    f.control(ControlCommand::Lock);
    assert!(closes(port(&long.url)).await);
}
