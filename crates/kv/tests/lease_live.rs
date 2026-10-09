//! `db_connect` leases relaying to real servers, with ordinary clients
//! (`tokio-postgres`, `redis`) on the lease URL. Set `KV_TEST_POSTGRES_URL`
//! (a superuser, Postgres 14 or later) and `KV_TEST_REDIS_URL` to run these;
//! without them they pass after a note, unless `KV_REQUIRE_DB_TESTS` is set.

mod common;

use common::*;
use kv::broker::lease;
use kv_core::policy::Mode;
use kv_core::proto::{AgentResponse, ConnectCall, LeaseReply};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

async fn start(f: &mut Fixture, call: ConnectCall) -> LeaseReply {
    match lease::start(f.connect(call).unwrap()).await {
        AgentResponse::Lease(reply) => reply,
        other => panic!("expected a lease, got {other:?}"),
    }
}

fn password(url: &str) -> String {
    url::Url::parse(url).unwrap().password().unwrap().to_owned()
}

#[tokio::test]
async fn a_redis_lease_relays_commands_with_secrets_scrubbed() {
    let Some(url) = server("KV_TEST_REDIS_URL") else {
        return;
    };
    let secret = "redis-lease-secret-0123456789";
    let mut f = Fixture::new();
    f.add(redis("cache", &url, false, Mode::Auto));
    f.add(env_secret("other", &[("TOKEN", secret)], &[], Mode::Auto));
    let reply = start(&mut f, lease("cache")).await;

    let client = redis::Client::open(reply.url.as_str()).unwrap();
    let mut db = client.get_multiplexed_async_connection().await.unwrap();
    let () = redis::cmd("SET")
        .arg("kv:lease")
        .arg(format!("value {secret}"))
        .query_async(&mut db)
        .await
        .unwrap();
    let got: String = redis::cmd("GET")
        .arg("kv:lease")
        .query_async(&mut db)
        .await
        .unwrap();
    assert_eq!(got, "value [kv:other]");
    let error = redis::cmd("SUBSCRIBE")
        .arg("news")
        .query_async::<()>(&mut db)
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("not available through db_connect"),
        "{error}"
    );

    // RESP3, where the client logs in with HELLO.
    let resp3 = redis::Client::open(format!("{}?protocol=resp3", reply.url)).unwrap();
    let mut db = resp3.get_multiplexed_async_connection().await.unwrap();
    let got: String = redis::cmd("GET")
        .arg("kv:lease")
        .query_async(&mut db)
        .await
        .unwrap();
    assert_eq!(got, "value [kv:other]");
}

#[tokio::test]
async fn a_read_only_redis_lease_answers_pipelined_commands_in_order() {
    let Some(url) = server("KV_TEST_REDIS_URL") else {
        return;
    };
    let mut f = Fixture::new();
    f.add(redis("cache", &url, false, Mode::Auto));
    f.add(redis("cache-ro", &url, true, Mode::Auto));
    run_redis(&mut f, "cache", "SET kv:pipe abc").await;
    let reply = start(&mut f, lease("cache-ro")).await;
    let token = password(&reply.url);
    let port = url::Url::parse(&reply.url).unwrap().port().unwrap();
    let mut socket = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let mut commands = format!("*2\r\n$4\r\nAUTH\r\n${}\r\n{token}\r\n", token.len()).into_bytes();
    for command in [
        &["GET", "kv:pipe"][..],
        &["DEL", "kv:pipe"],
        &["GET", "kv:pipe"],
    ] {
        commands.extend(format!("*{}\r\n", command.len()).bytes());
        for arg in command {
            commands.extend(format!("${}\r\n{arg}\r\n", arg.len()).bytes());
        }
    }
    commands.extend(b"*1\r\n$4\r\nQUIT\r\n");
    socket.write_all(&commands).await.unwrap();
    let mut answers = String::new();
    socket.read_to_string(&mut answers).await.unwrap();
    assert_eq!(
        answers,
        "+OK\r\n$3\r\nabc\r\n\
         -ERR kv: DEL is not a read command, and the handle is read-only\r\n\
         $3\r\nabc\r\n+OK\r\n"
    );
}

#[tokio::test]
async fn a_redis_lease_logs_in_upstream_with_a_user_and_password() {
    let Some(url) = server("KV_TEST_REDIS_URL") else {
        return;
    };
    let mut f = Fixture::new();
    f.add(redis("cache", &url, false, Mode::Auto));
    run_redis(
        &mut f,
        "cache",
        "ACL SETUSER kvlease on >kvlease-password-0123 ~kv:* +@all",
    )
    .await;
    let mut with_user = url::Url::parse(&url).unwrap();
    with_user.set_username("kvlease").unwrap();
    with_user
        .set_password(Some("kvlease-password-0123"))
        .unwrap();
    f.add(redis("cache-user", with_user.as_str(), false, Mode::Auto));
    let reply = start(&mut f, lease("cache-user")).await;
    let client = redis::Client::open(reply.url.as_str()).unwrap();
    let mut db = client.get_multiplexed_async_connection().await.unwrap();
    let who: String = redis::cmd("ACL")
        .arg("WHOAMI")
        .query_async(&mut db)
        .await
        .unwrap();
    assert_eq!(who, "kvlease");
}

async fn run_redis(f: &mut Fixture, handle: &str, command: &str) {
    let response = kv::broker::db::run(f.db(query(handle, command)).unwrap()).await;
    assert!(
        matches!(response, AgentResponse::Redis(_)),
        "{command}: {response:?}"
    );
}
