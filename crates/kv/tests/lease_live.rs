//! `db_connect` leases relaying to real servers, with ordinary clients
//! (`tokio-postgres`, `redis`) on the lease URL. Set `KV_TEST_POSTGRES_URL`
//! (a superuser, Postgres 14 or later) and `KV_TEST_REDIS_URL` to run these;
//! without them they pass after a note, unless `KV_REQUIRE_DB_TESTS` is set.

mod common;

use std::time::Duration;

use common::*;
use futures_util::StreamExt;
use kv::broker::lease;
use kv_core::policy::Mode;
use kv_core::proto::{AgentResponse, ConnectCall, ControlCommand, LeaseReply};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_postgres::{NoTls, SimpleQueryMessage};

async fn start(f: &mut Fixture, call: ConnectCall) -> LeaseReply {
    match lease::start(f.connect(call).unwrap()).await {
        AgentResponse::Lease(reply) => reply,
        other => panic!("expected a lease, got {other:?}"),
    }
}

async fn client(url: &str) -> tokio_postgres::Client {
    let (client, connection) = tokio_postgres::connect(url, NoTls).await.unwrap();
    tokio::spawn(connection);
    client
}

/// The first value of the first row, in text.
async fn value(client: &tokio_postgres::Client, sql: &str) -> Option<String> {
    let messages = client.simple_query(sql).await.unwrap();
    messages.iter().find_map(|message| match message {
        SimpleQueryMessage::Row(row) => Some(row.get(0).map(str::to_owned)),
        _ => None,
    })?
}

fn password(url: &str) -> String {
    url::Url::parse(url).unwrap().password().unwrap().to_owned()
}

#[tokio::test]
async fn a_postgres_lease_relays_queries_with_secrets_scrubbed() {
    let Some(url) = server("KV_TEST_POSTGRES_URL") else {
        return;
    };
    let secret = password(&url);
    let admin = admin(&url, "kv_lease").await;
    admin
        .batch_execute(&format!(
            "CREATE TABLE kv_lease.notes (id int, body text);
             INSERT INTO kv_lease.notes VALUES
               (1, 'the password is {secret}'), (2, 'later: other-secret-0123456789');"
        ))
        .await
        .unwrap();
    let mut f = Fixture::new();
    f.add(postgres("pg", &url, false, Mode::Auto));
    let reply = start(&mut f, lease("pg")).await;
    assert!(reply.warnings.is_empty(), "not read-only: no role check");
    let db = client(&reply.url).await;

    let body = value(&db, "SELECT body FROM kv_lease.notes WHERE id = 1").await;
    assert_eq!(body.as_deref(), Some("the password is [kv:pg]"));
    // The extended protocol, as drivers use for parameters.
    let rows = db
        .query("SELECT body FROM kv_lease.notes WHERE id = $1", &[&1i32])
        .await
        .unwrap();
    assert_eq!(rows[0].get::<_, String>(0), "the password is [kv:pg]");
    let error = db
        .simple_query(&format!("SELECT * FROM \"{secret}\""))
        .await
        .unwrap_err();
    let error = format!("{error:?}");
    assert!(
        !error.contains(&secret) && error.contains("[kv:pg]"),
        "{error}"
    );
    db.batch_execute("INSERT INTO kv_lease.notes VALUES (3, 'written')")
        .await
        .unwrap();
    let copied: Vec<_> = db
        .copy_out("COPY (SELECT body FROM kv_lease.notes WHERE id = 1) TO STDOUT")
        .await
        .unwrap()
        .collect()
        .await;
    let copied: Vec<u8> = copied
        .into_iter()
        .flat_map(|chunk| chunk.unwrap())
        .collect();
    assert_eq!(copied, b"the password is [kv:pg]\n");

    // A secret added while the lease is open is scrubbed from then on.
    f.add(env_secret(
        "other",
        &[("TOKEN", "other-secret-0123456789")],
        &[],
        Mode::Auto,
    ));
    let body = value(&db, "SELECT body FROM kv_lease.notes WHERE id = 2").await;
    assert_eq!(body.as_deref(), Some("later: [kv:other]"));
}

#[tokio::test]
async fn a_read_only_postgres_lease_keeps_the_session_read_only() {
    let Some(url) = server("KV_TEST_POSTGRES_URL") else {
        return;
    };
    let admin = admin(&url, "kv_lease_ro").await;
    admin
        .batch_execute("CREATE TABLE kv_lease_ro.items (id int)")
        .await
        .unwrap();
    let mut f = Fixture::new();
    f.add(postgres("pg", &url, true, Mode::Auto));
    let reply = start(&mut f, lease("pg")).await;
    assert!(
        reply.warnings[0].contains("role can write"),
        "{:?}",
        reply.warnings
    );

    let db = client(&reply.url).await;
    let error = db
        .batch_execute("INSERT INTO kv_lease_ro.items VALUES (1)")
        .await
        .unwrap_err();
    assert!(
        format!("{error:?}").contains("read-only transaction"),
        "{error:?}"
    );
    // Transactions in separate queries are fine.
    for sql in ["BEGIN", "SELECT count(*) FROM kv_lease_ro.items", "COMMIT"] {
        db.batch_execute(sql).await.unwrap();
    }
    let error = db
        .batch_execute("COMMIT; INSERT INTO kv_lease_ro.items VALUES (1)")
        .await
        .unwrap_err();
    assert!(
        format!("{error:?}").contains("send them separately"),
        "{error:?}"
    );
    assert!(db.is_closed() || db.batch_execute("SELECT 1").await.is_err());

    // A switch built from pieces passes the text checks; the server
    // reports it, and kv ends the session before anything else runs.
    let db = client(&reply.url).await;
    let sneaky = "SELECT query_to_xml('select set_' || 'config(''default_' || 'transaction_' \
                  || 'read_' || 'only'', ''off'', false)', true, true, '')";
    let error = db.simple_query(sneaky).await.unwrap_err();
    assert!(
        format!("{error:?}").contains("tried to change that"),
        "{error:?}"
    );
    assert!(db.batch_execute("SELECT 1").await.is_err());

    let mut options = tokio_postgres::Config::new();
    options
        .host("127.0.0.1")
        .port(url::Url::parse(&reply.url).unwrap().port().unwrap())
        .user("kv")
        .password(password(&reply.url))
        .dbname(
            url::Url::parse(&reply.url)
                .unwrap()
                .path()
                .trim_start_matches('/'),
        )
        .options("-c default_transaction_read_only=off");
    let error = options.connect(NoTls).await.err().unwrap();
    assert!(
        format!("{error:?}").contains("startup parameter options"),
        "{error:?}"
    );

    let count = value(&admin, "SELECT count(*) FROM kv_lease_ro.items").await;
    assert_eq!(count.as_deref(), Some("0"));
}

#[tokio::test]
async fn a_postgres_lease_ends_its_connections_when_the_vault_locks() {
    let Some(url) = server("KV_TEST_POSTGRES_URL") else {
        return;
    };
    let mut f = Fixture::new();
    f.add(postgres("pg", &url, false, Mode::Auto));
    let reply = start(&mut f, lease("pg")).await;
    let (db, connection) = tokio_postgres::connect(&reply.url, NoTls).await.unwrap();
    let connection = tokio::spawn(connection);
    assert_eq!(value(&db, "SELECT 1").await.as_deref(), Some("1"));
    f.control(ControlCommand::Lock);
    let ended = tokio::time::timeout(Duration::from_secs(3), connection)
        .await
        .expect("the connection closes")
        .unwrap()
        .unwrap_err();
    assert!(
        format!("{ended:?}").contains("the lease ended"),
        "{ended:?}"
    );
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
