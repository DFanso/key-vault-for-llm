//! `db_query` against real servers. Set `KV_TEST_POSTGRES_URL` (a
//! superuser) and `KV_TEST_REDIS_URL` to run these; without them they pass
//! after a note, unless `KV_REQUIRE_DB_TESTS` is set, as it is in CI.

mod common;

use common::*;
use kv::broker::db;
use kv_core::policy::Mode;
use kv_core::proto::{AgentErrorCode, AgentResponse, DbCall, RedisReply, RowsReply};
use tokio_postgres::NoTls;

fn server(var: &str) -> Option<String> {
    match std::env::var(var) {
        Ok(url) if !url.is_empty() => Some(url),
        _ => {
            assert!(
                std::env::var_os("KV_REQUIRE_DB_TESTS").is_none(),
                "{var} is not set, and KV_REQUIRE_DB_TESTS says these tests must run"
            );
            eprintln!("skipped: {var} is not set");
            None
        }
    }
}

/// A connection for setting up test data, and a schema of the test's own.
async fn admin(url: &str, schema: &str) -> tokio_postgres::Client {
    let (client, connection) = tokio_postgres::connect(url, NoTls).await.unwrap();
    tokio::spawn(connection);
    client
        .batch_execute(&format!(
            "DROP SCHEMA IF EXISTS {schema} CASCADE; CREATE SCHEMA {schema};"
        ))
        .await
        .unwrap();
    client
}

async fn run(f: &mut Fixture, call: DbCall) -> AgentResponse {
    db::run(f.db(call).unwrap()).await
}

fn rows(response: AgentResponse) -> RowsReply {
    match response {
        AgentResponse::Rows(rows) => rows,
        other => panic!("expected rows, got {other:?}"),
    }
}

fn upstream_error(response: AgentResponse) -> String {
    match response {
        AgentResponse::Error {
            code: AgentErrorCode::UpstreamError,
            message,
        } => message,
        other => panic!("expected upstream_error, got {other:?}"),
    }
}

#[tokio::test]
async fn postgres_rows_come_back_as_text_with_secrets_scrubbed() {
    let Some(url) = server("KV_TEST_POSTGRES_URL") else {
        return;
    };
    let password = url::Url::parse(&url)
        .unwrap()
        .password()
        .unwrap()
        .to_owned();
    let admin = admin(&url, "kv_rows").await;
    admin
        .batch_execute(&format!(
            "CREATE TABLE kv_rows.notes (id int, body text);
             INSERT INTO kv_rows.notes VALUES (1, 'the password is {password}'), (2, NULL);"
        ))
        .await
        .unwrap();
    let mut f = Fixture::new();
    f.add(postgres("pg", &url, false, Mode::Auto));

    let reply = rows(
        run(
            &mut f,
            query(
                "pg",
                "SELECT id, body FROM kv_rows.notes ORDER BY id; UPDATE kv_rows.notes SET id = id",
            ),
        )
        .await,
    );
    assert_eq!(reply.results.len(), 2);
    let select = &reply.results[0];
    assert_eq!(select.columns, ["id", "body"]);
    assert_eq!(
        select.rows,
        [
            vec![Some("1".into()), Some("the password is [kv:pg]".into())],
            vec![Some("2".into()), None],
        ]
    );
    assert_eq!(reply.results[1].rows_affected, Some(2));
    assert!(!reply.truncated);
    assert!(reply.warnings.is_empty(), "not read-only: no role check");

    let message = upstream_error(
        run(
            &mut f,
            query("pg", &format!("SELECT * FROM \"{password}\"")),
        )
        .await,
    );
    assert!(!message.contains(&password), "{message}");
    assert!(message.contains("[kv:pg]"), "{message}");
}

#[tokio::test]
async fn a_read_only_postgres_session_refuses_writes_and_warns_about_the_role() {
    let Some(url) = server("KV_TEST_POSTGRES_URL") else {
        return;
    };
    let admin = admin(&url, "kv_ro").await;
    admin
        .batch_execute(
            "CREATE TABLE kv_ro.items (id int);
             DROP ROLE IF EXISTS kv_ro_reader;
             CREATE ROLE kv_ro_reader LOGIN PASSWORD 'reader-password-0123';
             GRANT USAGE ON SCHEMA kv_ro TO kv_ro_reader;
             GRANT SELECT ON kv_ro.items TO kv_ro_reader;",
        )
        .await
        .unwrap();
    let mut f = Fixture::new();
    f.add(postgres("pg", &url, true, Mode::Auto));

    let message =
        upstream_error(run(&mut f, query("pg", "INSERT INTO kv_ro.items VALUES (1)")).await);
    assert!(message.contains("read-only transaction"), "{message}");
    let reply = rows(run(&mut f, query("pg", "SELECT count(*) FROM kv_ro.items")).await);
    assert_eq!(reply.results[0].rows, [vec![Some("0".into())]]);
    assert!(
        reply.warnings[0].contains("role can write"),
        "{:?}",
        reply.warnings
    );
    let token = f.token();
    assert!(f.overview(&token).role_warnings.contains_key("pg"));

    let mut reader = url::Url::parse(&url).unwrap();
    reader.set_username("kv_ro_reader").unwrap();
    reader.set_password(Some("reader-password-0123")).unwrap();
    f.add(postgres("reader", reader.as_str(), true, Mode::Auto));
    let reply = rows(run(&mut f, query("reader", "SELECT count(*) FROM kv_ro.items")).await);
    assert!(reply.warnings.is_empty(), "{:?}", reply.warnings);
    assert!(!f.overview(&token).role_warnings.contains_key("reader"));
}

#[tokio::test]
async fn big_postgres_results_are_cut_and_slow_ones_time_out() {
    let Some(url) = server("KV_TEST_POSTGRES_URL") else {
        return;
    };
    let mut f = Fixture::new();
    f.add(postgres("pg", &url, false, Mode::Auto));
    let reply = rows(
        run(
            &mut f,
            query(
                "pg",
                "SELECT repeat('x', 1000) FROM generate_series(1, 1000)",
            ),
        )
        .await,
    );
    assert!(reply.truncated);
    let kept = reply.results.iter().map(|r| r.rows.len()).sum::<usize>();
    assert!(kept > 100 && kept < 1000, "{kept}");

    let message = upstream_error(
        run(
            &mut f,
            DbCall {
                timeout_secs: Some(1),
                ..query("pg", "SELECT pg_sleep(5)")
            },
        )
        .await,
    );
    assert!(message.contains("time"), "{message}");
}

#[tokio::test]
async fn redis_replies_come_back_as_json_with_secrets_scrubbed() {
    let Some(url) = server("KV_TEST_REDIS_URL") else {
        return;
    };
    let mut f = Fixture::new();
    f.add(redis("cache", &url, false, Mode::Auto));
    f.add(redis("cache-ro", &url, true, Mode::Auto));
    let secret = "redis-secret-0123456789";
    f.add(env_secret("other", &[("TOKEN", secret)], &[], Mode::Auto));

    let ok = run(&mut f, query("cache", &format!("SET kv:test \"{secret}\""))).await;
    assert_eq!(
        ok,
        AgentResponse::Redis(RedisReply {
            value: serde_json::json!("OK"),
            truncated: false
        })
    );
    run(&mut f, query("cache", "DEL kv:list")).await;
    run(&mut f, query("cache", "RPUSH kv:list a 42")).await;
    let reply = run(&mut f, query("cache-ro", "GET kv:test")).await;
    assert_eq!(
        reply,
        AgentResponse::Redis(RedisReply {
            value: serde_json::json!("[kv:other]"),
            truncated: false
        })
    );
    let reply = run(&mut f, query("cache-ro", "LRANGE kv:list 0 -1")).await;
    assert_eq!(
        reply,
        AgentResponse::Redis(RedisReply {
            value: serde_json::json!(["a", "42"]),
            truncated: false
        })
    );
    let reply = run(&mut f, query("cache-ro", "LLEN kv:list")).await;
    assert_eq!(
        reply,
        AgentResponse::Redis(RedisReply {
            value: serde_json::json!(2),
            truncated: false
        })
    );
    let (code, _) = f.db(query("cache-ro", "DEL kv:test")).unwrap_err();
    assert_eq!(code, AgentErrorCode::PolicyDenied);
}

#[tokio::test]
async fn kv_add_can_check_a_role_on_its_own() {
    let Some(url) = server("KV_TEST_POSTGRES_URL") else {
        return;
    };
    let admin = admin(&url, "kv_cr").await;
    admin
        .batch_execute(
            "DROP ROLE IF EXISTS kv_cr_reader;
             CREATE ROLE kv_cr_reader LOGIN PASSWORD 'reader-password-4567';",
        )
        .await
        .unwrap();
    let warning = db::check_role("pg", &url).await.unwrap();
    assert!(warning.unwrap().contains("role can write"));
    let mut reader = url::Url::parse(&url).unwrap();
    reader.set_username("kv_cr_reader").unwrap();
    reader.set_password(Some("reader-password-4567")).unwrap();
    assert_eq!(db::check_role("pg", reader.as_str()).await.unwrap(), None);
    let mut closed = url::Url::parse(&url).unwrap();
    closed.set_port(Some(1)).unwrap();
    let error = db::check_role("pg", closed.as_str()).await.unwrap_err();
    assert!(!error.contains("reader-password"), "{error}");
}

#[tokio::test]
async fn big_redis_replies_are_cut() {
    let Some(url) = server("KV_TEST_REDIS_URL") else {
        return;
    };
    let mut f = Fixture::new();
    f.add(redis("cache", &url, false, Mode::Auto));
    let big = "x".repeat(300 * 1024);
    run(&mut f, query("cache", &format!("SET kv:big {big}"))).await;
    match run(&mut f, query("cache", "GET kv:big")).await {
        AgentResponse::Redis(RedisReply { value, truncated }) => {
            assert!(truncated);
            let text = value.as_str().unwrap();
            assert!(
                text.len() < 256 * 1024 && text.len() > 200 * 1024,
                "{}",
                text.len()
            );
        }
        other => panic!("{other:?}"),
    }
    let keys: Vec<String> = (0..100_000).map(|i| format!("kv:missing:{i}")).collect();
    match run(&mut f, query("cache", &format!("MGET {}", keys.join(" ")))).await {
        AgentResponse::Redis(RedisReply { value, truncated }) => {
            assert!(truncated);
            let shown = value.as_array().unwrap().len();
            assert!(shown < 100_000, "{shown}");
        }
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn the_role_check_sees_column_grants_views_and_server_file_roles() {
    let Some(url) = server("KV_TEST_POSTGRES_URL") else {
        return;
    };
    let admin = admin(&url, "kv_cg").await;
    admin
        .batch_execute(
            "CREATE TABLE kv_cg.t (a int, b int);
             CREATE VIEW kv_cg.v AS SELECT a FROM kv_cg.t;
             DROP ROLE IF EXISTS kv_cg_column;
             DROP ROLE IF EXISTS kv_cg_view;
             DROP ROLE IF EXISTS kv_cg_files;
             CREATE ROLE kv_cg_column LOGIN PASSWORD 'column-password-0123';
             CREATE ROLE kv_cg_view LOGIN PASSWORD 'view-password-0123';
             CREATE ROLE kv_cg_files LOGIN PASSWORD 'files-password-0123';
             GRANT USAGE ON SCHEMA kv_cg TO kv_cg_column, kv_cg_view;
             GRANT UPDATE (a) ON kv_cg.t TO kv_cg_column;
             GRANT INSERT ON kv_cg.v TO kv_cg_view;
             GRANT pg_write_server_files TO kv_cg_files;",
        )
        .await
        .unwrap();
    for (user, password) in [
        ("kv_cg_column", "column-password-0123"),
        ("kv_cg_view", "view-password-0123"),
        ("kv_cg_files", "files-password-0123"),
    ] {
        let mut role = url::Url::parse(&url).unwrap();
        role.set_username(user).unwrap();
        role.set_password(Some(password)).unwrap();
        let warning = db::check_role("pg", role.as_str()).await.unwrap();
        assert!(warning.is_some(), "{user} can write");
    }
}
