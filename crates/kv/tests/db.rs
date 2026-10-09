//! `db_query` as the daemon authorizes it, without a database: kinds,
//! URLs, read-only guards, approval and timeouts. `db_live.rs` runs queries
//! against real servers.

mod common;

use std::time::Duration;

use common::*;
use kv_core::policy::Mode;
use kv_core::proto::{AgentErrorCode, AgentRequest, ControlCommand, ControlResponse, DbCall};
use kv_core::secret::{SecretText, SecretValue};

const PG_URL: &str = "postgres://app:pg-password-0123456789@db.internal.example:5432/app";
const REDIS_URL: &str = "rediss://:redis-password-0123456789@cache.internal.example:6380/0";

#[test]
fn only_database_handles_take_queries() {
    let mut f = Fixture::new();
    f.add(openrouter(Mode::Auto));
    let (code, message) = f.db(query("openrouter", "select 1")).unwrap_err();
    assert_eq!(code, AgentErrorCode::PolicyDenied, "{message}");
    let (code, _) = f.db(query("missing", "select 1")).unwrap_err();
    assert_eq!(code, AgentErrorCode::UnknownHandle);
}

#[test]
fn an_auto_query_becomes_a_job_with_its_timeout() {
    let mut f = Fixture::new();
    f.add(postgres("pg", PG_URL, false, Mode::Auto));
    let job = f.db(query("pg", "select 1")).unwrap();
    assert_eq!(job.timeout, Duration::from_secs(30));
    let job = f
        .db(DbCall {
            timeout_secs: Some(5),
            ..query("pg", "select 1")
        })
        .unwrap();
    assert_eq!(job.timeout, Duration::from_secs(5));
    let (code, message) = f
        .db(DbCall {
            timeout_secs: Some(301),
            ..query("pg", "select 1")
        })
        .unwrap_err();
    assert_eq!(code, AgentErrorCode::BadRequest);
    assert!(message.contains("300"), "{message}");
}

#[test]
fn read_only_guards_refuse_before_anything_runs() {
    let mut f = Fixture::new();
    f.add(postgres("pg", PG_URL, true, Mode::Ask));
    f.add(redis("cache", REDIS_URL, true, Mode::Ask));
    let (code, _) = f
        .db(query("pg", "BEGIN READ WRITE; DELETE FROM users"))
        .unwrap_err();
    assert_eq!(code, AgentErrorCode::PolicyDenied);
    let (code, message) = f.db(query("cache", "SET k v")).unwrap_err();
    assert_eq!(code, AgentErrorCode::PolicyDenied);
    assert!(message.contains("SET"), "{message}");
    let (code, _) = f.db(query("cache", "SUBSCRIBE news")).unwrap_err();
    assert_eq!(code, AgentErrorCode::BadRequest);
    let (code, _) = f.db(query("cache", r#"GET "open"#)).unwrap_err();
    assert_eq!(code, AgentErrorCode::BadRequest);
    let audit = f.audit_lines();
    assert!(
        audit
            .iter()
            .all(|line| line["decision"] != "approved" && line["decision"] != "auto"),
        "{audit:?}"
    );
}

#[test]
fn a_query_in_ask_mode_waits_and_shows_the_query() {
    let mut f = Fixture::new();
    f.add(postgres("pg", PG_URL, false, Mode::Ask));
    let long = format!("select '{}'", "x".repeat(400));
    let waiting = f.wait(
        Some(&session("s1")),
        AgentRequest::DbQuery(query("pg", &long)),
        f.t0,
    );
    let token = f.token();
    let approvals = f.overview(&token).approvals;
    assert_eq!(approvals[0].id, waiting.id);
    assert_eq!(approvals[0].tool, "db_query");
    assert!(approvals[0].detail.starts_with("select 'xxx"));
    assert!(approvals[0].detail.chars().count() <= 300);
}

#[test]
fn connection_urls_must_be_postgres_or_redis_urls() {
    let mut f = Fixture::new();
    let token = f.token();
    for (value, ok) in [
        (SecretValue::Postgres { url: url(PG_URL) }, true),
        (
            SecretValue::Postgres {
                url: url("postgresql://app@db.example/app"),
            },
            true,
        ),
        (
            SecretValue::Postgres {
                url: url("host=db.example user=app password=pg-password-0123"),
            },
            false,
        ),
        (
            SecretValue::Postgres {
                url: url("mysql://app:pw@db.example/app"),
            },
            false,
        ),
        (
            SecretValue::Redis {
                url: url(REDIS_URL),
            },
            true,
        ),
        (
            SecretValue::Redis {
                url: url("postgres://app:pw@db.example/app"),
            },
            false,
        ),
    ] {
        let response = f.send(
            None,
            Some(&token),
            ControlCommand::Add {
                secret: secret("db", value.clone(), Default::default()),
                replace: true,
            },
        );
        assert_eq!(
            matches!(response, ControlResponse::Done { .. }),
            ok,
            "{value:?}: {response:?}"
        );
    }
}

fn url(text: &str) -> SecretText {
    SecretText::new(text)
}

#[test]
fn a_role_check_that_started_before_its_handle_changed_is_not_kept() {
    let checks = kv::broker::RoleChecks::default();
    let stamp = checks.stamp();
    checks.forget("pg");
    checks.record("pg", stamp, Some("can write".into()));
    assert!(!checks.is_checked("pg"));
    let stamp = checks.stamp();
    checks.record("pg", stamp, Some("can write".into()));
    assert!(checks.warnings().contains_key("pg"));
}
