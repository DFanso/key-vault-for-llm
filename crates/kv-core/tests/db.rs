use kv_core::db::{
    RedisRefusal, check_redis, pg_read_only_violation, postgres_requires_tls, split_command,
};

fn args(line: &str) -> Vec<Vec<u8>> {
    split_command(line).unwrap()
}

#[test]
fn reads_pass_the_postgres_read_only_guard() {
    for sql in [
        "select * from users where id = 1",
        "SELECT count(*) FROM orders; SELECT now()",
        "with t as (select 1) select * from t",
        "EXPLAIN ANALYZE SELECT 1",
        "select 'do not' as note",
        "select $1::text",
        "show search_path",
    ] {
        assert_eq!(pg_read_only_violation(sql), None, "{sql}");
    }
}

#[test]
fn changing_read_only_mode_is_refused_however_it_is_written() {
    for sql in [
        "SET transaction_read_only = off",
        "set session characteristics as transaction read write",
        "BEGIN READ WRITE; delete from users",
        "start transaction read write",
        "BEGIN READ/**/WRITE",
        "begin read -- comment\n write",
        "SET default_transaction_read_only TO off",
        "SELECT set_config('default_transaction_read_only', 'off', false)",
        "SET \"transaction_read_only\" = off",
        "SET U&\"transaction\\005fread\\005fonly\" = off",
        "reset default_transaction_read_only",
        "SET DEFAULT_TRANSACTION_ISOLATION = serializable",
        "select 1; DO $$ BEGIN EXECUTE 'x'; END $$",
        "do 'begin null; end'",
    ] {
        assert!(pg_read_only_violation(sql).is_some(), "{sql}");
    }
}

#[test]
fn comments_and_quotes_cannot_hide_a_statement() {
    // A `--` inside a string is not a comment, so what follows still counts.
    assert!(pg_read_only_violation("select '--'; begin read write").is_some());
    assert!(pg_read_only_violation("select $tag$ -- $tag$; begin read write").is_some());
    assert!(pg_read_only_violation("select e'\\' --'; begin read write").is_some());
    assert!(pg_read_only_violation("select /* /* nested */ */ 1; begin read write").is_some());
    // `a$x$` is one name: the `$x$` in it does not open a dollar quote.
    assert!(
        pg_read_only_violation("select 1 as a$x$, '$x$ -- '; commit; create table t(x int)")
            .is_some()
    );
    assert!(pg_read_only_violation("select 1 as a$x$, '$x$ -- '; begin read write").is_some());
}

#[test]
fn redis_commands_split_like_redis_cli() {
    assert_eq!(args("GET user:1"), [b"GET".to_vec(), b"user:1".to_vec()]);
    assert_eq!(
        args(r#"  set "a b" 'x y'  "#),
        [b"set".to_vec(), b"a b".to_vec(), b"x y".to_vec()]
    );
    assert_eq!(
        args(r#"echo "line\nnext \x41\"""#),
        [b"echo".to_vec(), b"line\nnext A\"".to_vec()]
    );
    assert_eq!(args(r"get 'a\'b'"), [b"get".to_vec(), b"a'b".to_vec()]);
    for bad in [
        "",
        "   ",
        r#"get "open"#,
        r#"get "a"b"#,
        "get 'x",
        "get 'a''b'",
    ] {
        assert!(split_command(bad).is_err(), "{bad:?}");
    }
}

#[test]
fn a_read_only_redis_handle_runs_only_read_commands() {
    for line in [
        "GET k",
        "hgetall h",
        "SCAN 0 MATCH user:* COUNT 100",
        "object encoding k",
        "MEMORY USAGE k",
        "ping",
    ] {
        assert_eq!(check_redis(&args(line), true), Ok(()), "{line}");
    }
    for line in [
        "SET k v",
        "DEL k",
        "flushall",
        "EVAL 'return 1' 0",
        "CONFIG GET requirepass",
        "OBJECT HELP",
        "SORT k STORE out",
    ] {
        assert!(
            matches!(
                check_redis(&args(line), true),
                Err(RedisRefusal::NotRead(_))
            ),
            "{line}"
        );
    }
    assert_eq!(check_redis(&args("SET k v"), false), Ok(()));
}

#[test]
fn commands_that_hold_the_connection_are_never_run() {
    for line in [
        "SUBSCRIBE news",
        "monitor",
        "AUTH user pass",
        "HELLO 3",
        "quit",
    ] {
        for read_only in [true, false] {
            assert!(
                matches!(
                    check_redis(&args(line), read_only),
                    Err(RedisRefusal::Never(_))
                ),
                "{line}"
            );
        }
    }
}

#[test]
fn ending_the_transaction_is_refused_on_a_read_only_handle() {
    // Built from pieces so no guarded word appears, then committed so the
    // next statement would start a read-write transaction.
    let bypass = "select query_to_xml('select set_con'||'fig(''default_trans''||''action_rea''||''d_only'',''off'',false)', true, false, ''); commit; create table t(x int)";
    for sql in [
        bypass,
        "select 1; COMMIT",
        "select 1; end",
        "select 1; rollback",
        "select 1; abort",
        "prepare transaction 'x'",
        "CALL refresh_all()",
        "select 1;\n  /* c */ commit and chain",
    ] {
        assert!(pg_read_only_violation(sql).is_some(), "{sql}");
    }
    for sql in [
        "select 'commit' as word",
        "prepare q as select 1; execute q",
        "select endpoint from services",
    ] {
        assert_eq!(pg_read_only_violation(sql), None, "{sql}");
    }
}

#[test]
fn tls_is_required_for_remote_postgres_unless_the_url_says_otherwise() {
    for (url, required) in [
        ("postgres://app:pw@db.example.com/app", true),
        ("postgresql://app:pw@10.0.0.5:5432/app", true),
        (
            "postgres://app:pw@db.example.com/app?sslmode=disable",
            false,
        ),
        ("postgres://app:pw@db.example.com/app?sslmode=prefer", false),
        ("postgres://app:pw@localhost/app", false),
        ("postgres://app:pw@127.0.0.1:5432/app", false),
        ("postgres://app:pw@[::1]/app", false),
        ("postgres://app:pw@/app?host=/var/run/postgresql", false),
        ("postgres://app:pw@localhost/app?host=db.example.com", true),
    ] {
        assert_eq!(postgres_requires_tls(url), required, "{url}");
    }
}
