# kv Plan 5b: db_connect Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give agents `db_connect`: a loopback connection URL for a postgres or redis handle that tools such as `psql`, `redis-cli`, ORMs and test suites can use, while kv holds the real credentials, scrubs every reply and keeps read-only handles read-only.

**Architecture:** The daemon authorizes `db_connect` like `db_query` (kind, TTL, policy, approval) and takes a place in a `Leases` book under its lock, so a lock or a handle change ends the lease even while it waits. `lease::start` then binds `127.0.0.1:0`, returns a URL with a 256-bit lease token in place of the password, and serves until the TTL ends. Each connection logs in with the token, kv logs in upstream with the real credentials (TLS checked against the platform store) and relays both ways: Redis through kv's own RESP reader (which `db_query` now uses too), Postgres through a small wire-protocol layer that scrubs every server message in place. On read-only Postgres sessions kv passes one batch at a time and ends the session if the server reports `default_transaction_read_only` off. Pure checks stay in `kv-core::db`.

**Tech Stack:** Rust 2024 (MSRV 1.89), tokio, tokio-rustls 0.26, rustls 0.23 (`aws_lc_rs`), rustls-platform-verifier 0.7, postgres-protocol 0.6 (SCRAM, MD5), tokio-postgres 0.7 (URL parsing, `db_query`, and the test client), percent-encoding 2.3, redis 1.7 (dev-dependency only, as a test client), rmcp 3.5.

**Spec:** `docs/superpowers/specs/2026-10-08-kv-llm-secrets-broker-design.md` (sections 3, 4 "db_connect" and "Read-only enforcement", 5, 6). Task 6 writes the decisions below into it.

## Decisions this plan makes

The spec gave `db_connect` one paragraph. These fill it in; each is a choice for you to confirm or change.

- **Scrubbed, not passed through.** The spec said the proxy "passes traffic through", but also that nothing reaches an agent unscrubbed. Every server message is scrubbed in place (Postgres rows, column names, errors, notices, notifications, parameters, tags, COPY data; Redis strings, errors, and numbers matching a secret, which become strings).
- **Read-only Postgres leases need PostgreSQL 14+.** A session lasts many transactions, and a function can build `set_config('default_transaction_read_only', 'off', false)` from string pieces. From 14, the server reports that setting when it changes, so kv passes one batch at a time on read-only sessions and closes the session (`25006`) when the report says off. Older servers are refused at login with a clear message; `db_query` still works on them. `COMMIT`/`END`/`ROLLBACK`/`ABORT` are allowed only as the last statement of a batch; `DO`, `CALL`, `PREPARE TRANSACTION` and fast-path calls are refused.
- **Lifetime and limits.** TTL 900 s by default, 1 to 3600 s. A lease ends at expiry, on lock, or when its handle changes, and cuts its connections. At most 16 leases (counting those awaiting approval), 16 connections each, 30 s to log in, 20 s for the server, 16 MiB per message.
- **Not passed on:** query cancellation, replication, `_pq_.` protocol options; Redis `AUTH`/`HELLO ... AUTH` after login, `RESET`, subscriptions, `MONITOR`, `CLIENT REPLY`, `SYNC`/`PSYNC`/`REPLCONF`. The client must ask for the lease's Postgres database.
- **Redis without the `redis` crate.** kv already parses RESP for the proxy, so `db_query` uses the same client and reads a reply only as far as the 256 KiB cap (the 5a buffering minor). `rediss://...#insecure` is refused; the README said it skipped the certificate check.
- **5a's other deferred minors:** role checks that raced a handle change are dropped (stamp); the scrubber ignores ASCII case; multi-host Postgres URLs, `host=`, `hostaddr=` and `password=` are read for scrubbing and for the TLS rule (multi-host remote URLs previously escaped the TLS requirement). One huge Postgres row in `db_query` is still held whole (documented).
- **Audit:** the lease is audited like other requests; each connection once, when it closes, with how it ended.
- **Protocol modules are public** (`kv::broker::{net, resp, pgwire}`) so their tests live in `crates/kv/tests/`, like `db`.

## Global Constraints

- Every cargo command runs with `export DEVELOPER_DIR=/Library/Developer/CommandLineTools KV_REQUIRE_DB_TESTS=1 KV_TEST_POSTGRES_URL=postgres://postgres:kv-test-password-123@127.0.0.1:54417/postgres KV_TEST_REDIS_URL=redis://127.0.0.1:63799/0` set. Servers: `docker run --rm -d --name kv-test-pg17 -p 54417:5432 -e POSTGRES_PASSWORD=kv-test-password-123 postgres:17` and `docker run --rm -d --name kv-test-redis -p 63799:6379 redis:7`.
- `KV_TEST_POSTGRES_URL` must be a superuser on Postgres 14 or later.
- No message type on the agent socket carries a secret value; every byte a database sends back to an agent or a leased client goes through the scrubber.
- Lease tokens are 32 random bytes as 64 hex characters, compared in constant time, and never added to the scrubber.
- TLS certificates are always verified against the platform trust store, for `db_query` and leases alike.
- Commits as DFanso <leogavin123@outlook.com>, no AI attribution.
- `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings` and `cargo test --workspace` stay clean after every task.

## Review Focus

- A remote Postgres or Redis over TLS through a lease: CI's servers are plain, so the TLS upstream path (SNI is the URL host, or `hostaddr` connects while the name is checked) is not exercised. Expect a public certificate to work and a self-signed one to fail with a scrubbed error to the client.
- `psql` on a lease: Ctrl-C does nothing (cancel is not passed on), `\c otherdb` gets `3D000` naming the lease's database, and `\password` or `SET ROLE` behave as on the server. Check the messages are clear.
- A JDBC-style client pipelining many extended-protocol batches on a read-only lease: kv waits for each `ReadyForQuery`, so throughput drops but nothing should hang.
- A row or Redis value over 16 MiB through a lease: the connection ends with a kv error naming the limit, and the audit line says `upstream_error`.
- A client still logging in when its lease ends: it may finish logging in, then the relay closes it at once (`lease_ended`); nothing reaches the server.

---

### Task 1: Postgres URL hosts and passwords, case-insensitive scrubbing, and the db_connect guard

**Files:**
- Modify: `crates/kv-core/src/db.rs`
- Modify: `crates/kv-core/src/scrub.rs`
- Modify: `crates/kv-core/src/secret.rs`
- Modify: `crates/kv-core/tests/db.rs`
- Modify: `crates/kv-core/tests/scrub.rs`
- Modify: `crates/kv-core/tests/secret.rs`

**Interfaces:**
- Consumes: nothing new.
- Produces: `kv_core::db::{pg_session_violation(&str) -> Result<bool, &'static str>, postgres_hosts(&str) -> Vec<String>, postgres_passwords(&str) -> Vec<String>}`; `postgres_requires_tls` now sees every host of a multi-host URL; `pg_read_only_violation` keeps its behaviour. `Scrubber` matches ASCII case-insensitively. `Secret::sensitive_values()` for postgres yields every non-local host (authority, `host=`, `hostaddr=`) and every password (authority, `password=`), raw and percent-decoded.

- [ ] **Step 1: Write the failing tests**

Apply with `git apply` from the repository root:

```diff
diff --git a/crates/kv-core/tests/db.rs b/crates/kv-core/tests/db.rs
index a641f7b..400641a 100644
--- a/crates/kv-core/tests/db.rs
+++ b/crates/kv-core/tests/db.rs
@@ -1,5 +1,6 @@
 use kv_core::db::{
-    RedisRefusal, check_redis, pg_read_only_violation, postgres_requires_tls, split_command,
+    RedisRefusal, check_redis, pg_read_only_violation, pg_session_violation, postgres_hosts,
+    postgres_passwords, postgres_requires_tls, split_command,
 };
 
 fn args(line: &str) -> Vec<Vec<u8>> {
@@ -176,7 +177,60 @@ fn tls_is_required_for_remote_postgres_unless_the_url_says_otherwise() {
         ("postgres://app:pw@[::1]/app", false),
         ("postgres://app:pw@/app?host=/var/run/postgresql", false),
         ("postgres://app:pw@localhost/app?host=db.example.com", true),
+        (
+            "postgres://app:pw@localhost:5432,db.example.com:5433/app",
+            true,
+        ),
+        ("postgres://app:pw@localhost:5432,127.0.0.1/app", false),
     ] {
         assert_eq!(postgres_requires_tls(url), required, "{url}");
     }
 }
+
+#[test]
+fn a_read_only_session_may_end_a_transaction_only_at_the_end_of_a_batch() {
+    for sql in [
+        "select * from users",
+        "begin",
+        "begin read only",
+        "insert into t values (1); commit",
+        "commit",
+        "rollback to savepoint a",
+    ] {
+        assert!(pg_session_violation(sql).is_ok(), "{sql}");
+    }
+    assert_eq!(pg_session_violation("select 1"), Ok(false));
+    assert_eq!(pg_session_violation("select 1; commit;"), Ok(true));
+    assert_eq!(pg_session_violation("END"), Ok(true));
+    for sql in [
+        // A switch built at run time, then a new transaction, in one batch.
+        "select query_to_xml('select set_' || 'config(1)', true, true, ''); commit; insert into t values (1)",
+        "commit; insert into t values (1)",
+        "rollback; select 1",
+        "set default_transaction_read_only = off",
+        "do $$ begin perform 1; end $$",
+        "call refresh()",
+        "prepare transaction 'x'",
+    ] {
+        assert!(pg_session_violation(sql).is_err(), "{sql}");
+    }
+}
+
+#[test]
+fn postgres_urls_with_several_hosts_name_them_all() {
+    assert_eq!(
+        postgres_hosts(
+            "postgres://app:pw@db1.example.com:5432,[::1]:5433,db2/app?host=db3,/tmp&hostaddr=10.0.0.9"
+        ),
+        ["db1.example.com", "::1", "db2", "db3", "/tmp", "10.0.0.9"]
+    );
+    assert_eq!(
+        postgres_hosts("postgres:///app?host=/var/run/postgresql"),
+        ["/var/run/postgresql"]
+    );
+    assert_eq!(
+        postgres_passwords("postgres://app:p%40ss@h1,h2/app?password=second"),
+        ["p%40ss", "second"]
+    );
+    assert!(postgres_passwords("postgres://app@h/app").is_empty());
+}
diff --git a/crates/kv-core/tests/scrub.rs b/crates/kv-core/tests/scrub.rs
index 2fdb111..8badf10 100644
--- a/crates/kv-core/tests/scrub.rs
+++ b/crates/kv-core/tests/scrub.rs
@@ -18,6 +18,15 @@ fn scrub(s: &Scrubber, input: &str) -> String {
     String::from_utf8(s.scrub(input.as_bytes())).unwrap()
 }
 
+#[test]
+fn a_secret_in_another_case_is_still_scrubbed() {
+    let s = Scrubber::new([("prod-db", "kyc.postgres.database.azure.com")]);
+    assert_eq!(
+        scrub(&s, "could not reach KYC.Postgres.Database.Azure.com"),
+        "could not reach [kv:prod-db]"
+    );
+}
+
 #[test]
 fn replaces_raw_value_with_handle_label() {
     let s = Scrubber::new([("openrouter", KEY)]);
diff --git a/crates/kv-core/tests/secret.rs b/crates/kv-core/tests/secret.rs
index 570a508..400b994 100644
--- a/crates/kv-core/tests/secret.rs
+++ b/crates/kv-core/tests/secret.rs
@@ -211,4 +211,16 @@ fn a_database_host_is_scrubbed_unless_it_is_loopback() {
         let host = url::Url::parse(url).unwrap().host_str().unwrap().to_owned();
         assert!(!values(url).contains(&host), "{url}");
     }
+    let all = values(
+        "postgres://app:pw-0123456789@db1.example.com,db2.example.com/app?hostaddr=10.1.2.3&password=pw-second-0123",
+    );
+    for value in [
+        "db1.example.com",
+        "db2.example.com",
+        "10.1.2.3",
+        "pw-0123456789",
+        "pw-second-0123",
+    ] {
+        assert!(all.contains(&value.to_string()), "{value} in {all:?}");
+    }
 }
```

- [ ] **Step 2: Run the tests to watch them fail**

Run: `cargo test -p kv-core --test db --test secret --test scrub`
Expected: FAIL: `error[E0432]: unresolved imports kv_core::db::pg_session_violation, kv_core::db::postgres_hosts, kv_core::db::postgres_passwords`. (Run alone, `--test scrub` also fails `a_secret_in_another_case_is_still_scrubbed`.)

- [ ] **Step 3: Implement**

Apply with `git apply`:

```diff
diff --git a/crates/kv-core/src/db.rs b/crates/kv-core/src/db.rs
index 44a931e..05f8113 100644
--- a/crates/kv-core/src/db.rs
+++ b/crates/kv-core/src/db.rs
@@ -1,47 +1,29 @@
-//! Checks on what `db_query` sends: the best-effort guard that keeps a
-//! read-only Postgres session read-only, and how a Redis command line is
-//! split and which commands run.
+//! Checks on what `db_query` and `db_connect` send: the best-effort guards
+//! that keep a read-only Postgres session read-only, what a Postgres URL
+//! names, and how a Redis command line is split and which commands run.
 
-/// Why `sql` may not run on a read-only Postgres handle, or `None`.
+/// Why `sql` may not run through `db_query` on a read-only Postgres
+/// handle, or `None`.
 ///
 /// Sessions for read-only handles start with
 /// `default_transaction_read_only=on`; this refuses statements that would
 /// switch that off, `DO` blocks, which can build such a statement at run
-/// time, and statements that end the transaction (or call a procedure,
-/// which can): a query can build the switch from string pieces inside a
-/// function, but it only takes effect in the next transaction. Comments are read as spaces, as Postgres reads them, and
-/// quoted text is kept, so a mention inside a string is refused too: when
-/// in doubt it says no. The real guarantee is a role without write
-/// privileges.
+/// time, and statements that end the transaction or call a procedure
+/// (which can end one): a query can build the switch from string pieces
+/// inside a function, and it takes effect in the next transaction.
+/// Comments are read as spaces, as Postgres reads them, and quoted text is
+/// kept, so a mention inside a string is refused too: when in doubt it says
+/// no. The real guarantee is a role without write privileges.
 pub fn pg_read_only_violation(sql: &str) -> Option<&'static str> {
     let text = normalize_sql(sql);
-    let changes_mode = ["read_only", "read write", "characteristics", "set_config"]
-        .iter()
-        .any(|word| text.contains(word))
-        || text.contains("default_transaction")
-        || text.contains("u&");
-    if changes_mode {
-        return Some(
-            "the handle is read-only, and this query mentions a way to change that; kv refuses it",
-        );
+    if let Some(reason) = mode_change(&text) {
+        return Some(reason);
     }
-    let starts = |statement: &str, word: &str| {
-        statement.strip_prefix(word).is_some_and(|rest| {
-            !rest
-                .chars()
-                .next()
-                .is_some_and(|c| c.is_alphanumeric() || c == '_')
-        })
-    };
-    for statement in text.split(';').map(str::trim_start) {
-        if starts(statement, "do") {
-            return Some("the handle is read-only, and kv refuses DO blocks on read-only handles");
+    for statement in statements(&text) {
+        if let Some(reason) = runs_code(statement) {
+            return Some(reason);
         }
-        let ends_transaction = ["commit", "end", "rollback", "abort", "call"]
-            .iter()
-            .any(|word| starts(statement, word))
-            || starts(statement, "prepare transaction");
-        if ends_transaction {
+        if ends_transaction(statement) {
             return Some(
                 "the handle is read-only, and kv refuses statements that end the transaction \
                  or call procedures on read-only handles",
@@ -51,29 +33,158 @@ pub fn pg_read_only_violation(sql: &str) -> Option<&'static str> {
     None
 }
 
+/// The `db_connect` guard for one batch on a read-only Postgres session: a
+/// simple query, or one statement of the extended protocol. `Ok(true)`
+/// when the batch ends with a statement that ends the transaction.
+///
+/// The proxy watches the server report `default_transaction_read_only`
+/// before it passes on the client's next batch, so a switch built at run
+/// time is caught there. What it cannot catch is a switch and a write in
+/// one batch with the transaction ended between them, so nothing may
+/// follow `COMMIT`, `END`, `ROLLBACK` or `ABORT` in a batch, and `CALL`,
+/// `PREPARE TRANSACTION` and `DO`, which can end transactions inside them,
+/// are refused.
+pub fn pg_session_violation(sql: &str) -> Result<bool, &'static str> {
+    let text = normalize_sql(sql);
+    if let Some(reason) = mode_change(&text) {
+        return Err(reason);
+    }
+    let mut ended = false;
+    for statement in statements(&text) {
+        if ended {
+            return Err(
+                "the handle is read-only, and kv refuses statements after COMMIT, END, ROLLBACK \
+                 or ABORT in the same query; send them separately",
+            );
+        }
+        if let Some(reason) = runs_code(statement) {
+            return Err(reason);
+        }
+        ended = ends_transaction(statement);
+    }
+    Ok(ended)
+}
+
+/// Mentions of a way to turn read-only off.
+fn mode_change(text: &str) -> Option<&'static str> {
+    let changes_mode = ["read_only", "read write", "characteristics", "set_config"]
+        .iter()
+        .any(|word| text.contains(word))
+        || text.contains("default_transaction")
+        || text.contains("u&");
+    changes_mode.then_some(
+        "the handle is read-only, and this query mentions a way to change that; kv refuses it",
+    )
+}
+
+/// `DO` blocks and procedures, which can end transactions inside them.
+fn runs_code(statement: &str) -> Option<&'static str> {
+    if starts(statement, "do") {
+        return Some("the handle is read-only, and kv refuses DO blocks on read-only handles");
+    }
+    if starts(statement, "call") || starts(statement, "prepare transaction") {
+        return Some(
+            "the handle is read-only, and kv refuses statements that end the transaction \
+             or call procedures on read-only handles",
+        );
+    }
+    None
+}
+
+fn ends_transaction(statement: &str) -> bool {
+    ["commit", "end", "rollback", "abort"]
+        .iter()
+        .any(|word| starts(statement, word))
+}
+
+/// The statements in normalized SQL. A `;` inside quotes splits too, which
+/// only ever makes the guards stricter.
+fn statements(text: &str) -> impl Iterator<Item = &str> {
+    text.split(';').map(str::trim).filter(|s| !s.is_empty())
+}
+
+fn starts(statement: &str, word: &str) -> bool {
+    statement.strip_prefix(word).is_some_and(|rest| {
+        !rest
+            .chars()
+            .next()
+            .is_some_and(|c| c.is_alphanumeric() || c == '_')
+    })
+}
+
 /// Whether kv should insist on TLS for a Postgres URL: it names no
 /// `sslmode`, and some host it names is not on this machine. Postgres
 /// clients default to `prefer`, which an attacker on the network can turn
 /// into plain text by answering that the server has no TLS.
 pub fn postgres_requires_tls(url: &str) -> bool {
-    let Ok(parsed) = url::Url::parse(url) else {
-        return false;
-    };
-    if parsed.query_pairs().any(|(key, _)| key == "sslmode") {
-        return false;
+    let named = postgres_query(url).any(|(key, _)| key == "sslmode");
+    !named && postgres_hosts(url).iter().any(|host| !is_local(host))
+}
+
+/// The hosts a Postgres URL names: those in its authority, which may list
+/// several (`h1:5432,h2`), and those in `host=` and `hostaddr=`. URLs with
+/// several hosts are valid for Postgres but not for the `url` crate.
+pub fn postgres_hosts(url: &str) -> Vec<String> {
+    let mut hosts: Vec<String> = postgres_authority(url)
+        .map(|authority| authority.rsplit_once('@').map_or(authority, |(_, h)| h))
+        .into_iter()
+        .flat_map(|list| list.split(','))
+        .filter_map(|entry| match entry.strip_prefix('[') {
+            Some(v6) => v6.split(']').next(),
+            None => entry.split(':').next(),
+        })
+        .map(|host| {
+            percent_encoding::percent_decode_str(host)
+                .decode_utf8_lossy()
+                .into_owned()
+        })
+        .collect();
+    for (key, value) in postgres_query(url) {
+        if key == "host" || key == "hostaddr" {
+            hosts.extend(value.split(',').map(|h| h.trim().to_owned()));
+        }
     }
-    let hosts = parsed
-        .query_pairs()
-        .filter(|(key, _)| key == "host" || key == "hostaddr")
-        .flat_map(|(_, value)| value.split(',').map(str::to_owned).collect::<Vec<_>>())
-        .chain(parsed.host_str().map(str::to_owned));
+    hosts.retain(|host| !host.is_empty());
     hosts
-        .filter(|host| !host.is_empty())
-        .any(|host| !is_local(&host))
+}
+
+/// The passwords a Postgres URL holds, as written: in its authority, and
+/// in `password=`.
+pub fn postgres_passwords(url: &str) -> Vec<String> {
+    let mut passwords: Vec<String> = postgres_authority(url)
+        .and_then(|authority| authority.rsplit_once('@'))
+        .and_then(|(userinfo, _)| userinfo.split_once(':'))
+        .map(|(_, password)| password.to_owned())
+        .into_iter()
+        .collect();
+    passwords.extend(
+        postgres_query(url)
+            .filter(|(key, _)| key == "password")
+            .map(|(_, value)| value),
+    );
+    passwords.retain(|p| !p.is_empty());
+    passwords
+}
+
+/// Between `://` and the path, query or fragment.
+fn postgres_authority(url: &str) -> Option<&str> {
+    let (_, rest) = url.split_once("://")?;
+    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
+    Some(&rest[..end])
+}
+
+fn postgres_query(url: &str) -> impl Iterator<Item = (String, String)> {
+    let query = url
+        .split_once('?')
+        .map_or("", |(_, q)| q.split('#').next().unwrap_or(""));
+    url::form_urlencoded::parse(query.as_bytes())
+        .map(|(k, v)| (k.into_owned(), v.into_owned()))
+        .collect::<Vec<_>>()
+        .into_iter()
 }
 
 /// `localhost`, a loopback address, or a Unix socket directory.
-fn is_local(host: &str) -> bool {
+pub(crate) fn is_local(host: &str) -> bool {
     let host = host.trim_start_matches('[').trim_end_matches(']');
     host.starts_with('/')
         || host.eq_ignore_ascii_case("localhost")
diff --git a/crates/kv-core/src/scrub.rs b/crates/kv-core/src/scrub.rs
index c441e53..a257fb4 100644
--- a/crates/kv-core/src/scrub.rs
+++ b/crates/kv-core/src/scrub.rs
@@ -64,6 +64,9 @@ impl Scrubber {
         let matcher = (!patterns.is_empty()).then(|| {
             AhoCorasick::builder()
                 .match_kind(MatchKind::LeftmostLongest)
+                // Host names are case-insensitive, and a secret in another
+                // case is still a secret.
+                .ascii_case_insensitive(true)
                 .build(&patterns)
                 .expect("scrub patterns build into an automaton")
         });
diff --git a/crates/kv-core/src/secret.rs b/crates/kv-core/src/secret.rs
index 9a3db87..f084919 100644
--- a/crates/kv-core/src/secret.rs
+++ b/crates/kv-core/src/secret.rs
@@ -184,7 +184,23 @@ impl Secret {
                     }
                 }
             }
-            SecretValue::Postgres { url } | SecretValue::Redis { url } => {
+            SecretValue::Postgres { url } => {
+                let url = url.expose();
+                out.push(Zeroizing::new(url.to_owned()));
+                for host in crate::db::postgres_hosts(url) {
+                    if !crate::db::is_local(&host) {
+                        out.push(Zeroizing::new(host));
+                    }
+                }
+                for password in crate::db::postgres_passwords(url) {
+                    let decoded = percent_decode_str(&password).decode_utf8_lossy();
+                    if decoded != password {
+                        out.push(Zeroizing::new(decoded.into_owned()));
+                    }
+                    out.push(Zeroizing::new(password));
+                }
+            }
+            SecretValue::Redis { url } => {
                 out.push(Zeroizing::new(url.expose().to_owned()));
                 let parsed = url::Url::parse(url.expose()).ok();
                 if let Some(host) = parsed.as_ref().and_then(url::Url::host)
```

- [ ] **Step 4: Run the tests to watch them pass**

Run: `cargo test -p kv-core`
Expected: PASS, every kv-core test.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "Read every host and password in a Postgres URL, and add the db_connect guard"
```

### Task 2: Role checks that raced a handle change are not kept

**Files:**
- Modify: `crates/kv/src/broker.rs`
- Modify: `crates/kv/src/broker/db.rs`
- Modify: `crates/kv/src/daemon/state.rs`
- Modify: `crates/kv/tests/db.rs`

**Interfaces:**
- Consumes: nothing new.
- Produces: `RoleChecks::stamp(&self) -> u64` and `RoleChecks::record(&self, handle: &str, stamp: u64, warning: Option<String>)` (kept only if no `forget`/`clear` happened since `stamp`); `DbJob.role_stamp: u64`, set from `role_checks.stamp()` in `Daemon::prepare_db`.

- [ ] **Step 1: Write the failing tests**

Apply with `git apply` from the repository root:

```diff
diff --git a/crates/kv/tests/db.rs b/crates/kv/tests/db.rs
index 4315070..6c9ffff 100644
--- a/crates/kv/tests/db.rs
+++ b/crates/kv/tests/db.rs
@@ -146,3 +146,15 @@ fn connection_urls_must_be_postgres_or_redis_urls() {
 fn url(text: &str) -> SecretText {
     SecretText::new(text)
 }
+
+#[test]
+fn a_role_check_that_started_before_its_handle_changed_is_not_kept() {
+    let checks = kv::broker::RoleChecks::default();
+    let stamp = checks.stamp();
+    checks.forget("pg");
+    checks.record("pg", stamp, Some("can write".into()));
+    assert!(!checks.is_checked("pg"));
+    let stamp = checks.stamp();
+    checks.record("pg", stamp, Some("can write".into()));
+    assert!(checks.warnings().contains_key("pg"));
+}
```

- [ ] **Step 2: Run the tests to watch them fail**

Run: `cargo test -p kv --test db`
Expected: FAIL: `error[E0599]: no method named stamp found for struct RoleChecks` and `this method takes 2 arguments but 3 arguments were supplied`.

- [ ] **Step 3: Implement**

Apply with `git apply`:

```diff
diff --git a/crates/kv/src/broker.rs b/crates/kv/src/broker.rs
index 85817cc..2a47afb 100644
--- a/crates/kv/src/broker.rs
+++ b/crates/kv/src/broker.rs
@@ -61,6 +61,9 @@ pub struct DbJob {
     /// Where a read-only Postgres handle's role check is kept; the job runs
     /// the check if this handle has none since the vault was unlocked.
     pub role_checks: RoleChecks,
+    /// `role_checks.stamp()` when the job was authorized; a check whose
+    /// handle changed since is not kept.
+    pub role_stamp: u64,
 }
 
 /// Decodes scrubbed bytes, cutting them to `MAX_OUTPUT_LEN` (replacement
diff --git a/crates/kv/src/broker/db.rs b/crates/kv/src/broker/db.rs
index 28b60fa..857da15 100644
--- a/crates/kv/src/broker/db.rs
+++ b/crates/kv/src/broker/db.rs
@@ -24,40 +24,66 @@ use crate::audit::Use;
 const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
 
 /// Whether a write-capable role is behind each read-only Postgres handle,
-/// learned on its first query since the vault was unlocked. Shared by the
+/// learned on its first use since the vault was unlocked. Shared by the
 /// daemon, which shows the warnings and forgets them when a handle changes
 /// or the vault locks, and the jobs that run the checks.
 #[derive(Clone, Default)]
-pub struct RoleChecks(Arc<Mutex<BTreeMap<String, Option<String>>>>);
+pub struct RoleChecks(Arc<Mutex<Checks>>);
+
+#[derive(Default)]
+struct Checks {
+    /// Moves on whenever a check is forgotten, so a check that started
+    /// before then is not kept.
+    stamp: u64,
+    warnings: BTreeMap<String, Option<String>>,
+}
 
 impl RoleChecks {
-    fn map(&self) -> std::sync::MutexGuard<'_, BTreeMap<String, Option<String>>> {
+    fn checks(&self) -> std::sync::MutexGuard<'_, Checks> {
         self.0.lock().unwrap_or_else(PoisonError::into_inner)
     }
 
+    /// Taken when a job is authorized and handed back to `record`.
+    pub fn stamp(&self) -> u64 {
+        self.checks().stamp
+    }
+
     pub fn is_checked(&self, handle: &str) -> bool {
-        self.map().contains_key(handle)
+        self.checks().warnings.contains_key(handle)
     }
 
-    pub fn record(&self, handle: &str, warning: Option<String>) {
-        self.map().insert(handle.to_owned(), warning);
+    /// Keeps a check's result unless something was forgotten since `stamp`.
+    pub fn record(&self, handle: &str, stamp: u64, warning: Option<String>) {
+        let mut checks = self.checks();
+        if checks.stamp == stamp {
+            checks.warnings.insert(handle.to_owned(), warning);
+        }
     }
 
     pub fn forget(&self, handle: &str) {
-        self.map().remove(handle);
+        let mut checks = self.checks();
+        checks.stamp += 1;
+        checks.warnings.remove(handle);
     }
 
     pub fn clear(&self) {
-        self.map().clear();
+        let mut checks = self.checks();
+        checks.stamp += 1;
+        checks.warnings.clear();
     }
 
     /// The handles whose role can write, with the warning for each.
     pub fn warnings(&self) -> BTreeMap<String, String> {
-        self.map()
+        self.checks()
+            .warnings
             .iter()
             .filter_map(|(handle, warning)| Some((handle.clone(), warning.clone()?)))
             .collect()
     }
+
+    fn warning(&self, handle: &str) -> Option<String> {
+        self.checks().warnings.get(handle).cloned().flatten()
+    }
 }
 
 /// Runs the query within the job's timeout and records it in the audit log.
@@ -103,15 +129,20 @@ async fn postgres(job: &DbJob, url: &str) -> Result<AgentResponse, AgentResponse
     let client = connect(url, &options, scrubber).await?;
 
     let mut warnings = Vec::new();
-    if job.secret.policy.read_only && !job.role_checks.is_checked(&job.secret.name) {
-        let warning = role_can_write(&client)
-            .await
-            .map_err(|e| upstream(scrubber, &e))?
-            .then(|| role_warning(&job.secret.name));
-        job.role_checks.record(&job.secret.name, warning);
-    }
-    if let Some(warning) = job.role_checks.warnings().remove(&job.secret.name) {
-        warnings.push(warning);
+    if job.secret.policy.read_only {
+        let name = &job.secret.name;
+        let warning = if job.role_checks.is_checked(name) {
+            job.role_checks.warning(name)
+        } else {
+            let warning = role_can_write(&client)
+                .await
+                .map_err(|e| upstream(scrubber, &e))?
+                .then(|| role_warning(name));
+            job.role_checks
+                .record(name, job.role_stamp, warning.clone());
+            warning
+        };
+        warnings.extend(warning);
     }
 
     let stream = client
diff --git a/crates/kv/src/daemon/state.rs b/crates/kv/src/daemon/state.rs
index 2a60891..59e23a9 100644
--- a/crates/kv/src/daemon/state.rs
+++ b/crates/kv/src/daemon/state.rs
@@ -712,6 +712,7 @@ impl Daemon {
                 "auto"
             },
             role_checks: self.role_checks.clone(),
+            role_stamp: self.role_checks.stamp(),
         }));
         if !ask {
             return job;
```

- [ ] **Step 4: Run the tests to watch them pass**

Run: `cargo test -p kv --test db --test db_live`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "Keep a role check only if nothing was forgotten while it ran"
```

### Task 3: kv speaks RESP itself for Redis queries

**Files:**
- Modify: `crates/kv/Cargo.toml`
- Modify: `crates/kv/src/broker.rs`
- Modify: `crates/kv/src/broker/db.rs`
- Create: `crates/kv/src/broker/net.rs`
- Create: `crates/kv/src/broker/resp.rs`
- Create: `crates/kv/tests/resp.rs`

**Interfaces:**
- Consumes: nothing new.
- Produces: `kv::broker::net::{CONNECT_TIMEOUT, MAX_WIRE_MESSAGE, Upstream, tcp(&str, u16), tls(TcpStream, &str), tls_config() -> Result<rustls::ClientConfig, String>, Buffered<R>::{new, data, consume, fill, get_mut}}`; `kv::broker::resp::{RedisTarget::parse(&str) -> Result<RedisTarget, String>, RedisTarget.db: u32, connect(&RedisTarget) -> io::Result<Buffered<Upstream>>, Token, parse_token, encode, next_token, encode_command, read_json(&mut Buffered<R>, &Scrubber, budget: usize) -> io::Result<Result<(serde_json::Value, bool), String>>}`. The `redis` crate is no longer a dependency; `#insecure` in a Redis URL is refused.

- [ ] **Step 1: Write the failing tests**

Apply with `git apply` from the repository root:

```diff
diff --git a/crates/kv/tests/resp.rs b/crates/kv/tests/resp.rs
new file mode 100644
index 0000000..6c4be42
--- /dev/null
+++ b/crates/kv/tests/resp.rs
@@ -0,0 +1,90 @@
+//! The Redis protocol as kv reads and writes it: tokens, replies as JSON,
+//! scrubbing, and the commands clients send.
+
+use kv::broker::net::Buffered;
+use kv::broker::resp::*;
+use kv_core::scrub::Scrubber;
+
+fn tokens(mut data: &[u8]) -> Vec<Token> {
+    let mut out = Vec::new();
+    while let Some((token, used)) = parse_token(data).unwrap() {
+        out.push(token);
+        data = &data[used..];
+    }
+    assert!(data.is_empty(), "left over: {data:?}");
+    out
+}
+
+#[test]
+fn tokens_round_trip() {
+    let wire: &[u8] =
+        b"*3\r\n$5\r\nhello\r\n:42\r\n$-1\r\n%1\r\n+k\r\n_\r\n>2\r\n$7\r\nmessage\r\n#t\r\n";
+    let parsed = tokens(wire);
+    let mut out = Vec::new();
+    for token in &parsed {
+        encode(token, &mut out);
+    }
+    assert_eq!(out, wire);
+    assert_eq!(parsed[4], Token::Aggregate { kind: b'%', len: 2 });
+}
+
+#[test]
+fn a_token_waits_for_all_its_bytes() {
+    assert_eq!(parse_token(b"$5\r\nhel").unwrap(), None);
+    assert_eq!(parse_token(b":4").unwrap(), None);
+    assert!(parse_token(b"$3\r\nabcd\r\n").is_err());
+    assert!(parse_token(b"?x\r\n").is_err());
+}
+
+#[test]
+fn redis_urls_must_name_a_server_and_a_numbered_database() {
+    assert_eq!(
+        RedisTarget::parse("rediss://app:p%40ss@cache.example:6380/3")
+            .unwrap()
+            .db,
+        3
+    );
+    assert_eq!(RedisTarget::parse("redis://[::1]").unwrap().db, 0);
+    let error = RedisTarget::parse("rediss://cache.example/0#insecure")
+        .err()
+        .unwrap();
+    assert!(error.contains("#insecure"), "{error}");
+    assert!(RedisTarget::parse("redis://cache.example/x").is_err());
+    assert!(RedisTarget::parse("http://cache.example").is_err());
+}
+
+#[tokio::test]
+async fn json_stops_reading_at_the_budget() {
+    let scrubber = Scrubber::new([("cache", "s3cret-value-123")]);
+    let reply = b"*3\r\n$16\r\ns3cret-value-123\r\n%1\r\n$1\r\nk\r\n,1.5\r\n$4\r\nlast\r\n";
+    let mut conn = Buffered::new(&reply[..]);
+    let (value, truncated) = read_json(&mut conn, &scrubber, 1000)
+        .await
+        .unwrap()
+        .unwrap();
+    assert_eq!(
+        value,
+        serde_json::json!(["[kv:cache]", [["k", 1.5]], "last"])
+    );
+    assert!(!truncated);
+
+    let mut many = b"*1000\r\n".to_vec();
+    for _ in 0..1000 {
+        many.extend_from_slice(b"$10\r\n0123456789\r\n");
+    }
+    let mut conn = Buffered::new(&many[..]);
+    let (value, truncated) = read_json(&mut conn, &scrubber, 100).await.unwrap().unwrap();
+    assert!(truncated);
+    assert!(value.as_array().unwrap().len() < 10);
+    assert!(
+        !conn.data().is_empty() || conn.fill().await.unwrap(),
+        "the rest stays unread"
+    );
+
+    let mut conn = Buffered::new(&b"-ERR wrong s3cret-value-123\r\n"[..]);
+    let error = read_json(&mut conn, &scrubber, 1000)
+        .await
+        .unwrap()
+        .unwrap_err();
+    assert_eq!(error, "ERR wrong [kv:cache]");
+}
```

- [ ] **Step 2: Run the tests to watch them fail**

Run: `cargo test -p kv --test resp`
Expected: FAIL: `error[E0432]: unresolved import kv::broker::resp` and `kv::broker::net`.

- [ ] **Step 3: Implement**

Apply with `git apply` (Cargo.lock updates itself on the next build):

```diff
diff --git a/crates/kv/Cargo.toml b/crates/kv/Cargo.toml
index 7f7a63a..0a8c1f3 100644
--- a/crates/kv/Cargo.toml
+++ b/crates/kv/Cargo.toml
@@ -12,8 +12,8 @@ futures-util = { version = "0.3", default-features = false }
 humantime = "2"
 kv-core = { path = "../kv-core" }
 notify-rust = "4.18"
+percent-encoding = "2.3"
 ratatui = { version = "0.30", features = ["unstable-rendered-line-info"] }
-redis = { version = "1.7", default-features = false, features = ["tokio-rustls-comp"] }
 reqwest = { version = "0.13", default-features = false, features = ["rustls"] }
 rmcp = { version = "3.5", default-features = false, features = ["macros", "server", "transport-io"] }
 rpassword = "7.5"
@@ -24,6 +24,7 @@ serde_json = "1"
 tokio = { version = "1.53", features = ["io-util", "macros", "net", "process", "rt-multi-thread", "sync", "time"] }
 tokio-postgres = { version = "0.7", default-features = false, features = ["runtime"] }
 tokio-postgres-rustls = { version = "0.14", default-features = false, features = ["aws-lc-rs"] }
+tokio-rustls = { version = "0.26", default-features = false }
 url = "2.5"
 zeroize = "1.9"
 
diff --git a/crates/kv/src/broker.rs b/crates/kv/src/broker.rs
index 2a47afb..c272a41 100644
--- a/crates/kv/src/broker.rs
+++ b/crates/kv/src/broker.rs
@@ -16,7 +16,9 @@ use crate::audit::Audit;
 pub mod db;
 pub mod exec;
 pub mod http;
+pub mod net;
 mod process;
+pub mod resp;
 
 pub use db::RoleChecks;
 
diff --git a/crates/kv/src/broker/db.rs b/crates/kv/src/broker/db.rs
index 857da15..38598e4 100644
--- a/crates/kv/src/broker/db.rs
+++ b/crates/kv/src/broker/db.rs
@@ -5,7 +5,6 @@
 use std::collections::BTreeMap;
 use std::pin::pin;
 use std::sync::{Arc, Mutex, PoisonError};
-use std::time::Duration;
 
 use futures_util::StreamExt;
 use kv_core::db::{postgres_requires_tls, split_command};
@@ -15,14 +14,14 @@ use kv_core::proto::{
 };
 use kv_core::scrub::Scrubber;
 use kv_core::secret::{Secret, SecretText, SecretValue};
-use rustls_platform_verifier::BuilderVerifierExt;
+use tokio::io::AsyncWriteExt;
 use tokio_postgres::SimpleQueryMessage;
 
 use super::DbJob;
+use super::net::CONNECT_TIMEOUT;
+use super::resp::{self, RedisTarget};
 use crate::audit::Use;
 
-const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
-
 /// Whether a write-capable role is behind each read-only Postgres handle,
 /// learned on its first use since the vault was unlocked. Shared by the
 /// daemon, which shows the warnings and forgets them when a handle changes
@@ -226,7 +225,9 @@ async fn connect(
     if postgres_requires_tls(url) {
         config.ssl_mode(tokio_postgres::config::SslMode::Require);
     }
-    let tls = tokio_postgres_rustls::MakeRustlsConnect::new(tls_config()?);
+    let tls = super::net::tls_config()
+        .map_err(|message| error(AgentErrorCode::UpstreamError, message))?;
+    let tls = tokio_postgres_rustls::MakeRustlsConnect::new(tls);
     let (client, connection) = config
         .connect(tls)
         .await
@@ -304,156 +305,29 @@ FROM pg_catalog.pg_roles r WHERE r.rolname = current_user";
         .any(|message| matches!(message, SimpleQueryMessage::Row(row) if row.get(0) == Some("t"))))
 }
 
-/// Certificates are always checked against the platform's trust store,
-/// whatever `sslmode` says; `sslmode=disable` still turns TLS off. A remote
-/// server with no `sslmode` in the URL must use TLS.
-fn tls_config() -> Result<rustls::ClientConfig, AgentResponse> {
-    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
-    rustls::ClientConfig::builder_with_provider(provider)
-        .with_safe_default_protocol_versions()
-        .and_then(|builder| builder.with_platform_verifier())
-        .map(|builder| builder.with_no_client_auth())
-        .map_err(|e| {
-            error(
-                AgentErrorCode::UpstreamError,
-                format!("could not set up TLS: {e}"),
-            )
-        })
-}
-
+/// One command on a connection of its own. The reply is read only as far
+/// as the output cap, so a huge one is never held whole.
 async fn redis(job: &DbJob, url: &str) -> Result<AgentResponse, AgentResponse> {
     let scrubber = &job.scrubber;
     // Checked by the daemon already; this split cannot fail.
     let args = split_command(&job.call.query)
         .map_err(|message| error(AgentErrorCode::BadRequest, message))?;
-    let client = redis::Client::open(url).map_err(|_| {
-        error(
-            AgentErrorCode::BadRequest,
-            "the handle's connection URL is not a valid Redis URL",
-        )
-    })?;
-    let config = redis::AsyncConnectionConfig::new()
-        .set_connection_timeout(Some(CONNECT_TIMEOUT))
-        .set_response_timeout(Some(job.timeout));
-    let mut connection = client
-        .get_multiplexed_async_connection_with_config(&config)
+    let target =
+        RedisTarget::parse(url).map_err(|message| error(AgentErrorCode::BadRequest, message))?;
+    let mut conn = resp::connect(&target)
         .await
         .map_err(|e| upstream(scrubber, &e))?;
-    let mut command = redis::cmd(&String::from_utf8_lossy(&args[0]));
-    for arg in &args[1..] {
-        command.arg(arg.as_slice());
-    }
-    let value: redis::Value = command
-        .query_async(&mut connection)
+    conn.get_mut()
+        .write_all(&resp::encode_command(&args))
         .await
         .map_err(|e| upstream(scrubber, &e))?;
-    let mut budget = MAX_OUTPUT_LEN;
-    let mut truncated = false;
-    let value = to_json(scrubber, value, &mut budget, &mut truncated);
-    Ok(AgentResponse::Redis(RedisReply { value, truncated }))
-}
-
-/// A Redis value as JSON, scrubbed, spending `budget` bytes at most.
-/// Anything past the budget is cut or left out and `truncated` is set.
-fn to_json(
-    scrubber: &Scrubber,
-    value: redis::Value,
-    budget: &mut usize,
-    truncated: &mut bool,
-) -> serde_json::Value {
-    use redis::Value;
-    use serde_json::Value as Json;
-    match value {
-        Value::Nil => {
-            charge(budget, 4);
-            Json::Null
-        }
-        Value::Boolean(b) => {
-            charge(budget, 5);
-            Json::Bool(b)
-        }
-        Value::Okay => text(scrubber, b"OK", budget, truncated),
-        Value::Int(n) => number(scrubber, n.to_string(), Json::from(n), budget),
-        Value::Double(n) => number(scrubber, n.to_string(), Json::from(n), budget),
-        Value::BulkString(bytes) => text(scrubber, &bytes, budget, truncated),
-        Value::SimpleString(s) => text(scrubber, s.as_bytes(), budget, truncated),
-        Value::VerbatimString { text: s, .. } => text(scrubber, s.as_bytes(), budget, truncated),
-        Value::BigNumber(digits) => text(scrubber, &digits, budget, truncated),
-        Value::Array(items) | Value::Set(items) => list(scrubber, items, budget, truncated),
-        Value::Map(pairs) => list(
-            scrubber,
-            pairs
-                .into_iter()
-                .map(|(k, v)| Value::Array(vec![k, v]))
-                .collect(),
-            budget,
-            truncated,
-        ),
-        Value::Attribute { data, .. } => to_json(scrubber, *data, budget, truncated),
-        Value::Push { data, .. } => list(scrubber, data, budget, truncated),
-        Value::ServerError(e) => text(scrubber, e.to_string().as_bytes(), budget, truncated),
-        _ => Json::Null,
-    }
-}
-
-fn charge(budget: &mut usize, bytes: usize) {
-    *budget = budget.saturating_sub(bytes);
-}
-
-/// Scrubbed first and cut after, so a cut never splits a secret in two
-/// halves the scrubber cannot see.
-fn text(
-    scrubber: &Scrubber,
-    bytes: &[u8],
-    budget: &mut usize,
-    truncated: &mut bool,
-) -> serde_json::Value {
-    let mut text = scrub_text(scrubber, bytes);
-    let room = budget.saturating_sub(3);
-    if text.len() > room {
-        let mut end = room;
-        while !text.is_char_boundary(end) {
-            end -= 1;
-        }
-        text.truncate(end);
-        *truncated = true;
-    }
-    charge(budget, text.len() + 3);
-    serde_json::Value::String(text)
-}
-
-/// A number could be a numeric secret, so it goes through the scrubber
-/// too, and comes back as a string if it was replaced.
-fn number(
-    scrubber: &Scrubber,
-    digits: String,
-    json: serde_json::Value,
-    budget: &mut usize,
-) -> serde_json::Value {
-    charge(budget, digits.len() + 1);
-    let scrubbed = scrub_text(scrubber, digits.as_bytes());
-    if scrubbed == digits {
-        json
-    } else {
-        serde_json::Value::String(scrubbed)
-    }
-}
-
-fn list(
-    scrubber: &Scrubber,
-    items: Vec<redis::Value>,
-    budget: &mut usize,
-    truncated: &mut bool,
-) -> serde_json::Value {
-    let mut out = Vec::new();
-    for item in items {
-        if *budget == 0 {
-            *truncated = true;
-            break;
-        }
-        out.push(to_json(scrubber, item, budget, truncated));
+    match resp::read_json(&mut conn, scrubber, MAX_OUTPUT_LEN)
+        .await
+        .map_err(|e| upstream(scrubber, &e))?
+    {
+        Ok((value, truncated)) => Ok(AgentResponse::Redis(RedisReply { value, truncated })),
+        Err(message) => Err(error(AgentErrorCode::UpstreamError, message)),
     }
-    serde_json::Value::Array(out)
 }
 
 fn scrub_text(scrubber: &Scrubber, bytes: &[u8]) -> String {
diff --git a/crates/kv/src/broker/net.rs b/crates/kv/src/broker/net.rs
new file mode 100644
index 0000000..33f7df8
--- /dev/null
+++ b/crates/kv/src/broker/net.rs
@@ -0,0 +1,151 @@
+//! Connections to database servers: TCP with a time limit, then TLS
+//! checked against the platform's trust store.
+
+use std::io;
+use std::pin::Pin;
+use std::sync::Arc;
+use std::task::{Context, Poll};
+use std::time::Duration;
+
+use rustls::pki_types::ServerName;
+use rustls_platform_verifier::BuilderVerifierExt;
+use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
+use tokio::net::TcpStream;
+use tokio_rustls::TlsConnector;
+use tokio_rustls::client::TlsStream;
+
+pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
+
+/// Largest single message kv reads from a database server or a leased
+/// client: a Postgres message, or one Redis string. Each is held whole
+/// while it is scrubbed.
+pub const MAX_WIRE_MESSAGE: usize = 16 * 1024 * 1024;
+
+/// A connection to a database server, with or without TLS.
+pub enum Upstream {
+    Plain(TcpStream),
+    Tls(Box<TlsStream<TcpStream>>),
+}
+
+pub async fn tcp(host: &str, port: u16) -> io::Result<TcpStream> {
+    match tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect((host, port))).await {
+        Ok(connected) => connected,
+        Err(_) => Err(io::Error::new(
+            io::ErrorKind::TimedOut,
+            "the server did not answer in time",
+        )),
+    }
+}
+
+/// Starts TLS on `stream`, checking the certificate for `host`.
+pub async fn tls(stream: TcpStream, host: &str) -> io::Result<Upstream> {
+    let config = tls_config().map_err(io::Error::other)?;
+    let name = ServerName::try_from(host.to_owned())
+        .map_err(|_| io::Error::other("the host name is not valid for TLS"))?;
+    let connecting = TlsConnector::from(Arc::new(config)).connect(name, stream);
+    match tokio::time::timeout(CONNECT_TIMEOUT, connecting).await {
+        Ok(connected) => connected.map(|s| Upstream::Tls(Box::new(s))),
+        Err(_) => Err(io::Error::new(
+            io::ErrorKind::TimedOut,
+            "the TLS handshake did not finish in time",
+        )),
+    }
+}
+
+/// Certificates are always checked against the platform's trust store.
+pub fn tls_config() -> Result<rustls::ClientConfig, String> {
+    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
+    rustls::ClientConfig::builder_with_provider(provider)
+        .with_safe_default_protocol_versions()
+        .and_then(|builder| builder.with_platform_verifier())
+        .map(|builder| builder.with_no_client_auth())
+        .map_err(|e| format!("could not set up TLS: {e}"))
+}
+
+/// Reads protocol messages from a stream into a buffer. Only `fill` waits,
+/// and it keeps what it read in the buffer, so a read that is cancelled in
+/// a `select!` loses nothing.
+pub struct Buffered<R> {
+    inner: R,
+    buf: Vec<u8>,
+    start: usize,
+}
+
+impl<R: AsyncRead + Unpin> Buffered<R> {
+    pub fn new(inner: R) -> Self {
+        Self {
+            inner,
+            buf: Vec::new(),
+            start: 0,
+        }
+    }
+
+    /// The bytes read but not yet consumed.
+    pub fn data(&self) -> &[u8] {
+        &self.buf[self.start..]
+    }
+
+    pub fn consume(&mut self, n: usize) {
+        self.start += n;
+        if self.start == self.buf.len() {
+            self.buf.clear();
+            self.start = 0;
+        }
+    }
+
+    /// Reads more; `false` at the end of the stream.
+    pub async fn fill(&mut self) -> io::Result<bool> {
+        if self.start > 0 && self.start * 2 >= self.buf.len() {
+            self.buf.drain(..self.start);
+            self.start = 0;
+        }
+        let mut chunk = [0u8; 16 * 1024];
+        let n = self.inner.read(&mut chunk).await?;
+        self.buf.extend_from_slice(&chunk[..n]);
+        Ok(n > 0)
+    }
+
+    pub fn get_mut(&mut self) -> &mut R {
+        &mut self.inner
+    }
+}
+
+impl AsyncRead for Upstream {
+    fn poll_read(
+        self: Pin<&mut Self>,
+        cx: &mut Context<'_>,
+        buf: &mut ReadBuf<'_>,
+    ) -> Poll<io::Result<()>> {
+        match self.get_mut() {
+            Self::Plain(s) => Pin::new(s).poll_read(cx, buf),
+            Self::Tls(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
+        }
+    }
+}
+
+impl AsyncWrite for Upstream {
+    fn poll_write(
+        self: Pin<&mut Self>,
+        cx: &mut Context<'_>,
+        buf: &[u8],
+    ) -> Poll<io::Result<usize>> {
+        match self.get_mut() {
+            Self::Plain(s) => Pin::new(s).poll_write(cx, buf),
+            Self::Tls(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
+        }
+    }
+
+    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
+        match self.get_mut() {
+            Self::Plain(s) => Pin::new(s).poll_flush(cx),
+            Self::Tls(s) => Pin::new(s.as_mut()).poll_flush(cx),
+        }
+    }
+
+    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
+        match self.get_mut() {
+            Self::Plain(s) => Pin::new(s).poll_shutdown(cx),
+            Self::Tls(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
+        }
+    }
+}
diff --git a/crates/kv/src/broker/resp.rs b/crates/kv/src/broker/resp.rs
new file mode 100644
index 0000000..f16599d
--- /dev/null
+++ b/crates/kv/src/broker/resp.rs
@@ -0,0 +1,401 @@
+//! The Redis protocol (RESP2 and RESP3): connecting to a server, commands,
+//! and replies read one token at a time, so a reply is never held whole.
+
+use std::io;
+
+use kv_core::scrub::Scrubber;
+use percent_encoding::percent_decode_str;
+use tokio::io::{AsyncRead, AsyncWriteExt};
+
+use super::net::{self, Buffered, MAX_WIRE_MESSAGE, Upstream};
+
+/// Where a Redis URL points, and how to log in.
+#[derive(Clone)]
+pub struct RedisTarget {
+    host: String,
+    port: u16,
+    tls: bool,
+    username: Option<String>,
+    password: Option<String>,
+    pub db: u32,
+}
+
+impl RedisTarget {
+    pub fn parse(url: &str) -> Result<Self, String> {
+        let invalid = || "the handle's connection URL is not a valid Redis URL".to_owned();
+        let parsed = url::Url::parse(url).map_err(|_| invalid())?;
+        let tls = match parsed.scheme() {
+            "redis" => false,
+            "rediss" => true,
+            _ => return Err(invalid()),
+        };
+        if parsed.fragment().is_some() {
+            return Err(
+                "kv does not accept a fragment such as #insecure in a Redis URL; it always checks \
+                 TLS certificates"
+                    .into(),
+            );
+        }
+        let host = match parsed.host() {
+            Some(url::Host::Ipv6(ip)) => ip.to_string(),
+            Some(host) => host.to_string(),
+            None => return Err(invalid()),
+        };
+        let decode = |s: &str| percent_decode_str(s).decode_utf8_lossy().into_owned();
+        let db = match parsed.path().trim_matches('/') {
+            "" => 0,
+            n => n
+                .parse()
+                .map_err(|_| "the database in the Redis URL is not a number".to_owned())?,
+        };
+        Ok(Self {
+            host,
+            port: parsed.port().unwrap_or(6379),
+            tls,
+            username: (!parsed.username().is_empty()).then(|| decode(parsed.username())),
+            password: parsed.password().map(decode),
+            db,
+        })
+    }
+}
+
+/// Connects, logs in and selects the URL's database.
+pub async fn connect(target: &RedisTarget) -> io::Result<Buffered<Upstream>> {
+    let stream = net::tcp(&target.host, target.port).await?;
+    let stream = if target.tls {
+        net::tls(stream, &target.host).await?
+    } else {
+        Upstream::Plain(stream)
+    };
+    let mut conn = Buffered::new(stream);
+    if let Some(password) = &target.password {
+        let mut auth = vec![b"AUTH".to_vec()];
+        auth.extend(target.username.iter().map(|u| u.as_bytes().to_vec()));
+        auth.push(password.as_bytes().to_vec());
+        expect_ok(&mut conn, &auth).await?;
+    }
+    if target.db != 0 {
+        expect_ok(
+            &mut conn,
+            &[b"SELECT".to_vec(), target.db.to_string().into()],
+        )
+        .await?;
+    }
+    Ok(conn)
+}
+
+async fn expect_ok(conn: &mut Buffered<Upstream>, command: &[Vec<u8>]) -> io::Result<()> {
+    conn.get_mut().write_all(&encode_command(command)).await?;
+    match next_token(conn).await? {
+        Some(Token::Line { kind: b'+', .. }) => Ok(()),
+        Some(
+            Token::Line { kind: b'-', text }
+            | Token::Bulk {
+                kind: b'!',
+                data: text,
+            },
+        ) => Err(io::Error::other(
+            String::from_utf8_lossy(&text).into_owned(),
+        )),
+        _ => Err(io::Error::other("the server sent an unexpected reply")),
+    }
+}
+
+/// One piece of a reply.
+#[derive(Clone, Debug, PartialEq, Eq)]
+pub enum Token {
+    /// An array, set, push or map header and how many values follow (a
+    /// map's keys and values both count).
+    Aggregate { kind: u8, len: usize },
+    /// A null, as it was sent.
+    Null(Vec<u8>),
+    /// `+`, `-`, `:`, `,`, `(` or `#`, without the line end.
+    Line { kind: u8, text: Vec<u8> },
+    /// `$`, `!` or `=`.
+    Bulk { kind: u8, data: Vec<u8> },
+}
+
+/// Reads one token from the front of `data`, with the bytes it took;
+/// `None` until all of it has arrived.
+pub fn parse_token(data: &[u8]) -> Result<Option<(Token, usize)>, String> {
+    let Some(&kind) = data.first() else {
+        return Ok(None);
+    };
+    let Some(end) = data.windows(2).position(|w| w == b"\r\n") else {
+        if data.len() > MAX_WIRE_MESSAGE {
+            return Err("a line is longer than kv accepts".into());
+        }
+        return Ok(None);
+    };
+    let line = &data[1..end];
+    let after = end + 2;
+    let null = || Ok(Some((Token::Null(data[..after].to_vec()), after)));
+    match kind {
+        b'+' | b'-' | b':' | b',' | b'(' | b'#' => Ok(Some((
+            Token::Line {
+                kind,
+                text: line.to_vec(),
+            },
+            after,
+        ))),
+        b'_' => null(),
+        b'$' | b'!' | b'=' => {
+            let Ok(len) = usize::try_from(length(line)?) else {
+                return null();
+            };
+            if len > MAX_WIRE_MESSAGE {
+                return Err("a string is larger than kv accepts (16 MiB)".into());
+            }
+            if data.len() < after + len + 2 {
+                return Ok(None);
+            }
+            if &data[after + len..after + len + 2] != b"\r\n" {
+                return Err("a string has the wrong length".into());
+            }
+            Ok(Some((
+                Token::Bulk {
+                    kind,
+                    data: data[after..after + len].to_vec(),
+                },
+                after + len + 2,
+            )))
+        }
+        b'*' | b'%' | b'~' | b'>' => {
+            let Ok(len) = usize::try_from(length(line)?) else {
+                return null();
+            };
+            let len = if kind == b'%' {
+                len.checked_mul(2).ok_or("a map is too large")?
+            } else {
+                len
+            };
+            Ok(Some((Token::Aggregate { kind, len }, after)))
+        }
+        other => Err(format!(
+            "kv does not handle Redis replies of type {:?}",
+            other as char
+        )),
+    }
+}
+
+fn length(line: &[u8]) -> Result<i64, String> {
+    std::str::from_utf8(line)
+        .ok()
+        .and_then(|s| s.parse().ok())
+        .ok_or_else(|| "a length is not a number".to_owned())
+}
+
+pub fn encode(token: &Token, out: &mut Vec<u8>) {
+    match token {
+        Token::Aggregate { kind, len } => {
+            let count = if *kind == b'%' { len / 2 } else { *len };
+            out.push(*kind);
+            out.extend_from_slice(count.to_string().as_bytes());
+            out.extend_from_slice(b"\r\n");
+        }
+        Token::Null(raw) => out.extend_from_slice(raw),
+        Token::Line { kind, text } => {
+            out.push(*kind);
+            out.extend_from_slice(text);
+            out.extend_from_slice(b"\r\n");
+        }
+        Token::Bulk { kind, data } => {
+            out.push(*kind);
+            out.extend_from_slice(data.len().to_string().as_bytes());
+            out.extend_from_slice(b"\r\n");
+            out.extend_from_slice(data);
+            out.extend_from_slice(b"\r\n");
+        }
+    }
+}
+
+pub async fn next_token<R: AsyncRead + Unpin>(conn: &mut Buffered<R>) -> io::Result<Option<Token>> {
+    loop {
+        if let Some((token, used)) = parse_token(conn.data()).map_err(io::Error::other)? {
+            conn.consume(used);
+            return Ok(Some(token));
+        }
+        if !conn.fill().await? {
+            return match conn.data().is_empty() {
+                true => Ok(None),
+                false => Err(io::ErrorKind::UnexpectedEof.into()),
+            };
+        }
+    }
+}
+
+pub fn encode_command(args: &[Vec<u8>]) -> Vec<u8> {
+    let mut out = format!("*{}\r\n", args.len()).into_bytes();
+    for arg in args {
+        encode(
+            &Token::Bulk {
+                kind: b'$',
+                data: arg.clone(),
+            },
+            &mut out,
+        );
+    }
+    out
+}
+
+/// A container still taking values while a reply becomes JSON.
+struct Open {
+    kind: u8,
+    items: Vec<serde_json::Value>,
+    left: usize,
+}
+
+impl Open {
+    /// Maps become arrays of `[key, value]` pairs.
+    fn close(self) -> serde_json::Value {
+        if self.kind == b'%' {
+            serde_json::Value::Array(
+                self.items
+                    .chunks(2)
+                    .map(|pair| serde_json::Value::Array(pair.to_vec()))
+                    .collect(),
+            )
+        } else {
+            serde_json::Value::Array(self.items)
+        }
+    }
+}
+
+/// Reads one reply as JSON, scrubbed, spending at most `budget` bytes; the
+/// flag says something was cut or left out, and the rest of the reply is
+/// never read. A server error as the whole reply is `Err`, scrubbed.
+pub async fn read_json<R: AsyncRead + Unpin>(
+    conn: &mut Buffered<R>,
+    scrubber: &Scrubber,
+    mut budget: usize,
+) -> io::Result<Result<(serde_json::Value, bool), String>> {
+    use serde_json::Value as Json;
+    let mut stack: Vec<Open> = Vec::new();
+    let mut truncated = false;
+    loop {
+        if budget == 0 && !stack.is_empty() {
+            let mut value = stack.pop().map(Open::close).unwrap_or_default();
+            while let Some(mut parent) = stack.pop() {
+                parent.items.push(value);
+                value = parent.close();
+            }
+            return Ok(Ok((value, true)));
+        }
+        let token = next_token(conn)
+            .await?
+            .ok_or(io::ErrorKind::UnexpectedEof)?;
+        let mut value = match token {
+            Token::Aggregate { kind, len } if len > 0 => {
+                charge(&mut budget, 2);
+                stack.push(Open {
+                    kind,
+                    items: Vec::new(),
+                    left: len,
+                });
+                continue;
+            }
+            Token::Aggregate { .. } => {
+                charge(&mut budget, 2);
+                Json::Array(Vec::new())
+            }
+            Token::Null(_) => {
+                charge(&mut budget, 4);
+                Json::Null
+            }
+            Token::Line {
+                kind: b'-',
+                text: error,
+            }
+            | Token::Bulk {
+                kind: b'!',
+                data: error,
+            } if stack.is_empty() => {
+                return Ok(Err(scrub_text(scrubber, &error)));
+            }
+            Token::Line { kind: b'#', text } => {
+                charge(&mut budget, 5);
+                Json::Bool(text == b"t")
+            }
+            Token::Line { kind: b':', text } => {
+                let digits = String::from_utf8_lossy(&text).into_owned();
+                let json = digits.parse::<i64>().map(Json::from).ok();
+                number(scrubber, digits, json, &mut budget)
+            }
+            Token::Line { kind: b',', text } => {
+                let digits = String::from_utf8_lossy(&text).into_owned();
+                let json = digits
+                    .parse::<f64>()
+                    .ok()
+                    .and_then(serde_json::Number::from_f64)
+                    .map(Json::Number);
+                number(scrubber, digits, json, &mut budget)
+            }
+            Token::Bulk { kind: b'=', data } => {
+                // Verbatim strings start with a format such as `txt:`.
+                let text_part = data.get(4..).unwrap_or(&data);
+                text(scrubber, text_part, &mut budget, &mut truncated)
+            }
+            Token::Line { text: bytes, .. } | Token::Bulk { data: bytes, .. } => {
+                text(scrubber, &bytes, &mut budget, &mut truncated)
+            }
+        };
+        loop {
+            let Some(top) = stack.last_mut() else {
+                return Ok(Ok((value, truncated)));
+            };
+            top.items.push(value);
+            top.left -= 1;
+            if top.left > 0 {
+                break;
+            }
+            value = stack.pop().map(Open::close).unwrap_or_default();
+        }
+    }
+}
+
+fn charge(budget: &mut usize, bytes: usize) {
+    *budget = budget.saturating_sub(bytes);
+}
+
+/// Scrubbed first and cut after, so a cut never splits a secret in two
+/// halves the scrubber cannot see.
+fn text(
+    scrubber: &Scrubber,
+    bytes: &[u8],
+    budget: &mut usize,
+    truncated: &mut bool,
+) -> serde_json::Value {
+    let mut text = scrub_text(scrubber, bytes);
+    let room = budget.saturating_sub(3);
+    if text.len() > room {
+        let mut end = room;
+        while !text.is_char_boundary(end) {
+            end -= 1;
+        }
+        text.truncate(end);
+        *truncated = true;
+    }
+    charge(budget, text.len() + 3);
+    serde_json::Value::String(text)
+}
+
+/// A number could be a numeric secret, so it goes through the scrubber
+/// too, and comes back as a string if it was replaced (or is not a JSON
+/// number, such as `inf`).
+fn number(
+    scrubber: &Scrubber,
+    digits: String,
+    json: Option<serde_json::Value>,
+    budget: &mut usize,
+) -> serde_json::Value {
+    charge(budget, digits.len() + 1);
+    let scrubbed = scrub_text(scrubber, digits.as_bytes());
+    match json {
+        Some(json) if scrubbed == digits => json,
+        _ => serde_json::Value::String(scrubbed),
+    }
+}
+
+fn scrub_text(scrubber: &Scrubber, bytes: &[u8]) -> String {
+    String::from_utf8_lossy(&scrubber.scrub(bytes)).into_owned()
+}
```

- [ ] **Step 4: Run the tests to watch them pass**

Run: `cargo test -p kv --test resp --test db --test db_live`
Expected: PASS, including the existing live Redis tests (`redis_replies_come_back_as_json_with_secrets_scrubbed`, `big_redis_replies_are_cut`).

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "Speak RESP directly for Redis queries, reading replies only up to the cap"
```

### Task 4: db_connect leases, with the Redis relay

**Files:**
- Modify: `crates/kv-core/src/proto.rs`
- Modify: `crates/kv-core/tests/proto.rs`
- Modify: `crates/kv/Cargo.toml`
- Modify: `crates/kv/src/broker.rs`
- Create: `crates/kv/src/broker/lease.rs`
- Create: `crates/kv/src/broker/lease/redis.rs`
- Modify: `crates/kv/src/broker/net.rs`
- Modify: `crates/kv/src/broker/resp.rs`
- Modify: `crates/kv/src/daemon/server.rs`
- Modify: `crates/kv/src/daemon/state.rs`
- Modify: `crates/kv/src/mcp.rs`
- Modify: `crates/kv/tests/approve.rs`
- Modify: `crates/kv/tests/common/mod.rs`
- Modify: `crates/kv/tests/db_live.rs`
- Create: `crates/kv/tests/lease.rs`
- Create: `crates/kv/tests/lease_live.rs`
- Modify: `crates/kv/tests/mcp.rs`
- Modify: `crates/kv/tests/resp.rs`
- Modify: `crates/kv/tests/state.rs`

**Interfaces:**
- Consumes: Task 3 `net` and `resp`; `kv_core::db::{check_redis, RedisRefusal}`.
- Produces: `kv_core::proto::{AgentRequest::DbConnect(ConnectCall { handle: String, ttl_secs: Option<u64> }), AgentResponse::Lease(LeaseReply { url: String, expires_in_secs: u64, warnings: Vec<String> })}`; `kv::broker::{ConnectJob, Leases, LeaseTicket}`; `kv::broker::lease::{start(ConnectJob) -> AgentResponse, DEFAULT_TTL, MAX_TTL, MAX_LEASES}`; `Leases::{open(&str) -> Option<LeaseTicket>, end_handle(&str), end_all(), count(), subscribe(), set_scrubber(Arc<Scrubber>)}`; `LeaseTicket::has_ended()`; `Prepared::Connect(Box<ConnectJob>)`; `net::Buffered::{with_data, into_parts}`; `resp::{scrub_token, Frame, Command, parse_command, next_command}`; the `db_connect` MCP tool. Test helpers: `Fixture::connect(ConnectCall)`, `lease(&str) -> ConnectCall`, and `server`/`admin` moved from `db_live.rs` to `tests/common`. Postgres handles get `bad_request` from `lease::start` until Task 5.

- [ ] **Step 1: Write the failing tests**

Apply with `git apply` from the repository root:

```diff
diff --git a/crates/kv-core/tests/proto.rs b/crates/kv-core/tests/proto.rs
index 4cd46cd..c00cf8d 100644
--- a/crates/kv-core/tests/proto.rs
+++ b/crates/kv-core/tests/proto.rs
@@ -3,9 +3,10 @@ use std::time::Duration;
 
 use kv_core::policy::{Mode, Policy};
 use kv_core::proto::{
-    AgentErrorCode, AgentRequest, AgentResponse, ControlCommand, ControlRequest, ControlResponse,
-    DbCall, ExecCall, ExecReply, HttpReply, MAX_FRAME_LEN, MAX_OUTPUT_LEN, Overview, PolicyPatch,
-    RedisReply, ResultSet, RowsReply, SessionInfo, Status, Verdict,
+    AgentErrorCode, AgentRequest, AgentResponse, ConnectCall, ControlCommand, ControlRequest,
+    ControlResponse, DbCall, ExecCall, ExecReply, HttpReply, LeaseReply, MAX_FRAME_LEN,
+    MAX_OUTPUT_LEN, Overview, PolicyPatch, RedisReply, ResultSet, RowsReply, SessionInfo, Status,
+    Verdict,
 };
 use kv_core::secret::{AuthPlacement, Secret, SecretText, SecretValue};
 
@@ -355,6 +356,19 @@ fn a_db_query_is_a_flat_tagged_object_with_an_optional_timeout() {
     );
 }
 
+#[test]
+fn a_db_connect_takes_a_handle_and_an_optional_ttl() {
+    let request: AgentRequest =
+        serde_json::from_str(r#"{"type":"db_connect","handle":"prod-db"}"#).unwrap();
+    assert_eq!(
+        request,
+        AgentRequest::DbConnect(ConnectCall {
+            handle: "prod-db".into(),
+            ttl_secs: None,
+        })
+    );
+}
+
 #[test]
 fn database_replies_round_trip() {
     for response in [
@@ -371,6 +385,11 @@ fn database_replies_round_trip() {
             value: serde_json::json!(["a", 1, null]),
             truncated: true,
         }),
+        AgentResponse::Lease(LeaseReply {
+            url: "postgres://kv:token@127.0.0.1:41823/app".into(),
+            expires_in_secs: 900,
+            warnings: Vec::new(),
+        }),
     ] {
         let json = serde_json::to_string(&response).unwrap();
         assert_eq!(
diff --git a/crates/kv/tests/approve.rs b/crates/kv/tests/approve.rs
index f9d7759..505bb5b 100644
--- a/crates/kv/tests/approve.rs
+++ b/crates/kv/tests/approve.rs
@@ -29,6 +29,7 @@ fn job_decision(prepared: Prepared) -> &'static str {
         Prepared::Http(job) => job.decision,
         Prepared::Exec(job) => job.decision,
         Prepared::Db(job) => job.decision,
+        Prepared::Connect(job) => job.decision,
         Prepared::Reply(reply) => panic!("expected a job, got {reply:?}"),
         Prepared::Wait(_) => panic!("expected a job, got a wait"),
     }
diff --git a/crates/kv/tests/common/mod.rs b/crates/kv/tests/common/mod.rs
index 31fb0f8..5ff520f 100644
--- a/crates/kv/tests/common/mod.rs
+++ b/crates/kv/tests/common/mod.rs
@@ -7,12 +7,12 @@ use std::path::PathBuf;
 use std::time::Instant;
 
 use kv::audit::Audit;
-use kv::broker::{DbJob, ExecJob, HttpJob};
+use kv::broker::{ConnectJob, DbJob, ExecJob, HttpJob};
 use kv::daemon::{Daemon, Prepared, Settings, Waiting};
 use kv_core::policy::{Mode, Policy};
 use kv_core::proto::{
-    AgentErrorCode, AgentRequest, AgentResponse, ControlCommand, ControlRequest, ControlResponse,
-    DbCall, ExecCall, HttpCall, Overview, SessionInfo, Verdict,
+    AgentErrorCode, AgentRequest, AgentResponse, ConnectCall, ControlCommand, ControlRequest,
+    ControlResponse, DbCall, ExecCall, HttpCall, Overview, SessionInfo, Verdict,
 };
 use kv_core::secret::{AuthPlacement, Secret, SecretText, SecretValue};
 use tempfile::TempDir;
@@ -75,8 +75,7 @@ impl Fixture {
             Prepared::Http(job) => Ok(*job),
             Prepared::Reply(AgentResponse::Error { code, message }) => Err((code, message)),
             Prepared::Reply(other) => panic!("unexpected reply {other:?}"),
-            Prepared::Exec(_) => panic!("unexpected exec job"),
-            Prepared::Db(_) => panic!("unexpected db job"),
+            Prepared::Exec(_) | Prepared::Db(_) | Prepared::Connect(_) => panic!("unexpected job"),
             Prepared::Wait(_) => panic!("unexpected wait for approval"),
         }
     }
@@ -86,8 +85,7 @@ impl Fixture {
             Prepared::Exec(job) => Ok(*job),
             Prepared::Reply(AgentResponse::Error { code, message }) => Err((code, message)),
             Prepared::Reply(other) => panic!("unexpected reply {other:?}"),
-            Prepared::Http(_) => panic!("unexpected http job"),
-            Prepared::Db(_) => panic!("unexpected db job"),
+            Prepared::Http(_) | Prepared::Db(_) | Prepared::Connect(_) => panic!("unexpected job"),
             Prepared::Wait(_) => panic!("unexpected wait for approval"),
         }
     }
@@ -97,7 +95,19 @@ impl Fixture {
             Prepared::Db(job) => Ok(*job),
             Prepared::Reply(AgentResponse::Error { code, message }) => Err((code, message)),
             Prepared::Reply(other) => panic!("unexpected reply {other:?}"),
-            Prepared::Http(_) | Prepared::Exec(_) => panic!("unexpected job"),
+            Prepared::Http(_) | Prepared::Exec(_) | Prepared::Connect(_) => {
+                panic!("unexpected job")
+            }
+            Prepared::Wait(_) => panic!("unexpected wait for approval"),
+        }
+    }
+
+    pub fn connect(&mut self, call: ConnectCall) -> Result<ConnectJob, (AgentErrorCode, String)> {
+        match self.prepare(AgentRequest::DbConnect(call)) {
+            Prepared::Connect(job) => Ok(*job),
+            Prepared::Reply(AgentResponse::Error { code, message }) => Err((code, message)),
+            Prepared::Reply(other) => panic!("unexpected reply {other:?}"),
+            Prepared::Http(_) | Prepared::Exec(_) | Prepared::Db(_) => panic!("unexpected job"),
             Prepared::Wait(_) => panic!("unexpected wait for approval"),
         }
     }
@@ -113,7 +123,7 @@ impl Fixture {
         match self.daemon.prepare_in(session, request, now) {
             Prepared::Wait(waiting) => *waiting,
             Prepared::Reply(reply) => panic!("expected a wait, got {reply:?}"),
-            Prepared::Http(_) | Prepared::Exec(_) | Prepared::Db(_) => {
+            Prepared::Http(_) | Prepared::Exec(_) | Prepared::Db(_) | Prepared::Connect(_) => {
                 panic!("expected a wait, got a job")
             }
         }
@@ -297,3 +307,41 @@ pub fn query(handle: &str, query: &str) -> DbCall {
         timeout_secs: None,
     }
 }
+
+pub fn lease(handle: &str) -> ConnectCall {
+    ConnectCall {
+        handle: handle.into(),
+        ttl_secs: None,
+    }
+}
+
+/// A database server's URL from `var`, or `None` after a note when it is
+/// not set; with `KV_REQUIRE_DB_TESTS` set, as in CI, a missing URL fails.
+pub fn server(var: &str) -> Option<String> {
+    match std::env::var(var) {
+        Ok(url) if !url.is_empty() => Some(url),
+        _ => {
+            assert!(
+                std::env::var_os("KV_REQUIRE_DB_TESTS").is_none(),
+                "{var} is not set, and KV_REQUIRE_DB_TESTS says these tests must run"
+            );
+            eprintln!("skipped: {var} is not set");
+            None
+        }
+    }
+}
+
+/// A connection for setting up test data, and a schema of the test's own.
+pub async fn admin(url: &str, schema: &str) -> tokio_postgres::Client {
+    let (client, connection) = tokio_postgres::connect(url, tokio_postgres::NoTls)
+        .await
+        .unwrap();
+    tokio::spawn(connection);
+    client
+        .batch_execute(&format!(
+            "DROP SCHEMA IF EXISTS {schema} CASCADE; CREATE SCHEMA {schema};"
+        ))
+        .await
+        .unwrap();
+    client
+}
diff --git a/crates/kv/tests/db_live.rs b/crates/kv/tests/db_live.rs
index 3c367c2..77eeae8 100644
--- a/crates/kv/tests/db_live.rs
+++ b/crates/kv/tests/db_live.rs
@@ -8,34 +8,6 @@ use common::*;
 use kv::broker::db;
 use kv_core::policy::Mode;
 use kv_core::proto::{AgentErrorCode, AgentResponse, DbCall, RedisReply, RowsReply};
-use tokio_postgres::NoTls;
-
-fn server(var: &str) -> Option<String> {
-    match std::env::var(var) {
-        Ok(url) if !url.is_empty() => Some(url),
-        _ => {
-            assert!(
-                std::env::var_os("KV_REQUIRE_DB_TESTS").is_none(),
-                "{var} is not set, and KV_REQUIRE_DB_TESTS says these tests must run"
-            );
-            eprintln!("skipped: {var} is not set");
-            None
-        }
-    }
-}
-
-/// A connection for setting up test data, and a schema of the test's own.
-async fn admin(url: &str, schema: &str) -> tokio_postgres::Client {
-    let (client, connection) = tokio_postgres::connect(url, NoTls).await.unwrap();
-    tokio::spawn(connection);
-    client
-        .batch_execute(&format!(
-            "DROP SCHEMA IF EXISTS {schema} CASCADE; CREATE SCHEMA {schema};"
-        ))
-        .await
-        .unwrap();
-    client
-}
 
 async fn run(f: &mut Fixture, call: DbCall) -> AgentResponse {
     db::run(f.db(call).unwrap()).await
diff --git a/crates/kv/tests/lease.rs b/crates/kv/tests/lease.rs
new file mode 100644
index 0000000..be3c5fa
--- /dev/null
+++ b/crates/kv/tests/lease.rs
@@ -0,0 +1,176 @@
+//! `db_connect` as the daemon authorizes it, and the parts of a lease that
+//! need no database: the URL, logging in with the token, expiry, and ending
+//! when the vault locks or the handle changes. `db_live.rs` relays real
+//! traffic.
+
+mod common;
+
+use std::time::Duration;
+
+use common::*;
+use kv::broker::lease;
+use kv_core::policy::Mode;
+use kv_core::proto::{
+    AgentErrorCode, AgentRequest, AgentResponse, ConnectCall, ControlCommand, LeaseReply,
+};
+use tokio::io::{AsyncReadExt, AsyncWriteExt};
+use tokio::net::TcpStream;
+
+const PG_URL: &str = "postgres://app:pg-password-0123456789@db.internal.example:5432/app";
+const REDIS_URL: &str = "redis://:redis-password-0123456789@cache.internal.example:6380/2";
+
+async fn start(f: &mut Fixture, call: ConnectCall) -> LeaseReply {
+    match lease::start(f.connect(call).unwrap()).await {
+        AgentResponse::Lease(reply) => reply,
+        other => panic!("expected a lease, got {other:?}"),
+    }
+}
+
+fn port(url: &str) -> u16 {
+    url::Url::parse(url).unwrap().port().unwrap()
+}
+
+/// Waits for the lease's port to stop accepting, for at most 3 seconds.
+async fn closes(port: u16) -> bool {
+    for _ in 0..60 {
+        if TcpStream::connect(("127.0.0.1", port)).await.is_err() {
+            return true;
+        }
+        tokio::time::sleep(Duration::from_millis(50)).await;
+    }
+    false
+}
+
+#[test]
+fn only_database_handles_get_leases_for_a_bounded_time() {
+    let mut f = Fixture::new();
+    f.add(openrouter(Mode::Auto));
+    f.add(postgres("pg", PG_URL, false, Mode::Auto));
+    let (code, _) = f.connect(lease("openrouter")).unwrap_err();
+    assert_eq!(code, AgentErrorCode::PolicyDenied);
+    let (code, _) = f.connect(lease("missing")).unwrap_err();
+    assert_eq!(code, AgentErrorCode::UnknownHandle);
+    assert_eq!(
+        f.connect(lease("pg")).unwrap().ttl,
+        Duration::from_secs(900)
+    );
+    for ttl in [0, 3601] {
+        let (code, message) = f
+            .connect(ConnectCall {
+                ttl_secs: Some(ttl),
+                ..lease("pg")
+            })
+            .unwrap_err();
+        assert_eq!(code, AgentErrorCode::BadRequest);
+        assert!(message.contains("3600"), "{message}");
+    }
+}
+
+#[test]
+fn a_lease_in_ask_mode_waits_and_says_for_how_long() {
+    let mut f = Fixture::new();
+    f.add(postgres("pg", PG_URL, false, Mode::Ask));
+    let waiting = f.wait(
+        Some(&session("s1")),
+        AgentRequest::DbConnect(ConnectCall {
+            ttl_secs: Some(600),
+            ..lease("pg")
+        }),
+        f.t0,
+    );
+    let token = f.token();
+    let approvals = f.overview(&token).approvals;
+    assert_eq!(approvals[0].id, waiting.id);
+    assert_eq!(approvals[0].tool, "db_connect");
+    assert_eq!(approvals[0].detail, "a connection URL that works for 10m");
+}
+
+#[test]
+fn leases_end_when_the_vault_locks_or_their_handle_changes() {
+    let mut f = Fixture::new();
+    f.add(postgres("pg", PG_URL, false, Mode::Auto));
+    f.add(redis("cache", REDIS_URL, false, Mode::Auto));
+    let pg = f.connect(lease("pg")).unwrap();
+    let cache = f.connect(lease("cache")).unwrap();
+    f.control(ControlCommand::Remove { name: "pg".into() });
+    assert!(pg.ticket.has_ended());
+    assert!(!cache.ticket.has_ended());
+    f.control(ControlCommand::Lock);
+    assert!(cache.ticket.has_ended());
+}
+
+#[test]
+fn at_most_sixteen_leases_are_open_at_once() {
+    let mut f = Fixture::new();
+    f.add(postgres("pg", PG_URL, false, Mode::Auto));
+    let mut open: Vec<_> = (0..16).map(|_| f.connect(lease("pg")).unwrap()).collect();
+    let (code, message) = f.connect(lease("pg")).unwrap_err();
+    assert_eq!(code, AgentErrorCode::PolicyDenied);
+    assert!(message.contains("16 leases"), "{message}");
+    open.pop();
+    assert!(f.connect(lease("pg")).is_ok());
+}
+
+#[tokio::test]
+async fn a_lease_approved_after_the_vault_locked_does_not_start() {
+    let mut f = Fixture::new();
+    f.add(postgres("pg", PG_URL, false, Mode::Auto));
+    let job = f.connect(lease("pg")).unwrap();
+    f.control(ControlCommand::Lock);
+    match lease::start(job).await {
+        AgentResponse::Error { code, .. } => assert_eq!(code, AgentErrorCode::PolicyDenied),
+        other => panic!("expected an error, got {other:?}"),
+    }
+}
+
+#[tokio::test]
+async fn a_redis_lease_needs_the_token_before_any_command() {
+    let mut f = Fixture::new();
+    f.add(redis("cache", REDIS_URL, false, Mode::Auto));
+    let reply = start(&mut f, lease("cache")).await;
+    let url = url::Url::parse(&reply.url).unwrap();
+    assert_eq!((url.scheme(), url.path()), ("redis", "/2"));
+    let mut client = TcpStream::connect(("127.0.0.1", port(&reply.url)))
+        .await
+        .unwrap();
+    client
+        .write_all(b"*2\r\n$3\r\nGET\r\n$1\r\nk\r\n*2\r\n$4\r\nAUTH\r\n$5\r\nwrong\r\n")
+        .await
+        .unwrap();
+    let mut answer = String::new();
+    client.read_to_string(&mut answer).await.unwrap();
+    assert_eq!(
+        answer,
+        "-NOAUTH Authentication required.\r\n\
+         -WRONGPASS invalid username-password pair or user is disabled.\r\n"
+    );
+}
+
+#[tokio::test]
+async fn a_lease_stops_answering_when_it_expires_or_the_vault_locks() {
+    let mut f = Fixture::new();
+    f.add(redis("cache", REDIS_URL, false, Mode::Auto));
+    let short = start(
+        &mut f,
+        ConnectCall {
+            ttl_secs: Some(1),
+            ..lease("cache")
+        },
+    )
+    .await;
+    let long = start(&mut f, lease("cache")).await;
+    assert!(
+        TcpStream::connect(("127.0.0.1", port(&long.url)))
+            .await
+            .is_ok()
+    );
+    tokio::time::sleep(Duration::from_millis(1100)).await;
+    assert!(closes(port(&short.url)).await);
+    assert!(
+        TcpStream::connect(("127.0.0.1", port(&long.url)))
+            .await
+            .is_ok()
+    );
+    f.control(ControlCommand::Lock);
+    assert!(closes(port(&long.url)).await);
+}
diff --git a/crates/kv/tests/lease_live.rs b/crates/kv/tests/lease_live.rs
new file mode 100644
index 0000000..8c11f92
--- /dev/null
+++ b/crates/kv/tests/lease_live.rs
@@ -0,0 +1,146 @@
+//! `db_connect` leases relaying to real servers, with ordinary clients
+//! (`tokio-postgres`, `redis`) on the lease URL. Set `KV_TEST_POSTGRES_URL`
+//! (a superuser, Postgres 14 or later) and `KV_TEST_REDIS_URL` to run these;
+//! without them they pass after a note, unless `KV_REQUIRE_DB_TESTS` is set.
+
+mod common;
+
+use common::*;
+use kv::broker::lease;
+use kv_core::policy::Mode;
+use kv_core::proto::{AgentResponse, ConnectCall, LeaseReply};
+use tokio::io::{AsyncReadExt, AsyncWriteExt};
+use tokio::net::TcpStream;
+
+async fn start(f: &mut Fixture, call: ConnectCall) -> LeaseReply {
+    match lease::start(f.connect(call).unwrap()).await {
+        AgentResponse::Lease(reply) => reply,
+        other => panic!("expected a lease, got {other:?}"),
+    }
+}
+
+fn password(url: &str) -> String {
+    url::Url::parse(url).unwrap().password().unwrap().to_owned()
+}
+
+#[tokio::test]
+async fn a_redis_lease_relays_commands_with_secrets_scrubbed() {
+    let Some(url) = server("KV_TEST_REDIS_URL") else {
+        return;
+    };
+    let secret = "redis-lease-secret-0123456789";
+    let mut f = Fixture::new();
+    f.add(redis("cache", &url, false, Mode::Auto));
+    f.add(env_secret("other", &[("TOKEN", secret)], &[], Mode::Auto));
+    let reply = start(&mut f, lease("cache")).await;
+
+    let client = redis::Client::open(reply.url.as_str()).unwrap();
+    let mut db = client.get_multiplexed_async_connection().await.unwrap();
+    let () = redis::cmd("SET")
+        .arg("kv:lease")
+        .arg(format!("value {secret}"))
+        .query_async(&mut db)
+        .await
+        .unwrap();
+    let got: String = redis::cmd("GET")
+        .arg("kv:lease")
+        .query_async(&mut db)
+        .await
+        .unwrap();
+    assert_eq!(got, "value [kv:other]");
+    let error = redis::cmd("SUBSCRIBE")
+        .arg("news")
+        .query_async::<()>(&mut db)
+        .await
+        .unwrap_err();
+    assert!(
+        error
+            .to_string()
+            .contains("not available through db_connect"),
+        "{error}"
+    );
+
+    // RESP3, where the client logs in with HELLO.
+    let resp3 = redis::Client::open(format!("{}?protocol=resp3", reply.url)).unwrap();
+    let mut db = resp3.get_multiplexed_async_connection().await.unwrap();
+    let got: String = redis::cmd("GET")
+        .arg("kv:lease")
+        .query_async(&mut db)
+        .await
+        .unwrap();
+    assert_eq!(got, "value [kv:other]");
+}
+
+#[tokio::test]
+async fn a_read_only_redis_lease_answers_pipelined_commands_in_order() {
+    let Some(url) = server("KV_TEST_REDIS_URL") else {
+        return;
+    };
+    let mut f = Fixture::new();
+    f.add(redis("cache", &url, false, Mode::Auto));
+    f.add(redis("cache-ro", &url, true, Mode::Auto));
+    run_redis(&mut f, "cache", "SET kv:pipe abc").await;
+    let reply = start(&mut f, lease("cache-ro")).await;
+    let token = password(&reply.url);
+    let port = url::Url::parse(&reply.url).unwrap().port().unwrap();
+    let mut socket = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
+    let mut commands = format!("*2\r\n$4\r\nAUTH\r\n${}\r\n{token}\r\n", token.len()).into_bytes();
+    for command in [
+        &["GET", "kv:pipe"][..],
+        &["DEL", "kv:pipe"],
+        &["GET", "kv:pipe"],
+    ] {
+        commands.extend(format!("*{}\r\n", command.len()).bytes());
+        for arg in command {
+            commands.extend(format!("${}\r\n{arg}\r\n", arg.len()).bytes());
+        }
+    }
+    commands.extend(b"*1\r\n$4\r\nQUIT\r\n");
+    socket.write_all(&commands).await.unwrap();
+    let mut answers = String::new();
+    socket.read_to_string(&mut answers).await.unwrap();
+    assert_eq!(
+        answers,
+        "+OK\r\n$3\r\nabc\r\n\
+         -ERR kv: DEL is not a read command, and the handle is read-only\r\n\
+         $3\r\nabc\r\n+OK\r\n"
+    );
+}
+
+#[tokio::test]
+async fn a_redis_lease_logs_in_upstream_with_a_user_and_password() {
+    let Some(url) = server("KV_TEST_REDIS_URL") else {
+        return;
+    };
+    let mut f = Fixture::new();
+    f.add(redis("cache", &url, false, Mode::Auto));
+    run_redis(
+        &mut f,
+        "cache",
+        "ACL SETUSER kvlease on >kvlease-password-0123 ~kv:* +@all",
+    )
+    .await;
+    let mut with_user = url::Url::parse(&url).unwrap();
+    with_user.set_username("kvlease").unwrap();
+    with_user
+        .set_password(Some("kvlease-password-0123"))
+        .unwrap();
+    f.add(redis("cache-user", with_user.as_str(), false, Mode::Auto));
+    let reply = start(&mut f, lease("cache-user")).await;
+    let client = redis::Client::open(reply.url.as_str()).unwrap();
+    let mut db = client.get_multiplexed_async_connection().await.unwrap();
+    let who: String = redis::cmd("ACL")
+        .arg("WHOAMI")
+        .query_async(&mut db)
+        .await
+        .unwrap();
+    assert_eq!(who, "kvlease");
+}
+
+async fn run_redis(f: &mut Fixture, handle: &str, command: &str) {
+    let response = kv::broker::db::run(f.db(query(handle, command)).unwrap()).await;
+    assert!(
+        matches!(response, AgentResponse::Redis(_)),
+        "{command}: {response:?}"
+    );
+}
diff --git a/crates/kv/tests/mcp.rs b/crates/kv/tests/mcp.rs
index 01fec03..fa0e35d 100644
--- a/crates/kv/tests/mcp.rs
+++ b/crates/kv/tests/mcp.rs
@@ -454,3 +454,41 @@ async fn an_agent_queries_a_database_through_mcp() {
     assert!(!text.contains(password), "{text}");
     client.cancel().await.unwrap();
 }
+
+#[tokio::test]
+async fn an_agent_gets_a_database_lease_through_mcp() {
+    let home = Home::new();
+    home.kv(&["init", "--insecure-fast-kdf"], &format!("{PASS}\n"));
+    home.kv(
+        &["add", "cache", "--kind", "redis", "--mode", "auto"],
+        &format!("{PASS}\nredis://:cache-password-0123@127.0.0.1:1/0\n"),
+    );
+    let project = TempDir::new().unwrap();
+    let client = home.mcp(project.path()).await;
+    let (failed, text) = call(
+        &client,
+        "db_connect",
+        serde_json::json!({"handle": "cache", "ttl_secs": 60}),
+    )
+    .await;
+    assert!(!failed, "{text}");
+    let reply: serde_json::Value = serde_json::from_str(&text).unwrap();
+    assert_eq!(reply["expires_in_secs"], 60);
+    let url = url::Url::parse(reply["url"].as_str().unwrap()).unwrap();
+    assert_eq!(url.host_str(), Some("127.0.0.1"));
+    assert!(!text.contains("cache-password"), "{text}");
+
+    // The daemon holds the lease, so it answers after this call returns.
+    let mut socket = tokio::net::TcpStream::connect(("127.0.0.1", url.port().unwrap()))
+        .await
+        .unwrap();
+    tokio::io::AsyncWriteExt::write_all(&mut socket, b"*1\r\n$4\r\nPING\r\n")
+        .await
+        .unwrap();
+    let mut answer = [0u8; 6];
+    tokio::io::AsyncReadExt::read_exact(&mut socket, &mut answer)
+        .await
+        .unwrap();
+    assert_eq!(&answer, b"-NOAUT");
+    client.cancel().await.unwrap();
+}
diff --git a/crates/kv/tests/resp.rs b/crates/kv/tests/resp.rs
index 6c4be42..fee48dd 100644
--- a/crates/kv/tests/resp.rs
+++ b/crates/kv/tests/resp.rs
@@ -36,6 +36,67 @@ fn a_token_waits_for_all_its_bytes() {
     assert!(parse_token(b"?x\r\n").is_err());
 }
 
+#[test]
+fn frames_end_where_the_reply_ends() {
+    let mut frame = Frame::default();
+    let parsed = tokens(b"*2\r\n*2\r\n:1\r\n:2\r\n$1\r\nx\r\n");
+    let ends: Vec<bool> = parsed.iter().map(|t| frame.take(t)).collect();
+    assert_eq!(ends, [false, false, false, false, true]);
+    assert!(!frame.push);
+
+    let mut frame = Frame::default();
+    let parsed = tokens(b">2\r\n+invalidate\r\n*0\r\n");
+    let ends: Vec<bool> = parsed.iter().map(|t| frame.take(t)).collect();
+    assert_eq!(ends, [false, false, true]);
+    assert!(frame.push);
+}
+
+#[test]
+fn scrubbing_keeps_lengths_right_and_turns_matching_numbers_into_strings() {
+    let scrubber = Scrubber::new([("cache", "s3cret-value-123"), ("pin", "987654321")]);
+    let bulk = scrub_token(
+        Token::Bulk {
+            kind: b'$',
+            data: b"key=s3cret-value-123".to_vec(),
+        },
+        &scrubber,
+    );
+    let mut out = Vec::new();
+    encode(&bulk, &mut out);
+    assert_eq!(out, b"$14\r\nkey=[kv:cache]\r\n");
+    let number = scrub_token(
+        Token::Line {
+            kind: b':',
+            text: b"987654321".to_vec(),
+        },
+        &scrubber,
+    );
+    assert_eq!(
+        number,
+        Token::Bulk {
+            kind: b'$',
+            data: b"[kv:pin]".to_vec()
+        }
+    );
+}
+
+#[test]
+fn commands_must_be_arrays_of_strings() {
+    let (args, used) = parse_command(b"*2\r\n$3\r\nGET\r\n$1\r\nk\r\n*1")
+        .unwrap()
+        .unwrap();
+    assert_eq!(args, [b"GET".to_vec(), b"k".to_vec()]);
+    assert_eq!(used, 20);
+    assert_eq!(parse_command(b"*2\r\n$3\r\nGET\r\n").unwrap(), None);
+    assert!(parse_command(b"GET k\r\n").is_err());
+    assert!(parse_command(b"*1\r\n:1\r\n").is_err());
+    assert!(parse_command(b"*0\r\n").is_err());
+    assert_eq!(
+        encode_command(&[b"SET".to_vec(), b"a b".to_vec()]),
+        b"*2\r\n$3\r\nSET\r\n$3\r\na b\r\n"
+    );
+}
+
 #[test]
 fn redis_urls_must_name_a_server_and_a_numbered_database() {
     assert_eq!(
diff --git a/crates/kv/tests/state.rs b/crates/kv/tests/state.rs
index c23e243..2e1928c 100644
--- a/crates/kv/tests/state.rs
+++ b/crates/kv/tests/state.rs
@@ -83,9 +83,11 @@ impl Fixture {
     fn agent_at(&mut self, now: Instant, request: AgentRequest) -> AgentResponse {
         match self.daemon.prepare(request, now) {
             Prepared::Reply(response) => response,
-            Prepared::Http(_) | Prepared::Exec(_) | Prepared::Db(_) | Prepared::Wait(_) => {
-                panic!("expected a reply, got a job")
-            }
+            Prepared::Http(_)
+            | Prepared::Exec(_)
+            | Prepared::Db(_)
+            | Prepared::Connect(_)
+            | Prepared::Wait(_) => panic!("expected a reply, got a job"),
         }
     }
 
```

- [ ] **Step 2: Run the tests to watch them fail**

Run: `cargo test -p kv-core --test proto; cargo test -p kv --test lease --test resp`
Expected: FAIL: `unresolved imports kv_core::proto::ConnectCall, kv_core::proto::LeaseReply`, `unresolved import kv::broker::lease`, `no variant ... named Connect found for enum Prepared`, `cannot find function parse_command`.

- [ ] **Step 3: Implement**

Apply with `git apply` (Cargo.lock updates itself on the next build):

```diff
diff --git a/crates/kv-core/src/proto.rs b/crates/kv-core/src/proto.rs
index 7c56224..b851e96 100644
--- a/crates/kv-core/src/proto.rs
+++ b/crates/kv-core/src/proto.rs
@@ -35,6 +35,7 @@ pub enum AgentRequest {
     HttpRequest(HttpCall),
     Exec(ExecCall),
     DbQuery(DbCall),
+    DbConnect(ConnectCall),
     /// Asks the user to add a handle. Answered at once; the user finishes
     /// it in `kv tui`.
     RequestHandle(HandleRequest),
@@ -117,6 +118,16 @@ pub struct DbCall {
     pub timeout_secs: Option<u64>,
 }
 
+/// A loopback connection URL for a database handle, for tools that need a
+/// connection of their own.
+#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
+pub struct ConnectCall {
+    pub handle: String,
+    /// How long the URL works: 900 seconds by default, at most 3600.
+    #[serde(default)]
+    pub ttl_secs: Option<u64>,
+}
+
 #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
 #[serde(tag = "type", rename_all = "snake_case")]
 pub enum AgentResponse {
@@ -130,6 +141,7 @@ pub enum AgentResponse {
     Exec(ExecReply),
     Rows(RowsReply),
     Redis(RedisReply),
+    Lease(LeaseReply),
     /// The handle request is waiting for the user in `kv tui`.
     Requested {
         name: String,
@@ -189,6 +201,18 @@ pub struct RedisReply {
     pub truncated: bool,
 }
 
+/// A loopback URL with a lease token in place of the password. kv checks
+/// the token, connects with the real credentials and passes the traffic
+/// on, scrubbed. Connections close when the lease ends.
+#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
+pub struct LeaseReply {
+    pub url: String,
+    pub expires_in_secs: u64,
+    /// Such as a read-only handle whose role can write.
+    #[serde(default)]
+    pub warnings: Vec<String>,
+}
+
 #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
 pub struct Status {
     pub vault_exists: bool,
@@ -381,11 +405,12 @@ pub struct Approval {
     pub id: u64,
     /// Self-reported by the MCP client.
     pub client: Option<String>,
-    /// `http_request` or `exec`.
+    /// `http_request`, `exec`, `db_query` or `db_connect`.
     pub tool: String,
     /// The handles that need approval.
     pub handles: Vec<String>,
-    /// Method and URL, or the argv as a JSON array.
+    /// Method and URL, the argv as a JSON array, the query, or how long a
+    /// lease would last.
     pub detail: String,
     /// Working directory, for `exec`.
     pub cwd: Option<String>,
diff --git a/crates/kv/Cargo.toml b/crates/kv/Cargo.toml
index 0a8c1f3..1fb0d81 100644
--- a/crates/kv/Cargo.toml
+++ b/crates/kv/Cargo.toml
@@ -43,6 +43,7 @@ windows-sys = { version = "0.61", features = [
 
 [dev-dependencies]
 rcgen = "0.14"
+redis = { version = "1.7", default-features = false, features = ["tokio-comp"] }
 rmcp = { version = "3.5", default-features = false, features = ["client", "transport-child-process"] }
 tempfile = "3.27"
 tokio-rustls = "0.26"
diff --git a/crates/kv/src/broker.rs b/crates/kv/src/broker.rs
index c272a41..000c4c2 100644
--- a/crates/kv/src/broker.rs
+++ b/crates/kv/src/broker.rs
@@ -1,5 +1,6 @@
 //! Work an agent asked for, authorized by the daemon and run outside the
-//! daemon lock: HTTP requests, programs and database queries.
+//! daemon lock: HTTP requests, programs, database queries and database
+//! leases.
 
 use std::path::PathBuf;
 use std::sync::Arc;
@@ -16,11 +17,13 @@ use crate::audit::Audit;
 pub mod db;
 pub mod exec;
 pub mod http;
+pub mod lease;
 pub mod net;
 mod process;
 pub mod resp;
 
 pub use db::RoleChecks;
+pub use lease::{LeaseTicket, Leases};
 
 /// An `http_request` that passed every check.
 pub struct HttpJob {
@@ -68,6 +71,23 @@ pub struct DbJob {
     pub role_stamp: u64,
 }
 
+/// A `db_connect` that passed every check.
+pub struct ConnectJob {
+    pub secret: Secret,
+    pub ttl: Duration,
+    /// The lease's place among the open leases, taken when the request was
+    /// authorized, so a lock or a change to the handle ends it even before
+    /// it starts.
+    pub ticket: LeaseTicket,
+    /// The scrubber for every unlocked secret, kept current while the lease
+    /// is open.
+    pub scrubber: tokio::sync::watch::Receiver<Arc<Scrubber>>,
+    pub audit: Audit,
+    pub started: Instant,
+    /// `auto`, or `approved` after a decision in `kv tui`, for the audit log.
+    pub decision: &'static str,
+}
+
 /// Decodes scrubbed bytes, cutting them to `MAX_OUTPUT_LEN` (replacement
 /// markers can make scrubbed output longer than its input).
 pub(crate) fn capped_text(bytes: &[u8]) -> (String, bool) {
@@ -102,6 +122,15 @@ impl std::fmt::Debug for ExecJob {
     }
 }
 
+impl std::fmt::Debug for ConnectJob {
+    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
+        f.debug_struct("ConnectJob")
+            .field("handle", &self.secret.name)
+            .field("ttl", &self.ttl)
+            .finish_non_exhaustive()
+    }
+}
+
 impl std::fmt::Debug for DbJob {
     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
         f.debug_struct("DbJob")
diff --git a/crates/kv/src/broker/lease.rs b/crates/kv/src/broker/lease.rs
new file mode 100644
index 0000000..d2bfbe7
--- /dev/null
+++ b/crates/kv/src/broker/lease.rs
@@ -0,0 +1,313 @@
+//! `db_connect`: a loopback listener per lease that checks the lease token,
+//! connects to the database with the real credentials and passes traffic
+//! both ways, scrubbing what comes back and keeping read-only handles
+//! read-only. Connections close when the lease ends: at its expiry, when
+//! the vault locks, or when its handle changes.
+
+use std::net::Ipv4Addr;
+use std::sync::{Arc, Mutex, PoisonError};
+use std::time::{Duration, Instant};
+
+use kv_core::crypto::fill_random;
+use kv_core::proto::{AgentErrorCode, AgentResponse, LeaseReply};
+use kv_core::scrub::Scrubber;
+use kv_core::secret::SecretValue;
+use tokio::net::{TcpListener, TcpStream};
+use tokio::sync::{Semaphore, watch};
+
+use super::ConnectJob;
+use super::resp::RedisTarget;
+use crate::audit::{Audit, Use};
+
+mod redis;
+
+pub const DEFAULT_TTL: Duration = Duration::from_secs(900);
+pub const MAX_TTL: Duration = Duration::from_secs(3600);
+/// Leases open at once, counting those waiting for approval.
+pub const MAX_LEASES: usize = 16;
+/// Connections open at once on one lease.
+const MAX_CONNECTIONS: usize = 16;
+/// How long a client has to log in.
+const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);
+/// How long the server has to accept the login.
+const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(20);
+
+/// The leases that are open. The daemon ends them when the vault locks or
+/// a handle changes, and keeps their scrubber current as secrets change.
+#[derive(Clone)]
+pub struct Leases {
+    book: Arc<Mutex<Book>>,
+    scrubber: Arc<watch::Sender<Arc<Scrubber>>>,
+}
+
+#[derive(Default)]
+struct Book {
+    next: u64,
+    /// Dropping an entry's sender ends that lease.
+    live: Vec<(u64, String, watch::Sender<()>)>,
+}
+
+impl Default for Leases {
+    fn default() -> Self {
+        Self {
+            book: Arc::default(),
+            scrubber: Arc::new(watch::Sender::new(Arc::new(Scrubber::new([])))),
+        }
+    }
+}
+
+impl Leases {
+    fn book(&self) -> std::sync::MutexGuard<'_, Book> {
+        self.book.lock().unwrap_or_else(PoisonError::into_inner)
+    }
+
+    /// A place for a new lease on `handle`; `None` when `MAX_LEASES` are
+    /// open.
+    pub fn open(&self, handle: &str) -> Option<LeaseTicket> {
+        let mut book = self.book();
+        if book.live.len() >= MAX_LEASES {
+            return None;
+        }
+        book.next += 1;
+        let id = book.next;
+        let (sender, end) = watch::channel(());
+        book.live.push((id, handle.to_owned(), sender));
+        Some(LeaseTicket {
+            id,
+            leases: self.clone(),
+            end,
+        })
+    }
+
+    pub fn end_handle(&self, handle: &str) {
+        self.book().live.retain(|(_, h, _)| h != handle);
+    }
+
+    pub fn end_all(&self) {
+        self.book().live.clear();
+    }
+
+    pub fn count(&self) -> usize {
+        self.book().live.len()
+    }
+
+    /// The scrubber a new lease follows.
+    pub fn subscribe(&self) -> watch::Receiver<Arc<Scrubber>> {
+        self.scrubber.subscribe()
+    }
+
+    /// The scrubber open leases use from now on.
+    pub fn set_scrubber(&self, scrubber: Arc<Scrubber>) {
+        self.scrubber.send_replace(scrubber);
+    }
+}
+
+/// A lease's entry in the book; the lease ends when the entry goes, and
+/// the entry goes when this is dropped.
+pub struct LeaseTicket {
+    id: u64,
+    leases: Leases,
+    end: watch::Receiver<()>,
+}
+
+impl LeaseTicket {
+    pub fn has_ended(&self) -> bool {
+        self.end.has_changed().is_err()
+    }
+}
+
+impl Drop for LeaseTicket {
+    fn drop(&mut self) {
+        let id = self.id;
+        self.leases.book().live.retain(|(i, _, _)| *i != id);
+    }
+}
+
+/// Waits until the lease ends.
+async fn ended(mut end: watch::Receiver<()>) {
+    while end.changed().await.is_ok() {}
+}
+
+/// What every connection on a lease needs.
+struct Lease {
+    handle: String,
+    token: String,
+    target: Target,
+    read_only: bool,
+    scrubber: watch::Receiver<Arc<Scrubber>>,
+    audit: Audit,
+}
+
+impl Lease {
+    fn scrubber(&self) -> Arc<Scrubber> {
+        self.scrubber.borrow().clone()
+    }
+}
+
+enum Target {
+    Redis(RedisTarget),
+}
+
+/// Opens the lease and returns its URL, recording it in the audit log.
+pub async fn start(job: ConnectJob) -> AgentResponse {
+    let ticket = job.ticket;
+    let ttl = job.ttl;
+    let opened = open(&job.secret, ttl, job.scrubber.clone(), &job.audit, ticket);
+    let response = match opened.await {
+        Ok(reply) => AgentResponse::Lease(reply),
+        Err(response) => response,
+    };
+    let outcome = match &response {
+        AgentResponse::Error { code, .. } => code.as_str(),
+        _ => "ok",
+    };
+    job.audit.record_use(&Use {
+        action: "db_connect",
+        handle: &job.secret.name,
+        decision: job.decision,
+        summary: &format!("lease for {}s", ttl.as_secs()),
+        outcome,
+        duration: job.started.elapsed(),
+    });
+    response
+}
+
+async fn open(
+    secret: &kv_core::secret::Secret,
+    ttl: Duration,
+    scrubber_rx: watch::Receiver<Arc<Scrubber>>,
+    audit: &Audit,
+    ticket: LeaseTicket,
+) -> Result<LeaseReply, AgentResponse> {
+    if ticket.has_ended() {
+        return Err(error(
+            AgentErrorCode::PolicyDenied,
+            "the vault locked or the handle changed before the lease started; ask again",
+        ));
+    }
+    let bad = |message: String| error(AgentErrorCode::BadRequest, message);
+    let read_only = secret.policy.read_only;
+    let target = match &secret.value {
+        SecretValue::Redis { url } => Target::Redis(RedisTarget::parse(url.expose()).map_err(bad)?),
+        SecretValue::Postgres { .. } => {
+            return Err(bad("db_connect does not take postgres handles yet".into()));
+        }
+        _ => return Err(bad("not a database handle".into())),
+    };
+    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
+        .await
+        .map_err(|e| {
+            error(
+                AgentErrorCode::UpstreamError,
+                format!("could not listen: {e}"),
+            )
+        })?;
+    let port = listener
+        .local_addr()
+        .map_err(|e| {
+            error(
+                AgentErrorCode::UpstreamError,
+                format!("could not listen: {e}"),
+            )
+        })?
+        .port();
+    let mut bytes = [0u8; 32];
+    fill_random(&mut bytes);
+    let token = hex(&bytes);
+    let url = match &target {
+        Target::Redis(target) => format!("redis://kv:{token}@127.0.0.1:{port}/{}", target.db),
+    };
+    let lease = Arc::new(Lease {
+        handle: secret.name.clone(),
+        token,
+        target,
+        read_only,
+        scrubber: scrubber_rx,
+        audit: audit.clone(),
+    });
+    let expires = tokio::time::Instant::now() + ttl;
+    tokio::spawn(serve(listener, lease, ticket, expires));
+    Ok(LeaseReply {
+        url,
+        expires_in_secs: ttl.as_secs(),
+        warnings: Vec::new(),
+    })
+}
+
+/// Accepts connections until the lease ends, then closes the listener and,
+/// by dropping the ticket, every connection.
+async fn serve(
+    listener: TcpListener,
+    lease: Arc<Lease>,
+    ticket: LeaseTicket,
+    expires: tokio::time::Instant,
+) {
+    let connections = Arc::new(Semaphore::new(MAX_CONNECTIONS));
+    let expiry = tokio::time::sleep_until(expires);
+    tokio::pin!(expiry);
+    loop {
+        tokio::select! {
+            _ = &mut expiry => break,
+            _ = ended(ticket.end.clone()) => break,
+            accepted = listener.accept() => {
+                let Ok((stream, _)) = accepted else { continue };
+                let Ok(permit) = connections.clone().try_acquire_owned() else {
+                    record(&lease, "too_many_connections", Instant::now());
+                    continue;
+                };
+                let lease = lease.clone();
+                let end = ticket.end.clone();
+                tokio::spawn(async move {
+                    let _permit = permit;
+                    connection(stream, lease, end).await;
+                });
+            }
+        }
+    }
+    drop(ticket);
+}
+
+/// Serves one client. The relays watch for the lease's end themselves, so
+/// a Postgres client is told why; a client still logging in when the lease
+/// ends finds the relay closed the moment it starts.
+async fn connection(stream: TcpStream, lease: Arc<Lease>, end: watch::Receiver<()>) {
+    let started = Instant::now();
+    let _ = stream.set_nodelay(true);
+    let outcome = match &lease.target {
+        Target::Redis(target) => redis::serve(stream, &lease, target, end).await,
+    };
+    record(&lease, outcome, started);
+}
+
+fn record(lease: &Lease, outcome: &str, started: Instant) {
+    lease.audit.record_use(&Use {
+        action: "db_connect",
+        handle: &lease.handle,
+        decision: "lease",
+        summary: "connection",
+        outcome,
+        duration: started.elapsed(),
+    });
+}
+
+/// Compares without stopping at the first difference, so timing reveals
+/// nothing about the token.
+fn token_matches(given: &[u8], token: &str) -> bool {
+    given.len() == token.len()
+        && given
+            .iter()
+            .zip(token.bytes())
+            .fold(0u8, |diff, (x, y)| diff | (x ^ y))
+            == 0
+}
+
+fn hex(bytes: &[u8]) -> String {
+    bytes.iter().map(|b| format!("{b:02x}")).collect()
+}
+
+fn error(code: AgentErrorCode, message: impl Into<String>) -> AgentResponse {
+    AgentResponse::Error {
+        code,
+        message: message.into(),
+    }
+}
diff --git a/crates/kv/src/broker/lease/redis.rs b/crates/kv/src/broker/lease/redis.rs
new file mode 100644
index 0000000..2d1338f
--- /dev/null
+++ b/crates/kv/src/broker/lease/redis.rs
@@ -0,0 +1,325 @@
+//! One client on a Redis lease: kv answers until the client logs in with
+//! the lease token (`AUTH` or `HELLO ... AUTH`), logs in to the real
+//! server, then relays commands and replies in order.
+
+use kv_core::db::{RedisRefusal, check_redis};
+use tokio::io::{AsyncWriteExt, BufWriter, ReadHalf, WriteHalf};
+use tokio::net::TcpStream;
+use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
+use tokio::sync::{mpsc, watch};
+
+use super::{HANDSHAKE_TIMEOUT, Lease, UPSTREAM_TIMEOUT, token_matches};
+use crate::broker::net::{Buffered, Upstream};
+use crate::broker::resp::{
+    self, Frame, RedisTarget, Token, encode, encode_command, next_command, next_token, scrub_token,
+};
+
+type ClientRead = Buffered<OwnedReadHalf>;
+type ClientWrite = BufWriter<OwnedWriteHalf>;
+
+/// What the next answer to the client is, in the order commands came.
+enum Slot {
+    /// The server's reply to a command kv passed on.
+    Reply,
+    /// kv's own reply, for a command it refused.
+    Local(Vec<u8>),
+    /// `+OK`, then the connection closes.
+    Quit,
+}
+
+pub(super) async fn serve(
+    stream: TcpStream,
+    lease: &Lease,
+    target: &RedisTarget,
+    end: watch::Receiver<()>,
+) -> &'static str {
+    let (read, write) = stream.into_split();
+    let mut client = Buffered::new(read);
+    let mut write = BufWriter::new(write);
+    let hello =
+        match tokio::time::timeout(HANDSHAKE_TIMEOUT, log_in(&mut client, &mut write, lease)).await
+        {
+            Ok(Ok(hello)) => hello,
+            Ok(Err(outcome)) => return outcome,
+            Err(_) => return "timed_out",
+        };
+    let upstream = match tokio::time::timeout(UPSTREAM_TIMEOUT, resp::connect(target)).await {
+        Ok(Ok(upstream)) => upstream,
+        Ok(Err(e)) => {
+            let message = lease.scrubber().scrub(e.to_string().as_bytes());
+            let message = String::from_utf8_lossy(&message).replace(['\r', '\n'], " ");
+            send(&mut write, format!("-ERR kv: {message}\r\n").as_bytes()).await;
+            return "upstream_error";
+        }
+        Err(_) => {
+            send(
+                &mut write,
+                b"-ERR kv: the database did not answer in time\r\n",
+            )
+            .await;
+            return "upstream_error";
+        }
+    };
+    let (data, leftover) = upstream.into_parts();
+    let (up_read, mut up_write) = tokio::io::split(data);
+    let mut up_read = Buffered::with_data(up_read, leftover);
+
+    let (slots, queue) = mpsc::channel(1024);
+    // The login's answer comes first: kv's own for AUTH, the server's for
+    // HELLO, which kv passes on without the token.
+    match hello {
+        Some(hello) => {
+            if up_write.write_all(&encode_command(&hello)).await.is_err() {
+                return "closed";
+            }
+            let _ = slots.send(Slot::Reply).await;
+        }
+        None => {
+            let _ = slots.send(Slot::Local(b"+OK\r\n".to_vec())).await;
+        }
+    }
+    tokio::select! {
+        outcome = client_to_server(&mut client, &mut up_write, lease.read_only, slots) => outcome,
+        outcome = server_to_client(&mut up_read, &mut write, lease, queue, end) => outcome,
+    }
+}
+
+/// Answers until the client logs in with the token. Returns the `HELLO` to
+/// send the server, without its `AUTH`, if the client logged in that way.
+async fn log_in(
+    client: &mut ClientRead,
+    write: &mut ClientWrite,
+    lease: &Lease,
+) -> Result<Option<Vec<Vec<u8>>>, &'static str> {
+    const WRONG: &[u8] = b"-WRONGPASS invalid username-password pair or user is disabled.\r\n";
+    loop {
+        let args = match next_command(client).await {
+            Ok(Some(args)) => args,
+            Ok(None) | Err(_) => return Err("closed"),
+        };
+        let word = |i: usize| {
+            args.get(i)
+                .map(|a| String::from_utf8_lossy(a).to_ascii_uppercase())
+                .unwrap_or_default()
+        };
+        match word(0).as_str() {
+            "AUTH" if (2..=3).contains(&args.len()) => {
+                if token_matches(&args[args.len() - 1], &lease.token) {
+                    return Ok(None);
+                }
+                send(write, WRONG).await;
+                return Err("wrong_token");
+            }
+            "HELLO" => {
+                let auth = (2..args.len()).find(|&i| word(i) == "AUTH");
+                let Some(at) = auth.filter(|&at| at + 2 < args.len()) else {
+                    send(
+                        write,
+                        b"-NOAUTH HELLO must be called with the client already authenticated, \
+                          otherwise the HELLO <proto> AUTH <user> <pass> option can be used\r\n",
+                    )
+                    .await;
+                    continue;
+                };
+                if !token_matches(&args[at + 2], &lease.token) {
+                    send(write, WRONG).await;
+                    return Err("wrong_token");
+                }
+                let mut hello = args.clone();
+                hello.drain(at..at + 3);
+                return Ok(Some(hello));
+            }
+            "QUIT" => {
+                send(write, b"+OK\r\n").await;
+                return Err("closed");
+            }
+            _ => send(write, b"-NOAUTH Authentication required.\r\n").await,
+        }
+    }
+}
+
+/// Why kv answers a command itself instead of passing it on.
+enum Refusal {
+    Quit,
+    Error(String),
+}
+
+/// Commands that log in again, change how replies flow (subscriptions,
+/// `MONITOR`, `CLIENT REPLY`) or replicate are refused on every lease; on a
+/// read-only handle only reads pass.
+fn refusal(args: &[Vec<u8>], read_only: bool) -> Option<Refusal> {
+    let word = |i: usize| {
+        args.get(i)
+            .map(|a| String::from_utf8_lossy(a).to_ascii_uppercase())
+            .unwrap_or_default()
+    };
+    let command = word(0);
+    let unavailable = || {
+        Some(Refusal::Error(format!(
+            "{command} is not available through db_connect"
+        )))
+    };
+    match command.as_str() {
+        "QUIT" => return Some(Refusal::Quit),
+        "HELLO" if args.len() <= 2 => return None,
+        "AUTH" | "HELLO" | "RESET" | "MONITOR" | "SYNC" | "PSYNC" | "REPLCONF" | "SUBSCRIBE"
+        | "PSUBSCRIBE" | "SSUBSCRIBE" | "UNSUBSCRIBE" | "PUNSUBSCRIBE" | "SUNSUBSCRIBE" => {
+            return unavailable();
+        }
+        "CLIENT" if word(1) == "REPLY" => return unavailable(),
+        _ => {}
+    }
+    if read_only && let Err(refusal @ RedisRefusal::NotRead(_)) = check_redis(args, true) {
+        return Some(Refusal::Error(refusal.to_string()));
+    }
+    None
+}
+
+async fn client_to_server(
+    client: &mut ClientRead,
+    upstream: &mut WriteHalf<Upstream>,
+    read_only: bool,
+    slots: mpsc::Sender<Slot>,
+) -> &'static str {
+    loop {
+        let args = match next_command(client).await {
+            Ok(Some(args)) => args,
+            Ok(None) | Err(_) => return "closed",
+        };
+        let slot = match refusal(&args, read_only) {
+            Some(Refusal::Quit) => Slot::Quit,
+            Some(Refusal::Error(message)) => Slot::Local(format!("-ERR kv: {message}\r\n").into()),
+            None => {
+                if upstream.write_all(&encode_command(&args)).await.is_err() {
+                    return "closed";
+                }
+                Slot::Reply
+            }
+        };
+        let quit = matches!(slot, Slot::Quit);
+        if slots.send(slot).await.is_err() {
+            return "closed";
+        }
+        if quit {
+            return std::future::pending().await;
+        }
+    }
+}
+
+/// Writes the answers in the order of the commands, and passes on push
+/// messages (RESP3) whenever they come.
+async fn server_to_client(
+    upstream: &mut Buffered<ReadHalf<Upstream>>,
+    client: &mut ClientWrite,
+    lease: &Lease,
+    mut queue: mpsc::Receiver<Slot>,
+    end: watch::Receiver<()>,
+) -> &'static str {
+    loop {
+        let first = tokio::select! {
+            biased;
+            _ = super::ended(end.clone()) => return "lease_ended",
+            slot = queue.recv() => {
+                match answer(slot, None, upstream, client, lease).await {
+                    Ok(()) => continue,
+                    Err(outcome) => return outcome,
+                }
+            }
+            token = next_token(upstream) => match token {
+                Ok(Some(token)) => token,
+                Ok(None) => return "closed",
+                Err(_) => return "upstream_error",
+            },
+        };
+        // A token arrived before its slot: a push, or the reply to a command
+        // whose slot is on its way.
+        if matches!(first, Token::Aggregate { kind: b'>', .. }) {
+            if let Err(outcome) = forward(Some(first), upstream, client, lease).await {
+                return outcome;
+            }
+            continue;
+        }
+        let mut first = Some(first);
+        loop {
+            let slot = queue.recv().await;
+            let reply = matches!(slot, Some(Slot::Reply));
+            if let Err(outcome) =
+                answer(slot, first.take_if(|_| reply), upstream, client, lease).await
+            {
+                return outcome;
+            }
+            if reply {
+                break;
+            }
+        }
+    }
+}
+
+/// Writes one slot's answer; a reply may already have its first token.
+async fn answer(
+    slot: Option<Slot>,
+    first: Option<Token>,
+    upstream: &mut Buffered<ReadHalf<Upstream>>,
+    client: &mut ClientWrite,
+    lease: &Lease,
+) -> Result<(), &'static str> {
+    match slot {
+        None => Err("closed"),
+        Some(Slot::Local(bytes)) => write(client, &bytes).await,
+        Some(Slot::Quit) => {
+            let _ = write(client, b"+OK\r\n").await;
+            Err("closed")
+        }
+        // Push messages may come before the reply itself.
+        Some(Slot::Reply) => {
+            let mut first = first;
+            while forward(first.take(), upstream, client, lease).await? {}
+            Ok(())
+        }
+    }
+}
+
+/// Passes on one reply, scrubbed, token by token; `true` if it was a push
+/// message, so the reply is still to come.
+async fn forward(
+    first: Option<Token>,
+    upstream: &mut Buffered<ReadHalf<Upstream>>,
+    client: &mut ClientWrite,
+    lease: &Lease,
+) -> Result<bool, &'static str> {
+    let scrubber = lease.scrubber();
+    let mut frame = Frame::default();
+    let mut next = first;
+    let mut out = Vec::new();
+    loop {
+        let token = match next.take() {
+            Some(token) => token,
+            None => match next_token(upstream).await {
+                Ok(Some(token)) => token,
+                Ok(None) => return Err("closed"),
+                Err(_) => return Err("upstream_error"),
+            },
+        };
+        let done = frame.take(&token);
+        encode(&scrub_token(token, &scrubber), &mut out);
+        if out.len() >= 64 * 1024 || done {
+            if client.write_all(&out).await.is_err() {
+                return Err("closed");
+            }
+            out.clear();
+        }
+        if done {
+            client.flush().await.map_err(|_| "closed")?;
+            return Ok(frame.push);
+        }
+    }
+}
+
+async fn write(client: &mut ClientWrite, bytes: &[u8]) -> Result<(), &'static str> {
+    client.write_all(bytes).await.map_err(|_| "closed")?;
+    client.flush().await.map_err(|_| "closed")
+}
+
+async fn send(client: &mut ClientWrite, bytes: &[u8]) {
+    let _ = write(client, bytes).await;
+}
diff --git a/crates/kv/src/broker/net.rs b/crates/kv/src/broker/net.rs
index 33f7df8..0137ab5 100644
--- a/crates/kv/src/broker/net.rs
+++ b/crates/kv/src/broker/net.rs
@@ -80,6 +80,21 @@ impl<R: AsyncRead + Unpin> Buffered<R> {
         }
     }
 
+    /// Like `new`, with bytes already read from the stream.
+    pub fn with_data(inner: R, data: Vec<u8>) -> Self {
+        Self {
+            inner,
+            buf: data,
+            start: 0,
+        }
+    }
+
+    /// The stream, and what was read from it but not consumed.
+    pub fn into_parts(self) -> (R, Vec<u8>) {
+        let rest = self.buf[self.start..].to_vec();
+        (self.inner, rest)
+    }
+
     /// The bytes read but not yet consumed.
     pub fn data(&self) -> &[u8] {
         &self.buf[self.start..]
diff --git a/crates/kv/src/broker/resp.rs b/crates/kv/src/broker/resp.rs
index f16599d..587229e 100644
--- a/crates/kv/src/broker/resp.rs
+++ b/crates/kv/src/broker/resp.rs
@@ -209,6 +209,72 @@ pub fn encode(token: &Token, out: &mut Vec<u8>) {
     }
 }
 
+/// Replaces secrets in a token. A number that matches one becomes a string,
+/// since the replacement is not a number.
+pub fn scrub_token(token: Token, scrubber: &Scrubber) -> Token {
+    match token {
+        Token::Line {
+            kind: kind @ (b'+' | b'-'),
+            text,
+        } => Token::Line {
+            kind,
+            text: scrubber.scrub(&text),
+        },
+        Token::Line {
+            kind: kind @ (b':' | b',' | b'('),
+            text,
+        } => {
+            let scrubbed = scrubber.scrub(&text);
+            if scrubbed == text {
+                Token::Line { kind, text }
+            } else {
+                Token::Bulk {
+                    kind: b'$',
+                    data: scrubbed,
+                }
+            }
+        }
+        Token::Bulk { kind, data } => Token::Bulk {
+            kind,
+            data: scrubber.scrub(&data),
+        },
+        other => other,
+    }
+}
+
+/// Follows a reply's tokens to find where it ends.
+#[derive(Default)]
+pub struct Frame {
+    open: Vec<usize>,
+    started: bool,
+    /// The reply is a RESP3 push message, which answers no command.
+    pub push: bool,
+}
+
+impl Frame {
+    /// Takes the next token; `true` when it completes the reply.
+    pub fn take(&mut self, token: &Token) -> bool {
+        if !self.started {
+            self.started = true;
+            self.push = matches!(token, Token::Aggregate { kind: b'>', .. });
+        }
+        if let Token::Aggregate { len, .. } = token
+            && *len > 0
+        {
+            self.open.push(*len);
+            return false;
+        }
+        while let Some(left) = self.open.last_mut() {
+            *left -= 1;
+            if *left > 0 {
+                return false;
+            }
+            self.open.pop();
+        }
+        true
+    }
+}
+
 pub async fn next_token<R: AsyncRead + Unpin>(conn: &mut Buffered<R>) -> io::Result<Option<Token>> {
     loop {
         if let Some((token, used)) = parse_token(conn.data()).map_err(io::Error::other)? {
@@ -224,6 +290,59 @@ pub async fn next_token<R: AsyncRead + Unpin>(conn: &mut Buffered<R>) -> io::Res
     }
 }
 
+/// Reads one command as clients send it: an array of strings. `None` at
+/// the end of the stream.
+pub async fn next_command<R: AsyncRead + Unpin>(
+    conn: &mut Buffered<R>,
+) -> io::Result<Option<Command>> {
+    loop {
+        if let Some((args, used)) = parse_command(conn.data()).map_err(io::Error::other)? {
+            conn.consume(used);
+            return Ok(Some(args));
+        }
+        if conn.data().len() > 2 * MAX_WIRE_MESSAGE {
+            return Err(io::Error::other("a command is larger than kv accepts"));
+        }
+        if !conn.fill().await? {
+            return match conn.data().is_empty() {
+                true => Ok(None),
+                false => Err(io::ErrorKind::UnexpectedEof.into()),
+            };
+        }
+    }
+}
+
+/// A command's arguments, the command name first.
+pub type Command = Vec<Vec<u8>>;
+
+/// A command from the front of `data`, with the bytes it took.
+pub fn parse_command(data: &[u8]) -> Result<Option<(Command, usize)>, String> {
+    let Some((header, mut used)) = parse_token(data)? else {
+        return Ok(None);
+    };
+    let Token::Aggregate { kind: b'*', len } = header else {
+        return Err(
+            "kv takes commands as arrays of strings, as redis-cli and client libraries send them"
+                .into(),
+        );
+    };
+    if len == 0 {
+        return Err("the command is empty".into());
+    }
+    let mut args = Vec::new();
+    for _ in 0..len {
+        match parse_token(&data[used..])? {
+            None => return Ok(None),
+            Some((Token::Bulk { kind: b'$', data }, n)) => {
+                args.push(data);
+                used += n;
+            }
+            Some(_) => return Err("command arguments must be strings".into()),
+        }
+    }
+    Ok(Some((args, used)))
+}
+
 pub fn encode_command(args: &[Vec<u8>]) -> Vec<u8> {
     let mut out = format!("*{}\r\n", args.len()).into_bytes();
     for arg in args {
diff --git a/crates/kv/src/daemon/server.rs b/crates/kv/src/daemon/server.rs
index 42efaaf..0248b43 100644
--- a/crates/kv/src/daemon/server.rs
+++ b/crates/kv/src/daemon/server.rs
@@ -167,6 +167,7 @@ async fn run_job(prepared: Prepared, http: &reqwest::Client) -> AgentResponse {
         Prepared::Http(job) => broker::http::send(http, *job).await,
         Prepared::Exec(job) => broker::exec::run(*job).await,
         Prepared::Db(job) => broker::db::run(*job).await,
+        Prepared::Connect(job) => broker::lease::start(*job).await,
         // `Waiting::then` is always a job; it never waits twice.
         Prepared::Wait(_) => AgentResponse::Error {
             code: AgentErrorCode::UpstreamError,
diff --git a/crates/kv/src/daemon/state.rs b/crates/kv/src/daemon/state.rs
index 59e23a9..e6596d7 100644
--- a/crates/kv/src/daemon/state.rs
+++ b/crates/kv/src/daemon/state.rs
@@ -14,9 +14,9 @@ use kv_core::policy::{
     Decision, DenyReason, Mode, Operation, evaluate, http_target, is_host_entry,
 };
 use kv_core::proto::{
-    AgentErrorCode, AgentRequest, AgentResponse, Approval, ControlCommand, ControlErrorCode,
-    ControlRequest, ControlResponse, DbCall, ExecCall, HandleRequest, HttpCall, Overview,
-    PolicyPatch, RequestedHandle, SessionInfo, Status, Verdict,
+    AgentErrorCode, AgentRequest, AgentResponse, Approval, ConnectCall, ControlCommand,
+    ControlErrorCode, ControlRequest, ControlResponse, DbCall, ExecCall, HandleRequest, HttpCall,
+    Overview, PolicyPatch, RequestedHandle, SessionInfo, Status, Verdict,
 };
 use kv_core::scrub::{MIN_SECRET_LEN, Scrubber};
 use kv_core::secret::{
@@ -27,7 +27,8 @@ use tokio::sync::oneshot;
 use zeroize::Zeroizing;
 
 use crate::audit::{Audit, Use};
-use crate::broker::{DbJob, ExecJob, HttpJob, RoleChecks};
+use crate::broker::lease::{DEFAULT_TTL, MAX_LEASES, MAX_TTL};
+use crate::broker::{ConnectJob, DbJob, ExecJob, HttpJob, Leases, RoleChecks};
 use crate::throttle::Throttle;
 
 const DEFAULT_EXEC_TIMEOUT: Duration = Duration::from_secs(60);
@@ -144,6 +145,9 @@ pub struct Daemon {
     /// Read-only Postgres handles whose role has been checked since the
     /// vault was unlocked. Forgotten when the handle changes.
     role_checks: RoleChecks,
+    /// Open `db_connect` leases. All end when the vault locks; a handle's
+    /// end when it changes.
+    leases: Leases,
 }
 
 /// A request waiting for approval, as the daemon keeps it.
@@ -201,6 +205,7 @@ pub enum Prepared {
     Http(Box<HttpJob>),
     Exec(Box<ExecJob>),
     Db(Box<DbJob>),
+    Connect(Box<ConnectJob>),
     Wait(Box<Waiting>),
 }
 
@@ -239,6 +244,7 @@ impl Daemon {
             next_request: 0,
             request_notice: None,
             role_checks: RoleChecks::default(),
+            leases: Leases::default(),
             ended: BTreeMap::new(),
             grants: Vec::new(),
         }
@@ -286,6 +292,7 @@ impl Daemon {
             AgentRequest::HttpRequest(call) => self.prepare_http(call, session, now),
             AgentRequest::Exec(call) => self.prepare_exec(call, session, now),
             AgentRequest::DbQuery(call) => self.prepare_db(call, session, now),
+            AgentRequest::DbConnect(call) => self.prepare_connect(call, session, now),
             AgentRequest::RequestHandle(request) => {
                 let name = printable(&request.name, 63);
                 let response = self.request_handle(session, request);
@@ -728,6 +735,88 @@ impl Daemon {
         self.queue(ask, job, session, now)
     }
 
+    fn prepare_connect(
+        &mut self,
+        call: ConnectCall,
+        session: Option<&SessionInfo>,
+        now: Instant,
+    ) -> Prepared {
+        let ttl = call.ttl_secs.map_or(DEFAULT_TTL, Duration::from_secs);
+        let summary = format!("lease for {}s", ttl.as_secs());
+        let refuse = |daemon: &Self, decision, response| {
+            daemon.refuse("db_connect", &call.handle, &summary, decision, response)
+        };
+        let Some(vault) = &self.vault else {
+            return refuse(self, "locked", self.locked_error());
+        };
+        let Some(secret) = vault.get(&call.handle).cloned() else {
+            return refuse(self, "invalid", unknown_handle(vault, &call.handle));
+        };
+        if ttl.is_zero() || ttl > MAX_TTL {
+            let message = "ttl_secs must be between 1 and 3600";
+            return refuse(
+                self,
+                "invalid",
+                agent_error(AgentErrorCode::BadRequest, message),
+            );
+        }
+        let decision = evaluate(&secret, &Operation::DbConnect);
+        if let Decision::Deny(reason) = decision {
+            return refuse(
+                self,
+                "policy",
+                agent_error(AgentErrorCode::PolicyDenied, reason),
+            );
+        }
+        let ask = decision == Decision::Ask && !self.granted(session, &call.handle, now);
+        if ask && self.approvals.len() >= MAX_PENDING {
+            return refuse(self, "denied", too_many_waiting());
+        }
+        let Some(ticket) = self.leases.open(&call.handle) else {
+            let message = format!(
+                "{MAX_LEASES} leases are open already; let one expire, or ask the user to lock \
+                 the vault"
+            );
+            return refuse(
+                self,
+                "denied",
+                agent_error(AgentErrorCode::PolicyDenied, message),
+            );
+        };
+        self.touch(now);
+        let scrubber = self.scrubber();
+        self.leases.set_scrubber(scrubber);
+        let handle = call.handle.clone();
+        let job = Prepared::Connect(Box::new(ConnectJob {
+            secret,
+            ttl,
+            ticket,
+            scrubber: self.leases.subscribe(),
+            audit: self.audit.clone(),
+            started: now,
+            decision: if decision == Decision::Ask {
+                "approved"
+            } else {
+                "auto"
+            },
+        }));
+        if !ask {
+            return job;
+        }
+        let ask = Ask {
+            tool: "db_connect",
+            ask: vec![handle.clone()],
+            handles: handle,
+            summary,
+            detail: format!(
+                "a connection URL that works for {}",
+                humantime::format_duration(ttl)
+            ),
+            cwd: None,
+        };
+        self.queue(ask, job, session, now)
+    }
+
     fn granted(&self, session: Option<&SessionInfo>, handle: &str, now: Instant) -> bool {
         session.is_some_and(|session| {
             self.grants
@@ -778,11 +867,13 @@ impl Daemon {
     }
 
     /// Drops what was decided about a handle that was added, changed or
-    /// removed: its grants, its role check, and the requests waiting on it,
-    /// which hold its old value and policy and so may not run.
+    /// removed: its grants, its role check, its leases, and the requests
+    /// waiting on it, which hold its old value and policy and so may not
+    /// run.
     fn handle_changed(&mut self, name: &str, now: Instant) {
         self.grants.retain(|g| g.handle != name);
         self.role_checks.forget(name);
+        self.leases.end_handle(name);
         let (stale, kept) = std::mem::take(&mut self.approvals)
             .into_iter()
             .partition(|p: &Pending| p.handles.split(',').any(|h| h == name));
@@ -1030,6 +1121,11 @@ impl Daemon {
                         if let Some(name) = &handle {
                             self.handle_changed(name, now);
                         }
+                        // Open leases scrub with the secrets as they are now.
+                        if self.leases.count() > 0 {
+                            let scrubber = self.scrubber();
+                            self.leases.set_scrubber(scrubber);
+                        }
                         done(warnings)
                     })
             }
@@ -1063,13 +1159,15 @@ impl Daemon {
     }
 
     /// Forgets the vault key, the scrubber, every session and every grant,
-    /// and answers every waiting request with `vault_locked`.
+    /// ends every lease, and answers every waiting request with
+    /// `vault_locked`.
     fn lock_vault(&mut self) {
         self.vault = None;
         self.scrubber = None;
         self.sessions.clear();
         self.grants.clear();
         self.role_checks.clear();
+        self.leases.end_all();
         let now = Instant::now();
         for pending in std::mem::take(&mut self.approvals) {
             self.record_unanswered(&pending, "locked", "vault_locked", now);
diff --git a/crates/kv/src/mcp.rs b/crates/kv/src/mcp.rs
index 9e97f91..ab13cd9 100644
--- a/crates/kv/src/mcp.rs
+++ b/crates/kv/src/mcp.rs
@@ -9,7 +9,8 @@ use std::path::PathBuf;
 
 use kv_core::crypto::fill_random;
 use kv_core::proto::{
-    AgentRequest, AgentResponse, DbCall, ExecCall, HandleRequest, HttpCall, SessionInfo,
+    AgentRequest, AgentResponse, ConnectCall, DbCall, ExecCall, HandleRequest, HttpCall,
+    SessionInfo,
 };
 use kv_core::secret::{AuthPlacement, SecretKind};
 use rmcp::handler::server::wrapper::Parameters;
@@ -68,6 +69,15 @@ pub struct DbQueryArgs {
     timeout_secs: Option<u64>,
 }
 
+#[derive(Deserialize, schemars::JsonSchema)]
+pub struct DbConnectArgs {
+    /// A postgres or redis handle from list_handles.
+    handle: String,
+    /// Seconds the URL keeps working: 900 by default, at most 3600.
+    #[serde(default)]
+    ttl_secs: Option<u64>,
+}
+
 /// Never carries a secret value: unknown fields such as `token` are refused.
 #[derive(Deserialize, schemars::JsonSchema)]
 #[serde(deny_unknown_fields)]
@@ -196,6 +206,26 @@ impl KvServer {
             .await)
     }
 
+    #[tool(
+        description = "Get a connection URL for a postgres or redis handle, for a tool that needs its own connection (psql, redis-cli, a migration tool, a test suite). The URL points at kv on 127.0.0.1 and holds a lease token instead of the password; it works only on this machine and stops working when it expires, the vault locks or the handle changes, which also closes its connections. Results through it are scrubbed, and read-only handles stay read-only. Prefer db_query for single queries. If the handle's mode is ask, this waits up to 60 s for the user to approve it in kv tui."
+    )]
+    async fn db_connect(
+        &self,
+        peer: Peer<RoleServer>,
+        Parameters(args): Parameters<DbConnectArgs>,
+    ) -> Result<CallToolResult, ErrorData> {
+        let session = self.session(&peer);
+        Ok(self
+            .ask(
+                Some(&session),
+                AgentRequest::DbConnect(ConnectCall {
+                    handle: args.handle,
+                    ttl_secs: args.ttl_secs,
+                }),
+            )
+            .await)
+    }
+
     #[tool(
         description = "Ask the user to add a handle you need but do not have. Never include a secret value: the user types it in kv tui, where your request appears with the form filled in, and decides the policy. Returns at once; call list_handles later to see whether it was added."
     )]
@@ -253,7 +283,7 @@ impl KvServer {
     name = "kv",
     instructions = "kv lets you use the user's API keys, tokens and other secrets \
 without seeing them. Call list_handles to see what is available and how each handle may be \
-used, then call http_request, exec or db_query with a handle name. Secret values never appear in \
+used, then call http_request, exec, db_query or db_connect with a handle name. Secret values never appear in \
 results; where one would, you see [kv:<handle>]. Handles in ask mode wait for the user to \
 approve each use in kv tui; approval_denied means they said no, so do not retry it. If a call \
 fails with vault_locked, ask the user to run `kv unlock`. If you need a secret that has no \
```

- [ ] **Step 4: Run the tests to watch them pass**

Run: `cargo test -p kv-core --test proto && cargo test -p kv --test lease --test resp --test lease_live --test mcp --test state --test approve --test db_live`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "Add db_connect leases, with the Redis relay"
```

### Task 5: The Postgres relay, keeping read-only sessions read-only

**Files:**
- Modify: `crates/kv/Cargo.toml`
- Modify: `crates/kv/src/broker.rs`
- Modify: `crates/kv/src/broker/db.rs`
- Modify: `crates/kv/src/broker/lease.rs`
- Create: `crates/kv/src/broker/lease/postgres.rs`
- Create: `crates/kv/src/broker/pgwire.rs`
- Modify: `crates/kv/src/daemon/state.rs`
- Modify: `crates/kv/tests/lease.rs`
- Modify: `crates/kv/tests/lease_live.rs`
- Create: `crates/kv/tests/pgwire.rs`

**Interfaces:**
- Consumes: Task 1 `pg_session_violation`, `postgres_requires_tls`; Task 2 `RoleChecks::stamp`/`record`; Task 4 leases and `net::Buffered`.
- Produces: `kv::broker::pgwire::{Message, parse_message, next_message, Opening, parse_opening, next_opening, error, auth, negotiate_protocol, error_text, scrub_backend, parameter, ReadOnlyGate::check(&mut self, &Message) -> Result<bool, String>, PgTarget::parse(&str) -> Result<PgTarget, String>, PgTarget.dbname, connect(&PgTarget, &[(String, String)])}`; `kv::broker::db::role_warning(handle, url, &RoleChecks, stamp, &Scrubber)`; `ConnectJob.role_checks`/`role_stamp`. Adds `postgres-protocol = "0.6"` (SCRAM and MD5).

- [ ] **Step 1: Write the failing tests**

Apply with `git apply` from the repository root:

```diff
diff --git a/crates/kv/tests/lease.rs b/crates/kv/tests/lease.rs
index be3c5fa..bf26da9 100644
--- a/crates/kv/tests/lease.rs
+++ b/crates/kv/tests/lease.rs
@@ -123,6 +123,63 @@ async fn a_lease_approved_after_the_vault_locked_does_not_start() {
     }
 }
 
+#[tokio::test]
+async fn a_postgres_lease_url_holds_a_token_and_the_database() {
+    let mut f = Fixture::new();
+    f.add(postgres("pg", PG_URL, false, Mode::Auto));
+    let reply = start(&mut f, lease("pg")).await;
+    assert_eq!(reply.expires_in_secs, 900);
+    let url = url::Url::parse(&reply.url).unwrap();
+    assert_eq!(
+        (url.scheme(), url.username(), url.host_str(), url.path()),
+        ("postgres", "kv", Some("127.0.0.1"), "/app")
+    );
+    assert_eq!(url.query(), Some("sslmode=disable"));
+    let token = url.password().unwrap();
+    assert!(token.len() == 64 && token.bytes().all(|b| b.is_ascii_hexdigit()));
+    assert!(!reply.url.contains("pg-password"));
+
+    let mut wrong = url.clone();
+    wrong.set_password(Some("not-the-token")).unwrap();
+    let error = tokio_postgres::connect(wrong.as_str(), tokio_postgres::NoTls)
+        .await
+        .err()
+        .unwrap();
+    assert!(
+        format!("{error:?}").contains("password authentication failed"),
+        "{error:?}"
+    );
+    let mut other_db = url.clone();
+    other_db.set_path("/postgres");
+    let error = tokio_postgres::connect(other_db.as_str(), tokio_postgres::NoTls)
+        .await
+        .err()
+        .unwrap();
+    assert!(
+        format!("{error:?}").contains("this lease is for database"),
+        "{error:?}"
+    );
+
+    // The right token gets as far as the server, which cannot be reached;
+    // the error does not name it.
+    let error = tokio_postgres::connect(url.as_str(), tokio_postgres::NoTls)
+        .await
+        .err()
+        .unwrap();
+    let error = format!("{error:?}");
+    assert!(error.contains("kv:"), "{error}");
+    assert!(!error.contains("db.internal.example"), "{error}");
+
+    let audit = f.audit_lines();
+    let outcomes: Vec<_> = audit
+        .iter()
+        .filter(|line| line["action"] == "db_connect")
+        .map(|line| line["outcome"].as_str().unwrap().to_owned())
+        .collect();
+    assert_eq!(outcomes[0], "ok");
+    assert!(outcomes.contains(&"wrong_token".to_owned()), "{outcomes:?}");
+}
+
 #[tokio::test]
 async fn a_redis_lease_needs_the_token_before_any_command() {
     let mut f = Fixture::new();
diff --git a/crates/kv/tests/lease_live.rs b/crates/kv/tests/lease_live.rs
index 8c11f92..9379cdb 100644
--- a/crates/kv/tests/lease_live.rs
+++ b/crates/kv/tests/lease_live.rs
@@ -5,12 +5,16 @@
 
 mod common;
 
+use std::time::Duration;
+
 use common::*;
+use futures_util::StreamExt;
 use kv::broker::lease;
 use kv_core::policy::Mode;
-use kv_core::proto::{AgentResponse, ConnectCall, LeaseReply};
+use kv_core::proto::{AgentResponse, ConnectCall, ControlCommand, LeaseReply};
 use tokio::io::{AsyncReadExt, AsyncWriteExt};
 use tokio::net::TcpStream;
+use tokio_postgres::{NoTls, SimpleQueryMessage};
 
 async fn start(f: &mut Fixture, call: ConnectCall) -> LeaseReply {
     match lease::start(f.connect(call).unwrap()).await {
@@ -19,10 +23,189 @@ async fn start(f: &mut Fixture, call: ConnectCall) -> LeaseReply {
     }
 }
 
+async fn client(url: &str) -> tokio_postgres::Client {
+    let (client, connection) = tokio_postgres::connect(url, NoTls).await.unwrap();
+    tokio::spawn(connection);
+    client
+}
+
+/// The first value of the first row, in text.
+async fn value(client: &tokio_postgres::Client, sql: &str) -> Option<String> {
+    let messages = client.simple_query(sql).await.unwrap();
+    messages.iter().find_map(|message| match message {
+        SimpleQueryMessage::Row(row) => Some(row.get(0).map(str::to_owned)),
+        _ => None,
+    })?
+}
+
 fn password(url: &str) -> String {
     url::Url::parse(url).unwrap().password().unwrap().to_owned()
 }
 
+#[tokio::test]
+async fn a_postgres_lease_relays_queries_with_secrets_scrubbed() {
+    let Some(url) = server("KV_TEST_POSTGRES_URL") else {
+        return;
+    };
+    let secret = password(&url);
+    let admin = admin(&url, "kv_lease").await;
+    admin
+        .batch_execute(&format!(
+            "CREATE TABLE kv_lease.notes (id int, body text);
+             INSERT INTO kv_lease.notes VALUES
+               (1, 'the password is {secret}'), (2, 'later: other-secret-0123456789');"
+        ))
+        .await
+        .unwrap();
+    let mut f = Fixture::new();
+    f.add(postgres("pg", &url, false, Mode::Auto));
+    let reply = start(&mut f, lease("pg")).await;
+    assert!(reply.warnings.is_empty(), "not read-only: no role check");
+    let db = client(&reply.url).await;
+
+    let body = value(&db, "SELECT body FROM kv_lease.notes WHERE id = 1").await;
+    assert_eq!(body.as_deref(), Some("the password is [kv:pg]"));
+    // The extended protocol, as drivers use for parameters.
+    let rows = db
+        .query("SELECT body FROM kv_lease.notes WHERE id = $1", &[&1i32])
+        .await
+        .unwrap();
+    assert_eq!(rows[0].get::<_, String>(0), "the password is [kv:pg]");
+    let error = db
+        .simple_query(&format!("SELECT * FROM \"{secret}\""))
+        .await
+        .unwrap_err();
+    let error = format!("{error:?}");
+    assert!(
+        !error.contains(&secret) && error.contains("[kv:pg]"),
+        "{error}"
+    );
+    db.batch_execute("INSERT INTO kv_lease.notes VALUES (3, 'written')")
+        .await
+        .unwrap();
+    let copied: Vec<_> = db
+        .copy_out("COPY (SELECT body FROM kv_lease.notes WHERE id = 1) TO STDOUT")
+        .await
+        .unwrap()
+        .collect()
+        .await;
+    let copied: Vec<u8> = copied
+        .into_iter()
+        .flat_map(|chunk| chunk.unwrap())
+        .collect();
+    assert_eq!(copied, b"the password is [kv:pg]\n");
+
+    // A secret added while the lease is open is scrubbed from then on.
+    f.add(env_secret(
+        "other",
+        &[("TOKEN", "other-secret-0123456789")],
+        &[],
+        Mode::Auto,
+    ));
+    let body = value(&db, "SELECT body FROM kv_lease.notes WHERE id = 2").await;
+    assert_eq!(body.as_deref(), Some("later: [kv:other]"));
+}
+
+#[tokio::test]
+async fn a_read_only_postgres_lease_keeps_the_session_read_only() {
+    let Some(url) = server("KV_TEST_POSTGRES_URL") else {
+        return;
+    };
+    let admin = admin(&url, "kv_lease_ro").await;
+    admin
+        .batch_execute("CREATE TABLE kv_lease_ro.items (id int)")
+        .await
+        .unwrap();
+    let mut f = Fixture::new();
+    f.add(postgres("pg", &url, true, Mode::Auto));
+    let reply = start(&mut f, lease("pg")).await;
+    assert!(
+        reply.warnings[0].contains("role can write"),
+        "{:?}",
+        reply.warnings
+    );
+
+    let db = client(&reply.url).await;
+    let error = db
+        .batch_execute("INSERT INTO kv_lease_ro.items VALUES (1)")
+        .await
+        .unwrap_err();
+    assert!(
+        format!("{error:?}").contains("read-only transaction"),
+        "{error:?}"
+    );
+    // Transactions in separate queries are fine.
+    for sql in ["BEGIN", "SELECT count(*) FROM kv_lease_ro.items", "COMMIT"] {
+        db.batch_execute(sql).await.unwrap();
+    }
+    let error = db
+        .batch_execute("COMMIT; INSERT INTO kv_lease_ro.items VALUES (1)")
+        .await
+        .unwrap_err();
+    assert!(
+        format!("{error:?}").contains("send them separately"),
+        "{error:?}"
+    );
+    assert!(db.is_closed() || db.batch_execute("SELECT 1").await.is_err());
+
+    // A switch built from pieces passes the text checks; the server
+    // reports it, and kv ends the session before anything else runs.
+    let db = client(&reply.url).await;
+    let sneaky = "SELECT query_to_xml('select set_' || 'config(''default_' || 'transaction_' \
+                  || 'read_' || 'only'', ''off'', false)', true, true, '')";
+    let error = db.simple_query(sneaky).await.unwrap_err();
+    assert!(
+        format!("{error:?}").contains("tried to change that"),
+        "{error:?}"
+    );
+    assert!(db.batch_execute("SELECT 1").await.is_err());
+
+    let mut options = tokio_postgres::Config::new();
+    options
+        .host("127.0.0.1")
+        .port(url::Url::parse(&reply.url).unwrap().port().unwrap())
+        .user("kv")
+        .password(password(&reply.url))
+        .dbname(
+            url::Url::parse(&reply.url)
+                .unwrap()
+                .path()
+                .trim_start_matches('/'),
+        )
+        .options("-c default_transaction_read_only=off");
+    let error = options.connect(NoTls).await.err().unwrap();
+    assert!(
+        format!("{error:?}").contains("startup parameter options"),
+        "{error:?}"
+    );
+
+    let count = value(&admin, "SELECT count(*) FROM kv_lease_ro.items").await;
+    assert_eq!(count.as_deref(), Some("0"));
+}
+
+#[tokio::test]
+async fn a_postgres_lease_ends_its_connections_when_the_vault_locks() {
+    let Some(url) = server("KV_TEST_POSTGRES_URL") else {
+        return;
+    };
+    let mut f = Fixture::new();
+    f.add(postgres("pg", &url, false, Mode::Auto));
+    let reply = start(&mut f, lease("pg")).await;
+    let (db, connection) = tokio_postgres::connect(&reply.url, NoTls).await.unwrap();
+    let connection = tokio::spawn(connection);
+    assert_eq!(value(&db, "SELECT 1").await.as_deref(), Some("1"));
+    f.control(ControlCommand::Lock);
+    let ended = tokio::time::timeout(Duration::from_secs(3), connection)
+        .await
+        .expect("the connection closes")
+        .unwrap()
+        .unwrap_err();
+    assert!(
+        format!("{ended:?}").contains("the lease ended"),
+        "{ended:?}"
+    );
+}
+
 #[tokio::test]
 async fn a_redis_lease_relays_commands_with_secrets_scrubbed() {
     let Some(url) = server("KV_TEST_REDIS_URL") else {
diff --git a/crates/kv/tests/pgwire.rs b/crates/kv/tests/pgwire.rs
new file mode 100644
index 0000000..2c17470
--- /dev/null
+++ b/crates/kv/tests/pgwire.rs
@@ -0,0 +1,136 @@
+//! The Postgres wire protocol as the db_connect proxy handles it: framing,
+//! the first packet, scrubbing what the server sends, and the read-only
+//! gate.
+
+use kv::broker::net::MAX_WIRE_MESSAGE;
+use kv::broker::pgwire::*;
+use kv_core::scrub::Scrubber;
+
+fn cstrs(parts: &[&str]) -> Vec<u8> {
+    let mut out = Vec::new();
+    for part in parts {
+        out.extend_from_slice(part.as_bytes());
+        out.push(0);
+    }
+    out
+}
+
+#[test]
+fn messages_frame_and_wait_for_their_bytes() {
+    let encoded = Message::new(b'Q', cstrs(&["select 1"])).encode();
+    let (message, used) = parse_message(&encoded).unwrap().unwrap();
+    assert_eq!((message.tag, used), (b'Q', encoded.len()));
+    assert_eq!(parse_message(&encoded[..encoded.len() - 1]).unwrap(), None);
+    let mut huge = vec![b'D'];
+    huge.extend_from_slice(&(MAX_WIRE_MESSAGE as u32 + 5).to_be_bytes());
+    assert!(parse_message(&huge).is_err());
+}
+
+#[test]
+fn the_first_packet_says_what_the_client_wants() {
+    let mut ssl = 8u32.to_be_bytes().to_vec();
+    ssl.extend_from_slice(&80_877_103u32.to_be_bytes());
+    assert_eq!(parse_opening(&ssl).unwrap(), Some((Opening::Ssl, 8)));
+
+    let mut body = 196_608u32.to_be_bytes().to_vec();
+    body.extend(cstrs(&["user", "kv", "database", "app"]));
+    body.push(0);
+    let mut packet = (body.len() as u32 + 4).to_be_bytes().to_vec();
+    packet.extend(body);
+    let (opening, used) = parse_opening(&packet).unwrap().unwrap();
+    assert_eq!(used, packet.len());
+    assert_eq!(
+        opening,
+        Opening::Startup {
+            minor: 0,
+            params: vec![
+                ("user".into(), "kv".into()),
+                ("database".into(), "app".into())
+            ],
+        }
+    );
+    let mut old = 8u32.to_be_bytes().to_vec();
+    old.extend_from_slice(&0x0002_0000u32.to_be_bytes());
+    assert!(parse_opening(&old).is_err());
+}
+
+#[test]
+fn rows_errors_and_names_are_scrubbed_in_place() {
+    let scrubber = Scrubber::new([("pg", "pg-password-0123")]);
+    let value = b"pw=pg-password-0123";
+    let mut row = 2u16.to_be_bytes().to_vec();
+    row.extend_from_slice(&(-1i32).to_be_bytes());
+    row.extend_from_slice(&(value.len() as i32).to_be_bytes());
+    row.extend_from_slice(value);
+    let scrubbed = scrub_backend(Message::new(b'D', row), &scrubber).unwrap();
+    let mut expected = 2u16.to_be_bytes().to_vec();
+    expected.extend_from_slice(&(-1i32).to_be_bytes());
+    expected.extend_from_slice(&10i32.to_be_bytes());
+    expected.extend_from_slice(b"pw=[kv:pg]");
+    assert_eq!(scrubbed.body, expected);
+
+    let mut description = 1u16.to_be_bytes().to_vec();
+    description.extend(cstrs(&["pg-password-0123"]));
+    description.extend_from_slice(&[0; 18]);
+    let scrubbed = scrub_backend(Message::new(b'T', description), &scrubber).unwrap();
+    assert!(scrubbed.body.windows(7).any(|w| w == b"[kv:pg]"));
+    assert_eq!(scrubbed.body.len(), 2 + 8 + 18);
+
+    let failed = error(
+        "ERROR",
+        "42P01",
+        "relation \"pg-password-0123\" does not exist",
+    );
+    let scrubbed = scrub_backend(failed, &scrubber).unwrap();
+    assert_eq!(
+        error_text(&scrubbed.body),
+        "relation \"[kv:pg]\" does not exist (SQLSTATE 42P01)"
+    );
+    assert!(scrub_backend(Message::new(b'D', vec![0, 1, 0]), &scrubber).is_err());
+}
+
+fn parse(name: &str, sql: &str) -> Message {
+    let mut body = cstrs(&[name, sql]);
+    body.extend_from_slice(&0u16.to_be_bytes());
+    Message::new(b'P', body)
+}
+
+fn bind(portal: &str, statement: &str) -> Message {
+    let mut body = cstrs(&[portal, statement]);
+    body.extend_from_slice(&[0; 6]);
+    Message::new(b'B', body)
+}
+
+fn execute(portal: &str) -> Message {
+    let mut body = cstrs(&[portal]);
+    body.extend_from_slice(&0u32.to_be_bytes());
+    Message::new(b'E', body)
+}
+
+#[test]
+fn the_gate_lets_one_batch_end_a_transaction_only_at_its_end() {
+    let mut gate = ReadOnlyGate::default();
+    let query = |sql: &str| Message::new(b'Q', cstrs(&[sql]));
+    assert_eq!(gate.check(&query("select 1")), Ok(true));
+    assert_eq!(gate.check(&query("commit")), Ok(true));
+    assert!(gate.check(&query("commit; delete from t")).is_err());
+
+    // Extended protocol: a COMMIT executed, then anything but Sync.
+    let sync = Message::new(b'S', Vec::new());
+    assert_eq!(gate.check(&parse("c", "COMMIT")), Ok(false));
+    assert_eq!(gate.check(&bind("", "c")), Ok(false));
+    assert_eq!(gate.check(&execute("")), Ok(false));
+    assert!(gate.check(&parse("", "insert into t values (1)")).is_err());
+
+    let mut gate = ReadOnlyGate::default();
+    for message in [parse("c", "COMMIT"), bind("", "c"), execute("")] {
+        gate.check(&message).unwrap();
+    }
+    assert_eq!(gate.check(&sync), Ok(true));
+    assert_eq!(gate.check(&parse("", "select 1")), Ok(false));
+    assert!(
+        gate.check(&parse("", "set default_transaction_read_only = off"))
+            .is_err()
+    );
+    assert!(gate.check(&Message::new(b'F', vec![0; 8])).is_err());
+}
```

- [ ] **Step 2: Run the tests to watch them fail**

Run: `cargo test -p kv --test pgwire --test lease`
Expected: FAIL: `error[E0432]: unresolved import kv::broker::pgwire`.

- [ ] **Step 3: Implement**

Apply with `git apply` (Cargo.lock updates itself on the next build):

```diff
diff --git a/crates/kv/Cargo.toml b/crates/kv/Cargo.toml
index 1fb0d81..15c1939 100644
--- a/crates/kv/Cargo.toml
+++ b/crates/kv/Cargo.toml
@@ -13,6 +13,7 @@ humantime = "2"
 kv-core = { path = "../kv-core" }
 notify-rust = "4.18"
 percent-encoding = "2.3"
+postgres-protocol = "0.6"
 ratatui = { version = "0.30", features = ["unstable-rendered-line-info"] }
 reqwest = { version = "0.13", default-features = false, features = ["rustls"] }
 rmcp = { version = "3.5", default-features = false, features = ["macros", "server", "transport-io"] }
diff --git a/crates/kv/src/broker.rs b/crates/kv/src/broker.rs
index 000c4c2..8001af7 100644
--- a/crates/kv/src/broker.rs
+++ b/crates/kv/src/broker.rs
@@ -19,6 +19,7 @@ pub mod exec;
 pub mod http;
 pub mod lease;
 pub mod net;
+pub mod pgwire;
 mod process;
 pub mod resp;
 
@@ -86,6 +87,8 @@ pub struct ConnectJob {
     pub started: Instant,
     /// `auto`, or `approved` after a decision in `kv tui`, for the audit log.
     pub decision: &'static str,
+    pub role_checks: RoleChecks,
+    pub role_stamp: u64,
 }
 
 /// Decodes scrubbed bytes, cutting them to `MAX_OUTPUT_LEN` (replacement
diff --git a/crates/kv/src/broker/db.rs b/crates/kv/src/broker/db.rs
index 38598e4..d36a214 100644
--- a/crates/kv/src/broker/db.rs
+++ b/crates/kv/src/broker/db.rs
@@ -136,7 +136,7 @@ async fn postgres(job: &DbJob, url: &str) -> Result<AgentResponse, AgentResponse
             let warning = role_can_write(&client)
                 .await
                 .map_err(|e| upstream(scrubber, &e))?
-                .then(|| role_warning(name));
+                .then(|| warning_for(name));
             job.role_checks
                 .record(name, job.role_stamp, warning.clone());
             warning
@@ -263,12 +263,46 @@ pub async fn check_role(handle: &str, url: &str) -> Result<Option<String>, Strin
             .map_err(|e| message(upstream(&scrubber, &e)))
     };
     match tokio::time::timeout(CONNECT_TIMEOUT * 2, check).await {
-        Ok(can_write) => Ok(can_write?.then(|| role_warning(handle))),
+        Ok(can_write) => Ok(can_write?.then(|| warning_for(handle))),
         Err(_) => Err("the database did not answer in time".into()),
     }
 }
 
-fn role_warning(handle: &str) -> String {
+/// The warning for a read-only Postgres handle whose role can write, from
+/// the check since the vault was unlocked, or from a new check on a
+/// connection of its own. For `db_connect`, which has no connection of its
+/// own to check on.
+pub(crate) async fn role_warning(
+    handle: &str,
+    url: &str,
+    role_checks: &RoleChecks,
+    stamp: u64,
+    scrubber: &Scrubber,
+) -> Result<Option<String>, AgentResponse> {
+    if role_checks.is_checked(handle) {
+        return Ok(role_checks.warning(handle));
+    }
+    let check = async {
+        let client = connect(url, "", scrubber).await?;
+        role_can_write(&client)
+            .await
+            .map_err(|e| upstream(scrubber, &e))
+    };
+    let can_write = match tokio::time::timeout(CONNECT_TIMEOUT * 2, check).await {
+        Ok(can_write) => can_write?,
+        Err(_) => {
+            return Err(error(
+                AgentErrorCode::UpstreamError,
+                "the database did not answer in time",
+            ));
+        }
+    };
+    let warning = can_write.then(|| warning_for(handle));
+    role_checks.record(handle, stamp, warning.clone());
+    Ok(warning)
+}
+
+fn warning_for(handle: &str) -> String {
     format!(
         "{handle} is read-only, but its database role can write; kv keeps the session \
          read-only only on a best-effort basis. Use a role that can only read."
diff --git a/crates/kv/src/broker/lease.rs b/crates/kv/src/broker/lease.rs
index d2bfbe7..e3fd155 100644
--- a/crates/kv/src/broker/lease.rs
+++ b/crates/kv/src/broker/lease.rs
@@ -16,9 +16,11 @@ use tokio::net::{TcpListener, TcpStream};
 use tokio::sync::{Semaphore, watch};
 
 use super::ConnectJob;
+use super::pgwire::PgTarget;
 use super::resp::RedisTarget;
 use crate::audit::{Audit, Use};
 
+mod postgres;
 mod redis;
 
 pub const DEFAULT_TTL: Duration = Duration::from_secs(900);
@@ -145,6 +147,7 @@ impl Lease {
 }
 
 enum Target {
+    Postgres(PgTarget),
     Redis(RedisTarget),
 }
 
@@ -152,7 +155,15 @@ enum Target {
 pub async fn start(job: ConnectJob) -> AgentResponse {
     let ticket = job.ticket;
     let ttl = job.ttl;
-    let opened = open(&job.secret, ttl, job.scrubber.clone(), &job.audit, ticket);
+    let opened = open(
+        &job.secret,
+        ttl,
+        job.scrubber.clone(),
+        &job.audit,
+        &job.role_checks,
+        job.role_stamp,
+        ticket,
+    );
     let response = match opened.await {
         Ok(reply) => AgentResponse::Lease(reply),
         Err(response) => response,
@@ -177,6 +188,8 @@ async fn open(
     ttl: Duration,
     scrubber_rx: watch::Receiver<Arc<Scrubber>>,
     audit: &Audit,
+    role_checks: &super::RoleChecks,
+    role_stamp: u64,
     ticket: LeaseTicket,
 ) -> Result<LeaseReply, AgentResponse> {
     if ticket.has_ended() {
@@ -185,13 +198,28 @@ async fn open(
             "the vault locked or the handle changed before the lease started; ask again",
         ));
     }
+    let scrubber = scrubber_rx.borrow().clone();
     let bad = |message: String| error(AgentErrorCode::BadRequest, message);
     let read_only = secret.policy.read_only;
+    let mut warnings = Vec::new();
     let target = match &secret.value {
-        SecretValue::Redis { url } => Target::Redis(RedisTarget::parse(url.expose()).map_err(bad)?),
-        SecretValue::Postgres { .. } => {
-            return Err(bad("db_connect does not take postgres handles yet".into()));
+        SecretValue::Postgres { url } => {
+            let target = PgTarget::parse(url.expose()).map_err(bad)?;
+            if read_only {
+                warnings.extend(
+                    super::db::role_warning(
+                        &secret.name,
+                        url.expose(),
+                        role_checks,
+                        role_stamp,
+                        &scrubber,
+                    )
+                    .await?,
+                );
+            }
+            Target::Postgres(target)
         }
+        SecretValue::Redis { url } => Target::Redis(RedisTarget::parse(url.expose()).map_err(bad)?),
         _ => return Err(bad("not a database handle".into())),
     };
     let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
@@ -215,6 +243,16 @@ async fn open(
     fill_random(&mut bytes);
     let token = hex(&bytes);
     let url = match &target {
+        Target::Postgres(target) => {
+            let mut url = url::Url::parse(&format!("postgres://127.0.0.1:{port}"))
+                .expect("a loopback URL parses");
+            url.set_username("kv").expect("postgres URLs take a user");
+            url.set_password(Some(&token))
+                .expect("postgres URLs take a password");
+            url.set_path(&target.dbname);
+            url.set_query(Some("sslmode=disable"));
+            url.to_string()
+        }
         Target::Redis(target) => format!("redis://kv:{token}@127.0.0.1:{port}/{}", target.db),
     };
     let lease = Arc::new(Lease {
@@ -230,7 +268,7 @@ async fn open(
     Ok(LeaseReply {
         url,
         expires_in_secs: ttl.as_secs(),
-        warnings: Vec::new(),
+        warnings,
     })
 }
 
@@ -274,6 +312,7 @@ async fn connection(stream: TcpStream, lease: Arc<Lease>, end: watch::Receiver<(
     let started = Instant::now();
     let _ = stream.set_nodelay(true);
     let outcome = match &lease.target {
+        Target::Postgres(target) => postgres::serve(stream, &lease, target, end).await,
         Target::Redis(target) => redis::serve(stream, &lease, target, end).await,
     };
     record(&lease, outcome, started);
diff --git a/crates/kv/src/broker/lease/postgres.rs b/crates/kv/src/broker/lease/postgres.rs
new file mode 100644
index 0000000..4729616
--- /dev/null
+++ b/crates/kv/src/broker/lease/postgres.rs
@@ -0,0 +1,306 @@
+//! One client on a Postgres lease: kv plays the server until the client
+//! gives the lease token, logs in to the real server, then relays messages.
+//! On a read-only handle it checks what the client sends and lets one batch
+//! through at a time, so it sees the server report
+//! `default_transaction_read_only` before the next batch runs.
+
+use kv_core::db::pg_session_violation;
+use tokio::io::{AsyncWriteExt, BufWriter, ReadHalf, WriteHalf};
+use tokio::net::TcpStream;
+use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
+use tokio::sync::{oneshot, watch};
+
+use super::{HANDSHAKE_TIMEOUT, Lease, UPSTREAM_TIMEOUT, token_matches};
+use crate::broker::net::{Buffered, Upstream};
+use crate::broker::pgwire::{
+    self, Message, Opening, PgTarget, ReadOnlyGate, error, next_message, next_opening,
+    parse_message, scrub_backend,
+};
+
+type ClientRead = Buffered<OwnedReadHalf>;
+type ClientWrite = BufWriter<OwnedWriteHalf>;
+
+pub(super) async fn serve(
+    stream: TcpStream,
+    lease: &Lease,
+    target: &PgTarget,
+    end: watch::Receiver<()>,
+) -> &'static str {
+    let (read, write) = stream.into_split();
+    let mut client = Buffered::new(read);
+    let mut write = BufWriter::new(write);
+    let params = match tokio::time::timeout(
+        HANDSHAKE_TIMEOUT,
+        handshake(&mut client, &mut write, lease, target),
+    )
+    .await
+    {
+        Ok(Ok(params)) => params,
+        Ok(Err(outcome)) => return outcome,
+        Err(_) => return "timed_out",
+    };
+    let connected = tokio::time::timeout(UPSTREAM_TIMEOUT, pgwire::connect(target, &params)).await;
+    let (upstream, after) = match connected {
+        Ok(Ok(connected)) => connected,
+        Ok(Err(message)) => {
+            let message =
+                String::from_utf8_lossy(&lease.scrubber().scrub(message.as_bytes())).into_owned();
+            fatal(&mut write, "08006", &format!("kv: {message}")).await;
+            return "upstream_error";
+        }
+        Err(_) => {
+            fatal(
+                &mut write,
+                "08006",
+                "kv: the database did not answer in time",
+            )
+            .await;
+            return "upstream_error";
+        }
+    };
+
+    // The client already gave the token; the server's own login is done.
+    let mut reported = false;
+    let mut hello = pgwire::auth(0, &[]).encode();
+    for message in after {
+        if message.tag == b'S'
+            && let Some((name, value)) = pgwire::parameter(&message)
+            && name == "default_transaction_read_only"
+        {
+            reported = value == "on";
+        }
+        match scrub_backend(message, &lease.scrubber()) {
+            Ok(message) => hello.extend(message.encode()),
+            Err(_) => return "upstream_error",
+        }
+    }
+    if lease.read_only && !reported {
+        fatal(
+            &mut write,
+            "0A000",
+            "kv: read-only db_connect needs PostgreSQL 14 or later, which reports \
+             default_transaction_read_only; use db_query instead",
+        )
+        .await;
+        return "policy_denied";
+    }
+    if write.write_all(&hello).await.is_err() || write.flush().await.is_err() {
+        return "closed";
+    }
+
+    let (data, leftover) = upstream.into_parts();
+    let (up_read, mut up_write) = tokio::io::split(data);
+    let mut up_read = Buffered::with_data(up_read, leftover);
+    let (batches_done, done) = watch::channel(0u64);
+    let (stop, stopped) = oneshot::channel();
+    let gate = lease.read_only.then(ReadOnlyGate::default);
+    tokio::select! {
+        outcome = client_to_server(&mut client, &mut up_write, gate, done, stop) => outcome,
+        outcome = server_to_client(&mut up_read, &mut write, lease, batches_done, stopped, end) => outcome,
+    }
+}
+
+/// Answers TLS requests with "no", takes the startup packet and the
+/// lease token. Returns the parameters to pass on to the server.
+async fn handshake(
+    client: &mut ClientRead,
+    write: &mut ClientWrite,
+    lease: &Lease,
+    target: &PgTarget,
+) -> Result<Vec<(String, String)>, &'static str> {
+    let (minor, params) = loop {
+        match next_opening(client).await {
+            Ok(Some(Opening::Ssl | Opening::Gss)) => {
+                if write.write_all(b"N").await.is_err() || write.flush().await.is_err() {
+                    return Err("closed");
+                }
+            }
+            Ok(Some(Opening::Startup { minor, params })) => break (minor, params),
+            // Query cancellation is not passed on.
+            Ok(Some(Opening::Cancel) | None) | Err(_) => return Err("closed"),
+        }
+    };
+    let mut forward = Vec::new();
+    let mut options = target.options.clone().unwrap_or_default();
+    let mut unknown = Vec::new();
+    for (name, value) in params {
+        match name.as_str() {
+            "user" => {}
+            "database" if value != target.dbname => {
+                let message = format!("kv: this lease is for database \"{}\"", target.dbname);
+                fatal(write, "3D000", &message).await;
+                return Err("bad_request");
+            }
+            "database" => {}
+            "replication" => {
+                fatal(
+                    write,
+                    "08P01",
+                    "kv: db_connect does not pass on replication",
+                )
+                .await;
+                return Err("bad_request");
+            }
+            _ if name.starts_with("_pq_.") => unknown.push(name),
+            _ => {
+                if lease.read_only && pg_session_violation(&format!("{name} {value}")).is_err() {
+                    let message = format!(
+                        "kv: the handle is read-only, and kv refuses the startup parameter {name}"
+                    );
+                    fatal(write, "25006", &message).await;
+                    return Err("policy_denied");
+                }
+                if name == "options" {
+                    options = format!("{options} {value}");
+                } else {
+                    forward.push((name, value));
+                }
+            }
+        }
+    }
+    if lease.read_only {
+        options.push_str(" -c default_transaction_read_only=on");
+    }
+    if !options.trim().is_empty() {
+        forward.push(("options".into(), options.trim().to_owned()));
+    }
+    let mut reply = Vec::new();
+    if minor > 0 || !unknown.is_empty() {
+        reply.extend(pgwire::negotiate_protocol(&unknown).encode());
+    }
+    reply.extend(pgwire::auth(3, &[]).encode());
+    if write.write_all(&reply).await.is_err() || write.flush().await.is_err() {
+        return Err("closed");
+    }
+    let password = match next_message(client).await {
+        Ok(Some(Message { tag: b'p', body })) => body,
+        _ => return Err("closed"),
+    };
+    let given = password.strip_suffix(&[0]).unwrap_or(&password);
+    if !token_matches(given, &lease.token) {
+        fatal(
+            write,
+            "28P01",
+            "password authentication failed for user \"kv\" (the lease token is wrong)",
+        )
+        .await;
+        return Err("wrong_token");
+    }
+    Ok(forward)
+}
+
+/// Passes the client's messages on. With a gate, a violation goes to the
+/// other half, which tells the client and ends the connection, and after
+/// each batch it waits for the server's `ReadyForQuery`.
+async fn client_to_server(
+    client: &mut ClientRead,
+    upstream: &mut WriteHalf<Upstream>,
+    mut gate: Option<ReadOnlyGate>,
+    mut done: watch::Receiver<u64>,
+    stop: oneshot::Sender<String>,
+) -> &'static str {
+    let mut batches = 0u64;
+    loop {
+        let message = match next_message(client).await {
+            Ok(Some(message)) => message,
+            Ok(None) | Err(_) => return "closed",
+        };
+        let ends_batch = match gate.as_mut().map(|gate| gate.check(&message)) {
+            Some(Err(reason)) => {
+                let _ = stop.send(reason);
+                return std::future::pending().await;
+            }
+            Some(Ok(ends)) => ends,
+            None => false,
+        };
+        if upstream.write_all(&message.encode()).await.is_err() {
+            return "closed";
+        }
+        if message.tag == b'X' {
+            return "closed";
+        }
+        if ends_batch {
+            batches += 1;
+            if done.wait_for(|n| *n >= batches).await.is_err() {
+                return "closed";
+            }
+        }
+    }
+}
+
+/// Passes the server's messages back, scrubbed, and counts each
+/// `ReadyForQuery`. On a read-only handle it ends the session if the server
+/// reports `default_transaction_read_only` off, or starts a COPY from the
+/// client.
+async fn server_to_client(
+    upstream: &mut Buffered<ReadHalf<Upstream>>,
+    client: &mut ClientWrite,
+    lease: &Lease,
+    batches_done: watch::Sender<u64>,
+    mut stopped: oneshot::Receiver<String>,
+    end: watch::Receiver<()>,
+) -> &'static str {
+    loop {
+        let message = tokio::select! {
+            biased;
+            reason = &mut stopped => {
+                let Ok(reason) = reason else { return "closed" };
+                fatal(client, "25006", &format!("kv: {reason}")).await;
+                return "policy_denied";
+            }
+            _ = super::ended(end.clone()) => {
+                fatal(client, "57P01", "kv: the lease ended; ask for a new one with db_connect").await;
+                return "lease_ended";
+            }
+            read = next_message(upstream) => match read {
+                Ok(Some(message)) => message,
+                Ok(None) => return "closed",
+                Err(e) => {
+                    fatal(client, "08006", &format!("kv: {e}")).await;
+                    return "upstream_error";
+                }
+            },
+        };
+        if lease.read_only {
+            let switched_off = message.tag == b'S'
+                && pgwire::parameter(&message).is_some_and(|(name, value)| {
+                    name == "default_transaction_read_only" && value != "on"
+                });
+            if switched_off || matches!(message.tag, b'G' | b'W') {
+                fatal(
+                    client,
+                    "25006",
+                    "kv: the handle is read-only, and the session tried to change that; kv \
+                     closed it",
+                )
+                .await;
+                return "policy_denied";
+            }
+        }
+        let ready = message.tag == b'Z';
+        let Ok(message) = scrub_backend(message, &lease.scrubber()) else {
+            fatal(client, "08P01", "kv: the server sent a malformed message").await;
+            return "upstream_error";
+        };
+        if client.write_all(&message.encode()).await.is_err() {
+            return "closed";
+        }
+        // Flush once nothing more is waiting, so rows go out in big writes
+        // but a notification or the end of a query is never held back.
+        if (ready || !matches!(parse_message(upstream.data()), Ok(Some(_))))
+            && client.flush().await.is_err()
+        {
+            return "closed";
+        }
+        if ready {
+            batches_done.send_modify(|n| *n += 1);
+        }
+    }
+}
+
+async fn fatal(write: &mut ClientWrite, code: &str, message: &str) {
+    let _ = write
+        .write_all(&error("FATAL", code, message).encode())
+        .await;
+    let _ = write.flush().await;
+}
diff --git a/crates/kv/src/broker/pgwire.rs b/crates/kv/src/broker/pgwire.rs
new file mode 100644
index 0000000..69d7881
--- /dev/null
+++ b/crates/kv/src/broker/pgwire.rs
@@ -0,0 +1,612 @@
+//! The Postgres wire protocol, as far as the `db_connect` proxy needs it:
+//! framing, the messages kv writes itself, scrubbing what the server sends,
+//! the read-only gate, and logging in to the server.
+
+use std::collections::HashMap;
+use std::io;
+
+use kv_core::db::{pg_session_violation, postgres_requires_tls};
+use kv_core::scrub::Scrubber;
+use postgres_protocol::authentication::md5_hash;
+use postgres_protocol::authentication::sasl::{ChannelBinding, SCRAM_SHA_256, ScramSha256};
+use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
+
+use super::net::{self, Buffered, MAX_WIRE_MESSAGE, Upstream};
+
+const SSL_REQUEST: u32 = 80_877_103;
+const GSS_REQUEST: u32 = 80_877_104;
+const CANCEL_REQUEST: u32 = 80_877_102;
+const PROTOCOL_3_0: u32 = 196_608;
+
+/// A message with a type byte, as both sides send after the first packet.
+#[derive(Clone, Debug, PartialEq, Eq)]
+pub struct Message {
+    pub tag: u8,
+    pub body: Vec<u8>,
+}
+
+impl Message {
+    pub fn new(tag: u8, body: Vec<u8>) -> Self {
+        Self { tag, body }
+    }
+
+    pub fn encode(&self) -> Vec<u8> {
+        let mut out = Vec::with_capacity(self.body.len() + 5);
+        out.push(self.tag);
+        out.extend_from_slice(&(self.body.len() as u32 + 4).to_be_bytes());
+        out.extend_from_slice(&self.body);
+        out
+    }
+}
+
+/// A message from the front of `data`, with the bytes it took.
+pub fn parse_message(data: &[u8]) -> Result<Option<(Message, usize)>, String> {
+    if data.len() < 5 {
+        return Ok(None);
+    }
+    let len = u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as usize;
+    if len < 4 {
+        return Err("a message has a bad length".into());
+    }
+    if len - 4 > MAX_WIRE_MESSAGE {
+        return Err("a message is larger than kv accepts (16 MiB)".into());
+    }
+    if data.len() < 1 + len {
+        return Ok(None);
+    }
+    Ok(Some((
+        Message::new(data[0], data[5..1 + len].to_vec()),
+        1 + len,
+    )))
+}
+
+/// `None` at the end of the stream.
+pub async fn next_message<R: AsyncRead + Unpin>(
+    conn: &mut Buffered<R>,
+) -> io::Result<Option<Message>> {
+    loop {
+        if let Some((message, used)) = parse_message(conn.data()).map_err(io::Error::other)? {
+            conn.consume(used);
+            return Ok(Some(message));
+        }
+        if !conn.fill().await? {
+            return match conn.data().is_empty() {
+                true => Ok(None),
+                false => Err(io::ErrorKind::UnexpectedEof.into()),
+            };
+        }
+    }
+}
+
+/// The first packet a client sends, which has no type byte.
+#[derive(Debug, PartialEq, Eq)]
+pub enum Opening {
+    Ssl,
+    Gss,
+    Cancel,
+    /// Protocol 3.`minor`, with its parameters in order.
+    Startup {
+        minor: u16,
+        params: Vec<(String, String)>,
+    },
+}
+
+pub async fn next_opening<R: AsyncRead + Unpin>(
+    conn: &mut Buffered<R>,
+) -> io::Result<Option<Opening>> {
+    loop {
+        if let Some((opening, used)) = parse_opening(conn.data()).map_err(io::Error::other)? {
+            conn.consume(used);
+            return Ok(Some(opening));
+        }
+        if !conn.fill().await? {
+            return Ok(None);
+        }
+    }
+}
+
+pub fn parse_opening(data: &[u8]) -> Result<Option<(Opening, usize)>, String> {
+    if data.len() < 8 {
+        return Ok(None);
+    }
+    let len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
+    if !(8..=10_000).contains(&len) {
+        return Err("the startup packet has a bad length".into());
+    }
+    if data.len() < len {
+        return Ok(None);
+    }
+    let code = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
+    let opening = match code {
+        SSL_REQUEST => Opening::Ssl,
+        GSS_REQUEST => Opening::Gss,
+        CANCEL_REQUEST => Opening::Cancel,
+        code if code >> 16 == 3 => {
+            let mut params = Vec::new();
+            let mut pos = 8;
+            while let Some((name, next)) = cstr(&data[..len], pos) {
+                if name.is_empty() {
+                    break;
+                }
+                let (value, next) =
+                    cstr(&data[..len], next).ok_or("the startup packet is malformed")?;
+                params.push((
+                    String::from_utf8_lossy(name).into_owned(),
+                    String::from_utf8_lossy(value).into_owned(),
+                ));
+                pos = next;
+            }
+            Opening::Startup {
+                minor: (code & 0xffff) as u16,
+                params,
+            }
+        }
+        _ => return Err("kv speaks only protocol 3 of Postgres".into()),
+    };
+    Ok(Some((opening, len)))
+}
+
+/// A NUL-terminated string at `pos`, and where the next field starts.
+fn cstr(body: &[u8], pos: usize) -> Option<(&[u8], usize)> {
+    let rest = body.get(pos..)?;
+    let end = rest.iter().position(|&b| b == 0)?;
+    Some((&rest[..end], pos + end + 1))
+}
+
+fn put_cstr(out: &mut Vec<u8>, text: &[u8]) {
+    out.extend_from_slice(text);
+    out.push(0);
+}
+
+/// `ErrorResponse` with `severity` (`ERROR` or `FATAL`), an SQLSTATE and a
+/// message.
+pub fn error(severity: &str, code: &str, message: &str) -> Message {
+    let mut body = Vec::new();
+    for (field, value) in [(b'S', severity), (b'V', severity), (b'C', code)] {
+        body.push(field);
+        put_cstr(&mut body, value.as_bytes());
+    }
+    body.push(b'M');
+    put_cstr(&mut body, message.replace('\0', " ").as_bytes());
+    body.push(0);
+    Message::new(b'E', body)
+}
+
+/// `Authentication*` with its code and any data after it.
+pub fn auth(code: u32, data: &[u8]) -> Message {
+    let mut body = code.to_be_bytes().to_vec();
+    body.extend_from_slice(data);
+    Message::new(b'R', body)
+}
+
+/// Tells a client that asked for 3.`minor` that kv speaks 3.0, and which
+/// protocol options it does not know.
+pub fn negotiate_protocol(unknown: &[String]) -> Message {
+    let mut body = 0u32.to_be_bytes().to_vec();
+    body.extend_from_slice(&(unknown.len() as u32).to_be_bytes());
+    for name in unknown {
+        put_cstr(&mut body, name.as_bytes());
+    }
+    Message::new(b'v', body)
+}
+
+/// The fields of an `ErrorResponse` or `NoticeResponse` as one line.
+pub fn error_text(body: &[u8]) -> String {
+    let mut message = String::new();
+    let mut code = String::new();
+    let mut pos = 0;
+    while let Some(&field) = body.get(pos) {
+        if field == 0 {
+            break;
+        }
+        let Some((value, next)) = cstr(body, pos + 1) else {
+            break;
+        };
+        match field {
+            b'M' => message = String::from_utf8_lossy(value).into_owned(),
+            b'C' => code = String::from_utf8_lossy(value).into_owned(),
+            _ => {}
+        }
+        pos = next;
+    }
+    if code.is_empty() {
+        message
+    } else {
+        format!("{message} (SQLSTATE {code})")
+    }
+}
+
+/// Replaces secrets in what the server sends, keeping each message's
+/// layout: values in rows, column names, error and notice fields,
+/// notifications, parameter values, command tags, COPY data and function
+/// results.
+pub fn scrub_backend(message: Message, scrubber: &Scrubber) -> Result<Message, String> {
+    let malformed = || "the server sent a malformed message".to_owned();
+    let body = &message.body;
+    let mut out = Vec::with_capacity(body.len());
+    match message.tag {
+        b'D' => {
+            let count = body.get(..2).ok_or_else(malformed)?;
+            out.extend_from_slice(count);
+            let mut pos = 2;
+            for _ in 0..u16::from_be_bytes([count[0], count[1]]) {
+                let len = body.get(pos..pos + 4).ok_or_else(malformed)?;
+                let len = i32::from_be_bytes([len[0], len[1], len[2], len[3]]);
+                pos += 4;
+                let Ok(len) = usize::try_from(len) else {
+                    out.extend_from_slice(&(-1i32).to_be_bytes());
+                    continue;
+                };
+                let value = body.get(pos..pos + len).ok_or_else(malformed)?;
+                let value = scrubber.scrub(value);
+                out.extend_from_slice(&(value.len() as i32).to_be_bytes());
+                out.extend_from_slice(&value);
+                pos += len;
+            }
+        }
+        b'T' => {
+            let count = body.get(..2).ok_or_else(malformed)?;
+            out.extend_from_slice(count);
+            let mut pos = 2;
+            for _ in 0..u16::from_be_bytes([count[0], count[1]]) {
+                let (name, next) = cstr(body, pos).ok_or_else(malformed)?;
+                put_cstr(&mut out, &scrubber.scrub(name));
+                out.extend_from_slice(body.get(next..next + 18).ok_or_else(malformed)?);
+                pos = next + 18;
+            }
+        }
+        b'E' | b'N' => {
+            let mut pos = 0;
+            while let Some(&field) = body.get(pos) {
+                if field == 0 {
+                    break;
+                }
+                let (value, next) = cstr(body, pos + 1).ok_or_else(malformed)?;
+                out.push(field);
+                put_cstr(&mut out, &scrubber.scrub(value));
+                pos = next;
+            }
+            out.push(0);
+        }
+        b'A' => {
+            out.extend_from_slice(body.get(..4).ok_or_else(malformed)?);
+            let (channel, next) = cstr(body, 4).ok_or_else(malformed)?;
+            let (payload, _) = cstr(body, next).ok_or_else(malformed)?;
+            put_cstr(&mut out, &scrubber.scrub(channel));
+            put_cstr(&mut out, &scrubber.scrub(payload));
+        }
+        b'S' => {
+            let (name, next) = cstr(body, 0).ok_or_else(malformed)?;
+            let (value, _) = cstr(body, next).ok_or_else(malformed)?;
+            put_cstr(&mut out, name);
+            put_cstr(&mut out, &scrubber.scrub(value));
+        }
+        b'C' => {
+            let (tag, _) = cstr(body, 0).ok_or_else(malformed)?;
+            put_cstr(&mut out, &scrubber.scrub(tag));
+        }
+        b'd' => out = scrubber.scrub(body),
+        b'V' => {
+            let len = body.get(..4).ok_or_else(malformed)?;
+            let len = i32::from_be_bytes([len[0], len[1], len[2], len[3]]);
+            match usize::try_from(len) {
+                Ok(len) => {
+                    let value = scrubber.scrub(body.get(4..4 + len).ok_or_else(malformed)?);
+                    out.extend_from_slice(&(value.len() as i32).to_be_bytes());
+                    out.extend_from_slice(&value);
+                }
+                Err(_) => out.extend_from_slice(&(-1i32).to_be_bytes()),
+            }
+        }
+        _ => return Ok(message),
+    }
+    Ok(Message::new(message.tag, out))
+}
+
+/// The value of a `ParameterStatus` message.
+pub fn parameter(message: &Message) -> Option<(String, String)> {
+    let (name, next) = cstr(&message.body, 0)?;
+    let (value, _) = cstr(&message.body, next)?;
+    Some((
+        String::from_utf8_lossy(name).into_owned(),
+        String::from_utf8_lossy(value).into_owned(),
+    ))
+}
+
+/// Checks what a client sends on a read-only session, message by message,
+/// with `pg_session_violation` on each simple query and each statement it
+/// prepares. In the extended protocol a batch runs until `Sync`, so once a
+/// portal that ends the transaction has been executed only `Sync` may
+/// follow. Fast-path function calls are refused: they could call
+/// `set_config`.
+#[derive(Default)]
+pub struct ReadOnlyGate {
+    statements: HashMap<Vec<u8>, bool>,
+    portals: HashMap<Vec<u8>, bool>,
+    ended: bool,
+}
+
+impl ReadOnlyGate {
+    /// `Ok(true)` when the message ends a batch: the server answers it
+    /// with `ReadyForQuery`.
+    pub fn check(&mut self, message: &Message) -> Result<bool, String> {
+        let body = &message.body;
+        let malformed = || "the client sent a malformed message".to_owned();
+        if self.ended && !matches!(message.tag, b'S' | b'H' | b'X') {
+            return Err(
+                "the handle is read-only, and kv refuses statements after COMMIT, END, \
+                 ROLLBACK or ABORT before the next Sync; send them separately"
+                    .into(),
+            );
+        }
+        match message.tag {
+            b'Q' => {
+                let (sql, _) = cstr(body, 0).ok_or_else(malformed)?;
+                pg_session_violation(&String::from_utf8_lossy(sql))?;
+                Ok(true)
+            }
+            b'P' => {
+                let (name, next) = cstr(body, 0).ok_or_else(malformed)?;
+                let (sql, _) = cstr(body, next).ok_or_else(malformed)?;
+                let ends = pg_session_violation(&String::from_utf8_lossy(sql))?;
+                self.statements.insert(name.to_vec(), ends);
+                Ok(false)
+            }
+            b'B' => {
+                let (portal, next) = cstr(body, 0).ok_or_else(malformed)?;
+                let (statement, _) = cstr(body, next).ok_or_else(malformed)?;
+                let ends = self.statements.get(statement).copied().unwrap_or(false);
+                self.portals.insert(portal.to_vec(), ends);
+                Ok(false)
+            }
+            b'E' => {
+                let (portal, _) = cstr(body, 0).ok_or_else(malformed)?;
+                self.ended = self.portals.get(portal).copied().unwrap_or(false);
+                Ok(false)
+            }
+            b'C' => {
+                let kind = body.first().ok_or_else(malformed)?;
+                let (name, _) = cstr(body, 1).ok_or_else(malformed)?;
+                match kind {
+                    b'S' => self.statements.remove(name),
+                    _ => self.portals.remove(name),
+                };
+                Ok(false)
+            }
+            b'S' => {
+                self.ended = false;
+                Ok(true)
+            }
+            b'F' => Err(
+                "the handle is read-only, and kv refuses fast-path function calls on read-only \
+                 handles"
+                    .into(),
+            ),
+            _ => Ok(false),
+        }
+    }
+}
+
+enum Ssl {
+    Disable,
+    Prefer,
+    Require,
+}
+
+/// Where a Postgres URL points, and how to log in.
+pub struct PgTarget {
+    /// The address to connect to, the name to check its certificate
+    /// against, and the port.
+    hosts: Vec<(String, String, u16)>,
+    user: String,
+    password: Option<Vec<u8>>,
+    pub dbname: String,
+    ssl: Ssl,
+    /// `options` from the URL.
+    pub options: Option<String>,
+}
+
+impl PgTarget {
+    pub fn parse(url: &str) -> Result<Self, String> {
+        use tokio_postgres::config::{Host, SslMode};
+        let config: tokio_postgres::Config = url
+            .parse()
+            .map_err(|_| "the handle's connection URL is not a valid Postgres URL".to_owned())?;
+        let ports = config.get_ports();
+        let addrs = config.get_hostaddrs();
+        let mut hosts = Vec::new();
+        for (i, host) in config.get_hosts().iter().enumerate() {
+            let port = ports.get(i).or(ports.first()).copied().unwrap_or(5432);
+            if let Host::Tcp(name) = host {
+                let address = addrs.get(i).map_or_else(|| name.clone(), |a| a.to_string());
+                hosts.push((address, name.clone(), port));
+            }
+        }
+        if config.get_hosts().is_empty() {
+            for (i, addr) in addrs.iter().enumerate() {
+                let port = ports.get(i).or(ports.first()).copied().unwrap_or(5432);
+                hosts.push((addr.to_string(), addr.to_string(), port));
+            }
+        }
+        if hosts.is_empty() {
+            return Err("db_connect needs a TCP host in the handle's URL".into());
+        }
+        let user = config
+            .get_user()
+            .ok_or("the handle's URL names no user")?
+            .to_owned();
+        let ssl = if postgres_requires_tls(url) {
+            Ssl::Require
+        } else {
+            match config.get_ssl_mode() {
+                SslMode::Disable => Ssl::Disable,
+                SslMode::Prefer => Ssl::Prefer,
+                _ => Ssl::Require,
+            }
+        };
+        Ok(Self {
+            hosts,
+            dbname: config.get_dbname().unwrap_or(&user).to_owned(),
+            user,
+            password: config.get_password().map(<[u8]>::to_vec),
+            ssl,
+            options: config.get_options().map(str::to_owned),
+        })
+    }
+}
+
+/// Connects to the first host that answers, logs in with `params` (other
+/// than `user` and `database`, which come from the URL) and reads up to the
+/// first `ReadyForQuery`. Returns the stream and what the server sent after
+/// logging in. Errors may name the host: scrub them.
+pub async fn connect(
+    target: &PgTarget,
+    params: &[(String, String)],
+) -> Result<(Buffered<Upstream>, Vec<Message>), String> {
+    let mut last = String::from("no host to connect to");
+    for (address, name, port) in &target.hosts {
+        match connect_to(target, address, name, *port, params).await {
+            Ok(connected) => return Ok(connected),
+            Err(e) => last = e,
+        }
+    }
+    Err(last)
+}
+
+async fn connect_to(
+    target: &PgTarget,
+    address: &str,
+    name: &str,
+    port: u16,
+    params: &[(String, String)],
+) -> Result<(Buffered<Upstream>, Vec<Message>), String> {
+    let failed = |e: io::Error| format!("could not connect to {name}:{port}: {e}");
+    let mut tcp = net::tcp(address, port).await.map_err(failed)?;
+    let stream = match target.ssl {
+        Ssl::Disable => Upstream::Plain(tcp),
+        Ssl::Prefer | Ssl::Require => {
+            let mut request = 8u32.to_be_bytes().to_vec();
+            request.extend_from_slice(&SSL_REQUEST.to_be_bytes());
+            tcp.write_all(&request).await.map_err(failed)?;
+            let mut answer = [0u8; 1];
+            tcp.read_exact(&mut answer).await.map_err(failed)?;
+            match (answer[0], &target.ssl) {
+                (b'S', _) => net::tls(tcp, name).await.map_err(failed)?,
+                (b'N', Ssl::Prefer) => Upstream::Plain(tcp),
+                (b'N', _) => {
+                    return Err(format!(
+                        "{name}:{port} does not offer TLS, and kv requires it for a remote server \
+                         (add sslmode=disable to the URL to connect without it)"
+                    ));
+                }
+                _ => return Err(format!("{name}:{port} answered the TLS request oddly")),
+            }
+        }
+    };
+    let mut conn = Buffered::new(stream);
+    let mut startup = PROTOCOL_3_0.to_be_bytes().to_vec();
+    let fixed = [("user", target.user.as_str()), ("database", &target.dbname)];
+    for (key, value) in fixed
+        .into_iter()
+        .chain(params.iter().map(|(k, v)| (k.as_str(), v.as_str())))
+    {
+        put_cstr(&mut startup, key.as_bytes());
+        put_cstr(&mut startup, value.as_bytes());
+    }
+    startup.push(0);
+    let mut packet = (startup.len() as u32 + 4).to_be_bytes().to_vec();
+    packet.extend_from_slice(&startup);
+    send(&mut conn, &packet).await?;
+    log_in(&mut conn, target).await?;
+
+    let mut after = Vec::new();
+    loop {
+        let message = recv(&mut conn).await?;
+        match message.tag {
+            b'E' => return Err(error_text(&message.body)),
+            b'Z' => {
+                after.push(message);
+                return Ok((conn, after));
+            }
+            _ => after.push(message),
+        }
+    }
+}
+
+async fn log_in(conn: &mut Buffered<Upstream>, target: &PgTarget) -> Result<(), String> {
+    let password = target.password.as_deref().unwrap_or_default();
+    let mut scram: Option<ScramSha256> = None;
+    loop {
+        let message = recv(conn).await?;
+        match message.tag {
+            b'E' => return Err(error_text(&message.body)),
+            b'R' => {}
+            _ => return Err("the server sent something unexpected while logging in".into()),
+        }
+        let body = &message.body;
+        let code = body
+            .get(..4)
+            .map(|c| u32::from_be_bytes([c[0], c[1], c[2], c[3]]))
+            .ok_or("the server sent a malformed message")?;
+        match code {
+            0 => return Ok(()),
+            3 => {
+                let mut reply = password.to_vec();
+                reply.push(0);
+                send(conn, &Message::new(b'p', reply).encode()).await?;
+            }
+            5 => {
+                let salt: [u8; 4] = body
+                    .get(4..8)
+                    .and_then(|s| s.try_into().ok())
+                    .ok_or("the server sent a malformed message")?;
+                let mut reply = md5_hash(target.user.as_bytes(), password, salt).into_bytes();
+                reply.push(0);
+                send(conn, &Message::new(b'p', reply).encode()).await?;
+            }
+            10 => {
+                let offered = body[4..]
+                    .split(|&b| b == 0)
+                    .any(|m| m == SCRAM_SHA_256.as_bytes());
+                if !offered {
+                    return Err("the server offers no login method kv supports".into());
+                }
+                let state = ScramSha256::new(password, ChannelBinding::unsupported());
+                let mut reply = Vec::new();
+                put_cstr(&mut reply, SCRAM_SHA_256.as_bytes());
+                reply.extend_from_slice(&(state.message().len() as i32).to_be_bytes());
+                reply.extend_from_slice(state.message());
+                send(conn, &Message::new(b'p', reply).encode()).await?;
+                scram = Some(state);
+            }
+            11 => {
+                let state = scram.as_mut().ok_or("the server's login is out of order")?;
+                state
+                    .update(&body[4..])
+                    .map_err(|e| format!("the login failed: {e}"))?;
+                send(conn, &Message::new(b'p', state.message().to_vec()).encode()).await?;
+            }
+            12 => {
+                let state = scram.as_mut().ok_or("the server's login is out of order")?;
+                state
+                    .finish(&body[4..])
+                    .map_err(|e| format!("the server's login proof is wrong: {e}"))?;
+            }
+            _ => return Err("the server asks for a login method kv does not support".into()),
+        }
+    }
+}
+
+async fn send(conn: &mut Buffered<Upstream>, bytes: &[u8]) -> Result<(), String> {
+    conn.get_mut()
+        .write_all(bytes)
+        .await
+        .map_err(|e| format!("the connection failed: {e}"))
+}
+
+async fn recv(conn: &mut Buffered<Upstream>) -> Result<Message, String> {
+    next_message(conn)
+        .await
+        .map_err(|e| format!("the connection failed: {e}"))?
+        .ok_or_else(|| "the server closed the connection".to_owned())
+}
diff --git a/crates/kv/src/daemon/state.rs b/crates/kv/src/daemon/state.rs
index e6596d7..affaa2d 100644
--- a/crates/kv/src/daemon/state.rs
+++ b/crates/kv/src/daemon/state.rs
@@ -799,6 +799,8 @@ impl Daemon {
             } else {
                 "auto"
             },
+            role_checks: self.role_checks.clone(),
+            role_stamp: self.role_checks.stamp(),
         }));
         if !ask {
             return job;
```

- [ ] **Step 4: Run the tests to watch them pass**

Run: `cargo test -p kv --test pgwire --test lease --test lease_live --test db_live`
Expected: PASS (needs Postgres 14 or later at `KV_TEST_POSTGRES_URL`).

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "Relay Postgres through db_connect leases, keeping read-only sessions read-only"
```

### Task 6: Docs and CI

**Files:**
- Modify: `.github/workflows/ci.yml`
- Modify: `README.md`
- Modify: `docs/superpowers/specs/2026-10-08-kv-llm-secrets-broker-design.md`

**Interfaces:**
- Consumes: Tasks 1-5.
- Produces: README "Databases" and tool list, spec sections 4, "Read-only enforcement", 5 (scrubber) and 6, and the CI `databases` job running `lease_live` too.

- [ ] **Step 1: Implement**

Apply with `git apply`:

```diff
diff --git a/.github/workflows/ci.yml b/.github/workflows/ci.yml
index 5734b74..17272f9 100644
--- a/.github/workflows/ci.yml
+++ b/.github/workflows/ci.yml
@@ -29,7 +29,8 @@ jobs:
       - run: cargo test --workspace
 
   databases:
-    # db_query against real servers; service containers run on Linux only.
+    # db_query and db_connect against real servers; service containers run on
+    # Linux only.
     runs-on: ubuntu-latest
     timeout-minutes: 20
     services:
@@ -55,4 +56,4 @@ jobs:
           persist-credentials: false
       - uses: dtolnay/rust-toolchain@stable
       - uses: Swatinem/rust-cache@v2
-      - run: cargo test -p kv --test db_live
+      - run: cargo test -p kv --test db_live --test lease_live
```

- [ ] **Step 2: Update the docs**

Apply with `git apply`:

````diff
diff --git a/README.md b/README.md
index 3cb1cde..ae2acb0 100644
--- a/README.md
+++ b/README.md
@@ -5,10 +5,10 @@ secrets (`prod-db`, `openrouter`, `github`) and the broker does the
 authenticated work, so API keys, database URLs and other credentials never
 show up in a chat transcript or in the model's context.
 
-Status: agents can make HTTP requests, run programs and query Postgres and
-Redis with your secrets over MCP, and `kv tui` approves `--mode ask` requests
-as they arrive. A local database proxy for tools that need a connection comes
-next.
+Status: agents can make HTTP requests, run programs, and query or connect to
+Postgres and Redis with your secrets over MCP, and `kv tui` approves
+`--mode ask` requests as they arrive. Touch ID and Windows Hello unlock and
+prebuilt binaries come next.
 
 ## Setup
 
@@ -24,13 +24,15 @@ kv add prod-db --kind postgres --read-only true   # prompts for the postgres://
 claude mcp add kv -- kv mcp   # or add `kv mcp` as a stdio server in any MCP client
 ```
 
-The agent then sees six tools:
+The agent then sees seven tools:
 
 - `list_handles`: names, kinds and policies, never values.
 - `http_request`: sends a request with the handle's credential attached.
 - `exec`: runs a program (never a shell) with an `env` handle's variables set.
 - `db_query`: runs SQL on a `postgres` handle or a command on a `redis`
   handle (see below).
+- `db_connect`: a connection URL on this machine for tools that need their own
+  connection, such as `psql` or a migration tool (see below).
 - `request_handle`: asks you to add a handle it needs (see below).
 - `status`: whether the vault is unlocked.
 
@@ -56,13 +58,23 @@ more statements and returns one result per statement, every value as text; a
 Redis command line such as `HGETALL user:1` returns the reply as JSON. Results
 stop at 256 KiB, and a query stops after 30 seconds unless the agent asks for
 up to 300. The database's address is scrubbed from results like the password,
-unless it is `localhost`. TLS certificates are checked against the system's
-trust store. For Postgres, `sslmode=disable` in the URL turns TLS off, and a
-remote server with no `sslmode` in its URL must use TLS; for Redis, use
-`rediss://`, and note that a URL ending in `#insecure` skips the certificate
-check. A Redis reply, or a
-single Postgres row, is held in memory whole before it is cut, so avoid
-commands such as `KEYS *` on very large keyspaces.
+unless it is `localhost`. TLS certificates are always checked against the
+system's trust store. For Postgres, `sslmode=disable` in the URL turns TLS off,
+and a remote server with no `sslmode` in its URL must use TLS; for Redis, use
+`rediss://` (kv refuses `#insecure`). A single Postgres row is held in memory
+whole before it is cut; a Redis reply is read only as far as the cap.
+
+`db_connect` returns a URL such as
+`postgres://kv:<token>@127.0.0.1:41823/app?sslmode=disable` for tools that
+need a connection of their own. The URL points at kv, holds a random lease
+token instead of the password, and works for 15 minutes unless the agent asks
+for up to an hour. kv checks the token, connects to the database with the real
+credentials, and passes traffic both ways, scrubbing what comes back as
+`db_query` does. When the lease expires, the vault locks or the handle
+changes, its connections close. At most 16 leases are open at once, with 16
+connections each, and no single message may be larger than 16 MiB. Query
+cancellation (Ctrl-C in `psql`) is not passed on, and Redis subscriptions,
+`MONITOR` and `CLIENT REPLY` are refused.
 
 With `--read-only true`:
 
@@ -78,6 +90,11 @@ With `--read-only true`:
   write server files or run programs, can create in a schema, or can insert,
   update, delete or truncate in any table, view or foreign table, column
   grants included.
+- Through `db_connect`, a read-only Postgres session needs PostgreSQL 14 or
+  later. kv refuses the same mentions, `DO` and `CALL`, but lets a
+  transaction end as the last statement of a query, and passes one query on
+  at a time: if the server reports that the session is no longer read-only,
+  kv closes it before the next query runs.
 
 ## Approving requests
 
@@ -154,8 +171,6 @@ audit log (`audit.jsonl`), without values.
 
 ## Planned for v1
 
-- `db_connect`: a local database proxy (Postgres, Redis) for tools that need a
-  connection, which connects upstream with the real credentials
 - Touch ID and Windows Hello unlock, and prebuilt binaries
 
 ## What kv protects against
diff --git a/docs/superpowers/specs/2026-10-08-kv-llm-secrets-broker-design.md b/docs/superpowers/specs/2026-10-08-kv-llm-secrets-broker-design.md
index ed6d455..7238ef4 100644
--- a/docs/superpowers/specs/2026-10-08-kv-llm-secrets-broker-design.md
+++ b/docs/superpowers/specs/2026-10-08-kv-llm-secrets-broker-design.md
@@ -208,7 +208,7 @@ returns values, the hostname inside a DB URL, or a secret's `base_url`.
 | `list_handles` | — | handles with kind, description, constraints |
 | `http_request` | handle, method, url, headers?, body? | status, headers, body (scrubbed, body capped at 256 KB) |
 | `db_query` | handle, query (SQL or Redis command), timeout? | Postgres: one result per statement, values as text; Redis: the reply as JSON (scrubbed, capped at 256 KB) |
-| `db_connect` | handle, ttl? | local connection URL with a lease token |
+| `db_connect` | handle, ttl_secs? | loopback connection URL with a lease token, its lifetime, warnings |
 | `exec` | handles[], argv[], cwd?, timeout? | exit code, stdout, stderr (scrubbed) |
 | `request_handle` | name, kind, description?, reason?, header?/template?/query_param?, base_url?, allowed_hosts?, env_vars?, allowed_cmds? | confirmation that the request waits in `kv tui` |
 | `status` | — | locked/unlocked, pending approvals |
@@ -283,24 +283,60 @@ A notification announces each request.
     secret comes back as the scrubbed string).
   - The timeout defaults to 30 s and may be at most 300 s; Postgres also gets
     it as `statement_timeout`, so the server stops an abandoned query.
-    Results are cut at 256 KB and marked `truncated`. A Redis reply, or one
-    Postgres row, is held in memory whole before it is cut.
+    Results are cut at 256 KB and marked `truncated`. One Postgres row is
+    held in memory whole before it is cut; kv speaks RESP itself and reads a
+    Redis reply only as far as the cap.
   - Commands that hold or change the connection (`SUBSCRIBE` and friends,
     `MONITOR`, `AUTH`, `HELLO`, `QUIT`, `RESET`, `SYNC`) are refused for every
-    Redis handle.
+    Redis handle. `#insecure` in a `rediss://` URL is refused, since kv always
+    checks certificates.
   - TLS certificates are always verified against the platform trust store,
     whatever `sslmode` says (`sslmode=disable` still turns TLS off). A
     Postgres URL that names no `sslmode` and a host other than loopback or a
     Unix socket gets `sslmode=require`, since `prefer` can be downgraded to
     plain text by an attacker on the network.
   - Connection URLs must use `postgres://`/`postgresql://` or
-    `redis://`/`rediss://`. The host is scrubbed like the password unless it
-    is loopback, and errors are scrubbed, since they can quote the query.
+    `redis://`/`rediss://`. Every host is scrubbed like the password unless it
+    is loopback, and errors are scrubbed, since they can quote the query. A
+    Postgres URL may list several hosts (`h1:5432,h2`) and name more in
+    `host=` and `hostaddr=`, and a password in `password=`; kv reads all of
+    them, though the `url` crate cannot parse such URLs.
 - **`db_connect`**: starts a loopback proxy on a random port and returns e.g.
-  `postgres://kv:<lease-token>@127.0.0.1:41823/app`. The lease token is
-  random, single-lease and expires with the TTL. The proxy authenticates the
-  client with the token, connects upstream with the real credentials, then
-  passes traffic through.
+  `postgres://kv:<lease-token>@127.0.0.1:41823/app?sslmode=disable` (or
+  `redis://kv:<lease-token>@127.0.0.1:41823/0`). The lease token is 256
+  random bits, belongs to one lease and is compared in constant time. The
+  proxy authenticates the client with the token (Postgres: a cleartext
+  password over loopback, after answering `N` to TLS requests; Redis: `AUTH`
+  or `HELLO ... AUTH`), connects upstream with the real credentials (TLS as
+  for `db_query`; Postgres logs in with SCRAM-SHA-256, MD5 or a password),
+  then relays traffic both ways, scrubbing what comes back. It is not a plain
+  pass-through: every message from the server is scrubbed in place (Postgres
+  row values, column names, error and notice fields, notifications,
+  parameter values, command tags, COPY data; Redis strings, errors, and any
+  number that matches a secret, which becomes a string).
+  - The TTL defaults to 900 s and may be at most 3600 s. A lease ends at its
+    expiry, when the vault locks, or when its handle is added, changed or
+    removed (as grants do); its listener closes and its connections are cut
+    (Postgres clients get `57P01`). The lease's place is taken when the
+    request is authorized, so a lock while it waits for approval ends it too.
+  - At most 16 leases are open at once (counting those waiting for
+    approval), with at most 16 connections each. A client has 30 s to log in,
+    and the server 20 s. Any single message larger than 16 MiB ends the
+    connection, since each is held whole while it is scrubbed.
+  - Leases follow the current scrubber, so a secret added while one is open
+    is scrubbed from then on.
+  - Postgres: the client must ask for the lease's database; `user` is
+    ignored, replication connections and query cancellation are not passed
+    on, and `_pq_.` protocol options are declined. Other startup parameters
+    pass through.
+  - Redis: commands must arrive as RESP arrays of strings. Replies are
+    written in the order of the commands, with kv's own errors in their
+    place; RESP3 push messages pass through. `AUTH`, `HELLO` with options,
+    `RESET`, subscriptions, `MONITOR`, `CLIENT REPLY` and replication
+    commands are refused on every lease.
+  - Each connection is audited when it closes, with how it ended (`closed`,
+    `wrong_token`, `policy_denied`, `lease_ended`, ...); the lease itself is
+    audited like other requests.
 - **`exec`**: argv array only, never a shell string. `sh`, `bash`, `cmd`,
   `powershell` are not allowed unless listed in `allowed_cmds`. Env vars from
   all listed handles are injected; output streams through the scrubber; the
@@ -325,7 +361,7 @@ A notification announces each request.
 ### Read-only enforcement
 
 - **Redis**: enforced. RESP is parsed and only an allow-list of read commands
-  is forwarded.
+  is forwarded, in `db_query` and through `db_connect`.
 - **Postgres**: best effort. Sessions are opened with
   `default_transaction_read_only=on`, and statements that change it
   (`SET ... transaction_read_only`, `BEGIN READ WRITE`, `SET SESSION
@@ -347,7 +383,25 @@ A notification announces each request.
   result and the TUI when a `read_only` secret uses a role with write access.
   `kv add` runs the check itself, with the URL it just read, so a slow
   database never holds up the daemon; `kv tui` relies on the first-use
-  check.
+  check. `db_connect` runs it before returning the URL and returns the
+  warning with it.
+- **Postgres through `db_connect`**: a session lasts many transactions, so
+  the proxy also watches the server. It needs PostgreSQL 14 or later, which
+  reports `default_transaction_read_only` at login and whenever it changes;
+  a read-only lease on an older server is refused at login. The proxy:
+  - adds `-c default_transaction_read_only=on` to the session's options and
+    refuses startup parameters that mention a way to change it;
+  - checks each simple query and each statement the client prepares as
+    `db_query` does, except that a statement ending the transaction is
+    allowed as the last one of a batch (a simple query, or the extended
+    protocol up to `Sync`); `DO`, `CALL` and `PREPARE TRANSACTION` are
+    refused, and so are fast-path function calls;
+  - passes one batch on at a time, waiting for the server's
+    `ReadyForQuery` before the next, and closes the session (`25006`) if the
+    server reports `default_transaction_read_only` other than `on` or starts
+    a COPY from the client. So a switch built at run time is caught before
+    any later batch runs, and nothing can follow the transaction it was
+    made in within the same batch.
 
 ## 5. Scrubbing, unlock, approval, audit, errors
 
@@ -360,7 +414,9 @@ A notification announces each request.
   secret changes.
 - Streaming: hold back `longest pattern − 1` bytes between chunks so secrets
   split across chunks are caught.
-- Matches are replaced with `[kv:<handle>]`.
+- Matches are replaced with `[kv:<handle>]`. Matching ignores ASCII case:
+  host names are case-insensitive, and a secret in another case is still a
+  secret.
 - Values shorter than 8 characters are not scrubbed (false positives);
   `kv add` warns about them.
 
@@ -459,7 +515,8 @@ or unscrubbed paths.
   - Exec: test helper binary prints the injected secret raw, base64 and hex;
     output must be scrubbed.
   - Postgres and Redis on real servers (Linux CI only, as GitHub Actions
-    service containers), including read-only enforcement. The tests read
+    service containers), including read-only enforcement, and `db_connect`
+    leases driven by ordinary clients (`tokio-postgres`, `redis`). The tests read
     `KV_TEST_POSTGRES_URL` and `KV_TEST_REDIS_URL` and skip without them,
     unless `KV_REQUIRE_DB_TESTS` is set, as CI sets it; locally any server
     will do.
````

- [ ] **Step 3: Run the tests to watch them pass**

Run: `cargo fmt --all --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace`
Expected: PASS, 365 tests with both servers set.

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "Document db_connect and run the lease tests in CI"
```
