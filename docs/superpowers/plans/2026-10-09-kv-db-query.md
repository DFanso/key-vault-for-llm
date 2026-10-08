# kv Plan 5a: db_query Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Agents run SQL on `postgres` handles and commands on `redis` handles through a `db_query` MCP tool, with read-only handles kept read-only, without ever seeing the connection URL.

**Architecture:** `db_query` follows `http_request` and `exec`: the daemon authorizes the request under its lock (kind, timeout, read-only guards, approval), then a `DbJob` runs outside the lock on a connection of its own (`tokio-postgres` with the simple query protocol and rustls, or `redis` with rustls), and the reply is scrubbed and capped. Pure checks (the Postgres read-only guard, Redis command splitting and the read allow-list) live in `kv-core::db`. The role check for read-only Postgres handles runs in `kv add` and on each handle's first query after unlock, and is shown in the reply, the overview and `kv tui`. Plan 5b (`db_connect` proxies) follows separately.

**Tech Stack:** Rust 2024 (MSRV 1.89), tokio, tokio-postgres 0.7 (`runtime`), tokio-postgres-rustls 0.14 (`aws-lc-rs`), rustls 0.23 (`aws_lc_rs`), rustls-platform-verifier 0.7, redis 1.7 (`tokio-rustls-comp`), futures-util 0.3, rmcp 3.5, ratatui 0.30.

**Spec:** `docs/superpowers/specs/2026-10-08-kv-llm-secrets-broker-design.md` (sections 3, 4 "db_query", "Read-only enforcement", 5, 6). Task 6 updates it with the decisions below.

## Global Constraints

- Builds on this Mac need `DEVELOPER_DIR=/Library/Developer/CommandLineTools` before every cargo command.
- Database tests read `KV_TEST_POSTGRES_URL` (a superuser) and `KV_TEST_REDIS_URL`; without them they print `skipped:` and pass, unless `KV_REQUIRE_DB_TESTS` is set (CI sets it). Local Postgres for this plan: `initdb -D /tmp/kvpg -U kv --auth=scram-sha-256 --pwfile=<(echo kv-test-password-123)` then `pg_ctl -D /tmp/kvpg -o "-p 54329 -k /tmp" -l /tmp/kvpg.log start`.
- No message type on the agent socket may carry a secret value; every string from a database (values, column names, errors) goes through the scrubber.
- `db_query` timeout: 30 s by default, 1 to 300 s; output capped at `MAX_OUTPUT_LEN` (256 KiB) and marked `truncated`.
- Connection URLs: `postgres://` or `postgresql://` for postgres handles, `redis://` or `rediss://` for redis handles. TLS certificates are always verified against the platform trust store.
- Read-only guards and the Redis never-run list are checked before approval, so the user is never asked about a request that would be refused.
- Commits as DFanso <leogavin123@outlook.com>, no AI attribution.
- `cargo fmt --all --check` and `cargo clippy --workspace --all-targets -- -D warnings` stay clean after every task.

## Review Focus

- A `rediss://` server with a valid public certificate: the Redis TLS path is not exercised by any test (CI's Redis is plain). Expect it to connect, and a self-signed one to fail with a scrubbed `upstream_error`.
- `sslmode=require` against a Postgres server with a self-signed certificate: kv verifies anyway and fails closed, which is stricter than libpq. The error must name the certificate problem without the host or password.
- A multi-statement query whose later statement fails: the earlier results are dropped and the whole call is an `upstream_error`. A reasonable person would accept this; check the message is scrubbed.
- The agent hangs up while a query runs: the query keeps running until it ends or times out (the server's `statement_timeout` stops it), and the result is discarded. Check nothing is written to the agent and the audit line still appears.
- A read-only handle whose role is changed in the database after the first query: the warning (or its absence) lasts until the vault locks or the handle changes. Acceptable; the spec says "first use after each unlock".

---

### Task 1: Database guards and host scrubbing in kv-core

**Files:**
- Create: `crates/kv-core/src/db.rs`
- Modify: `crates/kv-core/src/lib.rs`
- Modify: `crates/kv-core/src/secret.rs`
- Create: `crates/kv-core/tests/db.rs`
- Modify: `crates/kv-core/tests/secret.rs`

**Interfaces:**
- Consumes: nothing new.
- Produces: `kv_core::db::{pg_read_only_violation(&str) -> Option<&'static str>, split_command(&str) -> Result<Vec<Vec<u8>>, String>, check_redis(&[Vec<u8>], read_only: bool) -> Result<(), RedisRefusal>, RedisRefusal::{Never(String), NotRead(String)}}` (`RedisRefusal: Display`); `Secret::sensitive_values()` now also yields a non-loopback database host.

- [ ] **Step 1: Write the failing tests**

Apply with `git apply` from the repository root:

```diff
diff --git a/crates/kv-core/tests/db.rs b/crates/kv-core/tests/db.rs
new file mode 100644
index 0000000..17fe974
--- /dev/null
+++ b/crates/kv-core/tests/db.rs
@@ -0,0 +1,128 @@
+use kv_core::db::{RedisRefusal, check_redis, pg_read_only_violation, split_command};
+
+fn args(line: &str) -> Vec<Vec<u8>> {
+    split_command(line).unwrap()
+}
+
+#[test]
+fn reads_pass_the_postgres_read_only_guard() {
+    for sql in [
+        "select * from users where id = 1",
+        "SELECT count(*) FROM orders; SELECT now()",
+        "with t as (select 1) select * from t",
+        "EXPLAIN ANALYZE SELECT 1",
+        "select 'do not' as note",
+        "select $1::text",
+        "show search_path",
+    ] {
+        assert_eq!(pg_read_only_violation(sql), None, "{sql}");
+    }
+}
+
+#[test]
+fn changing_read_only_mode_is_refused_however_it_is_written() {
+    for sql in [
+        "SET transaction_read_only = off",
+        "set session characteristics as transaction read write",
+        "BEGIN READ WRITE; delete from users",
+        "start transaction read write",
+        "BEGIN READ/**/WRITE",
+        "begin read -- comment\n write",
+        "SET default_transaction_read_only TO off",
+        "SELECT set_config('default_transaction_read_only', 'off', false)",
+        "SET \"transaction_read_only\" = off",
+        "SET U&\"transaction\\005fread\\005fonly\" = off",
+        "reset default_transaction_read_only",
+        "SET DEFAULT_TRANSACTION_ISOLATION = serializable",
+        "select 1; DO $$ BEGIN EXECUTE 'x'; END $$",
+        "do 'begin null; end'",
+    ] {
+        assert!(pg_read_only_violation(sql).is_some(), "{sql}");
+    }
+}
+
+#[test]
+fn comments_and_quotes_cannot_hide_a_statement() {
+    // A `--` inside a string is not a comment, so what follows still counts.
+    assert!(pg_read_only_violation("select '--'; begin read write").is_some());
+    assert!(pg_read_only_violation("select $tag$ -- $tag$; begin read write").is_some());
+    assert!(pg_read_only_violation("select e'\\' --'; begin read write").is_some());
+    assert!(pg_read_only_violation("select /* /* nested */ */ 1; begin read write").is_some());
+}
+
+#[test]
+fn redis_commands_split_like_redis_cli() {
+    assert_eq!(args("GET user:1"), [b"GET".to_vec(), b"user:1".to_vec()]);
+    assert_eq!(
+        args(r#"  set "a b" 'x y'  "#),
+        [b"set".to_vec(), b"a b".to_vec(), b"x y".to_vec()]
+    );
+    assert_eq!(
+        args(r#"echo "line\nnext \x41\"""#),
+        [b"echo".to_vec(), b"line\nnext A\"".to_vec()]
+    );
+    assert_eq!(args(r"get 'a\'b'"), [b"get".to_vec(), b"a'b".to_vec()]);
+    for bad in [
+        "",
+        "   ",
+        r#"get "open"#,
+        r#"get "a"b"#,
+        "get 'x",
+        "get 'a''b'",
+    ] {
+        assert!(split_command(bad).is_err(), "{bad:?}");
+    }
+}
+
+#[test]
+fn a_read_only_redis_handle_runs_only_read_commands() {
+    for line in [
+        "GET k",
+        "hgetall h",
+        "SCAN 0 MATCH user:* COUNT 100",
+        "object encoding k",
+        "MEMORY USAGE k",
+        "ping",
+    ] {
+        assert_eq!(check_redis(&args(line), true), Ok(()), "{line}");
+    }
+    for line in [
+        "SET k v",
+        "DEL k",
+        "flushall",
+        "EVAL 'return 1' 0",
+        "CONFIG GET requirepass",
+        "OBJECT HELP",
+        "SORT k STORE out",
+    ] {
+        assert!(
+            matches!(
+                check_redis(&args(line), true),
+                Err(RedisRefusal::NotRead(_))
+            ),
+            "{line}"
+        );
+    }
+    assert_eq!(check_redis(&args("SET k v"), false), Ok(()));
+}
+
+#[test]
+fn commands_that_hold_the_connection_are_never_run() {
+    for line in [
+        "SUBSCRIBE news",
+        "monitor",
+        "AUTH user pass",
+        "HELLO 3",
+        "quit",
+    ] {
+        for read_only in [true, false] {
+            assert!(
+                matches!(
+                    check_redis(&args(line), read_only),
+                    Err(RedisRefusal::Never(_))
+                ),
+                "{line}"
+            );
+        }
+    }
+}
diff --git a/crates/kv-core/tests/secret.rs b/crates/kv-core/tests/secret.rs
index fab9d52..c101a8a 100644
--- a/crates/kv-core/tests/secret.rs
+++ b/crates/kv-core/tests/secret.rs
@@ -186,3 +186,26 @@ fn a_base_url_is_scrubbed_and_never_shown_to_agents() {
     assert!(!json.contains("dokploy"), "{json}");
     assert!(!http_secret().info().takes_path);
 }
+
+#[test]
+fn a_database_host_is_scrubbed_unless_it_is_loopback() {
+    let values = |url: &str| -> Vec<String> {
+        pg_secret(url)
+            .sensitive_values()
+            .iter()
+            .map(|v| v.to_string())
+            .collect()
+    };
+    assert!(
+        values("postgres://app:pw-0123456789@kyc.postgres.database.azure.com/app")
+            .contains(&"kyc.postgres.database.azure.com".to_string())
+    );
+    for url in [
+        "postgres://app:pw-0123456789@localhost/app",
+        "postgres://app:pw-0123456789@127.0.0.1:5432/app",
+        "postgres://app:pw-0123456789@[::1]/app",
+    ] {
+        let host = url::Url::parse(url).unwrap().host_str().unwrap().to_owned();
+        assert!(!values(url).contains(&host), "{url}");
+    }
+}
```

- [ ] **Step 2: Run the tests to watch them fail**

Run: `DEVELOPER_DIR=/Library/Developer/CommandLineTools cargo test -p kv-core --test db --test secret`
Expected: FAIL: `unresolved imports kv_core::db::...` (the module does not exist yet).

- [ ] **Step 3: Implement**

Apply with `git apply`:

```diff
diff --git a/crates/kv-core/src/db.rs b/crates/kv-core/src/db.rs
new file mode 100644
index 0000000..d5d6ac8
--- /dev/null
+++ b/crates/kv-core/src/db.rs
@@ -0,0 +1,393 @@
+//! Checks on what `db_query` sends: the best-effort guard that keeps a
+//! read-only Postgres session read-only, and how a Redis command line is
+//! split and which commands run.
+
+/// Why `sql` may not run on a read-only Postgres handle, or `None`.
+///
+/// Sessions for read-only handles start with
+/// `default_transaction_read_only=on`; this refuses statements that would
+/// switch that off, and `DO` blocks, which can build such a statement at
+/// run time. Comments are read as spaces, as Postgres reads them, and
+/// quoted text is kept, so a mention inside a string is refused too: when
+/// in doubt it says no. The real guarantee is a role without write
+/// privileges.
+pub fn pg_read_only_violation(sql: &str) -> Option<&'static str> {
+    let text = normalize_sql(sql);
+    let changes_mode = ["read_only", "read write", "characteristics", "set_config"]
+        .iter()
+        .any(|word| text.contains(word))
+        || text.contains("default_transaction")
+        || text.contains("u&");
+    if changes_mode {
+        return Some(
+            "the handle is read-only, and this query mentions a way to change that; kv refuses it",
+        );
+    }
+    let starts_do = text.split(';').any(|statement| {
+        let statement = statement.trim_start();
+        statement.strip_prefix("do").is_some_and(|rest| {
+            !rest
+                .chars()
+                .next()
+                .is_some_and(|c| c.is_alphanumeric() || c == '_')
+        })
+    });
+    if starts_do {
+        return Some("the handle is read-only, and kv refuses DO blocks on read-only handles");
+    }
+    None
+}
+
+/// Lowercases `sql`, turns comments into a space and collapses whitespace,
+/// keeping quoted text (strings, quoted identifiers, dollar quotes) as it
+/// is, so a comment marker inside quotes is not read as a comment.
+fn normalize_sql(sql: &str) -> String {
+    let chars: Vec<char> = sql.chars().collect();
+    let mut out = String::with_capacity(sql.len());
+    let mut i = 0;
+    let push_space = |out: &mut String| {
+        if !out.ends_with(' ') {
+            out.push(' ');
+        }
+    };
+    while i < chars.len() {
+        let c = chars[i];
+        let next = chars.get(i + 1).copied();
+        match c {
+            '-' if next == Some('-') => {
+                while i < chars.len() && chars[i] != '\n' {
+                    i += 1;
+                }
+                push_space(&mut out);
+            }
+            '/' if next == Some('*') => {
+                let mut depth = 0;
+                while i < chars.len() {
+                    if chars[i] == '/' && chars.get(i + 1) == Some(&'*') {
+                        depth += 1;
+                        i += 2;
+                    } else if chars[i] == '*' && chars.get(i + 1) == Some(&'/') {
+                        depth -= 1;
+                        i += 2;
+                        if depth == 0 {
+                            break;
+                        }
+                    } else {
+                        i += 1;
+                    }
+                }
+                push_space(&mut out);
+            }
+            '\'' | '"' => {
+                // E'...' strings take backslash escapes.
+                let escapes = c == '\''
+                    && i > 0
+                    && matches!(chars[i - 1], 'e' | 'E')
+                    && (i < 2 || !(chars[i - 2].is_alphanumeric() || chars[i - 2] == '_'));
+                out.push(c);
+                i += 1;
+                while i < chars.len() {
+                    let d = chars[i];
+                    if escapes && d == '\\' && i + 1 < chars.len() {
+                        out.extend(chars[i..i + 2].iter().flat_map(|c| c.to_lowercase()));
+                        i += 2;
+                        continue;
+                    }
+                    out.extend(d.to_lowercase());
+                    i += 1;
+                    if d == c {
+                        // A doubled quote is a quote inside the text.
+                        if chars.get(i) == Some(&c) {
+                            out.push(c);
+                            i += 1;
+                            continue;
+                        }
+                        break;
+                    }
+                }
+            }
+            '$' => match dollar_tag(&chars[i..]) {
+                Some(tag) => {
+                    let tag: Vec<char> = tag.chars().collect();
+                    out.extend(tag.iter().flat_map(|c| c.to_lowercase()));
+                    i += tag.len();
+                    while i < chars.len() && !chars[i..].starts_with(&tag) {
+                        out.extend(chars[i].to_lowercase());
+                        i += 1;
+                    }
+                    out.extend(tag.iter().flat_map(|c| c.to_lowercase()));
+                    i += tag.len();
+                }
+                None => {
+                    out.push('$');
+                    i += 1;
+                }
+            },
+            c if c.is_whitespace() => {
+                push_space(&mut out);
+                i += 1;
+            }
+            c => {
+                out.extend(c.to_lowercase());
+                i += 1;
+            }
+        }
+    }
+    out
+}
+
+/// The `$tag$` opening a dollar-quoted string at the start of `chars`. Not
+/// `$1`: a tag never starts with a digit.
+fn dollar_tag(chars: &[char]) -> Option<String> {
+    let mut end = 1;
+    while end < chars.len() && chars[end] != '$' {
+        let c = chars[end];
+        let ok = c == '_' || c.is_alphabetic() || (end > 1 && c.is_ascii_digit());
+        if !ok {
+            return None;
+        }
+        end += 1;
+    }
+    (end < chars.len()).then(|| chars[..=end].iter().collect())
+}
+
+/// Splits a Redis command line the way `redis-cli` does: words separated by
+/// spaces; `"..."` takes `\n`, `\r`, `\t`, `\b`, `\a`, `\\`, `\"` and
+/// `\xHH`; `'...'` takes only `\'`. A closing quote must end the word.
+pub fn split_command(line: &str) -> Result<Vec<Vec<u8>>, String> {
+    let bytes = line.as_bytes();
+    let mut args = Vec::new();
+    let mut i = 0;
+    loop {
+        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
+            i += 1;
+        }
+        if i == bytes.len() {
+            break;
+        }
+        let mut arg = Vec::new();
+        let quote = match bytes[i] {
+            q @ (b'"' | b'\'') => {
+                i += 1;
+                Some(q)
+            }
+            _ => None,
+        };
+        loop {
+            let Some(&b) = bytes.get(i) else {
+                if quote.is_some() {
+                    return Err("a quote is not closed".into());
+                }
+                break;
+            };
+            match quote {
+                None if b.is_ascii_whitespace() => break,
+                None => {
+                    arg.push(b);
+                    i += 1;
+                }
+                Some(q) if b == q => {
+                    i += 1;
+                    if bytes.get(i).is_some_and(|b| !b.is_ascii_whitespace()) {
+                        return Err("a closing quote must be followed by a space".into());
+                    }
+                    break;
+                }
+                Some(b'"') if b == b'\\' && i + 1 < bytes.len() => {
+                    let e = bytes[i + 1];
+                    let hex = bytes
+                        .get(i + 2..i + 4)
+                        .and_then(|h| std::str::from_utf8(h).ok())
+                        .and_then(|h| u8::from_str_radix(h, 16).ok());
+                    match (e, hex) {
+                        (b'x', Some(value)) => {
+                            arg.push(value);
+                            i += 4;
+                            continue;
+                        }
+                        (b'n', _) => arg.push(b'\n'),
+                        (b'r', _) => arg.push(b'\r'),
+                        (b't', _) => arg.push(b'\t'),
+                        (b'b', _) => arg.push(8),
+                        (b'a', _) => arg.push(7),
+                        (other, _) => arg.push(other),
+                    }
+                    i += 2;
+                }
+                Some(_) if b == b'\\' && bytes.get(i + 1) == Some(&b'\'') => {
+                    arg.push(b'\'');
+                    i += 2;
+                }
+                Some(_) => {
+                    arg.push(b);
+                    i += 1;
+                }
+            }
+        }
+        args.push(arg);
+    }
+    if args.is_empty() {
+        return Err("the command is empty".into());
+    }
+    Ok(args)
+}
+
+/// Why a Redis command is not run.
+#[derive(Clone, Debug, PartialEq, Eq)]
+pub enum RedisRefusal {
+    /// It holds or changes the connection (subscriptions, `MONITOR`,
+    /// `AUTH`), which a one-shot query cannot use.
+    Never(String),
+    /// The handle is read-only and this is not a read command.
+    NotRead(String),
+}
+
+impl std::fmt::Display for RedisRefusal {
+    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
+        match self {
+            Self::Never(command) => write!(
+                f,
+                "{command} holds or changes the connection, which db_query cannot do"
+            ),
+            Self::NotRead(command) => write!(
+                f,
+                "{command} is not a read command, and the handle is read-only"
+            ),
+        }
+    }
+}
+
+/// Commands that hold or change the connection.
+const NEVER: &[&str] = &[
+    "AUTH",
+    "HELLO",
+    "MONITOR",
+    "PSUBSCRIBE",
+    "PSYNC",
+    "PUNSUBSCRIBE",
+    "QUIT",
+    "RESET",
+    "SSUBSCRIBE",
+    "SUBSCRIBE",
+    "SUNSUBSCRIBE",
+    "SYNC",
+    "UNSUBSCRIBE",
+];
+
+/// Commands that only read. Ones with subcommands are in `READ_SUBCOMMANDS`.
+const READ: &[&str] = &[
+    "BITCOUNT",
+    "BITFIELD_RO",
+    "BITPOS",
+    "DBSIZE",
+    "ECHO",
+    "EXISTS",
+    "EXPIRETIME",
+    "GEODIST",
+    "GEOHASH",
+    "GEOPOS",
+    "GEORADIUSBYMEMBER_RO",
+    "GEORADIUS_RO",
+    "GEOSEARCH",
+    "GET",
+    "GETBIT",
+    "GETRANGE",
+    "HEXISTS",
+    "HGET",
+    "HGETALL",
+    "HKEYS",
+    "HLEN",
+    "HMGET",
+    "HRANDFIELD",
+    "HSCAN",
+    "HSTRLEN",
+    "HVALS",
+    "INFO",
+    "KEYS",
+    "LASTSAVE",
+    "LCS",
+    "LINDEX",
+    "LLEN",
+    "LPOS",
+    "LRANGE",
+    "MGET",
+    "PEXPIRETIME",
+    "PFCOUNT",
+    "PING",
+    "PTTL",
+    "RANDOMKEY",
+    "SCAN",
+    "SCARD",
+    "SDIFF",
+    "SINTER",
+    "SINTERCARD",
+    "SISMEMBER",
+    "SMEMBERS",
+    "SMISMEMBER",
+    "SORT_RO",
+    "SRANDMEMBER",
+    "SSCAN",
+    "STRLEN",
+    "SUBSTR",
+    "SUNION",
+    "TIME",
+    "TTL",
+    "TYPE",
+    "XLEN",
+    "XPENDING",
+    "XRANGE",
+    "XREAD",
+    "XREVRANGE",
+    "ZCARD",
+    "ZCOUNT",
+    "ZDIFF",
+    "ZINTER",
+    "ZINTERCARD",
+    "ZLEXCOUNT",
+    "ZMSCORE",
+    "ZRANDMEMBER",
+    "ZRANGE",
+    "ZRANGEBYLEX",
+    "ZRANGEBYSCORE",
+    "ZRANK",
+    "ZREVRANGE",
+    "ZREVRANGEBYLEX",
+    "ZREVRANGEBYSCORE",
+    "ZREVRANK",
+    "ZSCAN",
+    "ZSCORE",
+    "ZUNION",
+];
+
+const READ_SUBCOMMANDS: &[(&str, &[&str])] = &[
+    ("MEMORY", &["USAGE"]),
+    ("OBJECT", &["ENCODING", "FREQ", "IDLETIME", "REFCOUNT"]),
+    ("XINFO", &["CONSUMERS", "GROUPS", "STREAM"]),
+];
+
+/// Whether `args` (a split command line) may run on a handle.
+pub fn check_redis(args: &[Vec<u8>], read_only: bool) -> Result<(), RedisRefusal> {
+    let word = |i: usize| {
+        args.get(i)
+            .map(|a| String::from_utf8_lossy(a).to_ascii_uppercase())
+            .unwrap_or_default()
+    };
+    let command = word(0);
+    if NEVER.contains(&command.as_str()) {
+        return Err(RedisRefusal::Never(command));
+    }
+    if !read_only || READ.contains(&command.as_str()) {
+        return Ok(());
+    }
+    let sub = word(1);
+    let reads = READ_SUBCOMMANDS
+        .iter()
+        .any(|(name, subs)| *name == command && subs.contains(&sub.as_str()));
+    if reads {
+        Ok(())
+    } else if READ_SUBCOMMANDS.iter().any(|(name, _)| *name == command) {
+        Err(RedisRefusal::NotRead(format!("{command} {sub}")))
+    } else {
+        Err(RedisRefusal::NotRead(command))
+    }
+}
diff --git a/crates/kv-core/src/lib.rs b/crates/kv-core/src/lib.rs
index ad0d9ba..44c9fe1 100644
--- a/crates/kv-core/src/lib.rs
+++ b/crates/kv-core/src/lib.rs
@@ -2,6 +2,7 @@
 //! output scrubbing. Nothing here does network or socket I/O.
 
 pub mod crypto;
+pub mod db;
 pub mod error;
 pub mod policy;
 pub mod proto;
diff --git a/crates/kv-core/src/secret.rs b/crates/kv-core/src/secret.rs
index f679670..9a3db87 100644
--- a/crates/kv-core/src/secret.rs
+++ b/crates/kv-core/src/secret.rs
@@ -164,8 +164,9 @@ impl Secret {
     }
 
     /// Every string that must never appear in output: the token or URL, for
-    /// connection URLs the password both as written and percent-decoded, and
-    /// for an http `base_url` the URL and its host.
+    /// connection URLs the password both as written and percent-decoded and
+    /// the host unless it is loopback, and for an http `base_url` the URL
+    /// and its host.
     pub fn sensitive_values(&self) -> Vec<Zeroizing<String>> {
         let mut out = Vec::new();
         match &self.value {
@@ -185,7 +186,13 @@ impl Secret {
             }
             SecretValue::Postgres { url } | SecretValue::Redis { url } => {
                 out.push(Zeroizing::new(url.expose().to_owned()));
-                if let Ok(parsed) = url::Url::parse(url.expose())
+                let parsed = url::Url::parse(url.expose()).ok();
+                if let Some(host) = parsed.as_ref().and_then(url::Url::host)
+                    && !is_loopback(&host)
+                {
+                    out.push(Zeroizing::new(host.to_string()));
+                }
+                if let Some(parsed) = &parsed
                     && let Some(password) = parsed.password()
                 {
                     out.push(Zeroizing::new(password.to_owned()));
@@ -203,6 +210,22 @@ impl Secret {
     }
 }
 
+/// `localhost` and loopback addresses say nothing about where a database
+/// lives, and scrubbing them would mangle ordinary output. In `postgres://`
+/// and `redis://` URLs an IPv4 address arrives as a domain name.
+fn is_loopback(host: &url::Host<&str>) -> bool {
+    match host {
+        url::Host::Domain(name) => {
+            name.eq_ignore_ascii_case("localhost")
+                || name
+                    .parse::<std::net::IpAddr>()
+                    .is_ok_and(|ip| ip.is_loopback())
+        }
+        url::Host::Ipv4(ip) => ip.is_loopback(),
+        url::Host::Ipv6(ip) => ip.is_loopback(),
+    }
+}
+
 /// Handle names: 1-63 chars of `[a-z0-9_-]`, starting with `[a-z0-9]`.
 pub fn validate_handle(name: &str) -> Result<(), VaultError> {
     let mut chars = name.chars();
```

- [ ] **Step 4: Run the tests to watch them pass**

Run: `DEVELOPER_DIR=/Library/Developer/CommandLineTools cargo test -p kv-core`
Expected: PASS, including 6 tests in `tests/db.rs` and `a_database_host_is_scrubbed_unless_it_is_loopback`.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "Database guards and host scrubbing in kv-core"
```

### Task 2: db_query in the daemon

**Files:**
- Modify: `Cargo.lock`
- Modify: `crates/kv-core/src/proto.rs`
- Modify: `crates/kv-core/tests/proto.rs`
- Modify: `crates/kv/Cargo.toml`
- Modify: `crates/kv/src/broker.rs`
- Create: `crates/kv/src/broker/db.rs`
- Modify: `crates/kv/src/daemon/server.rs`
- Modify: `crates/kv/src/daemon/state.rs`
- Modify: `crates/kv/tests/approve.rs`
- Modify: `crates/kv/tests/common/mod.rs`
- Create: `crates/kv/tests/db.rs`
- Create: `crates/kv/tests/db_live.rs`
- Modify: `crates/kv/tests/state.rs`
- Modify: `crates/kv/tests/tui.rs`
- Modify: `crates/kv/tests/tui_edit.rs`
- Modify: `crates/kv/tests/tui_requests.rs`

**Interfaces:**
- Consumes: Task 1's `pg_read_only_violation`, `split_command`, `check_redis`, `RedisRefusal`.
- Produces: `kv_core::proto::{DbCall { handle, query, timeout_secs: Option<u64> }, RowsReply { results: Vec<ResultSet>, truncated, warnings: Vec<String> }, ResultSet { columns, rows: Vec<Vec<Option<String>>>, rows_affected: Option<u64> }, RedisReply { value: serde_json::Value, truncated }}`; `AgentRequest::DbQuery(DbCall)`; `AgentResponse::{Rows(RowsReply), Redis(RedisReply)}`; `Overview.role_warnings: BTreeMap<String, String>`.
- Produces: `kv::broker::DbJob { secret, call, timeout, scrubber, audit, started, decision, role_checks }`, `kv::broker::RoleChecks` (`is_checked`, `record`, `forget`, `clear`, `warnings`), `kv::broker::db::run(DbJob) -> AgentResponse`, private `connect(url, options, &Scrubber)` and `role_warning(handle)` used by Task 3; `kv::daemon::Prepared::Db(Box<DbJob>)`.
- Test helpers in `tests/common`: `Fixture::db(DbCall)`, `postgres(name, url, read_only, mode)`, `redis(...)`, `query(handle, query)`.

- [ ] **Step 1: Write the failing tests**

Apply with `git apply` from the repository root:

```diff
diff --git a/crates/kv-core/tests/proto.rs b/crates/kv-core/tests/proto.rs
index 4baf7a8..4cd46cd 100644
--- a/crates/kv-core/tests/proto.rs
+++ b/crates/kv-core/tests/proto.rs
@@ -4,8 +4,8 @@ use std::time::Duration;
 use kv_core::policy::{Mode, Policy};
 use kv_core::proto::{
     AgentErrorCode, AgentRequest, AgentResponse, ControlCommand, ControlRequest, ControlResponse,
-    ExecCall, ExecReply, HttpReply, MAX_FRAME_LEN, MAX_OUTPUT_LEN, PolicyPatch, SessionInfo,
-    Status, Verdict,
+    DbCall, ExecCall, ExecReply, HttpReply, MAX_FRAME_LEN, MAX_OUTPUT_LEN, Overview, PolicyPatch,
+    RedisReply, ResultSet, RowsReply, SessionInfo, Status, Verdict,
 };
 use kv_core::secret::{AuthPlacement, Secret, SecretText, SecretValue};
 
@@ -339,3 +339,52 @@ fn a_handle_request_has_defaults_and_no_place_for_a_value() {
         );
     }
 }
+
+#[test]
+fn a_db_query_is_a_flat_tagged_object_with_an_optional_timeout() {
+    let request: AgentRequest =
+        serde_json::from_str(r#"{"type":"db_query","handle":"prod-db","query":"select 1"}"#)
+            .unwrap();
+    assert_eq!(
+        request,
+        AgentRequest::DbQuery(DbCall {
+            handle: "prod-db".into(),
+            query: "select 1".into(),
+            timeout_secs: None,
+        })
+    );
+}
+
+#[test]
+fn database_replies_round_trip() {
+    for response in [
+        AgentResponse::Rows(RowsReply {
+            results: vec![ResultSet {
+                columns: vec!["id".into(), "email".into()],
+                rows: vec![vec![Some("1".into()), None]],
+                rows_affected: Some(1),
+            }],
+            truncated: false,
+            warnings: vec!["the role can write".into()],
+        }),
+        AgentResponse::Redis(RedisReply {
+            value: serde_json::json!(["a", 1, null]),
+            truncated: true,
+        }),
+    ] {
+        let json = serde_json::to_string(&response).unwrap();
+        assert_eq!(
+            serde_json::from_str::<AgentResponse>(&json).unwrap(),
+            response
+        );
+    }
+}
+
+#[test]
+fn an_overview_from_before_role_warnings_still_parses() {
+    let overview: Overview = serde_json::from_str(
+        r#"{"status":{"vault_exists":true,"locked":false,"handle_count":0,"locks_in_secs":null},"handles":[]}"#,
+    )
+    .unwrap();
+    assert!(overview.role_warnings.is_empty());
+}
diff --git a/crates/kv/tests/approve.rs b/crates/kv/tests/approve.rs
index 6f19b74..4203b9f 100644
--- a/crates/kv/tests/approve.rs
+++ b/crates/kv/tests/approve.rs
@@ -28,6 +28,7 @@ fn job_decision(prepared: Prepared) -> &'static str {
     match prepared {
         Prepared::Http(job) => job.decision,
         Prepared::Exec(job) => job.decision,
+        Prepared::Db(job) => job.decision,
         Prepared::Reply(reply) => panic!("expected a job, got {reply:?}"),
         Prepared::Wait(_) => panic!("expected a job, got a wait"),
     }
diff --git a/crates/kv/tests/common/mod.rs b/crates/kv/tests/common/mod.rs
index e9ce6d4..31fb0f8 100644
--- a/crates/kv/tests/common/mod.rs
+++ b/crates/kv/tests/common/mod.rs
@@ -7,12 +7,12 @@ use std::path::PathBuf;
 use std::time::Instant;
 
 use kv::audit::Audit;
-use kv::broker::{ExecJob, HttpJob};
+use kv::broker::{DbJob, ExecJob, HttpJob};
 use kv::daemon::{Daemon, Prepared, Settings, Waiting};
 use kv_core::policy::{Mode, Policy};
 use kv_core::proto::{
     AgentErrorCode, AgentRequest, AgentResponse, ControlCommand, ControlRequest, ControlResponse,
-    ExecCall, HttpCall, Overview, SessionInfo, Verdict,
+    DbCall, ExecCall, HttpCall, Overview, SessionInfo, Verdict,
 };
 use kv_core::secret::{AuthPlacement, Secret, SecretText, SecretValue};
 use tempfile::TempDir;
@@ -76,6 +76,7 @@ impl Fixture {
             Prepared::Reply(AgentResponse::Error { code, message }) => Err((code, message)),
             Prepared::Reply(other) => panic!("unexpected reply {other:?}"),
             Prepared::Exec(_) => panic!("unexpected exec job"),
+            Prepared::Db(_) => panic!("unexpected db job"),
             Prepared::Wait(_) => panic!("unexpected wait for approval"),
         }
     }
@@ -86,6 +87,17 @@ impl Fixture {
             Prepared::Reply(AgentResponse::Error { code, message }) => Err((code, message)),
             Prepared::Reply(other) => panic!("unexpected reply {other:?}"),
             Prepared::Http(_) => panic!("unexpected http job"),
+            Prepared::Db(_) => panic!("unexpected db job"),
+            Prepared::Wait(_) => panic!("unexpected wait for approval"),
+        }
+    }
+
+    pub fn db(&mut self, call: DbCall) -> Result<DbJob, (AgentErrorCode, String)> {
+        match self.prepare(AgentRequest::DbQuery(call)) {
+            Prepared::Db(job) => Ok(*job),
+            Prepared::Reply(AgentResponse::Error { code, message }) => Err((code, message)),
+            Prepared::Reply(other) => panic!("unexpected reply {other:?}"),
+            Prepared::Http(_) | Prepared::Exec(_) => panic!("unexpected job"),
             Prepared::Wait(_) => panic!("unexpected wait for approval"),
         }
     }
@@ -101,7 +113,9 @@ impl Fixture {
         match self.daemon.prepare_in(session, request, now) {
             Prepared::Wait(waiting) => *waiting,
             Prepared::Reply(reply) => panic!("expected a wait, got {reply:?}"),
-            Prepared::Http(_) | Prepared::Exec(_) => panic!("expected a wait, got a job"),
+            Prepared::Http(_) | Prepared::Exec(_) | Prepared::Db(_) => {
+                panic!("expected a wait, got a job")
+            }
         }
     }
 
@@ -247,3 +261,39 @@ pub fn session(id: &str) -> SessionInfo {
         client: "test agent".into(),
     }
 }
+
+pub fn postgres(name: &str, url: &str, read_only: bool, mode: Mode) -> Secret {
+    secret(
+        name,
+        SecretValue::Postgres {
+            url: SecretText::new(url),
+        },
+        Policy {
+            mode,
+            read_only,
+            ..Policy::default()
+        },
+    )
+}
+
+pub fn redis(name: &str, url: &str, read_only: bool, mode: Mode) -> Secret {
+    secret(
+        name,
+        SecretValue::Redis {
+            url: SecretText::new(url),
+        },
+        Policy {
+            mode,
+            read_only,
+            ..Policy::default()
+        },
+    )
+}
+
+pub fn query(handle: &str, query: &str) -> DbCall {
+    DbCall {
+        handle: handle.into(),
+        query: query.into(),
+        timeout_secs: None,
+    }
+}
diff --git a/crates/kv/tests/db.rs b/crates/kv/tests/db.rs
new file mode 100644
index 0000000..4315070
--- /dev/null
+++ b/crates/kv/tests/db.rs
@@ -0,0 +1,148 @@
+//! `db_query` as the daemon authorizes it, without a database: kinds,
+//! URLs, read-only guards, approval and timeouts. `db_live.rs` runs queries
+//! against real servers.
+
+mod common;
+
+use std::time::Duration;
+
+use common::*;
+use kv_core::policy::Mode;
+use kv_core::proto::{AgentErrorCode, AgentRequest, ControlCommand, ControlResponse, DbCall};
+use kv_core::secret::{SecretText, SecretValue};
+
+const PG_URL: &str = "postgres://app:pg-password-0123456789@db.internal.example:5432/app";
+const REDIS_URL: &str = "rediss://:redis-password-0123456789@cache.internal.example:6380/0";
+
+#[test]
+fn only_database_handles_take_queries() {
+    let mut f = Fixture::new();
+    f.add(openrouter(Mode::Auto));
+    let (code, message) = f.db(query("openrouter", "select 1")).unwrap_err();
+    assert_eq!(code, AgentErrorCode::PolicyDenied, "{message}");
+    let (code, _) = f.db(query("missing", "select 1")).unwrap_err();
+    assert_eq!(code, AgentErrorCode::UnknownHandle);
+}
+
+#[test]
+fn an_auto_query_becomes_a_job_with_its_timeout() {
+    let mut f = Fixture::new();
+    f.add(postgres("pg", PG_URL, false, Mode::Auto));
+    let job = f.db(query("pg", "select 1")).unwrap();
+    assert_eq!(job.timeout, Duration::from_secs(30));
+    let job = f
+        .db(DbCall {
+            timeout_secs: Some(5),
+            ..query("pg", "select 1")
+        })
+        .unwrap();
+    assert_eq!(job.timeout, Duration::from_secs(5));
+    let (code, message) = f
+        .db(DbCall {
+            timeout_secs: Some(301),
+            ..query("pg", "select 1")
+        })
+        .unwrap_err();
+    assert_eq!(code, AgentErrorCode::BadRequest);
+    assert!(message.contains("300"), "{message}");
+}
+
+#[test]
+fn read_only_guards_refuse_before_anything_runs() {
+    let mut f = Fixture::new();
+    f.add(postgres("pg", PG_URL, true, Mode::Ask));
+    f.add(redis("cache", REDIS_URL, true, Mode::Ask));
+    let (code, _) = f
+        .db(query("pg", "BEGIN READ WRITE; DELETE FROM users"))
+        .unwrap_err();
+    assert_eq!(code, AgentErrorCode::PolicyDenied);
+    let (code, message) = f.db(query("cache", "SET k v")).unwrap_err();
+    assert_eq!(code, AgentErrorCode::PolicyDenied);
+    assert!(message.contains("SET"), "{message}");
+    let (code, _) = f.db(query("cache", "SUBSCRIBE news")).unwrap_err();
+    assert_eq!(code, AgentErrorCode::BadRequest);
+    let (code, _) = f.db(query("cache", r#"GET "open"#)).unwrap_err();
+    assert_eq!(code, AgentErrorCode::BadRequest);
+    let audit = f.audit_lines();
+    assert!(
+        audit
+            .iter()
+            .all(|line| line["decision"] != "approved" && line["decision"] != "auto"),
+        "{audit:?}"
+    );
+}
+
+#[test]
+fn a_query_in_ask_mode_waits_and_shows_the_query() {
+    let mut f = Fixture::new();
+    f.add(postgres("pg", PG_URL, false, Mode::Ask));
+    let long = format!("select '{}'", "x".repeat(400));
+    let waiting = f.wait(
+        Some(&session("s1")),
+        AgentRequest::DbQuery(query("pg", &long)),
+        f.t0,
+    );
+    let token = f.token();
+    let approvals = f.overview(&token).approvals;
+    assert_eq!(approvals[0].id, waiting.id);
+    assert_eq!(approvals[0].tool, "db_query");
+    assert!(approvals[0].detail.starts_with("select 'xxx"));
+    assert!(approvals[0].detail.chars().count() <= 300);
+}
+
+#[test]
+fn connection_urls_must_be_postgres_or_redis_urls() {
+    let mut f = Fixture::new();
+    let token = f.token();
+    for (value, ok) in [
+        (SecretValue::Postgres { url: url(PG_URL) }, true),
+        (
+            SecretValue::Postgres {
+                url: url("postgresql://app@db.example/app"),
+            },
+            true,
+        ),
+        (
+            SecretValue::Postgres {
+                url: url("host=db.example user=app password=pg-password-0123"),
+            },
+            false,
+        ),
+        (
+            SecretValue::Postgres {
+                url: url("mysql://app:pw@db.example/app"),
+            },
+            false,
+        ),
+        (
+            SecretValue::Redis {
+                url: url(REDIS_URL),
+            },
+            true,
+        ),
+        (
+            SecretValue::Redis {
+                url: url("postgres://app:pw@db.example/app"),
+            },
+            false,
+        ),
+    ] {
+        let response = f.send(
+            None,
+            Some(&token),
+            ControlCommand::Add {
+                secret: secret("db", value.clone(), Default::default()),
+                replace: true,
+            },
+        );
+        assert_eq!(
+            matches!(response, ControlResponse::Done { .. }),
+            ok,
+            "{value:?}: {response:?}"
+        );
+    }
+}
+
+fn url(text: &str) -> SecretText {
+    SecretText::new(text)
+}
diff --git a/crates/kv/tests/db_live.rs b/crates/kv/tests/db_live.rs
new file mode 100644
index 0000000..bf89a63
--- /dev/null
+++ b/crates/kv/tests/db_live.rs
@@ -0,0 +1,239 @@
+//! `db_query` against real servers. Set `KV_TEST_POSTGRES_URL` (a
+//! superuser) and `KV_TEST_REDIS_URL` to run these; without them they pass
+//! after a note, unless `KV_REQUIRE_DB_TESTS` is set, as it is in CI.
+
+mod common;
+
+use common::*;
+use kv::broker::db;
+use kv_core::policy::Mode;
+use kv_core::proto::{AgentErrorCode, AgentResponse, DbCall, RedisReply, RowsReply};
+use tokio_postgres::NoTls;
+
+fn server(var: &str) -> Option<String> {
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
+async fn admin(url: &str, schema: &str) -> tokio_postgres::Client {
+    let (client, connection) = tokio_postgres::connect(url, NoTls).await.unwrap();
+    tokio::spawn(connection);
+    client
+        .batch_execute(&format!(
+            "DROP SCHEMA IF EXISTS {schema} CASCADE; CREATE SCHEMA {schema};"
+        ))
+        .await
+        .unwrap();
+    client
+}
+
+async fn run(f: &mut Fixture, call: DbCall) -> AgentResponse {
+    db::run(f.db(call).unwrap()).await
+}
+
+fn rows(response: AgentResponse) -> RowsReply {
+    match response {
+        AgentResponse::Rows(rows) => rows,
+        other => panic!("expected rows, got {other:?}"),
+    }
+}
+
+fn upstream_error(response: AgentResponse) -> String {
+    match response {
+        AgentResponse::Error {
+            code: AgentErrorCode::UpstreamError,
+            message,
+        } => message,
+        other => panic!("expected upstream_error, got {other:?}"),
+    }
+}
+
+#[tokio::test]
+async fn postgres_rows_come_back_as_text_with_secrets_scrubbed() {
+    let Some(url) = server("KV_TEST_POSTGRES_URL") else {
+        return;
+    };
+    let password = url::Url::parse(&url)
+        .unwrap()
+        .password()
+        .unwrap()
+        .to_owned();
+    let admin = admin(&url, "kv_rows").await;
+    admin
+        .batch_execute(&format!(
+            "CREATE TABLE kv_rows.notes (id int, body text);
+             INSERT INTO kv_rows.notes VALUES (1, 'the password is {password}'), (2, NULL);"
+        ))
+        .await
+        .unwrap();
+    let mut f = Fixture::new();
+    f.add(postgres("pg", &url, false, Mode::Auto));
+
+    let reply = rows(
+        run(
+            &mut f,
+            query(
+                "pg",
+                "SELECT id, body FROM kv_rows.notes ORDER BY id; UPDATE kv_rows.notes SET id = id",
+            ),
+        )
+        .await,
+    );
+    assert_eq!(reply.results.len(), 2);
+    let select = &reply.results[0];
+    assert_eq!(select.columns, ["id", "body"]);
+    assert_eq!(
+        select.rows,
+        [
+            vec![Some("1".into()), Some("the password is [kv:pg]".into())],
+            vec![Some("2".into()), None],
+        ]
+    );
+    assert_eq!(reply.results[1].rows_affected, Some(2));
+    assert!(!reply.truncated);
+    assert!(reply.warnings.is_empty(), "not read-only: no role check");
+
+    let message = upstream_error(
+        run(
+            &mut f,
+            query("pg", &format!("SELECT * FROM \"{password}\"")),
+        )
+        .await,
+    );
+    assert!(!message.contains(&password), "{message}");
+    assert!(message.contains("[kv:pg]"), "{message}");
+}
+
+#[tokio::test]
+async fn a_read_only_postgres_session_refuses_writes_and_warns_about_the_role() {
+    let Some(url) = server("KV_TEST_POSTGRES_URL") else {
+        return;
+    };
+    let admin = admin(&url, "kv_ro").await;
+    admin
+        .batch_execute(
+            "CREATE TABLE kv_ro.items (id int);
+             DROP ROLE IF EXISTS kv_ro_reader;
+             CREATE ROLE kv_ro_reader LOGIN PASSWORD 'reader-password-0123';
+             GRANT USAGE ON SCHEMA kv_ro TO kv_ro_reader;
+             GRANT SELECT ON kv_ro.items TO kv_ro_reader;",
+        )
+        .await
+        .unwrap();
+    let mut f = Fixture::new();
+    f.add(postgres("pg", &url, true, Mode::Auto));
+
+    let message =
+        upstream_error(run(&mut f, query("pg", "INSERT INTO kv_ro.items VALUES (1)")).await);
+    assert!(message.contains("read-only transaction"), "{message}");
+    let reply = rows(run(&mut f, query("pg", "SELECT count(*) FROM kv_ro.items")).await);
+    assert_eq!(reply.results[0].rows, [vec![Some("0".into())]]);
+    assert!(
+        reply.warnings[0].contains("role can write"),
+        "{:?}",
+        reply.warnings
+    );
+    let token = f.token();
+    assert!(f.overview(&token).role_warnings.contains_key("pg"));
+
+    let mut reader = url::Url::parse(&url).unwrap();
+    reader.set_username("kv_ro_reader").unwrap();
+    reader.set_password(Some("reader-password-0123")).unwrap();
+    f.add(postgres("reader", reader.as_str(), true, Mode::Auto));
+    let reply = rows(run(&mut f, query("reader", "SELECT count(*) FROM kv_ro.items")).await);
+    assert!(reply.warnings.is_empty(), "{:?}", reply.warnings);
+    assert!(!f.overview(&token).role_warnings.contains_key("reader"));
+}
+
+#[tokio::test]
+async fn big_postgres_results_are_cut_and_slow_ones_time_out() {
+    let Some(url) = server("KV_TEST_POSTGRES_URL") else {
+        return;
+    };
+    let mut f = Fixture::new();
+    f.add(postgres("pg", &url, false, Mode::Auto));
+    let reply = rows(
+        run(
+            &mut f,
+            query(
+                "pg",
+                "SELECT repeat('x', 1000) FROM generate_series(1, 1000)",
+            ),
+        )
+        .await,
+    );
+    assert!(reply.truncated);
+    let kept = reply.results.iter().map(|r| r.rows.len()).sum::<usize>();
+    assert!(kept > 100 && kept < 1000, "{kept}");
+
+    let message = upstream_error(
+        run(
+            &mut f,
+            DbCall {
+                timeout_secs: Some(1),
+                ..query("pg", "SELECT pg_sleep(5)")
+            },
+        )
+        .await,
+    );
+    assert!(message.contains("time"), "{message}");
+}
+
+#[tokio::test]
+async fn redis_replies_come_back_as_json_with_secrets_scrubbed() {
+    let Some(url) = server("KV_TEST_REDIS_URL") else {
+        return;
+    };
+    let mut f = Fixture::new();
+    f.add(redis("cache", &url, false, Mode::Auto));
+    f.add(redis("cache-ro", &url, true, Mode::Auto));
+    let secret = "redis-secret-0123456789";
+    f.add(env_secret("other", &[("TOKEN", secret)], &[], Mode::Auto));
+
+    let ok = run(&mut f, query("cache", &format!("SET kv:test \"{secret}\""))).await;
+    assert_eq!(
+        ok,
+        AgentResponse::Redis(RedisReply {
+            value: serde_json::json!("OK"),
+            truncated: false
+        })
+    );
+    run(&mut f, query("cache", "DEL kv:list")).await;
+    run(&mut f, query("cache", "RPUSH kv:list a 42")).await;
+    let reply = run(&mut f, query("cache-ro", "GET kv:test")).await;
+    assert_eq!(
+        reply,
+        AgentResponse::Redis(RedisReply {
+            value: serde_json::json!("[kv:other]"),
+            truncated: false
+        })
+    );
+    let reply = run(&mut f, query("cache-ro", "LRANGE kv:list 0 -1")).await;
+    assert_eq!(
+        reply,
+        AgentResponse::Redis(RedisReply {
+            value: serde_json::json!(["a", "42"]),
+            truncated: false
+        })
+    );
+    let reply = run(&mut f, query("cache-ro", "LLEN kv:list")).await;
+    assert_eq!(
+        reply,
+        AgentResponse::Redis(RedisReply {
+            value: serde_json::json!(2),
+            truncated: false
+        })
+    );
+    let (code, _) = f.db(query("cache-ro", "DEL kv:test")).unwrap_err();
+    assert_eq!(code, AgentErrorCode::PolicyDenied);
+}
diff --git a/crates/kv/tests/state.rs b/crates/kv/tests/state.rs
index 2826134..c23e243 100644
--- a/crates/kv/tests/state.rs
+++ b/crates/kv/tests/state.rs
@@ -83,7 +83,7 @@ impl Fixture {
     fn agent_at(&mut self, now: Instant, request: AgentRequest) -> AgentResponse {
         match self.daemon.prepare(request, now) {
             Prepared::Reply(response) => response,
-            Prepared::Http(_) | Prepared::Exec(_) | Prepared::Wait(_) => {
+            Prepared::Http(_) | Prepared::Exec(_) | Prepared::Db(_) | Prepared::Wait(_) => {
                 panic!("expected a reply, got a job")
             }
         }
diff --git a/crates/kv/tests/tui.rs b/crates/kv/tests/tui.rs
index aeb475c..2724528 100644
--- a/crates/kv/tests/tui.rs
+++ b/crates/kv/tests/tui.rs
@@ -85,6 +85,7 @@ fn overview(approvals: Vec<Approval>) -> Overview {
         handles: vec![handle("openrouter", Mode::Ask)],
         approvals,
         handle_requests: Vec::new(),
+        role_warnings: Default::default(),
     }
 }
 
diff --git a/crates/kv/tests/tui_edit.rs b/crates/kv/tests/tui_edit.rs
index 8406578..9d14c51 100644
--- a/crates/kv/tests/tui_edit.rs
+++ b/crates/kv/tests/tui_edit.rs
@@ -119,6 +119,7 @@ fn handles(handles: Vec<HandleInfo>) -> App {
         handles,
         approvals: Vec::new(),
         handle_requests: Vec::new(),
+        role_warnings: Default::default(),
     }));
     key(&mut app, '2');
     app
diff --git a/crates/kv/tests/tui_requests.rs b/crates/kv/tests/tui_requests.rs
index f38faca..87739be 100644
--- a/crates/kv/tests/tui_requests.rs
+++ b/crates/kv/tests/tui_requests.rs
@@ -119,6 +119,7 @@ fn overview(requests: Vec<HandleRequest>, handles: Vec<HandleInfo>) -> Overview
                 request,
             })
             .collect(),
+        role_warnings: Default::default(),
     }
 }
 
```

- [ ] **Step 2: Run the tests to watch them fail**

Run: `DEVELOPER_DIR=/Library/Developer/CommandLineTools cargo test -p kv --test db`
Expected: FAIL to compile: `DbCall`, `DbJob`, `Prepared::Db` and `AgentRequest::DbQuery` do not exist.

- [ ] **Step 3: Implement**

Apply with `git apply` (Cargo.lock updates itself on the next build):

```diff
diff --git a/crates/kv-core/src/proto.rs b/crates/kv-core/src/proto.rs
index 73bbf3c..7c56224 100644
--- a/crates/kv-core/src/proto.rs
+++ b/crates/kv-core/src/proto.rs
@@ -34,6 +34,7 @@ pub enum AgentRequest {
     Status,
     HttpRequest(HttpCall),
     Exec(ExecCall),
+    DbQuery(DbCall),
     /// Asks the user to add a handle. Answered at once; the user finishes
     /// it in `kv tui`.
     RequestHandle(HandleRequest),
@@ -104,6 +105,18 @@ pub struct ExecCall {
     pub timeout_secs: Option<u64>,
 }
 
+/// One query or Redis command, run by the daemon on its own connection.
+#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
+pub struct DbCall {
+    pub handle: String,
+    /// SQL for `postgres` handles, which may hold several statements; a
+    /// command line such as `HGETALL user:1` for `redis` handles.
+    pub query: String,
+    /// Defaults to 30 seconds; at most 300.
+    #[serde(default)]
+    pub timeout_secs: Option<u64>,
+}
+
 #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
 #[serde(tag = "type", rename_all = "snake_case")]
 pub enum AgentResponse {
@@ -115,6 +128,8 @@ pub enum AgentResponse {
     },
     Http(HttpReply),
     Exec(ExecReply),
+    Rows(RowsReply),
+    Redis(RedisReply),
     /// The handle request is waiting for the user in `kv tui`.
     Requested {
         name: String,
@@ -146,6 +161,34 @@ pub struct ExecReply {
     pub truncated: bool,
 }
 
+/// What a Postgres query returned, scrubbed: one result per statement.
+#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
+pub struct RowsReply {
+    pub results: Vec<ResultSet>,
+    /// Rows were left out to stay under `MAX_OUTPUT_LEN`.
+    pub truncated: bool,
+    /// Such as a read-only handle whose role can write.
+    #[serde(default)]
+    pub warnings: Vec<String>,
+}
+
+/// Values in Postgres's text format; `None` is NULL.
+#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
+pub struct ResultSet {
+    pub columns: Vec<String>,
+    pub rows: Vec<Vec<Option<String>>>,
+    /// From the command tag, for statements that report a count.
+    pub rows_affected: Option<u64>,
+}
+
+/// A Redis reply as JSON, scrubbed: strings, numbers, null, and arrays;
+/// maps become arrays of `[key, value]` pairs.
+#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
+pub struct RedisReply {
+    pub value: serde_json::Value,
+    pub truncated: bool,
+}
+
 #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
 pub struct Status {
     pub vault_exists: bool,
@@ -315,6 +358,10 @@ pub struct Overview {
     pub approvals: Vec<Approval>,
     #[serde(default)]
     pub handle_requests: Vec<RequestedHandle>,
+    /// Read-only Postgres handles whose role turned out to have write
+    /// access, by handle name.
+    #[serde(default)]
+    pub role_warnings: BTreeMap<String, String>,
 }
 
 /// A handle request waiting for the user. Agent text has been made safe to
diff --git a/crates/kv/Cargo.toml b/crates/kv/Cargo.toml
index fcc2066..7f7a63a 100644
--- a/crates/kv/Cargo.toml
+++ b/crates/kv/Cargo.toml
@@ -8,16 +8,22 @@ description = "Local secrets broker that lets AI agents use secrets without seei
 [dependencies]
 clap = { version = "4.6", features = ["derive", "env"] }
 dirs = "7.0"
+futures-util = { version = "0.3", default-features = false }
 humantime = "2"
 kv-core = { path = "../kv-core" }
 notify-rust = "4.18"
 ratatui = { version = "0.30", features = ["unstable-rendered-line-info"] }
+redis = { version = "1.7", default-features = false, features = ["tokio-rustls-comp"] }
 reqwest = { version = "0.13", default-features = false, features = ["rustls"] }
 rmcp = { version = "3.5", default-features = false, features = ["macros", "server", "transport-io"] }
 rpassword = "7.5"
+rustls = { version = "0.23", default-features = false, features = ["aws_lc_rs", "std", "tls12"] }
+rustls-platform-verifier = "0.7"
 serde = { version = "1", features = ["derive"] }
 serde_json = "1"
 tokio = { version = "1.53", features = ["io-util", "macros", "net", "process", "rt-multi-thread", "sync", "time"] }
+tokio-postgres = { version = "0.7", default-features = false, features = ["runtime"] }
+tokio-postgres-rustls = { version = "0.14", default-features = false, features = ["aws-lc-rs"] }
 url = "2.5"
 zeroize = "1.9"
 
diff --git a/crates/kv/src/broker.rs b/crates/kv/src/broker.rs
index 4b1620b..85817cc 100644
--- a/crates/kv/src/broker.rs
+++ b/crates/kv/src/broker.rs
@@ -1,11 +1,11 @@
 //! Work an agent asked for, authorized by the daemon and run outside the
-//! daemon lock: HTTP requests and programs.
+//! daemon lock: HTTP requests, programs and database queries.
 
 use std::path::PathBuf;
 use std::sync::Arc;
 use std::time::{Duration, Instant};
 
-use kv_core::proto::HttpCall;
+use kv_core::proto::{DbCall, HttpCall};
 use kv_core::scrub::Scrubber;
 use kv_core::secret::{Secret, SecretText};
 
@@ -13,10 +13,13 @@ use kv_core::proto::MAX_OUTPUT_LEN;
 
 use crate::audit::Audit;
 
+pub mod db;
 pub mod exec;
 pub mod http;
 mod process;
 
+pub use db::RoleChecks;
+
 /// An `http_request` that passed every check.
 pub struct HttpJob {
     pub secret: Secret,
@@ -45,6 +48,21 @@ pub struct ExecJob {
     pub decision: &'static str,
 }
 
+/// A `db_query` that passed every check.
+pub struct DbJob {
+    pub secret: Secret,
+    pub call: DbCall,
+    pub timeout: Duration,
+    pub scrubber: Arc<Scrubber>,
+    pub audit: Audit,
+    pub started: Instant,
+    /// `auto`, or `approved` after a decision in `kv tui`, for the audit log.
+    pub decision: &'static str,
+    /// Where a read-only Postgres handle's role check is kept; the job runs
+    /// the check if this handle has none since the vault was unlocked.
+    pub role_checks: RoleChecks,
+}
+
 /// Decodes scrubbed bytes, cutting them to `MAX_OUTPUT_LEN` (replacement
 /// markers can make scrubbed output longer than its input).
 pub(crate) fn capped_text(bytes: &[u8]) -> (String, bool) {
@@ -78,3 +96,12 @@ impl std::fmt::Debug for ExecJob {
             .finish_non_exhaustive()
     }
 }
+
+impl std::fmt::Debug for DbJob {
+    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
+        f.debug_struct("DbJob")
+            .field("handle", &self.secret.name)
+            .field("timeout", &self.timeout)
+            .finish_non_exhaustive()
+    }
+}
diff --git a/crates/kv/src/broker/db.rs b/crates/kv/src/broker/db.rs
new file mode 100644
index 0000000..e512079
--- /dev/null
+++ b/crates/kv/src/broker/db.rs
@@ -0,0 +1,375 @@
+//! Runs an authorized `db_query` on a connection of its own and scrubs what
+//! comes back. Postgres queries use the simple query protocol, so values
+//! arrive as text; Redis replies become JSON.
+
+use std::collections::BTreeMap;
+use std::pin::pin;
+use std::sync::{Arc, Mutex, PoisonError};
+use std::time::Duration;
+
+use futures_util::StreamExt;
+use kv_core::db::split_command;
+use kv_core::proto::{
+    AgentErrorCode, AgentResponse, MAX_OUTPUT_LEN, RedisReply, ResultSet, RowsReply,
+};
+use kv_core::scrub::Scrubber;
+use kv_core::secret::SecretValue;
+use rustls_platform_verifier::BuilderVerifierExt;
+use tokio_postgres::SimpleQueryMessage;
+
+use super::DbJob;
+use crate::audit::Use;
+
+const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
+
+/// Whether a write-capable role is behind each read-only Postgres handle,
+/// learned on its first query since the vault was unlocked. Shared by the
+/// daemon, which shows the warnings and forgets them when a handle changes
+/// or the vault locks, and the jobs that run the checks.
+#[derive(Clone, Default)]
+pub struct RoleChecks(Arc<Mutex<BTreeMap<String, Option<String>>>>);
+
+impl RoleChecks {
+    fn map(&self) -> std::sync::MutexGuard<'_, BTreeMap<String, Option<String>>> {
+        self.0.lock().unwrap_or_else(PoisonError::into_inner)
+    }
+
+    pub fn is_checked(&self, handle: &str) -> bool {
+        self.map().contains_key(handle)
+    }
+
+    pub fn record(&self, handle: &str, warning: Option<String>) {
+        self.map().insert(handle.to_owned(), warning);
+    }
+
+    pub fn forget(&self, handle: &str) {
+        self.map().remove(handle);
+    }
+
+    pub fn clear(&self) {
+        self.map().clear();
+    }
+
+    /// The handles whose role can write, with the warning for each.
+    pub fn warnings(&self) -> BTreeMap<String, String> {
+        self.map()
+            .iter()
+            .filter_map(|(handle, warning)| Some((handle.clone(), warning.clone()?)))
+            .collect()
+    }
+}
+
+/// Runs the query within the job's timeout and records it in the audit log.
+pub async fn run(job: DbJob) -> AgentResponse {
+    let response = match tokio::time::timeout(job.timeout, query(&job)).await {
+        Ok(Ok(response) | Err(response)) => response,
+        Err(_) => error(
+            AgentErrorCode::UpstreamError,
+            format!("the query timed out after {}s", job.timeout.as_secs()),
+        ),
+    };
+    let outcome = match &response {
+        AgentResponse::Error { code, .. } => code.as_str(),
+        _ => "ok",
+    };
+    let summary: String = job.call.query.chars().take(200).collect();
+    job.audit.record_use(&Use {
+        action: "db_query",
+        handle: &job.secret.name,
+        decision: job.decision,
+        summary: &summary,
+        outcome,
+        duration: job.started.elapsed(),
+    });
+    response
+}
+
+async fn query(job: &DbJob) -> Result<AgentResponse, AgentResponse> {
+    match &job.secret.value {
+        SecretValue::Postgres { url } => postgres(job, url.expose()).await,
+        SecretValue::Redis { url } => redis(job, url.expose()).await,
+        _ => Err(error(AgentErrorCode::BadRequest, "not a database handle")),
+    }
+}
+
+async fn postgres(job: &DbJob, url: &str) -> Result<AgentResponse, AgentResponse> {
+    let scrubber = &job.scrubber;
+    // The server enforces the timeout too, so an abandoned query stops.
+    let mut options = format!(" -c statement_timeout={}", job.timeout.as_millis());
+    if job.secret.policy.read_only {
+        options.push_str(" -c default_transaction_read_only=on");
+    }
+    let client = connect(url, &options, scrubber).await?;
+
+    let mut warnings = Vec::new();
+    if job.secret.policy.read_only && !job.role_checks.is_checked(&job.secret.name) {
+        let warning = role_can_write(&client)
+            .await
+            .map_err(|e| upstream(scrubber, &e))?
+            .then(|| role_warning(&job.secret.name));
+        job.role_checks.record(&job.secret.name, warning);
+    }
+    if let Some(warning) = job.role_checks.warnings().remove(&job.secret.name) {
+        warnings.push(warning);
+    }
+
+    let stream = client
+        .simple_query_raw(&job.call.query)
+        .await
+        .map_err(|e| upstream(scrubber, &e))?;
+    let mut stream = pin!(stream);
+    let mut results: Vec<ResultSet> = Vec::new();
+    let mut open: Option<ResultSet> = None;
+    let mut size = 0;
+    let mut truncated = false;
+    while let Some(message) = stream.next().await {
+        match message.map_err(|e| upstream(scrubber, &e))? {
+            SimpleQueryMessage::RowDescription(columns) => {
+                let columns: Vec<String> = columns
+                    .iter()
+                    .map(|c| scrub_text(scrubber, c.name().as_bytes()))
+                    .collect();
+                size += columns.iter().map(|c| c.len() + 3).sum::<usize>();
+                open = Some(ResultSet {
+                    columns,
+                    rows: Vec::new(),
+                    rows_affected: None,
+                });
+            }
+            SimpleQueryMessage::Row(row) => {
+                let cells: Vec<Option<String>> = (0..row.len())
+                    .map(|i| row.get(i).map(|v| scrub_text(scrubber, v.as_bytes())))
+                    .collect();
+                size += cells
+                    .iter()
+                    .map(|c| c.as_ref().map_or(4, |v| v.len() + 3))
+                    .sum::<usize>();
+                if size > MAX_OUTPUT_LEN {
+                    truncated = true;
+                    break;
+                }
+                if let Some(set) = &mut open {
+                    set.rows.push(cells);
+                }
+            }
+            SimpleQueryMessage::CommandComplete(count) => {
+                let mut set = open.take().unwrap_or(ResultSet {
+                    columns: Vec::new(),
+                    rows: Vec::new(),
+                    rows_affected: None,
+                });
+                set.rows_affected = Some(count);
+                results.push(set);
+            }
+            _ => {}
+        }
+    }
+    results.extend(open);
+    Ok(AgentResponse::Rows(RowsReply {
+        results,
+        truncated,
+        warnings,
+    }))
+}
+
+/// Connects with `options` added to any the URL has. The connection runs
+/// until the client is dropped, which also stops a query cut short.
+async fn connect(
+    url: &str,
+    options: &str,
+    scrubber: &Scrubber,
+) -> Result<tokio_postgres::Client, AgentResponse> {
+    let mut config: tokio_postgres::Config = url.parse().map_err(|_| {
+        error(
+            AgentErrorCode::BadRequest,
+            "the handle's connection URL is not a valid Postgres URL",
+        )
+    })?;
+    let mut all = config.get_options().unwrap_or_default().to_owned();
+    all.push_str(options);
+    config
+        .options(all.trim())
+        .application_name("kv")
+        .connect_timeout(CONNECT_TIMEOUT);
+    let tls = tokio_postgres_rustls::MakeRustlsConnect::new(tls_config()?);
+    let (client, connection) = config
+        .connect(tls)
+        .await
+        .map_err(|e| upstream(scrubber, &e))?;
+    tokio::spawn(connection);
+    Ok(client)
+}
+
+fn role_warning(handle: &str) -> String {
+    format!(
+        "{handle} is read-only, but its database role can write; kv keeps the session \
+         read-only only on a best-effort basis. Use a role that can only read."
+    )
+}
+
+/// Whether the session's role can change data: a superuser, or one with
+/// INSERT, UPDATE, DELETE or TRUNCATE on any table, or CREATE on any
+/// schema, outside the system schemas.
+async fn role_can_write(client: &tokio_postgres::Client) -> Result<bool, tokio_postgres::Error> {
+    const CHECK: &str = "\
+SELECT r.rolsuper
+  OR EXISTS (
+    SELECT 1 FROM pg_catalog.pg_class c
+    JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
+    WHERE c.relkind IN ('r', 'p')
+      AND n.nspname NOT IN ('pg_catalog', 'information_schema')
+      AND n.nspname NOT LIKE 'pg\\_%'
+      AND (has_table_privilege(c.oid, 'INSERT') OR has_table_privilege(c.oid, 'UPDATE')
+        OR has_table_privilege(c.oid, 'DELETE') OR has_table_privilege(c.oid, 'TRUNCATE')))
+  OR EXISTS (
+    SELECT 1 FROM pg_catalog.pg_namespace n
+    WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
+      AND n.nspname NOT LIKE 'pg\\_%'
+      AND has_schema_privilege(n.oid, 'CREATE'))
+FROM pg_catalog.pg_roles r WHERE r.rolname = current_user";
+    let messages = client.simple_query(CHECK).await?;
+    Ok(messages
+        .iter()
+        .any(|message| matches!(message, SimpleQueryMessage::Row(row) if row.get(0) == Some("t"))))
+}
+
+/// Certificates are always checked against the platform's trust store,
+/// whatever `sslmode` says; `sslmode=disable` still turns TLS off.
+fn tls_config() -> Result<rustls::ClientConfig, AgentResponse> {
+    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
+    rustls::ClientConfig::builder_with_provider(provider)
+        .with_safe_default_protocol_versions()
+        .and_then(|builder| builder.with_platform_verifier())
+        .map(|builder| builder.with_no_client_auth())
+        .map_err(|e| {
+            error(
+                AgentErrorCode::UpstreamError,
+                format!("could not set up TLS: {e}"),
+            )
+        })
+}
+
+async fn redis(job: &DbJob, url: &str) -> Result<AgentResponse, AgentResponse> {
+    let scrubber = &job.scrubber;
+    // Checked by the daemon already; this split cannot fail.
+    let args = split_command(&job.call.query)
+        .map_err(|message| error(AgentErrorCode::BadRequest, message))?;
+    let client = redis::Client::open(url).map_err(|_| {
+        error(
+            AgentErrorCode::BadRequest,
+            "the handle's connection URL is not a valid Redis URL",
+        )
+    })?;
+    let config = redis::AsyncConnectionConfig::new()
+        .set_connection_timeout(Some(CONNECT_TIMEOUT))
+        .set_response_timeout(Some(job.timeout));
+    let mut connection = client
+        .get_multiplexed_async_connection_with_config(&config)
+        .await
+        .map_err(|e| upstream(scrubber, &e))?;
+    let mut command = redis::cmd(&String::from_utf8_lossy(&args[0]));
+    for arg in &args[1..] {
+        command.arg(arg.as_slice());
+    }
+    let value: redis::Value = command
+        .query_async(&mut connection)
+        .await
+        .map_err(|e| upstream(scrubber, &e))?;
+    let mut budget = MAX_OUTPUT_LEN;
+    let mut truncated = false;
+    let value = to_json(scrubber, value, &mut budget, &mut truncated);
+    Ok(AgentResponse::Redis(RedisReply { value, truncated }))
+}
+
+/// A Redis value as JSON, scrubbed, spending `budget` bytes at most.
+/// Anything past the budget is left out and `truncated` is set.
+fn to_json(
+    scrubber: &Scrubber,
+    value: redis::Value,
+    budget: &mut usize,
+    truncated: &mut bool,
+) -> serde_json::Value {
+    use redis::Value;
+    use serde_json::Value as Json;
+    let text = |bytes: &[u8], budget: &mut usize| {
+        let text = scrub_text(scrubber, bytes);
+        *budget = budget.saturating_sub(text.len() + 3);
+        Json::String(text)
+    };
+    // A number could be a numeric secret, so it goes through the scrubber
+    // too, and comes back as a string if it was replaced.
+    let number = |digits: String, json: Json, budget: &mut usize| {
+        *budget = budget.saturating_sub(digits.len() + 1);
+        let scrubbed = scrub_text(scrubber, digits.as_bytes());
+        if scrubbed == digits {
+            json
+        } else {
+            Json::String(scrubbed)
+        }
+    };
+    let list = |items: Vec<Value>, budget: &mut usize, truncated: &mut bool| {
+        let mut out = Vec::new();
+        for item in items {
+            if *budget == 0 {
+                *truncated = true;
+                break;
+            }
+            out.push(to_json(scrubber, item, budget, truncated));
+        }
+        Json::Array(out)
+    };
+    match value {
+        Value::Nil => Json::Null,
+        Value::Okay => text(b"OK", budget),
+        Value::Int(n) => number(n.to_string(), Json::from(n), budget),
+        Value::Double(n) => number(n.to_string(), Json::from(n), budget),
+        Value::Boolean(b) => Json::Bool(b),
+        Value::BulkString(bytes) => text(&bytes, budget),
+        Value::SimpleString(s) => text(s.as_bytes(), budget),
+        Value::VerbatimString { text: s, .. } => text(s.as_bytes(), budget),
+        Value::BigNumber(digits) => text(&digits, budget),
+        Value::Array(items) | Value::Set(items) => list(items, budget, truncated),
+        Value::Map(pairs) => list(
+            pairs
+                .into_iter()
+                .map(|(k, v)| Value::Array(vec![k, v]))
+                .collect(),
+            budget,
+            truncated,
+        ),
+        Value::Attribute { data, .. } => to_json(scrubber, *data, budget, truncated),
+        Value::Push { data, .. } => list(data, budget, truncated),
+        Value::ServerError(e) => text(e.to_string().as_bytes(), budget),
+        _ => Json::Null,
+    }
+}
+
+fn scrub_text(scrubber: &Scrubber, bytes: &[u8]) -> String {
+    String::from_utf8_lossy(&scrubber.scrub(bytes)).into_owned()
+}
+
+/// An `upstream_error` with the whole chain of causes, scrubbed: database
+/// errors can quote the query, and connection errors can name the host.
+fn upstream(scrubber: &Scrubber, e: &(dyn std::error::Error + 'static)) -> AgentResponse {
+    let mut message = e.to_string();
+    let mut source = e.source();
+    while let Some(cause) = source {
+        let cause = cause.to_string();
+        if !message.contains(&cause) {
+            message.push_str(": ");
+            message.push_str(&cause);
+        }
+        source = source.and_then(|s| s.source());
+    }
+    error(
+        AgentErrorCode::UpstreamError,
+        scrub_text(scrubber, message.as_bytes()),
+    )
+}
+
+fn error(code: AgentErrorCode, message: impl Into<String>) -> AgentResponse {
+    AgentResponse::Error {
+        code,
+        message: message.into(),
+    }
+}
diff --git a/crates/kv/src/daemon/server.rs b/crates/kv/src/daemon/server.rs
index 633369b..758d9f2 100644
--- a/crates/kv/src/daemon/server.rs
+++ b/crates/kv/src/daemon/server.rs
@@ -166,6 +166,7 @@ async fn run_job(prepared: Prepared, http: &reqwest::Client) -> AgentResponse {
         Prepared::Reply(response) => response,
         Prepared::Http(job) => broker::http::send(http, *job).await,
         Prepared::Exec(job) => broker::exec::run(*job).await,
+        Prepared::Db(job) => broker::db::run(*job).await,
         // `Waiting::then` is always a job; it never waits twice.
         Prepared::Wait(_) => AgentResponse::Error {
             code: AgentErrorCode::UpstreamError,
diff --git a/crates/kv/src/daemon/state.rs b/crates/kv/src/daemon/state.rs
index 079f0b1..5f91813 100644
--- a/crates/kv/src/daemon/state.rs
+++ b/crates/kv/src/daemon/state.rs
@@ -9,13 +9,14 @@ use std::time::{Duration, Instant, SystemTime};
 use kv_core::VaultError;
 use kv_core::crypto::KdfParams;
 use kv_core::crypto::fill_random;
+use kv_core::db::{RedisRefusal, check_redis, pg_read_only_violation, split_command};
 use kv_core::policy::{
     Decision, DenyReason, Mode, Operation, evaluate, http_target, is_host_entry,
 };
 use kv_core::proto::{
     AgentErrorCode, AgentRequest, AgentResponse, Approval, ControlCommand, ControlErrorCode,
-    ControlRequest, ControlResponse, ExecCall, HandleRequest, HttpCall, Overview, PolicyPatch,
-    RequestedHandle, SessionInfo, Status, Verdict,
+    ControlRequest, ControlResponse, DbCall, ExecCall, HandleRequest, HttpCall, Overview,
+    PolicyPatch, RequestedHandle, SessionInfo, Status, Verdict,
 };
 use kv_core::scrub::{MIN_SECRET_LEN, Scrubber};
 use kv_core::secret::{
@@ -26,11 +27,13 @@ use tokio::sync::oneshot;
 use zeroize::Zeroizing;
 
 use crate::audit::{Audit, Use};
-use crate::broker::{ExecJob, HttpJob};
+use crate::broker::{DbJob, ExecJob, HttpJob, RoleChecks};
 use crate::throttle::Throttle;
 
 const DEFAULT_EXEC_TIMEOUT: Duration = Duration::from_secs(60);
 const MAX_EXEC_TIMEOUT: Duration = Duration::from_secs(600);
+const DEFAULT_DB_TIMEOUT: Duration = Duration::from_secs(30);
+const MAX_DB_TIMEOUT: Duration = Duration::from_secs(300);
 
 /// Headers kv sets itself, that would change how the request is framed, or
 /// that would let a response carry a secret past the scrubber: compressed,
@@ -135,6 +138,9 @@ pub struct Daemon {
     next_request: u64,
     /// The name of a handle request not yet announced; only new names are.
     request_notice: Option<String>,
+    /// Read-only Postgres handles whose role has been checked since the
+    /// vault was unlocked. Forgotten when the handle changes.
+    role_checks: RoleChecks,
 }
 
 /// A request waiting for approval, as the daemon keeps it.
@@ -191,6 +197,7 @@ pub enum Prepared {
     Reply(AgentResponse),
     Http(Box<HttpJob>),
     Exec(Box<ExecJob>),
+    Db(Box<DbJob>),
     Wait(Box<Waiting>),
 }
 
@@ -228,6 +235,7 @@ impl Daemon {
             handle_requests: Vec::new(),
             next_request: 0,
             request_notice: None,
+            role_checks: RoleChecks::default(),
             grants: Vec::new(),
         }
     }
@@ -273,6 +281,7 @@ impl Daemon {
             }
             AgentRequest::HttpRequest(call) => self.prepare_http(call, session, now),
             AgentRequest::Exec(call) => self.prepare_exec(call, session, now),
+            AgentRequest::DbQuery(call) => self.prepare_db(call, session, now),
             AgentRequest::RequestHandle(request) => {
                 let name = printable(&request.name, 63);
                 let response = self.request_handle(session, request);
@@ -618,6 +627,102 @@ impl Daemon {
         self.queue(ask, job, session, now)
     }
 
+    fn prepare_db(
+        &mut self,
+        call: DbCall,
+        session: Option<&SessionInfo>,
+        now: Instant,
+    ) -> Prepared {
+        let summary: String = call.query.chars().take(200).collect();
+        let refuse = |daemon: &Self, decision, response| {
+            daemon.refuse("db_query", &call.handle, &summary, decision, response)
+        };
+        let bad = |message: String| agent_error(AgentErrorCode::BadRequest, message);
+        let denied = |message: String| agent_error(AgentErrorCode::PolicyDenied, message);
+        let Some(vault) = &self.vault else {
+            return refuse(self, "locked", self.locked_error());
+        };
+        let Some(secret) = vault.get(&call.handle).cloned() else {
+            return refuse(self, "invalid", unknown_handle(vault, &call.handle));
+        };
+        let timeout = call
+            .timeout_secs
+            .map_or(DEFAULT_DB_TIMEOUT, Duration::from_secs);
+        if timeout.is_zero() || timeout > MAX_DB_TIMEOUT {
+            return refuse(
+                self,
+                "invalid",
+                bad("timeout_secs must be between 1 and 300".into()),
+            );
+        }
+        if call.query.trim().is_empty() {
+            return refuse(self, "invalid", bad("the query is empty".into()));
+        }
+        let decision = evaluate(&secret, &Operation::DbQuery);
+        if let Decision::Deny(reason) = decision {
+            return refuse(self, "policy", denied(reason.to_string()));
+        }
+        // The read-only guards run before any approval, so the user is
+        // never asked about a query that would be refused anyway.
+        let read_only = secret.policy.read_only;
+        match &secret.value {
+            SecretValue::Postgres { .. } if read_only => {
+                if let Some(reason) = pg_read_only_violation(&call.query) {
+                    return refuse(self, "policy", denied(reason.into()));
+                }
+            }
+            SecretValue::Redis { .. } => {
+                let args = match split_command(&call.query) {
+                    Ok(args) => args,
+                    Err(message) => return refuse(self, "invalid", bad(message)),
+                };
+                match check_redis(&args, read_only) {
+                    Ok(()) => {}
+                    Err(refusal @ RedisRefusal::Never(_)) => {
+                        return refuse(self, "invalid", bad(refusal.to_string()));
+                    }
+                    Err(refusal @ RedisRefusal::NotRead(_)) => {
+                        return refuse(self, "policy", denied(refusal.to_string()));
+                    }
+                }
+            }
+            _ => {}
+        }
+        let ask = decision == Decision::Ask && !self.granted(session, &call.handle, now);
+        if ask && self.approvals.len() >= MAX_PENDING {
+            return refuse(self, "denied", too_many_waiting());
+        }
+        self.touch(now);
+        let handle = call.handle.clone();
+        let detail = call.query.clone();
+        let job = Prepared::Db(Box::new(DbJob {
+            secret,
+            call,
+            timeout,
+            scrubber: self.scrubber(),
+            audit: self.audit.clone(),
+            started: now,
+            decision: if decision == Decision::Ask {
+                "approved"
+            } else {
+                "auto"
+            },
+            role_checks: self.role_checks.clone(),
+        }));
+        if !ask {
+            return job;
+        }
+        let ask = Ask {
+            tool: "db_query",
+            ask: vec![handle.clone()],
+            handles: handle,
+            summary,
+            detail,
+            cwd: None,
+        };
+        self.queue(ask, job, session, now)
+    }
+
     fn granted(&self, session: Option<&SessionInfo>, handle: &str, now: Instant) -> bool {
         session.is_some_and(|session| {
             self.grants
@@ -879,6 +984,10 @@ impl Daemon {
                         if let Some(name) = added {
                             self.handle_requests.retain(|r| r.request.name != name);
                         }
+                        // A new URL or policy may mean a different role.
+                        if let Some(name) = &handle {
+                            self.role_checks.forget(name);
+                        }
                         done(warnings)
                     })
             }
@@ -918,6 +1027,7 @@ impl Daemon {
         self.scrubber = None;
         self.sessions.clear();
         self.grants.clear();
+        self.role_checks.clear();
         let now = Instant::now();
         for pending in std::mem::take(&mut self.approvals) {
             self.record_unanswered(&pending, "locked", "vault_locked", now);
@@ -972,6 +1082,7 @@ impl Daemon {
                 handles: vault.secrets().iter().map(Secret::info).collect(),
                 approvals,
                 handle_requests: self.handle_requests.clone(),
+                role_warnings: self.role_checks.warnings(),
             },
         }
     }
@@ -1308,9 +1419,16 @@ fn validate_value(value: &SecretValue) -> Result<(), Failure> {
                 }
             }
         }
-        SecretValue::Postgres { url } | SecretValue::Redis { url } => {
-            if url.expose().is_empty() {
-                return invalid("the connection URL is empty");
+        SecretValue::Postgres { url } => {
+            let scheme = url::Url::parse(url.expose()).map(|u| u.scheme().to_owned());
+            if !matches!(scheme.as_deref(), Ok("postgres" | "postgresql")) {
+                return invalid("a postgres handle needs a postgres:// or postgresql:// URL");
+            }
+        }
+        SecretValue::Redis { url } => {
+            let scheme = url::Url::parse(url.expose()).map(|u| u.scheme().to_owned());
+            if !matches!(scheme.as_deref(), Ok("redis" | "rediss")) {
+                return invalid("a redis handle needs a redis:// or rediss:// URL");
             }
         }
         SecretValue::Env { vars } => {
```

- [ ] **Step 4: Run the tests to watch them pass**

Run: `DEVELOPER_DIR=/Library/Developer/CommandLineTools KV_TEST_POSTGRES_URL=postgres://kv:kv-test-password-123@127.0.0.1:54329/postgres cargo test --workspace`
Expected: PASS. `tests/db.rs` has 5 tests; `tests/db_live.rs` runs its Postgres tests against the local server (start it as in Global Constraints) and prints `skipped: KV_TEST_REDIS_URL is not set` for Redis.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "Db_query in the daemon"
```

### Task 3: Role check in kv add and kv tui

**Files:**
- Modify: `crates/kv/src/broker/db.rs`
- Modify: `crates/kv/src/cli.rs`
- Modify: `crates/kv/src/tui/view.rs`
- Modify: `crates/kv/tests/db_live.rs`
- Modify: `crates/kv/tests/tui_edit.rs`

**Interfaces:**
- Consumes: Task 2's private `connect`, `role_can_write`, `role_warning`, `upstream`; `Overview.role_warnings`.
- Produces: `kv::broker::db::check_role(handle: &str, url: &str) -> Result<Option<String>, String>`; `kv add` prints `warning: ...` or a `note:` when it cannot check; the Handles tab marks a handle in `role_warnings` with "read-only, but the role can write".

- [ ] **Step 1: Write the failing tests**

Apply with `git apply` from the repository root:

```diff
diff --git a/crates/kv/tests/db_live.rs b/crates/kv/tests/db_live.rs
index bf89a63..3d73cda 100644
--- a/crates/kv/tests/db_live.rs
+++ b/crates/kv/tests/db_live.rs
@@ -237,3 +237,28 @@ async fn redis_replies_come_back_as_json_with_secrets_scrubbed() {
     let (code, _) = f.db(query("cache-ro", "DEL kv:test")).unwrap_err();
     assert_eq!(code, AgentErrorCode::PolicyDenied);
 }
+
+#[tokio::test]
+async fn kv_add_can_check_a_role_on_its_own() {
+    let Some(url) = server("KV_TEST_POSTGRES_URL") else {
+        return;
+    };
+    let admin = admin(&url, "kv_cr").await;
+    admin
+        .batch_execute(
+            "DROP ROLE IF EXISTS kv_cr_reader;
+             CREATE ROLE kv_cr_reader LOGIN PASSWORD 'reader-password-4567';",
+        )
+        .await
+        .unwrap();
+    let warning = db::check_role("pg", &url).await.unwrap();
+    assert!(warning.unwrap().contains("role can write"));
+    let mut reader = url::Url::parse(&url).unwrap();
+    reader.set_username("kv_cr_reader").unwrap();
+    reader.set_password(Some("reader-password-4567")).unwrap();
+    assert_eq!(db::check_role("pg", reader.as_str()).await.unwrap(), None);
+    let mut closed = url::Url::parse(&url).unwrap();
+    closed.set_port(Some(1)).unwrap();
+    let error = db::check_role("pg", closed.as_str()).await.unwrap_err();
+    assert!(!error.contains("reader-password"), "{error}");
+}
diff --git a/crates/kv/tests/tui_edit.rs b/crates/kv/tests/tui_edit.rs
index 9d14c51..25a2260 100644
--- a/crates/kv/tests/tui_edit.rs
+++ b/crates/kv/tests/tui_edit.rs
@@ -653,3 +653,38 @@ fn a_value_with_equals_signs_typed_first_is_not_shown() {
         }
     }
 }
+
+#[test]
+fn a_read_only_handle_whose_role_can_write_is_flagged() {
+    let pg = HandleInfo {
+        kind: SecretKind::Postgres,
+        read_only: true,
+        auth: None,
+        allowed_hosts: Vec::new(),
+        ..http_handle("prod-db")
+    };
+    let mut app = handles(vec![pg.clone(), http_handle("openrouter")]);
+    assert!(!screen(&app).contains("role can write"));
+    app.apply(Outcome::Overview(Overview {
+        status: Status {
+            vault_exists: true,
+            locked: false,
+            handle_count: Some(2),
+            locks_in_secs: None,
+            pending_approvals: 0,
+        },
+        handles: vec![pg, http_handle("openrouter")],
+        approvals: Vec::new(),
+        handle_requests: Vec::new(),
+        role_warnings: [(
+            "prod-db".to_owned(),
+            "prod-db is read-only, but...".to_owned(),
+        )]
+        .into(),
+    }));
+    let shown = screen(&app);
+    let line = shown.lines().find(|l| l.contains("prod-db")).unwrap();
+    assert!(line.contains("the role can write"), "{shown}");
+    let other = shown.lines().find(|l| l.contains("openrouter")).unwrap();
+    assert!(!other.contains("role can write"), "{shown}");
+}
```

- [ ] **Step 2: Run the tests to watch them fail**

Run: `DEVELOPER_DIR=/Library/Developer/CommandLineTools KV_TEST_POSTGRES_URL=postgres://kv:kv-test-password-123@127.0.0.1:54329/postgres cargo test -p kv --test db_live --test tui_edit`
Expected: FAIL to compile: `cannot find function check_role in module db`. (With `db_live` left out, `a_read_only_handle_whose_role_can_write_is_flagged` fails on the missing marker.)

- [ ] **Step 3: Implement**

Apply with `git apply`:

```diff
diff --git a/crates/kv/src/broker/db.rs b/crates/kv/src/broker/db.rs
index e512079..1b6a111 100644
--- a/crates/kv/src/broker/db.rs
+++ b/crates/kv/src/broker/db.rs
@@ -9,11 +9,12 @@ use std::time::Duration;
 
 use futures_util::StreamExt;
 use kv_core::db::split_command;
+use kv_core::policy::Policy;
 use kv_core::proto::{
     AgentErrorCode, AgentResponse, MAX_OUTPUT_LEN, RedisReply, ResultSet, RowsReply,
 };
 use kv_core::scrub::Scrubber;
-use kv_core::secret::SecretValue;
+use kv_core::secret::{Secret, SecretText, SecretValue};
 use rustls_platform_verifier::BuilderVerifierExt;
 use tokio_postgres::SimpleQueryMessage;
 
@@ -200,6 +201,38 @@ async fn connect(
     Ok(client)
 }
 
+/// Checks the role behind a Postgres URL on its own connection, for
+/// `kv add`: the warning to show if it can write, or why it could not be
+/// checked, with the URL's secrets scrubbed.
+pub async fn check_role(handle: &str, url: &str) -> Result<Option<String>, String> {
+    let secret = Secret {
+        name: handle.to_owned(),
+        description: String::new(),
+        value: SecretValue::Postgres {
+            url: SecretText::new(url),
+        },
+        policy: Policy::default(),
+        created_at: 0,
+        updated_at: 0,
+    };
+    let values = secret.sensitive_values();
+    let scrubber = Scrubber::new(values.iter().map(|v| (handle, v.as_str())));
+    let message = |response: AgentResponse| match response {
+        AgentResponse::Error { message, .. } => message,
+        _ => String::new(),
+    };
+    let check = async {
+        let client = connect(url, "", &scrubber).await.map_err(message)?;
+        role_can_write(&client)
+            .await
+            .map_err(|e| message(upstream(&scrubber, &e)))
+    };
+    match tokio::time::timeout(CONNECT_TIMEOUT * 2, check).await {
+        Ok(can_write) => Ok(can_write?.then(|| role_warning(handle))),
+        Err(_) => Err("the database did not answer in time".into()),
+    }
+}
+
 fn role_warning(handle: &str) -> String {
     format!(
         "{handle} is read-only, but its database role can write; kv keeps the session \
diff --git a/crates/kv/src/cli.rs b/crates/kv/src/cli.rs
index 31518ed..43bcd0e 100644
--- a/crates/kv/src/cli.rs
+++ b/crates/kv/src/cli.rs
@@ -317,6 +317,12 @@ async fn run(cli: Cli) -> Result<()> {
             let value = read_value(&args, &mut input)?;
             let mut policy = Policy::default();
             args.policy.patch().apply(&mut policy);
+            // Checked here, where the URL already is, so a slow database
+            // never holds up the daemon.
+            let role_url = match &value {
+                SecretValue::Postgres { url } if policy.read_only => Some(url.clone()),
+                _ => None,
+            };
             let secret = Secret {
                 name: args.name.clone(),
                 description: args.description.clone(),
@@ -335,6 +341,15 @@ async fn run(cli: Cli) -> Result<()> {
             )
             .await?;
             println!("added {}", args.name);
+            if let Some(url) = role_url {
+                match crate::broker::db::check_role(&args.name, url.expose()).await {
+                    Ok(None) => {}
+                    Ok(Some(warning)) => eprintln!("warning: {warning}"),
+                    Err(why) => eprintln!(
+                        "note: could not check the database role ({why}); kv checks it again on first use"
+                    ),
+                }
+            }
             Ok(())
         }
         Command::Rm { name } => {
diff --git a/crates/kv/src/tui/view.rs b/crates/kv/src/tui/view.rs
index abda011..dd03713 100644
--- a/crates/kv/src/tui/view.rs
+++ b/crates/kv/src/tui/view.rs
@@ -259,11 +259,17 @@ fn draw_handles(frame: &mut Frame, app: &App, area: Rect) {
     if !requests.is_empty() && !handles.is_empty() {
         lines.push(Line::raw(""));
     }
+    let role_warnings = app.overview().map(|o| &o.role_warnings);
     for (index, handle) in handles.iter().enumerate() {
         if requests.len() + index == selected {
             selected_lines = lines.len()..lines.len() + 1;
         }
-        lines.push(handle_line(handle, requests.len() + index == selected));
+        let can_write = role_warnings.is_some_and(|w| w.contains_key(&handle.name));
+        lines.push(handle_line(
+            handle,
+            requests.len() + index == selected,
+            can_write,
+        ));
     }
     // The keys act on the selected row, so it is always on screen.
     let scroll = scroll_to(&lines, selected_lines, area.width, area.height);
@@ -322,7 +328,9 @@ fn request_lines(requested: &RequestedHandle, selected: bool) -> Vec<Line<'stati
     vec![first, Line::styled(why, dim())]
 }
 
-fn handle_line(handle: &HandleInfo, selected: bool) -> Line<'static> {
+/// `can_write`: a read-only handle whose database role turned out to have
+/// write access.
+fn handle_line(handle: &HandleInfo, selected: bool, can_write: bool) -> Line<'static> {
     let mode = match handle.mode {
         Mode::Auto => "auto",
         Mode::Ask => "ask",
@@ -334,11 +342,19 @@ fn handle_line(handle: &HandleInfo, selected: bool) -> Line<'static> {
     if !handle.description.is_empty() {
         text.push_str(&format!(" {}", handle.description));
     }
-    if selected {
-        Line::styled(text, Style::new().add_modifier(Modifier::BOLD))
+    let style = if selected {
+        Style::new().add_modifier(Modifier::BOLD)
     } else {
-        Line::raw(text)
+        Style::new()
+    };
+    let mut spans = vec![Span::styled(text, style)];
+    if can_write {
+        spans.push(Span::styled(
+            "  read-only, but the role can write",
+            Style::new().fg(Color::Red),
+        ));
     }
+    Line::from(spans)
 }
 
 fn draw_audit(frame: &mut Frame, entries: &[Entry], area: Rect) {
```

- [ ] **Step 4: Run the tests to watch them pass**

Run: `DEVELOPER_DIR=/Library/Developer/CommandLineTools KV_TEST_POSTGRES_URL=postgres://kv:kv-test-password-123@127.0.0.1:54329/postgres cargo test -p kv --test db_live --test tui_edit`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "Role check in kv add and kv tui"
```

### Task 4: The db_query MCP tool

**Files:**
- Modify: `crates/kv/src/mcp.rs`
- Modify: `crates/kv/tests/mcp.rs`

**Interfaces:**
- Consumes: Task 2's `AgentRequest::DbQuery(DbCall)`.
- Produces: the `db_query` MCP tool with arguments `handle`, `query`, `timeout_secs?`.

- [ ] **Step 1: Write the failing tests**

Apply with `git apply` from the repository root:

```diff
diff --git a/crates/kv/tests/mcp.rs b/crates/kv/tests/mcp.rs
index f68852e..01fec03 100644
--- a/crates/kv/tests/mcp.rs
+++ b/crates/kv/tests/mcp.rs
@@ -405,3 +405,52 @@ async fn an_agent_asks_for_a_handle_it_does_not_have() {
     assert!(requests[0].client.is_some());
     client.cancel().await.unwrap();
 }
+
+#[tokio::test]
+async fn an_agent_queries_a_database_through_mcp() {
+    let password = "pg-mcp-password-0123";
+    let home = Home::new();
+    home.kv(&["init", "--insecure-fast-kdf"], &format!("{PASS}\n"));
+    // Port 1: nothing listens, so the query fails upstream.
+    home.kv(
+        &[
+            "add",
+            "pg",
+            "--kind",
+            "postgres",
+            "--read-only",
+            "true",
+            "--mode",
+            "auto",
+        ],
+        &format!("{PASS}\npostgres://app:{password}@127.0.0.1:1/app\n"),
+    );
+    let project = TempDir::new().unwrap();
+    let client = home.mcp(project.path()).await;
+    let tools: Vec<String> = client
+        .list_all_tools()
+        .await
+        .unwrap()
+        .into_iter()
+        .map(|t| t.name.to_string())
+        .collect();
+    assert!(tools.contains(&"db_query".to_owned()), "{tools:?}");
+
+    let (failed, text) = call(
+        &client,
+        "db_query",
+        serde_json::json!({"handle": "pg", "query": "BEGIN READ WRITE"}),
+    )
+    .await;
+    assert!(failed && text.starts_with("policy_denied"), "{text}");
+
+    let (failed, text) = call(
+        &client,
+        "db_query",
+        serde_json::json!({"handle": "pg", "query": "select 1", "timeout_secs": 5}),
+    )
+    .await;
+    assert!(failed && text.starts_with("upstream_error"), "{text}");
+    assert!(!text.contains(password), "{text}");
+    client.cancel().await.unwrap();
+}
```

- [ ] **Step 2: Run the tests to watch them fail**

Run: `DEVELOPER_DIR=/Library/Developer/CommandLineTools cargo test -p kv --test mcp an_agent_queries_a_database_through_mcp`
Expected: FAIL: the tool list (`["exec", "http_request", "list_handles", "request_handle", "status"]`) has no `db_query`.

- [ ] **Step 3: Implement**

Apply with `git apply`:

```diff
diff --git a/crates/kv/src/mcp.rs b/crates/kv/src/mcp.rs
index 52a23b9..9e97f91 100644
--- a/crates/kv/src/mcp.rs
+++ b/crates/kv/src/mcp.rs
@@ -8,7 +8,9 @@ use std::io;
 use std::path::PathBuf;
 
 use kv_core::crypto::fill_random;
-use kv_core::proto::{AgentRequest, AgentResponse, ExecCall, HandleRequest, HttpCall, SessionInfo};
+use kv_core::proto::{
+    AgentRequest, AgentResponse, DbCall, ExecCall, HandleRequest, HttpCall, SessionInfo,
+};
 use kv_core::secret::{AuthPlacement, SecretKind};
 use rmcp::handler::server::wrapper::Parameters;
 use rmcp::model::{CallToolResult, ContentBlock};
@@ -53,6 +55,19 @@ pub struct ExecArgs {
     timeout_secs: Option<u64>,
 }
 
+#[derive(Deserialize, schemars::JsonSchema)]
+pub struct DbQueryArgs {
+    /// A postgres or redis handle from list_handles.
+    handle: String,
+    /// postgres: SQL, one or more statements separated by semicolons.
+    /// redis: one command line, such as HGETALL user:1 (quote arguments
+    /// with spaces as redis-cli does).
+    query: String,
+    /// Seconds before the query is stopped: 30 by default, at most 300.
+    #[serde(default)]
+    timeout_secs: Option<u64>,
+}
+
 /// Never carries a secret value: unknown fields such as `token` are refused.
 #[derive(Deserialize, schemars::JsonSchema)]
 #[serde(deny_unknown_fields)]
@@ -160,6 +175,27 @@ impl KvServer {
             .await)
     }
 
+    #[tool(
+        description = "Run a query on a postgres or redis handle. Postgres returns one result per statement, with values as text and NULL as null; redis returns the reply as JSON. Results are capped at 256 KiB, with secrets replaced by [kv:<handle>]. Read-only handles refuse writes. If the handle's mode is ask, this waits up to 60 s for the user to approve it in kv tui."
+    )]
+    async fn db_query(
+        &self,
+        peer: Peer<RoleServer>,
+        Parameters(args): Parameters<DbQueryArgs>,
+    ) -> Result<CallToolResult, ErrorData> {
+        let session = self.session(&peer);
+        Ok(self
+            .ask(
+                Some(&session),
+                AgentRequest::DbQuery(DbCall {
+                    handle: args.handle,
+                    query: args.query,
+                    timeout_secs: args.timeout_secs,
+                }),
+            )
+            .await)
+    }
+
     #[tool(
         description = "Ask the user to add a handle you need but do not have. Never include a secret value: the user types it in kv tui, where your request appears with the form filled in, and decides the policy. Returns at once; call list_handles later to see whether it was added."
     )]
@@ -217,7 +253,7 @@ impl KvServer {
     name = "kv",
     instructions = "kv lets you use the user's API keys, tokens and other secrets \
 without seeing them. Call list_handles to see what is available and how each handle may be \
-used, then call http_request or exec with a handle name. Secret values never appear in \
+used, then call http_request, exec or db_query with a handle name. Secret values never appear in \
 results; where one would, you see [kv:<handle>]. Handles in ask mode wait for the user to \
 approve each use in kv tui; approval_denied means they said no, so do not retry it. If a call \
 fails with vault_locked, ask the user to run `kv unlock`. If you need a secret that has no \
```

- [ ] **Step 4: Run the tests to watch them pass**

Run: `DEVELOPER_DIR=/Library/Developer/CommandLineTools cargo test -p kv --test mcp`
Expected: PASS (6 tests).

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "Db_query MCP tool"
```

### Task 5: Handle changes end grants and withdraw waiting requests

**Files:**
- Modify: `crates/kv/src/daemon/server.rs`
- Modify: `crates/kv/src/daemon/state.rs`
- Modify: `crates/kv/tests/approve.rs`
- Modify: `crates/kv/tests/approve_server.rs`

**Interfaces:**
- Consumes: Task 2's `RoleChecks::forget` (now called from `handle_changed`).
- Produces: `Daemon::take_ended(id: u64) -> Option<AgentResponse>`; a request waiting on a handle that is added, changed or removed is answered `policy_denied` ("... changed while the request waited; send it again") and audited `withdrawn` / `handle_changed`; that handle's grants end.

- [ ] **Step 1: Write the failing tests**

Apply with `git apply` from the repository root:

```diff
diff --git a/crates/kv/tests/approve.rs b/crates/kv/tests/approve.rs
index 4203b9f..c6e820a 100644
--- a/crates/kv/tests/approve.rs
+++ b/crates/kv/tests/approve.rs
@@ -325,3 +325,68 @@ fn a_base_url_request_shows_its_path_not_the_address() {
     // The agent's path; the base path is part of the hidden address.
     assert_eq!(approval.detail, "GET /projects?all=1");
 }
+
+#[test]
+fn a_grant_ends_when_its_handle_is_removed() {
+    let mut f = fixture();
+    let token = f.token();
+    let agent = session("s1");
+    let granted = f.wait(Some(&agent), ask_get(), f.t0);
+    done(&f.decide(&token, granted.id, Verdict::AllowSession));
+    f.control(ControlCommand::Remove {
+        name: "openrouter".into(),
+    });
+    f.add(openrouter(Mode::Ask));
+    // A new handle of the same name is asked about afresh.
+    f.wait(Some(&agent), ask_get(), f.t0);
+}
+
+#[test]
+fn changing_a_handle_withdraws_the_requests_waiting_on_it() {
+    let mut f = fixture();
+    f.add(env_secret(
+        "aws",
+        &[("AWS_KEY", AWS_KEY)],
+        &["terraform"],
+        Mode::Ask,
+    ));
+    let token = f.token();
+    let mut changed = f.wait(Some(&session("s1")), ask_get(), f.t0);
+    let mut other = f.wait(
+        Some(&session("s1")),
+        AgentRequest::Exec(run(&["aws"], &["terraform"], std::env::temp_dir())),
+        f.t0,
+    );
+    done(&f.send(
+        None,
+        Some(&token),
+        ControlCommand::SetPolicy {
+            name: "openrouter".into(),
+            patch: kv_core::proto::PolicyPatch {
+                allowed_hosts: Some(vec!["evil.example".into()]),
+                ..Default::default()
+            },
+        },
+    ));
+    assert!(
+        changed.verdict.try_recv().is_err(),
+        "the old request can no longer be approved"
+    );
+    match f.daemon.take_ended(changed.id) {
+        Some(AgentResponse::Error { code, message }) => {
+            assert_eq!(code, AgentErrorCode::PolicyDenied);
+            assert!(message.contains("changed"), "{message}");
+        }
+        other => panic!("{other:?}"),
+    }
+    assert_eq!(f.daemon.take_ended(changed.id), None, "answered once");
+    let approvals = f.overview(&token).approvals;
+    assert_eq!(approvals.len(), 1);
+    assert_eq!(approvals[0].id, other.id);
+    assert!(verdict(&mut other).is_none());
+    assert!(
+        f.audit_lines()
+            .iter()
+            .any(|l| l["decision"] == "withdrawn" && l["outcome"] == "handle_changed")
+    );
+}
diff --git a/crates/kv/tests/approve_server.rs b/crates/kv/tests/approve_server.rs
index 304178b..316b0e7 100644
--- a/crates/kv/tests/approve_server.rs
+++ b/crates/kv/tests/approve_server.rs
@@ -141,3 +141,26 @@ async fn a_request_whose_agent_hung_up_is_withdrawn() {
     let audit = std::fs::read_to_string(&daemon.paths.audit).unwrap();
     assert!(audit.contains(r#""outcome":"cancelled""#), "{audit}");
 }
+
+#[tokio::test(flavor = "multi_thread")]
+async fn a_request_waiting_on_a_changed_handle_is_told_why() {
+    let daemon = Daemon::start().await;
+    let call = daemon.agent_call();
+    daemon.waiting_id().await;
+    daemon
+        .with_token(ControlCommand::SetPolicy {
+            name: "api".into(),
+            patch: kv_core::proto::PolicyPatch {
+                allow_plain_http: Some(false),
+                ..Default::default()
+            },
+        })
+        .await;
+    match call.await.unwrap() {
+        AgentResponse::Error { code, message } => {
+            assert_eq!(code, AgentErrorCode::PolicyDenied);
+            assert!(message.contains("changed"), "{message}");
+        }
+        other => panic!("{other:?}"),
+    }
+}
```

- [ ] **Step 2: Run the tests to watch them fail**

Run: `DEVELOPER_DIR=/Library/Developer/CommandLineTools cargo test -p kv --test approve --test approve_server`
Expected: FAIL to compile: `no method named take_ended found for struct Daemon`.

- [ ] **Step 3: Implement**

Apply with `git apply`:

```diff
diff --git a/crates/kv/src/daemon/server.rs b/crates/kv/src/daemon/server.rs
index 758d9f2..42efaaf 100644
--- a/crates/kv/src/daemon/server.rs
+++ b/crates/kv/src/daemon/server.rs
@@ -225,12 +225,16 @@ async fn wait_then_run(
             code: AgentErrorCode::ApprovalDenied,
             message: "the user denied the request".into(),
         },
-        None => AgentResponse::Error {
-            code: AgentErrorCode::VaultLocked,
-            message:
-                "the vault was locked before the request was approved; ask the user to unlock it"
-                    .into(),
-        },
+        None => {
+            let shared = daemon.clone();
+            let ended = tokio::task::spawn_blocking(move || lock(&shared).take_ended(id)).await;
+            ended.ok().flatten().unwrap_or_else(|| AgentResponse::Error {
+                code: AgentErrorCode::VaultLocked,
+                message:
+                    "the vault was locked before the request was approved; ask the user to unlock it"
+                        .into(),
+            })
+        }
     })
 }
 
diff --git a/crates/kv/src/daemon/state.rs b/crates/kv/src/daemon/state.rs
index 5f91813..06adc07 100644
--- a/crates/kv/src/daemon/state.rs
+++ b/crates/kv/src/daemon/state.rs
@@ -132,6 +132,9 @@ pub struct Daemon {
     next_approval: u64,
     /// "Allow for the session" decisions. Cleared whenever the vault locks.
     grants: Vec<Grant>,
+    /// Answers for requests withdrawn while they waited, for the server to
+    /// pick up. Oldest are dropped past `MAX_PENDING`.
+    ended: BTreeMap<u64, AgentResponse>,
     /// Handles agents asked the user to add, oldest first. They hold no
     /// secrets, so they outlast a lock.
     handle_requests: Vec<RequestedHandle>,
@@ -236,6 +239,7 @@ impl Daemon {
             next_request: 0,
             request_notice: None,
             role_checks: RoleChecks::default(),
+            ended: BTreeMap::new(),
             grants: Vec::new(),
         }
     }
@@ -772,6 +776,37 @@ impl Daemon {
         }))
     }
 
+    /// Drops what was decided about a handle that was added, changed or
+    /// removed: its grants, its role check, and the requests waiting on it,
+    /// which hold its old value and policy and so may not run.
+    fn handle_changed(&mut self, name: &str, now: Instant) {
+        self.grants.retain(|g| g.handle != name);
+        self.role_checks.forget(name);
+        let (stale, kept) = std::mem::take(&mut self.approvals)
+            .into_iter()
+            .partition(|p: &Pending| p.handles.split(',').any(|h| h == name));
+        self.approvals = kept;
+        for pending in stale {
+            self.record_unanswered(&pending, "withdrawn", "handle_changed", now);
+            self.ended.insert(
+                pending.id,
+                agent_error(
+                    AgentErrorCode::PolicyDenied,
+                    format!("{name} changed while the request waited; send it again"),
+                ),
+            );
+            while self.ended.len() > MAX_PENDING {
+                self.ended.pop_first();
+            }
+        }
+    }
+
+    /// Why a request stopped waiting without a decision, if it was
+    /// withdrawn; `None` means the vault locked.
+    pub fn take_ended(&mut self, id: u64) -> Option<AgentResponse> {
+        self.ended.remove(&id)
+    }
+
     /// Ends the wait for a request nobody answered, and returns its reply.
     /// `None` if it was already decided or the vault locked.
     pub fn expire(&mut self, id: u64, now: Instant) -> Option<AgentResponse> {
@@ -984,9 +1019,8 @@ impl Daemon {
                         if let Some(name) = added {
                             self.handle_requests.retain(|r| r.request.name != name);
                         }
-                        // A new URL or policy may mean a different role.
                         if let Some(name) = &handle {
-                            self.role_checks.forget(name);
+                            self.handle_changed(name, now);
                         }
                         done(warnings)
                     })
```

- [ ] **Step 4: Run the tests to watch them pass**

Run: `DEVELOPER_DIR=/Library/Developer/CommandLineTools cargo test -p kv --test approve --test approve_server`
Expected: PASS (approve 16, approve_server 6).

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "Handle changes end grants and withdraw waiting requests"
```

### Task 6: CI databases job and docs

**Files:**
- Modify: `.github/workflows/ci.yml`
- Modify: `README.md`
- Modify: `docs/superpowers/specs/2026-10-08-kv-llm-secrets-broker-design.md`

**Interfaces:**
- Consumes: `KV_TEST_POSTGRES_URL`, `KV_TEST_REDIS_URL`, `KV_REQUIRE_DB_TESTS` as read by `tests/db_live.rs` (Task 2).
- Produces: a `databases` CI job on ubuntu-latest with Postgres 17 and Redis 7 service containers; README and spec text for `db_query`, read-only enforcement, the role check and withdrawn requests.

- [ ] **Step 1: Write the failing tests**

Apply with `git apply` from the repository root:

```diff
diff --git a/.github/workflows/ci.yml b/.github/workflows/ci.yml
index 52d6a51..5734b74 100644
--- a/.github/workflows/ci.yml
+++ b/.github/workflows/ci.yml
@@ -27,3 +27,32 @@ jobs:
       - run: cargo fmt --all --check
       - run: cargo clippy --workspace --all-targets -- -D warnings
       - run: cargo test --workspace
+
+  databases:
+    # db_query against real servers; service containers run on Linux only.
+    runs-on: ubuntu-latest
+    timeout-minutes: 20
+    services:
+      postgres:
+        image: postgres:17
+        env:
+          POSTGRES_PASSWORD: kv-test-password-123
+        ports: ["5432:5432"]
+        options: >-
+          --health-cmd pg_isready --health-interval 2s --health-timeout 5s --health-retries 15
+      redis:
+        image: redis:7
+        ports: ["6379:6379"]
+        options: >-
+          --health-cmd "redis-cli ping" --health-interval 2s --health-timeout 5s --health-retries 15
+    env:
+      KV_TEST_POSTGRES_URL: postgres://postgres:kv-test-password-123@localhost:5432/postgres
+      KV_TEST_REDIS_URL: redis://localhost:6379/0
+      KV_REQUIRE_DB_TESTS: "1"
+    steps:
+      - uses: actions/checkout@v5
+        with:
+          persist-credentials: false
+      - uses: dtolnay/rust-toolchain@stable
+      - uses: Swatinem/rust-cache@v2
+      - run: cargo test -p kv --test db_live
```

- [ ] **Step 2: Update the docs**

Apply with `git apply`:

````diff
diff --git a/README.md b/README.md
index d46c2e6..46d8851 100644
--- a/README.md
+++ b/README.md
@@ -5,9 +5,10 @@ secrets (`prod-db`, `openrouter`, `github`) and the broker does the
 authenticated work, so API keys, database URLs and other credentials never
 show up in a chat transcript or in the model's context.
 
-Status: agents can make HTTP requests and run programs with your secrets over
-MCP, and `kv tui` approves `--mode ask` requests as they arrive. Database
-access comes next.
+Status: agents can make HTTP requests, run programs and query Postgres and
+Redis with your secrets over MCP, and `kv tui` approves `--mode ask` requests
+as they arrive. A local database proxy for tools that need a connection comes
+next.
 
 ## Setup
 
@@ -18,15 +19,18 @@ kv init                       # create the vault and choose a passphrase
 kv add openrouter --kind http --host openrouter.ai --mode auto
 kv add aws --kind env --var AWS_ACCESS_KEY_ID --var AWS_SECRET_ACCESS_KEY \
   --cmd terraform             # mode ask: each use waits for you in kv tui
+kv add prod-db --kind postgres --read-only true   # prompts for the postgres:// URL
 
 claude mcp add kv -- kv mcp   # or add `kv mcp` as a stdio server in any MCP client
 ```
 
-The agent then sees five tools:
+The agent then sees six tools:
 
 - `list_handles`: names, kinds and policies, never values.
 - `http_request`: sends a request with the handle's credential attached.
 - `exec`: runs a program (never a shell) with an `env` handle's variables set.
+- `db_query`: runs SQL on a `postgres` handle or a command on a `redis`
+  handle (see below).
 - `request_handle`: asks you to add a handle it needs (see below).
 - `status`: whether the vault is unlocked.
 
@@ -45,6 +49,27 @@ from everything it gets back:
 kv add dokploy --kind http --base-url --header x-api-key --template '{}' --mode auto
 ```
 
+### Databases
+
+`db_query` opens a connection of its own for each query. Postgres takes one or
+more statements and returns one result per statement, every value as text; a
+Redis command line such as `HGETALL user:1` returns the reply as JSON. Results
+stop at 256 KiB, and a query stops after 30 seconds unless the agent asks for
+up to 300. The database's address is scrubbed from results like the password,
+unless it is `localhost`. TLS certificates are always checked against the
+system's trust store; `sslmode=disable` in the URL turns TLS off.
+
+With `--read-only true`:
+
+- Redis runs only read commands, such as `GET`, `HGETALL`, `SCAN` and
+  `ZRANGE`.
+- Postgres sessions start with `default_transaction_read_only=on`, and kv
+  refuses queries that mention a way to change that, and `DO` blocks. This is
+  best effort; the real guarantee is a database role that can only read. kv
+  checks the role when you `kv add` the handle and on its first query after
+  each unlock, and warns (in `kv add`, the query result and the Handles tab of
+  `kv tui`) when it can write.
+
 ## Approving requests
 
 Handles in `--mode ask` (the default) make the agent wait until you answer in
@@ -120,8 +145,8 @@ audit log (`audit.jsonl`), without values.
 
 ## Planned for v1
 
-- Local database proxy (Postgres, Redis) that connects upstream with the real
-  credentials, with optional read-only enforcement
+- `db_connect`: a local database proxy (Postgres, Redis) for tools that need a
+  connection, which connects upstream with the real credentials
 - Touch ID and Windows Hello unlock, and prebuilt binaries
 
 ## What kv protects against
diff --git a/docs/superpowers/specs/2026-10-08-kv-llm-secrets-broker-design.md b/docs/superpowers/specs/2026-10-08-kv-llm-secrets-broker-design.md
index e075845..5b391d2 100644
--- a/docs/superpowers/specs/2026-10-08-kv-llm-secrets-broker-design.md
+++ b/docs/superpowers/specs/2026-10-08-kv-llm-secrets-broker-design.md
@@ -207,7 +207,7 @@ returns values, the hostname inside a DB URL, or a secret's `base_url`.
 |---|---|---|
 | `list_handles` | — | handles with kind, description, constraints |
 | `http_request` | handle, method, url, headers?, body? | status, headers, body (scrubbed, body capped at 256 KB) |
-| `db_query` | handle, query (SQL or Redis command) | rows as JSON (scrubbed, capped) |
+| `db_query` | handle, query (SQL or Redis command), timeout? | Postgres: one result per statement, values as text; Redis: the reply as JSON (scrubbed, capped at 256 KB) |
 | `db_connect` | handle, ttl? | local connection URL with a lease token |
 | `exec` | handles[], argv[], cwd?, timeout? | exit code, stdout, stderr (scrubbed) |
 | `request_handle` | name, kind, description?, reason?, header?/template?/query_param?, base_url?, allowed_hosts?, env_vars?, allowed_cmds? | confirmation that the request waits in `kv tui` |
@@ -275,6 +275,23 @@ A notification announces each request.
     scrubber, so responses and errors never reveal the address.
 - **`db_query`**: the daemon connects itself (`tokio-postgres` / `redis`) and
   returns rows. Preferred path for agents.
+  - One connection per query. Postgres uses the simple query protocol, so a
+    query may hold several statements and every value comes back as text
+    (`null` for NULL), one result per statement with its row count. Redis
+    takes one command line, split as `redis-cli` splits it, and returns the
+    reply as JSON (maps as `[key, value]` pairs; a number that matches a
+    secret comes back as the scrubbed string).
+  - The timeout defaults to 30 s and may be at most 300 s; Postgres also gets
+    it as `statement_timeout`, so the server stops an abandoned query.
+    Results are cut at 256 KB and marked `truncated`.
+  - Commands that hold or change the connection (`SUBSCRIBE` and friends,
+    `MONITOR`, `AUTH`, `HELLO`, `QUIT`, `RESET`, `SYNC`) are refused for every
+    Redis handle.
+  - TLS certificates are always verified against the platform trust store,
+    whatever `sslmode` says (`sslmode=disable` still turns TLS off).
+  - Connection URLs must use `postgres://`/`postgresql://` or
+    `redis://`/`rediss://`. The host is scrubbed like the password unless it
+    is loopback, and errors are scrubbed, since they can quote the query.
 - **`db_connect`**: starts a loopback proxy on a random port and returns e.g.
   `postgres://kv:<lease-token>@127.0.0.1:41823/app`. The lease token is
   random, single-lease and expires with the TTL. The proxy authenticates the
@@ -309,10 +326,18 @@ A notification announces each request.
   `default_transaction_read_only=on`, and statements that change it
   (`SET ... transaction_read_only`, `BEGIN READ WRITE`, `SET SESSION
   CHARACTERISTICS`) are rejected in the simple query protocol and in `db_query`.
-  The real guarantee is a read-only role: kv checks the role's privileges when
-  the secret is added (via the unlocked daemon) and again on first use after
-  each unlock, and warns in the `kv add` output and the TUI when a `read_only`
-  secret uses a role with write access.
+  In `db_query` the check reads comments as spaces and keeps quoted text, and
+  refuses any query mentioning `read_only`, `read write`, `characteristics`,
+  `set_config`, `default_transaction` or `U&` escapes, and `DO` blocks, which
+  can build such a statement at run time. The checks run before approval.
+  The real guarantee is a read-only role: kv checks the role's privileges
+  (superuser, INSERT/UPDATE/DELETE/TRUNCATE on any table or CREATE on any
+  schema outside the system schemas) when the secret is added and again on
+  first use after each unlock, and warns in the `kv add` output, the query
+  result and the TUI when a `read_only` secret uses a role with write access.
+  `kv add` runs the check itself, with the URL it just read, so a slow
+  database never holds up the daemon; `kv tui` relies on the first-use
+  check.
 
 ## 5. Scrubbing, unlock, approval, audit, errors
 
@@ -372,7 +397,11 @@ A notification announces each request.
 - Handles tab: add, edit (description, or a new value of the same kind;
   blank secret fields keep the old value, and an http value without a base
   URL keeps the handle's), change policy, remove after a yes. Secret fields
-  are drawn as dots.
+  are drawn as dots. A read-only handle whose role can write is marked.
+- Adding, changing or removing a handle ends its "allow for session" grants
+  and its role check, and withdraws requests waiting on it, since they hold
+  its old value and policy; the agent gets `policy_denied` saying the handle
+  changed, and the request is audited as `withdrawn` / `handle_changed`.
 - Audit tab: the newest 200 entries, read from the end of `audit.jsonl` by
   the TUI itself, with control characters replaced.
 
@@ -419,8 +448,11 @@ or unscrubbed paths.
     upstream, host allow-list, redirect auth stripping, echoed key scrubbed.
   - Exec: test helper binary prints the injected secret raw, base64 and hex;
     output must be scrubbed.
-  - Postgres and Redis via `testcontainers` (Linux CI only), including
-    read-only enforcement.
+  - Postgres and Redis on real servers (Linux CI only, as GitHub Actions
+    service containers), including read-only enforcement. The tests read
+    `KV_TEST_POSTGRES_URL` and `KV_TEST_REDIS_URL` and skip without them,
+    unless `KV_REQUIRE_DB_TESTS` is set, as CI sets it; locally any server
+    will do.
   - Security: agent socket rejects control messages; control messages without
     token rejected; unlock backoff; decoder fuzzing; approval timeout fails
     closed.
````

- [ ] **Step 3: Run the tests to watch them pass**

Run: `DEVELOPER_DIR=/Library/Developer/CommandLineTools KV_TEST_POSTGRES_URL=postgres://kv:kv-test-password-123@127.0.0.1:54329/postgres cargo test --workspace && DEVELOPER_DIR=/Library/Developer/CommandLineTools cargo clippy --workspace --all-targets -- -D warnings`
Expected: PASS (329 tests with the local Postgres), no clippy warnings. The Redis test runs only in CI.

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "CI databases job and docs"
```
