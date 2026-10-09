//! Checks on what `db_query` and `db_connect` send: the best-effort guards
//! that keep a read-only Postgres session read-only, what a Postgres URL
//! names, and how a Redis command line is split and which commands run.

/// Why `sql` may not run through `db_query` on a read-only Postgres
/// handle, or `None`.
///
/// Sessions for read-only handles start with
/// `default_transaction_read_only=on`; this refuses statements that would
/// switch that off, `DO` blocks, which can build such a statement at run
/// time, and statements that end the transaction or call a procedure
/// (which can end one): a query can build the switch from string pieces
/// inside a function, and it takes effect in the next transaction.
/// Comments are read as spaces, as Postgres reads them, and quoted text is
/// kept, so a mention inside a string is refused too: when in doubt it says
/// no. The real guarantee is a role without write privileges.
pub fn pg_read_only_violation(sql: &str) -> Option<&'static str> {
    let text = normalize_sql(sql);
    if let Some(reason) = mode_change(&text) {
        return Some(reason);
    }
    for statement in statements(&text) {
        if let Some(reason) = runs_code(statement) {
            return Some(reason);
        }
        if ends_transaction(statement) {
            return Some(
                "the handle is read-only, and kv refuses statements that end the transaction \
                 or call procedures on read-only handles",
            );
        }
    }
    None
}

/// The `db_connect` guard for one batch on a read-only Postgres session: a
/// simple query, or one statement of the extended protocol. `Ok(true)`
/// when the batch ends with a statement that ends the transaction.
///
/// The proxy watches the server report `default_transaction_read_only`
/// before it passes on the client's next batch, so a switch built at run
/// time is caught there. What it cannot catch is a switch and a write in
/// one batch with the transaction ended between them, so nothing may
/// follow `COMMIT`, `END`, `ROLLBACK` or `ABORT` in a batch, and `CALL`,
/// `PREPARE TRANSACTION` and `DO`, which can end transactions inside them,
/// are refused.
pub fn pg_session_violation(sql: &str) -> Result<bool, &'static str> {
    let text = normalize_sql(sql);
    if let Some(reason) = mode_change(&text) {
        return Err(reason);
    }
    let mut ended = false;
    for statement in statements(&text) {
        if ended {
            return Err(
                "the handle is read-only, and kv refuses statements after COMMIT, END, ROLLBACK \
                 or ABORT in the same query; send them separately",
            );
        }
        if let Some(reason) = runs_code(statement) {
            return Err(reason);
        }
        ended = ends_transaction(statement);
    }
    Ok(ended)
}

/// Mentions of a way to turn read-only off.
fn mode_change(text: &str) -> Option<&'static str> {
    let changes_mode = ["read_only", "read write", "characteristics", "set_config"]
        .iter()
        .any(|word| text.contains(word))
        || text.contains("default_transaction")
        || text.contains("u&");
    changes_mode.then_some(
        "the handle is read-only, and this query mentions a way to change that; kv refuses it",
    )
}

/// `DO` blocks and procedures, which can end transactions inside them.
fn runs_code(statement: &str) -> Option<&'static str> {
    if starts(statement, "do") {
        return Some("the handle is read-only, and kv refuses DO blocks on read-only handles");
    }
    if starts(statement, "call") || starts(statement, "prepare transaction") {
        return Some(
            "the handle is read-only, and kv refuses statements that end the transaction \
             or call procedures on read-only handles",
        );
    }
    None
}

fn ends_transaction(statement: &str) -> bool {
    ["commit", "end", "rollback", "abort"]
        .iter()
        .any(|word| starts(statement, word))
}

/// The statements in normalized SQL. A `;` inside quotes splits too, which
/// only ever makes the guards stricter.
fn statements(text: &str) -> impl Iterator<Item = &str> {
    text.split(';').map(str::trim).filter(|s| !s.is_empty())
}

fn starts(statement: &str, word: &str) -> bool {
    statement.strip_prefix(word).is_some_and(|rest| {
        !rest
            .chars()
            .next()
            .is_some_and(|c| c.is_alphanumeric() || c == '_')
    })
}

/// Whether kv should insist on TLS for a Postgres URL: it names no
/// `sslmode`, and some host it names is not on this machine. Postgres
/// clients default to `prefer`, which an attacker on the network can turn
/// into plain text by answering that the server has no TLS.
pub fn postgres_requires_tls(url: &str) -> bool {
    let named = postgres_query(url).any(|(key, _)| key == "sslmode");
    !named && postgres_hosts(url).iter().any(|host| !is_local(host))
}

/// The hosts a Postgres URL names: those in its authority, which may list
/// several (`h1:5432,h2`), and those in `host=` and `hostaddr=`. URLs with
/// several hosts are valid for Postgres but not for the `url` crate.
pub fn postgres_hosts(url: &str) -> Vec<String> {
    let mut hosts: Vec<String> = postgres_authority(url)
        .map(|authority| authority.rsplit_once('@').map_or(authority, |(_, h)| h))
        .into_iter()
        .flat_map(|list| list.split(','))
        .filter_map(|entry| match entry.strip_prefix('[') {
            Some(v6) => v6.split(']').next(),
            None => entry.split(':').next(),
        })
        .map(|host| {
            percent_encoding::percent_decode_str(host)
                .decode_utf8_lossy()
                .into_owned()
        })
        .collect();
    for (key, value) in postgres_query(url) {
        if key == "host" || key == "hostaddr" {
            hosts.extend(value.split(',').map(|h| h.trim().to_owned()));
        }
    }
    hosts.retain(|host| !host.is_empty());
    hosts
}

/// The passwords a Postgres URL holds, as written: in its authority, and
/// in `password=`.
pub fn postgres_passwords(url: &str) -> Vec<String> {
    let mut passwords: Vec<String> = postgres_authority(url)
        .and_then(|authority| authority.rsplit_once('@'))
        .and_then(|(userinfo, _)| userinfo.split_once(':'))
        .map(|(_, password)| password.to_owned())
        .into_iter()
        .collect();
    passwords.extend(
        postgres_query(url)
            .filter(|(key, _)| key == "password")
            .map(|(_, value)| value),
    );
    passwords.retain(|p| !p.is_empty());
    passwords
}

/// Between `://` and the path, query or fragment.
fn postgres_authority(url: &str) -> Option<&str> {
    let (_, rest) = url.split_once("://")?;
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    Some(&rest[..end])
}

fn postgres_query(url: &str) -> impl Iterator<Item = (String, String)> {
    let query = url
        .split_once('?')
        .map_or("", |(_, q)| q.split('#').next().unwrap_or(""));
    url::form_urlencoded::parse(query.as_bytes())
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect::<Vec<_>>()
        .into_iter()
}

/// `localhost`, a loopback address, or a Unix socket directory.
pub(crate) fn is_local(host: &str) -> bool {
    let host = host.trim_start_matches('[').trim_end_matches(']');
    host.starts_with('/')
        || host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

/// Lowercases `sql`, turns comments into a space and collapses whitespace,
/// keeping quoted text (strings, quoted identifiers, dollar quotes) as it
/// is, so a comment marker inside quotes is not read as a comment.
fn normalize_sql(sql: &str) -> String {
    let chars: Vec<char> = sql.chars().collect();
    let mut out = String::with_capacity(sql.len());
    let mut i = 0;
    let push_space = |out: &mut String| {
        if !out.ends_with(' ') {
            out.push(' ');
        }
    };
    while i < chars.len() {
        let c = chars[i];
        let next = chars.get(i + 1).copied();
        match c {
            '-' if next == Some('-') => {
                while i < chars.len() && chars[i] != '\n' {
                    i += 1;
                }
                push_space(&mut out);
            }
            '/' if next == Some('*') => {
                let mut depth = 0;
                while i < chars.len() {
                    if chars[i] == '/' && chars.get(i + 1) == Some(&'*') {
                        depth += 1;
                        i += 2;
                    } else if chars[i] == '*' && chars.get(i + 1) == Some(&'/') {
                        depth -= 1;
                        i += 2;
                        if depth == 0 {
                            break;
                        }
                    } else {
                        i += 1;
                    }
                }
                push_space(&mut out);
            }
            '\'' | '"' => {
                // E'...' strings take backslash escapes.
                let escapes = c == '\''
                    && i > 0
                    && matches!(chars[i - 1], 'e' | 'E')
                    && (i < 2 || !(chars[i - 2].is_alphanumeric() || chars[i - 2] == '_'));
                out.push(c);
                i += 1;
                while i < chars.len() {
                    let d = chars[i];
                    if escapes && d == '\\' && i + 1 < chars.len() {
                        out.extend(chars[i..i + 2].iter().flat_map(|c| c.to_lowercase()));
                        i += 2;
                        continue;
                    }
                    out.extend(d.to_lowercase());
                    i += 1;
                    if d == c {
                        // A doubled quote is a quote inside the text.
                        if chars.get(i) == Some(&c) {
                            out.push(c);
                            i += 1;
                            continue;
                        }
                        break;
                    }
                }
            }
            // After a name character, `$` is part of the name (`a$x$`).
            '$' if i > 0
                && (chars[i - 1].is_alphanumeric() || matches!(chars[i - 1], '_' | '$')) =>
            {
                out.push('$');
                i += 1;
            }
            '$' => match dollar_tag(&chars[i..]) {
                Some(tag) => {
                    let tag: Vec<char> = tag.chars().collect();
                    out.extend(tag.iter().flat_map(|c| c.to_lowercase()));
                    i += tag.len();
                    while i < chars.len() && !chars[i..].starts_with(&tag) {
                        out.extend(chars[i].to_lowercase());
                        i += 1;
                    }
                    out.extend(tag.iter().flat_map(|c| c.to_lowercase()));
                    i += tag.len();
                }
                None => {
                    out.push('$');
                    i += 1;
                }
            },
            c if c.is_whitespace() => {
                push_space(&mut out);
                i += 1;
            }
            c => {
                out.extend(c.to_lowercase());
                i += 1;
            }
        }
    }
    out
}

/// The `$tag$` opening a dollar-quoted string at the start of `chars`. Not
/// `$1`: a tag never starts with a digit.
fn dollar_tag(chars: &[char]) -> Option<String> {
    let mut end = 1;
    while end < chars.len() && chars[end] != '$' {
        let c = chars[end];
        let ok = c == '_' || c.is_alphabetic() || (end > 1 && c.is_ascii_digit());
        if !ok {
            return None;
        }
        end += 1;
    }
    (end < chars.len()).then(|| chars[..=end].iter().collect())
}

/// Splits a Redis command line the way `redis-cli` does: words separated by
/// spaces; `"..."` takes `\n`, `\r`, `\t`, `\b`, `\a`, `\\`, `\"` and
/// `\xHH`; `'...'` takes only `\'`. A closing quote must end the word.
pub fn split_command(line: &str) -> Result<Vec<Vec<u8>>, String> {
    let bytes = line.as_bytes();
    let mut args = Vec::new();
    let mut i = 0;
    loop {
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i == bytes.len() {
            break;
        }
        let mut arg = Vec::new();
        let quote = match bytes[i] {
            q @ (b'"' | b'\'') => {
                i += 1;
                Some(q)
            }
            _ => None,
        };
        loop {
            let Some(&b) = bytes.get(i) else {
                if quote.is_some() {
                    return Err("a quote is not closed".into());
                }
                break;
            };
            match quote {
                None if b.is_ascii_whitespace() => break,
                None => {
                    arg.push(b);
                    i += 1;
                }
                Some(q) if b == q => {
                    i += 1;
                    if bytes.get(i).is_some_and(|b| !b.is_ascii_whitespace()) {
                        return Err("a closing quote must be followed by a space".into());
                    }
                    break;
                }
                Some(b'"') if b == b'\\' && i + 1 < bytes.len() => {
                    let e = bytes[i + 1];
                    let hex = bytes
                        .get(i + 2..i + 4)
                        .and_then(|h| std::str::from_utf8(h).ok())
                        .and_then(|h| u8::from_str_radix(h, 16).ok());
                    match (e, hex) {
                        (b'x', Some(value)) => {
                            arg.push(value);
                            i += 4;
                            continue;
                        }
                        (b'n', _) => arg.push(b'\n'),
                        (b'r', _) => arg.push(b'\r'),
                        (b't', _) => arg.push(b'\t'),
                        (b'b', _) => arg.push(8),
                        (b'a', _) => arg.push(7),
                        (other, _) => arg.push(other),
                    }
                    i += 2;
                }
                Some(_) if b == b'\\' && bytes.get(i + 1) == Some(&b'\'') => {
                    arg.push(b'\'');
                    i += 2;
                }
                Some(_) => {
                    arg.push(b);
                    i += 1;
                }
            }
        }
        args.push(arg);
    }
    if args.is_empty() {
        return Err("the command is empty".into());
    }
    Ok(args)
}

/// Why a Redis command is not run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RedisRefusal {
    /// It holds or changes the connection (subscriptions, `MONITOR`,
    /// `AUTH`), which a one-shot query cannot use.
    Never(String),
    /// The handle is read-only and this is not a read command.
    NotRead(String),
}

impl std::fmt::Display for RedisRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Never(command) => write!(
                f,
                "{command} holds or changes the connection, which db_query cannot do"
            ),
            Self::NotRead(command) => write!(
                f,
                "{command} is not a read command, and the handle is read-only"
            ),
        }
    }
}

/// Commands that hold or change the connection.
const NEVER: &[&str] = &[
    "AUTH",
    "HELLO",
    "MONITOR",
    "PSUBSCRIBE",
    "PSYNC",
    "PUNSUBSCRIBE",
    "QUIT",
    "RESET",
    "SSUBSCRIBE",
    "SUBSCRIBE",
    "SUNSUBSCRIBE",
    "SYNC",
    "UNSUBSCRIBE",
];

/// Commands that only read. Ones with subcommands are in `READ_SUBCOMMANDS`.
const READ: &[&str] = &[
    "BITCOUNT",
    "BITFIELD_RO",
    "BITPOS",
    "DBSIZE",
    "ECHO",
    "EXISTS",
    "EXPIRETIME",
    "GEODIST",
    "GEOHASH",
    "GEOPOS",
    "GEORADIUSBYMEMBER_RO",
    "GEORADIUS_RO",
    "GEOSEARCH",
    "GET",
    "GETBIT",
    "GETRANGE",
    "HEXISTS",
    "HGET",
    "HGETALL",
    "HKEYS",
    "HLEN",
    "HMGET",
    "HRANDFIELD",
    "HSCAN",
    "HSTRLEN",
    "HVALS",
    "INFO",
    "KEYS",
    "LASTSAVE",
    "LCS",
    "LINDEX",
    "LLEN",
    "LPOS",
    "LRANGE",
    "MGET",
    "PEXPIRETIME",
    "PFCOUNT",
    "PING",
    "PTTL",
    "RANDOMKEY",
    "SCAN",
    "SCARD",
    "SDIFF",
    "SINTER",
    "SINTERCARD",
    "SISMEMBER",
    "SMEMBERS",
    "SMISMEMBER",
    "SORT_RO",
    "SRANDMEMBER",
    "SSCAN",
    "STRLEN",
    "SUBSTR",
    "SUNION",
    "TIME",
    "TTL",
    "TYPE",
    "XLEN",
    "XPENDING",
    "XRANGE",
    "XREAD",
    "XREVRANGE",
    "ZCARD",
    "ZCOUNT",
    "ZDIFF",
    "ZINTER",
    "ZINTERCARD",
    "ZLEXCOUNT",
    "ZMSCORE",
    "ZRANDMEMBER",
    "ZRANGE",
    "ZRANGEBYLEX",
    "ZRANGEBYSCORE",
    "ZRANK",
    "ZREVRANGE",
    "ZREVRANGEBYLEX",
    "ZREVRANGEBYSCORE",
    "ZREVRANK",
    "ZSCAN",
    "ZSCORE",
    "ZUNION",
];

const READ_SUBCOMMANDS: &[(&str, &[&str])] = &[
    ("MEMORY", &["USAGE"]),
    ("OBJECT", &["ENCODING", "FREQ", "IDLETIME", "REFCOUNT"]),
    ("XINFO", &["CONSUMERS", "GROUPS", "STREAM"]),
];

/// Whether `args` (a split command line) may run on a handle.
pub fn check_redis(args: &[Vec<u8>], read_only: bool) -> Result<(), RedisRefusal> {
    let word = |i: usize| {
        args.get(i)
            .map(|a| String::from_utf8_lossy(a).to_ascii_uppercase())
            .unwrap_or_default()
    };
    let command = word(0);
    if NEVER.contains(&command.as_str()) {
        return Err(RedisRefusal::Never(command));
    }
    if !read_only || READ.contains(&command.as_str()) {
        return Ok(());
    }
    let sub = word(1);
    let reads = READ_SUBCOMMANDS
        .iter()
        .any(|(name, subs)| *name == command && subs.contains(&sub.as_str()));
    if reads {
        Ok(())
    } else if READ_SUBCOMMANDS.iter().any(|(name, _)| *name == command) {
        Err(RedisRefusal::NotRead(format!("{command} {sub}")))
    } else {
        Err(RedisRefusal::NotRead(command))
    }
}
