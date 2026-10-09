//! The Postgres wire protocol, as far as the `db_connect` proxy needs it:
//! framing, the messages kv writes itself, scrubbing what the server sends,
//! the read-only gate, and logging in to the server.

use std::collections::HashMap;
use std::io;

use kv_core::db::{pg_session_violation, postgres_requires_tls};
use kv_core::scrub::Scrubber;
use postgres_protocol::authentication::md5_hash;
use postgres_protocol::authentication::sasl::{ChannelBinding, SCRAM_SHA_256, ScramSha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

use super::net::{self, Buffered, MAX_WIRE_MESSAGE, Upstream};

const SSL_REQUEST: u32 = 80_877_103;
const GSS_REQUEST: u32 = 80_877_104;
const CANCEL_REQUEST: u32 = 80_877_102;
const PROTOCOL_3_0: u32 = 196_608;

/// A message with a type byte, as both sides send after the first packet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    pub tag: u8,
    pub body: Vec<u8>,
}

impl Message {
    pub fn new(tag: u8, body: Vec<u8>) -> Self {
        Self { tag, body }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.body.len() + 5);
        out.push(self.tag);
        out.extend_from_slice(&(self.body.len() as u32 + 4).to_be_bytes());
        out.extend_from_slice(&self.body);
        out
    }
}

/// A message from the front of `data`, with the bytes it took.
pub fn parse_message(data: &[u8]) -> Result<Option<(Message, usize)>, String> {
    if data.len() < 5 {
        return Ok(None);
    }
    let len = u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as usize;
    if len < 4 {
        return Err("a message has a bad length".into());
    }
    if len - 4 > MAX_WIRE_MESSAGE {
        return Err("a message is larger than kv accepts (16 MiB)".into());
    }
    if data.len() < 1 + len {
        return Ok(None);
    }
    Ok(Some((
        Message::new(data[0], data[5..1 + len].to_vec()),
        1 + len,
    )))
}

/// `None` at the end of the stream.
pub async fn next_message<R: AsyncRead + Unpin>(
    conn: &mut Buffered<R>,
) -> io::Result<Option<Message>> {
    loop {
        if let Some((message, used)) = parse_message(conn.data()).map_err(io::Error::other)? {
            conn.consume(used);
            return Ok(Some(message));
        }
        if !conn.fill().await? {
            return match conn.data().is_empty() {
                true => Ok(None),
                false => Err(io::ErrorKind::UnexpectedEof.into()),
            };
        }
    }
}

/// The first packet a client sends, which has no type byte.
#[derive(Debug, PartialEq, Eq)]
pub enum Opening {
    Ssl,
    Gss,
    Cancel,
    /// Protocol 3.`minor`, with its parameters in order.
    Startup {
        minor: u16,
        params: Vec<(String, String)>,
    },
}

pub async fn next_opening<R: AsyncRead + Unpin>(
    conn: &mut Buffered<R>,
) -> io::Result<Option<Opening>> {
    loop {
        if let Some((opening, used)) = parse_opening(conn.data()).map_err(io::Error::other)? {
            conn.consume(used);
            return Ok(Some(opening));
        }
        if !conn.fill().await? {
            return Ok(None);
        }
    }
}

pub fn parse_opening(data: &[u8]) -> Result<Option<(Opening, usize)>, String> {
    if data.len() < 8 {
        return Ok(None);
    }
    let len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
    if !(8..=10_000).contains(&len) {
        return Err("the startup packet has a bad length".into());
    }
    if data.len() < len {
        return Ok(None);
    }
    let code = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    let opening = match code {
        SSL_REQUEST => Opening::Ssl,
        GSS_REQUEST => Opening::Gss,
        CANCEL_REQUEST => Opening::Cancel,
        code if code >> 16 == 3 => {
            let mut params = Vec::new();
            let mut pos = 8;
            while let Some((name, next)) = cstr(&data[..len], pos) {
                if name.is_empty() {
                    break;
                }
                let (value, next) =
                    cstr(&data[..len], next).ok_or("the startup packet is malformed")?;
                params.push((
                    String::from_utf8_lossy(name).into_owned(),
                    String::from_utf8_lossy(value).into_owned(),
                ));
                pos = next;
            }
            Opening::Startup {
                minor: (code & 0xffff) as u16,
                params,
            }
        }
        _ => return Err("kv speaks only protocol 3 of Postgres".into()),
    };
    Ok(Some((opening, len)))
}

/// A NUL-terminated string at `pos`, and where the next field starts.
fn cstr(body: &[u8], pos: usize) -> Option<(&[u8], usize)> {
    let rest = body.get(pos..)?;
    let end = rest.iter().position(|&b| b == 0)?;
    Some((&rest[..end], pos + end + 1))
}

fn put_cstr(out: &mut Vec<u8>, text: &[u8]) {
    out.extend_from_slice(text);
    out.push(0);
}

/// `ErrorResponse` with `severity` (`ERROR` or `FATAL`), an SQLSTATE and a
/// message.
pub fn error(severity: &str, code: &str, message: &str) -> Message {
    let mut body = Vec::new();
    for (field, value) in [(b'S', severity), (b'V', severity), (b'C', code)] {
        body.push(field);
        put_cstr(&mut body, value.as_bytes());
    }
    body.push(b'M');
    put_cstr(&mut body, message.replace('\0', " ").as_bytes());
    body.push(0);
    Message::new(b'E', body)
}

/// `Authentication*` with its code and any data after it.
pub fn auth(code: u32, data: &[u8]) -> Message {
    let mut body = code.to_be_bytes().to_vec();
    body.extend_from_slice(data);
    Message::new(b'R', body)
}

/// Tells a client that asked for 3.`minor` that kv speaks 3.0, and which
/// protocol options it does not know.
pub fn negotiate_protocol(unknown: &[String]) -> Message {
    let mut body = 0u32.to_be_bytes().to_vec();
    body.extend_from_slice(&(unknown.len() as u32).to_be_bytes());
    for name in unknown {
        put_cstr(&mut body, name.as_bytes());
    }
    Message::new(b'v', body)
}

/// The fields of an `ErrorResponse` or `NoticeResponse` as one line.
pub fn error_text(body: &[u8]) -> String {
    let mut message = String::new();
    let mut code = String::new();
    let mut pos = 0;
    while let Some(&field) = body.get(pos) {
        if field == 0 {
            break;
        }
        let Some((value, next)) = cstr(body, pos + 1) else {
            break;
        };
        match field {
            b'M' => message = String::from_utf8_lossy(value).into_owned(),
            b'C' => code = String::from_utf8_lossy(value).into_owned(),
            _ => {}
        }
        pos = next;
    }
    if code.is_empty() {
        message
    } else {
        format!("{message} (SQLSTATE {code})")
    }
}

/// Replaces secrets in what the server sends, keeping each message's
/// layout: values in rows, column names, error and notice fields,
/// notifications, parameter values, command tags, COPY data and function
/// results.
pub fn scrub_backend(message: Message, scrubber: &Scrubber) -> Result<Message, String> {
    let malformed = || "the server sent a malformed message".to_owned();
    let body = &message.body;
    let mut out = Vec::with_capacity(body.len());
    match message.tag {
        b'D' => {
            let count = body.get(..2).ok_or_else(malformed)?;
            out.extend_from_slice(count);
            let mut pos = 2;
            for _ in 0..u16::from_be_bytes([count[0], count[1]]) {
                let len = body.get(pos..pos + 4).ok_or_else(malformed)?;
                let len = i32::from_be_bytes([len[0], len[1], len[2], len[3]]);
                pos += 4;
                let Ok(len) = usize::try_from(len) else {
                    out.extend_from_slice(&(-1i32).to_be_bytes());
                    continue;
                };
                let value = body.get(pos..pos + len).ok_or_else(malformed)?;
                let value = scrubber.scrub(value);
                out.extend_from_slice(&(value.len() as i32).to_be_bytes());
                out.extend_from_slice(&value);
                pos += len;
            }
        }
        b'T' => {
            let count = body.get(..2).ok_or_else(malformed)?;
            out.extend_from_slice(count);
            let mut pos = 2;
            for _ in 0..u16::from_be_bytes([count[0], count[1]]) {
                let (name, next) = cstr(body, pos).ok_or_else(malformed)?;
                put_cstr(&mut out, &scrubber.scrub(name));
                out.extend_from_slice(body.get(next..next + 18).ok_or_else(malformed)?);
                pos = next + 18;
            }
        }
        b'E' | b'N' => {
            let mut pos = 0;
            while let Some(&field) = body.get(pos) {
                if field == 0 {
                    break;
                }
                let (value, next) = cstr(body, pos + 1).ok_or_else(malformed)?;
                out.push(field);
                put_cstr(&mut out, &scrubber.scrub(value));
                pos = next;
            }
            out.push(0);
        }
        b'A' => {
            out.extend_from_slice(body.get(..4).ok_or_else(malformed)?);
            let (channel, next) = cstr(body, 4).ok_or_else(malformed)?;
            let (payload, _) = cstr(body, next).ok_or_else(malformed)?;
            put_cstr(&mut out, &scrubber.scrub(channel));
            put_cstr(&mut out, &scrubber.scrub(payload));
        }
        b'S' => {
            let (name, next) = cstr(body, 0).ok_or_else(malformed)?;
            let (value, _) = cstr(body, next).ok_or_else(malformed)?;
            put_cstr(&mut out, name);
            put_cstr(&mut out, &scrubber.scrub(value));
        }
        b'C' => {
            let (tag, _) = cstr(body, 0).ok_or_else(malformed)?;
            put_cstr(&mut out, &scrubber.scrub(tag));
        }
        b'd' => out = scrubber.scrub(body),
        b'V' => {
            let len = body.get(..4).ok_or_else(malformed)?;
            let len = i32::from_be_bytes([len[0], len[1], len[2], len[3]]);
            match usize::try_from(len) {
                Ok(len) => {
                    let value = scrubber.scrub(body.get(4..4 + len).ok_or_else(malformed)?);
                    out.extend_from_slice(&(value.len() as i32).to_be_bytes());
                    out.extend_from_slice(&value);
                }
                Err(_) => out.extend_from_slice(&(-1i32).to_be_bytes()),
            }
        }
        _ => return Ok(message),
    }
    Ok(Message::new(message.tag, out))
}

/// The value of a `ParameterStatus` message.
pub fn parameter(message: &Message) -> Option<(String, String)> {
    let (name, next) = cstr(&message.body, 0)?;
    let (value, _) = cstr(&message.body, next)?;
    Some((
        String::from_utf8_lossy(name).into_owned(),
        String::from_utf8_lossy(value).into_owned(),
    ))
}

/// Checks what a client sends on a read-only session, message by message,
/// with `pg_session_violation` on each simple query and each statement it
/// prepares. In the extended protocol a batch runs until `Sync`, so once a
/// portal that ends the transaction has been executed only `Sync` may
/// follow. Fast-path function calls are refused: they could call
/// `set_config`.
#[derive(Default)]
pub struct ReadOnlyGate {
    statements: HashMap<Vec<u8>, bool>,
    portals: HashMap<Vec<u8>, bool>,
    ended: bool,
    /// Extended-protocol messages have passed since the last Sync. After an
    /// error the server skips the rest of the batch, so kv cannot be sure
    /// they took effect.
    open: bool,
}

impl ReadOnlyGate {
    /// `Ok(true)` when the message ends a batch: the server answers it
    /// with `ReadyForQuery`.
    pub fn check(&mut self, message: &Message) -> Result<bool, String> {
        let body = &message.body;
        let malformed = || "the client sent a malformed message".to_owned();
        if self.ended && !matches!(message.tag, b'S' | b'H' | b'X') {
            return Err(
                "the handle is read-only, and kv refuses statements after COMMIT, END, \
                 ROLLBACK or ABORT before the next Sync; send them separately"
                    .into(),
            );
        }
        let open = self.open;
        if matches!(message.tag, b'P' | b'B' | b'E' | b'C' | b'D') {
            self.open = true;
        }
        match message.tag {
            // The server would skip it after an error, and never answer.
            b'Q' if open => Err(
                "the handle is read-only, and kv refuses a simple query in the middle of an \
                 extended-protocol batch; send Sync first"
                    .into(),
            ),
            b'Q' => {
                let (sql, _) = cstr(body, 0).ok_or_else(malformed)?;
                pg_session_violation(&String::from_utf8_lossy(sql))?;
                Ok(true)
            }
            b'P' => {
                let (name, next) = cstr(body, 0).ok_or_else(malformed)?;
                let (sql, _) = cstr(body, next).ok_or_else(malformed)?;
                let ends = pg_session_violation(&String::from_utf8_lossy(sql))?;
                // The server keeps a named statement until it is closed and
                // refuses to reuse the name, and a Parse may be skipped after
                // an error: once a name may end a transaction it stays that
                // way. Only an unnamed Parse first in its batch surely
                // replaces the last one.
                let replaced = name.is_empty() && !open;
                let known = self.statements.entry(name.to_vec()).or_default();
                *known = ends || (*known && !replaced);
                Ok(false)
            }
            b'B' => {
                let (portal, next) = cstr(body, 0).ok_or_else(malformed)?;
                let (statement, _) = cstr(body, next).ok_or_else(malformed)?;
                // A statement kv never saw prepared may be anything.
                let ends = self.statements.get(statement).copied().unwrap_or(true);
                self.portals.insert(portal.to_vec(), ends);
                Ok(false)
            }
            b'E' => {
                let (portal, _) = cstr(body, 0).ok_or_else(malformed)?;
                self.ended = self.portals.get(portal).copied().unwrap_or(true);
                Ok(false)
            }
            b'C' => {
                let kind = body.first().ok_or_else(malformed)?;
                let (name, _) = cstr(body, 1).ok_or_else(malformed)?;
                // A Close may be skipped too: a statement that may end a
                // transaction is never forgotten.
                match kind {
                    b'S' if self.statements.get(name) == Some(&false) => {
                        self.statements.remove(name);
                    }
                    b'S' => {}
                    _ => {
                        self.portals.remove(name);
                    }
                }
                Ok(false)
            }
            b'S' => {
                self.ended = false;
                self.open = false;
                Ok(true)
            }
            b'F' => Err(
                "the handle is read-only, and kv refuses fast-path function calls on read-only \
                 handles"
                    .into(),
            ),
            _ => Ok(false),
        }
    }
}

enum Ssl {
    Disable,
    Prefer,
    Require,
}

/// Where a Postgres URL points, and how to log in.
pub struct PgTarget {
    /// The address to connect to, the name to check its certificate
    /// against, and the port.
    hosts: Vec<(String, String, u16)>,
    user: String,
    password: Option<Vec<u8>>,
    pub dbname: String,
    ssl: Ssl,
    /// `options` from the URL.
    pub options: Option<String>,
}

impl PgTarget {
    pub fn parse(url: &str) -> Result<Self, String> {
        use tokio_postgres::config::{Host, SslMode};
        let config: tokio_postgres::Config = url
            .parse()
            .map_err(|_| "the handle's connection URL is not a valid Postgres URL".to_owned())?;
        let ports = config.get_ports();
        let addrs = config.get_hostaddrs();
        let mut hosts = Vec::new();
        for (i, host) in config.get_hosts().iter().enumerate() {
            let port = ports.get(i).or(ports.first()).copied().unwrap_or(5432);
            if let Host::Tcp(name) = host {
                let address = addrs.get(i).map_or_else(|| name.clone(), |a| a.to_string());
                hosts.push((address, name.clone(), port));
            }
        }
        if config.get_hosts().is_empty() {
            for (i, addr) in addrs.iter().enumerate() {
                let port = ports.get(i).or(ports.first()).copied().unwrap_or(5432);
                hosts.push((addr.to_string(), addr.to_string(), port));
            }
        }
        if hosts.is_empty() {
            return Err("db_connect needs a TCP host in the handle's URL".into());
        }
        let user = config
            .get_user()
            .ok_or("the handle's URL names no user")?
            .to_owned();
        let ssl = if postgres_requires_tls(url) {
            Ssl::Require
        } else {
            match config.get_ssl_mode() {
                SslMode::Disable => Ssl::Disable,
                SslMode::Prefer => Ssl::Prefer,
                _ => Ssl::Require,
            }
        };
        Ok(Self {
            hosts,
            dbname: config.get_dbname().unwrap_or(&user).to_owned(),
            user,
            password: config.get_password().map(<[u8]>::to_vec),
            ssl,
            options: config.get_options().map(str::to_owned),
        })
    }
}

/// Connects to the first host that answers, logs in with `params` (other
/// than `user` and `database`, which come from the URL) and reads up to the
/// first `ReadyForQuery`. Returns the stream and what the server sent after
/// logging in. Errors may name the host: scrub them.
pub async fn connect(
    target: &PgTarget,
    params: &[(String, String)],
) -> Result<(Buffered<Upstream>, Vec<Message>), String> {
    let mut last = String::from("no host to connect to");
    for (address, name, port) in &target.hosts {
        match connect_to(target, address, name, *port, params).await {
            Ok(connected) => return Ok(connected),
            Err(e) => last = e,
        }
    }
    Err(last)
}

async fn connect_to(
    target: &PgTarget,
    address: &str,
    name: &str,
    port: u16,
    params: &[(String, String)],
) -> Result<(Buffered<Upstream>, Vec<Message>), String> {
    let failed = |e: io::Error| format!("could not connect to {name}:{port}: {e}");
    let mut tcp = net::tcp(address, port).await.map_err(failed)?;
    let stream = match target.ssl {
        Ssl::Disable => Upstream::Plain(tcp),
        Ssl::Prefer | Ssl::Require => {
            let mut request = 8u32.to_be_bytes().to_vec();
            request.extend_from_slice(&SSL_REQUEST.to_be_bytes());
            tcp.write_all(&request).await.map_err(failed)?;
            let mut answer = [0u8; 1];
            tcp.read_exact(&mut answer).await.map_err(failed)?;
            match (answer[0], &target.ssl) {
                (b'S', _) => net::tls(tcp, name).await.map_err(failed)?,
                (b'N', Ssl::Prefer) => Upstream::Plain(tcp),
                (b'N', _) => {
                    return Err(format!(
                        "{name}:{port} does not offer TLS, and kv requires it for a remote server \
                         (add sslmode=disable to the URL to connect without it)"
                    ));
                }
                _ => return Err(format!("{name}:{port} answered the TLS request oddly")),
            }
        }
    };
    let mut conn = Buffered::new(stream);
    let mut startup = PROTOCOL_3_0.to_be_bytes().to_vec();
    let fixed = [("user", target.user.as_str()), ("database", &target.dbname)];
    for (key, value) in fixed
        .into_iter()
        .chain(params.iter().map(|(k, v)| (k.as_str(), v.as_str())))
    {
        put_cstr(&mut startup, key.as_bytes());
        put_cstr(&mut startup, value.as_bytes());
    }
    startup.push(0);
    let mut packet = (startup.len() as u32 + 4).to_be_bytes().to_vec();
    packet.extend_from_slice(&startup);
    send(&mut conn, &packet).await?;
    log_in(&mut conn, target).await?;

    let mut after = Vec::new();
    loop {
        let message = recv(&mut conn).await?;
        match message.tag {
            b'E' => return Err(error_text(&message.body)),
            b'Z' => {
                after.push(message);
                return Ok((conn, after));
            }
            _ => after.push(message),
        }
    }
}

async fn log_in(conn: &mut Buffered<Upstream>, target: &PgTarget) -> Result<(), String> {
    let password = target.password.as_deref().unwrap_or_default();
    let mut scram: Option<ScramSha256> = None;
    loop {
        let message = recv(conn).await?;
        match message.tag {
            b'E' => return Err(error_text(&message.body)),
            b'R' => {}
            _ => return Err("the server sent something unexpected while logging in".into()),
        }
        let body = &message.body;
        let code = body
            .get(..4)
            .map(|c| u32::from_be_bytes([c[0], c[1], c[2], c[3]]))
            .ok_or("the server sent a malformed message")?;
        match code {
            0 => return Ok(()),
            3 => {
                let mut reply = password.to_vec();
                reply.push(0);
                send(conn, &Message::new(b'p', reply).encode()).await?;
            }
            5 => {
                let salt: [u8; 4] = body
                    .get(4..8)
                    .and_then(|s| s.try_into().ok())
                    .ok_or("the server sent a malformed message")?;
                let mut reply = md5_hash(target.user.as_bytes(), password, salt).into_bytes();
                reply.push(0);
                send(conn, &Message::new(b'p', reply).encode()).await?;
            }
            10 => {
                let offered = body[4..]
                    .split(|&b| b == 0)
                    .any(|m| m == SCRAM_SHA_256.as_bytes());
                if !offered {
                    return Err("the server offers no login method kv supports".into());
                }
                let state = ScramSha256::new(password, ChannelBinding::unsupported());
                let mut reply = Vec::new();
                put_cstr(&mut reply, SCRAM_SHA_256.as_bytes());
                reply.extend_from_slice(&(state.message().len() as i32).to_be_bytes());
                reply.extend_from_slice(state.message());
                send(conn, &Message::new(b'p', reply).encode()).await?;
                scram = Some(state);
            }
            11 => {
                let state = scram.as_mut().ok_or("the server's login is out of order")?;
                state
                    .update(&body[4..])
                    .map_err(|e| format!("the login failed: {e}"))?;
                send(conn, &Message::new(b'p', state.message().to_vec()).encode()).await?;
            }
            12 => {
                let state = scram.as_mut().ok_or("the server's login is out of order")?;
                state
                    .finish(&body[4..])
                    .map_err(|e| format!("the server's login proof is wrong: {e}"))?;
            }
            _ => return Err("the server asks for a login method kv does not support".into()),
        }
    }
}

async fn send(conn: &mut Buffered<Upstream>, bytes: &[u8]) -> Result<(), String> {
    conn.get_mut()
        .write_all(bytes)
        .await
        .map_err(|e| format!("the connection failed: {e}"))
}

async fn recv(conn: &mut Buffered<Upstream>) -> Result<Message, String> {
    next_message(conn)
        .await
        .map_err(|e| format!("the connection failed: {e}"))?
        .ok_or_else(|| "the server closed the connection".to_owned())
}
