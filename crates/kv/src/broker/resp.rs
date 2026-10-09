//! The Redis protocol (RESP2 and RESP3): connecting to a server, commands,
//! and replies read one token at a time, so a reply is never held whole.

use std::io;

use kv_core::scrub::Scrubber;
use percent_encoding::percent_decode_str;
use tokio::io::{AsyncRead, AsyncWriteExt};

use super::net::{self, Buffered, MAX_WIRE_MESSAGE, Upstream};

/// Where a Redis URL points, and how to log in.
#[derive(Clone)]
pub struct RedisTarget {
    host: String,
    port: u16,
    tls: bool,
    username: Option<String>,
    password: Option<String>,
    pub db: u32,
}

impl RedisTarget {
    pub fn parse(url: &str) -> Result<Self, String> {
        let invalid = || "the handle's connection URL is not a valid Redis URL".to_owned();
        let parsed = url::Url::parse(url).map_err(|_| invalid())?;
        let tls = match parsed.scheme() {
            "redis" => false,
            "rediss" => true,
            _ => return Err(invalid()),
        };
        if parsed.fragment().is_some() {
            return Err(
                "kv does not accept a fragment such as #insecure in a Redis URL; it always checks \
                 TLS certificates"
                    .into(),
            );
        }
        let host = match parsed.host() {
            Some(url::Host::Ipv6(ip)) => ip.to_string(),
            Some(host) => host.to_string(),
            None => return Err(invalid()),
        };
        let decode = |s: &str| percent_decode_str(s).decode_utf8_lossy().into_owned();
        let db = match parsed.path().trim_matches('/') {
            "" => 0,
            n => n
                .parse()
                .map_err(|_| "the database in the Redis URL is not a number".to_owned())?,
        };
        Ok(Self {
            host,
            port: parsed.port().unwrap_or(6379),
            tls,
            username: (!parsed.username().is_empty()).then(|| decode(parsed.username())),
            password: parsed.password().map(decode),
            db,
        })
    }
}

/// Connects, logs in and selects the URL's database.
pub async fn connect(target: &RedisTarget) -> io::Result<Buffered<Upstream>> {
    let stream = net::tcp(&target.host, target.port).await?;
    let stream = if target.tls {
        net::tls(stream, &target.host).await?
    } else {
        Upstream::Plain(stream)
    };
    let mut conn = Buffered::new(stream);
    if let Some(password) = &target.password {
        let mut auth = vec![b"AUTH".to_vec()];
        auth.extend(target.username.iter().map(|u| u.as_bytes().to_vec()));
        auth.push(password.as_bytes().to_vec());
        expect_ok(&mut conn, &auth).await?;
    }
    if target.db != 0 {
        expect_ok(
            &mut conn,
            &[b"SELECT".to_vec(), target.db.to_string().into()],
        )
        .await?;
    }
    Ok(conn)
}

async fn expect_ok(conn: &mut Buffered<Upstream>, command: &[Vec<u8>]) -> io::Result<()> {
    conn.get_mut().write_all(&encode_command(command)).await?;
    match next_token(conn).await? {
        Some(Token::Line { kind: b'+', .. }) => Ok(()),
        Some(
            Token::Line { kind: b'-', text }
            | Token::Bulk {
                kind: b'!',
                data: text,
            },
        ) => Err(io::Error::other(
            String::from_utf8_lossy(&text).into_owned(),
        )),
        _ => Err(io::Error::other("the server sent an unexpected reply")),
    }
}

/// One piece of a reply.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Token {
    /// An array, set, push or map header and how many values follow (a
    /// map's keys and values both count).
    Aggregate { kind: u8, len: usize },
    /// A null, as it was sent.
    Null(Vec<u8>),
    /// `+`, `-`, `:`, `,`, `(` or `#`, without the line end.
    Line { kind: u8, text: Vec<u8> },
    /// `$`, `!` or `=`.
    Bulk { kind: u8, data: Vec<u8> },
}

/// Reads one token from the front of `data`, with the bytes it took;
/// `None` until all of it has arrived.
pub fn parse_token(data: &[u8]) -> Result<Option<(Token, usize)>, String> {
    let Some(&kind) = data.first() else {
        return Ok(None);
    };
    let Some(end) = data.windows(2).position(|w| w == b"\r\n") else {
        if data.len() > MAX_WIRE_MESSAGE {
            return Err("a line is longer than kv accepts".into());
        }
        return Ok(None);
    };
    let line = &data[1..end];
    let after = end + 2;
    let null = || Ok(Some((Token::Null(data[..after].to_vec()), after)));
    match kind {
        b'+' | b'-' | b':' | b',' | b'(' | b'#' => Ok(Some((
            Token::Line {
                kind,
                text: line.to_vec(),
            },
            after,
        ))),
        b'_' => null(),
        b'$' | b'!' | b'=' => {
            let Ok(len) = usize::try_from(length(line)?) else {
                return null();
            };
            if len > MAX_WIRE_MESSAGE {
                return Err("a string is larger than kv accepts (16 MiB)".into());
            }
            if data.len() < after + len + 2 {
                return Ok(None);
            }
            if &data[after + len..after + len + 2] != b"\r\n" {
                return Err("a string has the wrong length".into());
            }
            Ok(Some((
                Token::Bulk {
                    kind,
                    data: data[after..after + len].to_vec(),
                },
                after + len + 2,
            )))
        }
        b'*' | b'%' | b'~' | b'>' => {
            let Ok(len) = usize::try_from(length(line)?) else {
                return null();
            };
            let len = if kind == b'%' {
                len.checked_mul(2).ok_or("a map is too large")?
            } else {
                len
            };
            Ok(Some((Token::Aggregate { kind, len }, after)))
        }
        other => Err(format!(
            "kv does not handle Redis replies of type {:?}",
            other as char
        )),
    }
}

fn length(line: &[u8]) -> Result<i64, String> {
    std::str::from_utf8(line)
        .ok()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| "a length is not a number".to_owned())
}

pub fn encode(token: &Token, out: &mut Vec<u8>) {
    match token {
        Token::Aggregate { kind, len } => {
            let count = if *kind == b'%' { len / 2 } else { *len };
            out.push(*kind);
            out.extend_from_slice(count.to_string().as_bytes());
            out.extend_from_slice(b"\r\n");
        }
        Token::Null(raw) => out.extend_from_slice(raw),
        Token::Line { kind, text } => {
            out.push(*kind);
            out.extend_from_slice(text);
            out.extend_from_slice(b"\r\n");
        }
        Token::Bulk { kind, data } => {
            out.push(*kind);
            out.extend_from_slice(data.len().to_string().as_bytes());
            out.extend_from_slice(b"\r\n");
            out.extend_from_slice(data);
            out.extend_from_slice(b"\r\n");
        }
    }
}

pub async fn next_token<R: AsyncRead + Unpin>(conn: &mut Buffered<R>) -> io::Result<Option<Token>> {
    loop {
        if let Some((token, used)) = parse_token(conn.data()).map_err(io::Error::other)? {
            conn.consume(used);
            return Ok(Some(token));
        }
        if !conn.fill().await? {
            return match conn.data().is_empty() {
                true => Ok(None),
                false => Err(io::ErrorKind::UnexpectedEof.into()),
            };
        }
    }
}

pub fn encode_command(args: &[Vec<u8>]) -> Vec<u8> {
    let mut out = format!("*{}\r\n", args.len()).into_bytes();
    for arg in args {
        encode(
            &Token::Bulk {
                kind: b'$',
                data: arg.clone(),
            },
            &mut out,
        );
    }
    out
}

/// A container still taking values while a reply becomes JSON.
struct Open {
    kind: u8,
    items: Vec<serde_json::Value>,
    left: usize,
}

impl Open {
    /// Maps become arrays of `[key, value]` pairs.
    fn close(self) -> serde_json::Value {
        if self.kind == b'%' {
            serde_json::Value::Array(
                self.items
                    .chunks(2)
                    .map(|pair| serde_json::Value::Array(pair.to_vec()))
                    .collect(),
            )
        } else {
            serde_json::Value::Array(self.items)
        }
    }
}

/// Reads one reply as JSON, scrubbed, spending at most `budget` bytes; the
/// flag says something was cut or left out, and the rest of the reply is
/// never read. A server error as the whole reply is `Err`, scrubbed.
pub async fn read_json<R: AsyncRead + Unpin>(
    conn: &mut Buffered<R>,
    scrubber: &Scrubber,
    mut budget: usize,
) -> io::Result<Result<(serde_json::Value, bool), String>> {
    use serde_json::Value as Json;
    let mut stack: Vec<Open> = Vec::new();
    let mut truncated = false;
    loop {
        if budget == 0 && !stack.is_empty() {
            let mut value = stack.pop().map(Open::close).unwrap_or_default();
            while let Some(mut parent) = stack.pop() {
                parent.items.push(value);
                value = parent.close();
            }
            return Ok(Ok((value, true)));
        }
        let token = next_token(conn)
            .await?
            .ok_or(io::ErrorKind::UnexpectedEof)?;
        let mut value = match token {
            Token::Aggregate { kind, len } if len > 0 => {
                charge(&mut budget, 2);
                stack.push(Open {
                    kind,
                    items: Vec::new(),
                    left: len,
                });
                continue;
            }
            Token::Aggregate { .. } => {
                charge(&mut budget, 2);
                Json::Array(Vec::new())
            }
            Token::Null(_) => {
                charge(&mut budget, 4);
                Json::Null
            }
            Token::Line {
                kind: b'-',
                text: error,
            }
            | Token::Bulk {
                kind: b'!',
                data: error,
            } if stack.is_empty() => {
                return Ok(Err(scrub_text(scrubber, &error)));
            }
            Token::Line { kind: b'#', text } => {
                charge(&mut budget, 5);
                Json::Bool(text == b"t")
            }
            Token::Line { kind: b':', text } => {
                let digits = String::from_utf8_lossy(&text).into_owned();
                let json = digits.parse::<i64>().map(Json::from).ok();
                number(scrubber, digits, json, &mut budget)
            }
            Token::Line { kind: b',', text } => {
                let digits = String::from_utf8_lossy(&text).into_owned();
                let json = digits
                    .parse::<f64>()
                    .ok()
                    .and_then(serde_json::Number::from_f64)
                    .map(Json::Number);
                number(scrubber, digits, json, &mut budget)
            }
            Token::Bulk { kind: b'=', data } => {
                // Verbatim strings start with a format such as `txt:`.
                let text_part = data.get(4..).unwrap_or(&data);
                text(scrubber, text_part, &mut budget, &mut truncated)
            }
            Token::Line { text: bytes, .. } | Token::Bulk { data: bytes, .. } => {
                text(scrubber, &bytes, &mut budget, &mut truncated)
            }
        };
        loop {
            let Some(top) = stack.last_mut() else {
                return Ok(Ok((value, truncated)));
            };
            top.items.push(value);
            top.left -= 1;
            if top.left > 0 {
                break;
            }
            value = stack.pop().map(Open::close).unwrap_or_default();
        }
    }
}

fn charge(budget: &mut usize, bytes: usize) {
    *budget = budget.saturating_sub(bytes);
}

/// Scrubbed first and cut after, so a cut never splits a secret in two
/// halves the scrubber cannot see.
fn text(
    scrubber: &Scrubber,
    bytes: &[u8],
    budget: &mut usize,
    truncated: &mut bool,
) -> serde_json::Value {
    let mut text = scrub_text(scrubber, bytes);
    let room = budget.saturating_sub(3);
    if text.len() > room {
        let mut end = room;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        text.truncate(end);
        *truncated = true;
    }
    charge(budget, text.len() + 3);
    serde_json::Value::String(text)
}

/// A number could be a numeric secret, so it goes through the scrubber
/// too, and comes back as a string if it was replaced (or is not a JSON
/// number, such as `inf`).
fn number(
    scrubber: &Scrubber,
    digits: String,
    json: Option<serde_json::Value>,
    budget: &mut usize,
) -> serde_json::Value {
    charge(budget, digits.len() + 1);
    let scrubbed = scrub_text(scrubber, digits.as_bytes());
    match json {
        Some(json) if scrubbed == digits => json,
        _ => serde_json::Value::String(scrubbed),
    }
}

fn scrub_text(scrubber: &Scrubber, bytes: &[u8]) -> String {
    String::from_utf8_lossy(&scrubber.scrub(bytes)).into_owned()
}
