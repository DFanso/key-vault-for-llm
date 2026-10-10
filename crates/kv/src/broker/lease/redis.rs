//! One client on a Redis lease: kv answers until the client logs in with
//! the lease token (`AUTH` or `HELLO ... AUTH`), logs in to the real
//! server, then relays commands and replies in order.

use kv_core::db::{RedisRefusal, check_redis};
use tokio::io::{AsyncWriteExt, BufWriter, ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::{mpsc, watch};

use super::{EndReason, HANDSHAKE_TIMEOUT, Lease, UPSTREAM_TIMEOUT, token_matches};
use crate::broker::net::{Buffered, MAX_WIRE_MESSAGE, Upstream};
use crate::broker::resp::{
    self, Frame, RedisTarget, Token, encode, encode_command, next_command, next_token, scrub_token,
};

type ClientRead = Buffered<OwnedReadHalf>;

/// The largest command kv reads before the client logs in, as Redis limits
/// clients that have not authenticated.
const LOGIN_LIMIT: usize = 16 * 1024;
type ClientWrite = BufWriter<OwnedWriteHalf>;

/// What the next answer to the client is, in the order commands came.
enum Slot {
    /// The server's reply to a command kv passed on.
    Reply,
    /// kv's own reply, for a command it refused.
    Local(Vec<u8>),
    /// `+OK`, then the connection closes.
    Quit,
}

pub(super) async fn serve(
    stream: TcpStream,
    lease: &Lease,
    target: &RedisTarget,
    end: watch::Receiver<Option<EndReason>>,
) -> &'static str {
    let (read, write) = stream.into_split();
    let mut client = Buffered::new(read);
    let mut write = BufWriter::new(write);
    let hello =
        match tokio::time::timeout(HANDSHAKE_TIMEOUT, log_in(&mut client, &mut write, lease)).await
        {
            Ok(Ok(hello)) => hello,
            Ok(Err(outcome)) => return outcome,
            Err(_) => return "timed_out",
        };
    let upstream = match tokio::time::timeout(UPSTREAM_TIMEOUT, resp::connect(target)).await {
        Ok(Ok(upstream)) => upstream,
        Ok(Err(e)) => {
            let message = lease.scrubber().scrub(e.to_string().as_bytes());
            let message = String::from_utf8_lossy(&message).replace(['\r', '\n'], " ");
            send(&mut write, format!("-ERR kv: {message}\r\n").as_bytes()).await;
            return "upstream_error";
        }
        Err(_) => {
            send(
                &mut write,
                b"-ERR kv: the database did not answer in time\r\n",
            )
            .await;
            return "upstream_error";
        }
    };
    let (data, leftover) = upstream.into_parts();
    let (up_read, mut up_write) = tokio::io::split(data);
    let mut up_read = Buffered::with_data(up_read, leftover);

    let (slots, queue) = mpsc::channel(1024);
    // The login's answer comes first: kv's own for AUTH, the server's for
    // HELLO, which kv passes on without the token.
    match hello {
        Some(hello) => {
            if up_write.write_all(&encode_command(&hello)).await.is_err() {
                return "closed";
            }
            let _ = slots.send(Slot::Reply).await;
        }
        None => {
            let _ = slots.send(Slot::Local(b"+OK\r\n".to_vec())).await;
        }
    }
    tokio::select! {
        outcome = client_to_server(&mut client, &mut up_write, lease.read_only, slots) => outcome,
        outcome = server_to_client(&mut up_read, &mut write, lease, queue, end) => outcome,
    }
}

/// Answers until the client logs in with the token. Returns the `HELLO` to
/// send the server, without its `AUTH`, if the client logged in that way.
async fn log_in(
    client: &mut ClientRead,
    write: &mut ClientWrite,
    lease: &Lease,
) -> Result<Option<Vec<Vec<u8>>>, &'static str> {
    const WRONG: &[u8] = b"-WRONGPASS invalid username-password pair or user is disabled.\r\n";
    loop {
        let args = match next_command(client, LOGIN_LIMIT).await {
            Ok(Some(args)) => args,
            Ok(None) | Err(_) => return Err("closed"),
        };
        let word = |i: usize| {
            args.get(i)
                .map(|a| String::from_utf8_lossy(a).to_ascii_uppercase())
                .unwrap_or_default()
        };
        match word(0).as_str() {
            "AUTH" if (2..=3).contains(&args.len()) => {
                if token_matches(&args[args.len() - 1], &lease.token) {
                    return Ok(None);
                }
                send(write, WRONG).await;
                return Err("wrong_token");
            }
            "HELLO" => {
                let auth = (2..args.len()).find(|&i| word(i) == "AUTH");
                let Some(at) = auth.filter(|&at| at + 2 < args.len()) else {
                    send(
                        write,
                        b"-NOAUTH HELLO must be called with the client already authenticated, \
                          otherwise the HELLO <proto> AUTH <user> <pass> option can be used\r\n",
                    )
                    .await;
                    continue;
                };
                if !token_matches(&args[at + 2], &lease.token) {
                    send(write, WRONG).await;
                    return Err("wrong_token");
                }
                let mut hello = args.clone();
                hello.drain(at..at + 3);
                return Ok(Some(hello));
            }
            "QUIT" => {
                send(write, b"+OK\r\n").await;
                return Err("closed");
            }
            _ => send(write, b"-NOAUTH Authentication required.\r\n").await,
        }
    }
}

/// Why kv answers a command itself instead of passing it on.
enum Refusal {
    Quit,
    Error(String),
}

/// Commands that log in again, change how replies flow (subscriptions,
/// `MONITOR`, `CLIENT REPLY`) or replicate are refused on every lease; on a
/// read-only handle only reads pass.
fn refusal(args: &[Vec<u8>], read_only: bool) -> Option<Refusal> {
    let word = |i: usize| {
        args.get(i)
            .map(|a| String::from_utf8_lossy(a).to_ascii_uppercase())
            .unwrap_or_default()
    };
    let command = word(0);
    let unavailable = || {
        Some(Refusal::Error(format!(
            "{command} is not available through db_connect"
        )))
    };
    match command.as_str() {
        "QUIT" => return Some(Refusal::Quit),
        "HELLO" if args.len() <= 2 => return None,
        "AUTH" | "HELLO" | "RESET" | "MONITOR" | "SYNC" | "PSYNC" | "REPLCONF" | "SUBSCRIBE"
        | "PSUBSCRIBE" | "SSUBSCRIBE" | "UNSUBSCRIBE" | "PUNSUBSCRIBE" | "SUNSUBSCRIBE" => {
            return unavailable();
        }
        "CLIENT" if word(1) == "REPLY" => return unavailable(),
        _ => {}
    }
    if read_only && let Err(refusal @ RedisRefusal::NotRead(_)) = check_redis(args, true) {
        return Some(Refusal::Error(refusal.to_string()));
    }
    None
}

async fn client_to_server(
    client: &mut ClientRead,
    upstream: &mut WriteHalf<Upstream>,
    read_only: bool,
    slots: mpsc::Sender<Slot>,
) -> &'static str {
    loop {
        let args = match next_command(client, 2 * MAX_WIRE_MESSAGE).await {
            Ok(Some(args)) => args,
            Ok(None) | Err(_) => return "closed",
        };
        let slot = match refusal(&args, read_only) {
            Some(Refusal::Quit) => Slot::Quit,
            Some(Refusal::Error(message)) => Slot::Local(format!("-ERR kv: {message}\r\n").into()),
            None => {
                if upstream.write_all(&encode_command(&args)).await.is_err() {
                    return "closed";
                }
                Slot::Reply
            }
        };
        let quit = matches!(slot, Slot::Quit);
        if slots.send(slot).await.is_err() {
            return "closed";
        }
        if quit {
            return std::future::pending().await;
        }
    }
}

/// Writes the answers in the order of the commands, and passes on push
/// messages (RESP3) whenever they come.
async fn server_to_client(
    upstream: &mut Buffered<ReadHalf<Upstream>>,
    client: &mut ClientWrite,
    lease: &Lease,
    mut queue: mpsc::Receiver<Slot>,
    end: watch::Receiver<Option<EndReason>>,
) -> &'static str {
    loop {
        let first = tokio::select! {
            biased;
            _ = super::ended(end.clone()) => return "lease_ended",
            slot = queue.recv() => {
                match answer(slot, None, upstream, client, lease).await {
                    Ok(()) => continue,
                    Err(outcome) => return outcome,
                }
            }
            token = next_token(upstream) => match token {
                Ok(Some(token)) => token,
                Ok(None) => return "closed",
                Err(_) => return "upstream_error",
            },
        };
        // A token arrived before its slot: a push, or the reply to a command
        // whose slot is on its way.
        if matches!(first, Token::Aggregate { kind: b'>', .. }) {
            if let Err(outcome) = forward(Some(first), upstream, client, lease).await {
                return outcome;
            }
            continue;
        }
        let mut first = Some(first);
        loop {
            let slot = queue.recv().await;
            let reply = matches!(slot, Some(Slot::Reply));
            if let Err(outcome) =
                answer(slot, first.take_if(|_| reply), upstream, client, lease).await
            {
                return outcome;
            }
            if reply {
                break;
            }
        }
    }
}

/// Writes one slot's answer; a reply may already have its first token.
async fn answer(
    slot: Option<Slot>,
    first: Option<Token>,
    upstream: &mut Buffered<ReadHalf<Upstream>>,
    client: &mut ClientWrite,
    lease: &Lease,
) -> Result<(), &'static str> {
    match slot {
        None => Err("closed"),
        Some(Slot::Local(bytes)) => write(client, &bytes).await,
        Some(Slot::Quit) => {
            let _ = write(client, b"+OK\r\n").await;
            Err("closed")
        }
        // Push messages may come before the reply itself.
        Some(Slot::Reply) => {
            let mut first = first;
            while forward(first.take(), upstream, client, lease).await? {}
            Ok(())
        }
    }
}

/// Passes on one reply, scrubbed, token by token; `true` if it was a push
/// message, so the reply is still to come.
async fn forward(
    first: Option<Token>,
    upstream: &mut Buffered<ReadHalf<Upstream>>,
    client: &mut ClientWrite,
    lease: &Lease,
) -> Result<bool, &'static str> {
    let scrubber = lease.scrubber();
    let mut frame = Frame::default();
    let mut next = first;
    let mut out = Vec::new();
    loop {
        let token = match next.take() {
            Some(token) => token,
            None => match next_token(upstream).await {
                Ok(Some(token)) => token,
                Ok(None) => return Err("closed"),
                Err(_) => return Err("upstream_error"),
            },
        };
        let done = frame.take(&token);
        encode(&scrub_token(token, &scrubber), &mut out);
        if out.len() >= 64 * 1024 || done {
            if client.write_all(&out).await.is_err() {
                return Err("closed");
            }
            out.clear();
        }
        if done {
            client.flush().await.map_err(|_| "closed")?;
            return Ok(frame.push);
        }
    }
}

async fn write(client: &mut ClientWrite, bytes: &[u8]) -> Result<(), &'static str> {
    client.write_all(bytes).await.map_err(|_| "closed")?;
    client.flush().await.map_err(|_| "closed")
}

async fn send(client: &mut ClientWrite, bytes: &[u8]) {
    let _ = write(client, bytes).await;
}
