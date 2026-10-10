//! One client on a Postgres lease: kv plays the server until the client
//! gives the lease token, logs in to the real server, then relays messages.
//! On a read-only handle it checks what the client sends and lets one batch
//! through at a time, so it sees the server report
//! `default_transaction_read_only` before the next batch runs.

use kv_core::db::pg_session_violation;
use tokio::io::{AsyncWriteExt, BufWriter, ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::{oneshot, watch};

use super::{EndReason, HANDSHAKE_TIMEOUT, Lease, UPSTREAM_TIMEOUT, token_matches};
use crate::broker::net::{Buffered, Upstream};
use crate::broker::pgwire::{
    self, Message, Opening, PgTarget, ReadOnlyGate, error, next_message, next_opening,
    parse_message, scrub_backend,
};

type ClientRead = Buffered<OwnedReadHalf>;
type ClientWrite = BufWriter<OwnedWriteHalf>;

pub(super) async fn serve(
    stream: TcpStream,
    lease: &Lease,
    target: &PgTarget,
    end: watch::Receiver<Option<EndReason>>,
) -> &'static str {
    let (read, write) = stream.into_split();
    let mut client = Buffered::new(read);
    let mut write = BufWriter::new(write);
    let params = match tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        handshake(&mut client, &mut write, lease, target),
    )
    .await
    {
        Ok(Ok(params)) => params,
        Ok(Err(outcome)) => return outcome,
        Err(_) => return "timed_out",
    };
    let connected = tokio::time::timeout(UPSTREAM_TIMEOUT, pgwire::connect(target, &params)).await;
    let (upstream, after) = match connected {
        Ok(Ok(connected)) => connected,
        Ok(Err(message)) => {
            let message =
                String::from_utf8_lossy(&lease.scrubber().scrub(message.as_bytes())).into_owned();
            fatal(&mut write, "08006", &format!("kv: {message}")).await;
            return "upstream_error";
        }
        Err(_) => {
            fatal(
                &mut write,
                "08006",
                "kv: the database did not answer in time",
            )
            .await;
            return "upstream_error";
        }
    };

    // The client already gave the token; the server's own login is done.
    let mut reported = false;
    let mut hello = pgwire::auth(0, &[]).encode();
    for message in after {
        if message.tag == b'S'
            && let Some((name, value)) = pgwire::parameter(&message)
            && name == "default_transaction_read_only"
        {
            reported = value == "on";
        }
        match scrub_backend(message, &lease.scrubber()) {
            Ok(message) => hello.extend(message.encode()),
            Err(_) => return "upstream_error",
        }
    }
    if lease.read_only && !reported {
        fatal(
            &mut write,
            "0A000",
            "kv: read-only db_connect needs PostgreSQL 14 or later, which reports \
             default_transaction_read_only; use db_query instead",
        )
        .await;
        return "policy_denied";
    }
    if write.write_all(&hello).await.is_err() || write.flush().await.is_err() {
        return "closed";
    }

    let (data, leftover) = upstream.into_parts();
    let (up_read, mut up_write) = tokio::io::split(data);
    let mut up_read = Buffered::with_data(up_read, leftover);
    let (batches_done, done) = watch::channel(0u64);
    let (stop, stopped) = oneshot::channel();
    let gate = lease.read_only.then(ReadOnlyGate::default);
    tokio::select! {
        outcome = client_to_server(&mut client, &mut up_write, gate, done, stop) => outcome,
        outcome = server_to_client(&mut up_read, &mut write, lease, batches_done, stopped, end) => outcome,
    }
}

/// Answers TLS requests with "no", takes the startup packet and the
/// lease token. Returns the parameters to pass on to the server.
async fn handshake(
    client: &mut ClientRead,
    write: &mut ClientWrite,
    lease: &Lease,
    target: &PgTarget,
) -> Result<Vec<(String, String)>, &'static str> {
    let (minor, params) = loop {
        match next_opening(client).await {
            Ok(Some(Opening::Ssl | Opening::Gss)) => {
                if write.write_all(b"N").await.is_err() || write.flush().await.is_err() {
                    return Err("closed");
                }
            }
            Ok(Some(Opening::Startup { minor, params })) => break (minor, params),
            // Query cancellation is not passed on.
            Ok(Some(Opening::Cancel) | None) | Err(_) => return Err("closed"),
        }
    };
    let mut forward = Vec::new();
    let mut options = target.options.clone().unwrap_or_default();
    let mut unknown = Vec::new();
    for (name, value) in params {
        match name.as_str() {
            "user" => {}
            "database" if value != target.dbname => {
                let message = format!("kv: this lease is for database \"{}\"", target.dbname);
                fatal(write, "3D000", &message).await;
                return Err("bad_request");
            }
            "database" => {}
            "replication" => {
                fatal(
                    write,
                    "08P01",
                    "kv: db_connect does not pass on replication",
                )
                .await;
                return Err("bad_request");
            }
            _ if name.starts_with("_pq_.") => unknown.push(name),
            _ => {
                if lease.read_only && pg_session_violation(&format!("{name} {value}")).is_err() {
                    let message = format!(
                        "kv: the handle is read-only, and kv refuses the startup parameter {name}"
                    );
                    fatal(write, "25006", &message).await;
                    return Err("policy_denied");
                }
                if name == "options" {
                    options = format!("{options} {value}");
                } else {
                    forward.push((name, value));
                }
            }
        }
    }
    if lease.read_only {
        options.push_str(" -c default_transaction_read_only=on");
    }
    if !options.trim().is_empty() {
        forward.push(("options".into(), options.trim().to_owned()));
    }
    let mut reply = Vec::new();
    if minor > 0 || !unknown.is_empty() {
        reply.extend(pgwire::negotiate_protocol(&unknown).encode());
    }
    reply.extend(pgwire::auth(3, &[]).encode());
    if write.write_all(&reply).await.is_err() || write.flush().await.is_err() {
        return Err("closed");
    }
    let password = match next_message(client).await {
        Ok(Some(Message { tag: b'p', body })) => body,
        _ => return Err("closed"),
    };
    let given = password.strip_suffix(&[0]).unwrap_or(&password);
    if !token_matches(given, &lease.token) {
        fatal(
            write,
            "28P01",
            "password authentication failed for user \"kv\" (the lease token is wrong)",
        )
        .await;
        return Err("wrong_token");
    }
    Ok(forward)
}

/// Passes the client's messages on. With a gate, a violation goes to the
/// other half, which tells the client and ends the connection, and after
/// each batch it waits for the server's `ReadyForQuery`.
async fn client_to_server(
    client: &mut ClientRead,
    upstream: &mut WriteHalf<Upstream>,
    mut gate: Option<ReadOnlyGate>,
    mut done: watch::Receiver<u64>,
    stop: oneshot::Sender<String>,
) -> &'static str {
    let mut batches = 0u64;
    loop {
        let message = match next_message(client).await {
            Ok(Some(message)) => message,
            Ok(None) | Err(_) => return "closed",
        };
        let ends_batch = match gate.as_mut().map(|gate| gate.check(&message)) {
            Some(Err(reason)) => {
                let _ = stop.send(reason);
                return std::future::pending().await;
            }
            Some(Ok(ends)) => ends,
            None => false,
        };
        if upstream.write_all(&message.encode()).await.is_err() {
            return "closed";
        }
        if message.tag == b'X' {
            return "closed";
        }
        if ends_batch {
            batches += 1;
            if done.wait_for(|n| *n >= batches).await.is_err() {
                return "closed";
            }
        }
    }
}

/// Passes the server's messages back, scrubbed, and counts each
/// `ReadyForQuery`. On a read-only handle it ends the session if the server
/// reports `default_transaction_read_only` off, or starts a COPY from the
/// client.
async fn server_to_client(
    upstream: &mut Buffered<ReadHalf<Upstream>>,
    client: &mut ClientWrite,
    lease: &Lease,
    batches_done: watch::Sender<u64>,
    mut stopped: oneshot::Receiver<String>,
    end: watch::Receiver<Option<EndReason>>,
) -> &'static str {
    loop {
        let message = tokio::select! {
            biased;
            reason = &mut stopped => {
                let Ok(reason) = reason else { return "closed" };
                fatal(client, "25006", &format!("kv: {reason}")).await;
                return "policy_denied";
            }
            _ = super::ended(end.clone()) => {
                fatal(client, "57P01", "kv: the lease ended; ask for a new one with db_connect").await;
                return "lease_ended";
            }
            read = next_message(upstream) => match read {
                Ok(Some(message)) => message,
                Ok(None) => return "closed",
                Err(e) => {
                    fatal(client, "08006", &format!("kv: {e}")).await;
                    return "upstream_error";
                }
            },
        };
        if lease.read_only {
            let switched_off = message.tag == b'S'
                && pgwire::parameter(&message).is_some_and(|(name, value)| {
                    name == "default_transaction_read_only" && value != "on"
                });
            if switched_off || matches!(message.tag, b'G' | b'W') {
                fatal(
                    client,
                    "25006",
                    "kv: the handle is read-only, and the session tried to change that; kv \
                     closed it",
                )
                .await;
                return "policy_denied";
            }
        }
        let ready = message.tag == b'Z';
        let Ok(message) = scrub_backend(message, &lease.scrubber()) else {
            fatal(client, "08P01", "kv: the server sent a malformed message").await;
            return "upstream_error";
        };
        if client.write_all(&message.encode()).await.is_err() {
            return "closed";
        }
        // Flush once nothing more is waiting, so rows go out in big writes
        // but a notification or the end of a query is never held back.
        if (ready || !matches!(parse_message(upstream.data()), Ok(Some(_))))
            && client.flush().await.is_err()
        {
            return "closed";
        }
        if ready {
            batches_done.send_modify(|n| *n += 1);
        }
    }
}

async fn fatal(write: &mut ClientWrite, code: &str, message: &str) {
    let _ = write
        .write_all(&error("FATAL", code, message).encode())
        .await;
    let _ = write.flush().await;
}
