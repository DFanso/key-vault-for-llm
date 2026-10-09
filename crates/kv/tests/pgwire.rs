//! The Postgres wire protocol as the db_connect proxy handles it: framing,
//! the first packet, scrubbing what the server sends, and the read-only
//! gate.

use kv::broker::net::MAX_WIRE_MESSAGE;
use kv::broker::pgwire::*;
use kv_core::scrub::Scrubber;

fn cstrs(parts: &[&str]) -> Vec<u8> {
    let mut out = Vec::new();
    for part in parts {
        out.extend_from_slice(part.as_bytes());
        out.push(0);
    }
    out
}

#[test]
fn messages_frame_and_wait_for_their_bytes() {
    let encoded = Message::new(b'Q', cstrs(&["select 1"])).encode();
    let (message, used) = parse_message(&encoded).unwrap().unwrap();
    assert_eq!((message.tag, used), (b'Q', encoded.len()));
    assert_eq!(parse_message(&encoded[..encoded.len() - 1]).unwrap(), None);
    let mut huge = vec![b'D'];
    huge.extend_from_slice(&(MAX_WIRE_MESSAGE as u32 + 5).to_be_bytes());
    assert!(parse_message(&huge).is_err());
}

#[test]
fn the_first_packet_says_what_the_client_wants() {
    let mut ssl = 8u32.to_be_bytes().to_vec();
    ssl.extend_from_slice(&80_877_103u32.to_be_bytes());
    assert_eq!(parse_opening(&ssl).unwrap(), Some((Opening::Ssl, 8)));

    let mut body = 196_608u32.to_be_bytes().to_vec();
    body.extend(cstrs(&["user", "kv", "database", "app"]));
    body.push(0);
    let mut packet = (body.len() as u32 + 4).to_be_bytes().to_vec();
    packet.extend(body);
    let (opening, used) = parse_opening(&packet).unwrap().unwrap();
    assert_eq!(used, packet.len());
    assert_eq!(
        opening,
        Opening::Startup {
            minor: 0,
            params: vec![
                ("user".into(), "kv".into()),
                ("database".into(), "app".into())
            ],
        }
    );
    let mut old = 8u32.to_be_bytes().to_vec();
    old.extend_from_slice(&0x0002_0000u32.to_be_bytes());
    assert!(parse_opening(&old).is_err());
}

#[test]
fn rows_errors_and_names_are_scrubbed_in_place() {
    let scrubber = Scrubber::new([("pg", "pg-password-0123")]);
    let value = b"pw=pg-password-0123";
    let mut row = 2u16.to_be_bytes().to_vec();
    row.extend_from_slice(&(-1i32).to_be_bytes());
    row.extend_from_slice(&(value.len() as i32).to_be_bytes());
    row.extend_from_slice(value);
    let scrubbed = scrub_backend(Message::new(b'D', row), &scrubber).unwrap();
    let mut expected = 2u16.to_be_bytes().to_vec();
    expected.extend_from_slice(&(-1i32).to_be_bytes());
    expected.extend_from_slice(&10i32.to_be_bytes());
    expected.extend_from_slice(b"pw=[kv:pg]");
    assert_eq!(scrubbed.body, expected);

    let mut description = 1u16.to_be_bytes().to_vec();
    description.extend(cstrs(&["pg-password-0123"]));
    description.extend_from_slice(&[0; 18]);
    let scrubbed = scrub_backend(Message::new(b'T', description), &scrubber).unwrap();
    assert!(scrubbed.body.windows(7).any(|w| w == b"[kv:pg]"));
    assert_eq!(scrubbed.body.len(), 2 + 8 + 18);

    let failed = error(
        "ERROR",
        "42P01",
        "relation \"pg-password-0123\" does not exist",
    );
    let scrubbed = scrub_backend(failed, &scrubber).unwrap();
    assert_eq!(
        error_text(&scrubbed.body),
        "relation \"[kv:pg]\" does not exist (SQLSTATE 42P01)"
    );
    assert!(scrub_backend(Message::new(b'D', vec![0, 1, 0]), &scrubber).is_err());
}

fn parse(name: &str, sql: &str) -> Message {
    let mut body = cstrs(&[name, sql]);
    body.extend_from_slice(&0u16.to_be_bytes());
    Message::new(b'P', body)
}

fn bind(portal: &str, statement: &str) -> Message {
    let mut body = cstrs(&[portal, statement]);
    body.extend_from_slice(&[0; 6]);
    Message::new(b'B', body)
}

fn execute(portal: &str) -> Message {
    let mut body = cstrs(&[portal]);
    body.extend_from_slice(&0u32.to_be_bytes());
    Message::new(b'E', body)
}

#[test]
fn the_gate_lets_one_batch_end_a_transaction_only_at_its_end() {
    let mut gate = ReadOnlyGate::default();
    let query = |sql: &str| Message::new(b'Q', cstrs(&[sql]));
    assert_eq!(gate.check(&query("select 1")), Ok(true));
    assert_eq!(gate.check(&query("commit")), Ok(true));
    assert!(gate.check(&query("commit; delete from t")).is_err());

    // Extended protocol: a COMMIT executed, then anything but Sync.
    let sync = Message::new(b'S', Vec::new());
    assert_eq!(gate.check(&parse("c", "COMMIT")), Ok(false));
    assert_eq!(gate.check(&bind("", "c")), Ok(false));
    assert_eq!(gate.check(&execute("")), Ok(false));
    assert!(gate.check(&parse("", "insert into t values (1)")).is_err());

    let mut gate = ReadOnlyGate::default();
    for message in [parse("c", "COMMIT"), bind("", "c"), execute("")] {
        gate.check(&message).unwrap();
    }
    assert_eq!(gate.check(&sync), Ok(true));
    assert_eq!(gate.check(&parse("", "select 1")), Ok(false));
    assert!(
        gate.check(&parse("", "set default_transaction_read_only = off"))
            .is_err()
    );
    assert!(gate.check(&Message::new(b'F', vec![0; 8])).is_err());
}

fn close_statement(name: &str) -> Message {
    let mut body = vec![b'S'];
    body.extend(cstrs(&[name]));
    Message::new(b'C', body)
}

/// After an error the server skips everything up to Sync, and it refuses to
/// reuse a statement name, so a Parse or Close kv passed on may not have
/// happened. The gate must then assume the statement ends a transaction.
#[test]
fn the_gate_assumes_the_worst_when_the_server_may_disagree_about_a_statement() {
    let sync = Message::new(b'S', Vec::new());
    let ends_then_more = |gate: &mut ReadOnlyGate, statement: &str| {
        gate.check(&bind("", statement)).unwrap();
        gate.check(&execute("")).unwrap();
        gate.check(&parse("", "insert into t values (1)")).is_err()
    };

    // "c" stays COMMIT on the server: the second Parse fails on the name.
    let mut gate = ReadOnlyGate::default();
    for message in [
        parse("c", "COMMIT"),
        sync.clone(),
        parse("c", "select 1"),
        sync.clone(),
    ] {
        gate.check(&message).unwrap();
    }
    assert!(ends_then_more(&mut gate, "c"));

    // A Close skipped after an error leaves "c" on the server.
    let mut gate = ReadOnlyGate::default();
    for message in [
        parse("c", "COMMIT"),
        sync.clone(),
        close_statement("c"),
        sync.clone(),
    ] {
        gate.check(&message).unwrap();
    }
    assert!(ends_then_more(&mut gate, "c"));

    // A statement kv never saw prepared.
    let mut gate = ReadOnlyGate::default();
    assert!(ends_then_more(&mut gate, "unknown"));

    // An unnamed Parse after something that may have failed may be skipped.
    let mut gate = ReadOnlyGate::default();
    for message in [
        parse("", "COMMIT"),
        sync.clone(),
        parse("x", "select 1/0"),
        parse("", "select 1"),
    ] {
        gate.check(&message).unwrap();
    }
    assert!(ends_then_more(&mut gate, ""));

    // First in its batch, it surely replaced the last one: drivers that send
    // COMMIT unnamed are not held back afterwards.
    let mut gate = ReadOnlyGate::default();
    for message in [
        parse("", "COMMIT"),
        bind("", ""),
        execute(""),
        sync.clone(),
        parse("", "select 1"),
        bind("", ""),
        execute(""),
    ] {
        gate.check(&message).unwrap();
    }
    assert_eq!(gate.check(&parse("", "select 2")), Ok(false));
}

/// The server skips a simple query sent after a failed extended message, so
/// waiting for its ReadyForQuery would hang the connection.
#[test]
fn the_gate_refuses_a_simple_query_inside_an_extended_batch() {
    let query = Message::new(b'Q', cstrs(&["select 2"]));
    let mut gate = ReadOnlyGate::default();
    gate.check(&parse("", "select 1")).unwrap();
    let error = gate.check(&query).unwrap_err();
    assert!(error.contains("Sync"), "{error}");
    assert_eq!(gate.check(&Message::new(b'S', Vec::new())), Ok(true));
    assert_eq!(gate.check(&query), Ok(true));
}
