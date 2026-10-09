//! The Redis protocol as kv reads and writes it: tokens, replies as JSON,
//! scrubbing, and the commands clients send.

use kv::broker::net::Buffered;
use kv::broker::resp::*;
use kv_core::scrub::Scrubber;

fn tokens(mut data: &[u8]) -> Vec<Token> {
    let mut out = Vec::new();
    while let Some((token, used)) = parse_token(data).unwrap() {
        out.push(token);
        data = &data[used..];
    }
    assert!(data.is_empty(), "left over: {data:?}");
    out
}

#[test]
fn tokens_round_trip() {
    let wire: &[u8] =
        b"*3\r\n$5\r\nhello\r\n:42\r\n$-1\r\n%1\r\n+k\r\n_\r\n>2\r\n$7\r\nmessage\r\n#t\r\n";
    let parsed = tokens(wire);
    let mut out = Vec::new();
    for token in &parsed {
        encode(token, &mut out);
    }
    assert_eq!(out, wire);
    assert_eq!(parsed[4], Token::Aggregate { kind: b'%', len: 2 });
}

#[test]
fn a_token_waits_for_all_its_bytes() {
    assert_eq!(parse_token(b"$5\r\nhel").unwrap(), None);
    assert_eq!(parse_token(b":4").unwrap(), None);
    assert!(parse_token(b"$3\r\nabcd\r\n").is_err());
    assert!(parse_token(b"?x\r\n").is_err());
}

#[test]
fn frames_end_where_the_reply_ends() {
    let mut frame = Frame::default();
    let parsed = tokens(b"*2\r\n*2\r\n:1\r\n:2\r\n$1\r\nx\r\n");
    let ends: Vec<bool> = parsed.iter().map(|t| frame.take(t)).collect();
    assert_eq!(ends, [false, false, false, false, true]);
    assert!(!frame.push);

    let mut frame = Frame::default();
    let parsed = tokens(b">2\r\n+invalidate\r\n*0\r\n");
    let ends: Vec<bool> = parsed.iter().map(|t| frame.take(t)).collect();
    assert_eq!(ends, [false, false, true]);
    assert!(frame.push);
}

#[test]
fn scrubbing_keeps_lengths_right_and_turns_matching_numbers_into_strings() {
    let scrubber = Scrubber::new([("cache", "s3cret-value-123"), ("pin", "987654321")]);
    let bulk = scrub_token(
        Token::Bulk {
            kind: b'$',
            data: b"key=s3cret-value-123".to_vec(),
        },
        &scrubber,
    );
    let mut out = Vec::new();
    encode(&bulk, &mut out);
    assert_eq!(out, b"$14\r\nkey=[kv:cache]\r\n");
    let number = scrub_token(
        Token::Line {
            kind: b':',
            text: b"987654321".to_vec(),
        },
        &scrubber,
    );
    assert_eq!(
        number,
        Token::Bulk {
            kind: b'$',
            data: b"[kv:pin]".to_vec()
        }
    );
}

#[test]
fn commands_must_be_arrays_of_strings() {
    let (args, used) = parse_command(b"*2\r\n$3\r\nGET\r\n$1\r\nk\r\n*1")
        .unwrap()
        .unwrap();
    assert_eq!(args, [b"GET".to_vec(), b"k".to_vec()]);
    assert_eq!(used, 20);
    assert_eq!(parse_command(b"*2\r\n$3\r\nGET\r\n").unwrap(), None);
    assert!(parse_command(b"GET k\r\n").is_err());
    assert!(parse_command(b"*1\r\n:1\r\n").is_err());
    assert!(parse_command(b"*0\r\n").is_err());
    assert_eq!(
        encode_command(&[b"SET".to_vec(), b"a b".to_vec()]),
        b"*2\r\n$3\r\nSET\r\n$3\r\na b\r\n"
    );
}

#[test]
fn redis_urls_must_name_a_server_and_a_numbered_database() {
    assert_eq!(
        RedisTarget::parse("rediss://app:p%40ss@cache.example:6380/3")
            .unwrap()
            .db,
        3
    );
    assert_eq!(RedisTarget::parse("redis://[::1]").unwrap().db, 0);
    let error = RedisTarget::parse("rediss://cache.example/0#insecure")
        .err()
        .unwrap();
    assert!(error.contains("#insecure"), "{error}");
    assert!(RedisTarget::parse("redis://cache.example/x").is_err());
    assert!(RedisTarget::parse("http://cache.example").is_err());
}

#[tokio::test]
async fn json_stops_reading_at_the_budget() {
    let scrubber = Scrubber::new([("cache", "s3cret-value-123")]);
    let reply = b"*3\r\n$16\r\ns3cret-value-123\r\n%1\r\n$1\r\nk\r\n,1.5\r\n$4\r\nlast\r\n";
    let mut conn = Buffered::new(&reply[..]);
    let (value, truncated) = read_json(&mut conn, &scrubber, 1000)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        value,
        serde_json::json!(["[kv:cache]", [["k", 1.5]], "last"])
    );
    assert!(!truncated);

    let mut many = b"*1000\r\n".to_vec();
    for _ in 0..1000 {
        many.extend_from_slice(b"$10\r\n0123456789\r\n");
    }
    let mut conn = Buffered::new(&many[..]);
    let (value, truncated) = read_json(&mut conn, &scrubber, 100).await.unwrap().unwrap();
    assert!(truncated);
    assert!(value.as_array().unwrap().len() < 10);
    assert!(
        !conn.data().is_empty() || conn.fill().await.unwrap(),
        "the rest stays unread"
    );

    let mut conn = Buffered::new(&b"-ERR wrong s3cret-value-123\r\n"[..]);
    let error = read_json(&mut conn, &scrubber, 1000)
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(error, "ERR wrong [kv:cache]");
}
