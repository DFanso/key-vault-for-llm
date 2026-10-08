use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE};
use kv_core::scrub::Scrubber;
use percent_encoding::{NON_ALPHANUMERIC, percent_encode};
use proptest::prelude::*;

const KEY: &str = "sk-or-v1-0123456789abcdef";

fn scrub(s: &Scrubber, input: &str) -> String {
    String::from_utf8(s.scrub(input.as_bytes())).unwrap()
}

#[test]
fn replaces_raw_value_with_handle_label() {
    let s = Scrubber::new([("openrouter", KEY)]);
    assert_eq!(scrub(&s, &format!("key={KEY};")), "key=[kv:openrouter];");
}

#[test]
fn replaces_hex_in_both_cases() {
    let s = Scrubber::new([("openrouter", KEY)]);
    let lower = hex::encode(KEY);
    let upper = hex::encode_upper(KEY);
    assert_eq!(
        scrub(&s, &format!("{lower} {upper}")),
        "[kv:openrouter] [kv:openrouter]"
    );
}

#[test]
fn replaces_base64_at_every_alignment() {
    let s = Scrubber::new([("openrouter", KEY)]);
    for prefix in ["", "a", "ab", "abc"] {
        for engine in [&STANDARD, &URL_SAFE] {
            let encoded = engine.encode(format!("{prefix}{KEY}~~"));
            let out = scrub(&s, &encoded);
            assert!(out.contains("[kv:openrouter]"), "prefix {prefix:?}: {out}");
        }
    }
}

#[test]
fn replaces_percent_and_json_encoded_db_passwords() {
    let password = r#"p@ss"word/with:chars"#;
    let s = Scrubber::new([("prod-db", password)]);
    let percent = percent_encode(password.as_bytes(), NON_ALPHANUMERIC).to_string();
    let json = serde_json::to_string(password).unwrap();
    assert_eq!(scrub(&s, &percent), "[kv:prod-db]");
    assert_eq!(
        scrub(&s, &format!("{{\"pw\":{json}}}")),
        "{\"pw\":\"[kv:prod-db]\"}"
    );
    let component = "p%40ss%22word%2Fwith%3Achars";
    assert_eq!(scrub(&s, component), "[kv:prod-db]");
}

#[test]
fn labels_each_secret_with_its_own_handle() {
    let s = Scrubber::new([("a", "aaaaaaaaaaaa"), ("b", "bbbbbbbbbbbb")]);
    assert_eq!(scrub(&s, "bbbbbbbbbbbb aaaaaaaaaaaa"), "[kv:b] [kv:a]");
}

#[test]
fn ignores_values_shorter_than_eight_characters() {
    let s = Scrubber::new([("short", "abc1234")]);
    assert!(s.is_empty());
    assert_eq!(scrub(&s, "abc1234"), "abc1234");
}

#[test]
fn leaves_partial_matches_alone() {
    let s = Scrubber::new([("openrouter", KEY)]);
    assert_eq!(scrub(&s, "sk-or-v1-0123"), "sk-or-v1-0123");
}

#[test]
fn stream_catches_a_secret_split_across_chunks() {
    let s = Scrubber::new([("openrouter", KEY)]);
    let mut stream = s.stream();
    let mut out = stream.push(b"token: sk-or-v1-01");
    out.extend(stream.push(b"23456789abcdef\n"));
    out.extend(stream.finish());
    assert_eq!(String::from_utf8(out).unwrap(), "token: [kv:openrouter]\n");
}

#[test]
fn stream_without_secrets_passes_through() {
    let s = Scrubber::new(std::iter::empty::<(&str, &str)>());
    let mut stream = s.stream();
    assert_eq!(stream.push(b"hello"), b"hello");
    assert!(stream.finish().is_empty());
}

fn chunked<'a>(input: &'a [u8], cuts: &[usize]) -> Vec<&'a [u8]> {
    let mut points: Vec<usize> = cuts.iter().map(|c| c % (input.len() + 1)).collect();
    points.sort_unstable();
    points.dedup();
    let mut chunks = Vec::new();
    let mut last = 0;
    for p in points {
        chunks.push(&input[last..p]);
        last = p;
    }
    chunks.push(&input[last..]);
    chunks
}

fn encode(secret: &str, how: u8, prefix: &[u8]) -> String {
    let mut buf = prefix.to_vec();
    buf.extend_from_slice(secret.as_bytes());
    match how {
        0 => secret.to_string(),
        1 => hex::encode(secret),
        2 => hex::encode_upper(secret),
        3 => STANDARD.encode(&buf),
        4 => URL_SAFE.encode(&buf),
        5 => percent_encode(secret.as_bytes(), NON_ALPHANUMERIC).to_string(),
        _ => serde_json::to_string(secret).unwrap(),
    }
}

proptest! {
    #[test]
    fn stream_output_equals_one_shot_output(
        secret in "[a-zA-Z0-9!@#$%^&*()_+=/:\"'{}-]{8,40}",
        pieces in prop::collection::vec((0u8..7, prop::collection::vec(any::<u8>(), 0..3), "[ ,;\n]{0,20}"), 0..6),
        cuts in prop::collection::vec(any::<usize>(), 0..8),
    ) {
        let s = Scrubber::new([("h", secret.as_str())]);
        let mut input = String::new();
        for (how, prefix, noise) in &pieces {
            input.push_str(noise);
            input.push_str(&encode(&secret, *how, prefix));
        }
        let mut stream = s.stream();
        let mut streamed = Vec::new();
        for chunk in chunked(input.as_bytes(), &cuts) {
            streamed.extend(stream.push(chunk));
        }
        streamed.extend(stream.finish());
        prop_assert_eq!(streamed, s.scrub(input.as_bytes()));
    }

    #[test]
    fn no_encoding_of_a_secret_survives(
        secret in "[a-zA-Z0-9!@#$%^&*()_+=/:\"'{}-]{8,40}",
        how in 0u8..7,
        prefix in prop::collection::vec(any::<u8>(), 0..3),
        before in "[ ,;\n]{0,20}",
        after in "[ ,;\n]{0,20}",
        cuts in prop::collection::vec(any::<usize>(), 0..8),
    ) {
        let s = Scrubber::new([("h", secret.as_str())]);
        let encoded = encode(&secret, how, &prefix);
        let input = format!("{before}{encoded}{after}");
        let mut stream = s.stream();
        let mut out = Vec::new();
        for chunk in chunked(input.as_bytes(), &cuts) {
            out.extend(stream.push(chunk));
        }
        out.extend(stream.finish());
        let out = String::from_utf8_lossy(&out);
        prop_assert!(!out.contains(secret.as_str()), "raw secret survived: {}", out);
        prop_assert!(out.contains("[kv:h]"), "nothing replaced in {}", out);
    }
}
