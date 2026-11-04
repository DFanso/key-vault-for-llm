//! Replaces secret values, and common encodings of them, in tool output.

use std::collections::HashSet;

use aho_corasick::{AhoCorasick, AhoCorasickKind, MatchKind};
use base64::Engine;
use base64::engine::GeneralPurpose;
use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, percent_encode};

use crate::crypto::fill_random;

/// Values shorter than this many characters are not scrubbed; they would
/// match ordinary text.
pub const MIN_SECRET_LEN: usize = 8;

/// `encodeURIComponent`-style: leaves `-_.~` alone.
const URI_COMPONENT: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~');

/// Python's `quote()`: also leaves `/` alone.
const PATH_SEGMENT: &AsciiSet = &URI_COMPONENT.remove(b'/');

/// `encodeURI`-style: leaves URL delimiters alone.
const URI: &AsciiSet = &PATH_SEGMENT
    .remove(b';')
    .remove(b',')
    .remove(b'?')
    .remove(b':')
    .remove(b'@')
    .remove(b'&')
    .remove(b'=')
    .remove(b'+')
    .remove(b'$')
    .remove(b'!')
    .remove(b'*')
    .remove(b'\'')
    .remove(b'(')
    .remove(b')')
    .remove(b'#');

pub struct Scrubber {
    matcher: Option<AhoCorasick>,
    /// `replacements[i]` replaces pattern `i`.
    replacements: Vec<Vec<u8>>,
    max_pattern_len: usize,
    /// A hash of every proper prefix of every pattern, in ASCII lowercase,
    /// with its length: the tails a stream must hold back, because more
    /// input could complete a secret. Hashes rather than the prefixes
    /// themselves keep this linear in the patterns' length; keeping every
    /// prefix took gigabytes for a few long values. Two strings that share
    /// a hash only make a stream hold back more than it had to, never less.
    prefixes: HashSet<u64>,
    /// The base of the prefix hash, random per scrubber, so text chosen to
    /// collide with a secret's prefixes does not know it.
    base: u64,
}

/// The prime the prefix hash works modulo: 2^61 - 1.
const MODULUS: u64 = (1 << 61) - 1;

fn mul_mod(a: u64, b: u64) -> u64 {
    let product = u128::from(a) * u128::from(b);
    let folded = (product as u64 & MODULUS) + (product >> 61) as u64;
    let folded = (folded & MODULUS) + (folded >> 61);
    if folded >= MODULUS {
        folded - MODULUS
    } else {
        folded
    }
}

fn add_mod(a: u64, b: u64) -> u64 {
    let sum = a + b;
    if sum >= MODULUS { sum - MODULUS } else { sum }
}

/// One byte of a prefix, as the hash counts it: never zero, so leading
/// zero bytes still change it.
fn digit(byte: u8) -> u64 {
    u64::from(byte.to_ascii_lowercase()) + 1
}

/// What the prefix set holds for a prefix of `len` bytes hashing to `hash`.
fn prefix_key(len: usize, hash: u64) -> u64 {
    hash ^ (len as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15)
}

fn random_base() -> u64 {
    let mut bytes = [0u8; 8];
    fill_random(&mut bytes);
    // Anything from 2^8 up keeps bytes from colliding as digits.
    (u64::from_le_bytes(bytes) % (MODULUS - 512)) + 256
}

/// The most `cost` all of a vault's values may add up to. The scrubber
/// takes about 52 bytes of memory and 0.2 microseconds to build per unit,
/// so this keeps it near 110 MB and half a second at worst. Ordinary
/// tokens cost about 8 per byte, so this is about 256 KiB of them; values
/// full of punctuation, whose percent-encodings are long, cost about 55.
pub const MAX_TOTAL_COST: usize = 2 * 1024 * 1024;

/// What scrubbing `value` costs: the bytes of every encoding of it the
/// scrubber looks for, which its memory and build time grow with. A value
/// too short to scrub costs nothing.
pub fn cost(value: &str) -> usize {
    if value.chars().count() < MIN_SECRET_LEN {
        return 0;
    }
    variants(value).iter().map(Vec::len).sum()
}

impl Scrubber {
    /// `secrets` yields `(handle, value)` pairs. Matches become `[kv:<handle>]`.
    pub fn new<'a>(secrets: impl IntoIterator<Item = (&'a str, &'a str)>) -> Self {
        let mut patterns = Vec::new();
        let mut replacements = Vec::new();
        for (handle, value) in secrets {
            if value.chars().count() < MIN_SECRET_LEN {
                continue;
            }
            let replacement = format!("[kv:{handle}]").into_bytes();
            for pattern in variants(value) {
                patterns.push(pattern);
                replacements.push(replacement.clone());
            }
        }
        let max_pattern_len = patterns.iter().map(Vec::len).max().unwrap_or(0);
        let base = random_base();
        let mut prefixes = HashSet::new();
        for pattern in &patterns {
            let mut hash = 0;
            for (len, &byte) in pattern.iter().enumerate().take(pattern.len() - 1) {
                hash = add_mod(mul_mod(hash, base), digit(byte));
                prefixes.insert(prefix_key(len + 1, hash));
            }
        }
        let matcher = (!patterns.is_empty()).then(|| {
            AhoCorasick::builder()
                .match_kind(MatchKind::LeftmostLongest)
                // A DFA took seconds to build for a long value of one
                // repeated letter, under the daemon's lock; the contiguous
                // NFA takes milliseconds and is quick enough for output.
                .kind(Some(AhoCorasickKind::ContiguousNFA))
                // Host names are case-insensitive, and a secret in another
                // case is still a secret.
                .ascii_case_insensitive(true)
                .build(&patterns)
                .expect("scrub patterns build into an automaton")
        });
        Self {
            matcher,
            replacements,
            max_pattern_len,
            prefixes,
            base,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.matcher.is_none()
    }

    pub fn scrub(&self, input: &[u8]) -> Vec<u8> {
        match &self.matcher {
            Some(ac) => ac.replace_all_bytes(input, &self.replacements),
            None => input.to_vec(),
        }
    }

    pub fn stream(&self) -> StreamScrubber<'_> {
        StreamScrubber {
            scrubber: self,
            pending: Vec::new(),
        }
    }

    /// A stream that starts with `pending`, the bytes another stream held
    /// back (`StreamScrubber::into_pending`), so a long-running stream can
    /// move to a scrubber with newer secrets without losing them.
    pub fn resume(&self, pending: Vec<u8>) -> StreamScrubber<'_> {
        StreamScrubber {
            scrubber: self,
            pending,
        }
    }

    /// Where the tail that could still grow into a secret starts: the
    /// longest suffix of `pending` that is a proper prefix of a pattern, or
    /// `pending.len()` when none is.
    fn held_from(&self, pending: &[u8]) -> usize {
        let longest = self.max_pattern_len.saturating_sub(1).min(pending.len());
        let tail = &pending[pending.len() - longest..];
        // The suffixes' hashes, shortest first: each adds one byte in front,
        // at the next power of the base. Linear in the tail.
        let mut hash = 0;
        let mut power = 1;
        let mut held = 0;
        for (index, &byte) in tail.iter().enumerate().rev() {
            hash = add_mod(hash, mul_mod(digit(byte), power));
            power = mul_mod(power, self.base);
            let len = tail.len() - index;
            if self.prefixes.contains(&prefix_key(len, hash)) {
                held = len;
            }
        }
        pending.len() - held
    }
}

/// Scrubs output that arrives in chunks. Holds back only a tail that could
/// still grow into a secret, so a secret split across chunks is caught and
/// everything else goes out at once. The concatenated output equals
/// `Scrubber::scrub` on the whole input.
pub struct StreamScrubber<'s> {
    scrubber: &'s Scrubber,
    pending: Vec<u8>,
}

impl StreamScrubber<'_> {
    pub fn push(&mut self, chunk: &[u8]) -> Vec<u8> {
        let Some(ac) = &self.scrubber.matcher else {
            let mut out = std::mem::take(&mut self.pending);
            out.extend_from_slice(chunk);
            return out;
        };
        self.pending.extend_from_slice(chunk);
        // A match starting before `cut` lies entirely inside `pending` and
        // cannot grow into a longer one: that would make the bytes from its
        // start a proper prefix of a pattern, and so part of the held tail.
        let cut = self.scrubber.held_from(&self.pending);
        let mut out = Vec::new();
        let mut last = 0;
        for m in ac.find_iter(&self.pending) {
            if m.start() >= cut {
                break;
            }
            out.extend_from_slice(&self.pending[last..m.start()]);
            out.extend_from_slice(&self.scrubber.replacements[m.pattern().as_usize()]);
            last = m.end();
        }
        let emit_to = cut.max(last);
        out.extend_from_slice(&self.pending[last..emit_to]);
        self.pending.drain(..emit_to);
        out
    }

    pub fn finish(self) -> Vec<u8> {
        self.scrubber.scrub(&self.pending)
    }

    /// The bytes held back so far, neither scrubbed nor emitted.
    pub fn into_pending(self) -> Vec<u8> {
        self.pending
    }
}

fn variants(value: &str) -> Vec<Vec<u8>> {
    let raw = value.as_bytes();
    let mut out = vec![
        raw.to_vec(),
        hex::encode(raw).into_bytes(),
        hex::encode_upper(raw).into_bytes(),
    ];
    out.extend(percent_variants(raw).into_iter().map(String::into_bytes));
    out.extend(json_variants(value).into_iter().map(String::into_bytes));
    for engine in [&STANDARD_NO_PAD, &URL_SAFE_NO_PAD] {
        for offset in 0..3 {
            out.extend(base64_core(engine, raw, offset));
        }
    }
    out.retain(|p| p.len() >= MIN_SECRET_LEN);
    out.sort();
    out.dedup();
    out
}

/// Percent-encodings as common libraries produce them: four reserved-char
/// sets, upper- or lowercase hex escapes, and form-style `+` for spaces.
fn percent_variants(raw: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    for set in [NON_ALPHANUMERIC, URI_COMPONENT, PATH_SEGMENT, URI] {
        let upper = percent_encode(raw, set).to_string();
        let lower = lowercase_escapes(&upper);
        for form in [upper, lower] {
            if form.contains("%20") {
                out.push(form.replace("%20", "+"));
            }
            out.push(form);
        }
    }
    out
}

fn lowercase_escapes(encoded: &str) -> String {
    let mut out = String::with_capacity(encoded.len());
    let mut chars = encoded.chars();
    while let Some(c) = chars.next() {
        out.push(c);
        if c == '%' {
            out.extend(chars.by_ref().take(2).map(|h| h.to_ascii_lowercase()));
        }
    }
    out
}

/// JSON string bodies (without quotes) as common encoders produce them:
/// plain, with `/` escaped as `\/`, and with non-ASCII as `\uXXXX` in either
/// hex case.
fn json_variants(value: &str) -> Vec<String> {
    let quoted = serde_json::to_string(value).expect("a str serializes");
    let plain = quoted[1..quoted.len() - 1].to_owned();
    let mut out = Vec::new();
    for form in [
        escape_non_ascii(&plain, false),
        escape_non_ascii(&plain, true),
        plain,
    ] {
        out.push(form.replace('/', "\\/"));
        out.push(form);
    }
    out
}

fn escape_non_ascii(json: &str, uppercase: bool) -> String {
    let mut out = String::with_capacity(json.len());
    for c in json.chars() {
        if c.is_ascii() {
            out.push(c);
            continue;
        }
        let mut units = [0u16; 2];
        for unit in c.encode_utf16(&mut units) {
            if uppercase {
                out.push_str(&format!("\\u{unit:04X}"));
            } else {
                out.push_str(&format!("\\u{unit:04x}"));
            }
        }
    }
    out
}

/// The base64 characters that depend only on `raw` when it starts `offset`
/// bytes into a base64-encoded buffer. Covers secrets embedded anywhere in a
/// larger encoded blob.
fn base64_core(engine: &GeneralPurpose, raw: &[u8], offset: usize) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; offset];
    buf.extend_from_slice(raw);
    let encoded = engine.encode(&buf);
    let start = (offset * 8).div_ceil(6);
    let end = (offset + raw.len()) * 8 / 6;
    (end > start).then(|| encoded.as_bytes()[start..end].to_vec())
}
