//! Replaces secret values, and common encodings of them, in tool output.

use aho_corasick::{AhoCorasick, MatchKind};
use base64::Engine;
use base64::engine::GeneralPurpose;
use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, percent_encode};

/// Values shorter than this many characters are not scrubbed; they would
/// match ordinary text.
pub const MIN_SECRET_LEN: usize = 8;

/// `encodeURIComponent`-style: leaves `-_.~` alone.
const URI_COMPONENT: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~');

pub struct Scrubber {
    matcher: Option<AhoCorasick>,
    /// `replacements[i]` replaces pattern `i`.
    replacements: Vec<Vec<u8>>,
    max_pattern_len: usize,
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
        let matcher = (!patterns.is_empty()).then(|| {
            AhoCorasick::builder()
                .match_kind(MatchKind::LeftmostLongest)
                .build(&patterns)
                .expect("scrub patterns build into an automaton")
        });
        Self {
            matcher,
            replacements,
            max_pattern_len,
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
}

/// Scrubs output that arrives in chunks. Holds back the last
/// `longest pattern - 1` bytes so a secret split across chunks is still
/// caught. The concatenated output equals `Scrubber::scrub` on the whole
/// input.
pub struct StreamScrubber<'s> {
    scrubber: &'s Scrubber,
    pending: Vec<u8>,
}

impl StreamScrubber<'_> {
    pub fn push(&mut self, chunk: &[u8]) -> Vec<u8> {
        let Some(ac) = &self.scrubber.matcher else {
            return chunk.to_vec();
        };
        self.pending.extend_from_slice(chunk);
        // Every match starting before `cut` lies entirely inside `pending`.
        let cut = self
            .pending
            .len()
            .saturating_sub(self.scrubber.max_pattern_len - 1);
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
}

fn variants(value: &str) -> Vec<Vec<u8>> {
    let raw = value.as_bytes();
    let mut out = vec![
        raw.to_vec(),
        hex::encode(raw).into_bytes(),
        hex::encode_upper(raw).into_bytes(),
        percent_encode(raw, NON_ALPHANUMERIC)
            .to_string()
            .into_bytes(),
        percent_encode(raw, URI_COMPONENT).to_string().into_bytes(),
    ];
    let json = serde_json::to_string(value).expect("a str serializes");
    out.push(json.as_bytes()[1..json.len() - 1].to_vec());
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
