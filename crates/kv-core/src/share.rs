//! Sharing a secret with someone else's kv.
//!
//! The vault that wants a secret makes an X25519 key pair, keeps the private
//! half and hands out the public half as a request code. The vault that has
//! the secret seals it to that key: an ephemeral X25519 key, HKDF-SHA256 and
//! XChaCha20-Poly1305. Only the requesting vault can open the result, so the
//! codes and the sealed text can travel over any chat.
//!
//! Anyone who sees a request code can seal something to it, so a share says
//! nothing reliable about who sent it. The safety code, a short fingerprint
//! of the request's key, lets the two people check over another channel
//! that the sender sealed to the right vault.

use std::fmt;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::crypto::{KEY_LEN, NONCE_LEN, fill_random, random_nonce};
use crate::secret::{SecretKind, SecretText, SecretValue};

/// What a request code starts with.
pub const REQUEST_PREFIX: &str = "kv-request:v1:";
/// What sealed share text starts with.
pub const SHARE_PREFIX: &str = "kv-share:v1:";

/// Domain separation for the key derivation and the AEAD.
const INFO: &[u8] = b"kv-share-v1";
const SAFETY_DOMAIN: &[u8] = b"kv-share-safety-v1";
const VALUE_DOMAIN: &[u8] = b"kv-share-value-v1";

/// Longest text accepted as a request code or a share, in bytes.
pub const MAX_TEXT_LEN: usize = 256 * 1024;
/// Longest sealed payload, in bytes.
pub const MAX_PAYLOAD_LEN: usize = 128 * 1024;
/// Longest sealed payload of a file, in bytes: the largest file as base64
/// and the room its name and checksum take.
pub const MAX_FILE_PAYLOAD_LEN: usize = crate::secret::MAX_FILE_LEN / 3 * 4 + 4096;
/// Longest share text that holds a file, in bytes: the payload sealed and
/// written as base64 twice over. Such a share travels as a file, never
/// as a pasted message.
pub const MAX_FILE_TEXT_LEN: usize = MAX_FILE_PAYLOAD_LEN / 3 * 4 / 3 * 4 + 4096;

// A share of the largest file has to fit a frame of the control socket.
const _: () = assert!(MAX_FILE_TEXT_LEN + 1024 < crate::proto::MAX_FRAME_LEN);
/// Longest note or name a request carries, in characters.
const MAX_REQUEST_TEXT: usize = 300;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShareError {
    /// No `kv-request:v1:` code in the text, or it does not decode.
    NotARequest,
    /// No `kv-share:v1:` text in the text, or it does not decode.
    NotAShare,
    /// The share decodes but does not open: changed on the way, or cut off.
    Damaged,
    /// The share was sealed to a key this vault has no open request for.
    NoMatchingRequest,
    /// The request's key is not a usable X25519 key.
    WeakKey,
    TooLarge,
    /// The file in the share is not the one that was sent: its checksum
    /// does not match, or its name is not a plain file name.
    BadFile,
}

impl fmt::Display for ShareError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotARequest => "that is not a kv request code (it starts with kv-request:v1:)",
            Self::NotAShare => "that is not a kv share (it starts with kv-share:v1:)",
            Self::Damaged => {
                "the share does not open: it was changed or cut off on the way; ask for it again"
            }
            Self::NoMatchingRequest => {
                "the share was not sealed to an open request of this vault: it was used already, \
                 cancelled or expired, or it was made for someone else"
            }
            Self::WeakKey => "the request code holds a key kv cannot seal to",
            Self::TooLarge => "the share is too large",
            Self::BadFile => {
                "the file in the share does not match its checksum, or has an unsafe name, so kv \
                 does not take it; ask for it again"
            }
        })
    }
}

impl std::error::Error for ShareError {}

/// A request as the other side reads it from the code: the key to seal to,
/// and what the requester said about it. The note and name are written by
/// whoever made the code; show them as such.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShareRequest {
    pub public_key: [u8; 32],
    pub note: String,
    pub from: String,
}

#[derive(Serialize, Deserialize)]
struct RequestWire {
    k: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    n: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    f: String,
}

impl ShareRequest {
    pub fn encode(&self) -> String {
        let wire = RequestWire {
            k: URL_SAFE_NO_PAD.encode(self.public_key),
            n: self.note.clone(),
            f: self.from.clone(),
        };
        let json = serde_json::to_vec(&wire).expect("a request serializes");
        format!("{REQUEST_PREFIX}{}", URL_SAFE_NO_PAD.encode(json))
    }

    /// Finds a request code in `text`, which may be a whole chat message.
    pub fn decode(text: &str) -> Result<Self, ShareError> {
        let bytes = extract(text, REQUEST_PREFIX).ok_or(ShareError::NotARequest)?;
        let wire: RequestWire =
            serde_json::from_slice(&bytes).map_err(|_| ShareError::NotARequest)?;
        let public_key = key_bytes(&wire.k).ok_or(ShareError::NotARequest)?;
        Ok(Self {
            public_key,
            note: cut(&wire.n, MAX_REQUEST_TEXT),
            from: cut(&wire.f, MAX_REQUEST_TEXT),
        })
    }

    pub fn safety_code(&self) -> String {
        safety_code(&self.public_key)
    }
}

/// A request this vault made and is waiting on, with its private key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenRequest {
    pub id: String,
    /// The X25519 private key, as base64.
    secret_key: SecretText,
    /// The public key, as unpadded base64url.
    pub public_key: String,
    #[serde(default)]
    pub note: String,
    #[serde(default)]
    pub from: String,
    /// Unix seconds.
    pub created_at: u64,
    pub expires_at: u64,
}

impl OpenRequest {
    /// A new key pair for a request. `note` and `from` go into the code as
    /// given.
    pub fn new(note: String, from: String, now: u64, ttl_secs: u64) -> Self {
        let mut raw = Zeroizing::new([0u8; 32]);
        fill_random(raw.as_mut());
        let secret = StaticSecret::from(*raw);
        let public = PublicKey::from(&secret);
        let encoded = Zeroizing::new(URL_SAFE_NO_PAD.encode(secret.as_bytes()));
        Self {
            id: new_id(),
            secret_key: SecretText::new(encoded.as_str()),
            public_key: URL_SAFE_NO_PAD.encode(public.as_bytes()),
            note,
            from,
            created_at: now,
            expires_at: now.saturating_add(ttl_secs),
        }
    }

    /// The code to send to whoever has the secret.
    pub fn code(&self) -> String {
        self.request().encode()
    }

    pub fn request(&self) -> ShareRequest {
        ShareRequest {
            public_key: key_bytes(&self.public_key).unwrap_or([0; 32]),
            note: self.note.clone(),
            from: self.from.clone(),
        }
    }

    pub fn safety_code(&self) -> String {
        self.request().safety_code()
    }

    pub fn is_expired(&self, now: u64) -> bool {
        now >= self.expires_at
    }

    /// What may be shown about it: everything but the private key.
    pub fn info(&self, now: u64) -> RequestInfo {
        RequestInfo {
            id: self.id.clone(),
            code: self.code(),
            safety_code: self.safety_code(),
            note: self.note.clone(),
            from: self.from.clone(),
            created_at: self.created_at,
            expires_at: self.expires_at,
            expired: self.is_expired(now),
        }
    }

    fn secret(&self) -> Option<StaticSecret> {
        let bytes = Zeroizing::new(URL_SAFE_NO_PAD.decode(self.secret_key.expose()).ok()?);
        let raw: Zeroizing<[u8; 32]> = Zeroizing::new(bytes.as_slice().try_into().ok()?);
        Some(StaticSecret::from(*raw))
    }
}

/// An open request as the user sees it. Holds no key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestInfo {
    pub id: String,
    /// The request code, which is public.
    pub code: String,
    pub safety_code: String,
    pub note: String,
    pub from: String,
    pub created_at: u64,
    pub expires_at: u64,
    pub expired: bool,
}

/// What a share carries: a handle's value and the parts of its policy that
/// say where the value may go. The receiving vault decides the rest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SharedSecret {
    /// The handle name the sender suggests.
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub value: SecretValue,
    #[serde(default)]
    pub allowed_hosts: Vec<String>,
    #[serde(default)]
    pub allow_plain_http: bool,
    #[serde(default)]
    pub allowed_methods: Vec<String>,
    #[serde(default)]
    pub read_only: bool,
    /// Who the sender says they are.
    #[serde(default)]
    pub from: String,
    #[serde(default)]
    pub note: String,
}

#[derive(Serialize, Deserialize)]
struct ShareWire {
    /// The request key it was sealed to.
    to: String,
    /// The ephemeral public key.
    e: String,
    n: String,
    c: String,
}

/// Seals `secret` so that only the vault that made `request` can open it,
/// and returns the text to send back.
pub fn seal(request: &ShareRequest, secret: &SharedSecret) -> Result<String, ShareError> {
    // A file is held to its checksum before it goes, so a sender never
    // seals one the receiver would refuse.
    secret
        .value
        .verify_file()
        .map_err(|_| ShareError::BadFile)?;
    let plaintext = Zeroizing::new(serde_json::to_vec(secret).expect("a share serializes"));
    let limit = if secret.value.kind() == SecretKind::File {
        MAX_FILE_PAYLOAD_LEN
    } else {
        MAX_PAYLOAD_LEN
    };
    if plaintext.len() > limit {
        return Err(ShareError::TooLarge);
    }
    let mut raw = Zeroizing::new([0u8; 32]);
    fill_random(raw.as_mut());
    let ephemeral = StaticSecret::from(*raw);
    let ephemeral_public = PublicKey::from(&ephemeral);
    let recipient = PublicKey::from(request.public_key);
    let shared = ephemeral.diffie_hellman(&recipient);
    if !shared.was_contributory() {
        return Err(ShareError::WeakKey);
    }
    let key = derive(
        shared.as_bytes(),
        ephemeral_public.as_bytes(),
        &request.public_key,
    );
    let nonce = random_nonce();
    let aad = aad(ephemeral_public.as_bytes(), &request.public_key);
    let ciphertext = cipher(&key)
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: &plaintext,
                aad: &aad,
            },
        )
        .expect("XChaCha20-Poly1305 encryption of an in-memory buffer cannot fail");
    let wire = ShareWire {
        to: URL_SAFE_NO_PAD.encode(request.public_key),
        e: URL_SAFE_NO_PAD.encode(ephemeral_public.as_bytes()),
        n: URL_SAFE_NO_PAD.encode(nonce),
        c: URL_SAFE_NO_PAD.encode(ciphertext),
    };
    let json = serde_json::to_vec(&wire).expect("a share serializes");
    Ok(format!("{SHARE_PREFIX}{}", URL_SAFE_NO_PAD.encode(json)))
}

/// Opens a share found in `text` with whichever of `requests` it was sealed
/// to. Returns that request's index and what the share carries.
pub fn open(text: &str, requests: &[OpenRequest]) -> Result<(usize, SharedSecret), ShareError> {
    let bytes =
        extract_within(text, SHARE_PREFIX, MAX_FILE_TEXT_LEN).ok_or(ShareError::NotAShare)?;
    let wire: ShareWire = serde_json::from_slice(&bytes).map_err(|_| ShareError::NotAShare)?;
    let to = key_bytes(&wire.to).ok_or(ShareError::NotAShare)?;
    let ephemeral = key_bytes(&wire.e).ok_or(ShareError::Damaged)?;
    let nonce: [u8; NONCE_LEN] = URL_SAFE_NO_PAD
        .decode(&wire.n)
        .ok()
        .and_then(|n| n.try_into().ok())
        .ok_or(ShareError::Damaged)?;
    let ciphertext = URL_SAFE_NO_PAD
        .decode(&wire.c)
        .map_err(|_| ShareError::Damaged)?;
    let index = requests
        .iter()
        .position(|r| key_bytes(&r.public_key) == Some(to))
        .ok_or(ShareError::NoMatchingRequest)?;
    let secret = requests[index]
        .secret()
        .ok_or(ShareError::NoMatchingRequest)?;
    let shared = secret.diffie_hellman(&PublicKey::from(ephemeral));
    if !shared.was_contributory() {
        return Err(ShareError::Damaged);
    }
    let key = derive(shared.as_bytes(), &ephemeral, &to);
    let plaintext = cipher(&key)
        .decrypt(
            &XNonce::from(nonce),
            Payload {
                msg: &ciphertext,
                aad: &aad(&ephemeral, &to),
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| ShareError::Damaged)?;
    let shared: SharedSecret =
        serde_json::from_slice(&plaintext).map_err(|_| ShareError::Damaged)?;
    // The encryption says the share is whole; the checksum says the file in
    // it is the one the sender had, and its name stays inside a folder.
    shared
        .value
        .verify_file()
        .map_err(|_| ShareError::BadFile)?;
    Ok((index, shared))
}

/// A share this vault opened and saved as a handle.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Received {
    pub id: String,
    /// The handle it was saved as.
    pub handle: String,
    pub kind: SecretKind,
    /// Who the sender said they were. Not verified.
    #[serde(default)]
    pub from: String,
    #[serde(default)]
    pub note: String,
    /// The safety code of the request it answered.
    pub safety_code: String,
    /// Unix seconds.
    pub received_at: u64,
    /// `value_digest` of what arrived. The value may be shown only while
    /// the handle still holds exactly that, never one the user typed in
    /// later. Kept in the vault only.
    #[serde(default)]
    pub value_digest: String,
}

/// A received share as the user sees it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceivedInfo {
    pub id: String,
    pub handle: String,
    pub kind: SecretKind,
    pub from: String,
    pub note: String,
    pub safety_code: String,
    pub received_at: u64,
    /// The handle still holds the value that arrived, so it can be shown.
    pub viewable: bool,
}

/// A handle this vault sealed for someone else's request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sent {
    pub id: String,
    pub handle: String,
    pub kind: SecretKind,
    /// The safety code of the request it was sealed to.
    pub safety_code: String,
    /// Who the requester said they were. Not verified.
    #[serde(default)]
    pub to: String,
    #[serde(default)]
    pub note: String,
    pub sent_at: u64,
}

/// Everything about sharing the vault keeps.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Shares {
    #[serde(default)]
    pub requests: Vec<OpenRequest>,
    #[serde(default)]
    pub received: Vec<Received>,
    #[serde(default)]
    pub sent: Vec<Sent>,
}

impl Shares {
    pub fn is_empty(&self) -> bool {
        self.requests.is_empty() && self.received.is_empty() && self.sent.is_empty()
    }

    /// What may be shown: the requests without their keys, and the
    /// received shares without their digests. `current` gives the
    /// `value_digest` of the handle with a name, if there is one.
    pub fn view(&self, now: u64, current: impl Fn(&str) -> Option<String>) -> SharesView {
        SharesView {
            requests: self.requests.iter().map(|r| r.info(now)).collect(),
            received: self
                .received
                .iter()
                .map(|r| ReceivedInfo {
                    id: r.id.clone(),
                    handle: r.handle.clone(),
                    kind: r.kind,
                    from: r.from.clone(),
                    note: r.note.clone(),
                    safety_code: r.safety_code.clone(),
                    received_at: r.received_at,
                    viewable: !r.value_digest.is_empty()
                        && current(&r.handle).is_some_and(|d| d == r.value_digest),
                })
                .collect(),
            sent: self.sent.clone(),
        }
    }

    /// Whether a received share was saved under `handle`, whatever it holds
    /// now.
    pub fn names_received(&self, handle: &str) -> bool {
        self.received.iter().any(|r| r.handle == handle)
    }

    /// Whether `handle` holds the value of a share it received.
    pub fn holds_received(&self, handle: &str, digest: &str) -> bool {
        self.received
            .iter()
            .any(|r| r.handle == handle && !r.value_digest.is_empty() && r.value_digest == digest)
    }

    /// Removes whatever has this id. Returns whether anything did.
    pub fn forget(&mut self, id: &str) -> bool {
        let before = self.requests.len() + self.received.len() + self.sent.len();
        self.requests.retain(|r| r.id != id);
        self.received.retain(|r| r.id != id);
        self.sent.retain(|s| s.id != id);
        before != self.requests.len() + self.received.len() + self.sent.len()
    }
}

/// Sharing as the user sees it, with no key or value in it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SharesView {
    #[serde(default)]
    pub requests: Vec<RequestInfo>,
    #[serde(default)]
    pub received: Vec<ReceivedInfo>,
    #[serde(default)]
    pub sent: Vec<Sent>,
}

/// A hash of a value, to tell later whether a handle still holds it.
pub fn value_digest(value: &SecretValue) -> String {
    let json = Zeroizing::new(serde_json::to_vec(value).expect("a value serializes"));
    hex::encode(
        Sha256::new()
            .chain_update(VALUE_DOMAIN)
            .chain_update(json.as_slice())
            .finalize(),
    )
}

/// Eight characters such as `7KQ2-M9XD` that both sides can read out to
/// each other: 40 bits of a hash of the request's key.
pub fn safety_code(public_key: &[u8; 32]) -> String {
    const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    let digest = Sha256::new()
        .chain_update(SAFETY_DOMAIN)
        .chain_update(public_key)
        .finalize();
    let bits = digest[..5]
        .iter()
        .fold(0u64, |acc, byte| (acc << 8) | u64::from(*byte));
    let chars: Vec<char> = (0..8)
        .rev()
        .map(|i| ALPHABET[((bits >> (i * 5)) & 31) as usize] as char)
        .collect();
    format!(
        "{}-{}",
        chars[..4].iter().collect::<String>(),
        chars[4..].iter().collect::<String>()
    )
}

/// A random id for a record: 16 hex digits.
pub fn new_id() -> String {
    let mut bytes = [0u8; 8];
    fill_random(&mut bytes);
    hex::encode(bytes)
}

/// The bytes after `prefix` in `text`: base64 in either alphabet, padded or
/// not, ending at the first character that cannot be part of it. Chat apps
/// may wrap the text in quotes or code marks, or keep the message around it.
fn extract(text: &str, prefix: &str) -> Option<Vec<u8>> {
    extract_within(text, prefix, MAX_TEXT_LEN)
}

/// `extract`, for text up to `max` bytes.
fn extract_within(text: &str, prefix: &str, max: usize) -> Option<Vec<u8>> {
    if text.len() > max {
        return None;
    }
    let start = text.find(prefix)? + prefix.len();
    let body: String = text[start..]
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '+' | '/' | '='))
        .filter(|c| *c != '=')
        .map(|c| match c {
            '+' => '-',
            '/' => '_',
            c => c,
        })
        .collect();
    URL_SAFE_NO_PAD.decode(body).ok()
}

fn key_bytes(encoded: &str) -> Option<[u8; 32]> {
    URL_SAFE_NO_PAD.decode(encoded).ok()?.try_into().ok()
}

fn derive(
    shared: &[u8; 32],
    ephemeral: &[u8; 32],
    recipient: &[u8; 32],
) -> Zeroizing<[u8; KEY_LEN]> {
    let mut salt = [0u8; 64];
    salt[..32].copy_from_slice(ephemeral);
    salt[32..].copy_from_slice(recipient);
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    Hkdf::<Sha256>::new(Some(&salt), shared)
        .expand(INFO, key.as_mut())
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    key
}

fn aad(ephemeral: &[u8; 32], recipient: &[u8; 32]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(INFO.len() + 64);
    aad.extend_from_slice(INFO);
    aad.extend_from_slice(ephemeral);
    aad.extend_from_slice(recipient);
    aad
}

fn cipher(key: &[u8; KEY_LEN]) -> XChaCha20Poly1305 {
    XChaCha20Poly1305::new_from_slice(key).expect("key is 32 bytes")
}

fn cut(text: &str, max_chars: usize) -> String {
    text.chars().take(max_chars).collect()
}
