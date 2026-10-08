//! Core types for kv: the encrypted vault, secret records, policy checks and
//! output scrubbing. Nothing here does network or socket I/O.

pub mod crypto;
pub mod db;
pub mod error;
pub mod policy;
pub mod proto;
pub mod scrub;
pub mod secret;
pub mod vault;

pub use error::VaultError;
