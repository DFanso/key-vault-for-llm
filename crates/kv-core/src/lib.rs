//! Core types for kv: the encrypted vault, secret records, policy checks and
//! output scrubbing. Nothing here does network or socket I/O.

pub mod crypto;
pub mod error;

pub use error::VaultError;
