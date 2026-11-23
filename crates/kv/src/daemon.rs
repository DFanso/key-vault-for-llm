//! The daemon: request handling (`state`), the socket server (`server`),
//! what it tells the user about things waiting on them (`notices`) and
//! process hardening (`harden`).

mod harden;
mod notices;
mod server;
mod state;

pub use notices::{LOCKED_EVERY, MAX_OUTBOX, MISSED_EVERY, MISSED_GATHER, Plain, TAKER_FRESH};
pub use server::{MAX_UNLOCK_WAITERS, Outcome, run};
pub(crate) use state::printable;
pub use state::{After, Daemon, Prepared, Settings, Waiting};
