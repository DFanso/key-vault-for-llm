//! The daemon: request handling (`state`), the socket server (`server`) and
//! process hardening (`harden`).

mod harden;
mod server;
mod state;

pub use server::{Outcome, run};
pub use state::{After, Daemon, Prepared, Settings};
