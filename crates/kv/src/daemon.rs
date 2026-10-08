//! The daemon: request handling (`state`), the socket server (`server`) and
//! process hardening (`harden`).

mod state;

pub use state::{After, Daemon, Settings};
