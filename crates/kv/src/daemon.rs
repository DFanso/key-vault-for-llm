//! The daemon: request handling (`state`), the socket server (`server`) and
//! process hardening (`harden`).

mod harden;
mod server;
mod state;

pub use server::run;
pub use state::{After, Daemon, Settings};
