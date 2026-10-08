//! The kv daemon, its CLI, and the socket plumbing they share.

pub mod audit;
pub mod broker;
pub mod cli;
pub mod client;
pub mod daemon;
pub mod frame;
pub mod ipc;
pub mod mcp;
pub mod notify;
pub mod paths;
pub mod throttle;
