//! `kv tray`: a menu bar (macOS) or notification area (Windows) icon that
//! shows waiting agent requests and answers them from its menu, after
//! unlocking with Touch ID or Windows Hello.

pub mod login;
pub mod model;
pub mod worker;
