//! `mlshtund` — tunnel daemon module.
//!
//! Long-lived daemon that owns TUN devices and manages overlay tunnel
//! connections. CLI and future GUI are thin clients communicating over
//! a Unix socket.

pub mod client;
pub mod control;
pub mod dns;
pub mod overlay_dns;
pub mod peer_table;
pub mod protocol;
pub mod quic_server;
pub mod relay_handler;
pub mod relay_tls;
pub mod signal_session;
pub mod tunnel;
pub mod tunnel_manager;
