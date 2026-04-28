//! `mlshtund` — tunnel daemon module.
//!
//! Long-lived daemon that owns TUN devices and manages overlay tunnel
//! connections. CLI and future GUI are thin clients communicating over
//! a Unix socket.

pub mod acme;
pub mod cluster_config;
pub mod control;
pub mod daemon;
pub mod ingress;
pub mod net;
pub mod overlay;
pub mod signal_session;
pub mod transport;
pub mod tunnel;
pub mod tunnel_manager;
