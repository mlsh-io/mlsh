//! `mlshtund` — tunnel daemon module.
//!
//! Long-lived daemon that owns TUN devices and manages overlay tunnel
//! connections. CLI and future GUI are thin clients communicating over
//! a Unix socket.

pub mod acme;
pub mod client;
pub mod cluster_config;
pub mod control;
pub mod control_child;
pub mod control_session;
pub mod daemon;
pub mod dns;
pub mod endpoint_migrate;
pub mod ingress;
pub mod net_filter;
pub mod net_watcher;
pub mod overlay_dns;
pub mod peer_fsm;
pub mod peer_table;
pub mod probe;
pub mod protocol;
pub mod quic_client;
pub mod quic_server;
pub mod relay_handler;
pub mod relay_initiator;
pub mod relay_tls;
pub mod routes;
pub mod signal_session;
pub mod transport;
pub mod tunnel;
pub mod tunnel_manager;
