//! QUIC server for mlsh-signal.
//!
//! Listens on UDP 4433 (configurable) and routes connections by ALPN:
//! - `mlsh-signal` — persistent signaling sessions (pub/sub + per-node auth)

pub mod alpn;
pub mod listener;
pub mod relay;
pub mod session;
pub mod tls;
