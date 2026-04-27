//! ALPN protocol identifiers for mlsh QUIC connections.

/// Persistent signaling connection from cluster nodes. Requires mTLS.
pub const ALPN_SIGNAL: &[u8] = b"mlsh-signal";

/// Direct peer-to-peer overlay tunnel between cluster nodes.
pub const ALPN_OVERLAY: &[u8] = b"mlsh-overlay";

/// Public → peer reverse-proxy traffic forwarded by mlsh-signal.
pub const ALPN_INGRESS: &[u8] = b"mlsh-ingress";

/// Node ↔ mlsh-control plane. Streams are relayed by mlsh-signal to the
/// node carrying the `control` role (ADR-033). Length-prefixed CBOR; see
/// `control` module.
pub const ALPN_CONTROL: &[u8] = b"mlsh-control";
