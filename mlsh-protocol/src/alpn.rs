//! ALPN protocol identifiers for mlsh QUIC connections.

/// Persistent signaling connection from cluster nodes. Requires mTLS.
pub const ALPN_SIGNAL: &[u8] = b"mlsh-signal";

/// Direct peer-to-peer overlay tunnel between cluster nodes.
pub const ALPN_OVERLAY: &[u8] = b"mlsh-overlay";
