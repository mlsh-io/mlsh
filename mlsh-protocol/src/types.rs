//! Shared data types for the mlsh signaling protocol.

use serde::{Deserialize, Serialize};

/// A network candidate address for direct connection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Candidate {
    /// Kind: "host" (local IP), "srflx" (server-reflexive / NAT-observed).
    pub kind: String,
    /// Candidate address (IP:port).
    pub addr: String,
    /// Priority (higher = preferred). Host candidates get lower priority than srflx.
    pub priority: u32,
}

/// Information about a peer in the overlay network.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    pub node_id: String,
    pub fingerprint: String,
    pub overlay_ip: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub candidates: Vec<Candidate>,
}

/// Information about a registered node (returned by ListNodes).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeInfo {
    pub node_id: String,
    pub overlay_ip: String,
    pub role: String,
    pub online: bool,
}
