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
    /// Ed25519 public key (base64url, 32 bytes) for admission cert verification.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub public_key: String,
    /// Admission certificate proving cluster membership (JSON-serialized).
    /// Peers verify this locally before accepting the peer.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub admission_cert: String,
    #[serde(default)]
    pub display_name: String,
    /// Cluster role: "node" (default), "admin", or "control" (implies admin).
    /// Used by peers to gate sensitive overlay operations like the admin
    /// tunnel without round-tripping to signal.
    #[serde(default)]
    pub role: String,
}

/// Information about a registered node (returned by ListNodes).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeInfo {
    pub node_id: String,
    pub overlay_ip: String,
    pub role: String,
    pub online: bool,
    /// Whether this node has a valid admission certificate stored.
    #[serde(default)]
    pub has_admission_cert: bool,
    #[serde(default)]
    pub display_name: String,
}

/// Ingress service mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IngressMode {
    /// HTTP(S) reverse proxy via rpxy-lib on the peer.
    #[default]
    Http,
    /// Raw L4 TCP passthrough (future work; rejected by signal for now).
    L4,
}

/// A registered public-ingress route (returned by ListExposed).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngressRoute {
    pub domain: String,
    pub target: String,
    pub node_id: String,
    #[serde(default)]
    pub mode: IngressMode,
    /// "relay" when traffic transits mlsh-signal; "direct" when DNS points at
    /// the node's public IP.
    pub public_mode: String,
    /// Node's public IP in direct mode, empty otherwise.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub public_ip: String,
}
