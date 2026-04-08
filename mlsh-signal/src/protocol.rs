//! Wire protocol types for QUIC streams.
//!
//! Re-exports shared types from `mlsh_protocol` and provides signal-specific
//! convenience aliases for the framing functions.

pub use mlsh_protocol::framing::read_msg_opt as read_message;
pub use mlsh_protocol::framing::write_msg as write_message;
pub use mlsh_protocol::messages::{RelayMessage, ServerMessage, StreamMessage};
pub use mlsh_protocol::types::{Candidate, NodeInfo, PeerInfo};
