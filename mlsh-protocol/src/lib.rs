pub mod alpn;
pub mod control;
pub mod framing;
pub mod messages;
pub mod types;

/// Wire protocol version. Bump on every breaking change to the
/// `StreamMessage` / `ServerMessage` schemas.
pub const PROTOCOL_VERSION: u32 = 1;

/// Lowest protocol version a signal server still accepts on the wire.
/// Clients reporting `protocol_version < MIN_PROTOCOL_VERSION` (or no
/// version at all, decoded as 0) are rejected at handshake time.
pub const MIN_PROTOCOL_VERSION: u32 = 1;
