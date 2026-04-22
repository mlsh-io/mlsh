//! Active QUIC path migration (RFC 9000 §9): swap the endpoint's UDP socket
//! so every live connection migrates via PATH_CHALLENGE to a fresh 4-tuple
//! without closing/reconnecting.

/// Rebind the endpoint to a fresh ephemeral UDP socket. Returns the new
/// local port. On success, every client-role connection on this endpoint
/// starts PATH_CHALLENGE against the new source address.
pub fn try_migrate(endpoint: &quinn::Endpoint) -> anyhow::Result<u16> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0")?;
    let new_port = socket.local_addr()?.port();
    let open_conns = endpoint.open_connections();
    endpoint.rebind(socket)?;
    tracing::info!(
        "Path migration: rebound endpoint to 0.0.0.0:{new_port}, {open_conns} conn(s) migrating"
    );
    Ok(new_port)
}
