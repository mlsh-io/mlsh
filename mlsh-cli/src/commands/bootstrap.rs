//! Shared bootstrap path used by `mlsh setup` and `mlsh adopt`.
//!
//! Both commands run the same dance against signal — connect via QUIC with
//! the bootstrap fingerprint pinned, send `Adopt`, persist the cluster
//! TOML — they only differ in where the inputs come from (CLI flags vs an
//! invite URL) and in which roles the resulting node holds.

use anyhow::{Context, Result};
use base64::Engine;

use crate::quic::client::{connect_to_signal, resolve_addr};

pub struct BootstrapInput<'a> {
    pub cluster_name: &'a str,
    pub cluster_id: &'a str,
    pub signal_endpoint: &'a str,
    pub signal_fingerprint: &'a str,
    pub root_fingerprint: &'a str,
    pub node_id: &'a str,
    pub pre_auth_token: &'a str,
    /// Roles this node holds locally (written to the TOML).
    pub roles: &'a [&'a str],
}

pub struct BootstrapOutput {
    pub overlay_ip: String,
    pub overlay_subnet: String,
    /// Cluster UUID echoed by signal — adopt-time invites carry the id but
    /// signal is authoritative, so we round-trip it.
    pub cluster_id: String,
    pub identity_dir: std::path::PathBuf,
    pub fingerprint: String,
}

/// Run the QUIC adopt + TOML write. Caller is responsible for any pre/post
/// printing tailored to its command.
pub async fn run(input: BootstrapInput<'_>) -> Result<BootstrapOutput> {
    let config_dir = crate::config::config_dir()?;
    let identity_dir = config_dir.join("identity");
    let identity = mlsh_crypto::identity::load_or_generate(&identity_dir, input.node_id)
        .map_err(|e| anyhow::anyhow!("Failed to generate identity: {}", e))?;

    let public_key = mlsh_crypto::invite::extract_public_key_from_cert_pem(&identity.cert_pem)
        .map(|pk| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&pk))
        .unwrap_or_default();

    let addr = resolve_addr(input.signal_endpoint)?;
    let conn = connect_to_signal(
        addr,
        input.signal_endpoint,
        input.signal_fingerprint,
        &identity,
    )
    .await?;

    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .context("Failed to open signal stream")?;

    use mlsh_protocol::framing;
    use mlsh_protocol::messages::{ServerMessage, StreamMessage};

    let adopt_msg = StreamMessage::Adopt {
        cluster_id: input.cluster_id.to_string(),
        pre_auth_token: input.pre_auth_token.to_string(),
        fingerprint: identity.fingerprint.clone(),
        node_uuid: input.node_id.to_string(),
        display_name: input.node_id.to_string(),
        public_key,
        expires_at: 0,
        // Signal stripped admission_cert in ADR-030 (still in the wire
        // format for now, but ignored on the server).
        admission_cert: String::new(),
    };
    framing::write_msg(&mut send, &adopt_msg).await?;

    let resp: ServerMessage = framing::read_msg(&mut recv).await?;
    conn.close(quinn::VarInt::from_u32(0), b"done");

    let (overlay_ip, overlay_subnet, resp_cluster_id) = match resp {
        ServerMessage::AdoptOk {
            overlay_ip,
            overlay_subnet,
            cluster_id,
            ..
        } => (overlay_ip, overlay_subnet, cluster_id),
        ServerMessage::Error { code, message } => {
            anyhow::bail!("Adopt failed: {} ({})", message, code);
        }
        other => anyhow::bail!("Unexpected response: {:?}", other),
    };

    write_cluster_toml(
        input,
        &resp_cluster_id,
        &identity.fingerprint,
        &overlay_ip,
        &overlay_subnet,
    )?;

    Ok(BootstrapOutput {
        overlay_ip,
        overlay_subnet,
        cluster_id: resp_cluster_id,
        identity_dir,
        fingerprint: identity.fingerprint,
    })
}

fn write_cluster_toml(
    input: BootstrapInput<'_>,
    cluster_id: &str,
    fingerprint: &str,
    overlay_ip: &str,
    overlay_subnet: &str,
) -> Result<()> {
    let config_dir = crate::config::config_dir()?;
    let clusters_dir = config_dir.join("clusters");
    std::fs::create_dir_all(&clusters_dir)?;

    let roles_toml = input
        .roles
        .iter()
        .map(|r| format!("\"{}\"", r))
        .collect::<Vec<_>>()
        .join(", ");

    let cluster_toml = format!(
        "[cluster]\n\
         name = \"{cluster_name}\"\n\
         id = \"{cluster_id}\"\n\
         mode = \"mtls\"\n\
         signal_endpoint = \"{signal_endpoint}\"\n\
         signal_fingerprint = \"{signal_fingerprint}\"\n\
         root_fingerprint = \"{root_fingerprint}\"\n\
         \n\
         [node_auth]\n\
         node_id = \"{node_id}\"\n\
         fingerprint = \"{fingerprint}\"\n\
         roles = [{roles_toml}]\n\
         \n\
         [overlay]\n\
         ip = \"{overlay_ip}\"\n\
         subnet = \"{overlay_subnet}\"\n",
        cluster_name = input.cluster_name,
        signal_endpoint = input.signal_endpoint,
        signal_fingerprint = input.signal_fingerprint,
        root_fingerprint = input.root_fingerprint,
        node_id = input.node_id,
    );

    let cluster_file = clusters_dir.join(format!("{}.toml", input.cluster_name));
    std::fs::write(&cluster_file, &cluster_toml)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&cluster_file, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// Default node_id from CLI flag or hostname.
pub fn default_node_id(name_override: Option<&str>) -> String {
    name_override
        .map(String::from)
        .unwrap_or_else(|| whoami::hostname().unwrap_or_else(|_| "node".to_string()))
}

/// Append a port if the host string doesn't already carry one.
pub fn ensure_port(host: &str, default_port: u16) -> String {
    if host.contains(':') {
        host.to_string()
    } else {
        format!("{}:{}", host, default_port)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ensure_port_adds_default() {
        assert_eq!(
            ensure_port("signal.example.com", 4433),
            "signal.example.com:4433"
        );
        assert_eq!(
            ensure_port("signal.example.com:5555", 4433),
            "signal.example.com:5555"
        );
    }
}
