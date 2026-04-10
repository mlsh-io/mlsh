//! `mlsh setup <cluster> --signal-host <host> --token <SECRET@FINGERPRINT>` — bootstrap a cluster.
//!
//! Uses the signal server's setup token (displayed at startup) to register
//! the first admin node via QUIC. The token contains both the cluster_secret
//! (for authentication) and the signal fingerprint (for QUIC cert verification).
//!
//! After setup, use `mlsh invite` to add more nodes.

use anyhow::{Context, Result};
use colored::Colorize;
use serde::Serialize;
use std::net::SocketAddr;
use std::sync::Arc;

const DEFAULT_SIGNAL_PORT: u16 = 4433;

/// Handle `mlsh setup <cluster> --signal-host <host> --token <token>`.
pub async fn handle_setup(
    cluster_name: &str,
    signal_host: &str,
    token: &str,
    name_override: Option<&str>,
) -> Result<()> {
    // Parse token: CODE@CLUSTER_ID@FINGERPRINT
    let (setup_code, cluster_id, signal_fingerprint) = parse_setup_token(token)?;

    println!("{}", "MLSH Cluster Setup".cyan().bold());
    println!("  Cluster: {}", cluster_name);
    println!("  Signal:  {}", signal_host);

    // Generate or load node identity
    let config_dir = crate::config::config_dir()?;
    let identity_dir = config_dir.join("identity");
    let node_id = name_override
        .map(String::from)
        .unwrap_or_else(|| whoami::hostname().unwrap_or_else(|_| "node".to_string()));
    let identity = mlsh_crypto::identity::load_or_generate(&identity_dir, &node_id)
        .map_err(|e| anyhow::anyhow!("Failed to generate identity: {}", e))?;

    println!("  Node:    {}", node_id);
    println!("  Fingerprint: {}...", &identity.fingerprint[..16]);

    use base64::Engine;
    let public_key = mlsh_crypto::invite::extract_public_key_from_cert_pem(&identity.cert_pem)
        .map(|pk| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&pk))
        .unwrap_or_default();

    // Connect to signal via QUIC (verified by fingerprint from token)
    let signal_endpoint = ensure_port(signal_host, DEFAULT_SIGNAL_PORT);
    println!(
        "{}",
        format!("Connecting to signal at {}...", signal_endpoint).cyan()
    );

    let addr = resolve_addr(&signal_endpoint)?;
    let conn = connect_to_signal(addr, &signal_endpoint, &signal_fingerprint, &identity).await?;

    // Send Adopt with setup code as pre_auth_token (registers as admin)
    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .context("Failed to open signal stream")?;

    // Generate self-signed admission cert for the root admin
    let admission_cert = mlsh_crypto::invite::generate_self_signed_admission_cert(
        &identity.key_pem,
        &node_id,
        &identity.fingerprint,
        &cluster_id,
    )
    .map_err(|e| anyhow::anyhow!("Failed to generate admission cert: {}", e))?;
    let admission_cert_json = serde_json::to_string(&admission_cert)?;

    let adopt_msg = serde_json::json!({
        "type": "adopt",
        "cluster_id": cluster_id,
        "pre_auth_token": setup_code,
        "fingerprint": identity.fingerprint,
        "node_id": node_id,
        "public_key": public_key,
        "admission_cert": admission_cert_json,
    });
    write_msg(&mut send, &adopt_msg).await?;

    let resp: serde_json::Value = read_msg(&mut recv).await?;
    conn.close(quinn::VarInt::from_u32(0), b"done");

    let msg_type = resp.get("type").and_then(|t| t.as_str()).unwrap_or("");
    if msg_type == "error" {
        let code = resp.get("code").and_then(|c| c.as_str()).unwrap_or("");
        let message = resp
            .get("message")
            .and_then(|m| m.as_str())
            .unwrap_or("unknown");
        anyhow::bail!("Setup failed: {} ({})", message, code);
    }

    if msg_type != "adopt_ok" {
        anyhow::bail!("Unexpected response: {}", msg_type);
    }

    let overlay_ip = resp["overlay_ip"].as_str().context("Missing overlay_ip")?;
    let overlay_subnet = resp["overlay_subnet"].as_str().unwrap_or("100.64.0.0/10");

    // Save cluster config
    let clusters_dir = config_dir.join("clusters");
    std::fs::create_dir_all(&clusters_dir)?;

    let cluster_toml = format!(
        "[cluster]\n\
         name = \"{cluster_name}\"\n\
         id = \"{cluster_id}\"\n\
         mode = \"mtls\"\n\
         signal_endpoint = \"{signal_endpoint}\"\n\
         signal_fingerprint = \"{signal_fingerprint}\"\n\
         root_fingerprint = \"{fp}\"\n\
         \n\
         [node_auth]\n\
         node_id = \"{node_id}\"\n\
         fingerprint = \"{fp}\"\n\
         \n\
         [overlay]\n\
         ip = \"{overlay_ip}\"\n\
         subnet = \"{overlay_subnet}\"\n",
        fp = identity.fingerprint,
    );

    let cluster_file = clusters_dir.join(format!("{}.toml", cluster_name));
    std::fs::write(&cluster_file, &cluster_toml)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&cluster_file, std::fs::Permissions::from_mode(0o600))?;
    }

    println!();
    println!("{}", "Setup completed!".green().bold());
    println!("  Cluster:    {}", cluster_name);
    println!("  Node:       {} (admin)", node_id);
    println!("  Overlay IP: {}", overlay_ip);
    println!();
    println!("{}", "Next steps:".cyan().bold());
    println!(
        "  1. Connect: {}",
        format!("mlsh connect {}", cluster_name).bold()
    );
    println!(
        "  2. Invite:  {}",
        format!("mlsh invite {} --ttl 3600", cluster_name).bold()
    );

    Ok(())
}

// --- Token parsing

/// Parse a setup token: `CODE@CLUSTER_ID@FINGERPRINT`.
fn parse_setup_token(token: &str) -> Result<(String, String, String)> {
    let parts: Vec<&str> = token.splitn(3, '@').collect();
    match parts.as_slice() {
        [code, cluster_id, fingerprint]
            if !code.is_empty() && !cluster_id.is_empty() && !fingerprint.is_empty() =>
        {
            Ok((
                code.to_string(),
                cluster_id.to_string(),
                fingerprint.to_string(),
            ))
        }
        _ => anyhow::bail!("Invalid setup token format. Expected: CODE@CLUSTER_ID@FINGERPRINT"),
    }
}

/// Ensure the endpoint has a port suffix.
fn ensure_port(host: &str, default_port: u16) -> String {
    if host.contains(':') {
        host.to_string()
    } else {
        format!("{}:{}", host, default_port)
    }
}

// --- QUIC helpers

async fn connect_to_signal(
    addr: SocketAddr,
    endpoint_str: &str,
    signal_fingerprint: &str,
    identity: &mlsh_crypto::identity::NodeIdentity,
) -> Result<quinn::Connection> {
    let cert_der = mlsh_crypto::identity::pem_to_der_pub(&identity.cert_pem)
        .map_err(|e| anyhow::anyhow!("Invalid cert PEM: {}", e))?;
    let cert = rustls::pki_types::CertificateDer::from(cert_der);
    let key = rustls_pemfile::private_key(&mut identity.key_pem.as_bytes())
        .context("Failed to parse identity key")?
        .context("No private key in PEM")?;

    let mut tls_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(
            crate::quic::verifier::FingerprintVerifier::new(signal_fingerprint),
        ))
        .with_client_auth_cert(vec![cert], key)
        .context("Failed to set client auth cert")?;
    tls_config.alpn_protocols = vec![b"mlsh-signal".to_vec()];

    let client_config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)
            .context("Failed to create QUIC TLS config")?,
    ));

    let bind_addr: SocketAddr = if addr.is_ipv6() {
        "[::]:0".parse().unwrap()
    } else {
        "0.0.0.0:0".parse().unwrap()
    };
    let mut endpoint = quinn::Endpoint::client(bind_addr)?;
    endpoint.set_default_client_config(client_config);

    let sni_host = endpoint_str.split(':').next().unwrap_or(endpoint_str);

    let conn = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        endpoint.connect(addr, sni_host)?,
    )
    .await
    .map_err(|_| anyhow::anyhow!("Timed out connecting to signal"))?
    .context("Failed to connect to signal")?;

    Ok(conn)
}

fn resolve_addr(endpoint: &str) -> Result<SocketAddr> {
    if let Ok(addr) = endpoint.parse::<SocketAddr>() {
        return Ok(addr);
    }
    let (host, port) = endpoint.rsplit_once(':').unwrap_or((endpoint, "4433"));
    let port: u16 = port.parse().unwrap_or(4433);
    use std::net::ToSocketAddrs;
    (host, port)
        .to_socket_addrs()?
        .find(|a| a.is_ipv4())
        .or_else(|| {
            (host, port)
                .to_socket_addrs()
                .ok()
                .and_then(|mut a| a.next())
        })
        .context(format!("Failed to resolve: {}", endpoint))
}

async fn write_msg<T: Serialize>(send: &mut quinn::SendStream, msg: &T) -> Result<()> {
    let json = serde_json::to_vec(msg)?;
    let len = (json.len() as u32).to_be_bytes();
    send.write_all(&len).await?;
    send.write_all(&json).await?;
    Ok(())
}

async fn read_msg<T: serde::de::DeserializeOwned>(recv: &mut quinn::RecvStream) -> Result<T> {
    let mut len_buf = [0u8; 4];
    recv.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > 1_048_576 {
        anyhow::bail!("Message too large: {} bytes", len);
    }
    let mut buf = vec![0u8; len];
    recv.read_exact(&mut buf).await?;
    Ok(serde_json::from_slice(&buf)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_token_valid() {
        let (code, cid, fp) =
            parse_setup_token("ABCD-EFGH-IJKL@550e8400-e29b@deadbeef1234").unwrap();
        assert_eq!(code, "ABCD-EFGH-IJKL");
        assert_eq!(cid, "550e8400-e29b");
        assert_eq!(fp, "deadbeef1234");
    }

    #[test]
    fn parse_token_missing_parts() {
        assert!(parse_setup_token("ABCDEFGH").is_err());
        assert!(parse_setup_token("code@cluster").is_err());
    }

    #[test]
    fn parse_token_empty_parts() {
        assert!(parse_setup_token("@@fingerprint").is_err());
        assert!(parse_setup_token("code@@fp").is_err());
    }
}
