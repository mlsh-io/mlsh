//! `mlsh rename <cluster> <node> <name>` — change a node's display name (admin only).

use anyhow::{Context, Result};
use colored::Colorize;

use crate::tund::tunnel::load_cluster_config;

pub async fn handle_rename(cluster_name: &str, target_node: &str, new_name: &str) -> Result<()> {
    let base_dir = crate::config::config_dir()?;
    let config = load_cluster_config(cluster_name, &base_dir)?;

    println!(
        "Renaming node {} to {} in cluster {}...",
        target_node.bold(),
        new_name.bold(),
        config.name.bold()
    );

    let identity = mlsh_crypto::identity::load_or_generate(&config.identity_dir, &config.node_id)
        .map_err(|e| anyhow::anyhow!("Failed to load identity: {}", e))?;

    let addr = resolve_addr(&config.signal_endpoint)?;
    let conn = connect_to_signal(
        addr,
        &config.signal_endpoint,
        &config.signal_fingerprint,
        &identity,
    )
    .await?;

    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .context("Failed to open signal stream")?;

    use mlsh_protocol::framing;
    use mlsh_protocol::messages::{ServerMessage, StreamMessage};

    let msg = StreamMessage::Rename {
        cluster_id: config.cluster_id.clone(),
        target_name: target_node.to_string(),
        new_display_name: new_name.to_string(),
    };
    framing::write_msg(&mut send, &msg).await?;

    let resp: ServerMessage = framing::read_msg(&mut recv).await?;
    conn.close(quinn::VarInt::from_u32(0), b"done");

    match resp {
        ServerMessage::RenameOk { display_name } => {
            println!(
                "{}",
                format!("Node '{}' renamed to '{}'.", target_node, display_name)
                    .green()
                    .bold()
            );
            Ok(())
        }
        ServerMessage::Error { code, message } => {
            anyhow::bail!("{} ({})", message, code)
        }
        other => anyhow::bail!("Unexpected response: {:?}", other),
    }
}

// --- QUIC helpers

use std::net::SocketAddr;
use std::sync::Arc;

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
