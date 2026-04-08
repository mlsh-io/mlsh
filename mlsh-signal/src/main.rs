use std::sync::Arc;

use anyhow::Context;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

use mlsh_signal::{config, db, quic, sessions::SessionStore};

/// Wait for either SIGTERM or SIGINT (Ctrl+C).
async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();

    #[cfg(unix)]
    {
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("Failed to install SIGTERM handler");
        tokio::select! {
            _ = ctrl_c => info!("Received SIGINT"),
            _ = sigterm.recv() => info!("Received SIGTERM"),
        }
    }

    #[cfg(not(unix))]
    {
        ctrl_c.await.ok();
        info!("Received SIGINT");
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Install aws-lc-rs crypto provider with post-quantum key exchange (X25519MLKEM768)
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("Failed to install crypto provider");

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("mlsh_signal=info".parse()?))
        .init();

    let mut cfg = config::Config::load()?;
    info!("mlsh-signal {} starting", env!("GIT_VERSION"));
    info!(db = cfg.db_path, "Database path");

    let pool = db::init(&cfg.db_path).await?;

    // Load secrets from DB, auto-generate on first startup, persist.
    load_or_generate_secret(&pool, &mut cfg.cluster_secret, "cluster_secret", || {
        let code = generate_human_code(12);
        format!("{}-{}-{}", &code[..4], &code[4..8], &code[8..12])
    })
    .await;
    load_or_generate_secret(&pool, &mut cfg.signing_key, "signing_key", || {
        use base64::Engine;
        let mut raw = [0u8; 32];
        ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut raw)
            .expect("Failed to generate random signing key");
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw)
    })
    .await;

    // Start QUIC server — cert is persisted in DB
    let quic_bind: std::net::SocketAddr = cfg.quic.bind.parse().expect("Invalid QUIC bind address");
    let (quic_server_config, signal_fingerprint) = quic::tls::build_server_config(&cfg.quic, &pool)
        .await
        .expect("Failed to build QUIC TLS config");

    // Store fingerprint in DB
    db::set_config(&pool, "signal_fingerprint", &signal_fingerprint)
        .await
        .ok();

    // Display setup token: SECRET@FINGERPRINT
    if let Some(ref secret) = cfg.cluster_secret {
        let setup_token = format!("{}@{}", secret, signal_fingerprint);
        info!("========================================");
        info!("  Setup token: {}", setup_token);
        info!("========================================");
        info!("  Run on a new machine:");
        info!(
            "    mlsh setup <cluster> --signal-host <host> --token {}",
            setup_token
        );
    }

    let overlay_subnet = db::OverlaySubnet::parse(&cfg.overlay_subnet)
        .context("Invalid overlay_subnet in config")?;
    info!("Overlay subnet: {}", overlay_subnet.cidr);

    let sessions = SessionStore::new();
    let cfg = Arc::new(cfg);

    let state = Arc::new(quic::listener::QuicState {
        db: pool,
        sessions,
        config: cfg,
        overlay_subnet,
    });

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    tokio::spawn(async move {
        shutdown_signal().await;
        let _ = shutdown_tx.send(true);
    });

    info!(bind = %quic_bind, "QUIC server starting");

    if let Err(e) = quic::listener::run(quic_bind, quic_server_config, state, shutdown_rx).await {
        error!("QUIC server failed: {}", e);
    }

    Ok(())
}

/// Load a secret from DB if not in config, or generate and persist it.
async fn load_or_generate_secret(
    pool: &sqlx::SqlitePool,
    field: &mut Option<String>,
    key: &str,
    generate: impl FnOnce() -> String,
) {
    if field.is_some() {
        return;
    }
    if let Ok(Some(s)) = db::get_config(pool, key).await {
        info!("Loaded {} from database", key);
        *field = Some(s);
        return;
    }
    let value = generate();
    info!("Generated {} (persisted in DB)", key);
    db::set_config(pool, key, &value).await.ok();
    *field = Some(value);
}

/// Generate a human-readable code of the given length.
///
/// Uses charset `0123456789ABCDEFGHJKLMNPQRSTUVWXYZ` (34 chars, no I/O to avoid
/// confusion with 1/0). 12 chars ≈ 61 bits of entropy.
fn generate_human_code(len: usize) -> String {
    const CHARSET: &[u8] = b"0123456789ABCDEFGHJKLMNPQRSTUVWXYZ";
    let mut raw = vec![0u8; len];
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut raw)
        .expect("Failed to generate random bytes");
    raw.iter()
        .map(|b| CHARSET[(*b as usize) % CHARSET.len()] as char)
        .collect()
}
