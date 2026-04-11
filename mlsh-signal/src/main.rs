use std::sync::Arc;

use anyhow::Context;
use clap::{Parser, Subcommand};
use sha2::{Digest, Sha256};
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

use mlsh_signal::{config, db, quic, sessions::SessionStore};

#[derive(Parser)]
#[command(name = "mlsh-signal", version = env!("GIT_VERSION"))]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the signal server (default if no subcommand).
    Serve,
    /// Cluster management.
    Cluster {
        #[command(subcommand)]
        action: ClusterAction,
    },
}

#[derive(Subcommand)]
enum ClusterAction {
    /// Create a new cluster and generate a one-time setup code.
    Create {
        /// Cluster name (human-readable, unique).
        name: String,
        /// Setup code TTL in minutes.
        #[arg(long, default_value = "15")]
        ttl: u64,
    },
}

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

    let cli = Cli::parse();

    match cli.command.unwrap_or(Commands::Serve) {
        Commands::Serve => run_server().await,
        Commands::Cluster { action } => match action {
            ClusterAction::Create { name, ttl } => create_cluster(&name, ttl).await,
        },
    }
}

/// Start the QUIC signal server.
async fn run_server() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("mlsh_signal=info".parse()?))
        .init();

    let cfg = config::Config::load()?;
    info!("mlsh-signal {} starting", env!("GIT_VERSION"));
    info!(db = cfg.db_path, "Database path");

    let pool = db::init(&cfg.db_path).await?;

    // Start QUIC server — cert is persisted in DB
    let quic_bind: std::net::SocketAddr = cfg.quic.bind.parse().expect("Invalid QUIC bind address");
    let (quic_server_config, signal_fingerprint) = quic::tls::build_server_config(&cfg.quic, &pool)
        .await
        .expect("Failed to build QUIC TLS config");

    // Store fingerprint in DB
    db::set_config(&pool, "signal_fingerprint", &signal_fingerprint)
        .await
        .ok();

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

/// Create a cluster and generate a one-time setup code.
async fn create_cluster(name: &str, ttl_minutes: u64) -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("mlsh_signal=warn".parse()?))
        .init();

    let cfg = config::Config::load()?;
    let pool = db::init(&cfg.db_path).await?;

    // Create the cluster
    let cluster_id = db::create_cluster(&pool, name).await?;

    // Generate a human-readable setup code
    let code = generate_human_code(12);
    let code_formatted = format!("{}-{}-{}", &code[..4], &code[4..8], &code[8..12]);

    // Store SHA-256 hash (not the code itself)
    let code_hash = format!("{:x}", Sha256::digest(code_formatted.as_bytes()));
    let expires_at = (time::OffsetDateTime::now_utc()
        + time::Duration::minutes(ttl_minutes as i64))
    .format(&time::format_description::well_known::Rfc3339)
    .unwrap();

    db::store_setup_code(&pool, &cluster_id, &code_hash, &expires_at).await?;

    // Load signal fingerprint for the full token
    let signal_fingerprint = db::get_config(&pool, "signal_fingerprint")
        .await?
        .unwrap_or_else(|| "<unknown — start the server first>".to_string());

    let setup_token = format!("{}@{}@{}", code_formatted, cluster_id, signal_fingerprint);

    eprintln!("Cluster created:");
    eprintln!("  Name:  {}", name);
    eprintln!("  ID:    {}", cluster_id);
    eprintln!(
        "  Code:  {} (valid {} min, single use)",
        code_formatted, ttl_minutes
    );
    eprintln!();
    eprintln!("  Setup token: {}", setup_token);
    eprintln!();
    eprintln!("  On a new machine:");
    eprintln!(
        "    mlsh setup {} --signal-host <host> --token {}",
        name, setup_token
    );

    Ok(())
}

/// Generate a human-readable code of the given length.
///
/// Uses charset `0123456789ABCDEFGHJKLMNPQRSTUVWXYZ` (34 chars, no I/O to avoid
/// confusion with 1/0). 12 chars ~ 61 bits of entropy.
fn generate_human_code(len: usize) -> String {
    const CHARSET: &[u8] = b"0123456789ABCDEFGHJKLMNPQRSTUVWXYZ";
    let mut raw = vec![0u8; len];
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut raw)
        .expect("Failed to generate random bytes");
    raw.iter()
        .map(|b| CHARSET[(*b as usize) % CHARSET.len()] as char)
        .collect()
}
