use std::sync::Arc;

use anyhow::Context;
use clap::{Parser, Subcommand};
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
            ClusterAction::Create { name, ttl } => cmd_create_cluster(&name, ttl).await,
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

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    // Start internal HTTP API if cloud integration is configured
    if let Some(ref api_token) = cfg.cloud_api_token {
        let http_bind: std::net::SocketAddr = cfg
            .http_bind
            .parse()
            .expect("Invalid http_bind address");
        let http_pool = pool.clone();
        let http_token = api_token.clone();
        let http_shutdown = shutdown_rx.clone();
        tokio::spawn(async move {
            if let Err(e) =
                mlsh_signal::http::run(http_bind, http_pool, http_token, http_shutdown).await
            {
                error!("Internal HTTP API failed: {}", e);
            }
        });
    }

    let cfg = Arc::new(cfg);

    let state = Arc::new(quic::listener::QuicState {
        db: pool,
        sessions,
        config: cfg,
        overlay_subnet,
    });

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

/// Create a cluster and generate a one-time setup code (CLI command).
async fn cmd_create_cluster(name: &str, ttl_minutes: u64) -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("mlsh_signal=warn".parse()?))
        .init();

    let cfg = config::Config::load()?;
    let pool = db::init(&cfg.db_path).await?;

    let result = mlsh_signal::cluster::create_cluster(&pool, name, ttl_minutes).await?;

    eprintln!("Cluster created:");
    eprintln!("  Name:  {}", name);
    eprintln!("  ID:    {}", result.cluster_id);
    eprintln!();
    eprintln!("  Setup token: {}", result.setup_token);
    eprintln!();
    eprintln!("  On a new machine:");
    eprintln!(
        "    mlsh setup {} --signal-host <host> --token {}",
        name, result.setup_token
    );

    Ok(())
}
