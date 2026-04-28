//! `mlshtund` daemon entry point: arg parsing, manager bootstrap,
//! ACME resume, control-socket loop, graceful shutdown.

use anyhow::Result;
use clap::Parser;
use std::sync::Arc;
use tokio::sync::{watch, Mutex};

use crate::tund::{acme, control, tunnel_manager::TunnelManager};

#[derive(Parser)]
#[command(name = "mlshtund")]
#[command(about = "MLSH tunnel daemon — manages overlay network tunnels")]
#[command(version)]
struct Args {
    /// Custom Unix socket path
    #[arg(long)]
    socket: Option<String>,
}

pub async fn run() -> Result<()> {
    let args = Args::parse();
    let sock_path = control::socket_path(args.socket.as_deref());
    tracing::info!("mlshtund starting, socket: {}", sock_path.display());

    let manager = Arc::new(Mutex::new(TunnelManager::new()));
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // Resume ACME renewal watchers for every cert that has a sidecar
    // `{domain}.meta.json`. Without this, certs issued before the daemon
    // restart would silently expire.
    acme::resume_on_startup(manager.clone());

    tokio::spawn(async move {
        shutdown_signal().await;
        tracing::info!("Shutdown signal received");
        let _ = shutdown_tx.send(true);
    });

    let result = control::run(&sock_path, manager.clone(), shutdown_rx).await;
    manager.lock().await.shutdown_all().await;
    tracing::info!("mlshtund exiting");
    result
}

async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();

    #[cfg(unix)]
    {
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("Failed to register SIGTERM handler");
        tokio::select! {
            _ = ctrl_c => {}
            _ = sigterm.recv() => {}
        }
    }

    #[cfg(not(unix))]
    {
        ctrl_c.await.ok();
    }
}
