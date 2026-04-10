use anyhow::Result;
use clap::{Parser, Subcommand};
use mlsh_cli::commands;

#[derive(Parser)]
#[command(name = "mlsh")]
#[command(about = "MLSH CLI - Manage your MLSH infrastructure from the command line", long_about = None)]
#[command(version = env!("GIT_VERSION"))]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Bootstrap a cluster using the signal server's setup token
    Setup {
        /// Cluster name
        cluster: String,

        /// Signal host (e.g. signal.example.com)
        #[arg(long)]
        signal_host: String,

        /// Setup token from signal server (format: SECRET@FINGERPRINT)
        #[arg(long)]
        token: String,

        /// Node name (defaults to hostname)
        #[arg(long)]
        name: Option<String>,
    },

    /// Enroll this machine in a cluster using an invite URL
    Adopt {
        /// Invite URL (e.g. https://signal.example.com/invite?token=XXXX-XXXX)
        url: String,

        /// Node name (defaults to system username)
        #[arg(long)]
        name: Option<String>,
    },

    /// Connect to a cluster via QUIC overlay
    Connect {
        /// Peer name or "node.cluster" syntax (e.g. "homelab" or "nas.homelab")
        name: String,

        /// Run tunnel directly in foreground (bypass daemon)
        #[arg(long)]
        foreground: bool,
    },

    /// Disconnect from a cluster
    Disconnect {
        /// Peer name
        name: String,
    },

    /// Generate a signed invite URL for another machine to join this cluster
    Invite {
        /// Cluster name (must match a configured cluster)
        cluster: String,

        /// Invite TTL in seconds
        #[arg(long, default_value = "3600")]
        ttl: u64,

        /// Role for the invited node (admin or node)
        #[arg(long, default_value = "node")]
        role: String,
    },

    /// List all nodes in a cluster (online/offline status)
    Nodes {
        /// Cluster name
        cluster: String,
    },

    /// Remove a node from the cluster (admin only)
    Revoke {
        /// Cluster name
        cluster: String,
        /// Node ID to revoke
        node: String,
    },

    /// Export the node identity (private key) for backup
    #[command(name = "identity-export")]
    IdentityExport,

    /// Import a node identity from backup
    #[command(name = "identity-import")]
    IdentityImport {
        /// Path to the PEM file (reads from stdin if omitted)
        file: Option<String>,
    },

    /// Show tunnel status
    Status,

    /// Manage the overlay tunnel daemon
    #[command(subcommand)]
    Tunnel(commands::daemon::DaemonCommands),
}

fn main() {
    // Install aws-lc-rs crypto provider with post-quantum key exchange (X25519MLKEM768)
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("Failed to install crypto provider");

    // If invoked as "mlshtund" (via symlink), run the tunnel daemon directly.
    if is_tund_invocation() {
        return run_tund();
    }

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("Failed to build tokio runtime");

    let code = match rt.block_on(run_cli()) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("Error: {e}");
            1
        }
    };
    std::process::exit(code);
}

/// Check if we were invoked as "mlshtund" (argv[0] ends with "mlshtund" or "mlshtund.exe").
fn is_tund_invocation() -> bool {
    std::env::args()
        .next()
        .map(|arg0| {
            std::path::Path::new(&arg0)
                .file_stem()
                .and_then(|f| f.to_str())
                .is_some_and(|name| name == "mlshtund")
        })
        .unwrap_or(false)
}

fn run_tund() {
    use std::sync::Arc;
    use tokio::sync::{watch, Mutex};
    use tracing_subscriber::EnvFilter;

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("mlsh_cli=info")),
        )
        .init();

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("Failed to build tokio runtime");

    let code = match rt.block_on(async {
        use mlsh_cli::tund::{control, tunnel_manager::TunnelManager};

        #[derive(Parser)]
        #[command(name = "mlshtund")]
        #[command(about = "MLSH tunnel daemon — manages overlay network tunnels")]
        #[command(version)]
        struct Args {
            /// Custom Unix socket path
            #[arg(long)]
            socket: Option<String>,
        }

        let args = Args::parse();
        let sock_path = control::socket_path(args.socket.as_deref());
        tracing::info!("mlshtund starting, socket: {}", sock_path.display());

        let manager = Arc::new(Mutex::new(TunnelManager::new()));
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        tokio::spawn(async move {
            shutdown_signal().await;
            tracing::info!("Shutdown signal received");
            let _ = shutdown_tx.send(true);
        });

        let result = control::run(&sock_path, manager.clone(), shutdown_rx).await;
        manager.lock().await.shutdown_all().await;
        tracing::info!("mlshtund exiting");
        result
    }) {
        Ok(()) => 0,
        Err(e) => {
            tracing::error!("Fatal: {:#}", e);
            eprintln!("Error: {:#}", e);
            1
        }
    };
    std::process::exit(code);
}

async fn run_cli() -> Result<()> {
    env_logger::init();
    let cli = Cli::parse();

    match cli.command {
        Commands::Setup {
            cluster,
            signal_host,
            token,
            name,
        } => commands::setup::handle_setup(&cluster, &signal_host, &token, name.as_deref()).await,
        Commands::Adopt { url, name } => commands::adopt::handle_adopt(&url, name.as_deref()).await,
        Commands::Connect { name, foreground } => {
            commands::connect::handle_connect(&name, foreground).await
        }
        Commands::Disconnect { name } => commands::connect::handle_disconnect(&name).await,
        Commands::Invite { cluster, ttl, role } => {
            commands::invite::handle_invite(&cluster, ttl, &role).await
        }
        Commands::Nodes { cluster } => commands::nodes::handle_nodes(&cluster).await,
        Commands::Revoke { cluster, node } => {
            commands::revoke::handle_revoke(&cluster, &node).await
        }
        Commands::IdentityExport => commands::identity::handle_export().await,
        Commands::IdentityImport { file } => {
            commands::identity::handle_import(file.as_deref()).await
        }
        Commands::Status => commands::connect::handle_status().await,
        Commands::Tunnel(cmd) => commands::daemon::handle(cmd).await,
    }
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
