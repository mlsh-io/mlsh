use anyhow::Result;
use clap::{Parser, Subcommand};
use mlsh_cli::commands;

#[derive(Parser)]
#[command(name = "mlsh")]
#[command(about = "Create and manage your mlsh mesh network", long_about = None)]
#[command(version = env!("GIT_VERSION"))]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Bootstrap a cluster (managed: mlsh.io, self-hosted: --signal-host + --token)
    Setup {
        /// Cluster name
        cluster: String,

        /// Signal host for self-hosted mode (e.g. signal.example.com)
        #[arg(long)]
        signal_host: Option<String>,

        /// Setup token for self-hosted mode (format: CODE@UUID@FINGERPRINT)
        #[arg(long)]
        token: Option<String>,

        /// Node name (defaults to hostname)
        #[arg(long)]
        name: Option<String>,
    },

    /// Enroll this machine in a cluster using an invite URL
    Adopt {
        /// Invite URL (e.g. mlsh://signal.example.com:4433/invite?token=XXXX-XXXX)
        url: String,

        /// Node name (defaults to hostname)
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

    /// Change a node's role (admin only)
    Promote {
        /// Cluster name
        cluster: String,
        /// Node ID to promote/demote
        node: String,
        /// New role (admin or node)
        #[arg(long)]
        role: String,
    },

    /// Remove a node from the cluster (admin only)
    Revoke {
        /// Cluster name
        cluster: String,
        /// Node ID to revoke
        node: String,
    },

    /// Rename a node in a cluster (admin only)
    Rename {
        /// Cluster name
        cluster: String,
        /// Current node display name
        node: String,
        /// New display name
        name: String,
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

    /// Expose a local service to the public internet over HTTPS
    Expose {
        /// Cluster name
        cluster: String,

        /// Upstream service URL (e.g. http://localhost:3000)
        target: String,

        /// Public domain (must be *.<cluster>.mlsh.io in this release,
        /// e.g. myapp.homelab.mlsh.io for the "homelab" cluster)
        #[arg(long)]
        domain: String,

        /// Contact email for the Let's Encrypt ACME account
        #[arg(long)]
        email: Option<String>,

        /// Use Let's Encrypt's staging directory (recommended for testing;
        /// production has hard rate limits)
        #[arg(long)]
        acme_staging: bool,
    },

    /// Remove a previously-exposed service
    Unexpose {
        /// Cluster name
        cluster: String,

        /// Domain to unexpose
        domain: String,
    },

    /// List services exposed in the cluster
    Exposed {
        /// Cluster name
        cluster: String,
    },

    /// Manage the overlay tunnel daemon
    #[command(subcommand)]
    Tunnel(commands::daemon::DaemonCommands),

    /// Manage the control-plane role on this node (ADR-030)
    #[command(subcommand)]
    Control(ControlCommands),
}

#[derive(Subcommand)]
enum ControlCommands {
    /// Start mlsh-control on this node and add the `control` role to its config.
    Promote {
        /// Cluster name
        cluster: String,
    },
    /// Stop mlsh-control on this node and remove the `control` role from its config.
    Demote {
        /// Cluster name
        cluster: String,
    },
    /// Demote this node and print the steps to promote a target node.
    /// Peer-to-peer transfer of the SQLite is a future enhancement; for now
    /// the operator copies the data dir manually and runs `mlsh control
    /// promote` on the target.
    Migrate {
        /// Cluster name
        cluster: String,
        /// Target node display name (informational; printed in instructions)
        node: String,
    },
}

fn main() {
    // Install aws-lc-rs crypto provider with post-quantum key exchange (X25519MLKEM768)
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("Failed to install crypto provider");

    // MLSH_RUN_AS=control wins over argv[0] so mlshtund can fork itself.
    #[cfg(feature = "control-plane")]
    if std::env::var("MLSH_RUN_AS").as_deref() == Ok("control") {
        return run_control();
    }

    if is_tund_invocation() {
        return run_tund();
    }

    #[cfg(feature = "control-plane")]
    if is_control_invocation() {
        return run_control();
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

fn argv0_stem() -> Option<String> {
    std::env::args().next().and_then(|arg0| {
        std::path::Path::new(&arg0)
            .file_stem()
            .and_then(|f| f.to_str())
            .map(|s| s.to_owned())
    })
}

/// Check if we were invoked as "mlshtund" (argv[0] ends with "mlshtund" or "mlshtund.exe").
fn is_tund_invocation() -> bool {
    argv0_stem().is_some_and(|name| name == "mlshtund")
}

#[cfg(feature = "control-plane")]
fn is_control_invocation() -> bool {
    argv0_stem().is_some_and(|name| name == "mlsh-control")
}

/// Boot a multi-threaded tokio runtime, run `f` to completion, and exit
/// with the appropriate code. Used by every daemon-mode entry point that
/// shouldn't return to the outer dispatch.
fn run_daemon<F, Fut>(f: F) -> !
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<()>>,
{
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

    let code = match rt.block_on(f()) {
        Ok(()) => 0,
        Err(e) => {
            tracing::error!("Fatal: {:#}", e);
            eprintln!("Error: {:#}", e);
            1
        }
    };
    std::process::exit(code);
}

#[cfg(feature = "control-plane")]
fn run_control() {
    run_daemon(mlsh_cli::control::run);
}

fn run_tund() {
    use std::sync::Arc;
    use tokio::sync::{watch, Mutex};

    run_daemon(|| async {
        use mlsh_cli::tund::{acme, control, tunnel_manager::TunnelManager};

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
    });
}

async fn run_cli() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Setup {
            cluster,
            signal_host,
            token,
            name,
        } => match (signal_host, token) {
            (Some(host), Some(tok)) => {
                commands::setup::handle_setup(&cluster, &host, &tok, name.as_deref()).await
            }
            (None, None) => commands::setup::handle_managed_setup(&cluster, name.as_deref()).await,
            _ => anyhow::bail!(
                "Provide both --signal-host and --token (self-hosted), or neither (managed mode)"
            ),
        },
        Commands::Adopt { url, name } => commands::adopt::handle_adopt(&url, name.as_deref()).await,
        Commands::Connect { name, foreground } => {
            commands::connect::handle_connect(&name, foreground).await
        }
        Commands::Disconnect { name } => commands::connect::handle_disconnect(&name).await,
        Commands::Invite { cluster, ttl, role } => {
            commands::invite::handle_invite(&cluster, ttl, &role).await
        }
        Commands::Nodes { cluster } => commands::nodes::handle_nodes(&cluster).await,
        Commands::Promote {
            cluster,
            node,
            role,
        } => commands::promote::handle_promote(&cluster, &node, &role).await,
        Commands::Revoke { cluster, node } => {
            commands::revoke::handle_revoke(&cluster, &node).await
        }
        Commands::Rename {
            cluster,
            node,
            name,
        } => commands::rename::handle_rename(&cluster, &node, &name).await,
        Commands::IdentityExport => commands::identity::handle_export().await,
        Commands::IdentityImport { file } => {
            commands::identity::handle_import(file.as_deref()).await
        }
        Commands::Status => commands::connect::handle_status().await,
        Commands::Expose {
            cluster,
            target,
            domain,
            email,
            acme_staging,
        } => {
            commands::expose::handle_expose(
                &cluster,
                &target,
                &domain,
                email.as_deref(),
                acme_staging,
            )
            .await
        }
        Commands::Unexpose { cluster, domain } => {
            commands::expose::handle_unexpose(&cluster, &domain).await
        }
        Commands::Exposed { cluster } => commands::expose::handle_list_exposed(&cluster).await,
        Commands::Tunnel(cmd) => commands::daemon::handle(cmd).await,
        Commands::Control(cmd) => match cmd {
            ControlCommands::Promote { cluster } => {
                commands::control::handle_promote(&cluster).await
            }
            ControlCommands::Demote { cluster } => commands::control::handle_demote(&cluster).await,
            ControlCommands::Migrate { cluster, node } => {
                commands::control::handle_migrate(&cluster, &node).await
            }
        },
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
