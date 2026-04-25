//! Tunnel manager: owns and orchestrates all active overlay tunnels.

use std::collections::HashMap;

use anyhow::{Context, Result};

use super::protocol::{DaemonResponse, TunnelState};
use super::tunnel::{ClusterConfig, ManagedTunnel};

/// Tunnel manager: owns all active tunnels.
#[derive(Default)]
pub struct TunnelManager {
    tunnels: HashMap<String, ManagedTunnel>,
}

impl TunnelManager {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn connect(&mut self, config: ClusterConfig) -> Result<DaemonResponse> {
        let cluster = &config.name;

        // If there's an existing tunnel that's still active or retrying, return its status instead of restarting
        if let Some(existing) = self.tunnels.get(cluster.as_str()) {
            let state = existing.state();
            if matches!(
                state,
                TunnelState::Connected | TunnelState::Connecting | TunnelState::Reconnecting
            ) {
                return Ok(DaemonResponse::Ok {
                    message: Some(format!(
                        "Tunnel '{}' is {} (daemon is retrying automatically)",
                        cluster, state
                    )),
                });
            }
        }

        // Stop and remove any stale tunnel to ensure the TUN device is released
        let cluster_name = config.name.clone();
        if let Some(mut old) = self.tunnels.remove(&cluster_name) {
            tracing::info!("Stopping stale tunnel '{}' before reconnect", cluster_name);
            old.stop().await;
        }

        let tunnel = ManagedTunnel::start(config)?;
        let message = format!("Tunnel '{}' connecting...", cluster_name);
        self.tunnels.insert(cluster_name, tunnel);

        Ok(DaemonResponse::Ok {
            message: Some(message),
        })
    }

    pub async fn disconnect(&mut self, cluster: &str) -> DaemonResponse {
        match self.tunnels.remove(cluster) {
            Some(mut tunnel) => {
                tunnel.stop().await;
                DaemonResponse::Ok {
                    message: Some(format!("Tunnel '{}' disconnected", cluster)),
                }
            }
            None => DaemonResponse::Error {
                code: "not_found".into(),
                message: format!("No tunnel for '{}'", cluster),
            },
        }
    }

    pub fn status(&self) -> DaemonResponse {
        let tunnels = self.tunnels.values().map(|t| t.status()).collect();
        DaemonResponse::Status { tunnels }
    }

    /// Return the signal QUIC connection for a named cluster, if connected.
    /// Used by ACME to publish HTTP-01 challenges via signal.
    pub fn signal_connection_for(&self, cluster: &str) -> Option<quinn::Connection> {
        self.tunnels
            .get(cluster)
            .and_then(|t| t.signal_connection())
    }

    /// Look up the cluster UUID for a named cluster.
    fn cluster_id_for(&self, cluster: &str) -> Result<String> {
        self.tunnels
            .get(cluster)
            .map(|t| t.cluster_id.clone())
            .with_context(|| format!("No active tunnel for cluster '{}'", cluster))
    }

    /// Send a one-shot `StreamMessage` over the persistent QUIC connection
    /// for the given cluster and read back a single `ServerMessage`.
    /// Push messages (PeerJoined etc.) are skipped.
    async fn forward_one_shot(
        &self,
        cluster: &str,
        msg: mlsh_protocol::messages::StreamMessage,
    ) -> Result<mlsh_protocol::messages::ServerMessage> {
        use mlsh_protocol::framing;
        use mlsh_protocol::messages::ServerMessage;

        let conn = self
            .signal_connection_for(cluster)
            .with_context(|| format!("No active signal connection for cluster '{}'", cluster))?;
        let (mut send, mut recv) = conn
            .open_bi()
            .await
            .context("Failed to open stream to signal")?;
        framing::write_msg(&mut send, &msg).await?;

        loop {
            let resp: ServerMessage = framing::read_msg(&mut recv).await?;
            // Filter out asynchronous push messages so callers always get a
            // direct reply.
            match resp {
                ServerMessage::PeerJoined { .. }
                | ServerMessage::PeerLeft { .. }
                | ServerMessage::PeerRenamed { .. }
                | ServerMessage::PeerUpdated { .. }
                | ServerMessage::Pong => continue,
                other => return Ok(other),
            }
        }
    }

    /// Forward a `ListNodes` request to signal via the persistent QUIC
    /// connection. Used by `mlsh-control` (and future admin clients) to
    /// query the cluster roster without opening their own QUIC connection.
    pub async fn list_nodes(&self, cluster: &str) -> Result<Vec<mlsh_protocol::types::NodeInfo>> {
        use mlsh_protocol::messages::{ServerMessage, StreamMessage};
        match self
            .forward_one_shot(cluster, StreamMessage::ListNodes)
            .await?
        {
            ServerMessage::NodeList { nodes } => Ok(nodes),
            ServerMessage::Error { code, message } => {
                anyhow::bail!("signal error ({}): {}", code, message);
            }
            other => anyhow::bail!("Unexpected signal response: {:?}", other),
        }
    }

    /// Forward a `Revoke` request to signal.
    pub async fn revoke(&self, cluster: &str, target: &str) -> Result<()> {
        use mlsh_protocol::messages::{ServerMessage, StreamMessage};
        let cluster_id = self.cluster_id_for(cluster)?;
        let msg = StreamMessage::Revoke {
            cluster_id,
            target_name: target.to_string(),
        };
        match self.forward_one_shot(cluster, msg).await? {
            ServerMessage::RevokeOk => Ok(()),
            ServerMessage::Error { code, message } => {
                anyhow::bail!("signal error ({}): {}", code, message);
            }
            other => anyhow::bail!("Unexpected signal response: {:?}", other),
        }
    }

    /// Forward a `Rename` request to signal.
    pub async fn rename(
        &self,
        cluster: &str,
        target: &str,
        new_display_name: &str,
    ) -> Result<String> {
        use mlsh_protocol::messages::{ServerMessage, StreamMessage};
        let cluster_id = self.cluster_id_for(cluster)?;
        let msg = StreamMessage::Rename {
            cluster_id,
            target_name: target.to_string(),
            new_display_name: new_display_name.to_string(),
        };
        match self.forward_one_shot(cluster, msg).await? {
            ServerMessage::RenameOk { display_name } => Ok(display_name),
            ServerMessage::Error { code, message } => {
                anyhow::bail!("signal error ({}): {}", code, message);
            }
            other => anyhow::bail!("Unexpected signal response: {:?}", other),
        }
    }

    /// Forward a `Promote` request to signal.
    pub async fn promote(&self, cluster: &str, target_node_id: &str, new_role: &str) -> Result<()> {
        use mlsh_protocol::messages::{ServerMessage, StreamMessage};
        let cluster_id = self.cluster_id_for(cluster)?;
        let msg = StreamMessage::Promote {
            cluster_id,
            target_node_id: target_node_id.to_string(),
            new_role: new_role.to_string(),
            // admission_cert is no longer stored signal-side (ADR-030 strip);
            // empty here, signal accepts and broadcasts an empty cert.
            admission_cert: String::new(),
        };
        match self.forward_one_shot(cluster, msg).await? {
            ServerMessage::PromoteOk => Ok(()),
            ServerMessage::Error { code, message } => {
                anyhow::bail!("signal error ({}): {}", code, message);
            }
            other => anyhow::bail!("Unexpected signal response: {:?}", other),
        }
    }

    /// Forward an `ExposeService` to signal.
    /// Returned tuple is `(domain, public_mode, public_ip)`.
    pub async fn expose(
        &self,
        cluster: &str,
        domain: &str,
        target: &str,
    ) -> Result<(String, String, Option<String>)> {
        use mlsh_protocol::messages::{ServerMessage, StreamMessage};
        use mlsh_protocol::types::IngressMode;
        let cluster_id = self.cluster_id_for(cluster)?;
        let msg = StreamMessage::ExposeService {
            cluster_id,
            domain: domain.to_string(),
            target: target.to_string(),
            mode: IngressMode::Http,
        };
        match self.forward_one_shot(cluster, msg).await? {
            ServerMessage::ExposeOk {
                domain,
                public_mode,
                public_ip,
            } => Ok((domain, public_mode, public_ip)),
            ServerMessage::Error { code, message } => {
                anyhow::bail!("signal error ({}): {}", code, message);
            }
            other => anyhow::bail!("Unexpected signal response: {:?}", other),
        }
    }

    /// Forward an `UnexposeService` to signal.
    pub async fn unexpose(&self, cluster: &str, domain: &str) -> Result<()> {
        use mlsh_protocol::messages::{ServerMessage, StreamMessage};
        let cluster_id = self.cluster_id_for(cluster)?;
        let msg = StreamMessage::UnexposeService {
            cluster_id,
            domain: domain.to_string(),
        };
        match self.forward_one_shot(cluster, msg).await? {
            ServerMessage::UnexposeOk => Ok(()),
            ServerMessage::Error { code, message } => {
                anyhow::bail!("signal error ({}): {}", code, message);
            }
            other => anyhow::bail!("Unexpected signal response: {:?}", other),
        }
    }

    /// Forward a `ListExposed` request to signal.
    pub async fn list_exposed(
        &self,
        cluster: &str,
    ) -> Result<Vec<mlsh_protocol::types::IngressRoute>> {
        use mlsh_protocol::messages::{ServerMessage, StreamMessage};
        let cluster_id = self.cluster_id_for(cluster)?;
        let msg = StreamMessage::ListExposed { cluster_id };
        match self.forward_one_shot(cluster, msg).await? {
            ServerMessage::ExposedList { routes } => Ok(routes),
            ServerMessage::Error { code, message } => {
                anyhow::bail!("signal error ({}): {}", code, message);
            }
            other => anyhow::bail!("Unexpected signal response: {:?}", other),
        }
    }

    /// Start `mlsh-control` for the named cluster. Returns an error if there
    /// is no active tunnel for that cluster (the daemon must be connected to
    /// signal first — control plane runs alongside, not standalone).
    pub fn start_control(&mut self, cluster: &str) -> DaemonResponse {
        match self.tunnels.get_mut(cluster) {
            Some(t) => {
                let was_running = t.has_control_child();
                t.start_control();
                let msg = if was_running {
                    "mlsh-control already running".into()
                } else {
                    "mlsh-control started".into()
                };
                DaemonResponse::Ok { message: Some(msg) }
            }
            None => DaemonResponse::Error {
                code: "not_connected".into(),
                message: format!(
                    "No active tunnel for '{}' — run `mlsh connect` first",
                    cluster
                ),
            },
        }
    }

    /// Stop `mlsh-control` for the named cluster. No-op if not running or
    /// no such cluster.
    pub async fn stop_control(&mut self, cluster: &str) -> DaemonResponse {
        match self.tunnels.get_mut(cluster) {
            Some(t) => {
                let was_running = t.has_control_child();
                t.stop_control().await;
                let msg = if was_running {
                    "mlsh-control stopped".into()
                } else {
                    "mlsh-control was not running".into()
                };
                DaemonResponse::Ok { message: Some(msg) }
            }
            None => DaemonResponse::Ok {
                message: Some(format!("No active tunnel for '{}'", cluster)),
            },
        }
    }

    pub async fn shutdown_all(&mut self) {
        let names: Vec<String> = self.tunnels.keys().cloned().collect();
        for name in names {
            if let Some(mut tunnel) = self.tunnels.remove(&name) {
                tracing::info!("Shutting down tunnel '{}'", name);
                tunnel.stop().await;
            }
        }
    }
}
