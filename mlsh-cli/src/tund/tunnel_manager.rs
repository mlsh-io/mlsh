//! Tunnel manager: owns and orchestrates all active overlay tunnels.

use std::collections::HashMap;

use anyhow::Result;

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

    /// Find the signal QUIC connection for a named cluster, if connected.
    pub fn signal_connection_for(&self, cluster: &str) -> Option<quinn::Connection> {
        self.tunnels.get(cluster).and_then(|t| t.signal_connection())
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
