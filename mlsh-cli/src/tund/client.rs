//! Daemon client for CLI and future GUI.
//!
//! Connects to the `mlshtund` control endpoint (Unix socket on Unix,
//! named pipe on Windows) and exchanges JSON requests/responses.

use std::path::{Path, PathBuf};

use anyhow::Result;

use super::protocol::{read_message, write_message, DaemonRequest, DaemonResponse};
use super::transport::{ActiveTransport, Transport};

/// Client for communicating with the `mlshtund` daemon.
pub struct DaemonClient {
    stream: <ActiveTransport as Transport>::Stream,
}

impl DaemonClient {
    /// Connect to the daemon at the given endpoint.
    pub async fn connect(path: &Path) -> Result<Self> {
        let stream = ActiveTransport::connect(path).await?;
        Ok(Self { stream })
    }

    /// Connect to the daemon, auto-discovering the endpoint.
    pub async fn connect_default() -> Result<Self> {
        let path = discover_socket()?;
        Self::connect(&path).await
    }

    /// Send a request and receive the response.
    pub async fn request(&mut self, req: &DaemonRequest) -> Result<DaemonResponse> {
        let (mut reader, mut writer) = tokio::io::split(&mut self.stream);
        write_message(&mut writer, req).await?;
        let resp: DaemonResponse = read_message(&mut reader).await?;
        Ok(resp)
    }

    pub async fn connect_cluster(
        &mut self,
        cluster: &str,
        config_toml: &str,
        cert_pem: &str,
        key_pem: &str,
    ) -> Result<DaemonResponse> {
        self.request(&DaemonRequest::Connect {
            cluster: cluster.to_string(),
            config_toml: config_toml.to_string(),
            cert_pem: cert_pem.to_string(),
            key_pem: key_pem.to_string(),
        })
        .await
    }

    pub async fn disconnect_cluster(&mut self, cluster: &str) -> Result<DaemonResponse> {
        self.request(&DaemonRequest::Disconnect {
            cluster: cluster.to_string(),
        })
        .await
    }

    pub async fn status(&mut self) -> Result<DaemonResponse> {
        self.request(&DaemonRequest::Status).await
    }

    pub async fn list_nodes(&mut self, cluster: &str) -> Result<DaemonResponse> {
        self.request(&DaemonRequest::ListNodes {
            cluster: cluster.to_string(),
        })
        .await
    }

    pub async fn control_start(&mut self, cluster: &str) -> Result<DaemonResponse> {
        self.request(&DaemonRequest::ControlStart {
            cluster: cluster.to_string(),
        })
        .await
    }

    pub async fn control_stop(&mut self, cluster: &str) -> Result<DaemonResponse> {
        self.request(&DaemonRequest::ControlStop {
            cluster: cluster.to_string(),
        })
        .await
    }

    pub async fn revoke(&mut self, cluster: &str, target: &str) -> Result<DaemonResponse> {
        self.request(&DaemonRequest::Revoke {
            cluster: cluster.to_string(),
            target: target.to_string(),
        })
        .await
    }

    pub async fn rename(
        &mut self,
        cluster: &str,
        target: &str,
        new_display_name: &str,
    ) -> Result<DaemonResponse> {
        self.request(&DaemonRequest::Rename {
            cluster: cluster.to_string(),
            target: target.to_string(),
            new_display_name: new_display_name.to_string(),
        })
        .await
    }

    pub async fn promote(
        &mut self,
        cluster: &str,
        target_node_id: &str,
        new_role: &str,
    ) -> Result<DaemonResponse> {
        self.request(&DaemonRequest::Promote {
            cluster: cluster.to_string(),
            target_node_id: target_node_id.to_string(),
            new_role: new_role.to_string(),
        })
        .await
    }

    pub async fn expose(
        &mut self,
        cluster: &str,
        domain: &str,
        target: &str,
        email: Option<&str>,
        acme_staging: bool,
    ) -> Result<DaemonResponse> {
        self.request(&DaemonRequest::Expose {
            cluster: cluster.to_string(),
            domain: domain.to_string(),
            target: target.to_string(),
            email: email.map(|s| s.to_string()),
            acme_staging,
        })
        .await
    }

    pub async fn unexpose(&mut self, cluster: &str, domain: &str) -> Result<DaemonResponse> {
        self.request(&DaemonRequest::Unexpose {
            cluster: cluster.to_string(),
            domain: domain.to_string(),
        })
        .await
    }

    pub async fn list_exposed(&mut self, cluster: &str) -> Result<DaemonResponse> {
        self.request(&DaemonRequest::ListExposed {
            cluster: cluster.to_string(),
        })
        .await
    }

    pub async fn open_admin_tunnel(
        &mut self,
        cluster: &str,
        target: &str,
    ) -> Result<DaemonResponse> {
        self.request(&DaemonRequest::OpenAdminTunnel {
            cluster: cluster.to_string(),
            target: target.to_string(),
        })
        .await
    }
}

/// Discover the daemon endpoint.
///
/// On Unix: checks the system socket, then the user socket.
/// On Windows: named pipes aren't filesystem entries, so we return the most
/// likely candidate and let the `connect` call surface a clear error if
/// nothing is listening.
pub fn discover_socket() -> Result<PathBuf> {
    #[cfg(unix)]
    {
        let system = PathBuf::from("/var/run/mlshtund.sock");
        if system.exists() {
            return Ok(system);
        }

        let user = dirs::config_dir()
            .ok_or_else(|| anyhow::anyhow!("Failed to determine config directory"))?
            .join("mlsh")
            .join("mlshtund.sock");
        if user.exists() {
            return Ok(user);
        }

        anyhow::bail!(
            "mlshtund is not running.\n  \
             Start it with: sudo mlshtund\n  \
             Or install as service: sudo mlsh tunnel install"
        )
    }
    #[cfg(windows)]
    {
        Ok(ActiveTransport::endpoint_default(false))
    }
    #[cfg(not(any(unix, windows)))]
    {
        anyhow::bail!("Daemon IPC is not supported on this platform")
    }
}
