//! Daemon client for CLI and future GUI.
//!
//! Connects to the `mlshtund` Unix socket and sends requests.
//! On Windows, named pipes will be used in a future release.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
#[cfg(unix)]
use tokio::net::UnixStream;

use super::protocol::{read_message, write_message, DaemonRequest, DaemonResponse};

/// Client for communicating with the `mlshtund` daemon.
pub struct DaemonClient {
    #[cfg(unix)]
    stream: UnixStream,
}

impl DaemonClient {
    /// Connect to the daemon at the given socket path.
    pub async fn connect(path: &Path) -> Result<Self> {
        #[cfg(unix)]
        {
            let stream = UnixStream::connect(path)
                .await
                .with_context(|| format!("Failed to connect to daemon at {}", path.display()))?;
            Ok(Self { stream })
        }
        #[cfg(not(unix))]
        {
            let _ = path;
            anyhow::bail!("Daemon IPC is not yet supported on this platform")
        }
    }

    /// Connect to the daemon, auto-discovering the socket path.
    pub async fn connect_default() -> Result<Self> {
        let path = discover_socket()?;
        Self::connect(&path).await
    }

    /// Send a request and receive the response.
    pub async fn request(&mut self, req: &DaemonRequest) -> Result<DaemonResponse> {
        #[cfg(unix)]
        {
            let (mut reader, mut writer) = self.stream.split();
            write_message(&mut writer, req).await?;
            let resp: DaemonResponse = read_message(&mut reader).await?;
            Ok(resp)
        }
        #[cfg(not(unix))]
        {
            let _ = req;
            anyhow::bail!("Daemon IPC is not yet supported on this platform")
        }
    }

    /// Send a connect request for a cluster, including the full config and identity.
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

    /// Send a disconnect request for a cluster.
    pub async fn disconnect_cluster(&mut self, cluster: &str) -> Result<DaemonResponse> {
        self.request(&DaemonRequest::Disconnect {
            cluster: cluster.to_string(),
        })
        .await
    }

    /// Query status of all tunnels.
    pub async fn status(&mut self) -> Result<DaemonResponse> {
        self.request(&DaemonRequest::Status).await
    }

    /// Register an ingress target with the local daemon.
    pub async fn ingress_add(
        &mut self,
        cluster: &str,
        domain: &str,
        target: &str,
        email: Option<&str>,
        acme_staging: bool,
    ) -> Result<DaemonResponse> {
        self.request(&DaemonRequest::IngressAdd {
            cluster: cluster.to_string(),
            domain: domain.to_string(),
            target: target.to_string(),
            email: email.map(|s| s.to_string()),
            acme_staging,
        })
        .await
    }

    /// Remove an ingress target from the local daemon.
    pub async fn ingress_remove(&mut self, domain: &str) -> Result<DaemonResponse> {
        self.request(&DaemonRequest::IngressRemove {
            domain: domain.to_string(),
        })
        .await
    }
}

/// Discover the daemon socket path.
///
/// Checks (in order):
/// 1. System socket `/var/run/mlshtund.sock`
/// 2. User socket `~/.config/mlsh/mlshtund.sock`
pub fn discover_socket() -> Result<PathBuf> {
    #[cfg(unix)]
    {
        let system = PathBuf::from("/var/run/mlshtund.sock");
        if system.exists() {
            return Ok(system);
        }

        let user = dirs::config_dir()
            .context("Failed to determine config directory")?
            .join("mlsh")
            .join("mlshtund.sock");
        if user.exists() {
            return Ok(user);
        }
    }

    anyhow::bail!(
        "mlshtund is not running.\n  \
         Start it with: sudo mlshtund\n  \
         Or install as service: sudo mlsh tunnel install"
    )
}
