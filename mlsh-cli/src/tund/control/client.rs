//! Daemon client for CLI and future GUI.
//!
//! Connects to the `mlshtund` control endpoint (Unix socket on Unix,
//! named pipe on Windows) and exchanges JSON requests/responses.

use std::path::Path;
#[cfg(not(windows))]
use std::path::PathBuf;

use anyhow::Result;

use super::protocol::{read_message, write_message, DaemonRequest, DaemonResponse};
use crate::tund::transport::{ActiveTransport, Transport};

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
        // On Windows the daemon usually runs as a LocalSystem service bound to
        // the system pipe `\\.\pipe\mlshtund`. Try that first, then fall back to
        // a per-user daemon pipe. Pipes aren't filesystem entries, so we probe
        // by attempting to connect.
        #[cfg(windows)]
        {
            let system = ActiveTransport::endpoint_default(true);
            if let Ok(client) = Self::connect(&system).await {
                return Ok(client);
            }
            let user = ActiveTransport::endpoint_default(false);
            return Self::connect(&user).await;
        }
        #[cfg(not(windows))]
        {
            let path = discover_socket()?;
            Self::connect(&path).await
        }
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
}

/// Discover the daemon endpoint on Unix.
///
/// Checks the system socket, then the user socket. (On Windows, named pipes
/// aren't filesystem entries, so `connect_default` probes them directly.)
#[cfg(not(windows))]
pub fn discover_socket() -> Result<PathBuf> {
    #[cfg(unix)]
    {
        #[cfg(target_os = "linux")]
        let system = PathBuf::from("/run/mlsh/mlshtund.sock");
        #[cfg(not(target_os = "linux"))]
        let system = PathBuf::from("/var/run/mlsh/mlshtund.sock");
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
    #[cfg(not(any(unix, windows)))]
    {
        anyhow::bail!("Daemon IPC is not supported on this platform")
    }
}
