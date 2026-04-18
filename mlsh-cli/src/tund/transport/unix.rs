//! Unix domain socket transport.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use tokio::net::{UnixListener, UnixStream};

use super::Transport;

const SYSTEM_SOCKET: &str = "/var/run/mlshtund.sock";

pub struct UnixTransport;

impl Transport for UnixTransport {
    type Listener = UnixListener;
    type Stream = UnixStream;

    fn endpoint_default(is_privileged: bool) -> PathBuf {
        if is_privileged {
            PathBuf::from(SYSTEM_SOCKET)
        } else {
            dirs::config_dir()
                .unwrap_or_else(|| PathBuf::from("/tmp"))
                .join("mlsh")
                .join("mlshtund.sock")
        }
    }

    async fn bind(path: &Path) -> Result<Self::Listener> {
        if path.exists() {
            std::fs::remove_file(path).ok();
        }
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }

        let listener = UnixListener::bind(path)
            .with_context(|| format!("Failed to bind Unix socket at {}", path.display()))?;

        // Make socket accessible to all local users (daemon runs as root, CLI runs as user).
        // TODO: add SO_PEERCRED check on Connect to restrict who can push configs.
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o666);
            std::fs::set_permissions(path, perms).ok();
        }

        Ok(listener)
    }

    async fn accept(listener: &mut Self::Listener) -> Result<Self::Stream> {
        let (stream, _addr) = listener.accept().await?;
        Ok(stream)
    }

    async fn connect(path: &Path) -> Result<Self::Stream> {
        UnixStream::connect(path)
            .await
            .with_context(|| format!("Failed to connect to daemon at {}", path.display()))
    }

    fn cleanup(path: &Path) {
        std::fs::remove_file(path).ok();
    }
}
