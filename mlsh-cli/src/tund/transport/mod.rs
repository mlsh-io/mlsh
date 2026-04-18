//! Platform-abstract IPC transport for the `mlshtund` control channel.
//!
//! Unix → Unix domain socket. Windows → named pipe.

use std::path::{Path, PathBuf};

use anyhow::Result;
use tokio::io::{AsyncRead, AsyncWrite};

#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

#[cfg(unix)]
pub use unix::UnixTransport as ActiveTransport;
#[cfg(windows)]
pub use windows::WindowsTransport as ActiveTransport;

/// A platform IPC transport.
///
/// Implementors are zero-sized selectors; all state lives in `Listener` /
/// `Stream`. This lets the control loop stay generic over the underlying
/// primitive (Unix domain socket vs. Windows named pipe).
#[allow(async_fn_in_trait)]
pub trait Transport {
    type Listener: Send;
    type Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static;

    /// Default endpoint (socket path or pipe name) for the daemon.
    fn endpoint_default(is_privileged: bool) -> PathBuf;

    /// Bind a listener at the given endpoint. Removes stale endpoints where
    /// that's meaningful (filesystem sockets).
    async fn bind(path: &Path) -> Result<Self::Listener>;

    /// Accept one inbound connection.
    async fn accept(listener: &mut Self::Listener) -> Result<Self::Stream>;

    /// Connect to a daemon listening at the given endpoint.
    async fn connect(path: &Path) -> Result<Self::Stream>;

    /// Remove the endpoint on shutdown where applicable.
    fn cleanup(path: &Path);
}
