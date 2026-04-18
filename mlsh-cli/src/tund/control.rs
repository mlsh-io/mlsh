//! Control-channel listener for the `mlshtund` daemon.
//!
//! Accepts connections over the active platform transport (Unix socket on
//! Unix, named pipe on Windows), reads `DaemonRequest`s, dispatches to the
//! tunnel manager, and sends `DaemonResponse`s.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{watch, Mutex};

use super::protocol::{read_message, write_message, DaemonRequest, DaemonResponse};
use super::transport::{ActiveTransport, Transport};
use super::tunnel::parse_cluster_config;
use super::tunnel_manager::TunnelManager;

/// Determine the endpoint path (socket / pipe name).
pub fn socket_path(custom: Option<&str>) -> PathBuf {
    if let Some(p) = custom {
        return PathBuf::from(p);
    }
    ActiveTransport::endpoint_default(is_privileged())
}

fn is_privileged() -> bool {
    #[cfg(unix)]
    {
        unsafe { libc::geteuid() == 0 }
    }
    #[cfg(not(unix))]
    {
        // TODO: detect Windows service / elevated token when service install lands.
        false
    }
}

/// Run the control listener loop.
pub async fn run(
    sock_path: &Path,
    manager: Arc<Mutex<TunnelManager>>,
    mut shutdown_rx: watch::Receiver<bool>,
) -> Result<()> {
    let mut listener = ActiveTransport::bind(sock_path).await?;
    tracing::info!("Listening on {}", sock_path.display());

    loop {
        tokio::select! {
            accept = ActiveTransport::accept(&mut listener) => {
                match accept {
                    Ok(stream) => {
                        let mgr = manager.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_client(stream, mgr).await {
                                tracing::debug!("Client error: {}", e);
                            }
                        });
                    }
                    Err(e) => {
                        tracing::warn!("Accept error: {}", e);
                    }
                }
            }
            _ = shutdown_rx.changed() => {
                tracing::info!("Server shutting down");
                break;
            }
        }
    }

    ActiveTransport::cleanup(sock_path);

    Ok(())
}

async fn handle_client<S>(stream: S, manager: Arc<Mutex<TunnelManager>>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let (mut reader, mut writer) = tokio::io::split(stream);

    let request: DaemonRequest = read_message(&mut reader).await?;
    tracing::debug!("Received request: {:?}", request);

    let response = match request {
        DaemonRequest::Connect {
            cluster,
            config_toml,
            cert_pem,
            key_pem,
        } => {
            match persist_config(&cluster, &config_toml, &cert_pem, &key_pem) {
                Ok(state_dir) => {
                    let identity_dir = state_dir.join("clusters").join(&cluster);
                    match parse_cluster_config(&config_toml, &identity_dir) {
                        Ok(config) => {
                            let mut mgr = manager.lock().await;
                            mgr.connect(config)
                                .await
                                .unwrap_or_else(|e| DaemonResponse::Error {
                                    code: "connect_failed".into(),
                                    message: format!("{:#}", e),
                                })
                        }
                        Err(e) => DaemonResponse::Error {
                            code: "invalid_config".into(),
                            message: format!("{:#}", e),
                        },
                    }
                }
                Err(e) => DaemonResponse::Error {
                    code: "persist_failed".into(),
                    message: format!("{:#}", e),
                },
            }
        }
        DaemonRequest::Disconnect { cluster } => {
            let mut mgr = manager.lock().await;
            mgr.disconnect(&cluster).await
        }
        DaemonRequest::Status => {
            let mgr = manager.lock().await;
            mgr.status()
        }
        DaemonRequest::IngressAdd {
            cluster,
            domain,
            target,
            email,
            acme_staging,
        } => {
            crate::tund::ingress::add(&domain, &target);
            if !cluster.is_empty() {
                let directory = if acme_staging {
                    crate::tund::acme::Directory::Staging
                } else {
                    crate::tund::acme::Directory::Production
                };
                crate::tund::acme::spawn_issuance(
                    manager.clone(),
                    cluster,
                    domain.clone(),
                    email,
                    directory,
                );
            }
            DaemonResponse::Ok {
                message: Some(format!("Ingress target registered for {}", domain)),
            }
        }
        DaemonRequest::IngressRemove { domain } => {
            crate::tund::ingress::remove(&domain);
            DaemonResponse::Ok {
                message: Some(format!("Ingress target removed for {}", domain)),
            }
        }
    };

    write_message(&mut writer, &response).await?;

    Ok(())
}

/// Validate that a cluster name is safe to use in file paths.
/// Allows only alphanumeric characters, hyphens, and underscores.
fn validate_cluster_name(name: &str) -> Result<()> {
    if name.is_empty() {
        anyhow::bail!("Cluster name must not be empty");
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        anyhow::bail!(
            "Invalid cluster name '{}': only alphanumeric, hyphens, and underscores allowed",
            name
        );
    }
    Ok(())
}

/// Write content to a file atomically with restricted permissions (0o600 on unix).
fn atomic_write_restricted(path: &Path, content: &str) -> Result<()> {
    use std::io::Write;

    let parent = path.parent().context("File path has no parent directory")?;
    std::fs::create_dir_all(parent)?;

    let tmp_path = parent.join(format!(".tmp_{}", std::process::id()));

    let mut file = {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        opts.open(&tmp_path)
            .with_context(|| format!("Failed to create temp file at {}", tmp_path.display()))?
    };

    file.write_all(content.as_bytes())?;
    file.sync_all()?;
    drop(file);

    std::fs::rename(&tmp_path, path).with_context(|| {
        format!(
            "Failed to rename {} to {}",
            tmp_path.display(),
            path.display()
        )
    })?;

    Ok(())
}

/// Persist cluster config and identity to the daemon state directory.
/// Returns the state directory path on success.
fn persist_config(
    cluster: &str,
    config_toml: &str,
    cert_pem: &str,
    key_pem: &str,
) -> Result<std::path::PathBuf> {
    validate_cluster_name(cluster)?;

    let state_dir = crate::config::daemon_state_dir()?;

    let cluster_file = state_dir.join("clusters").join(format!("{}.toml", cluster));
    atomic_write_restricted(&cluster_file, config_toml)?;

    let identity_dir = state_dir.join("clusters").join(cluster);
    atomic_write_restricted(&identity_dir.join("cert.pem"), cert_pem)?;
    atomic_write_restricted(&identity_dir.join("key.pem"), key_pem)?;

    tracing::info!(
        "Persisted config for '{}' to {}",
        cluster,
        state_dir.display()
    );

    Ok(state_dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_cluster_names() {
        assert!(validate_cluster_name("homelab").is_ok());
        assert!(validate_cluster_name("my-cluster").is_ok());
        assert!(validate_cluster_name("prod_01").is_ok());
        assert!(validate_cluster_name("A").is_ok());
    }

    #[test]
    fn rejects_empty_cluster_name() {
        assert!(validate_cluster_name("").is_err());
    }

    #[test]
    fn rejects_path_traversal() {
        assert!(validate_cluster_name("../../etc/cron.d/backdoor").is_err());
        assert!(validate_cluster_name("../evil").is_err());
        assert!(validate_cluster_name("foo/bar").is_err());
    }

    #[test]
    fn rejects_special_characters() {
        assert!(validate_cluster_name("hello world").is_err());
        assert!(validate_cluster_name("cluster;rm -rf /").is_err());
        assert!(validate_cluster_name("name\0null").is_err());
    }

    #[test]
    fn atomic_write_creates_file_with_correct_content() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.toml");
        atomic_write_restricted(&path, "hello = \"world\"").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "hello = \"world\"");
    }

    #[test]
    #[cfg(unix)]
    fn atomic_write_creates_file_with_restricted_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.pem");
        atomic_write_restricted(&path, "private").unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "expected 0o600, got 0o{:o}", mode);
    }

    #[test]
    fn atomic_write_creates_parent_directories() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("deep").join("file.txt");
        atomic_write_restricted(&path, "content").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "content");
    }

    #[test]
    fn atomic_write_overwrites_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("overwrite.txt");
        atomic_write_restricted(&path, "first").unwrap();
        atomic_write_restricted(&path, "second").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "second");
    }

    #[test]
    fn atomic_write_leaves_no_temp_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("clean.txt");
        atomic_write_restricted(&path, "content").unwrap();
        let entries: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .collect();
        assert_eq!(
            entries.len(),
            1,
            "expected only the final file, no leftover temp files"
        );
        assert_eq!(entries[0].file_name(), "clean.txt");
    }

    #[test]
    fn socket_path_uses_custom_when_provided() {
        let path = socket_path(Some("/tmp/custom.sock"));
        assert_eq!(path, PathBuf::from("/tmp/custom.sock"));
    }

    #[test]
    fn endpoint_default_differs_by_privilege() {
        let system = ActiveTransport::endpoint_default(true);
        let user = ActiveTransport::endpoint_default(false);
        assert_ne!(system, user);
    }
}
