//! mTLS-authenticated REST client used by `mlsh nodes/rename/promote/revoke`
//! to talk to the cluster's control plane (ADR-035 Phase E).
//!
//! The client uses the node's own identity cert (`cert.pem` + `key.pem` from
//! the cluster's identity dir) for mTLS. The server side (mlshtund running
//! the `control` role) validates the SHA-256 fingerprint against the
//! `nodes` registry and authorizes as `Caller::Machine`.
//!
//! Server cert verification is disabled because the control plane presents a
//! self-signed identity cert (CN = node UUID), not a chain-validated cert.
//! Trust pinning will land alongside the cluster-CA work in ADR-035 Phase C
//! (SNI + cluster-CA cert for `control.<cluster>`).

use anyhow::{Context, Result};
use reqwest::Identity;

use crate::tund::cluster_config::ClusterConfig;
use crate::tund::tunnel::load_cluster_config;

/// Default port the control HTTPS listener binds in
/// `crate::control::server::serve` (overridable via `MLSH_CONTROL_BIND`).
const DEFAULT_CONTROL_PORT: u16 = 8443;

/// Build a fully-configured mTLS [`reqwest::Client`] for the named cluster.
///
/// Returns the client + base URL + the resolved `ClusterConfig` (callers
/// commonly need all three — the client to call, the URL to format paths
/// against, and the cluster name/id to print).
pub fn for_cluster(cluster_name: &str) -> Result<(reqwest::Client, String, ClusterConfig)> {
    let base_dir = crate::config::config_dir()?;
    let config = load_cluster_config(cluster_name, &base_dir)?;

    let cert_pem =
        std::fs::read(config.identity_dir.join("cert.pem")).context("read identity cert.pem")?;
    let key_pem =
        std::fs::read(config.identity_dir.join("key.pem")).context("read identity key.pem")?;

    let mut identity_pem = cert_pem.clone();
    identity_pem.extend_from_slice(b"\n");
    identity_pem.extend_from_slice(&key_pem);
    let identity = Identity::from_pem(&identity_pem).context("build mTLS identity")?;

    let http = reqwest::Client::builder()
        .identity(identity)
        // The control plane serves a self-signed identity cert. Trust pinning
        // lands in ADR-035 Phase C.
        .danger_accept_invalid_certs(true)
        .build()
        .context("build reqwest client")?;

    let base_url = format!("https://{}:{}", config.name, DEFAULT_CONTROL_PORT);

    Ok((http, base_url, config))
}
