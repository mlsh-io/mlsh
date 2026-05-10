//! HTTP client for mlsh-cloud (device flow + cluster management).
//!
//! Used by `mlsh setup` in managed mode (no --token / --signal-host).

use anyhow::{Context, Result};
use serde::Deserialize;

const DEFAULT_CLOUD_URL: &str = "https://api.mlsh.io";

pub struct CloudClient {
    base_url: String,
    client: reqwest::Client,
}

#[derive(Deserialize)]
pub struct DeviceCodeResponse {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub expires_in: u64,
    pub interval: u64,
}

#[derive(Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub refresh_token: String,
}

#[derive(Deserialize)]
pub struct ClusterSetup {
    pub signal_cluster_id: String,
    pub signal_endpoint: String,
    pub setup_token: Option<String>,
}

impl Default for CloudClient {
    fn default() -> Self {
        Self::new()
    }
}

impl CloudClient {
    pub fn new() -> Self {
        let base_url =
            std::env::var("MLSH_CLOUD_URL").unwrap_or_else(|_| DEFAULT_CLOUD_URL.to_string());
        Self {
            base_url,
            client: reqwest::Client::new(),
        }
    }

    /// Step 1: Request a device code for the OAuth device flow.
    pub async fn request_device_code(&self) -> Result<DeviceCodeResponse> {
        self.client
            .get(format!("{}/auth/device/code", self.base_url))
            .send()
            .await
            .context("Failed to request device code")?
            .error_for_status()
            .context("Device code request returned error")?
            .json()
            .await
            .context("Invalid device code response")
    }

    /// One-shot poll. Returns:
    /// - `Ok(Some(token))` if mlsh-cloud emitted a token
    /// - `Ok(None)` if authorization is still pending (HTTP 428)
    /// - `Err(_)` for any other failure
    pub async fn poll_device_token_once(&self, device_code: &str) -> Result<Option<TokenResponse>> {
        let resp = self
            .client
            .post(format!("{}/auth/device/token", self.base_url))
            .json(&serde_json::json!({ "device_code": device_code }))
            .send()
            .await
            .context("Device token poll failed")?;

        if resp.status().as_u16() == 428 {
            return Ok(None);
        }
        if !resp.status().is_success() {
            anyhow::bail!("Device token poll failed (HTTP {})", resp.status().as_u16());
        }
        Ok(Some(resp.json().await.context("Invalid token response")?))
    }

    /// Step 2: Poll for the access token (loops until authorized or expired).
    pub async fn poll_device_token(
        &self,
        device_code: &str,
        interval_secs: u64,
    ) -> Result<TokenResponse> {
        let interval = std::time::Duration::from_secs(interval_secs.max(2));
        loop {
            tokio::time::sleep(interval).await;
            if let Some(t) = self.poll_device_token_once(device_code).await? {
                return Ok(t);
            }
        }
    }

    /// Step 3: Create a cluster (or get setup token for existing one).
    pub async fn create_cluster(&self, access_token: &str, name: &str) -> Result<ClusterSetup> {
        let resp = self
            .client
            .post(format!("{}/me/clusters", self.base_url))
            .bearer_auth(access_token)
            .json(&serde_json::json!({ "name": name }))
            .send()
            .await
            .context("Failed to create cluster")?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("Failed to create cluster ({}): {}", status.as_u16(), body);
        }
        resp.json().await.context("Invalid cluster response")
    }
}
