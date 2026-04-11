//! HTTP client for mlsh-cloud (device flow + cluster management).
//!
//! Used by `mlsh setup` in managed mode (no --token / --signal-host).

use anyhow::{Context, Result};
use serde::Deserialize;

const DEFAULT_CLOUD_URL: &str = "https://api.mlsh.io";

pub struct CloudClient {
    base_url: String,
    agent: ureq::Agent,
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
            agent: ureq::Agent::new_with_defaults(),
        }
    }

    /// Step 1: Request a device code for the OAuth device flow.
    pub fn request_device_code(&self) -> Result<DeviceCodeResponse> {
        let resp: DeviceCodeResponse = self
            .agent
            .get(format!("{}/auth/device/code", self.base_url))
            .call()
            .context("Failed to request device code")?
            .body_mut()
            .read_json()
            .context("Invalid device code response")?;
        Ok(resp)
    }

    /// Step 2: Poll for the access token (blocks until authorized or expired).
    pub fn poll_device_token(
        &self,
        device_code: &str,
        interval_secs: u64,
    ) -> Result<TokenResponse> {
        let interval = std::time::Duration::from_secs(interval_secs.max(2));

        loop {
            std::thread::sleep(interval);

            let result = self
                .agent
                .post(format!("{}/auth/device/token", self.base_url))
                .send_json(serde_json::json!({ "device_code": device_code }));

            match result {
                Ok(resp) => {
                    let token: TokenResponse = resp
                        .into_body()
                        .read_json()
                        .context("Invalid token response")?;
                    return Ok(token);
                }
                Err(ureq::Error::StatusCode(428)) => {
                    // authorization_pending — keep polling
                    continue;
                }
                Err(ureq::Error::StatusCode(code)) => {
                    anyhow::bail!("Device token poll failed (HTTP {})", code);
                }
                Err(e) => {
                    anyhow::bail!("Device token poll failed: {}", e);
                }
            }
        }
    }

    /// Step 3: Create a cluster (or get setup token for existing one).
    pub fn create_cluster(&self, access_token: &str, name: &str) -> Result<ClusterSetup> {
        let resp = self
            .agent
            .post(format!("{}/me/clusters", self.base_url))
            .header("Authorization", &format!("Bearer {}", access_token))
            .send_json(serde_json::json!({ "name": name }))
            .context("Failed to create cluster")?;

        let status = resp.status();
        if status != 201 && status != 200 {
            let body = resp.into_body().read_to_string().unwrap_or_default();
            anyhow::bail!("Failed to create cluster ({}): {}", status, body);
        }

        let cluster: ClusterSetup = resp
            .into_body()
            .read_json()
            .context("Invalid cluster response")?;
        Ok(cluster)
    }
}
