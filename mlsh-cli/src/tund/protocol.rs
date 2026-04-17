//! Wire protocol for the mlshtund Unix socket control API.
//!
//! JSON messages with 4-byte big-endian length prefix.

use serde::{Deserialize, Serialize};

// Client → Daemon

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DaemonRequest {
    /// Bring up a tunnel for the given cluster.
    /// CLI sends the full config + identity so the daemon doesn't need
    /// access to the user's home directory.
    Connect {
        cluster: String,
        /// Contents of the cluster TOML config file.
        config_toml: String,
        /// Node identity certificate (PEM).
        cert_pem: String,
        /// Node identity private key (PEM).
        key_pem: String,
    },
    /// Tear down a tunnel for the given cluster.
    Disconnect { cluster: String },
    /// Query the status of all tunnels.
    Status,
    /// Register a public-ingress route on the local daemon.
    /// Paired with `StreamMessage::ExposeService` sent to signal by the CLI.
    IngressAdd {
        /// Cluster whose signal session should be used for ACME DNS-01.
        /// If the cluster isn't connected, ACME is deferred and a self-signed
        /// cert is used until the daemon reconnects and retries.
        #[serde(default)]
        cluster: String,
        /// Public domain (e.g. "myapp.mlsh.io").
        domain: String,
        /// Local upstream URL (e.g. "http://localhost:3000").
        target: String,
        /// Contact email for the ACME account.
        #[serde(default)]
        email: Option<String>,
        /// When true, hit Let's Encrypt staging instead of production. Strongly
        /// recommended during smoke tests (production has hard rate limits).
        #[serde(default)]
        acme_staging: bool,
    },
    /// Remove a previously-registered ingress target.
    IngressRemove { domain: String },
}

// Daemon → Client

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DaemonResponse {
    /// Success.
    Ok {
        #[serde(skip_serializing_if = "Option::is_none")]
        message: Option<String>,
    },
    /// Error.
    Error { code: String, message: String },
    /// Status of all tunnels.
    Status { tunnels: Vec<TunnelStatus> },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TunnelState {
    Disconnected,
    Connecting,
    Connected,
    Reconnecting,
}

impl std::fmt::Display for TunnelState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TunnelState::Disconnected => write!(f, "disconnected"),
            TunnelState::Connecting => write!(f, "connecting"),
            TunnelState::Connected => write!(f, "connected"),
            TunnelState::Reconnecting => write!(f, "reconnecting"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelStatus {
    pub cluster: String,
    pub state: TunnelState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transport: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub overlay_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uptime_secs: Option<u64>,
    pub bytes_tx: u64,
    pub bytes_rx: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

// Socket I/O

use tokio::io::{AsyncReadExt, AsyncWriteExt};

const MAX_MSG_SIZE: u32 = 1024 * 1024;

/// Read a length-prefixed JSON message from an async reader.
pub async fn read_message<T: serde::de::DeserializeOwned>(
    reader: &mut (impl AsyncReadExt + Unpin),
) -> anyhow::Result<T> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf);
    if len > MAX_MSG_SIZE {
        anyhow::bail!("Message too large: {} bytes", len);
    }
    let mut buf = vec![0u8; len as usize];
    reader.read_exact(&mut buf).await?;
    Ok(serde_json::from_slice(&buf)?)
}

/// Write a length-prefixed JSON message to an async writer.
pub async fn write_message<T: Serialize>(
    writer: &mut (impl AsyncWriteExt + Unpin),
    msg: &T,
) -> anyhow::Result<()> {
    let json = serde_json::to_vec(msg)?;
    let len = (json.len() as u32).to_be_bytes();
    writer.write_all(&len).await?;
    writer.write_all(&json).await?;
    writer.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn serialize_connect_request() {
        let req = DaemonRequest::Connect {
            cluster: "homelab".into(),
            config_toml: "[cluster]\nname = \"homelab\"".into(),
            cert_pem: "cert".into(),
            key_pem: "key".into(),
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"type\":\"connect\""));
        assert!(json.contains("\"cluster\":\"homelab\""));
    }

    #[test]
    fn serialize_status_response() {
        let resp = DaemonResponse::Status {
            tunnels: vec![TunnelStatus {
                cluster: "homelab".into(),
                state: TunnelState::Connected,
                transport: Some("relay".into()),
                overlay_ip: Some("100.64.0.2".into()),
                uptime_secs: Some(3600),
                bytes_tx: 1024,
                bytes_rx: 512,
                last_error: None,
            }],
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"connected\""));
        assert!(json.contains("\"relay\""));
    }

    #[test]
    fn deserialize_request_roundtrip() {
        let req = DaemonRequest::Status;
        let json = serde_json::to_string(&req).unwrap();
        let parsed: DaemonRequest = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, DaemonRequest::Status));
    }

    #[tokio::test]
    async fn framing_roundtrip() {
        let req = DaemonRequest::Status;
        let mut buf = Vec::new();
        write_message(&mut buf, &req).await.unwrap();

        let mut reader = Cursor::new(buf);
        let parsed: DaemonRequest = read_message(&mut reader).await.unwrap();
        assert!(matches!(parsed, DaemonRequest::Status));
    }

    #[tokio::test]
    async fn framing_roundtrip_connect() {
        let req = DaemonRequest::Connect {
            cluster: "homelab".into(),
            config_toml: "[cluster]\nname = \"homelab\"".into(),
            cert_pem: "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----".into(),
            key_pem: "-----BEGIN PRIVATE KEY-----\nfake\n-----END PRIVATE KEY-----".into(),
        };
        let mut buf = Vec::new();
        write_message(&mut buf, &req).await.unwrap();

        let mut reader = Cursor::new(buf);
        let parsed: DaemonRequest = read_message(&mut reader).await.unwrap();
        match parsed {
            DaemonRequest::Connect { cluster, .. } => assert_eq!(cluster, "homelab"),
            _ => panic!("expected Connect"),
        }
    }

    #[tokio::test]
    async fn framing_rejects_oversized_message() {
        // Craft a length header claiming > MAX_MSG_SIZE
        let len = (MAX_MSG_SIZE + 1).to_be_bytes();
        let mut reader = Cursor::new(len.to_vec());
        let result: anyhow::Result<DaemonRequest> = read_message(&mut reader).await;
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("too large"),
            "expected 'too large', got: {}",
            err
        );
    }

    #[tokio::test]
    async fn framing_rejects_truncated_body() {
        // Length header says 100 bytes, but only 5 bytes follow
        let mut buf = Vec::new();
        buf.extend_from_slice(&100u32.to_be_bytes());
        buf.extend_from_slice(b"short");
        let mut reader = Cursor::new(buf);
        let result: anyhow::Result<DaemonRequest> = read_message(&mut reader).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn framing_rejects_truncated_header() {
        // Only 2 bytes instead of 4-byte length header
        let mut reader = Cursor::new(vec![0u8, 1]);
        let result: anyhow::Result<DaemonRequest> = read_message(&mut reader).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn framing_rejects_empty_input() {
        let mut reader = Cursor::new(Vec::new());
        let result: anyhow::Result<DaemonRequest> = read_message(&mut reader).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn framing_rejects_length_shorter_than_json() {
        // Length header says 5 bytes, but the full JSON is much longer
        let json = serde_json::to_vec(&DaemonRequest::Status).unwrap();
        assert!(json.len() > 5, "test assumes JSON is longer than 5 bytes");
        let mut buf = Vec::new();
        buf.extend_from_slice(&5u32.to_be_bytes());
        buf.extend_from_slice(&json);
        let mut reader = Cursor::new(buf);
        let result: anyhow::Result<DaemonRequest> = read_message(&mut reader).await;
        // Reads only 5 bytes of JSON → invalid JSON → error
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn framing_rejects_length_longer_than_body() {
        // Length header says 1000 bytes, but only a short JSON follows
        let json = serde_json::to_vec(&DaemonRequest::Status).unwrap();
        let mut buf = Vec::new();
        buf.extend_from_slice(&1000u32.to_be_bytes());
        buf.extend_from_slice(&json);
        let mut reader = Cursor::new(buf);
        let result: anyhow::Result<DaemonRequest> = read_message(&mut reader).await;
        // Tries to read 1000 bytes but hits EOF → error
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn framing_zero_length_message() {
        // Valid 4-byte header claiming 0 bytes, followed by empty body
        let buf = 0u32.to_be_bytes().to_vec();
        let mut reader = Cursor::new(buf);
        let result: anyhow::Result<DaemonRequest> = read_message(&mut reader).await;
        // 0 bytes of JSON is not valid — should error
        assert!(result.is_err());
    }
}
