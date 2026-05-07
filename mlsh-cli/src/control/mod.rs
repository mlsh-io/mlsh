pub mod api;
pub mod auth;
pub(crate) mod db;
pub mod events;
pub mod first_admin;
pub mod mode;
pub mod nodes;
pub mod server;
pub mod stream;
pub mod tls;

use std::sync::Arc;

pub use first_admin::{write as write_first_admin, FirstAdmin};
pub use mode::{write as write_mode_init, Mode};

use crate::tund::cluster_config::ClusterConfig;

/// Boot the control plane in-process. Spawned as a tokio task by mlshtund
/// for clusters whose config carries the `control` role (ADR-035 Phase 0).
pub async fn serve(config: Arc<ClusterConfig>) -> anyhow::Result<()> {
    tracing::info!(
        cluster = %config.name,
        cluster_id = %config.cluster_id,
        "control plane starting"
    );

    let pool = db::init().await?;
    let store = auth::AuthStore::new(pool);
    mode::consume(&store).await?;
    first_admin::consume(&store).await?;

    let key_path = db::data_dir().join("session.key");
    let key = auth::crypto::load_or_create_key(&key_path)?;
    let mfa_key_path = db::data_dir().join("mfa.key");
    let mfa_key = auth::crypto::load_or_create_key(&mfa_key_path)?;
    let oauth = auth::oauth::OAuthConfig::from_env()?;
    if !oauth.is_ready() {
        tracing::info!(
            "managed-mode OAuth disabled (set {} to enable)",
            "MLSH_CLOUD_JWT_PUBKEY_PEM"
        );
    }
    let webauthn = auth::webauthn::WebauthnConfig::from_env()?;
    if webauthn.is_none() {
        tracing::info!(
            "WebAuthn disabled (set {} and {} to enable)",
            "MLSH_CONTROL_RP_ID",
            "MLSH_CONTROL_RP_ORIGIN"
        );
    }
    let event_hub = events::EventHub::new();

    let state = auth::AuthState {
        store,
        key: auth::SessionKey::new(key),
        oauth,
        mfa_key: std::sync::Arc::new(mfa_key),
        webauthn,
        events: event_hub.clone(),
        cluster: config.clone(),
    };

    let stream_state = stream::StreamState {
        pool: state.store.pool().clone(),
        events: event_hub,
        control_node_uuid: config.node_uuid.clone(),
    };
    let socket_path = stream::default_socket_path();
    tokio::spawn(async move {
        if let Err(e) = stream::serve(&socket_path, stream_state).await {
            tracing::error!(error = %e, "control CBOR socket exited");
        }
    });

    server::serve(state).await
}
