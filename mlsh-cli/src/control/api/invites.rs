//! Invites API.
//!
//! Invites are sponsor-signed, **stateless** tokens — the cryptographic
//! payload carries cluster id, role, expiry, sponsor identity, and signal
//! fingerprint, all signed by the sponsor's Ed25519 private key. The control
//! plane therefore does not persist invites: there is no list/read/delete,
//! only a creation endpoint.
//!
//! When per-tenant audit/revocation lands, this module gains a small
//! `invites` table indexed by `nonce` (already in the payload) and the
//! corresponding GET/DELETE handlers — no token format change required.

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Json, Response},
    routing::post,
    Router,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::control::auth::{AuthState, Caller};

pub fn router(state: AuthState) -> Router {
    Router::new()
        .route("/api/v1/invites", post(create_invite))
        .with_state(state)
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateInviteRequest {
    /// `"node"` (default) or `"admin"`.
    #[serde(default = "default_role")]
    pub role: String,
    /// Lifetime in seconds. Capped at 30 days; 0 falls back to one hour.
    #[serde(default = "default_ttl")]
    pub ttl_seconds: u64,
}

fn default_role() -> String {
    "node".to_string()
}

fn default_ttl() -> u64 {
    3600
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct InviteResponse {
    /// Opaque invite token (CBOR + Ed25519 signature, base64-url encoded).
    pub token: String,
    /// Ready-to-paste URL for `mlsh adopt`.
    pub url: String,
    /// Cluster name this invite admits the new node into.
    pub cluster: String,
    /// Role the new node will receive (`"node"` or `"admin"`).
    pub role: String,
    /// Number of seconds remaining before the token expires.
    pub expires_in: u64,
}

const MAX_TTL_SECONDS: u64 = 30 * 24 * 3600;

/// Create a new sponsor-signed invite. The token is stateless: the response
/// is the *only* time the server sees it. Lose it and you must re-issue.
#[utoipa::path(
    post,
    path = "/api/v1/invites",
    request_body = CreateInviteRequest,
    responses(
        (status = 201, description = "Invite created", body = InviteResponse),
        (status = 400, description = "Invalid role or empty key"),
        (status = 401, description = "Not authenticated"),
        (status = 500, description = "Sponsor key unreadable or signing failed"),
    ),
    tag = "Invites"
)]
pub async fn create_invite(
    State(state): State<AuthState>,
    _caller: Caller,
    Json(body): Json<CreateInviteRequest>,
) -> Response {
    if body.role != "node" && body.role != "admin" {
        return (StatusCode::BAD_REQUEST, "role must be 'node' or 'admin'").into_response();
    }
    let ttl = if body.ttl_seconds == 0 {
        default_ttl()
    } else {
        body.ttl_seconds.min(MAX_TTL_SECONDS)
    };

    let cluster = state.cluster.clone();
    let key_path = cluster.identity_dir.join("key.pem");
    let key_pem = match std::fs::read_to_string(&key_path) {
        Ok(k) => k,
        Err(e) => {
            tracing::warn!(path = %key_path.display(), error = %e, "sponsor key.pem unreadable");
            return (StatusCode::INTERNAL_SERVER_ERROR, "sponsor key unavailable").into_response();
        }
    };

    let signal_fingerprint =
        (!cluster.signal_fingerprint.is_empty()).then_some(cluster.signal_fingerprint.as_str());
    let root_fingerprint =
        (!cluster.root_fingerprint.is_empty()).then_some(cluster.root_fingerprint.as_str());

    let token =
        match mlsh_crypto::invite::generate_signed_invite_full(&mlsh_crypto::invite::InviteParams {
            key_pem: &key_pem,
            cluster_id: &cluster.cluster_id,
            cluster_name: &cluster.name,
            sponsor_node_uuid: &cluster.node_uuid,
            target_role: &body.role,
            ttl_seconds: ttl,
            signal_fingerprint,
            root_fingerprint,
        }) {
            Ok(t) => t,
            Err(e) => {
                tracing::warn!(error = %e, "invite signing failed");
                return (StatusCode::INTERNAL_SERVER_ERROR, "invite signing failed")
                    .into_response();
            }
        };

    let url = format!("mlsh://{}/adopt/{}", cluster.signal_endpoint, token);

    let body = InviteResponse {
        token,
        url,
        cluster: cluster.name.clone(),
        role: body.role,
        expires_in: ttl,
    };
    (StatusCode::CREATED, Json(body)).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::api::test_harness::{body_json, TestApp};
    use serde_json::json;

    #[tokio::test]
    async fn create_invite_with_defaults() {
        let (app, _dir) = TestApp::with_identity_dir().await;
        let resp = app.post("/api/v1/invites", &json!({})).await;
        assert_eq!(resp.status(), StatusCode::CREATED);
        let body: InviteResponse = body_json(resp).await;
        assert_eq!(body.cluster, "test-cluster");
        assert_eq!(body.role, "node");
        assert_eq!(body.expires_in, 3600);
        assert!(!body.token.is_empty());
        assert!(body.url.starts_with("mlsh://"));
        assert!(body.url.contains("/adopt/"));
    }

    #[tokio::test]
    async fn create_invite_admin_role() {
        let (app, _dir) = TestApp::with_identity_dir().await;
        let resp = app
            .post(
                "/api/v1/invites",
                &json!({ "role": "admin", "ttl_seconds": 600 }),
            )
            .await;
        assert_eq!(resp.status(), StatusCode::CREATED);
        let body: InviteResponse = body_json(resp).await;
        assert_eq!(body.role, "admin");
        assert_eq!(body.expires_in, 600);
    }

    #[tokio::test]
    async fn create_invite_invalid_role_returns_400() {
        let (app, _dir) = TestApp::with_identity_dir().await;
        let resp = app
            .post("/api/v1/invites", &json!({ "role": "superadmin" }))
            .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn create_invite_ttl_zero_falls_back_to_default() {
        let (app, _dir) = TestApp::with_identity_dir().await;
        let resp = app
            .post("/api/v1/invites", &json!({ "ttl_seconds": 0 }))
            .await;
        assert_eq!(resp.status(), StatusCode::CREATED);
        let body: InviteResponse = body_json(resp).await;
        assert_eq!(body.expires_in, 3600);
    }

    #[tokio::test]
    async fn create_invite_ttl_capped_at_30_days() {
        let (app, _dir) = TestApp::with_identity_dir().await;
        let resp = app
            .post("/api/v1/invites", &json!({ "ttl_seconds": u64::MAX / 2 }))
            .await;
        assert_eq!(resp.status(), StatusCode::CREATED);
        let body: InviteResponse = body_json(resp).await;
        assert_eq!(body.expires_in, MAX_TTL_SECONDS);
    }

    #[tokio::test]
    async fn create_invite_unauthenticated_returns_401() {
        let (app, _dir) = TestApp::with_identity_dir().await;
        let resp = app
            .send_anonymous(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/api/v1/invites")
                    .header(axum::http::header::CONTENT_TYPE, "application/json"),
            )
            .with_body(serde_json::to_vec(&json!({})).unwrap())
            .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn create_invite_without_identity_files_returns_500() {
        // Plain `TestApp::new()` uses an empty identity_dir, so cert.pem
        // can't be read. The handler should return 500 with a clean error
        // message instead of panicking.
        let app = TestApp::new().await;
        let resp = app.post("/api/v1/invites", &json!({})).await;
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}
