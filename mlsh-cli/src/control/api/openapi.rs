//! OpenAPI spec + Scalar documentation UI.

use axum::{
    response::{Html, Json},
    routing::get,
    Router,
};
use utoipa::OpenApi;

#[derive(OpenApi)]
#[openapi(
    paths(
        // Health
        super::health::get_status,
        // Bootstrap / Auth
        super::auth::bootstrap_status,
        super::auth::bootstrap_create,
        super::auth::login,
        super::auth::logout,
        super::auth::device_start,
        super::auth::device_poll,
        // TOTP
        super::auth::totp_enroll,
        super::auth::totp_verify,
        super::auth::totp_delete,
        // WebAuthn
        super::auth::webauthn_register_start,
        super::auth::webauthn_register_finish,
        super::auth::webauthn_login_start,
        super::auth::webauthn_login_finish,
        super::auth::webauthn_list,
        super::auth::webauthn_delete,
        // Cluster
        super::cluster::get_cluster,
        // Users
        super::users::get_current,
        super::users::list_users,
        super::users::get_user,
        super::users::create_user,
        super::users::update_user,
        super::users::delete_user,
        // Nodes
        super::nodes::list_nodes,
        super::nodes::get_node,
        super::nodes::delete_node,
        super::nodes::revoke,
        super::nodes::set_name,
        super::nodes::set_role,
        // Invites
        super::invites::create_invite,
    ),
    components(
        schemas(
            // Health
            super::health::HealthStatusResponse,
            // Auth
            crate::control::auth::handlers::LoginRequest,
            crate::control::auth::handlers::UserView,
            crate::control::auth::handlers::BootstrapStatus,
            crate::control::auth::handlers::BootstrapRequest,
            crate::control::auth::handlers::DeviceStartResponse,
            crate::control::auth::handlers::DevicePollRequest,
            // TOTP
            crate::control::auth::handlers::TotpEnrollment,
            crate::control::auth::handlers::TotpVerifyRequest,
            // WebAuthn
            crate::control::auth::handlers::WebauthnId,
            crate::control::auth::webauthn::CredentialView,
            // Cluster
            super::cluster::ClusterResponse,
            // Users
            super::users::CurrentUserResponse,
            super::users::UserResponse,
            super::users::CreateUserRequest,
            super::users::UpdateUserRequest,
            // Nodes
            super::nodes::NodeResponse,
            super::nodes::SetNameRequest,
            super::nodes::SetRoleRequest,
            // Invites
            super::invites::CreateInviteRequest,
            super::invites::InviteResponse,
        )
    ),
    info(
        title = "MLSH Control API",
        version = "1.0.0",
        description = "API for managing the MLSH overlay network.",
    ),
)]
pub struct ApiDoc;

/// Mount `/api-docs/openapi.json` and `/api-docs` (Scalar UI).
pub fn router() -> Router {
    Router::new()
        .route("/api-docs/openapi.json", get(openapi_json))
        .route("/api-docs", get(scalar_ui))
}

/// OpenAPI JSON endpoint.
pub async fn openapi_json() -> Json<utoipa::openapi::OpenApi> {
    Json(ApiDoc::openapi())
}

/// Scalar API documentation UI.
pub async fn scalar_ui() -> Html<&'static str> {
    Html(SCALAR_HTML)
}

const SCALAR_HTML: &str = r#"<!doctype html>
<html>
  <head>
    <title>MLSH Control API - Scalar Documentation</title>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
  </head>
  <body>
    <script id="api-reference" data-url="/api-docs/openapi.json"></script>
    <script src="https://cdn.jsdelivr.net/npm/@scalar/api-reference"></script>
  </body>
</html>"#;
