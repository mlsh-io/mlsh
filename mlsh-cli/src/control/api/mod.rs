pub mod auth;
pub mod cluster;
pub mod health;
pub mod invites;
pub mod nodes;
pub mod openapi;
pub mod users;

#[cfg(test)]
pub(crate) mod test_harness;

pub use openapi::ApiDoc;

use axum::Router;

use crate::control::auth::AuthState;

/// Single router that mounts every public-facing API surface
/// (auth/bootstrap/totp/webauthn, health, cluster, users, nodes, invites,
/// OpenAPI spec, docs UI).
pub fn router(state: AuthState) -> Router {
    Router::new()
        .merge(health::router())
        .merge(auth::router(state.clone()))
        .merge(cluster::router(state.clone()))
        .merge(users::router(state.clone()))
        .merge(nodes::router(state.clone()))
        .merge(invites::router(state))
        .merge(openapi::router())
}
