//! `Caller` — typed identity injected into every authenticated handler.
//!
//! Two flavors:
//!   - [`Caller::Machine`]: the request connection presented an mTLS client
//!     cert whose SHA-256 fingerprint is registered in the `nodes` table.
//!     This is how the CLI and other nodes authenticate (ADR-035 Phase D).
//!   - [`Caller::Human`]: the request carries a valid session cookie tied
//!     to a `users` row. This is how the bundled web UI authenticates.
//!
//! The extractor tries machine first, then human. A handler that wants
//! either flavor takes `Caller`; a handler that only wants one variant
//! pattern-matches and returns 403 on the wrong flavor.

use axum::{
    extract::{FromRequestParts, OptionalFromRequestParts},
    http::{request::Parts, StatusCode},
    response::{IntoResponse, Response},
};
use super::mtls_acceptor::PeerCert;
use super::session::CurrentUser;
use super::store::User;
use super::AuthState;
use crate::control::nodes::{self, NodeRow};

/// Strict human-only extractor — requires a valid session cookie. The
/// presence of a client cert is *ignored*: the cookie is the source of
/// truth for human identity. This matters for the bundled UI accessed
/// through the local `mlsh ui` proxy, which always presents a node cert
/// for the upstream mTLS leg even when the operator is browsing as a
/// human (the cookie is what authenticates the human).
///
/// Endpoints whose semantics make no sense for a machine (TOTP
/// enrollment, WebAuthn ceremonies, password change) use this instead
/// of `Caller`.
pub struct HumanCaller(pub User);

impl FromRequestParts<AuthState> for HumanCaller {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AuthState,
    ) -> Result<Self, Self::Rejection> {
        match <CurrentUser as FromRequestParts<AuthState>>::from_request_parts(parts, state).await
        {
            Ok(CurrentUser(user)) => Ok(HumanCaller(user)),
            Err(rej) => Err(rej),
        }
    }
}

#[derive(Debug, Clone)]
pub enum Caller {
    Machine {
        node_uuid: String,
        role: String,
        fingerprint: String,
    },
    Human {
        user_id: String,
        email: String,
        must_change_password: bool,
    },
}

impl Caller {
    pub fn from_node(row: NodeRow) -> Self {
        Caller::Machine {
            node_uuid: row.node_uuid,
            role: row.role,
            fingerprint: row.fingerprint,
        }
    }

    pub fn from_user(user: User) -> Self {
        Caller::Human {
            user_id: user.id,
            email: user.email,
            must_change_password: user.must_change_password,
        }
    }
}

impl FromRequestParts<AuthState> for Caller {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AuthState,
    ) -> Result<Self, Self::Rejection> {
        if let Some(caller) = resolve_machine(parts, state).await? {
            return Ok(caller);
        }
        match <CurrentUser as FromRequestParts<AuthState>>::from_request_parts(parts, state).await
        {
            Ok(CurrentUser(user)) => Ok(Caller::from_user(user)),
            Err(rej) => Err(rej),
        }
    }
}

impl OptionalFromRequestParts<AuthState> for Caller {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AuthState,
    ) -> Result<Option<Self>, Self::Rejection> {
        if let Some(caller) = resolve_machine(parts, state).await? {
            return Ok(Some(caller));
        }
        match <CurrentUser as OptionalFromRequestParts<AuthState>>::from_request_parts(
            parts, state,
        )
        .await
        {
            Ok(opt) => Ok(opt.map(|CurrentUser(u)| Caller::from_user(u))),
            Err(rej) => Err(rej),
        }
    }
}

/// Try to authenticate the request as a known node by hashing the TLS peer
/// cert and looking the SHA-256 fingerprint up in the `nodes` table. Returns
/// `Ok(None)` when no peer cert is present *or* the fingerprint is not in
/// the registry — the caller falls back to the session-cookie path.
/// `Ok(Some)` returns a fully-resolved `Caller::Machine`. Errors only on
/// internal failures (DB unreachable).
async fn resolve_machine(
    parts: &Parts,
    state: &AuthState,
) -> Result<Option<Caller>, Response> {
    let Some(PeerCert(cert)) = parts.extensions.get::<PeerCert>().cloned() else {
        return Ok(None);
    };
    let fingerprint = mlsh_crypto::identity::compute_fingerprint(cert.as_ref());
    match nodes::find_by_fingerprint(state.store.pool(), &state.cluster.cluster_id, &fingerprint)
        .await
    {
        Ok(Some(row)) => Ok(Some(Caller::from_node(row))),
        Ok(None) => Ok(None),
        Err(e) => {
            tracing::warn!(error = %e, "machine fingerprint lookup failed");
            Err(
                (StatusCode::INTERNAL_SERVER_ERROR, "machine auth failed")
                    .into_response(),
            )
        }
    }
}
