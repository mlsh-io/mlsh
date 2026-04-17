//! Direct-ingress probe + DynDNS.
//!
//! For each registered ingress route, decide whether the public DNS A record
//! should point at:
//!   * the owning node's public IP ("direct" — Mode B), or
//!   * mlsh-signal ("relay" — Mode A) when the node isn't directly reachable.
//!
//! Decision is made by attempting a 3-second TCP connect to `<node-ip>:443`.
//! If it succeeds we promote to direct, otherwise we demote to relay. The
//! resulting `public_mode` + `public_ip` columns in `ingress_routes` feed the
//! authoritative DNS server (see `dns.rs`). We also push an
//! `IngressStatus { domain, public_mode, public_ip }` message to the owning
//! node so it can bind/unbind its own public :443 listener.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use sqlx::SqlitePool;
use tokio::net::TcpStream;
use tracing::{debug, info, warn};

use crate::db::{self, IngressRouteRecord};
use crate::protocol::ServerMessage;
use crate::sessions::SessionStore;

const PROBE_TIMEOUT: Duration = Duration::from_secs(3);
const HEALTH_INTERVAL: Duration = Duration::from_secs(5 * 60);
const INGRESS_PORT: u16 = 443;

/// Probe one route and transition its public_mode if needed. The `candidate_ip`
/// is the node's most recent srflx (NAT-observed) address. If absent we
/// immediately demote to relay.
pub async fn probe_route(
    pool: &SqlitePool,
    sessions: &SessionStore,
    route: &IngressRouteRecord,
    candidate_ip: Option<Ipv4Addr>,
) -> Result<()> {
    let (new_mode, new_ip) = match candidate_ip {
        Some(ip) if probe_reachable(ip, INGRESS_PORT).await => {
            debug!(domain = %route.domain, %ip, "Probe succeeded — direct mode");
            ("direct", ip.to_string())
        }
        _ => {
            debug!(domain = %route.domain, "Probe failed — relay mode");
            ("relay", String::new())
        }
    };

    if route.public_mode != new_mode || route.public_ip != new_ip {
        db::set_ingress_public_mode(pool, &route.domain, new_mode, &new_ip).await?;
        info!(
            domain = %route.domain,
            from = %route.public_mode,
            to = new_mode,
            ip = %new_ip,
            "Ingress public mode changed"
        );
        push_status(sessions, route, new_mode, &new_ip).await;
    }
    Ok(())
}

/// Fire-and-forget a 3-second TCP connect to `ip:port` and close immediately.
async fn probe_reachable(ip: Ipv4Addr, port: u16) -> bool {
    let addr = SocketAddr::new(ip.into(), port);
    match tokio::time::timeout(PROBE_TIMEOUT, TcpStream::connect(addr)).await {
        Ok(Ok(_)) => true,
        Ok(Err(e)) => {
            debug!(%ip, port, error = %e, "Probe TCP connect failed");
            false
        }
        Err(_) => {
            debug!(%ip, port, "Probe timed out");
            false
        }
    }
}

async fn push_status(
    sessions: &SessionStore,
    route: &IngressRouteRecord,
    new_mode: &str,
    new_ip: &str,
) {
    let public_ip = if new_ip.is_empty() {
        None
    } else {
        Some(new_ip.to_string())
    };
    let msg = ServerMessage::IngressStatus {
        domain: route.domain.clone(),
        public_mode: new_mode.to_string(),
        public_ip,
    };
    sessions
        .push_to_node(&route.cluster_id, &route.node_id, msg)
        .await;
}

/// Extract the first srflx IPv4 candidate from a node's session.
pub async fn srflx_ip(sessions: &SessionStore, cluster_id: &str, node_id: &str) -> Option<Ipv4Addr> {
    let conn = sessions.get_node_connection(cluster_id, node_id).await?;
    match conn.remote_address().ip() {
        std::net::IpAddr::V4(v4) => Some(v4),
        _ => None,
    }
}

/// Re-probe every route whose owner's srflx candidate might have changed, plus
/// a periodic sweep to detect nodes that went offline or came back.
pub async fn run_health_check(
    pool: SqlitePool,
    sessions: Arc<SessionStore>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> Result<()> {
    let mut tick = tokio::time::interval(HEALTH_INTERVAL);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    info!(
        interval = ?HEALTH_INTERVAL,
        "Ingress health-check loop started"
    );

    loop {
        tokio::select! {
            _ = tick.tick() => {
                if let Err(e) = sweep_once(&pool, &sessions).await {
                    warn!(error = %e, "Ingress health sweep error");
                }
            }
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    info!("Ingress health-check shutting down");
                    break;
                }
            }
        }
    }
    Ok(())
}

async fn sweep_once(pool: &SqlitePool, sessions: &SessionStore) -> Result<()> {
    let routes = db::list_all_ingress_routes(pool).await?;
    debug!(count = routes.len(), "Ingress health sweep");
    for route in routes {
        let ip = srflx_ip(sessions, &route.cluster_id, &route.node_id).await;
        if let Err(e) = probe_route(pool, sessions, &route, ip).await {
            warn!(domain = %route.domain, error = %e, "Probe error");
        }
    }
    Ok(())
}
