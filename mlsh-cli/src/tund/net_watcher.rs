//! Watches OS-level interface events and kicks the signal session + every
//! peer FSM when a network change (or wake) is detected.

use std::net::IpAddr;
use std::time::Duration;

use tokio::select;
use tokio_util::sync::CancellationToken;

use super::net_filter::{is_interesting_ip, OverlayNet};
use super::peer_fsm::{Event, FsmRegistry};
use super::signal_session::SignalSessionHandle;

const DEBOUNCE: Duration = Duration::from_millis(500);
const MIGRATION_VALIDATION: Duration = Duration::from_secs(5);
/// Silence window used to detect the end of if-watch's startup snapshot
/// (one Up event per pre-existing address).
const SNAPSHOT_DRAIN: Duration = Duration::from_millis(500);

pub fn spawn(
    session: SignalSessionHandle,
    fsm_registry: FsmRegistry,
    endpoint: quinn::Endpoint,
    overlay: OverlayNet,
    cancel: CancellationToken,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        if let Err(e) = run(session, fsm_registry, endpoint, overlay, cancel).await {
            tracing::warn!("net_watcher exited: {e:#}");
        }
    })
}

async fn run(
    session: SignalSessionHandle,
    fsm_registry: FsmRegistry,
    endpoint: quinn::Endpoint,
    overlay: OverlayNet,
    cancel: CancellationToken,
) -> anyhow::Result<()> {
    use std::future::poll_fn;

    let mut watcher = if_watch::tokio::IfWatcher::new()
        .map_err(|e| anyhow::anyhow!("failed to start if-watch: {e}"))?;

    async fn next_event(watcher: &mut if_watch::tokio::IfWatcher) -> Option<if_watch::IfEvent> {
        poll_fn(|cx| watcher.poll_if_event(cx))
            .await
            .map_err(|e| tracing::warn!("if-watch error: {e}"))
            .ok()
    }

    // Drain if-watch's startup snapshot: on creation it emits one Up event
    // per pre-existing address so consumers can build initial state. We
    // don't — those aren't changes, just baseline. Read until the stream
    // goes silent for SNAPSHOT_DRAIN.
    let mut snapshot_count = 0;
    while let Ok(Some(_)) = tokio::time::timeout(SNAPSHOT_DRAIN, next_event(&mut watcher)).await {
        snapshot_count += 1;
    }
    tracing::info!("net_watcher started (drained {snapshot_count} snapshot event(s))");

    let mut pending = false;

    loop {
        if pending {
            select! {
                _ = cancel.cancelled() => break,
                _ = tokio::time::sleep(DEBOUNCE) => {
                    pending = false;
                    kick(&session, &fsm_registry, &endpoint).await;
                }
                ev = next_event(&mut watcher) => {
                    if let Some(ev) = ev {
                        if interesting(&ev, overlay) {
                            tracing::debug!(?ev, "interface event during debounce");
                        }
                    }
                }
            }
        } else {
            select! {
                _ = cancel.cancelled() => break,
                ev = next_event(&mut watcher) => {
                    if let Some(ev) = ev {
                        if interesting(&ev, overlay) {
                            tracing::debug!(?ev, "interface event");
                            pending = true;
                        }
                    }
                }
            }
        }
    }

    tracing::info!("net_watcher shut down");
    Ok(())
}

async fn kick(
    session: &SignalSessionHandle,
    fsm_registry: &FsmRegistry,
    endpoint: &quinn::Endpoint,
) {
    match super::quic::try_migrate(endpoint) {
        Ok(new_port) => {
            session.report_candidates(new_port);
            spawn_migration_watchdog(session.clone(), fsm_registry.clone());
        }
        Err(e) => {
            tracing::warn!("Path migration failed to rebind ({e:#}); falling back to reconnect");
            session.kick_reconnect();
            fsm_registry.broadcast(Event::WakeKick).await;
        }
    }
}

fn spawn_migration_watchdog(session: SignalSessionHandle, fsm_registry: FsmRegistry) {
    tokio::spawn(async move {
        let Some(conn) = session.connection() else {
            return;
        };
        let baseline = conn.stats().frame_rx.acks;
        tokio::time::sleep(MIGRATION_VALIDATION).await;
        let Some(conn_now) = session.connection() else {
            return;
        };
        if conn_now.stable_id() != conn.stable_id() {
            return;
        }
        let after = conn_now.stats().frame_rx.acks;
        if after == baseline {
            tracing::warn!(
                "Path migration: no ACKs in {MIGRATION_VALIDATION:?} — server likely dropped \
                 migrated packets; forcing reconnect"
            );
            session.kick_reconnect();
            fsm_registry.broadcast(Event::WakeKick).await;
        } else {
            tracing::debug!(
                "Path migration validated: {} new ACK(s) in {MIGRATION_VALIDATION:?}",
                after - baseline
            );
        }
    });
}

fn interesting(event: &if_watch::IfEvent, overlay: OverlayNet) -> bool {
    let net = match event {
        if_watch::IfEvent::Up(net) | if_watch::IfEvent::Down(net) => net,
    };
    match net.addr() {
        IpAddr::V4(v4) => is_interesting_ip(v4, None, overlay),
        IpAddr::V6(_) => false,
    }
}
