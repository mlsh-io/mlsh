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

    tracing::info!("net_watcher started");

    async fn next_event(watcher: &mut if_watch::tokio::IfWatcher) -> Option<if_watch::IfEvent> {
        poll_fn(|cx| watcher.poll_if_event(cx))
            .await
            .map_err(|e| tracing::warn!("if-watch error: {e}"))
            .ok()
    }

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
    match super::endpoint_migrate::try_migrate(endpoint) {
        Ok(new_port) => {
            session.report_candidates(new_port);
        }
        Err(e) => {
            tracing::warn!("Path migration failed to rebind ({e:#}); falling back to reconnect");
            session.kick_reconnect();
            fsm_registry.broadcast(Event::WakeKick).await;
        }
    }
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
