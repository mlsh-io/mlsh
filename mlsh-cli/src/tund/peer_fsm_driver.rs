//! Async driver for the peer FSM in [`super::peer_fsm`]: executes effects as
//! spawned tasks and feeds their outcomes back as events.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use mlsh_protocol::types::PeerInfo;

use super::peer_table::PeerTable;
use super::probe::probe_candidates;
use super::relay_initiator::{run_relay_initiator, RelayInitiator};

const RELAY_GRACE: Duration = Duration::from_millis(200);
const PROBE_RETRY_INTERVAL: Duration = Duration::from_secs(60);

pub struct PeerConnectionContext {
    pub cancel: tokio_util::sync::CancellationToken,
    pub endpoint: quinn::Endpoint,
    pub peer: PeerInfo,
    pub peer_ip: Ipv4Addr,
    pub overlay_ip: Ipv4Addr,
    pub peer_table: PeerTable,
    pub device: Arc<tun_rs::AsyncDevice>,
    pub signal_conn: Option<quinn::Connection>,
    pub cluster_id: String,
    pub my_node_id: String,
    pub identity_dir: std::path::PathBuf,
    pub fsm_registry: super::peer_fsm::FsmRegistry,
}

pub async fn establish_peer_connection(ctx: PeerConnectionContext) {
    use super::peer_fsm::{initial_effects, transition, Effect, Event, State};

    let peer_ip = ctx.peer_ip;
    let is_initiator = ctx.overlay_ip < peer_ip;

    if !ctx.peer.candidates.is_empty() {
        let summary: Vec<String> = ctx
            .peer
            .candidates
            .iter()
            .map(|c| format!("{}:{}", c.kind, c.addr))
            .collect();
        tracing::info!(
            "Connecting to {} ({}) — candidates: [{}]",
            ctx.peer.node_id,
            peer_ip,
            summary.join(", ")
        );
    }

    let (events_tx, mut events_rx) = tokio::sync::mpsc::unbounded_channel::<Event>();
    ctx.fsm_registry.register(peer_ip, events_tx.clone()).await;

    let mut pending_direct_conn: Option<quinn::Connection> = None;
    let mut pending_relay_tx: Option<tokio::sync::mpsc::Sender<Vec<u8>>> = None;

    let mut probe_cancel = tokio_util::sync::CancellationToken::new();
    let mut relay_cancel = tokio_util::sync::CancellationToken::new();
    let mut direct_lifecycle: Option<tokio::task::JoinHandle<()>> = None;

    let probe_retry_ticker = {
        let ev = events_tx.clone();
        let cancel = ctx.cancel.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(PROBE_RETRY_INTERVAL);
            interval.tick().await; // skip the immediate first tick
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        if ev.send(Event::ProbeRetryTick).is_err() {
                            break;
                        }
                    }
                    _ = cancel.cancelled() => break,
                }
            }
        })
    };

    let mut state = State::Probing;
    let mut effects_to_run = initial_effects(is_initiator);

    'outer: loop {
        for effect in effects_to_run.drain(..) {
            match effect {
                Effect::SpawnProbe => {
                    if ctx.peer.candidates.is_empty() {
                        let _ = events_tx.send(Event::ProbeFailed);
                        continue;
                    }
                    probe_cancel = tokio_util::sync::CancellationToken::new();
                    let endpoint = ctx.endpoint.clone();
                    let candidates = ctx.peer.candidates.clone();
                    let fp = ctx.peer.fingerprint.clone();
                    let id_dir = ctx.identity_dir.clone();
                    let ev = events_tx.clone();
                    let cancel = probe_cancel.clone();
                    let peer_ip_copy = peer_ip;
                    let peer_node_id = ctx.peer.node_id.clone();
                    tokio::spawn(async move {
                        let result = tokio::select! {
                            r = probe_candidates(&endpoint, &candidates, &fp, &id_dir) => r,
                            _ = cancel.cancelled() => return,
                        };
                        match result {
                            Ok(probe) => {
                                tracing::info!(
                                    "Direct connection to {} ({}) via {}",
                                    peer_node_id,
                                    peer_ip_copy,
                                    probe.via
                                );
                                let _ = ev.send(Event::__ProbeSucceededWith(Box::new(probe.conn)));
                            }
                            Err(e) => {
                                tracing::debug!("Direct to {} failed: {}", peer_node_id, e);
                                let _ = ev.send(Event::ProbeFailed);
                            }
                        }
                    });
                }

                Effect::StartRelayGraceTimer => {
                    let ev = events_tx.clone();
                    let cancel = ctx.cancel.clone();
                    tokio::spawn(async move {
                        tokio::select! {
                            _ = tokio::time::sleep(RELAY_GRACE) => {
                                let _ = ev.send(Event::RelayGraceElapsed);
                            }
                            _ = cancel.cancelled() => {}
                        }
                    });
                }

                Effect::InitiateRelay => {
                    let Some(signal_conn) = ctx.signal_conn.clone() else {
                        tracing::warn!("No signal connection for relay to {}", ctx.peer.node_id);
                        continue;
                    };
                    relay_cancel = tokio_util::sync::CancellationToken::new();
                    let r = RelayInitiator {
                        signal_conn,
                        cluster_id: ctx.cluster_id.clone(),
                        my_node_id: ctx.my_node_id.clone(),
                        peer_node_id: ctx.peer.node_id.clone(),
                        peer_fingerprint: ctx.peer.fingerprint.clone(),
                        identity_dir: ctx.identity_dir.clone(),
                        device: ctx.device.clone(),
                        peer_table: ctx.peer_table.clone(),
                        events_tx: events_tx.clone(),
                        cancel: relay_cancel.clone(),
                    };
                    tokio::spawn(async move {
                        run_relay_initiator(r).await;
                    });
                }

                Effect::InsertDirectRoute => {
                    if let Some(conn) = pending_direct_conn.take() {
                        ctx.peer_table.insert_direct(peer_ip, conn.clone()).await;
                        let dev = ctx.device.clone();
                        let pt = ctx.peer_table.clone();
                        let cancel = ctx.cancel.clone();
                        let ev = events_tx.clone();
                        direct_lifecycle = Some(tokio::spawn(async move {
                            tokio::select! {
                                _ = super::quic_server::run_inbound(conn, &dev, &pt) => {}
                                _ = cancel.cancelled() => {}
                            }
                            let _ = ev.send(Event::DirectConnectionLost);
                        }));
                    }
                }

                Effect::InsertRelayRoute => {
                    if let Some(tx) = pending_relay_tx.take() {
                        ctx.peer_table.insert_relay(peer_ip, tx).await;
                    }
                }

                Effect::RemoveRoute => {
                    ctx.peer_table.remove_route(peer_ip).await;
                }

                Effect::RemoveRelayOnly => {
                    if ctx.peer_table.remove_relay_only(peer_ip).await {
                        tracing::info!("Relay to {} ended", ctx.peer.node_id);
                    } else {
                        tracing::debug!(
                            "Relay to {} ended, keeping active direct route",
                            ctx.peer.node_id
                        );
                    }
                }

                Effect::AbortRelayTask => relay_cancel.cancel(),
                Effect::AbortProbeTask => probe_cancel.cancel(),
                Effect::LogDirect => {} // already logged when the probe succeeded
                Effect::LogRelay => {}  // logged by run_relay_initiator
            }
        }

        if state == State::Done {
            break 'outer;
        }

        let event = tokio::select! {
            maybe = events_rx.recv() => match maybe {
                Some(e) => e,
                None => break 'outer,
            },
            _ = ctx.cancel.cancelled() => Event::Cancelled,
        };

        // Carrier variants hand runtime handles to the driver, then the
        // pure equivalent is passed to `transition`.
        let fsm_event = match event {
            Event::__ProbeSucceededWith(conn) => {
                pending_direct_conn = Some(*conn);
                Event::ProbeSucceeded
            }
            Event::__RelayReadyWith(tx) => {
                pending_relay_tx = Some(*tx);
                Event::RelayReady
            }
            other => other,
        };

        let (new_state, new_effects) = transition(state, fsm_event, is_initiator);
        state = new_state;
        effects_to_run = new_effects;
    }

    probe_cancel.cancel();
    relay_cancel.cancel();
    probe_retry_ticker.abort();
    if let Some(h) = direct_lifecycle {
        h.abort();
    }
    ctx.fsm_registry.unregister(peer_ip).await;
}
