//! State machine coordinating the direct QUIC probe and the relay fallback
//! for a peer connection. `transition` is pure; the async driver in
//! [`super::tunnel`] turns `Effect`s into spawned tasks and task outcomes
//! into `Event`s.

use std::collections::HashMap;
use std::fmt;
use std::net::Ipv4Addr;
use std::sync::Arc;

use tokio::sync::{mpsc, Mutex};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Probing,
    RelayWithProbing,
    Relay,
    Direct,
    Done,
}

#[derive(Debug)]
pub enum Event {
    ProbeSucceeded,
    ProbeFailed,
    RelayReady,
    RelayGraceElapsed,
    DirectConnectionLost,
    RelayClosed,
    PeerLeft,
    Cancelled,
    WakeKick,

    // Carrier variants: smuggle handles from I/O tasks to the driver. The
    // driver stashes the payload and feeds the matching pure variant to
    // `transition`.
    #[doc(hidden)]
    __ProbeSucceededWith(Box<quinn::Connection>),
    #[doc(hidden)]
    __RelayReadyWith(Box<tokio::sync::mpsc::Sender<Vec<u8>>>),
}

impl PartialEq for Event {
    fn eq(&self, other: &Self) -> bool {
        use Event::*;
        matches!(
            (self, other),
            (ProbeSucceeded, ProbeSucceeded)
                | (ProbeFailed, ProbeFailed)
                | (RelayReady, RelayReady)
                | (RelayGraceElapsed, RelayGraceElapsed)
                | (DirectConnectionLost, DirectConnectionLost)
                | (RelayClosed, RelayClosed)
                | (PeerLeft, PeerLeft)
                | (Cancelled, Cancelled)
                | (WakeKick, WakeKick)
        )
    }
}
impl Eq for Event {}

impl Clone for Event {
    fn clone(&self) -> Self {
        match self {
            Event::ProbeSucceeded => Event::ProbeSucceeded,
            Event::ProbeFailed => Event::ProbeFailed,
            Event::RelayReady => Event::RelayReady,
            Event::RelayGraceElapsed => Event::RelayGraceElapsed,
            Event::DirectConnectionLost => Event::DirectConnectionLost,
            Event::RelayClosed => Event::RelayClosed,
            Event::PeerLeft => Event::PeerLeft,
            Event::Cancelled => Event::Cancelled,
            Event::WakeKick => Event::WakeKick,
            Event::__ProbeSucceededWith(_) | Event::__RelayReadyWith(_) => {
                panic!("carrier Event variants are not Clone-able")
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Effect {
    SpawnProbe,
    StartRelayGraceTimer,
    InitiateRelay,
    /// Must precede `AbortRelayTask` so the route table swap is atomic.
    InsertDirectRoute,
    InsertRelayRoute,
    RemoveRoute,
    /// Removes a relay only if it has not been replaced by a direct route.
    RemoveRelayOnly,
    AbortRelayTask,
    AbortProbeTask,
    LogDirect,
    LogRelay,
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

/// `is_initiator` is true for the peer with the lower overlay IP; it opens
/// the relay stream. The higher-IP peer receives the relay via
/// `handle_incoming_relay` instead.
pub fn transition(state: State, event: Event, is_initiator: bool) -> (State, Vec<Effect>) {
    use Effect::*;
    use Event::*;
    use State::*;

    match (state, event) {
        (Probing, ProbeSucceeded) => (Direct, vec![InsertDirectRoute, LogDirect]),
        (Probing, ProbeFailed) => (Probing, vec![]),
        (Probing, RelayGraceElapsed) if is_initiator => (Probing, vec![InitiateRelay]),
        (Probing, RelayGraceElapsed) => (Probing, vec![]),
        (Probing, RelayReady) => (RelayWithProbing, vec![InsertRelayRoute, LogRelay]),

        (RelayWithProbing, ProbeSucceeded) => {
            (Direct, vec![InsertDirectRoute, AbortRelayTask, LogDirect])
        }
        (RelayWithProbing, ProbeFailed) => (Relay, vec![]),
        (RelayWithProbing, RelayClosed) => (Probing, vec![RemoveRelayOnly]),

        (Relay, RelayClosed) => (Done, vec![RemoveRelayOnly]),
        (Relay, ProbeSucceeded) => (Direct, vec![InsertDirectRoute, AbortRelayTask, LogDirect]),

        (Direct, DirectConnectionLost) => (Done, vec![RemoveRoute]),
        (Direct, RelayClosed) => (Direct, vec![]),

        (Probing, WakeKick) => (Probing, vec![AbortProbeTask, SpawnProbe]),
        (RelayWithProbing, WakeKick) => (
            Probing,
            vec![AbortProbeTask, AbortRelayTask, RemoveRelayOnly, SpawnProbe],
        ),
        (Relay, WakeKick) => (Probing, vec![AbortRelayTask, RemoveRelayOnly, SpawnProbe]),
        (Direct, WakeKick) => (Done, vec![RemoveRoute]),

        (_, PeerLeft) | (_, Cancelled) => (Done, vec![AbortProbeTask, AbortRelayTask, RemoveRoute]),

        (s, _) => (s, vec![]),
    }
}

/// Per-peer FSM event senders, keyed by overlay IP.
#[derive(Clone, Default)]
pub struct FsmRegistry {
    inner: Arc<Mutex<HashMap<Ipv4Addr, mpsc::UnboundedSender<Event>>>>,
}

impl FsmRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn register(&self, ip: Ipv4Addr, tx: mpsc::UnboundedSender<Event>) {
        self.inner.lock().await.insert(ip, tx);
    }

    pub async fn unregister(&self, ip: Ipv4Addr) {
        self.inner.lock().await.remove(&ip);
    }

    pub async fn notify(&self, ip: Ipv4Addr, event: Event) {
        if let Some(tx) = self.inner.lock().await.get(&ip) {
            let _ = tx.send(event);
        }
    }

    pub async fn broadcast(&self, event: Event) {
        let inner = self.inner.lock().await;
        for tx in inner.values() {
            let _ = tx.send(event.clone());
        }
    }
}

pub fn initial_effects(is_initiator: bool) -> Vec<Effect> {
    let mut v = vec![Effect::SpawnProbe];
    if is_initiator {
        v.push(Effect::StartRelayGraceTimer);
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_succeeds_from_probing_goes_direct() {
        let (state, effects) = transition(State::Probing, Event::ProbeSucceeded, true);
        assert_eq!(state, State::Direct);
        assert_eq!(effects, vec![Effect::InsertDirectRoute, Effect::LogDirect]);
    }

    #[test]
    fn probe_succeeds_during_relay_performs_atomic_upgrade() {
        // InsertDirectRoute must precede AbortRelayTask to keep the route
        // swap atomic.
        let (state, effects) = transition(State::RelayWithProbing, Event::ProbeSucceeded, true);
        assert_eq!(state, State::Direct);
        assert_eq!(
            effects,
            vec![
                Effect::InsertDirectRoute,
                Effect::AbortRelayTask,
                Effect::LogDirect,
            ]
        );
    }

    #[test]
    fn probe_fails_from_relay_with_probing_demotes_to_relay() {
        let (state, effects) = transition(State::RelayWithProbing, Event::ProbeFailed, true);
        assert_eq!(state, State::Relay);
        assert!(effects.is_empty());
    }

    #[test]
    fn relay_closed_removes_relay_only() {
        let (state, effects) = transition(State::Relay, Event::RelayClosed, true);
        assert_eq!(state, State::Done);
        assert_eq!(effects, vec![Effect::RemoveRelayOnly]);
    }

    #[test]
    fn relay_close_after_upgrade_is_noop_on_direct() {
        let (state, effects) = transition(State::Direct, Event::RelayClosed, true);
        assert_eq!(state, State::Direct);
        assert!(effects.is_empty());
    }

    #[test]
    fn peer_left_from_any_state_terminates_cleanly() {
        for start in [
            State::Probing,
            State::Relay,
            State::RelayWithProbing,
            State::Direct,
        ] {
            let (state, effects) = transition(start, Event::PeerLeft, true);
            assert_eq!(state, State::Done);
            assert_eq!(
                effects,
                vec![
                    Effect::AbortProbeTask,
                    Effect::AbortRelayTask,
                    Effect::RemoveRoute,
                ]
            );
        }
    }

    #[test]
    fn relay_grace_on_initiator_triggers_initiate_relay() {
        let (state, effects) = transition(State::Probing, Event::RelayGraceElapsed, true);
        assert_eq!(state, State::Probing);
        assert_eq!(effects, vec![Effect::InitiateRelay]);
    }

    #[test]
    fn relay_grace_on_non_initiator_is_noop() {
        let (state, effects) = transition(State::Probing, Event::RelayGraceElapsed, false);
        assert_eq!(state, State::Probing);
        assert!(effects.is_empty());
    }

    #[test]
    fn relay_ready_inserts_and_transitions_to_relay_with_probing() {
        let (state, effects) = transition(State::Probing, Event::RelayReady, false);
        assert_eq!(state, State::RelayWithProbing);
        assert_eq!(effects, vec![Effect::InsertRelayRoute, Effect::LogRelay]);
    }

    #[test]
    fn direct_lost_cleans_up_route() {
        let (state, effects) = transition(State::Direct, Event::DirectConnectionLost, true);
        assert_eq!(state, State::Done);
        assert_eq!(effects, vec![Effect::RemoveRoute]);
    }

    #[test]
    fn probe_failed_from_probing_stays_probing() {
        let (state, effects) = transition(State::Probing, Event::ProbeFailed, true);
        assert_eq!(state, State::Probing);
        assert!(effects.is_empty());
    }

    #[test]
    fn cancelled_terminates_like_peer_left() {
        for start in [
            State::Probing,
            State::Relay,
            State::RelayWithProbing,
            State::Direct,
        ] {
            let (state, effects_peer_left) = transition(start, Event::PeerLeft, true);
            let (state2, effects_cancelled) = transition(start, Event::Cancelled, true);
            assert_eq!(state, state2);
            assert_eq!(effects_peer_left, effects_cancelled);
        }
    }

    #[test]
    fn initial_effects_include_probe() {
        assert!(initial_effects(true).contains(&Effect::SpawnProbe));
        assert!(initial_effects(false).contains(&Effect::SpawnProbe));
    }

    #[test]
    fn initial_effects_grace_timer_only_for_initiator() {
        assert!(initial_effects(true).contains(&Effect::StartRelayGraceTimer));
        assert!(!initial_effects(false).contains(&Effect::StartRelayGraceTimer));
    }

    #[test]
    fn terminal_state_is_sticky() {
        for event in [
            Event::ProbeSucceeded,
            Event::ProbeFailed,
            Event::RelayReady,
            Event::RelayClosed,
            Event::DirectConnectionLost,
            Event::WakeKick,
        ] {
            let (state, _) = transition(State::Done, event, true);
            assert_eq!(state, State::Done);
        }
    }

    #[test]
    fn wake_kick_from_probing_restarts_probe() {
        let (state, effects) = transition(State::Probing, Event::WakeKick, true);
        assert_eq!(state, State::Probing);
        assert_eq!(effects, vec![Effect::AbortProbeTask, Effect::SpawnProbe]);
    }

    #[test]
    fn wake_kick_from_relay_with_probing_resets_everything() {
        let (state, effects) = transition(State::RelayWithProbing, Event::WakeKick, true);
        assert_eq!(state, State::Probing);
        assert_eq!(
            effects,
            vec![
                Effect::AbortProbeTask,
                Effect::AbortRelayTask,
                Effect::RemoveRelayOnly,
                Effect::SpawnProbe,
            ]
        );
    }

    #[test]
    fn wake_kick_from_relay_tears_down_and_probes() {
        let (state, effects) = transition(State::Relay, Event::WakeKick, true);
        assert_eq!(state, State::Probing);
        assert_eq!(
            effects,
            vec![
                Effect::AbortRelayTask,
                Effect::RemoveRelayOnly,
                Effect::SpawnProbe,
            ]
        );
    }

    #[test]
    fn wake_kick_from_direct_exits_to_let_manager_respawn() {
        let (state, effects) = transition(State::Direct, Event::WakeKick, true);
        assert_eq!(state, State::Done);
        assert_eq!(effects, vec![Effect::RemoveRoute]);
    }

    #[test]
    fn wake_kick_on_non_initiator_still_restarts_probe() {
        let (state, effects) = transition(State::Relay, Event::WakeKick, false);
        assert_eq!(state, State::Probing);
        assert_eq!(
            effects,
            vec![
                Effect::AbortRelayTask,
                Effect::RemoveRelayOnly,
                Effect::SpawnProbe,
            ]
        );
    }
}
