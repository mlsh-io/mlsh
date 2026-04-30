//! Server-side fanout for `Subscribe` streams on mlsh-control.
//!
//! Each connected subscriber owns a bounded mpsc channel. Publishers (the
//! request handlers in `stream.rs`) call [`EventHub::publish`] on every
//! mutation; the subscriber loop drains its channel and writes events to its
//! `SendStream`. Subscribers that fall behind (channel full) are dropped on
//! the spot — they reconnect and reseed via `ListNodes` (see ADR 018).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use mlsh_protocol::control::ControlEvent;
use tokio::sync::{mpsc, Mutex};

/// Bounded buffer per subscriber. Past this, the slow consumer is dropped.
const SUBSCRIBER_BUFFER: usize = 256;

/// One subscriber's outbound queue, scoped to a cluster.
struct Subscriber {
    cluster_key: String,
    tx: mpsc::Sender<Arc<ControlEvent>>,
}

#[derive(Default)]
struct Inner {
    next_id: AtomicU64,
    subscribers: Mutex<Vec<(u64, Subscriber)>>,
}

/// Multi-producer fanout to all `Subscribe` clients of a given cluster.
#[derive(Clone, Default)]
pub struct EventHub {
    inner: Arc<Inner>,
}

impl EventHub {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new subscriber. The returned receiver must be drained by the
    /// caller; the [`SubscriberHandle`] auto-deregisters on drop.
    pub async fn register(&self, cluster_key: &str) -> (SubscriberHandle, SubscriberRx) {
        let (tx, rx) = mpsc::channel(SUBSCRIBER_BUFFER);
        let id = self.inner.next_id.fetch_add(1, Ordering::Relaxed);
        let sub = Subscriber {
            cluster_key: cluster_key.to_string(),
            tx,
        };
        self.inner.subscribers.lock().await.push((id, sub));
        let handle = SubscriberHandle {
            id,
            inner: self.inner.clone(),
        };
        (handle, SubscriberRx { rx })
    }

    /// Fan an event out to every subscriber of `cluster_key`. Returns the
    /// number of receivers that accepted the event. Subscribers whose buffer
    /// is full are evicted in the same pass.
    pub async fn publish(&self, cluster_key: &str, event: ControlEvent) -> usize {
        let event = Arc::new(event);
        let mut subs = self.inner.subscribers.lock().await;
        let mut delivered = 0usize;
        subs.retain(|(_, sub)| {
            if sub.cluster_key != cluster_key {
                return true;
            }
            match sub.tx.try_send(Arc::clone(&event)) {
                Ok(()) => {
                    delivered += 1;
                    true
                }
                Err(mpsc::error::TrySendError::Full(_)) => {
                    tracing::warn!(
                        cluster = %sub.cluster_key,
                        "control: dropping slow subscriber (buffer full); client will reseed on reconnect"
                    );
                    false
                }
                Err(mpsc::error::TrySendError::Closed(_)) => false,
            }
        });
        delivered
    }
}

/// RAII guard that removes the subscriber from the hub on drop.
pub struct SubscriberHandle {
    id: u64,
    inner: Arc<Inner>,
}

impl Drop for SubscriberHandle {
    fn drop(&mut self) {
        let inner = self.inner.clone();
        let id = self.id;
        // Best-effort cleanup; the publisher's `retain` also evicts closed
        // channels, so a missed deregister just delays cleanup by one publish.
        tokio::spawn(async move {
            inner.subscribers.lock().await.retain(|(sid, _)| *sid != id);
        });
    }
}

/// Receiver side of a subscriber registration.
pub struct SubscriberRx {
    rx: mpsc::Receiver<Arc<ControlEvent>>,
}

impl SubscriberRx {
    pub async fn recv(&mut self) -> Option<Arc<ControlEvent>> {
        self.rx.recv().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn publish_reaches_only_matching_cluster() {
        let hub = EventHub::new();
        let (_h1, mut rx1) = hub.register("auriol").await;
        let (_h2, mut rx2) = hub.register("other").await;

        let n = hub
            .publish(
                "auriol",
                ControlEvent::NodeRenamed {
                    node_uuid: "u".into(),
                    new_display_name: "macbook".into(),
                },
            )
            .await;
        assert_eq!(n, 1);

        let received = rx1.recv().await.unwrap();
        assert!(matches!(&*received, ControlEvent::NodeRenamed { .. }));

        // Other-cluster subscriber must not receive.
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), rx2.recv())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn slow_subscriber_dropped_when_buffer_fills() {
        let hub = EventHub::new();
        let (_h, _rx) = hub.register("auriol").await;
        // Don't drain rx — fill the buffer past SUBSCRIBER_BUFFER.
        for _ in 0..(SUBSCRIBER_BUFFER + 8) {
            hub.publish(
                "auriol",
                ControlEvent::NodeLeft {
                    node_uuid: "u".into(),
                },
            )
            .await;
        }
        // After overflowing, publishing once more must report 0 deliveries —
        // the subscriber has been evicted.
        let n = hub
            .publish(
                "auriol",
                ControlEvent::NodeLeft {
                    node_uuid: "u".into(),
                },
            )
            .await;
        assert_eq!(n, 0);
    }

    #[tokio::test]
    async fn handle_drop_deregisters() {
        let hub = EventHub::new();
        {
            let (_h, _rx) = hub.register("auriol").await;
        }
        // Give the spawned cleanup a beat to run.
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let n = hub
            .publish(
                "auriol",
                ControlEvent::NodeLeft {
                    node_uuid: "u".into(),
                },
            )
            .await;
        assert_eq!(n, 0);
    }
}
