//! Metrics collection for mlsh-signal.
//!
//! Tracks relay bandwidth per (cluster_id, node_id) and exposes
//! all metrics in Prometheus text exposition format.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use tokio::sync::RwLock;

use crate::sessions::SessionStore;

struct NodeCounters {
    tx_bytes: AtomicU64,
    rx_bytes: AtomicU64,
}

pub struct Metrics {
    relay_counters: RwLock<HashMap<(String, String), Arc<NodeCounters>>>,
    sessions: Arc<SessionStore>,
}

impl Metrics {
    pub fn new(sessions: Arc<SessionStore>) -> Arc<Self> {
        Arc::new(Self {
            relay_counters: RwLock::new(HashMap::new()),
            sessions,
        })
    }

    /// Add bytes to a node's relay counters.
    pub async fn record_relay(&self, cluster_id: &str, node_id: &str, tx: u64, rx: u64) {
        let key = (cluster_id.to_string(), node_id.to_string());

        // Fast path: read lock
        {
            let counters = self.relay_counters.read().await;
            if let Some(c) = counters.get(&key) {
                c.tx_bytes.fetch_add(tx, Ordering::Relaxed);
                c.rx_bytes.fetch_add(rx, Ordering::Relaxed);
                return;
            }
        }

        // Slow path: write lock to insert
        let mut counters = self.relay_counters.write().await;
        let c = counters.entry(key).or_insert_with(|| {
            Arc::new(NodeCounters {
                tx_bytes: AtomicU64::new(0),
                rx_bytes: AtomicU64::new(0),
            })
        });
        c.tx_bytes.fetch_add(tx, Ordering::Relaxed);
        c.rx_bytes.fetch_add(rx, Ordering::Relaxed);
    }

    /// Export all metrics in Prometheus text exposition format.
    pub async fn prometheus(&self) -> String {
        let mut out = String::new();

        // -- Active sessions per cluster --
        let online = self.sessions.all_online_counts().await;
        if !online.is_empty() {
            out.push_str(
                "# HELP mlsh_signal_sessions_active Active sessions per cluster.\n\
                 # TYPE mlsh_signal_sessions_active gauge\n",
            );
            for (cluster_id, count) in &online {
                out.push_str(&format!(
                    "mlsh_signal_sessions_active{{cluster_id=\"{cluster_id}\"}} {count}\n",
                ));
            }
        }

        // -- Relay bandwidth per node --
        let counters = self.relay_counters.read().await;
        if !counters.is_empty() {
            out.push_str(
                "# HELP mlsh_signal_relay_bytes_total Total bytes relayed per node.\n\
                 # TYPE mlsh_signal_relay_bytes_total counter\n",
            );
            for ((cluster_id, node_id), c) in counters.iter() {
                let tx = c.tx_bytes.load(Ordering::Relaxed);
                let rx = c.rx_bytes.load(Ordering::Relaxed);
                out.push_str(&format!(
                    "mlsh_signal_relay_bytes_total{{cluster_id=\"{cluster_id}\",node_id=\"{node_id}\",direction=\"tx\"}} {tx}\n",
                ));
                out.push_str(&format!(
                    "mlsh_signal_relay_bytes_total{{cluster_id=\"{cluster_id}\",node_id=\"{node_id}\",direction=\"rx\"}} {rx}\n",
                ));
            }
        }

        out
    }
}
