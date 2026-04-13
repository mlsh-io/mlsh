//! Metrics collection for mlsh-signal.
//!
//! Tracks relay bandwidth per (cluster_id, node_id) in real-time
//! and exposes all metrics in Prometheus text exposition format.

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::AsyncWrite;
use tokio::sync::RwLock;

use crate::sessions::SessionStore;

/// Atomic byte counter shared between the relay writer and the metrics exporter.
pub struct Counter(AtomicU64);

impl Counter {
    fn new() -> Self {
        Self(AtomicU64::new(0))
    }

    pub fn add(&self, n: u64) {
        self.0.fetch_add(n, Ordering::Relaxed);
    }

    fn load(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

struct NodeCounters {
    tx: Arc<Counter>,
    rx: Arc<Counter>,
}

pub struct Metrics {
    counters: RwLock<HashMap<(String, String), NodeCounters>>,
    sessions: Arc<SessionStore>,
}

impl Metrics {
    pub fn new(sessions: Arc<SessionStore>) -> Arc<Self> {
        Arc::new(Self {
            counters: RwLock::new(HashMap::new()),
            sessions,
        })
    }

    /// Get or create counters for a node. Returns (tx, rx) counter handles.
    pub async fn node_counters(
        &self,
        cluster_id: &str,
        node_id: &str,
    ) -> (Arc<Counter>, Arc<Counter>) {
        let key = (cluster_id.to_string(), node_id.to_string());

        // Fast path
        {
            let map = self.counters.read().await;
            if let Some(c) = map.get(&key) {
                return (Arc::clone(&c.tx), Arc::clone(&c.rx));
            }
        }

        // Slow path
        let mut map = self.counters.write().await;
        let c = map.entry(key).or_insert_with(|| NodeCounters {
            tx: Arc::new(Counter::new()),
            rx: Arc::new(Counter::new()),
        });
        (Arc::clone(&c.tx), Arc::clone(&c.rx))
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
        let map = self.counters.read().await;
        if !map.is_empty() {
            out.push_str(
                "# HELP mlsh_signal_relay_bytes_total Total bytes relayed per node.\n\
                 # TYPE mlsh_signal_relay_bytes_total counter\n",
            );
            for ((cluster_id, node_id), c) in map.iter() {
                let tx = c.tx.load();
                let rx = c.rx.load();
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

/// Counts bytes for both sender TX and receiver RX in one write.
pub struct DualCounter(pub Arc<Counter>, pub Arc<Counter>);

impl DualCounter {
    fn add(&self, n: u64) {
        self.0.add(n); // sender TX
        self.1.add(n); // receiver RX
    }
}

/// An AsyncWrite wrapper that counts bytes written in real-time.
pub struct CountingWriter<W> {
    inner: W,
    counter: DualCounter,
}

impl<W> CountingWriter<W> {
    pub fn new(inner: W, counter: DualCounter) -> Self {
        Self { inner, counter }
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for CountingWriter<W> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &result {
            self.counter.add(*n as u64);
        }
        result
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
