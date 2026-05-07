//! Singleton handle to the daemon's `TunnelManager`. Set once by
//! `daemon::run` so in-process tasks (the control HTTP plane) can call
//! `mgr.expose(...)` without needing the manager threaded through every
//! call site. Same pattern as `ingress::targets()` / `acme` registries.

use std::sync::{Arc, OnceLock};

use tokio::sync::Mutex;

use super::tunnel_manager::TunnelManager;

static MANAGER: OnceLock<Arc<Mutex<TunnelManager>>> = OnceLock::new();

pub fn set(manager: Arc<Mutex<TunnelManager>>) {
    let _ = MANAGER.set(manager);
}

pub fn get() -> Option<Arc<Mutex<TunnelManager>>> {
    MANAGER.get().cloned()
}
