//! Fork the `mlsh-control` child process for nodes holding the `control` role
//! (ADR-030).

/// Spawn `mlsh-control` for the given cluster, re-exec'ing the current binary
/// with `MLSH_RUN_AS=control`. Returns `None` if the spawn fails — the daemon
/// keeps running without the admin UI.
pub fn spawn_control_child(cluster: &str) -> Option<tokio::process::Child> {
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, "current_exe() failed; mlsh-control not spawned");
            return None;
        }
    };

    let mut cmd = tokio::process::Command::new(&exe);
    cmd.env("MLSH_RUN_AS", "control")
        .env("MLSH_CONTROL_CLUSTER", cluster)
        .kill_on_drop(true);

    match cmd.spawn() {
        Ok(child) => {
            tracing::info!(cluster, exe = %exe.display(), "mlsh-control forked");
            Some(child)
        }
        Err(e) => {
            tracing::warn!(error = %e, "Failed to spawn mlsh-control; admin UI unavailable");
            None
        }
    }
}
