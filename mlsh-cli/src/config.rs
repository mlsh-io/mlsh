use anyhow::{Context, Result};
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

/// Canonical user config directory: ~/.config/mlsh/
/// Used by CLI commands (setup, adopt, connect --foreground, invite, etc.)
pub fn config_dir() -> Result<PathBuf> {
    let dir = dirs::home_dir()
        .context("Failed to determine home directory")?
        .join(".config")
        .join("mlsh");
    fs::create_dir_all(&dir).context("Failed to create mlsh config directory")?;
    Ok(dir)
}

/// Daemon state directory: /var/lib/mlsh/
/// Used by mlshtund (root) to persist cluster configs and identity received from CLI.
/// Independent of HOME — works correctly when running as a system service.
pub fn daemon_state_dir() -> Result<PathBuf> {
    let dir = PathBuf::from("/var/lib/mlsh");
    fs::create_dir_all(&dir).context("Failed to create daemon state directory /var/lib/mlsh")?;
    #[cfg(unix)]
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).ok();
    Ok(dir)
}

/// mlsh-control state subdirectory: /var/lib/mlsh/control/
/// Hosts the sqlite DB, session/MFA keys, mode + first-admin markers, and the
/// control-plane Unix socket. All daemon-side state lives under daemon_state_dir(),
/// so the systemd unit only needs to grant one ReadWritePaths/StateDirectory.
///
/// Returns the path without creating it; callers create_dir_all() before writing.
pub fn control_data_dir() -> PathBuf {
    PathBuf::from("/var/lib/mlsh/control")
}
