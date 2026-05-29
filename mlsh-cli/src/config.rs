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

/// Machine-wide daemon state root.
/// - Unix: `/var/lib/mlsh`
/// - Windows: `%ProgramData%\mlsh` (e.g. `C:\ProgramData\mlsh`)
///
/// Independent of HOME/USERPROFILE so it resolves to a stable, machine-wide
/// location even when mlshtund runs as a system service (LocalSystem on
/// Windows, where a user profile is unavailable).
fn daemon_state_root() -> PathBuf {
    #[cfg(windows)]
    {
        let base = std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".to_string());
        PathBuf::from(base).join("mlsh")
    }
    #[cfg(not(windows))]
    {
        PathBuf::from("/var/lib/mlsh")
    }
}

/// Daemon state directory.
/// Used by mlshtund to persist cluster configs and identity received from CLI.
pub fn daemon_state_dir() -> Result<PathBuf> {
    let dir = daemon_state_root();
    fs::create_dir_all(&dir)
        .with_context(|| format!("Failed to create daemon state directory {}", dir.display()))?;
    // On Windows the directory inherits ProgramData's ACL (SYSTEM + Administrators
    // full control), which is the appropriate machine-wide scope.
    #[cfg(unix)]
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).ok();
    Ok(dir)
}

/// mlsh-control state subdirectory (`<state_dir>/control/`).
/// Hosts the sqlite DB, session/MFA keys, mode + first-admin markers, and the
/// control-plane Unix socket. All daemon-side state lives under daemon_state_dir(),
/// so the systemd unit only needs to grant one ReadWritePaths/StateDirectory.
///
/// Returns the path without creating it; callers create_dir_all() before writing.
pub fn control_data_dir() -> PathBuf {
    daemon_state_root().join("control")
}
