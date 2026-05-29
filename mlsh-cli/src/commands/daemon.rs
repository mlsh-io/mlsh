//! `mlsh tunnel` — install/uninstall the `mlshtund` tunnel daemon as a system service.
//!
//! - macOS: LaunchDaemon plist at /Library/LaunchDaemons/io.mlsh.tund.plist
//! - Linux: systemd system unit at /etc/systemd/system/mlshtund.service

#[cfg(any(target_os = "macos", target_os = "linux", windows))]
use anyhow::Context;
use anyhow::Result;
use clap::Subcommand;
#[cfg(any(target_os = "macos", target_os = "linux", windows))]
use colored::Colorize;

#[derive(Subcommand)]
pub enum DaemonCommands {
    /// Install mlshtund as a system daemon
    Install,

    /// Uninstall the mlshtund daemon
    Uninstall,

    /// Show daemon installation status
    Status,
}

pub async fn handle(cmd: DaemonCommands) -> Result<()> {
    match cmd {
        DaemonCommands::Install => install_daemon(),
        DaemonCommands::Uninstall => uninstall_daemon(),
        DaemonCommands::Status => daemon_status(),
    }
}

// --- macOS (launchd)

#[cfg(target_os = "macos")]
const PLIST_PATH: &str = "/Library/LaunchDaemons/io.mlsh.tund.plist";

#[cfg(target_os = "macos")]
const LABEL: &str = "io.mlsh.tund";

#[cfg(target_os = "macos")]
fn install_daemon() -> Result<()> {
    let mlshtund_bin = std::env::current_exe()
        .context("Failed to determine binary path")?
        .parent()
        .context("No parent dir")?
        .join("mlshtund");
    let bin_path = mlshtund_bin.to_string_lossy();

    let log_dir = "/var/log/mlsh";
    std::fs::create_dir_all(log_dir).ok();

    let args_xml = format!(
        "    <array>\n        <string>{}</string>\n    </array>",
        bin_path
    );

    let plist = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{label}</string>
    <key>ProgramArguments</key>
{args}
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>{log_dir}/mlshtund.log</string>
    <key>StandardErrorPath</key>
    <string>{log_dir}/mlshtund.err</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>RUST_LOG</key>
        <string>mlsh_cli=info</string>
    </dict>
</dict>
</plist>
"#,
        label = LABEL,
        args = args_xml,
        log_dir = log_dir,
    );

    let plist_path = std::path::Path::new(PLIST_PATH);
    if plist_path.exists() {
        let _ = std::process::Command::new("launchctl")
            .args(["unload", PLIST_PATH])
            .output();
    }

    std::fs::write(PLIST_PATH, &plist).context(format!(
        "Failed to write plist to {}. Try running with sudo.",
        PLIST_PATH
    ))?;

    let output = std::process::Command::new("launchctl")
        .args(["load", PLIST_PATH])
        .output()
        .context("Failed to run launchctl load")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("launchctl load failed: {}", stderr);
    }

    println!("{}", "mlshtund daemon installed!".green().bold());
    println!("  Plist: {}", PLIST_PATH);
    println!("  Logs:  {}/mlshtund.log", log_dir);
    println!();
    println!("The daemon runs at boot and reconnects every cluster you have");
    println!("connected at least once. Use 'mlsh connect <cluster>' to add one.");
    println!("To uninstall: {}", "sudo mlsh tunnel uninstall".bold());

    Ok(())
}

#[cfg(target_os = "macos")]
fn uninstall_daemon() -> Result<()> {
    let plist_path = std::path::Path::new(PLIST_PATH);
    if !plist_path.exists() {
        anyhow::bail!("Daemon not installed (no plist at {})", PLIST_PATH);
    }

    let output = std::process::Command::new("launchctl")
        .args(["unload", PLIST_PATH])
        .output()
        .context("Failed to run launchctl unload")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        eprintln!("Warning: launchctl unload: {}", stderr);
    }

    std::fs::remove_file(PLIST_PATH).context("Failed to remove plist file")?;

    println!("{}", "Tunnel daemon uninstalled.".green().bold());
    Ok(())
}

#[cfg(target_os = "macos")]
fn daemon_status() -> Result<()> {
    let plist_path = std::path::Path::new(PLIST_PATH);
    if !plist_path.exists() {
        println!("{}", "Daemon not installed.".yellow());
        return Ok(());
    }

    let output = std::process::Command::new("launchctl")
        .args(["list", LABEL])
        .output()
        .context("Failed to run launchctl list")?;

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        println!("{}", "Daemon installed and registered.".green().bold());
        // Parse PID from launchctl output
        for line in stdout.lines() {
            if line.contains("PID") || line.starts_with('{') {
                continue;
            }
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 {
                let pid = parts[0];
                let status = parts[1];
                println!("  PID:    {}", if pid == "-" { "not running" } else { pid });
                println!("  Status: {}", status);
            }
        }
    } else {
        println!("{}", "Daemon installed but not loaded.".yellow());
        println!(
            "  Load with: {}",
            format!("sudo launchctl load {}", PLIST_PATH).bold()
        );
    }

    Ok(())
}

// --- Linux (systemd)

#[cfg(target_os = "linux")]
const SERVICE_PATH: &str = "/etc/systemd/system/mlshtund.service";

#[cfg(target_os = "linux")]
fn install_daemon() -> Result<()> {
    let mlshtund_bin = std::env::current_exe()
        .context("Failed to determine binary path")?
        .parent()
        .context("No parent dir")?
        .join("mlshtund");
    let bin_path = mlshtund_bin.to_string_lossy();

    let exec_start = bin_path.to_string();

    let unit = format!(
        r#"[Unit]
Description=MLSH Tunnel Daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={exec_start}
Restart=on-failure
RestartSec=5
Environment=RUST_LOG=mlsh_cli=info

[Install]
WantedBy=multi-user.target
"#,
        exec_start = exec_start,
    );

    std::fs::write(SERVICE_PATH, &unit).context(format!(
        "Failed to write {}. Try running with sudo.",
        SERVICE_PATH
    ))?;

    let _ = std::process::Command::new("systemctl")
        .args(["daemon-reload"])
        .output();

    let output = std::process::Command::new("systemctl")
        .args(["enable", "--now", "mlshtund.service"])
        .output()
        .context("Failed to enable systemd service")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        eprintln!("Warning: systemctl enable: {}", stderr);
    }

    println!("{}", "mlshtund daemon installed!".green().bold());
    println!("  Unit: {}", SERVICE_PATH);
    println!();
    println!("The daemon runs at boot and reconnects every cluster you have");
    println!("connected at least once. Use 'mlsh connect <cluster>' to add one.");
    println!("To check: {}", "systemctl status mlshtund".bold());
    println!("To uninstall: {}", "sudo mlsh tunnel uninstall".bold());

    Ok(())
}

#[cfg(target_os = "linux")]
fn uninstall_daemon() -> Result<()> {
    let service_path = std::path::Path::new(SERVICE_PATH);
    if !service_path.exists() {
        anyhow::bail!("Daemon not installed (no unit at {})", SERVICE_PATH);
    }

    let _ = std::process::Command::new("systemctl")
        .args(["disable", "--now", "mlshtund.service"])
        .output();

    std::fs::remove_file(service_path)?;

    let _ = std::process::Command::new("systemctl")
        .args(["daemon-reload"])
        .output();

    println!("{}", "mlshtund daemon uninstalled.".green().bold());
    Ok(())
}

#[cfg(target_os = "linux")]
fn daemon_status() -> Result<()> {
    let service_path = std::path::Path::new(SERVICE_PATH);
    if !service_path.exists() {
        println!("{}", "Daemon not installed.".yellow());
        return Ok(());
    }

    let output = std::process::Command::new("systemctl")
        .args(["status", "mlshtund.service"])
        .output()
        .context("Failed to run systemctl status")?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    println!("{}", stdout);

    Ok(())
}

// --- Windows (Service Control Manager)

#[cfg(windows)]
fn install_daemon() -> Result<()> {
    use std::ffi::{OsStr, OsString};

    use windows_service::service::{
        ServiceAccess, ServiceErrorControl, ServiceInfo, ServiceStartType, ServiceState,
        ServiceType,
    };
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

    use crate::tund::service_windows::{SERVICE_DISPLAY_NAME, SERVICE_NAME};

    if !crate::tund::service_windows::is_elevated() {
        anyhow::bail!(
            "Installing the mlshtund service requires Administrator rights.\n  \
             Open an elevated terminal (Run as administrator) and re-run: mlsh tunnel install"
        );
    }

    let mlshtund_bin = std::env::current_exe()
        .context("Failed to determine binary path")?
        .parent()
        .context("No parent dir")?
        .join("mlshtund.exe");
    if !mlshtund_bin.exists() {
        anyhow::bail!(
            "mlshtund.exe not found next to mlsh.exe (expected at {}).",
            mlshtund_bin.display()
        );
    }

    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )
    .context("Failed to open the Service Control Manager (need admin?)")?;

    let service_access =
        ServiceAccess::CHANGE_CONFIG | ServiceAccess::START | ServiceAccess::QUERY_STATUS;

    let service_info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(SERVICE_DISPLAY_NAME),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: mlshtund_bin,
        launch_arguments: vec![OsString::from("--service")],
        dependencies: vec![],
        account_name: None, // LocalSystem
        account_password: None,
    };

    // Reuse an existing service (reconfigure) or create a fresh one.
    let service = match manager.open_service(SERVICE_NAME, service_access) {
        Ok(svc) => {
            svc.change_config(&service_info)
                .context("Failed to update existing mlshtund service")?;
            svc
        }
        Err(_) => manager
            .create_service(&service_info, service_access)
            .map_err(|e| anyhow::anyhow!("Failed to create mlshtund service: {e}"))?,
    };

    let _ = service.set_description(
        "MLSH overlay tunnel daemon. Reconnects clusters you have connected at least once.",
    );

    // Restart on failure (parity with systemd Restart=on-failure).
    set_restart_on_failure(&service);

    // Start it now unless it's already running.
    let already_running = matches!(
        service.query_status(),
        Ok(status) if status.current_state == ServiceState::Running
    );
    if !already_running {
        let no_args: [&OsStr; 0] = [];
        service
            .start(&no_args)
            .context("Service installed but failed to start")?;
    }

    println!("{}", "mlshtund service installed!".green().bold());
    println!("  Service: {} ({})", SERVICE_NAME, SERVICE_DISPLAY_NAME);
    println!(
        "  Logs:    {}",
        crate::tund::service_windows::log_dir()
            .join("mlshtund.log")
            .display()
    );
    println!();
    println!("The service runs at boot (LocalSystem) and reconnects every cluster you");
    println!("have connected at least once. Use 'mlsh connect <cluster>' to add one.");
    println!("To check:     {}", "mlsh tunnel status".bold());
    println!("To uninstall: {}", "mlsh tunnel uninstall (elevated)".bold());

    Ok(())
}

#[cfg(windows)]
fn set_restart_on_failure(service: &windows_service::service::Service) {
    use std::time::Duration;

    use windows_service::service::{
        ServiceAction, ServiceActionType, ServiceFailureActions, ServiceFailureResetPeriod,
    };

    let restart = ServiceAction {
        action_type: ServiceActionType::Restart,
        delay: Duration::from_secs(5),
    };
    let actions = ServiceFailureActions {
        reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(86_400)),
        reboot_msg: None,
        command: None,
        actions: Some(vec![restart.clone(), restart.clone(), restart]),
    };
    if let Err(e) = service.update_failure_actions(actions) {
        tracing::debug!("Could not set service failure actions: {e}");
    }
    // Trigger the restart actions even when the daemon exits with a non-zero
    // code (not just on a hard crash), matching systemd Restart=on-failure.
    if let Err(e) = service.set_failure_actions_on_non_crash_failures(true) {
        tracing::debug!("Could not enable non-crash failure actions: {e}");
    }
}

#[cfg(windows)]
fn uninstall_daemon() -> Result<()> {
    use std::thread::sleep;
    use std::time::Duration;

    use windows_service::service::{ServiceAccess, ServiceState};
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

    use crate::tund::service_windows::SERVICE_NAME;

    if !crate::tund::service_windows::is_elevated() {
        anyhow::bail!(
            "Uninstalling the mlshtund service requires Administrator rights.\n  \
             Run from an elevated terminal: mlsh tunnel uninstall"
        );
    }

    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .context("Failed to open the Service Control Manager")?;

    let service = manager
        .open_service(
            SERVICE_NAME,
            ServiceAccess::STOP | ServiceAccess::QUERY_STATUS | ServiceAccess::DELETE,
        )
        .context("mlshtund service is not installed")?;

    // Stop it (if running) and wait for the SCM to confirm it has stopped,
    // otherwise the executable stays locked and DELETE only marks it pending.
    if let Ok(status) = service.query_status() {
        if status.current_state != ServiceState::Stopped {
            let _ = service.stop();
            for _ in 0..50 {
                match service.query_status() {
                    Ok(s) if s.current_state == ServiceState::Stopped => break,
                    _ => sleep(Duration::from_millis(200)),
                }
            }
        }
    }

    service
        .delete()
        .context("Failed to delete mlshtund service")?;

    println!("{}", "mlshtund service uninstalled.".green().bold());
    Ok(())
}

#[cfg(windows)]
fn daemon_status() -> Result<()> {
    use windows_service::service::ServiceAccess;
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

    use crate::tund::service_windows::SERVICE_NAME;

    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .context("Failed to open the Service Control Manager")?;

    let service = match manager.open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS) {
        Ok(s) => s,
        Err(_) => {
            println!("{}", "Service not installed.".yellow());
            println!(
                "  Install with (elevated): {}",
                "mlsh tunnel install".bold()
            );
            return Ok(());
        }
    };

    let status = service
        .query_status()
        .context("Failed to query service status")?;

    println!("{}", "mlshtund service installed.".green().bold());
    println!("  State: {:?}", status.current_state);
    println!(
        "  Logs:  {}",
        crate::tund::service_windows::log_dir()
            .join("mlshtund.log")
            .display()
    );
    Ok(())
}

// --- Unsupported platforms

#[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
fn install_daemon() -> Result<()> {
    anyhow::bail!("Daemon installation is only supported on Windows, macOS and Linux")
}

#[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
fn uninstall_daemon() -> Result<()> {
    anyhow::bail!("Daemon installation is only supported on Windows, macOS and Linux")
}

#[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
fn daemon_status() -> Result<()> {
    anyhow::bail!("Daemon installation is only supported on Windows, macOS and Linux")
}
