//! `mlsh tunnel` — install/uninstall the `mlshtund` tunnel daemon as a system service.
//!
//! - macOS: LaunchDaemon plist at /Library/LaunchDaemons/io.mlsh.tund.plist
//! - Linux: systemd system unit at /etc/systemd/system/mlshtund.service

use anyhow::{Context, Result};
use clap::Subcommand;
use colored::Colorize;

#[derive(Subcommand)]
pub enum DaemonCommands {
    /// Install mlshtund as a system daemon
    Install {
        /// Clusters to auto-connect on daemon start (comma-separated)
        #[arg(long, value_delimiter = ',')]
        auto_connect: Vec<String>,
    },

    /// Uninstall the mlshtund daemon
    Uninstall,

    /// Show daemon installation status
    Status,
}

pub async fn handle(cmd: DaemonCommands) -> Result<()> {
    match cmd {
        DaemonCommands::Install { auto_connect } => install_daemon(&auto_connect),
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
fn install_daemon(auto_connect: &[String]) -> Result<()> {
    let mlshtund_bin = std::env::current_exe()
        .context("Failed to determine binary path")?
        .parent()
        .context("No parent dir")?
        .join("mlshtund");
    let bin_path = mlshtund_bin.to_string_lossy();

    let log_dir = "/var/log/mlsh";
    std::fs::create_dir_all(log_dir).ok();

    // Build ProgramArguments
    let mut args_xml = format!("    <array>\n        <string>{}</string>\n", bin_path);
    if !auto_connect.is_empty() {
        args_xml.push_str(&format!(
            "        <string>--auto-connect</string>\n        <string>{}</string>\n",
            auto_connect.join(",")
        ));
    }
    args_xml.push_str("    </array>");

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
    if !auto_connect.is_empty() {
        println!("  Auto-connect: {}", auto_connect.join(", "));
    }
    println!("  Logs:  {}/mlshtund.log", log_dir);
    println!();
    println!("The daemon runs at boot. Use 'mlsh connect <cluster>' to start tunnels.");
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
fn install_daemon(auto_connect: &[String]) -> Result<()> {
    let mlshtund_bin = std::env::current_exe()
        .context("Failed to determine binary path")?
        .parent()
        .context("No parent dir")?
        .join("mlshtund");
    let bin_path = mlshtund_bin.to_string_lossy();

    let mut exec_start = bin_path.to_string();
    if !auto_connect.is_empty() {
        exec_start.push_str(&format!(" --auto-connect {}", auto_connect.join(",")));
    }

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
    if !auto_connect.is_empty() {
        println!("  Auto-connect: {}", auto_connect.join(", "));
    }
    println!();
    println!("The daemon runs at boot. Use 'mlsh connect <cluster>' to start tunnels.");
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

// --- Unsupported platforms

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn install_daemon(_auto_connect: &[String]) -> Result<()> {
    anyhow::bail!("Daemon installation is only supported on macOS and Linux")
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn uninstall_daemon() -> Result<()> {
    anyhow::bail!("Daemon installation is only supported on macOS and Linux")
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn daemon_status() -> Result<()> {
    anyhow::bail!("Daemon installation is only supported on macOS and Linux")
}
