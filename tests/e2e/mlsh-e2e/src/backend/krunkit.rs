use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{ChildStderr, ChildStdout, Command};

use super::{ExecCmd, ExecResult, ProcessHandle, VmBackend, VmConfig, VmHandle};
use crate::manifest::{Manifest, Resource as ManifestResource};

pub struct KrunkitBackend {
    binary: PathBuf,
    run_dir: PathBuf,
    manifest: Arc<Manifest>,
}

impl KrunkitBackend {
    pub async fn new(run_dir: PathBuf) -> Result<Self> {
        tokio::fs::create_dir_all(&run_dir)
            .await
            .with_context(|| format!("create run dir {}", run_dir.display()))?;
        let manifest = Arc::new(Manifest::create(run_dir.join("manifest.jsonl")).await?);
        let binary = which::which("krunkit").unwrap_or_else(|_| PathBuf::from("krunkit"));
        Ok(Self {
            binary,
            run_dir,
            manifest,
        })
    }

    pub fn manifest_path(&self) -> &Path {
        self.manifest.path()
    }
}

#[async_trait]
impl VmBackend for KrunkitBackend {
    async fn create_bridge(&self, _name: &str) -> Result<()> {
        // PR future : socket_vmnet / vmnet-helper. Cf. ADR-031.
        bail!("create_bridge not implemented yet on Krunkit backend")
    }

    async fn spawn_vm(&self, cfg: VmConfig) -> Result<Box<dyn VmHandle>> {
        let vm_dir = self.run_dir.join(&cfg.name);
        tokio::fs::create_dir_all(&vm_dir).await?;

        let efi_vars = vm_dir.join("efi-vars.fd");
        let mut cmd = Command::new(&self.binary);
        let console_log = vm_dir.join("console.log");
        cmd.arg("--cpus")
            .arg(cfg.vcpus.to_string())
            .arg("--memory")
            .arg(cfg.memory_mb.to_string())
            .arg("--bootloader")
            .arg(format!("efi,variable-store={},create", efi_vars.display()))
            .arg("--device")
            .arg(format!(
                "virtio-blk,path={},format=raw",
                cfg.rootfs.display()
            ))
            .arg("--device")
            .arg(format!(
                "virtio-serial,logFilePath={}",
                console_log.display()
            ));

        for shared in &cfg.shared_dirs {
            cmd.arg("--device").arg(format!(
                "virtio-fs,sharedDir={},mountTag={}",
                shared.host_path.display(),
                shared.guest_tag
            ));
        }

        cmd.stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .stdin(Stdio::null());

        tracing::info!(name = %cfg.name, "spawning krunkit");
        let mut child = cmd
            .spawn()
            .with_context(|| format!("spawn krunkit for {}", cfg.name))?;

        let pid = child
            .id()
            .ok_or_else(|| anyhow!("krunkit pid unavailable"))?;
        self.manifest
            .record(&ManifestResource::Vm {
                name: cfg.name.clone(),
                pid,
                run_dir: vm_dir.clone(),
            })
            .await?;

        if let Some(stdout) = child.stdout.take() {
            spawn_log_pump(cfg.name.clone(), "stdout", stdout);
        }
        if let Some(stderr) = child.stderr.take() {
            spawn_log_pump_err(cfg.name.clone(), "stderr", stderr);
        }

        let exit_watch_name = cfg.name.clone();
        let exited = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let exited_for_task = exited.clone();
        tokio::spawn(async move {
            let mut child = child;
            let status = child.wait().await;
            exited_for_task.store(true, std::sync::atomic::Ordering::SeqCst);
            match status {
                Ok(s) => tracing::warn!(
                    name = %exit_watch_name, status = ?s,
                    "krunkit exited"
                ),
                Err(e) => tracing::error!(
                    name = %exit_watch_name, error = %e,
                    "krunkit wait failed"
                ),
            }
        });

        Ok(Box::new(KrunkitVm {
            name: cfg.name,
            pid,
            exited,
        }))
    }

    async fn cleanup_from_manifest(&self, manifest_path: &Path) -> Result<()> {
        let resources = crate::manifest::read_all(manifest_path).await?;
        for r in resources.into_iter().rev() {
            match r {
                ManifestResource::Vm { name, pid, .. } => {
                    tracing::info!(name = %name, pid, "cleanup: SIGTERM krunkit");
                    let _ = kill(Pid::from_raw(pid as i32), Signal::SIGTERM);
                }
                ManifestResource::Bridge { .. }
                | ManifestResource::Tap { .. }
                | ManifestResource::NftTable { .. } => {
                    // PR future
                }
            }
        }
        Ok(())
    }
}

fn spawn_log_pump(vm: String, stream: &'static str, out: ChildStdout) {
    tokio::spawn(async move {
        let mut lines = BufReader::new(out).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            tracing::debug!(target: "krunkit", vm = %vm, stream, "{line}");
        }
    });
}

fn spawn_log_pump_err(vm: String, stream: &'static str, out: ChildStderr) {
    tokio::spawn(async move {
        let mut lines = BufReader::new(out).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            tracing::debug!(target: "krunkit", vm = %vm, stream, "{line}");
        }
    });
}

struct KrunkitVm {
    name: String,
    pid: u32,
    exited: Arc<std::sync::atomic::AtomicBool>,
}

#[async_trait]
impl VmHandle for KrunkitVm {
    fn name(&self) -> &str {
        &self.name
    }

    async fn wait_ready(&self, _timeout: Duration) -> Result<()> {
        bail!("wait_ready requires the guest agent (PR 2)")
    }

    async fn nic_ip(&self, _nic_idx: usize) -> Result<std::net::Ipv4Addr> {
        bail!("nic_ip requires bridges + DHCP (PR 3)")
    }

    async fn exec(&self, _cmd: ExecCmd) -> Result<ExecResult> {
        bail!("exec requires the guest agent (PR 2)")
    }

    async fn spawn(&self, _cmd: ExecCmd) -> Result<Box<dyn ProcessHandle>> {
        bail!("spawn requires the guest agent (PR 2)")
    }

    async fn shutdown(&self) -> Result<()> {
        if self.exited.load(std::sync::atomic::Ordering::SeqCst) {
            return Ok(());
        }
        let _ = kill(Pid::from_raw(self.pid as i32), Signal::SIGTERM);

        for _ in 0..50 {
            if self.exited.load(std::sync::atomic::Ordering::SeqCst) {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let _ = kill(Pid::from_raw(self.pid as i32), Signal::SIGKILL);
        Ok(())
    }
}

impl Drop for KrunkitVm {
    fn drop(&mut self) {
        // Best-effort sync cleanup. Le vrai nettoyage passe par mlsh-e2e-cleanup.
        let _ = kill(Pid::from_raw(self.pid as i32), Signal::SIGTERM);
    }
}
