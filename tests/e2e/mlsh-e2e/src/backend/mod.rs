use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufRead, AsyncWrite};

pub mod krunkit;
pub mod qemu;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VmConfig {
    pub name: String,
    pub rootfs: PathBuf,
    pub kernel: Option<PathBuf>,
    pub memory_mb: u32,
    pub vcpus: u32,
    pub nics: Vec<NicConfig>,
    pub shared_dirs: Vec<SharedDir>,
    pub kernel_cmdline_extra: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NicConfig {
    pub bridge: String,
    pub mac: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SharedDir {
    pub host_path: PathBuf,
    pub guest_tag: String,
    pub read_only: bool,
}

#[derive(Clone, Debug)]
pub struct ExecCmd {
    pub program: String,
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
    pub cwd: Option<PathBuf>,
    pub stdin: Option<Vec<u8>>,
}

#[derive(Debug)]
pub struct ExecResult {
    pub exit_code: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

#[async_trait]
pub trait VmHandle: Send + Sync {
    fn name(&self) -> &str;

    async fn wait_ready(&self, timeout: Duration) -> Result<()>;

    async fn nic_ip(&self, nic_idx: usize) -> Result<Ipv4Addr>;

    async fn exec(&self, cmd: ExecCmd) -> Result<ExecResult>;

    async fn spawn(&self, cmd: ExecCmd) -> Result<Box<dyn ProcessHandle>>;

    async fn shutdown(&self) -> Result<()>;
}

#[async_trait]
pub trait ProcessHandle: Send + Sync {
    fn pid(&self) -> u32;

    fn stdout(&mut self) -> Box<dyn AsyncBufRead + Send + Unpin + '_>;
    fn stderr(&mut self) -> Box<dyn AsyncBufRead + Send + Unpin + '_>;
    fn stdin(&mut self) -> Option<Box<dyn AsyncWrite + Send + Unpin + '_>>;

    async fn signal(&self, sig: i32) -> Result<()>;
    async fn wait(&mut self) -> Result<i32>;
    async fn kill(&mut self) -> Result<()>;
}

#[async_trait]
pub trait VmBackend: Send + Sync {
    async fn create_bridge(&self, name: &str) -> Result<()>;

    async fn spawn_vm(&self, cfg: VmConfig) -> Result<Box<dyn VmHandle>>;

    async fn cleanup_from_manifest(&self, manifest_path: &std::path::Path) -> Result<()>;
}
