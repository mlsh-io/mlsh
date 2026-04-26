use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;
use clap::Parser;
use mlsh_e2e::backend::{krunkit::KrunkitBackend, VmBackend, VmConfig};

#[derive(Parser)]
struct Cli {
    /// Path to a bootable Alpine raw EFI disk.
    #[arg(long)]
    rootfs: PathBuf,

    /// Where to write the manifest + per-VM dirs.
    #[arg(long, default_value = "/tmp/mlsh-e2e/run-boot-alpine")]
    run_dir: PathBuf,

    /// How long to let the VM run before shutting it down.
    #[arg(long, default_value_t = 5)]
    sleep_secs: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("mlsh_e2e=debug".parse().unwrap())
                .add_directive("krunkit=debug".parse().unwrap()),
        )
        .init();

    let cli = Cli::parse();
    let backend = KrunkitBackend::new(cli.run_dir.clone()).await?;

    let cfg = VmConfig {
        name: "alpine-1".into(),
        rootfs: cli.rootfs,
        kernel: None,
        memory_mb: 512,
        vcpus: 1,
        nics: vec![],
        shared_dirs: vec![],
        kernel_cmdline_extra: vec![],
    };

    let vm = backend.spawn_vm(cfg).await?;
    tracing::info!("VM spawned, sleeping {}s", cli.sleep_secs);
    tokio::time::sleep(Duration::from_secs(cli.sleep_secs)).await;

    tracing::info!("shutting down");
    vm.shutdown().await?;
    Ok(())
}
