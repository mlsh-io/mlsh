use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;
use clap::Parser;
use mlsh_e2e::backend::krunkit::KrunkitBackend;
use mlsh_e2e::backend::VmBackend;

#[derive(Parser)]
#[command(name = "mlsh-e2e-cleanup", about = "Cleanup leftover E2E resources")]
struct Cli {
    /// Run dir produced by a previous mlsh-e2e invocation.
    #[arg(long)]
    run_dir: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();
    let manifest = cli.run_dir.join("manifest.jsonl");
    let backend = KrunkitBackend::new(cli.run_dir.clone()).await?;
    backend.cleanup_from_manifest(&manifest).await?;

    // Laisse le temps aux processus de réagir au SIGTERM avant de rendre la main.
    tokio::time::sleep(Duration::from_millis(500)).await;
    Ok(())
}
