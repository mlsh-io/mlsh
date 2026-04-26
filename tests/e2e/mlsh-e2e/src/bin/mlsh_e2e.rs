use anyhow::Result;
use clap::Parser;

#[derive(Parser)]
#[command(name = "mlsh-e2e", about = "MLSH end-to-end test harness")]
struct Cli {
    // PR 5 : sous-commandes (run, list, ...). Pour l'instant, voir l'exemple
    // boot_alpine et le binaire mlsh-e2e-cleanup.
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let _ = Cli::parse();
    println!("mlsh-e2e: harness skeleton (PR 1a). Use examples/boot_alpine.rs.");
    Ok(())
}
