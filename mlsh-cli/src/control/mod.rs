mod db;
mod server;

pub async fn run() -> anyhow::Result<()> {
    tracing::info!("mlsh-control starting");

    let _pool = db::init().await?;
    server::serve().await
}
