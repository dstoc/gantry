use gantry::{AppConfig, serve};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt().with_target(true).init();

    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if matches!(args.as_slice(), [flag] if flag == "--help" || flag == "-h") {
        println!(
            "gantry [--bind-addr HOST:PORT | --bind-uds ABSOLUTE_PATH] [--policy-dir PATH] [--backend bubblewrap|direct]\n\n+             Phase 1 runtime default: direct. Bubblewrap execution is unavailable until Phase 2."
        );
        return Ok(());
    }

    let config = AppConfig::from_env()?;
    serve(config).await?;
    Ok(())
}
