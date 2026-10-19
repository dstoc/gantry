use gantry::{AppConfig, serve};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt().with_target(true).init();

    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if matches!(args.as_slice(), [flag] if flag == "--help" || flag == "-h") {
        println!(
            "gantry [--bind-addr HOST:PORT | --bind-uds ABSOLUTE_PATH] [--policy-dir PATH] [--backend bubblewrap|direct]\n\nBubblewrap is the default. Use --backend direct to select unsandboxed execution. Configure Baffle with GANTRY_BAFFLE_CONTROL_SOCKET, GANTRY_BAFFLE_SESSION_SOCKET_DIR, and GANTRY_BAFFLE_CA_CERT."
        );
        return Ok(());
    }

    let config = AppConfig::from_env()?;
    serve(config).await?;
    Ok(())
}
