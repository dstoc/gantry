use gantry::{AppConfig, serve};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt().with_target(true).init();

    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if matches!(args.as_slice(), [flag] if flag == "--help" || flag == "-h") {
        println!(
            "gantry [--bind-addr HOST:PORT | --bind-uds ABSOLUTE_PATH] [--policy-dir PATH] [--backend bubblewrap|direct]

Options:
  --bind-addr HOST:PORT      TCP listener (default 127.0.0.1:8000)
  --bind-uds ABSOLUTE_PATH   Unix socket listener
  --policy-dir PATH          Rego directory (or GANTRY_POLICY_DIR)
  --backend NAME             bubblewrap (default) or direct
  -h, --help                 Show this help

Listener environment:
  GANTRY_BIND_ADDR, GANTRY_BIND_UDS
  A listener flag overrides both variables. Without a flag, set at most one.
  GANTRY_POLICY_DIR selects the Rego directory. Legacy MCP_BIND_ADDR,
  MCP_BIND_UDS, and POLICY_DIR variables are ignored.

Bubblewrap is the default and requires Linux, working Bubblewrap namespaces,
and gantry-supervisor beside gantry. Setup failures never fall back to Direct.
Rego returns one structured decision with allow, filesystem, and
baffle_session fields. Bubblewrap requires a named filesystem profile.
Direct requires both selection fields to be null.
Commands use the authorized absolute CWD path inside the sandbox; execution
fails if the sandbox does not contain that path. Direct requires an explicit
--backend direct selection and uses Gantry's host filesystem and networking.
Direct execution changes CWD through the directory opened during authorization.
The run-remote client keeps RUN_REMOTE_SERVER and RUN_REMOTE_SOCKET.

Baffle settings:
  GANTRY_BAFFLE_CONTROL_SOCKET
  GANTRY_BAFFLE_SESSION_SOCKET_DIR
  GANTRY_BAFFLE_CA_CERT"
        );
        return Ok(());
    }

    let config = AppConfig::from_env()?;
    serve(config).await?;
    Ok(())
}
