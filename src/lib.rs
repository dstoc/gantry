#[cfg(not(all(
    any(target_os = "linux", target_os = "macos"),
    any(target_arch = "x86_64", target_arch = "aarch64")
)))]
compile_error!("gantry supports Linux and macOS targets on x86_64 and aarch64 only.");

mod backend;
mod execution;
mod executor;
mod filesystem;
mod mcp;
mod policy;
mod raw;
mod remote;

pub use execution::ExecutionBackend;
pub use executor::{
    MAX_OUTPUT_BYTES, RunCommandCheckOutput, RunCommandInput, RunCommandOutput, TRUNCATION_MARKER,
    ToolError, check_command, check_command_with_backend, run_command_impl,
    run_command_with_backend,
};
pub use mcp::{
    AppConfig, AppError, ConfigError, DEFAULT_BIND_ADDR, McpRunServer, build_app,
    build_app_with_backend, serve,
};
pub use policy::{PolicyEngine, PolicyMode, ValidationError};
pub use raw::{RawEndpointState, RawErrorBody, RawStreamEvent, raw_handler};
pub use remote::{LOCAL_FAILURE_EXIT_CODE, RemoteClientError, run_remote_from_env};
