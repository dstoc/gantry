mod bubblewrap;
mod direct;
mod runtime;

use std::io;
use std::os::fd::RawFd;

use crate::baffle::BaffleRuntimeConfig;
use crate::execution::{ExecutionBackend, ExecutionDiagnostics, ExecutionPlan, RunningExecution};

pub(crate) enum StartError {
    Spawn(io::Error),
    Setup(String),
}

pub(crate) async fn start(
    plan: ExecutionPlan,
    trusted_cwd_fd: RawFd,
    baffle: BaffleRuntimeConfig,
) -> Result<RunningExecution, StartError> {
    let diagnostics = ExecutionDiagnostics::from_plan(&plan);
    let result = match plan.backend {
        ExecutionBackend::Direct => direct::start(plan, trusted_cwd_fd),
        ExecutionBackend::Bubblewrap => bubblewrap::start(plan, baffle).await,
    };
    if let Err(error) = &result {
        match error {
            StartError::Spawn(_) => tracing::error!(
                backend = diagnostics.backend.as_str(),
                filesystem_profile = ?diagnostics.filesystem_profile,
                baffle_filename = ?diagnostics.baffle_filename,
                phase = "setup",
                failure_class = "process_spawn",
                "execution setup failed",
            ),
            StartError::Setup(_) => tracing::error!(
                backend = diagnostics.backend.as_str(),
                filesystem_profile = ?diagnostics.filesystem_profile,
                baffle_filename = ?diagnostics.baffle_filename,
                phase = "setup",
                failure_class = "backend_setup",
                "execution setup failed",
            ),
        }
    }
    result
}

#[cfg(all(test, target_os = "linux"))]
pub(crate) fn host_has_required_bubblewrap() -> bool {
    bubblewrap_test_environment_error().is_none()
}

#[cfg(all(test, target_os = "linux"))]
fn bubblewrap_test_environment_error() -> Option<String> {
    let Some(executable) = ["/usr/bin/bwrap", "/bin/bwrap"]
        .into_iter()
        .find(|path| std::path::Path::new(path).is_file())
    else {
        return Some("bubblewrap executable was not found".to_owned());
    };

    let output = match std::process::Command::new(executable)
        .args([
            "--unshare-user",
            "--unshare-pid",
            "--unshare-net",
            "--ro-bind",
            "/usr",
            "/usr",
            "--ro-bind",
            "/lib",
            "/lib",
            "--ro-bind",
            "/lib64",
            "/lib64",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--",
            "/usr/bin/true",
        ])
        .env_clear()
        .output()
    {
        Ok(output) => output,
        Err(error) => return Some(format!("failed to start {executable}: {error}")),
    };

    if output.status.success() {
        None
    } else {
        Some(format!(
            "{executable} exited with {}: {}{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ))
    }
}

#[cfg(all(test, target_os = "linux"))]
#[test]
fn required_bubblewrap_test_environment_is_available() {
    if std::env::var_os("GANTRY_REQUIRE_BUBBLEWRAP_TESTS").is_some()
        && let Some(error) = bubblewrap_test_environment_error()
    {
        panic!(
            "Bubblewrap integration tests were required, but the configured namespaces are unavailable: {error}"
        );
    }
}
