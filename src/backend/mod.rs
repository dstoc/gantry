mod bubblewrap;
mod direct;
mod runtime;

use std::io;
use std::os::fd::RawFd;

use crate::execution::{ExecutionBackend, ExecutionPlan, RunningExecution};

pub(crate) enum StartError {
    Spawn(io::Error),
    Setup(String),
}

pub(crate) async fn start(
    plan: ExecutionPlan,
    trusted_cwd_fd: RawFd,
) -> Result<RunningExecution, StartError> {
    match plan.backend {
        ExecutionBackend::Direct => direct::start(plan, trusted_cwd_fd),
        ExecutionBackend::Bubblewrap => bubblewrap::start(plan).await,
    }
}

#[cfg(all(test, target_os = "linux"))]
pub(crate) fn host_has_required_bubblewrap() -> bool {
    let Some(executable) = ["/usr/bin/bwrap", "/bin/bwrap"]
        .into_iter()
        .find(|path| std::path::Path::new(path).is_file())
    else {
        return false;
    };
    std::process::Command::new(executable)
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
        .is_ok_and(|output| output.status.success())
}

#[cfg(all(test, target_os = "linux"))]
#[test]
fn required_bubblewrap_test_environment_is_available() {
    if std::env::var_os("GANTRY_REQUIRE_BUBBLEWRAP_TESTS").is_some() {
        assert!(
            host_has_required_bubblewrap(),
            "Bubblewrap integration tests were required, but the configured namespaces are unavailable"
        );
    }
}
