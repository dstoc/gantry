use std::os::fd::RawFd;
use std::process::Stdio;

use tokio::process::Command;

use crate::backend::StartError;
use crate::execution::{ExecutionPlan, RunningExecution};

pub(super) fn start(
    plan: ExecutionPlan,
    trusted_cwd_fd: RawFd,
) -> Result<RunningExecution, StartError> {
    let invocation = plan.invocation;
    tracing::debug!(
        executable_hash = %invocation.executable_hash,
        policy_generation = invocation.generation.id(),
        cwd = %invocation.cwd_label,
        effective_cwd = %invocation.cwd.display(),
        "starting authorized direct invocation",
    );

    let mut command = Command::new(&invocation.executable);
    command
        .args(&invocation.args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    #[cfg(unix)]
    unsafe {
        command.pre_exec(move || {
            if libc::fchdir(trusted_cwd_fd) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::setpgid(0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }

    command.env_clear();
    command.envs(
        invocation
            .environment
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str())),
    );

    let child = command.spawn().map_err(StartError::Spawn)?;
    Ok(RunningExecution::new(child, true))
}
