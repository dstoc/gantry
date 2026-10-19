use std::collections::BTreeMap;
use std::io::Write;
use std::path::PathBuf;
use std::process::Stdio;

use serde::{Deserialize, Serialize};
use tokio::io::AsyncReadExt;
use tokio::process::Command;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorizedInvocation {
    executable: PathBuf,
    args: Vec<String>,
    cwd: PathBuf,
    environment: BTreeMap<String, String>,
}

#[derive(Debug, Serialize)]
struct SupervisorStatus<'a> {
    status: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<&'a str>,
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("gantry-supervisor: {error}");
        std::process::exit(125);
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut input = Vec::new();
    tokio::io::stdin().read_to_end(&mut input).await?;
    let invocation: AuthorizedInvocation = match serde_json::from_slice(&input) {
        Ok(invocation) => invocation,
        Err(error) => {
            write_status("setup_error", Some(&error.to_string()))?;
            return Err(error.into());
        }
    };
    if !invocation.executable.is_absolute() || !invocation.cwd.is_absolute() {
        let message = "authorized executable and cwd must be absolute paths";
        write_status("setup_error", Some(message))?;
        return Err(message.into());
    }

    let mut command = Command::new(&invocation.executable);
    command
        .args(&invocation.args)
        .current_dir(&invocation.cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    #[cfg(unix)]
    command.process_group(0);
    command.env_clear();
    command.envs(invocation.environment);

    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            write_status("setup_error", Some(&error.to_string()))?;
            return Err(error.into());
        }
    };
    let pid = child.id().ok_or("authorized command has no process id")? as i32;
    write_status("started", None)?;

    let stdout = child
        .stdout
        .take()
        .ok_or("authorized stdout pipe missing")?;
    let stderr = child
        .stderr
        .take()
        .ok_or("authorized stderr pipe missing")?;
    let stdout_task = tokio::spawn(async move {
        tokio::io::copy(
            &mut tokio::io::BufReader::new(stdout),
            &mut tokio::io::stdout(),
        )
        .await
    });
    let stderr_task = tokio::spawn(async move {
        tokio::io::copy(
            &mut tokio::io::BufReader::new(stderr),
            &mut tokio::io::stderr(),
        )
        .await
    });

    let status = child.wait().await?;
    terminate_sandbox_descendants(pid);
    let stdout_result = stdout_task.await?;
    let stderr_result = stderr_task.await?;
    stdout_result?;
    stderr_result?;

    std::process::exit(status.code().unwrap_or(128));
}

fn write_status(status: &str, error: Option<&str>) -> std::io::Result<()> {
    let message = serde_json::to_vec(&SupervisorStatus { status, error })?;
    let stdout = std::io::stdout();
    let mut output = stdout.lock();
    output.write_all(&message)?;
    output.write_all(b"\n")?;
    output.flush()
}

fn terminate_sandbox_descendants(command_pid: i32) {
    unsafe {
        libc::kill(-command_pid, libc::SIGKILL);
        libc::kill(-1, libc::SIGKILL);
        let mut status = 0;
        while libc::waitpid(-1, &mut status, 0) > 0 {}
    }
}
