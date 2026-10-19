use std::collections::BTreeMap;
use std::io;
use std::path::PathBuf;
use std::sync::Arc;

use tokio::io::AsyncRead;
use tokio::process::Child;

use crate::filesystem::FilesystemProfile;
use crate::policy::PolicyGeneration;

/// Backend selection is fixed once for the server process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionBackend {
    Bubblewrap,
    Direct,
}

impl ExecutionBackend {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Bubblewrap => "bubblewrap",
            Self::Direct => "direct",
        }
    }
}

impl std::str::FromStr for ExecutionBackend {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "bubblewrap" => Ok(Self::Bubblewrap),
            "direct" => Ok(Self::Direct),
            _ => Err(format!(
                "invalid backend '{value}'; expected bubblewrap or direct"
            )),
        }
    }
}

/// A fully authorized invocation. Callers cannot use this type to request
/// another executable lookup or policy evaluation.
#[derive(Debug, Clone)]
pub(crate) struct AuthorizedInvocation {
    pub(crate) executable: PathBuf,
    pub(crate) executable_hash: String,
    pub(crate) args: Vec<String>,
    pub(crate) environment: BTreeMap<String, String>,
    pub(crate) cwd: PathBuf,
    pub(crate) cwd_label: String,
    pub(crate) generation: Arc<PolicyGeneration>,
}

/// The policy selection resolved against one immutable policy generation and
/// the server's fixed backend selection.
#[derive(Debug, Clone)]
pub(crate) struct ExecutionPlan {
    pub(crate) invocation: AuthorizedInvocation,
    pub(crate) backend: ExecutionBackend,
    pub(crate) filesystem: Option<Arc<FilesystemProfile>>,
    pub(crate) baffle_session: Option<String>,
}

impl ExecutionPlan {
    pub(crate) fn validate_compatibility(&self) -> Result<(), String> {
        match self.backend {
            ExecutionBackend::Direct => {
                if self.filesystem.is_some() || self.baffle_session.is_some() {
                    return Err(
                        "direct backend requires filesystem: null and baffle_session: null"
                            .to_string(),
                    );
                }
            }
            ExecutionBackend::Bubblewrap => {
                if self.filesystem.is_none() {
                    return Err(
                        "bubblewrap backend requires a named filesystem profile".to_string()
                    );
                }
            }
        }
        Ok(())
    }
}

/// Backend-neutral ownership of a running execution. Backends expose the same
/// output, wait, and cancellation operations even when the owned process is a
/// sandbox launcher rather than the authorized command itself.
pub(crate) struct RunningExecution {
    child: Child,
    process_group: Option<i32>,
    stdout: Option<OutputReader>,
    stderr: Option<OutputReader>,
}

pub(crate) type OutputReader = Box<dyn AsyncRead + Unpin + Send>;

impl RunningExecution {
    pub(crate) fn new(mut child: Child, terminate_process_group: bool) -> Self {
        let process_group = terminate_process_group
            .then(|| child.id().map(|pid| pid as i32))
            .flatten();
        let stdout = child
            .stdout
            .take()
            .map(|reader| Box::new(reader) as OutputReader);
        let stderr = child
            .stderr
            .take()
            .map(|reader| Box::new(reader) as OutputReader);
        Self {
            child,
            process_group,
            stdout,
            stderr,
        }
    }

    pub(crate) fn new_with_streams(
        child: Child,
        terminate_process_group: bool,
        stdout: Option<OutputReader>,
        stderr: Option<OutputReader>,
    ) -> Self {
        let process_group = terminate_process_group
            .then(|| child.id().map(|pid| pid as i32))
            .flatten();
        Self {
            child,
            process_group,
            stdout,
            stderr,
        }
    }

    pub(crate) fn take_stdout(&mut self) -> Option<OutputReader> {
        self.stdout.take()
    }

    pub(crate) fn take_stderr(&mut self) -> Option<OutputReader> {
        self.stderr.take()
    }

    pub(crate) async fn wait(&mut self) -> Result<std::process::ExitStatus, io::Error> {
        let status = self.child.wait().await?;
        self.terminate_descendants();
        Ok(status)
    }

    pub(crate) async fn cancel(&mut self) {
        self.terminate_descendants();
        let _ = self.child.start_kill();
        let _ = self.child.wait().await;
    }

    fn terminate_descendants(&self) {
        #[cfg(unix)]
        if let Some(process_group) = self.process_group {
            unsafe {
                libc::kill(-(process_group as libc::pid_t), libc::SIGKILL);
            }
        }
    }
}

impl Drop for RunningExecution {
    fn drop(&mut self) {
        self.terminate_descendants();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_only_configured_backend_names() {
        assert_eq!("direct".parse(), Ok(ExecutionBackend::Direct));
        assert_eq!("bubblewrap".parse(), Ok(ExecutionBackend::Bubblewrap));
        assert!("Direct".parse::<ExecutionBackend>().is_err());
    }
}
