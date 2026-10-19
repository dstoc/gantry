use std::collections::BTreeMap;
use std::io;
use std::path::PathBuf;
use std::sync::Arc;

use tokio::io::AsyncRead;
use tokio::process::Child;
use tokio::sync::oneshot;

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

#[derive(Debug, Clone)]
pub(crate) struct ExecutionDiagnostics {
    pub(crate) backend: ExecutionBackend,
    pub(crate) filesystem_profile: Option<String>,
    pub(crate) baffle_filename: Option<String>,
    pub(crate) baffle_session_id: Option<String>,
}

impl ExecutionDiagnostics {
    pub(crate) fn from_plan(plan: &ExecutionPlan) -> Self {
        Self {
            backend: plan.backend,
            filesystem_profile: plan.filesystem.as_ref().map(|profile| profile.name.clone()),
            baffle_filename: plan.baffle_session.clone(),
            baffle_session_id: None,
        }
    }
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
    final_status: Option<FinalStatusReceiver>,
    completed_status: Option<ExecutionExitStatus>,
    baffle_lease: Option<crate::baffle::BaffleSessionLease>,
    diagnostics: ExecutionDiagnostics,
}

pub(crate) type OutputReader = Box<dyn AsyncRead + Unpin + Send>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ExecutionExitStatus {
    code: Option<i32>,
    signal: Option<i32>,
}

impl ExecutionExitStatus {
    pub(crate) fn from_process(status: std::process::ExitStatus) -> Self {
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            Self {
                code: status.code(),
                signal: status.signal(),
            }
        }
        #[cfg(not(unix))]
        {
            Self {
                code: status.code(),
                signal: None,
            }
        }
    }

    pub(crate) fn from_components(
        code: Option<i32>,
        signal: Option<i32>,
    ) -> Result<Self, io::Error> {
        if code.is_some() == signal.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "execution status must contain exactly one exit code or signal",
            ));
        }
        Ok(Self { code, signal })
    }

    pub(crate) fn code(self) -> Option<i32> {
        self.code
    }

    #[cfg(test)]
    fn signal(self) -> Option<i32> {
        self.signal
    }
}

type FinalStatusReceiver = oneshot::Receiver<Result<ExecutionExitStatus, io::Error>>;

impl RunningExecution {
    pub(crate) fn new(
        mut child: Child,
        terminate_process_group: bool,
        diagnostics: ExecutionDiagnostics,
    ) -> Self {
        let stdout = child
            .stdout
            .take()
            .map(|reader| Box::new(reader) as OutputReader);
        let stderr = child
            .stderr
            .take()
            .map(|reader| Box::new(reader) as OutputReader);
        let mut execution = Self::new_starting(child, terminate_process_group, None, diagnostics);
        execution.stdout = stdout;
        execution.stderr = stderr;
        execution
    }

    pub(crate) fn new_starting(
        child: Child,
        terminate_process_group: bool,
        baffle_lease: Option<crate::baffle::BaffleSessionLease>,
        mut diagnostics: ExecutionDiagnostics,
    ) -> Self {
        diagnostics.baffle_session_id = baffle_lease.as_ref().map(|lease| lease.id().to_owned());
        let process_group = terminate_process_group
            .then(|| child.id().map(|pid| pid as i32))
            .flatten();
        Self {
            child,
            process_group,
            stdout: None,
            stderr: None,
            final_status: None,
            completed_status: None,
            baffle_lease,
            diagnostics,
        }
    }

    pub(crate) fn diagnostics(&self) -> &ExecutionDiagnostics {
        &self.diagnostics
    }

    pub(crate) fn baffle_session_id(&self) -> Option<&str> {
        self.diagnostics.baffle_session_id.as_deref()
    }

    pub(crate) fn child_mut(&mut self) -> &mut Child {
        &mut self.child
    }

    pub(crate) fn set_streams(
        &mut self,
        stdout: Option<OutputReader>,
        stderr: Option<OutputReader>,
        final_status: FinalStatusReceiver,
    ) {
        self.stdout = stdout;
        self.stderr = stderr;
        self.final_status = Some(final_status);
    }

    pub(crate) fn take_stdout(&mut self) -> Option<OutputReader> {
        self.stdout.take()
    }

    pub(crate) fn take_stderr(&mut self) -> Option<OutputReader> {
        self.stderr.take()
    }

    pub(crate) async fn wait(&mut self) -> Result<ExecutionExitStatus, io::Error> {
        if let Some(status) = self.completed_status {
            return Ok(status);
        }
        let status = self.child.wait().await?;
        self.terminate_descendants();
        let status = if let Some(receiver) = self.final_status.as_mut() {
            let status = (&mut *receiver).await.map_err(|_| {
                io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "execution backend exited without reporting command status",
                )
            })??;
            self.final_status = None;
            status
        } else {
            ExecutionExitStatus::from_process(status)
        };
        self.completed_status = Some(status);
        let baffle_session_id = self.diagnostics.baffle_session_id.clone();
        self.baffle_lease.take();
        tracing::info!(
            backend = self.diagnostics.backend.as_str(),
            filesystem_profile = ?self.diagnostics.filesystem_profile,
            baffle_filename = ?self.diagnostics.baffle_filename,
            baffle_session_id = ?baffle_session_id,
            phase = "cleanup",
            outcome = "complete",
            command_outcome = if status.code() == Some(0) {
                "success"
            } else {
                "failed"
            },
            exit_code = ?status.code(),
            "execution finished and resources were released",
        );
        Ok(status)
    }

    pub(crate) async fn cancel(&mut self) {
        let baffle_session_id = self.diagnostics.baffle_session_id.clone();
        self.terminate_descendants();
        let _ = self.child.start_kill();
        let _ = self.child.wait().await;
        self.baffle_lease.take();
        tracing::info!(
            backend = self.diagnostics.backend.as_str(),
            filesystem_profile = ?self.diagnostics.filesystem_profile,
            baffle_filename = ?self.diagnostics.baffle_filename,
            baffle_session_id = ?baffle_session_id,
            phase = "cleanup",
            outcome = "cancelled_and_released",
            "execution cancellation cleanup finished",
        );
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
        let Some(lease) = self.baffle_lease.take() else {
            return;
        };
        let pid = self.child.id();
        let _ = self.child.start_kill();
        let diagnostics = self.diagnostics.clone();
        let baffle_session_id = self
            .diagnostics
            .baffle_session_id
            .clone()
            .unwrap_or_default();

        #[cfg(unix)]
        if let Some(pid) = pid {
            std::thread::spawn(move || {
                let mut status = 0;
                loop {
                    let result = unsafe { libc::waitpid(pid as libc::pid_t, &mut status, 0) };
                    if result == pid as libc::pid_t
                        || result < 0
                            && std::io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD)
                    {
                        break;
                    }
                    if result < 0
                        && std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR)
                    {
                        break;
                    }
                }
                drop(lease);
                tracing::info!(
                    backend = diagnostics.backend.as_str(),
                    filesystem_profile = ?diagnostics.filesystem_profile,
                    baffle_filename = ?diagnostics.baffle_filename,
                    baffle_session_id = %baffle_session_id,
                    phase = "cleanup",
                    outcome = "cancelled_and_released",
                    "dropped execution cleanup finished",
                );
            });
            return;
        }

        drop(lease);
        tracing::info!(
            backend = diagnostics.backend.as_str(),
            filesystem_profile = ?diagnostics.filesystem_profile,
            baffle_filename = ?diagnostics.baffle_filename,
            baffle_session_id = %baffle_session_id,
            phase = "cleanup",
            outcome = "released",
            "dropped execution lease released",
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    struct ReadObserved<R> {
        inner: R,
        first_poll: Option<tokio::sync::oneshot::Sender<()>>,
    }

    #[cfg(unix)]
    impl<R: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for ReadObserved<R> {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            context: &mut std::task::Context<'_>,
            buffer: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            let this = self.get_mut();
            if let Some(sender) = this.first_poll.take() {
                let _ = sender.send(());
            }
            std::pin::Pin::new(&mut this.inner).poll_read(context, buffer)
        }
    }

    #[cfg(unix)]
    #[test]
    fn execution_status_keeps_signal_distinct_from_exit_code() {
        let signaled =
            ExecutionExitStatus::from_components(None, Some(libc::SIGTERM)).expect("signal status");
        let exited = ExecutionExitStatus::from_components(Some(128), None).expect("exit status");

        assert_eq!(signaled.code(), None);
        assert_eq!(signaled.signal(), Some(libc::SIGTERM));
        assert_eq!(exited.code(), Some(128));
        assert_eq!(exited.signal(), None);
    }

    #[test]
    fn rejects_ambiguous_execution_status() {
        assert!(ExecutionExitStatus::from_components(None, None).is_err());
        assert!(ExecutionExitStatus::from_components(Some(128), Some(15)).is_err());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn cancelled_startup_waits_for_launcher_exit_before_releasing_baffle_lease() {
        use std::process::Stdio;

        use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
        use tokio::net::UnixListener;
        use tokio::process::Command;
        use tokio::time::{Duration, timeout};

        let directory = tempfile::tempdir().expect("temporary directory");
        let control_path = directory.path().join("control.sock");
        let session_path = directory.path().join("assigned.sock");
        let control_listener = UnixListener::bind(&control_path).expect("control listener");
        let _session_listener = UnixListener::bind(&session_path).expect("session listener");
        let response_socket = session_path.clone();
        let ca_certificate_pem = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("test CA certificate")
            .cert
            .pem();
        let (pid_tx, pid_rx) = tokio::sync::oneshot::channel();
        let (closed_tx, closed_rx) = tokio::sync::oneshot::channel();
        let daemon = tokio::spawn(async move {
            let (mut stream, _) = control_listener
                .accept()
                .await
                .expect("Baffle client connects");
            let mut header = [0; 4];
            stream
                .read_exact(&mut header)
                .await
                .expect("read request length");
            let mut request = vec![0; u32::from_be_bytes(header) as usize];
            stream
                .read_exact(&mut request)
                .await
                .expect("read create request");
            let response = serde_json::to_vec(&serde_json::json!({
                "version": 2,
                "ok": true,
                "result": {
                    "id": "startup-cancellation-session",
                    "socket": response_socket,
                    "persistent": false,
                    "ca_certificate_pem": ca_certificate_pem
                }
            }))
            .expect("response JSON");
            stream
                .write_all(&(response.len() as u32).to_be_bytes())
                .await
                .expect("write response length");
            stream.write_all(&response).await.expect("write response");

            let mut byte = [0; 1];
            assert_eq!(
                stream.read(&mut byte).await.expect("read lease closure"),
                0,
                "the session lease should close after startup cleanup"
            );
            let pid = pid_rx.await.expect("launcher PID");
            let launcher_alive = unsafe { libc::kill(pid as libc::pid_t, 0) == 0 };
            closed_tx
                .send(launcher_alive)
                .expect("report lease close ordering");
        });

        let lease = crate::baffle::create_ephemeral_session(
            &crate::baffle::BaffleRuntimeConfig {
                control_socket: control_path,
            },
            "startup-test.toml",
        )
        .await
        .expect("create mock Baffle session");
        let child = Command::new("sleep")
            .arg("30")
            .stdout(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .expect("start paused launcher");
        let pid = child.id().expect("launcher PID");
        pid_tx
            .send(pid)
            .expect("provide launcher PID to mock daemon");

        let (status_read_tx, status_read_rx) = tokio::sync::oneshot::channel();
        let startup = tokio::spawn(async move {
            let mut execution = RunningExecution::new_starting(
                child,
                true,
                Some(lease),
                ExecutionDiagnostics {
                    backend: ExecutionBackend::Bubblewrap,
                    filesystem_profile: Some("test".to_owned()),
                    baffle_filename: Some("startup-test.toml".to_owned()),
                    baffle_session_id: None,
                },
            );
            let stdout = execution
                .child_mut()
                .stdout
                .take()
                .expect("launcher status pipe");
            let mut status_reader = BufReader::new(ReadObserved {
                inner: stdout,
                first_poll: Some(status_read_tx),
            });
            let mut line = String::new();
            let _ = status_reader.read_line(&mut line).await;
        });

        timeout(Duration::from_secs(3), status_read_rx)
            .await
            .expect("startup reached its first status read")
            .expect("status reader poll notification");
        startup.abort();
        let _ = startup.await;

        let launcher_alive_when_lease_closed = timeout(Duration::from_secs(3), closed_rx)
            .await
            .expect("mock daemon observed lease close")
            .expect("report launcher state");
        assert!(
            !launcher_alive_when_lease_closed,
            "launcher must be reaped before the Baffle lease closes"
        );
        daemon.await.expect("mock daemon task");
    }

    #[test]
    fn parses_only_configured_backend_names() {
        assert_eq!("direct".parse(), Ok(ExecutionBackend::Direct));
        assert_eq!("bubblewrap".parse(), Ok(ExecutionBackend::Bubblewrap));
        assert!("Direct".parse::<ExecutionBackend>().is_err());
    }
}
