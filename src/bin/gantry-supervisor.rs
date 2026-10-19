use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Stdio;

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, UnixStream};
use tokio::process::Command;
use tokio::sync::oneshot;
use tokio::task::{JoinHandle, JoinSet};

#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum EncodedSupervisorMessage {
    Started,
    SetupError {
        error: String,
    },
    Stdout {
        data: String,
    },
    Exited {
        code: Option<i32>,
        signal: Option<i32>,
    },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorizedInvocation {
    executable: PathBuf,
    args: Vec<String>,
    cwd: PathBuf,
    environment: BTreeMap<String, String>,
    #[serde(default)]
    proxy_socket: Option<PathBuf>,
}

struct ProxyBridge {
    shutdown: Option<oneshot::Sender<()>>,
    task: JoinHandle<()>,
}

impl ProxyBridge {
    async fn start(socket_path: PathBuf) -> std::io::Result<Self> {
        Self::start_on(socket_path, "127.0.0.1:3128").await
    }

    async fn start_on(
        socket_path: PathBuf,
        address: impl tokio::net::ToSocketAddrs,
    ) -> std::io::Result<Self> {
        let listener = TcpListener::bind(address).await?;
        let (shutdown, receiver) = oneshot::channel();
        let task = tokio::spawn(serve_proxy_connections(listener, socket_path, receiver));
        Ok(Self {
            shutdown: Some(shutdown),
            task,
        })
    }

    async fn stop(mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        let _ = (&mut self.task).await;
    }
}

impl Drop for ProxyBridge {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        self.task.abort();
    }
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
            write_status(EncodedSupervisorMessage::SetupError {
                error: error.to_string(),
            })?;
            return Err(error.into());
        }
    };
    if !invocation.executable.is_absolute() || !invocation.cwd.is_absolute() {
        let message = "authorized executable and cwd must be absolute paths";
        write_status(EncodedSupervisorMessage::SetupError {
            error: message.to_string(),
        })?;
        return Err(message.into());
    }

    let mut bridge = if let Some(socket_path) = invocation.proxy_socket.as_ref() {
        if socket_path != Path::new("/run/gantry/proxy.sock") {
            let message = "authorized proxy socket must use the fixed sandbox path";
            write_status(EncodedSupervisorMessage::SetupError {
                error: message.to_string(),
            })?;
            return Err(message.into());
        }
        match ProxyBridge::start(socket_path.clone()).await {
            Ok(bridge) => Some(bridge),
            Err(error) => {
                write_status(EncodedSupervisorMessage::SetupError {
                    error: format!("failed to start the local Baffle proxy bridge: {error}"),
                })?;
                return Err(error.into());
            }
        }
    } else {
        None
    };

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
            if let Some(bridge) = bridge.take() {
                bridge.stop().await;
            }
            write_status(EncodedSupervisorMessage::SetupError {
                error: error.to_string(),
            })?;
            return Err(error.into());
        }
    };
    let pid = child.id().ok_or("authorized command has no process id")? as i32;
    write_status(EncodedSupervisorMessage::Started)?;

    let stdout = child
        .stdout
        .take()
        .ok_or("authorized stdout pipe missing")?;
    let stderr = child
        .stderr
        .take()
        .ok_or("authorized stderr pipe missing")?;
    let stdout_task = tokio::spawn(async move {
        let mut reader = BufReader::new(stdout);
        let mut writer = tokio::io::stdout();
        let mut buffer = [0; 8192];
        loop {
            let bytes_read = reader.read(&mut buffer).await?;
            if bytes_read == 0 {
                break;
            }
            let data = base64::engine::general_purpose::STANDARD.encode(&buffer[..bytes_read]);
            write_message(&mut writer, EncodedSupervisorMessage::Stdout { data }).await?;
        }
        Ok::<_, std::io::Error>(())
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
    if let Some(bridge) = bridge.take() {
        bridge.stop().await;
    }
    let stdout_result = stdout_task.await?;
    let stderr_result = stderr_task.await?;
    stdout_result?;
    stderr_result?;

    #[cfg(unix)]
    use std::os::unix::process::ExitStatusExt;
    let command_status = if let Some(code) = status.code() {
        (Some(code), None)
    } else {
        #[cfg(unix)]
        {
            (None, status.signal())
        }
        #[cfg(not(unix))]
        {
            (None, None)
        }
    };
    write_status(EncodedSupervisorMessage::Exited {
        code: command_status.0,
        signal: command_status.1,
    })?;

    std::process::exit(status.code().unwrap_or(128));
}

async fn serve_proxy_connections(
    listener: TcpListener,
    socket_path: PathBuf,
    mut shutdown: oneshot::Receiver<()>,
) {
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            accepted = listener.accept() => match accepted {
                Ok((mut client, _)) => {
                    let socket_path = socket_path.clone();
                    connections.spawn(async move {
                        let Ok(mut session) = UnixStream::connect(socket_path).await else {
                            return;
                        };
                        let _ = tokio::io::copy_bidirectional(&mut client, &mut session).await;
                    });
                }
                Err(_) => break,
            },
            Some(_) = connections.join_next(), if !connections.is_empty() => {}
        }
    }
    connections.abort_all();
    while connections.join_next().await.is_some() {}
}

fn write_status(status: EncodedSupervisorMessage) -> std::io::Result<()> {
    let message = serde_json::to_vec(&status)?;
    let stdout = std::io::stdout();
    let mut output = stdout.lock();
    output.write_all(&message)?;
    output.write_all(b"\n")?;
    output.flush()
}

async fn write_message<W: AsyncWrite + Unpin>(
    output: &mut W,
    message: EncodedSupervisorMessage,
) -> std::io::Result<()> {
    let message = serde_json::to_vec(&message)?;
    output.write_all(&message).await?;
    output.write_all(b"\n").await?;
    output.flush().await
}

fn terminate_sandbox_descendants(command_pid: i32) {
    unsafe {
        libc::kill(-command_pid, libc::SIGKILL);
        libc::kill(-1, libc::SIGKILL);
        let mut status = 0;
        while libc::waitpid(-1, &mut status, 0) > 0 {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn proxy_bridge_start_failure_is_reported_when_the_port_is_in_use() {
        let occupied = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("occupy a loopback port");
        let address = occupied.local_addr().expect("occupied address");
        let directory = tempfile::tempdir().expect("temporary directory");
        let error = ProxyBridge::start_on(directory.path().join("proxy.sock"), address)
            .await
            .err()
            .expect("the occupied port must prevent bridge startup");
        assert_eq!(error.kind(), std::io::ErrorKind::AddrInUse);
    }

    #[tokio::test]
    async fn bridge_opens_one_uds_connection_for_each_tcp_client() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let socket_path = directory.path().join("assigned.sock");
        let uds_listener = tokio::net::UnixListener::bind(&socket_path).expect("UDS listener");
        let (connections_tx, mut connections_rx) = tokio::sync::mpsc::unbounded_channel();
        let service = tokio::spawn(async move {
            for _ in 0..2 {
                let (mut stream, _) = uds_listener.accept().await.expect("UDS connection");
                connections_tx.send(()).expect("connection notification");
                tokio::spawn(async move {
                    let mut request = [0; 5];
                    stream.read_exact(&mut request).await.expect("read request");
                    assert_eq!(&request, b"hello");
                    stream.write_all(b"world").await.expect("write response");
                });
            }
        });

        let bridge_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bridge listener");
        let bridge_address = bridge_listener.local_addr().expect("bridge address");
        let (shutdown, shutdown_receiver) = oneshot::channel();
        let bridge = tokio::spawn(serve_proxy_connections(
            bridge_listener,
            socket_path,
            shutdown_receiver,
        ));

        for _ in 0..2 {
            let mut client = tokio::net::TcpStream::connect(bridge_address)
                .await
                .expect("TCP client");
            client.write_all(b"hello").await.expect("write request");
            client.shutdown().await.expect("close request side");
            let mut response = Vec::new();
            client
                .read_to_end(&mut response)
                .await
                .expect("read response");
            assert_eq!(response, b"world");
            connections_rx
                .recv()
                .await
                .expect("one UDS connection per accepted TCP client");
        }

        let _ = shutdown.send(());
        bridge.await.expect("bridge task");
        service.await.expect("UDS service");
    }
}
