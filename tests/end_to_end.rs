#![cfg(target_os = "linux")]

use std::fs;
use std::io::Read;
use std::net::SocketAddr;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use base64::Engine as _;
use futures_util::StreamExt;
use gantry::{
    ExecutionBackend, RawStreamEvent, RunCommandCheckOutput, RunCommandInput, RunCommandOutput,
};
use rmcp::ServiceExt;
use rmcp::model::CallToolRequestParams;
use rmcp::transport::StreamableHttpClientTransport;
use rmcp::transport::streamable_http_client::StreamableHttpClientTransportConfig;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixListener;
use tokio::time::{Instant, sleep};

const PRINTF: &str = "/usr/bin/printf";
const FALSE: &str = "/usr/bin/false";

struct ServerProcess(Child);

impl Drop for ServerProcess {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

impl ServerProcess {
    fn stop(&mut self) -> Vec<u8> {
        let _ = self.0.kill();
        let _ = self.0.wait();
        let mut stderr = Vec::new();
        if let Some(mut stream) = self.0.stdout.take() {
            let _ = stream.read_to_end(&mut stderr);
        }
        if let Some(mut stream) = self.0.stderr.take() {
            let _ = stream.read_to_end(&mut stderr);
        }
        stderr
    }
}

#[derive(Clone, Copy)]
enum Listener {
    Tcp,
    Uds,
}

#[tokio::test]
async fn server_transport_backend_matrix() {
    let bubblewrap_supported = bubblewrap_probe().await;
    if std::env::var_os("GANTRY_REQUIRE_BUBBLEWRAP_TESTS").is_some() {
        assert!(
            bubblewrap_supported,
            "Bubblewrap end-to-end coverage is required but its namespaces are unavailable"
        );
    } else if !bubblewrap_supported {
        eprintln!("skipping Bubblewrap cases in end-to-end matrix: namespaces unavailable");
    }

    for listener in [Listener::Tcp, Listener::Uds] {
        exercise_server(ExecutionBackend::Direct, listener).await;
        if bubblewrap_supported {
            exercise_server(ExecutionBackend::Bubblewrap, listener).await;
        }
    }
}

#[tokio::test]
async fn gantry_parent_termination_stops_bubblewrap_descendants() {
    let bubblewrap_supported = bubblewrap_probe().await;
    if !bubblewrap_supported {
        if std::env::var_os("GANTRY_REQUIRE_BUBBLEWRAP_TESTS").is_some() {
            panic!("Bubblewrap parent-termination test requires working namespaces");
        }
        eprintln!("skipping Bubblewrap parent-termination test: namespaces unavailable");
        return;
    }

    let root = tempfile::tempdir().expect("temporary parent-death fixture");
    let policies = root.path().join("policies");
    let filesystems = root.path().join("filesystems");
    let workspace = root.path().join("workspace");
    fs::create_dir_all(&policies).expect("policy directory");
    fs::create_dir_all(&filesystems).expect("filesystem directory");
    fs::create_dir_all(&workspace).expect("workspace mount source");
    fs::write(
        policies.join("main.rego"),
        format!(
            "package sandbox.main\n\ndefault decision := {{\"allow\": false, \"filesystem\": null, \"baffle_session\": null}}\nallowed_paths := {{{}: true, {}: true}}\ndecision := {{\"allow\": true, \"filesystem\": \"workspace\", \"baffle_session\": null}} if {{ allowed_paths[input.path] }}\n",
            serde_json::to_string("/usr/bin/dash").expect("encode shell path"),
            serde_json::to_string(PRINTF).expect("encode readiness command"),
        ),
    )
    .expect("shell policy");
    fs::write(
        filesystems.join("workspace.toml"),
        format!(
            "version = 1\n\n[[mounts]]\nsource = {:?}\ntarget = \"/tools\"\naccess = \"read-only\"\n\n[[mounts]]\nsource = {:?}\ntarget = \"/workspace\"\naccess = \"read-write\"\n",
            "/usr/bin",
            workspace.to_string_lossy(),
        ),
    )
    .expect("workspace filesystem profile");

    let probe = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("reserve TCP address");
    let address: SocketAddr = probe.local_addr().expect("TCP address");
    drop(probe);
    let mut server_command = Command::new(env!("CARGO_BIN_EXE_gantry"));
    let server = server_command
        .arg("--bind-addr")
        .arg(address.to_string())
        .arg("--policy-dir")
        .arg(&policies)
        .args(["--backend", "bubblewrap"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("start Bubblewrap Gantry server");
    let mut server = ServerProcess(server);

    let client = reqwest::Client::new();
    let base_url = format!("http://{address}");
    wait_until_ready(&client, &base_url, ExecutionBackend::Bubblewrap).await;

    let marker = workspace.join("descendant-completed-after-parent-death");
    let ready_file = workspace.join("descendant-started");
    let script = "echo ready > /workspace/descendant-started; (/tools/sleep 3; /tools/touch /workspace/descendant-completed-after-parent-death) & wait";
    let mut response = client
        .post(format!("{base_url}/raw"))
        .json(&RunCommandInput {
            executable: "/usr/bin/dash".into(),
            args: vec!["-c".into(), script.into(), "gantry-parent-test".into()],
            cwd: Some("/".into()),
            env: None,
        })
        .send()
        .await
        .expect("start long-running sandbox command")
        .error_for_status()
        .expect("raw stream response")
        .bytes_stream();
    let start_event = tokio::time::timeout(Duration::from_secs(5), async {
        while let Some(chunk) = response.next().await {
            let chunk = chunk.expect("read raw event");
            if String::from_utf8_lossy(&chunk).contains("\"event\":\"start\"") {
                return;
            }
        }
        panic!("raw stream closed before the child started");
    })
    .await;
    assert!(start_event.is_ok(), "authorized command did not start");

    tokio::time::timeout(Duration::from_secs(3), async {
        while !ready_file.exists() {
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("shell did not start its descendant");
    server.stop();
    sleep(Duration::from_secs(4)).await;
    assert!(!marker.exists());
    drop(response);
}

#[tokio::test]
async fn baffle_diagnostics_report_session_identity_without_request_secrets() {
    if !bubblewrap_probe().await {
        if std::env::var_os("GANTRY_REQUIRE_BUBBLEWRAP_TESTS").is_some() {
            panic!("Baffle diagnostic test requires working Bubblewrap namespaces");
        }
        eprintln!("skipping Baffle diagnostic test: namespaces unavailable");
        return;
    }

    let root = tempfile::tempdir().expect("temporary Baffle diagnostic fixture");
    let policies = root.path().join("policies");
    let filesystems = root.path().join("filesystems");
    let socket_dir = root.path().join("proxies");
    fs::create_dir_all(&policies).expect("policy directory");
    fs::create_dir_all(&filesystems).expect("filesystem directory");
    fs::create_dir_all(&socket_dir).expect("Baffle session socket directory");
    fs::write(
        policies.join("main.rego"),
        format!(
            "package sandbox.main\n\ndefault decision := {{\"allow\": false, \"filesystem\": null, \"baffle_session\": null}}\nallowed_paths := {{{}: true, {}: true}}\ndecision := {{\"allow\": true, \"filesystem\": \"minimal\", \"baffle_session\": \"diagnostics.toml\"}} if {{ allowed_paths[input.path] }}\n",
            serde_json::to_string("/usr/bin/true").expect("encode true path"),
            serde_json::to_string(PRINTF).expect("encode readiness path"),
        ),
    )
    .expect("Baffle diagnostic policy");
    fs::write(
        filesystems.join("minimal.toml"),
        "version = 1\nmounts = []\n",
    )
    .expect("minimal filesystem profile");

    let control_path = root.path().join("control.sock");
    let session_path = socket_dir.join("phase4-session.sock");
    let control_listener = UnixListener::bind(&control_path).expect("mock Baffle control socket");
    let _session_listener = UnixListener::bind(&session_path).expect("mock Baffle data socket");
    let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()])
        .expect("generate Baffle CA fixture");
    let ca_certificate_pem = certificate.cert.pem();
    let (lease_closed_tx, lease_closed_rx) = tokio::sync::oneshot::channel();
    let session_path_response = session_path.clone();
    let daemon = tokio::spawn(async move {
        let (mut stream, _) = control_listener
            .accept()
            .await
            .expect("Gantry creates the selected Baffle session");
        let mut header = [0; 4];
        stream
            .read_exact(&mut header)
            .await
            .expect("read frame length");
        let mut request = vec![0; u32::from_be_bytes(header) as usize];
        stream
            .read_exact(&mut request)
            .await
            .expect("read create request");
        let request = String::from_utf8(request).expect("request TOML");
        assert!(request.contains("operation = \"create_from_file\""));
        assert!(request.contains("require_ephemeral = true"));
        assert!(request.contains("name = \"diagnostics.toml\""));
        let response = serde_json::to_vec(&serde_json::json!({
            "version": 2,
            "ok": true,
            "result": {
                "id": "phase4-session-safe",
                "socket": session_path_response,
                "persistent": false,
                "ca_certificate_pem": ca_certificate_pem
            }
        }))
        .expect("mock Baffle response JSON");
        stream
            .write_all(&(response.len() as u32).to_be_bytes())
            .await
            .expect("write frame length");
        stream
            .write_all(&response)
            .await
            .expect("write session response");
        let mut byte = [0; 1];
        assert_eq!(stream.read(&mut byte).await.expect("read lease release"), 0);
        lease_closed_tx
            .send(())
            .expect("report Baffle lease release");
    });

    let probe = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("reserve TCP address");
    let address = probe.local_addr().expect("TCP address");
    drop(probe);
    let mut command = Command::new(env!("CARGO_BIN_EXE_gantry"));
    let server = command
        .arg("--bind-addr")
        .arg(address.to_string())
        .arg("--policy-dir")
        .arg(&policies)
        .args(["--backend", "bubblewrap"])
        .env("GANTRY_BAFFLE_CONTROL_SOCKET", &control_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start Gantry server for Baffle diagnostics");
    let mut server = ServerProcess(server);

    let client = reqwest::Client::new();
    let address = format!("http://{address}");
    wait_until_ready(&client, &address, ExecutionBackend::Bubblewrap).await;
    let checked = client
        .post(format!("{address}/check"))
        .json(&input("/usr/bin/true", vec![], "/"))
        .send()
        .await
        .expect("check Baffle command")
        .json::<RunCommandCheckOutput>()
        .await
        .expect("Baffle command check response");
    assert_eq!(checked.baffle_session.as_deref(), Some("diagnostics.toml"));

    let response = client
        .post(format!("{address}/raw"))
        .json(&serde_json::json!({
            "executable": "/usr/bin/true",
            "args": ["credential-sentinel-991e"],
            "cwd": "/",
            "env": {"API_TOKEN": "credential-sentinel-991e"}
        }))
        .send()
        .await
        .expect("start Baffle command");
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.expect("read Baffle error response");
        let logs = String::from_utf8_lossy(&server.stop()).into_owned();
        panic!("Baffle command failed with {status}: {body}\nGantry logs:\n{logs}");
    }
    let events = response
        .bytes()
        .await
        .expect("Baffle raw stream")
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice::<RawStreamEvent>(line).expect("raw event JSON"))
        .collect::<Vec<_>>();
    assert!(matches!(
        events.last(),
        Some(RawStreamEvent::Exit { exit_code: Some(0) })
    ));
    tokio::time::timeout(Duration::from_secs(3), lease_closed_rx)
        .await
        .expect("Baffle lease was not released after command completion")
        .expect("Baffle daemon reported lease release");
    daemon.await.expect("mock Baffle daemon task");

    let logs = String::from_utf8_lossy(&server.stop()).into_owned();
    assert!(logs.contains("diagnostics.toml"), "{logs}");
    assert!(logs.contains("phase4-session-safe"), "{logs}");
    assert!(
        !logs.contains("credential-sentinel-991e"),
        "request credentials must not appear in logs: {logs}"
    );
}

async fn exercise_server(backend: ExecutionBackend, listener: Listener) {
    let root = tempfile::tempdir().expect("temporary system-test directory");
    let policies = root.path().join("policies");
    let filesystems = root.path().join("filesystems");
    fs::create_dir_all(&policies).expect("policy directory");
    fs::create_dir_all(&filesystems).expect("filesystem directory");
    fs::write(
        policies.join("main.rego"),
        format!(
            "package sandbox.main\n\ndefault decision := {{\"allow\": false, \"filesystem\": null, \"baffle_session\": null}}\n\nallowed_paths := {{{}: true, {}: true}}\ndecision := {{\"allow\": true, \"filesystem\": {}, \"baffle_session\": null}} if {{ allowed_paths[input.path] }}\n",
            serde_json::to_string(PRINTF).expect("encode printf path"),
            serde_json::to_string(FALSE).expect("encode false path"),
            if backend == ExecutionBackend::Bubblewrap {
                "\"minimal\""
            } else {
                "null"
            },
        ),
    )
    .expect("policy file");
    fs::write(
        filesystems.join("minimal.toml"),
        "version = 1\nmounts = []\n",
    )
    .expect("minimal filesystem profile");

    let socket_path = root.path().join("gantry.sock");
    let (address, mut server) = start_server(backend, listener, &policies, &socket_path).await;
    let client = http_client(listener, &socket_path).expect("HTTP client");
    wait_until_ready(&client, &address, backend).await;

    let check = client
        .post(format!("{address}/check"))
        .json(&input(PRINTF, vec!["check"], "/"))
        .send()
        .await
        .expect("/check request")
        .error_for_status()
        .expect("/check response")
        .json::<RunCommandCheckOutput>()
        .await
        .expect("/check decision");
    assert!(check.allowed, "{backend:?}: {:?}", check.reason);
    assert_eq!(check.backend, backend.as_str());
    assert_eq!(
        check.filesystem.as_deref(),
        (backend == ExecutionBackend::Bubblewrap).then_some("minimal")
    );
    assert_eq!(check.baffle_session, None);

    let raw = client
        .post(format!("{address}/raw"))
        .json(&input(PRINTF, vec!["credential-sentinel-42f7"], "/"))
        .send()
        .await
        .expect("/raw request")
        .error_for_status()
        .expect("/raw response");
    let events = raw
        .bytes()
        .await
        .expect("/raw event stream")
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice::<RawStreamEvent>(line).expect("raw event JSON"))
        .collect::<Vec<_>>();
    assert!(matches!(events.first(), Some(RawStreamEvent::Start {})));
    let output = events
        .iter()
        .filter_map(|event| match event {
            RawStreamEvent::Stdout { data_b64 } => Some(
                base64::engine::general_purpose::STANDARD
                    .decode(data_b64)
                    .expect("stdout base64"),
            ),
            _ => None,
        })
        .flatten()
        .collect::<Vec<_>>();
    assert_eq!(output, b"credential-sentinel-42f7");
    assert!(matches!(
        events.last(),
        Some(RawStreamEvent::Exit { exit_code: Some(0) })
    ));

    let nonzero = client
        .post(format!("{address}/raw"))
        .json(&input(FALSE, vec![], "/"))
        .send()
        .await
        .expect("nonzero /raw request")
        .error_for_status()
        .expect("nonzero /raw response")
        .bytes()
        .await
        .expect("nonzero /raw stream")
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice::<RawStreamEvent>(line).expect("raw event JSON"))
        .collect::<Vec<_>>();
    assert!(matches!(
        nonzero.last(),
        Some(RawStreamEvent::Exit { exit_code: Some(1) })
    ));

    let remote = run_remote_check(listener, &address, &socket_path);
    assert_eq!(remote.0, 0, "run-remote --check failed: {}", remote.2);
    let remote_check: RunCommandCheckOutput =
        serde_json::from_slice(&remote.1).expect("run-remote check JSON");
    assert!(remote_check.allowed, "{:?}", remote_check.reason);
    assert_eq!(remote_check.backend, backend.as_str());

    let mcp_http_client = http_client(listener, &socket_path).expect("MCP HTTP client");
    let transport = StreamableHttpClientTransport::<reqwest::Client>::with_client(
        mcp_http_client,
        StreamableHttpClientTransportConfig::with_uri(format!("{address}/mcp")),
    );
    let client = ().serve(transport).await.expect("connect MCP client");
    let check = client
        .call_tool(CallToolRequestParams {
            meta: None,
            name: "check_command".to_string().into(),
            arguments: Some(
                serde_json::json!({
                    "executable": PRINTF,
                    "args": ["mcp-check"],
                    "cwd": "/"
                })
                .as_object()
                .cloned()
                .expect("MCP check object"),
            ),
            task: None,
        })
        .await
        .expect("MCP check command");
    let check: RunCommandCheckOutput = check.into_typed().expect("typed MCP check");
    assert!(check.allowed, "{:?}", check.reason);
    assert_eq!(check.backend, backend.as_str());

    let result = client
        .call_tool(CallToolRequestParams {
            meta: None,
            name: "run_command".to_string().into(),
            arguments: Some(
                serde_json::json!({
                    "executable": PRINTF,
                    "args": ["mcp-output"],
                    "cwd": "/"
                })
                .as_object()
                .cloned()
                .expect("MCP run object"),
            ),
            task: None,
        })
        .await
        .expect("MCP run command");
    let result: RunCommandOutput = result.into_typed().expect("typed MCP output");
    assert_eq!(result.stdout, "mcp-output");
    assert_eq!(result.exit_code, Some(0));
    client.cancel().await.expect("cancel MCP client");

    let logs = String::from_utf8_lossy(&server.stop()).into_owned();
    assert!(logs.contains("raw request accepted"), "{logs}");
    assert!(logs.contains(backend.as_str()), "{logs}");
    assert!(
        logs.contains("execution finished and resources were released"),
        "{logs}"
    );
    assert!(
        !logs.contains("credential-sentinel-42f7"),
        "request arguments must not appear in logs: {logs}"
    );
}

async fn start_server(
    backend: ExecutionBackend,
    listener: Listener,
    policy_dir: &Path,
    socket_path: &Path,
) -> (String, ServerProcess) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_gantry"));
    match listener {
        Listener::Tcp => {
            let probe = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("reserve TCP address");
            let address = probe.local_addr().expect("TCP address");
            drop(probe);
            command
                .arg("--bind-addr")
                .arg(address.to_string())
                .arg("--policy-dir")
                .arg(policy_dir)
                .args(["--backend", backend.as_str()])
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            let child = command.spawn().expect("start TCP Gantry server");
            (format!("http://{address}"), ServerProcess(child))
        }
        Listener::Uds => {
            command
                .arg("--bind-uds")
                .arg(socket_path)
                .arg("--policy-dir")
                .arg(policy_dir)
                .args(["--backend", backend.as_str()])
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            let child = command.spawn().expect("start UDS Gantry server");
            ("http://localhost".to_string(), ServerProcess(child))
        }
    }
}

fn http_client(listener: Listener, socket_path: &Path) -> Result<reqwest::Client, reqwest::Error> {
    match listener {
        Listener::Tcp => reqwest::Client::builder().build(),
        Listener::Uds => reqwest::Client::builder().unix_socket(socket_path).build(),
    }
}

async fn wait_until_ready(client: &reqwest::Client, address: &str, backend: ExecutionBackend) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let ready = client
            .post(format!("{address}/check"))
            .json(&input(PRINTF, vec![], "/"))
            .send()
            .await;
        let failure = match ready {
            Ok(response) => match response.error_for_status() {
                Ok(response) => match response.json::<RunCommandCheckOutput>().await {
                    Ok(decision) if decision.allowed && decision.backend == backend.as_str() => {
                        return;
                    }
                    Ok(decision) => {
                        format!("check denied or reported another backend: {decision:?}")
                    }
                    Err(error) => format!("invalid check response: {error}"),
                },
                Err(error) => format!("check returned an HTTP error: {error}"),
            },
            Err(error) => format!("check request failed: {error}"),
        };
        assert!(
            Instant::now() < deadline,
            "Gantry server did not become ready: {failure}"
        );
        sleep(Duration::from_millis(50)).await;
    }
}

fn run_remote_check(
    listener: Listener,
    address: &str,
    socket_path: &Path,
) -> (i32, Vec<u8>, String) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_run-remote"));
    command
        .args(["--check", "--", PRINTF])
        .env_remove("RUN_REMOTE_SERVER")
        .env_remove("RUN_REMOTE_SOCKET")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    match listener {
        Listener::Tcp => {
            command.env("RUN_REMOTE_SERVER", format!("{address}/raw"));
        }
        Listener::Uds => {
            command.env("RUN_REMOTE_SOCKET", socket_path);
        }
    }
    let output = command.output().expect("run run-remote --check");
    (
        output.status.code().unwrap_or(128),
        output.stdout,
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

fn input(executable: &str, args: Vec<&str>, cwd: &str) -> RunCommandInput {
    RunCommandInput {
        executable: executable.to_string(),
        args: args.into_iter().map(str::to_owned).collect(),
        cwd: Some(cwd.to_string()),
        env: None,
    }
}

async fn bubblewrap_probe() -> bool {
    let executable = ["/usr/bin/bwrap", "/bin/bwrap"]
        .into_iter()
        .find(|path| Path::new(path).is_file());
    let Some(executable) = executable else {
        return false;
    };
    let mut probe = tokio::process::Command::new(executable);
    probe
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
        .env_clear();
    probe.status().await.is_ok_and(|status| status.success())
}
