#![cfg(target_os = "linux")]

use std::collections::BTreeMap;
use std::fs;
use std::net::{SocketAddr, SocketAddrV6};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use baffle_client::Client;
use gantry::{
    BaffleRuntimeConfig, ExecutionBackend, PolicyEngine, RunCommandInput,
    run_command_with_baffle_config,
};
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio::time::{Instant, sleep, timeout};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

struct BaffleDaemon {
    child: Child,
    control_socket: PathBuf,
    session_socket_dir: PathBuf,
    ca_certificate: PathBuf,
    daemon_log: PathBuf,
}

impl Drop for BaffleDaemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

struct Origin {
    port: u16,
    stop: Vec<tokio::sync::oneshot::Sender<()>>,
    tasks: Vec<JoinHandle<()>>,
}

impl Drop for Origin {
    fn drop(&mut self) {
        for stop in self.stop.drain(..) {
            let _ = stop.send(());
        }
        for task in &self.tasks {
            task.abort();
        }
    }
}

#[tokio::test]
async fn bubblewrap_routes_only_through_distinct_file_backed_baffle_sessions() {
    let Some(binary) = std::env::var_os("GANTRY_BAFFLE_TEST_BINARY").map(PathBuf::from) else {
        eprintln!("skipping live Baffle integration: GANTRY_BAFFLE_TEST_BINARY is unset");
        return;
    };
    if !Path::new("/usr/bin/bwrap").is_file() && !Path::new("/bin/bwrap").is_file() {
        eprintln!("skipping live Baffle integration: Bubblewrap is unavailable");
        return;
    }

    let directory = tempfile::tempdir_in("/dev/shm").expect("temporary fixture directory");
    let origin = start_https_origin(directory.path()).await;
    let upstream_ca = directory.path().join("upstream-ca.pem");
    let daemon = start_baffle_daemon(&binary, directory.path(), &upstream_ca);
    let baffle = BaffleRuntimeConfig {
        control_socket: daemon.control_socket.clone(),
        session_socket_dir: daemon.session_socket_dir.clone(),
        ca_certificate: Some(daemon.ca_certificate.clone()),
    };

    write_session_file(
        directory.path(),
        "path-a.toml",
        origin.port,
        &["/a", "/hold"],
    );
    write_session_file(directory.path(), "path-b.toml", origin.port, &["/b"]);
    let curl = Path::new("/usr/bin/curl");
    assert!(
        curl.is_file(),
        "curl is required for the controlled HTTPS test"
    );
    // Each engine watches its policy directory for changes. Keep fixture
    // generations separate so loading one decision cannot reload another.
    let policy_a_root = directory.path().join("policy-a");
    let policy_b_root = directory.path().join("policy-b");
    let policy_a = Arc::new(policy_engine(&policy_a_root, curl, Some("path-a.toml")));
    let policy_b = Arc::new(policy_engine(&policy_b_root, curl, Some("path-b.toml")));
    let cwd = PathBuf::from("/");
    let port = origin.port;

    // Both requests remain active long enough to inspect the live lease set.
    let policy_a_for_task = Arc::clone(&policy_a);
    let cwd_a = cwd.clone();
    let baffle_a = baffle.clone();
    let request_a = tokio::spawn(async move {
        run_command_with_baffle_config(
            &policy_a_for_task,
            &cwd_a,
            ExecutionBackend::Bubblewrap,
            baffle_a,
            curl_input(port, "/a", hostile_proxy_environment()),
        )
        .await
    });
    let policy_b_for_task = Arc::clone(&policy_b);
    let cwd_b = cwd.clone();
    let baffle_b = baffle.clone();
    let request_b = tokio::spawn(async move {
        run_command_with_baffle_config(
            &policy_b_for_task,
            &cwd_b,
            ExecutionBackend::Bubblewrap,
            baffle_b,
            curl_input(port, "/b", hostile_proxy_environment()),
        )
        .await
    });

    let client = Client::new(&daemon.control_socket);
    let active_sessions = wait_for_sessions(&client, 2).await;
    assert_ne!(
        active_sessions[0].socket_path, active_sessions[1].socket_path,
        "concurrent authorized commands must receive distinct data sockets"
    );
    let (result_a, result_b) = tokio::join!(request_a, request_b);
    let result_a = result_a
        .expect("first request task")
        .expect("first command");
    let result_b = result_b
        .expect("second request task")
        .expect("second command");
    let diagnostics = format!(
        "Baffle daemon log:\n{}",
        fs::read_to_string(&daemon.daemon_log).unwrap_or_else(|error| error.to_string())
    );
    assert!(
        result_a.exit_code == Some(0) && result_b.exit_code == Some(0),
        "concurrent HTTPS requests failed\nA: exit={:?}; stderr:\n{}\nstdout:\n{}\nB: exit={:?}; stderr:\n{}\nstdout:\n{}\n{}",
        result_a.exit_code,
        result_a.stderr,
        result_a.stdout,
        result_b.exit_code,
        result_b.stderr,
        result_b.stdout,
        diagnostics,
    );
    assert_eq!(result_a.stdout, "served /a\n");
    assert_eq!(result_b.stdout, "served /b\n");
    wait_for_sessions(&client, 0).await;

    let denied_path = run_command_with_baffle_config(
        &policy_a,
        &cwd,
        ExecutionBackend::Bubblewrap,
        baffle.clone(),
        curl_input(origin.port, "/b", hostile_proxy_environment()),
    )
    .await
    .expect("denied path is a command result");
    assert_ne!(denied_path.exit_code, Some(0));
    wait_for_sessions(&client, 0).await;

    let denied_destination = run_command_with_baffle_config(
        &policy_a,
        &cwd,
        ExecutionBackend::Bubblewrap,
        baffle.clone(),
        curl_input_for_host(
            "denied.invalid",
            origin.port,
            "/a",
            hostile_proxy_environment(),
        ),
    )
    .await
    .expect("denied destination is a command result");
    assert_ne!(denied_destination.exit_code, Some(0));
    wait_for_sessions(&client, 0).await;

    // Check the mounted endpoint and public CA from inside the sandbox. The
    // Baffle control socket, its directory, another session, and the key stay
    // at their host paths and must not appear in the command's filesystem.
    let other_lease = client
        .create_from_file("path-a.toml")
        .await
        .expect("create another active session for the visibility check");
    let other_socket = other_lease.socket_path().to_path_buf();
    let shell = Path::new("/usr/bin/dash");
    let visibility_policy = policy_engine(
        &directory.path().join("visibility-policy"),
        shell,
        Some("path-a.toml"),
    );
    let visibility_script = concat!(
        "test -S /run/gantry/proxy.sock || exit 41; ",
        "test -f /run/gantry/baffle-ca.pem || exit 42; ",
        "test ! -e \"$1\" || exit 43; ",
        "test ! -e \"$2\" || exit 44; ",
        "test ! -e \"$3\" || exit 45; ",
        "test ! -e \"$4\" || exit 46"
    );
    let visibility = run_command_with_baffle_config(
        &visibility_policy,
        &cwd,
        ExecutionBackend::Bubblewrap,
        baffle.clone(),
        RunCommandInput {
            executable: shell.to_string_lossy().into_owned(),
            args: vec![
                "-c".into(),
                visibility_script.into(),
                "gantry-test".into(),
                daemon.control_socket.to_string_lossy().into_owned(),
                daemon.session_socket_dir.to_string_lossy().into_owned(),
                other_socket.to_string_lossy().into_owned(),
                directory
                    .path()
                    .join("baffle/ca-key.pem")
                    .to_string_lossy()
                    .into_owned(),
            ],
            cwd: Some("/".into()),
            env: None,
        },
    )
    .await
    .expect("visibility probe starts");
    assert_eq!(visibility.exit_code, Some(0), "{}", visibility.stderr);
    drop(other_lease);
    wait_for_sessions(&client, 0).await;

    // A no-session execution has neither bridge nor Baffle CA access.
    let no_session_shell_policy = policy_engine(
        &directory.path().join("no-session-shell-policy"),
        shell,
        None,
    );
    let no_session_visibility = run_command_with_baffle_config(
        &no_session_shell_policy,
        &cwd,
        ExecutionBackend::Bubblewrap,
        baffle.clone(),
        RunCommandInput {
            executable: shell.to_string_lossy().into_owned(),
            args: vec![
                "-c".into(),
                "test ! -e /run/gantry/proxy.sock && test ! -e /run/gantry/baffle-ca.pem".into(),
            ],
            cwd: Some("/".into()),
            env: Some(hostile_proxy_environment()),
        },
    )
    .await
    .expect("no-session Bubblewrap visibility probe");
    assert_eq!(
        no_session_visibility.exit_code,
        Some(0),
        "{}",
        no_session_visibility.stderr
    );

    let no_session_curl_policy =
        policy_engine(&directory.path().join("no-session-curl-policy"), curl, None);
    let no_session = run_command_with_baffle_config(
        &no_session_curl_policy,
        &cwd,
        ExecutionBackend::Bubblewrap,
        baffle.clone(),
        RunCommandInput {
            executable: curl.to_string_lossy().into_owned(),
            args: vec![
                "--silent".into(),
                "--show-error".into(),
                "--connect-timeout".into(),
                "1".into(),
                "--proxy".into(),
                "http://127.0.0.1:3128".into(),
                "http://example.invalid/".into(),
            ],
            cwd: Some("/".into()),
            env: Some(hostile_proxy_environment()),
        },
    )
    .await
    .expect("no-session Bubblewrap command starts");
    assert_ne!(no_session.exit_code, Some(0));
    assert!(
        no_session
            .stderr
            .to_ascii_lowercase()
            .contains("failed to connect"),
        "no-session execution must have no local proxy listener: {}",
        no_session.stderr
    );
    wait_for_sessions(&client, 0).await;

    // A supervisor spawn failure occurs after provisioning. It must still
    // stop the bridge and release its ephemeral Baffle lease.
    let missing_cwd = tempfile::tempdir().expect("host cwd fixture");
    let spawn_error = run_command_with_baffle_config(
        &policy_a,
        &cwd,
        ExecutionBackend::Bubblewrap,
        baffle.clone(),
        RunCommandInput {
            executable: curl.to_string_lossy().into_owned(),
            args: vec![],
            cwd: Some(missing_cwd.path().to_string_lossy().into_owned()),
            env: None,
        },
    )
    .await
    .expect_err("unmounted CWD must fail supervisor startup");
    assert!(spawn_error.to_string().contains("startup failed"));
    wait_for_sessions(&client, 0).await;

    // Cancel an active CONNECT request. The supervisor and bridge must stop
    // before Gantry closes the Baffle lease.
    let cancel_policy = Arc::clone(&policy_a);
    let cancel_cwd = cwd.clone();
    let cancel_baffle = baffle.clone();
    let cancel_task = tokio::spawn(async move {
        run_command_with_baffle_config(
            &cancel_policy,
            &cancel_cwd,
            ExecutionBackend::Bubblewrap,
            cancel_baffle,
            curl_input(port, "/hold", hostile_proxy_environment()),
        )
        .await
    });
    wait_for_sessions(&client, 1).await;
    sleep(Duration::from_millis(250)).await;
    cancel_task.abort();
    let _ = cancel_task.await;
    wait_for_sessions(&client, 0).await;

    drop(origin);
    drop(daemon);
}

#[tokio::test]
async fn bubblewrap_mounts_a_mock_file_only_baffle_uds_and_releases_its_lease() {
    if std::env::var_os("GANTRY_REQUIRE_BUBBLEWRAP_TESTS").is_none() {
        eprintln!("skipping mock Baffle UDS mount: required Bubblewrap tests are disabled");
        return;
    }
    if !Path::new("/usr/bin/bwrap").is_file() && !Path::new("/bin/bwrap").is_file() {
        panic!("Bubblewrap is required for the mock Baffle UDS mount test");
    }
    let directory = tempfile::tempdir_in("/dev/shm").expect("mock fixture directory");
    run_mock_uds_mount(directory.path()).await;
}

#[tokio::test]
async fn baffle_creation_failure_prevents_command_start() {
    if std::env::var_os("GANTRY_REQUIRE_BUBBLEWRAP_TESTS").is_none() {
        eprintln!("skipping Baffle creation failure test: required Bubblewrap tests are disabled");
        return;
    }
    if !Path::new("/usr/bin/bwrap").is_file() && !Path::new("/bin/bwrap").is_file() {
        panic!("Bubblewrap is required for the Baffle creation failure test");
    }

    let directory = tempfile::tempdir_in("/dev/shm").expect("temporary fixture directory");
    let socket_dir = directory.path().join("proxies");
    fs::create_dir_all(&socket_dir).expect("Baffle socket directory");
    let control_path = directory.path().join("control.sock");
    let control_listener =
        tokio::net::UnixListener::bind(&control_path).expect("mock Baffle control socket");
    let daemon = tokio::spawn(async move {
        let (mut stream, _) = control_listener
            .accept()
            .await
            .expect("Gantry attempts Baffle session creation");
        let mut header = [0; 4];
        stream
            .read_exact(&mut header)
            .await
            .expect("read Baffle request frame length");
        let mut request = vec![0; u32::from_be_bytes(header) as usize];
        stream
            .read_exact(&mut request)
            .await
            .expect("read Baffle request");
        let request = String::from_utf8(request).expect("Baffle request is UTF-8");
        assert!(request.contains("operation = \"create_from_file\""));
        assert!(request.contains("name = \"unavailable.toml\""));

        let response = serde_json::to_vec(&serde_json::json!({
            "version": 2,
            "ok": false,
            "error": {
                "code": "config_file_not_found",
                "message": "selected session is unavailable"
            }
        }))
        .expect("Baffle error response JSON");
        stream
            .write_all(&(response.len() as u32).to_be_bytes())
            .await
            .expect("write Baffle response length");
        stream
            .write_all(&response)
            .await
            .expect("write Baffle error response");
    });

    let ca_certificate = directory.path().join("ca.pem");
    fs::write(
        &ca_certificate,
        "-----BEGIN CERTIFICATE-----\nZm9v\n-----END CERTIFICATE-----\n",
    )
    .expect("write public certificate fixture");
    let executable = Path::new("/usr/bin/true");
    let policy = policy_engine(directory.path(), executable, Some("unavailable.toml"));
    let error = run_command_with_baffle_config(
        &policy,
        Path::new("/"),
        ExecutionBackend::Bubblewrap,
        BaffleRuntimeConfig {
            control_socket: control_path,
            session_socket_dir: socket_dir,
            ca_certificate: Some(ca_certificate),
        },
        RunCommandInput {
            executable: executable.to_string_lossy().into_owned(),
            args: vec![],
            cwd: Some("/".into()),
            env: None,
        },
    )
    .await
    .expect_err("failed Baffle creation prevents command startup");
    assert!(
        matches!(error, gantry::ToolError::BackendSetup { .. }),
        "unexpected error: {error}"
    );
    assert!(
        error
            .to_string()
            .contains("selected session is unavailable")
    );
    daemon.await.expect("mock Baffle error response completed");
}

async fn run_mock_uds_mount(root: &Path) {
    let mock_root = root.join("mock-baffle");
    let socket_dir = mock_root.join("proxies");
    fs::create_dir_all(&socket_dir).expect("mock Baffle socket directory");
    let control_path = mock_root.join("control.sock");
    let assigned_socket = socket_dir.join("mock-session.sock");
    let control_listener =
        tokio::net::UnixListener::bind(&control_path).expect("mock control listener");
    let proxy_listener =
        tokio::net::UnixListener::bind(&assigned_socket).expect("mock data listener");
    let response_socket = assigned_socket.clone();
    let control_task = tokio::spawn(async move {
        let (mut stream, _) = control_listener
            .accept()
            .await
            .expect("Gantry connects to mock Baffle control socket");
        let mut header = [0; 4];
        stream
            .read_exact(&mut header)
            .await
            .expect("read create_from_file frame length");
        let mut request = vec![0; u32::from_be_bytes(header) as usize];
        stream
            .read_exact(&mut request)
            .await
            .expect("read create_from_file request");
        let request = String::from_utf8(request).expect("request is UTF-8 TOML");
        assert!(request.contains("operation = \"create_from_file\""));
        assert!(request.contains("name = \"mock.toml\""));

        let response = serde_json::to_vec(&serde_json::json!({
            "version": 2,
            "ok": true,
            "result": {
                "id": "mock-session",
                "socket": response_socket,
                "persistent": false
            }
        }))
        .expect("mock response JSON");
        stream
            .write_all(&(response.len() as u32).to_be_bytes())
            .await
            .expect("write mock response length");
        stream
            .write_all(&response)
            .await
            .expect("write mock response");
        let mut byte = [0; 1];
        assert_eq!(stream.read(&mut byte).await.expect("read lease close"), 0);
    });
    let proxy_task = tokio::spawn(async move {
        let (mut stream, _) = proxy_listener
            .accept()
            .await
            .expect("bridge connects to the assigned mock UDS");
        let mut request = Vec::new();
        let mut buffer = [0; 1024];
        loop {
            let count = stream.read(&mut buffer).await.expect("read proxy request");
            assert_ne!(count, 0, "mock proxy request ended before headers");
            request.extend_from_slice(&buffer[..count]);
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        let request = String::from_utf8_lossy(&request);
        assert!(request.starts_with("GET http://mock.invalid/resource "));
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 17\r\nConnection: close\r\n\r\nmock UDS reached\n",
            )
            .await
            .expect("write mock proxy response");
    });

    let ca_certificate = mock_root.join("ca.pem");
    fs::write(
        &ca_certificate,
        "-----BEGIN CERTIFICATE-----\nZm9v\n-----END CERTIFICATE-----\n",
    )
    .expect("write mock public certificate");
    let policy = policy_engine(root, Path::new("/usr/bin/curl"), Some("mock.toml"));
    let output = run_command_with_baffle_config(
        &policy,
        Path::new("/"),
        ExecutionBackend::Bubblewrap,
        BaffleRuntimeConfig {
            control_socket: control_path,
            session_socket_dir: socket_dir,
            ca_certificate: Some(ca_certificate),
        },
        RunCommandInput {
            executable: "/usr/bin/curl".into(),
            args: vec![
                "--fail".into(),
                "--silent".into(),
                "--show-error".into(),
                "--max-time".into(),
                "10".into(),
                "--proxy".into(),
                "http://127.0.0.1:3128".into(),
                "--noproxy".into(),
                "".into(),
                "http://mock.invalid/resource".into(),
            ],
            cwd: Some("/".into()),
            env: Some(hostile_proxy_environment()),
        },
    )
    .await
    .expect("mock UDS mount execution");
    assert_eq!(output.exit_code, Some(0), "{}", output.stderr);
    assert_eq!(output.stdout, "mock UDS reached\n");
    control_task.await.expect("mock control lease task");
    proxy_task.await.expect("mock proxy task");
}

fn hostile_proxy_environment() -> BTreeMap<String, String> {
    BTreeMap::from([
        ("HTTP_PROXY".into(), "http://127.0.0.1:1".into()),
        ("HTTPS_PROXY".into(), "http://127.0.0.1:1".into()),
        ("ALL_PROXY".into(), "http://127.0.0.1:1".into()),
        ("NO_PROXY".into(), "*".into()),
        ("CURL_CA_BUNDLE".into(), "/definitely/not/a/ca.pem".into()),
    ])
}

fn curl_input(port: u16, path: &str, env: BTreeMap<String, String>) -> RunCommandInput {
    curl_input_for_host("localhost", port, path, env)
}

fn curl_input_for_host(
    host: &str,
    port: u16,
    path: &str,
    env: BTreeMap<String, String>,
) -> RunCommandInput {
    RunCommandInput {
        executable: "/usr/bin/curl".into(),
        args: vec![
            "--fail".into(),
            "--verbose".into(),
            "--silent".into(),
            "--show-error".into(),
            "--connect-timeout".into(),
            "3".into(),
            "--max-time".into(),
            "12".into(),
            format!("https://{host}:{port}{path}"),
        ],
        cwd: Some("/".into()),
        env: Some(env),
    }
}

fn policy_engine(root: &Path, executable: &Path, filename: Option<&str>) -> PolicyEngine {
    let policy_dir = root.join("gantry-policies");
    let filesystem_dir = root.join("filesystems");
    fs::create_dir_all(&policy_dir).expect("policy directory");
    fs::create_dir_all(&filesystem_dir).expect("filesystem directory");
    fs::write(
        policy_dir.join("main.rego"),
        format!(
            "package sandbox.main\n\ndefault decision := {{\"allow\": false, \"filesystem\": null, \"baffle_session\": null}}\n\ndecision := {{\"allow\": true, \"filesystem\": \"minimal\", \"baffle_session\": {}}} if {{\n  input.path == {:?}\n}}\n",
            filename
                .map(|value| format!("{value:?}"))
                .unwrap_or_else(|| "null".to_string()),
            executable.to_string_lossy()
        ),
    )
    .expect("policy file");
    fs::write(
        filesystem_dir.join("minimal.toml"),
        "version = 1\nmounts = []\n",
    )
    .expect("filesystem profile");
    PolicyEngine::from_sources(Some(policy_dir))
}

fn write_session_file(root: &Path, filename: &str, port: u16, allowed_paths: &[&str]) {
    let sessions = root.join("baffle/sessions");
    fs::create_dir_all(&sessions).expect("session configuration directory");
    let paths = allowed_paths
        .iter()
        .map(|path| format!("{path:?}"))
        .collect::<Vec<_>>()
        .join(", ");
    fs::write(
        sessions.join(filename),
        format!(
            "version = 2\npersistent = false\nunmatched = \"deny\"\n\n[rules.\"localhost\"]\nmode = \"intercept\"\nports = [{port}]\npaths = [{paths}]\n"
        ),
    )
    .expect("session file");
}

fn start_baffle_daemon(binary: &Path, root: &Path, upstream_ca: &Path) -> BaffleDaemon {
    let baffle_root = root.join("baffle");
    let run_dir = baffle_root.join("run");
    let socket_dir = baffle_root.join("proxies");
    let session_dir = baffle_root.join("sessions");
    let secrets_dir = baffle_root.join("secrets");
    fs::create_dir_all(&run_dir).expect("Baffle run directory");
    fs::create_dir_all(&socket_dir).expect("Baffle socket directory");
    fs::create_dir_all(&session_dir).expect("Baffle session directory");
    fs::create_dir_all(&secrets_dir).expect("Baffle secrets directory");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for directory in [
            &baffle_root,
            &run_dir,
            &socket_dir,
            &session_dir,
            &secrets_dir,
        ] {
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700))
                .expect("restrict Baffle directory permissions");
        }
    }
    let control_socket = run_dir.join("control.sock");
    let ca_certificate = baffle_root.join("ca.pem");
    let ca_private_key = baffle_root.join("ca-key.pem");
    let config_path = baffle_root.join("daemon.toml");
    let daemon_log_path = baffle_root.join("daemon.log");
    let daemon_log = fs::File::create(&daemon_log_path).expect("daemon log");
    let uid = fs::metadata(&baffle_root)
        .expect("Baffle root metadata")
        .uid();
    fs::write(
        &config_path,
        format!(
            "[daemon]\ncontrol_socket = {:?}\nsocket_dir = {:?}\ntrusted_operator_uid = {uid}\ncreate_mode = \"file_only\"\nsession_config_dir = {:?}\nmax_sessions = 16\n\n[ca]\ncertificate = {:?}\nprivate_key = {:?}\n\n[secrets]\ndirectory = {:?}\nallowed = []\n",
            control_socket,
            socket_dir,
            session_dir,
            ca_certificate,
            ca_private_key,
            secrets_dir,
        ),
    )
    .expect("Baffle daemon config");

    let output = Command::new(binary)
        .arg("ca")
        .arg("init")
        .arg("--config")
        .arg(&config_path)
        .output()
        .expect("initialize Baffle CA");
    assert!(
        output.status.success(),
        "Baffle CA initialization failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let child = Command::new(binary)
        .arg("daemon")
        .arg("--config")
        .arg(&config_path)
        .env("BAFFLE_TEST_UPSTREAM_CA", upstream_ca)
        .stdout(Stdio::null())
        .stderr(Stdio::from(daemon_log))
        .spawn()
        .expect("start Baffle daemon");
    let mut daemon = BaffleDaemon {
        child,
        control_socket,
        session_socket_dir: socket_dir,
        ca_certificate,
        daemon_log: daemon_log_path,
    };
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if daemon.control_socket.exists() {
            return daemon;
        }
        if let Some(status) = daemon.child.try_wait().expect("read daemon status") {
            let log = fs::read_to_string(baffle_root.join("daemon.log"))
                .unwrap_or_else(|error| format!("failed to read Baffle log: {error}"));
            panic!("Baffle exited before binding its control socket ({status}):\n{log}");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("Baffle did not bind its control socket before timeout");
}

async fn start_https_origin(root: &Path) -> Origin {
    let ca_key = KeyPair::generate().expect("origin CA key");
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca = ca_params
        .self_signed(&ca_key)
        .expect("origin CA certificate");
    let ca_path = root.join("upstream-ca.pem");
    fs::write(&ca_path, ca.pem()).expect("save upstream trust root");

    let issuer = Issuer::from_ca_cert_pem(&ca.pem(), ca_key).expect("origin CA issuer");
    let server_key = KeyPair::generate().expect("origin server key");
    let mut server_params =
        CertificateParams::new(vec!["localhost".into()]).expect("origin certificate parameters");
    server_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let server_certificate = server_params
        .signed_by(&server_key, &issuer)
        .expect("sign origin certificate");
    let tls = tokio_rustls::rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(server_certificate.der().to_vec())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server_key.serialize_der())),
        )
        .expect("origin TLS config");
    let acceptor = TlsAcceptor::from(std::sync::Arc::new(tls));

    let ipv4 = TcpListener::bind("127.0.0.1:0").await.expect("IPv4 origin");
    let port = ipv4.local_addr().expect("IPv4 address").port();
    let ipv6 = TcpListener::bind(SocketAddr::V6(SocketAddrV6::new(
        std::net::Ipv6Addr::LOCALHOST,
        port,
        0,
        0,
    )))
    .await
    .ok();
    let mut stops = Vec::new();
    let mut tasks = Vec::new();
    for listener in std::iter::once(ipv4).chain(ipv6) {
        let acceptor = acceptor.clone();
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
        stops.push(stop_tx);
        tasks.push(tokio::spawn(serve_origin(listener, acceptor, stop_rx)));
    }
    Origin {
        port,
        stop: stops,
        tasks,
    }
}

async fn serve_origin(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    mut stop: tokio::sync::oneshot::Receiver<()>,
) {
    loop {
        tokio::select! {
            _ = &mut stop => return,
            accepted = listener.accept() => {
                let Ok((stream, _)) = accepted else { return; };
                let acceptor = acceptor.clone();
                tokio::spawn(async move { serve_origin_connection(stream, acceptor).await; });
            }
        }
    }
}

async fn serve_origin_connection(stream: TcpStream, acceptor: TlsAcceptor) {
    let Ok(mut stream) = timeout(Duration::from_secs(5), acceptor.accept(stream))
        .await
        .unwrap_or_else(|_| Err(std::io::Error::other("origin TLS accept timed out")))
    else {
        return;
    };
    let mut request = Vec::new();
    let mut buffer = [0; 1024];
    loop {
        let Ok(count) = timeout(Duration::from_secs(5), stream.read(&mut buffer))
            .await
            .unwrap_or_else(|_| Err(std::io::Error::other("origin request timed out")))
        else {
            return;
        };
        if count == 0 {
            return;
        }
        request.extend_from_slice(&buffer[..count]);
        if request.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
        if request.len() > 16 * 1024 {
            return;
        }
    }
    let request_line = String::from_utf8_lossy(&request);
    let path = request_line.split_ascii_whitespace().nth(1).unwrap_or("/");
    if path == "/hold" {
        sleep(Duration::from_secs(30)).await;
    }
    let body = format!("served {path}\n");
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes()).await;
}

async fn wait_for_sessions(client: &Client, expected: usize) -> Vec<baffle_client::SessionInfo> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let sessions = client.list().await.expect("query active Baffle sessions");
        if sessions.len() == expected {
            return sessions;
        }
        assert!(
            Instant::now() < deadline,
            "expected {expected} active Baffle sessions, found {}",
            sessions.len()
        );
        sleep(Duration::from_millis(10)).await;
    }
}
