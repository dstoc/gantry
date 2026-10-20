use std::collections::HashSet;
use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use baffle_client::{Client, Session, default_control_socket};
use base64::Engine as _;

use crate::filesystem::{FilesystemMount, FilesystemProfile, validate_baffle_filename};

pub(crate) const SANDBOX_SOCKET: &str = "/run/gantry/proxy.sock";
pub(crate) const SANDBOX_CA_CERTIFICATE: &str = "/run/gantry/baffle-ca.pem";

static ACTIVE_SESSION_SOCKETS: OnceLock<Mutex<HashSet<PathBuf>>> = OnceLock::new();

#[derive(Debug, Clone)]
pub struct BaffleRuntimeConfig {
    pub control_socket: PathBuf,
}

impl BaffleRuntimeConfig {
    pub fn from_env() -> Self {
        Self::from_lookup(|name| std::env::var_os(name).map(PathBuf::from))
    }

    pub(crate) fn from_lookup(mut lookup: impl FnMut(&str) -> Option<PathBuf>) -> Self {
        let control_socket = lookup("GANTRY_BAFFLE_CONTROL_SOCKET")
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(default_control_socket);
        Self { control_socket }
    }

    pub(crate) fn validate_paths(&self) -> Result<(), String> {
        if !self.control_socket.is_absolute() {
            return Err("GANTRY_BAFFLE_CONTROL_SOCKET must be an absolute path".to_string());
        }
        Ok(())
    }

    pub(crate) fn validate_profile_sources(
        &self,
        profile: &FilesystemProfile,
        assigned_socket: Option<&Path>,
    ) -> Result<(), String> {
        let mut protected_paths = vec![
            self.control_socket.clone(),
            self.control_socket
                .parent()
                .unwrap_or(Path::new("/"))
                .to_path_buf(),
        ];
        if let Some(socket) = assigned_socket {
            if !socket.is_absolute() {
                return Err("Baffle returned a non-absolute session socket path".to_string());
            }
            protected_paths.push(socket.to_path_buf());
            protected_paths.push(socket.parent().unwrap_or(Path::new("/")).to_path_buf());
        }

        for mount in &profile.mounts {
            let FilesystemMount::Bind { source, .. } = mount else {
                continue;
            };
            let source = canonicalize_or_original(source);
            for protected in &protected_paths {
                let protected = canonicalize_or_original(protected);
                if paths_overlap(&source, &protected) {
                    return Err(format!(
                        "filesystem profile '{}' exposes a protected Baffle runtime path through '{}'",
                        profile.name,
                        source.display()
                    ));
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug)]
pub(crate) struct BaffleSessionLease {
    session: Option<Session>,
    socket_path: PathBuf,
    active_socket_key: PathBuf,
    ca_certificate_pem: String,
    id: String,
}

impl BaffleSessionLease {
    pub(crate) fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    pub(crate) fn id(&self) -> &str {
        &self.id
    }

    pub(crate) fn ca_certificate_pem(&self) -> &str {
        &self.ca_certificate_pem
    }
}

impl Drop for BaffleSessionLease {
    fn drop(&mut self) {
        let active = ACTIVE_SESSION_SOCKETS.get_or_init(|| Mutex::new(HashSet::new()));
        let mut active = active
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.session.take();
        active.remove(&self.active_socket_key);
    }
}

pub(crate) async fn create_ephemeral_session(
    config: &BaffleRuntimeConfig,
    filename: &str,
) -> Result<BaffleSessionLease, String> {
    validate_baffle_filename(filename)?;
    let client = Client::new(config.control_socket.clone());
    let session = client
        .create_ephemeral_from_file(filename)
        .await
        .map_err(|error| format!("failed to create Baffle session from selected file: {error}"))?;

    if session.is_persistent() {
        return Err(
            "Baffle returned a persistent session despite the ephemeral requirement".to_string(),
        );
    }

    if !session.socket_path().is_absolute() {
        return Err("Baffle returned a non-absolute session socket path".to_string());
    }
    let socket_path = session.socket_path().to_path_buf();
    let socket_metadata = std::fs::symlink_metadata(&socket_path).map_err(|error| {
        format!("Baffle returned a missing or inaccessible session socket: {error}")
    })?;
    if !socket_metadata.file_type().is_socket() {
        return Err("Baffle returned a session endpoint that is not a Unix socket".to_string());
    }
    let ca_certificate_pem = session
        .ca_certificate_pem()
        .ok_or_else(|| "Baffle did not return its public CA certificate".to_string())?;
    validate_public_ca_certificate_pem(ca_certificate_pem)?;
    let ca_certificate_pem = ca_certificate_pem.to_owned();
    let id = session.id().to_owned();
    let assigned_socket = canonicalize_or_original(&socket_path);
    let active = ACTIVE_SESSION_SOCKETS.get_or_init(|| Mutex::new(HashSet::new()));
    let mut active = active
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if !active.insert(assigned_socket.clone()) {
        return Err(
            "Baffle returned a data socket that is already assigned to another execution"
                .to_string(),
        );
    }
    Ok(BaffleSessionLease {
        session: Some(session),
        socket_path,
        active_socket_key: assigned_socket,
        ca_certificate_pem,
        id,
    })
}

fn validate_public_ca_certificate_pem(pem: &str) -> Result<(), String> {
    if pem.contains("PRIVATE KEY") {
        return Err(
            "Baffle returned private key material instead of a public CA certificate".to_string(),
        );
    }
    let mut remainder = pem.trim();
    let mut certificates = 0;
    while !remainder.is_empty() {
        let Some(block) = remainder.strip_prefix("-----BEGIN CERTIFICATE-----") else {
            return Err("Baffle returned data that is not public certificate PEM".to_string());
        };
        let end = block
            .find("-----END CERTIFICATE-----")
            .ok_or_else(|| "Baffle returned an incomplete public CA certificate".to_string())?;
        let encoded_der = block[..end]
            .bytes()
            .filter(|byte| !byte.is_ascii_whitespace())
            .map(char::from)
            .collect::<String>();
        let der = base64::engine::general_purpose::STANDARD
            .decode(encoded_der)
            .map_err(|_| "Baffle returned an invalid public CA certificate".to_string())?;
        let (trailing_der, _) = x509_parser::parse_x509_certificate(&der)
            .map_err(|_| "Baffle returned an invalid public CA certificate".to_string())?;
        if !trailing_der.is_empty() {
            return Err("Baffle returned an invalid public CA certificate".to_string());
        }
        remainder = block[end + "-----END CERTIFICATE-----".len()..].trim();
        certificates += 1;
    }
    if certificates == 0 {
        return Err("Baffle returned an empty public CA certificate".to_string());
    }
    reqwest::Certificate::from_pem(pem.as_bytes())
        .map_err(|_| "Baffle returned an invalid public CA certificate".to_string())?;
    Ok(())
}

fn canonicalize_or_original(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

fn paths_overlap(left: &Path, right: &Path) -> bool {
    left.starts_with(right) || right.starts_with(left)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixListener;
    use tokio::time::{Duration, timeout};

    #[test]
    fn baffle_settings_use_daemon_defaults_and_only_accept_control_socket_override() {
        let defaults = BaffleRuntimeConfig::from_lookup(|_| None);
        assert_eq!(defaults.control_socket, default_control_socket());

        let configured = BaffleRuntimeConfig::from_lookup(|name| match name {
            "GANTRY_BAFFLE_CONTROL_SOCKET" => Some("/tmp/control.sock".into()),
            _ => None,
        });
        assert_eq!(
            configured.control_socket,
            PathBuf::from("/tmp/control.sock")
        );
    }

    #[test]
    fn rejects_profile_sources_that_expose_baffle_runtime_directories() {
        let root = tempfile::tempdir().expect("test root");
        let source = root.path().join("workspace");
        let baffle_dir = root.path().join("baffle");
        std::fs::create_dir_all(&source).expect("workspace");
        std::fs::create_dir_all(&baffle_dir).expect("Baffle directory");
        let profile = FilesystemProfile {
            name: "workspace".to_string(),
            mounts: vec![FilesystemMount::Bind {
                source: root.path().to_path_buf(),
                target: "/workspace".into(),
                access: crate::filesystem::MountAccess::ReadOnly,
            }],
        };
        let config = BaffleRuntimeConfig {
            control_socket: baffle_dir.join("control.sock"),
        };

        let error = config
            .validate_profile_sources(&profile, None)
            .expect_err("parent mount must not expose Baffle state");
        assert!(error.contains("protected Baffle runtime path"));
    }

    #[test]
    fn rejects_profile_sources_that_expose_the_returned_socket_directory() {
        let root = tempfile::tempdir().expect("test root");
        let control_dir = root.path().join("control");
        let session_dir = root.path().join("sessions");
        std::fs::create_dir_all(&control_dir).expect("control directory");
        std::fs::create_dir_all(&session_dir).expect("session directory");
        let profile = FilesystemProfile {
            name: "sessions".to_string(),
            mounts: vec![FilesystemMount::Bind {
                source: session_dir.clone(),
                target: "/workspace/sessions".into(),
                access: crate::filesystem::MountAccess::ReadOnly,
            }],
        };
        let config = BaffleRuntimeConfig {
            control_socket: control_dir.join("control.sock"),
        };

        let error = config
            .validate_profile_sources(&profile, Some(&session_dir.join("assigned.sock")))
            .expect_err("the returned socket's containing directory must be protected");
        assert!(error.contains("protected Baffle runtime path"));
    }

    #[test]
    fn selected_session_filename_uses_gantry_relative_filename_contract() {
        for name in ["github.toml", "read-only_1.toml"] {
            validate_baffle_filename(name).expect("valid name");
        }
        for name in ["nested/github.toml", "../outside.toml", "github.conf"] {
            assert!(validate_baffle_filename(name).is_err(), "{name}");
        }
    }

    #[tokio::test]
    async fn creates_from_file_and_keeps_the_ephemeral_control_lease_until_drop() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let control_path = directory.path().join("control.sock");
        let session_path = directory.path().join("assigned.sock");
        let listener = UnixListener::bind(&control_path).expect("control listener");
        let session_listener = UnixListener::bind(&session_path).expect("session listener");
        let response_socket = session_path.clone();
        let (request_tx, request_rx) = tokio::sync::oneshot::channel();
        let (closed_tx, closed_rx) = tokio::sync::oneshot::channel();
        let daemon = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("client connects");
            let mut header = [0; 4];
            stream
                .read_exact(&mut header)
                .await
                .expect("read frame length");
            let mut request = vec![0; u32::from_be_bytes(header) as usize];
            stream.read_exact(&mut request).await.expect("read request");
            request_tx
                .send(String::from_utf8(request).expect("TOML request"))
                .expect("report request");
            let response = serde_json::to_vec(&serde_json::json!({
                "version": 2,
                "ok": true,
                "result": {
                    "id": "ephemeral-test-session",
                    "socket": response_socket,
                    "persistent": false,
                    "ca_certificate_pem": test_ca_certificate_pem()
                }
            }))
            .expect("response JSON");
            stream
                .write_all(&(response.len() as u32).to_be_bytes())
                .await
                .expect("write frame length");
            stream.write_all(&response).await.expect("write response");
            let mut byte = [0; 1];
            let result = stream.read(&mut byte).await.expect("read lease closure");
            assert_eq!(result, 0, "lease socket should close when Gantry drops it");
            closed_tx.send(()).expect("report lease closure");
        });

        let config = BaffleRuntimeConfig {
            control_socket: control_path,
        };
        let lease = create_ephemeral_session(&config, "github-readonly.toml")
            .await
            .expect("file-only session creation");
        assert_eq!(lease.socket_path(), session_path);
        assert!(lease.ca_certificate_pem().contains("BEGIN CERTIFICATE"));
        let request = request_rx.await.expect("capture control request");
        assert!(request.contains("operation = \"create_from_file\""));
        assert!(request.contains("require_ephemeral = true"));
        assert!(request.contains("name = \"github-readonly.toml\""));

        drop(lease);
        timeout(Duration::from_secs(1), closed_rx)
            .await
            .expect("lease closure should be observed")
            .expect("daemon closure signal");
        daemon.await.expect("mock daemon task");
        drop(session_listener);
    }

    #[tokio::test]
    async fn rejects_duplicate_active_socket_assignments() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let control_path = directory.path().join("control.sock");
        let session_path = directory.path().join("assigned.sock");
        let listener = UnixListener::bind(&control_path).expect("control listener");
        let _session_listener = UnixListener::bind(&session_path).expect("session listener");
        let response_socket = session_path.clone();
        let ca_certificate_pem = test_ca_certificate_pem();
        let (second_closed_tx, second_closed_rx) = tokio::sync::oneshot::channel();
        let (first_closed_tx, first_closed_rx) = tokio::sync::oneshot::channel();
        let daemon = tokio::spawn(async move {
            let mut first_stream = None;
            let mut second_closed_tx = Some(second_closed_tx);
            for index in 0..2 {
                let (mut stream, _) = listener.accept().await.expect("client connects");
                let mut header = [0; 4];
                stream
                    .read_exact(&mut header)
                    .await
                    .expect("read frame length");
                let mut request = vec![0; u32::from_be_bytes(header) as usize];
                stream.read_exact(&mut request).await.expect("read request");
                let response = serde_json::to_vec(&serde_json::json!({
                    "version": 2,
                    "ok": true,
                    "result": {
                        "id": format!("duplicate-session-{index}"),
                        "socket": response_socket.clone(),
                        "persistent": false,
                        "ca_certificate_pem": ca_certificate_pem.clone()
                    }
                }))
                .expect("response JSON");
                stream
                    .write_all(&(response.len() as u32).to_be_bytes())
                    .await
                    .expect("write frame length");
                stream.write_all(&response).await.expect("write response");
                if index == 0 {
                    first_stream = Some(stream);
                } else {
                    let mut byte = [0; 1];
                    assert_eq!(
                        stream
                            .read(&mut byte)
                            .await
                            .expect("read duplicate lease close"),
                        0
                    );
                    second_closed_tx
                        .take()
                        .expect("single duplicate assignment")
                        .send(())
                        .expect("report second lease close");
                }
            }
            let mut byte = [0; 1];
            assert_eq!(
                first_stream
                    .as_mut()
                    .expect("first session stream")
                    .read(&mut byte)
                    .await
                    .expect("read first lease close"),
                0
            );
            first_closed_tx.send(()).expect("report first lease close");
        });
        let config = BaffleRuntimeConfig {
            control_socket: control_path,
        };
        let first = create_ephemeral_session(&config, "github-readonly.toml")
            .await
            .expect("first session assignment");
        let error = create_ephemeral_session(&config, "github-readonly.toml")
            .await
            .expect_err("duplicate socket assignment must fail closed");
        assert!(error.contains("already assigned"));
        timeout(Duration::from_secs(1), second_closed_rx)
            .await
            .expect("duplicate lease closure should be observed")
            .expect("duplicate lease closed");
        drop(first);
        timeout(Duration::from_secs(1), first_closed_rx)
            .await
            .expect("first lease closure should be observed")
            .expect("first lease closed");
        daemon.await.expect("mock daemon task");
    }

    #[tokio::test]
    async fn rejects_missing_certificate_and_releases_the_session_lease() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let control_path = directory.path().join("control.sock");
        let session_path = directory.path().join("assigned.sock");
        let listener = UnixListener::bind(&control_path).expect("control listener");
        let _session_listener = UnixListener::bind(&session_path).expect("session listener");
        let (closed_tx, closed_rx) = tokio::sync::oneshot::channel();
        let daemon = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("client connects");
            let mut header = [0; 4];
            stream
                .read_exact(&mut header)
                .await
                .expect("read frame length");
            let mut request = vec![0; u32::from_be_bytes(header) as usize];
            stream.read_exact(&mut request).await.expect("read request");
            let response = serde_json::to_vec(&serde_json::json!({
                "version": 2,
                "ok": true,
                "result": {
                    "id": "missing-certificate-session",
                    "socket": session_path,
                    "persistent": false
                }
            }))
            .expect("response JSON");
            stream
                .write_all(&(response.len() as u32).to_be_bytes())
                .await
                .expect("write frame length");
            stream.write_all(&response).await.expect("write response");
            let mut byte = [0; 1];
            let result = stream.read(&mut byte).await.expect("read lease closure");
            assert_eq!(result, 0, "failed setup must release the lease");
            closed_tx.send(()).expect("report lease closure");
        });

        let error = create_ephemeral_session(
            &BaffleRuntimeConfig {
                control_socket: control_path,
            },
            "github-readonly.toml",
        )
        .await
        .expect_err("missing CA data must fail closed");
        assert!(error.contains("did not return its public CA certificate"));
        timeout(Duration::from_secs(1), closed_rx)
            .await
            .expect("lease closure should be observed")
            .expect("daemon closure signal");
        daemon.await.expect("mock daemon task");
    }

    #[tokio::test]
    async fn rejects_non_socket_metadata_and_releases_the_session_lease() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let control_path = directory.path().join("control.sock");
        let file_path = directory.path().join("not-a-socket");
        std::fs::write(&file_path, b"not a socket").expect("create invalid endpoint");
        let listener = UnixListener::bind(&control_path).expect("control listener");
        let (closed_tx, closed_rx) = tokio::sync::oneshot::channel();
        let daemon = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("client connects");
            let mut header = [0; 4];
            stream
                .read_exact(&mut header)
                .await
                .expect("read frame length");
            let mut request = vec![0; u32::from_be_bytes(header) as usize];
            stream.read_exact(&mut request).await.expect("read request");
            let response = serde_json::to_vec(&serde_json::json!({
                "version": 2,
                "ok": true,
                "result": {
                    "id": "invalid-socket-session",
                    "socket": file_path,
                    "persistent": false,
                    "ca_certificate_pem": test_ca_certificate_pem()
                }
            }))
            .expect("response JSON");
            stream
                .write_all(&(response.len() as u32).to_be_bytes())
                .await
                .expect("write frame length");
            stream.write_all(&response).await.expect("write response");
            let mut byte = [0; 1];
            assert_eq!(
                stream.read(&mut byte).await.expect("read lease closure"),
                0,
                "failed setup must release the lease"
            );
            closed_tx.send(()).expect("report lease closure");
        });

        let error = create_ephemeral_session(
            &BaffleRuntimeConfig {
                control_socket: control_path,
            },
            "github-readonly.toml",
        )
        .await
        .expect_err("non-socket metadata must fail closed");
        assert!(error.contains("not a Unix socket"));
        timeout(Duration::from_secs(1), closed_rx)
            .await
            .expect("lease closure should be observed")
            .expect("daemon closure signal");
        daemon.await.expect("mock daemon task");
    }

    #[tokio::test]
    async fn rejects_invalid_certificate_metadata_and_releases_the_session_lease() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let control_path = directory.path().join("control.sock");
        let session_path = directory.path().join("assigned.sock");
        let listener = UnixListener::bind(&control_path).expect("control listener");
        let _session_listener = UnixListener::bind(&session_path).expect("session listener");
        let (closed_tx, closed_rx) = tokio::sync::oneshot::channel();
        let daemon = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("client connects");
            let mut header = [0; 4];
            stream
                .read_exact(&mut header)
                .await
                .expect("read frame length");
            let mut request = vec![0; u32::from_be_bytes(header) as usize];
            stream.read_exact(&mut request).await.expect("read request");
            let response = serde_json::to_vec(&serde_json::json!({
                "version": 2,
                "ok": true,
                "result": {
                    "id": "invalid-certificate-session",
                    "socket": session_path,
                    "persistent": false,
                    "ca_certificate_pem": "-----BEGIN CERTIFICATE-----\nZm9v\n-----END CERTIFICATE-----\n"
                }
            }))
            .expect("response JSON");
            stream
                .write_all(&(response.len() as u32).to_be_bytes())
                .await
                .expect("write frame length");
            stream.write_all(&response).await.expect("write response");
            let mut byte = [0; 1];
            assert_eq!(
                stream.read(&mut byte).await.expect("read lease closure"),
                0,
                "failed setup must release the lease"
            );
            closed_tx.send(()).expect("report lease closure");
        });

        let error = create_ephemeral_session(
            &BaffleRuntimeConfig {
                control_socket: control_path,
            },
            "github-readonly.toml",
        )
        .await
        .expect_err("invalid certificate metadata must fail closed");
        assert!(error.contains("invalid public CA certificate"));
        timeout(Duration::from_secs(1), closed_rx)
            .await
            .expect("lease closure should be observed")
            .expect("daemon closure signal");
        daemon.await.expect("mock daemon task");
    }

    #[test]
    fn rejects_invalid_public_ca_pem() {
        assert!(validate_public_ca_certificate_pem("not a certificate").is_err());
        assert!(
            validate_public_ca_certificate_pem(
                "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----"
            )
            .is_err()
        );
    }

    fn test_ca_certificate_pem() -> String {
        rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("test CA certificate")
            .cert
            .pem()
    }
}
