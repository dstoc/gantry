use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use baffle_client::{Client, Session};

use crate::filesystem::{FilesystemMount, FilesystemProfile, validate_baffle_filename};

pub(crate) const SANDBOX_SOCKET: &str = "/run/gantry/proxy.sock";
pub(crate) const SANDBOX_CA_CERTIFICATE: &str = "/run/gantry/baffle-ca.pem";

static ACTIVE_SESSION_SOCKETS: OnceLock<Mutex<HashSet<PathBuf>>> = OnceLock::new();

#[derive(Debug, Clone)]
pub struct BaffleRuntimeConfig {
    pub control_socket: PathBuf,
    pub session_socket_dir: PathBuf,
    pub ca_certificate: Option<PathBuf>,
}

impl BaffleRuntimeConfig {
    pub fn from_env() -> Self {
        Self::from_lookup(|name| std::env::var_os(name).map(PathBuf::from))
    }

    pub(crate) fn from_lookup(mut lookup: impl FnMut(&str) -> Option<PathBuf>) -> Self {
        let control_socket = lookup("GANTRY_BAFFLE_CONTROL_SOCKET")
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(default_control_socket);
        let session_socket_dir = lookup("GANTRY_BAFFLE_SESSION_SOCKET_DIR")
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| PathBuf::from("/run/baffle/proxies"));
        let ca_certificate =
            lookup("GANTRY_BAFFLE_CA_CERT").filter(|path| !path.as_os_str().is_empty());

        Self {
            control_socket,
            session_socket_dir,
            ca_certificate,
        }
    }

    pub(crate) fn validate_for_session(&self) -> Result<&Path, String> {
        if !self.control_socket.is_absolute() {
            return Err("GANTRY_BAFFLE_CONTROL_SOCKET must be an absolute path".to_string());
        }
        if !self.session_socket_dir.is_absolute() {
            return Err("GANTRY_BAFFLE_SESSION_SOCKET_DIR must be an absolute path".to_string());
        }
        let certificate = self.ca_certificate.as_deref().ok_or_else(|| {
            "GANTRY_BAFFLE_CA_CERT must name the public Baffle CA certificate for a Baffle session".to_string()
        })?;
        if !certificate.is_absolute() {
            return Err("GANTRY_BAFFLE_CA_CERT must be an absolute path".to_string());
        }
        Ok(certificate)
    }

    pub(crate) fn validate_paths(&self) -> Result<(), String> {
        if !self.control_socket.is_absolute() {
            return Err("GANTRY_BAFFLE_CONTROL_SOCKET must be an absolute path".to_string());
        }
        if !self.session_socket_dir.is_absolute() {
            return Err("GANTRY_BAFFLE_SESSION_SOCKET_DIR must be an absolute path".to_string());
        }
        if self
            .ca_certificate
            .as_ref()
            .is_some_and(|path| !path.is_absolute())
        {
            return Err("GANTRY_BAFFLE_CA_CERT must be an absolute path".to_string());
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
            self.session_socket_dir.clone(),
        ];
        if let Some(certificate) = self.ca_certificate.as_deref() {
            protected_paths.push(certificate.to_path_buf());
            protected_paths.push(certificate.parent().unwrap_or(Path::new("/")).to_path_buf());
        }
        if let Some(socket) = assigned_socket {
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

pub(crate) struct BaffleSessionLease {
    session: Option<Session>,
    socket_path: PathBuf,
}

impl BaffleSessionLease {
    pub(crate) fn socket_path(&self) -> &Path {
        &self.socket_path
    }
}

impl Drop for BaffleSessionLease {
    fn drop(&mut self) {
        let active = ACTIVE_SESSION_SOCKETS.get_or_init(|| Mutex::new(HashSet::new()));
        let mut active = active
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.session.take();
        active.remove(&self.socket_path);
    }
}

pub(crate) async fn create_ephemeral_session(
    config: &BaffleRuntimeConfig,
    filename: &str,
) -> Result<BaffleSessionLease, String> {
    validate_baffle_filename(filename)?;
    let client = Client::new(config.control_socket.clone());
    let session = client
        .create_from_file(filename)
        .await
        .map_err(|error| format!("failed to create Baffle session from selected file: {error}"))?;

    if session.is_persistent() {
        let id = session.id().to_owned();
        drop(session);
        if let Err(error) = client.stop(&id).await {
            return Err(format!(
                "Baffle returned a persistent session where an ephemeral lease was required; stopping it failed: {error}"
            ));
        }
        return Err("Baffle selected session configuration must be ephemeral".to_string());
    }

    if !session.socket_path().is_absolute() {
        return Err("Baffle returned a non-absolute session socket path".to_string());
    }
    let socket_path = session.socket_path().to_path_buf();
    let socket_directory = canonicalize_or_original(config.session_socket_dir.as_path());
    let resolved_socket = canonicalize_or_original(&socket_path);
    if !resolved_socket.starts_with(&socket_directory) {
        return Err(
            "Baffle returned a data socket outside GANTRY_BAFFLE_SESSION_SOCKET_DIR".to_string(),
        );
    }
    let active = ACTIVE_SESSION_SOCKETS.get_or_init(|| Mutex::new(HashSet::new()));
    let mut active = active
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if !active.insert(socket_path.clone()) {
        return Err(
            "Baffle returned a data socket that is already assigned to another execution"
                .to_string(),
        );
    }
    Ok(BaffleSessionLease {
        session: Some(session),
        socket_path,
    })
}

fn canonicalize_or_original(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

fn default_control_socket() -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        let base = std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                let uid = unsafe { libc::geteuid() };
                PathBuf::from(format!("/tmp/baffle-{uid}"))
            });
        return base.join("Library/Caches/Baffle/control.sock");
    }
    #[cfg(not(target_os = "macos"))]
    PathBuf::from("/run/baffle/control.sock")
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
    fn baffle_settings_use_daemon_defaults_and_allow_explicit_paths() {
        let defaults = BaffleRuntimeConfig::from_lookup(|_| None);
        assert_eq!(
            defaults.control_socket,
            PathBuf::from("/run/baffle/control.sock")
        );
        assert_eq!(
            defaults.session_socket_dir,
            PathBuf::from("/run/baffle/proxies")
        );
        assert!(defaults.ca_certificate.is_none());

        let configured = BaffleRuntimeConfig::from_lookup(|name| match name {
            "GANTRY_BAFFLE_CONTROL_SOCKET" => Some("/tmp/control.sock".into()),
            "GANTRY_BAFFLE_SESSION_SOCKET_DIR" => Some("/tmp/sessions".into()),
            "GANTRY_BAFFLE_CA_CERT" => Some("/tmp/ca.pem".into()),
            _ => None,
        });
        assert_eq!(
            configured.control_socket,
            PathBuf::from("/tmp/control.sock")
        );
        assert_eq!(
            configured.session_socket_dir,
            PathBuf::from("/tmp/sessions")
        );
        assert_eq!(
            configured.ca_certificate,
            Some(PathBuf::from("/tmp/ca.pem"))
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
            session_socket_dir: baffle_dir.join("proxies"),
            ca_certificate: Some(baffle_dir.join("ca.pem")),
        };

        let error = config
            .validate_profile_sources(&profile, None)
            .expect_err("parent mount must not expose Baffle state");
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
            assert_eq!(result, 0, "lease socket should close when Gantry drops it");
            closed_tx.send(()).expect("report lease closure");
        });

        let config = BaffleRuntimeConfig {
            control_socket: control_path,
            session_socket_dir: directory.path().to_path_buf(),
            ca_certificate: Some(directory.path().join("ca.pem")),
        };
        let lease = create_ephemeral_session(&config, "github-readonly.toml")
            .await
            .expect("file-only session creation");
        assert_eq!(lease.socket_path(), session_path);
        let request = request_rx.await.expect("capture control request");
        assert!(request.contains("operation = \"create_from_file\""));
        assert!(request.contains("name = \"github-readonly.toml\""));

        drop(lease);
        timeout(Duration::from_secs(1), closed_rx)
            .await
            .expect("lease closure should be observed")
            .expect("daemon closure signal");
        daemon.await.expect("mock daemon task");
        drop(session_listener);
    }
}
