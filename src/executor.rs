use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io::Read;
use std::path::{Path, PathBuf};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::io::AsyncReadExt;

use crate::backend::{self, StartError};
use crate::baffle::BaffleRuntimeConfig;
use crate::execution::{AuthorizedInvocation, ExecutionBackend, ExecutionPlan, RunningExecution};
use crate::policy::{PolicyEngine, ValidationError};

pub const MAX_OUTPUT_BYTES: usize = 1024 * 1024;
pub const TRUNCATION_MARKER: &str = "\n...truncated...";

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct RunCommandInput {
    pub executable: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub cwd: Option<String>,
    #[serde(default)]
    pub env: Option<BTreeMap<String, String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct RunCommandOutput {
    pub stdout: String,
    pub stderr: String,
    #[serde(rename = "exitCode")]
    pub exit_code: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct RunCommandCheckOutput {
    pub allowed: bool,
    pub reason: Option<String>,
    pub executable: String,
    pub resolved_path: Option<String>,
    pub hash: Option<String>,
    #[serde(default)]
    pub cwd: Option<String>,
    pub policy_mode: String,
    pub filesystem: Option<String>,
    #[serde(rename = "baffle_session")]
    pub baffle_session: Option<String>,
    pub backend: String,
}

#[derive(Debug, Error)]
pub enum ToolError {
    #[error(transparent)]
    Validation(#[from] ValidationError),
    #[error("Failed to start subprocess: {source}")]
    Spawn { source: std::io::Error },
    #[error("execution backend setup failed: {details}")]
    BackendSetup { details: String },
    #[error("Failed to wait for subprocess: {source}")]
    Wait { source: std::io::Error },
    #[error("Failed to read stdout: {source}")]
    StdoutRead { source: std::io::Error },
    #[error("Failed to read stderr: {source}")]
    StderrRead { source: std::io::Error },
    #[error("Failed to join stdout reader: {source}")]
    StdoutJoin { source: tokio::task::JoinError },
    #[error("Failed to join stderr reader: {source}")]
    StderrJoin { source: tokio::task::JoinError },
}

pub async fn run_command_impl(
    policy_engine: &PolicyEngine,
    default_cwd: &Path,
    input: RunCommandInput,
) -> Result<RunCommandOutput, ToolError> {
    run_command_with_backend(
        policy_engine,
        default_cwd,
        ExecutionBackend::Bubblewrap,
        input,
    )
    .await
}

pub async fn run_command_with_backend(
    policy_engine: &PolicyEngine,
    default_cwd: &Path,
    backend: ExecutionBackend,
    input: RunCommandInput,
) -> Result<RunCommandOutput, ToolError> {
    run_command_with_baffle_config(
        policy_engine,
        default_cwd,
        backend,
        BaffleRuntimeConfig::from_env(),
        input,
    )
    .await
}

pub async fn run_command_with_baffle_config(
    policy_engine: &PolicyEngine,
    default_cwd: &Path,
    backend: ExecutionBackend,
    baffle: BaffleRuntimeConfig,
    input: RunCommandInput,
) -> Result<RunCommandOutput, ToolError> {
    let mut execution = start_command_process_with_baffle_config(
        policy_engine,
        default_cwd,
        backend,
        baffle,
        input,
    )
    .await?;

    let stdout = execution
        .take_stdout()
        .ok_or_else(|| ToolError::StdoutRead {
            source: std::io::Error::other("stdout pipe missing"),
        })?;
    let stderr = execution
        .take_stderr()
        .ok_or_else(|| ToolError::StderrRead {
            source: std::io::Error::other("stderr pipe missing"),
        })?;

    let stdout_task = tokio::spawn(read_limited(stdout));
    let stderr_task = tokio::spawn(read_limited(stderr));

    let status = execution
        .wait()
        .await
        .map_err(|source| ToolError::Wait { source })?;

    let stdout_capture = stdout_task
        .await
        .map_err(|source| ToolError::StdoutJoin { source })?;
    let stderr_capture = stderr_task
        .await
        .map_err(|source| ToolError::StderrJoin { source })?;

    let (stdout_bytes, stdout_truncated) =
        stdout_capture.map_err(|source| ToolError::StdoutRead { source })?;
    let (stderr_bytes, stderr_truncated) =
        stderr_capture.map_err(|source| ToolError::StderrRead { source })?;

    Ok(RunCommandOutput {
        stdout: finalize_capture(stdout_bytes, stdout_truncated),
        stderr: finalize_capture(stderr_bytes, stderr_truncated),
        exit_code: status.code(),
    })
}

#[cfg(test)]
pub(crate) async fn start_command_process_with_backend(
    policy_engine: &PolicyEngine,
    default_cwd: &Path,
    backend: ExecutionBackend,
    input: RunCommandInput,
) -> Result<RunningExecution, ToolError> {
    start_command_process_with_baffle_config(
        policy_engine,
        default_cwd,
        backend,
        BaffleRuntimeConfig::from_env(),
        input,
    )
    .await
}

pub(crate) async fn start_command_process_with_baffle_config(
    policy_engine: &PolicyEngine,
    default_cwd: &Path,
    backend: ExecutionBackend,
    baffle: BaffleRuntimeConfig,
    input: RunCommandInput,
) -> Result<RunningExecution, ToolError> {
    let authorization = authorize_command_request(policy_engine, default_cwd, backend, input);
    if !authorization.decision.allowed {
        return Err(ToolError::Validation(
            authorization
                .validation_error
                .expect("authorization denial without validation error"),
        ));
    }

    let plan = authorization.plan.ok_or_else(|| ToolError::BackendSetup {
        details: "allowed authorization did not produce an execution plan".to_string(),
    })?;
    let authorized_cwd = authorization
        .authorized_cwd
        .ok_or_else(|| ToolError::BackendSetup {
            details: "allowed authorization did not preserve the trusted cwd".to_string(),
        })?;
    #[cfg(unix)]
    let cwd_fd = std::os::fd::AsRawFd::as_raw_fd(&authorized_cwd.fd);
    #[cfg(not(unix))]
    let cwd_fd = -1;

    match backend::start(plan, cwd_fd, baffle).await {
        Ok(execution) => Ok(execution),
        Err(StartError::Spawn(source)) => Err(ToolError::Spawn { source }),
        Err(StartError::Setup(details)) => Err(ToolError::BackendSetup { details }),
        Err(StartError::StartupTimeout { timeout }) => Err(ToolError::BackendSetup {
            details: format!(
                "Bubblewrap supervisor startup timed out after {} seconds",
                timeout.as_secs()
            ),
        }),
    }
}

pub fn check_command(
    policy_engine: &PolicyEngine,
    default_cwd: &Path,
    input: RunCommandInput,
) -> RunCommandCheckOutput {
    check_command_with_backend(
        policy_engine,
        default_cwd,
        ExecutionBackend::Bubblewrap,
        input,
    )
}

pub fn check_command_with_backend(
    policy_engine: &PolicyEngine,
    default_cwd: &Path,
    backend: ExecutionBackend,
    input: RunCommandInput,
) -> RunCommandCheckOutput {
    authorize_command_request(policy_engine, default_cwd, backend, input).decision
}

#[derive(Debug)]
struct CommandAuthorization {
    decision: RunCommandCheckOutput,
    validation_error: Option<ValidationError>,
    authorized_cwd: Option<AuthorizedCwd>,
    plan: Option<ExecutionPlan>,
}

#[derive(Debug)]
struct AuthorizedCwd {
    #[cfg(unix)]
    fd: std::os::fd::OwnedFd,
    effective_input: PathBuf,
    cwd_label: String,
}

fn authorize_command_request(
    policy_engine: &PolicyEngine,
    default_cwd: &Path,
    backend: ExecutionBackend,
    input: RunCommandInput,
) -> CommandAuthorization {
    let user_env = input.env.clone().unwrap_or_default();
    let policy_mode = match policy_engine.mode() {
        crate::policy::PolicyMode::Rego => "rego",
        crate::policy::PolicyMode::DenyAll => "deny-all",
    }
    .to_string();

    let mut decision = RunCommandCheckOutput {
        allowed: false,
        reason: None,
        executable: input.executable.clone(),
        resolved_path: None,
        hash: None,
        cwd: None,
        policy_mode,
        filesystem: None,
        baffle_session: None,
        backend: backend.as_str().to_string(),
    };

    let authorized_cwd = match resolve_authorized_cwd(input.cwd.as_deref(), default_cwd) {
        Ok(cwd) => {
            decision.cwd = Some(cwd.cwd_label.clone());
            cwd
        }
        Err(validation_error) => {
            decision.reason = Some(validation_error.to_string());
            return CommandAuthorization {
                decision,
                validation_error: Some(validation_error),
                authorized_cwd: None,
                plan: None,
            };
        }
    };

    let resolved_path =
        match resolve_executable_path(&input.executable, &authorized_cwd.effective_input) {
            Ok(path) => path,
            Err(details) => {
                let validation_error = ValidationError::PathResolutionFailed {
                    command: input.executable.clone(),
                    details,
                };
                decision.reason = Some(validation_error.to_string());
                return CommandAuthorization {
                    decision,
                    validation_error: Some(validation_error),
                    authorized_cwd: Some(authorized_cwd),
                    plan: None,
                };
            }
        };
    decision.resolved_path = Some(resolved_path.clone());

    let executable_hash = match compute_executable_sha256_hex(&resolved_path) {
        Ok(hash) => hash,
        Err(details) => {
            let validation_error = ValidationError::HashResolutionFailed {
                command: input.executable.clone(),
                details,
            };
            decision.reason = Some(validation_error.to_string());
            return CommandAuthorization {
                decision,
                validation_error: Some(validation_error),
                authorized_cwd: Some(authorized_cwd),
                plan: None,
            };
        }
    };
    decision.hash = Some(executable_hash.clone());

    match policy_engine.authorize_invocation(
        &input.executable,
        &resolved_path,
        &executable_hash,
        &input.args,
        &user_env,
        &authorized_cwd.cwd_label,
    ) {
        Ok(policy_authorization) if !policy_authorization.decision.allow => {
            let validation_error = ValidationError::CommandNotAllowed(input.executable.clone());
            decision.reason = Some(validation_error.to_string());
            CommandAuthorization {
                decision,
                validation_error: Some(validation_error),
                authorized_cwd: Some(authorized_cwd),
                plan: None,
            }
        }
        Ok(policy_authorization) => {
            let policy_decision = &policy_authorization.decision;
            decision.filesystem = policy_decision.filesystem.clone();
            decision.baffle_session = policy_decision.baffle_session.clone();
            if let Some(validation_error) = policy_authorization.validation_error {
                decision.reason = Some(validation_error.to_string());
                return CommandAuthorization {
                    decision,
                    validation_error: Some(validation_error),
                    authorized_cwd: Some(authorized_cwd),
                    plan: None,
                };
            }
            let plan = ExecutionPlan {
                invocation: AuthorizedInvocation {
                    executable: PathBuf::from(&resolved_path),
                    executable_hash: executable_hash.clone(),
                    args: input.args.clone(),
                    environment: build_effective_command_env(
                        &user_env,
                        backend,
                        policy_decision.baffle_session.is_some(),
                    ),
                    cwd: authorized_cwd.effective_input.clone(),
                    cwd_label: authorized_cwd.cwd_label.clone(),
                    generation: policy_authorization.generation.clone(),
                },
                backend,
                filesystem: policy_authorization.filesystem_profile,
                baffle_session: policy_decision.baffle_session.clone(),
            };
            if let Err(details) = plan.validate_compatibility() {
                let validation_error = ValidationError::IncompatibleBackend {
                    backend: backend.as_str().to_string(),
                    details,
                };
                decision.reason = Some(validation_error.to_string());
                return CommandAuthorization {
                    decision,
                    validation_error: Some(validation_error),
                    authorized_cwd: Some(authorized_cwd),
                    plan: None,
                };
            }
            tracing::debug!(
                backend = plan.backend.as_str(),
                policy_generation = plan.invocation.generation.id(),
                filesystem_profile = ?plan.filesystem.as_ref().map(|profile| profile.name.as_str()),
                "authorized execution plan created",
            );
            tracing::info!(
                command = %input.executable,
                path = %resolved_path,
                cwd = %authorized_cwd.cwd_label,
                effective_cwd = %authorized_cwd.effective_input.display(),
                "command authorization allowed",
            );
            decision.allowed = true;
            CommandAuthorization {
                decision,
                validation_error: None,
                authorized_cwd: Some(authorized_cwd),
                plan: Some(plan),
            }
        }
        Err(validation_error) => {
            decision.reason = Some(validation_error.to_string());
            CommandAuthorization {
                decision,
                validation_error: Some(validation_error),
                authorized_cwd: Some(authorized_cwd),
                plan: None,
            }
        }
    }
}

fn resolve_authorized_cwd(
    request_cwd: Option<&str>,
    default_cwd: &Path,
) -> Result<AuthorizedCwd, ValidationError> {
    let effective_input = request_cwd
        .map(PathBuf::from)
        .unwrap_or_else(|| default_cwd.to_path_buf());
    let cwd_for_error = effective_input.to_string_lossy().into_owned();

    if !effective_input.is_absolute() {
        return Err(ValidationError::CwdResolutionFailed {
            cwd: cwd_for_error,
            details: "cwd must be absolute".to_string(),
        });
    }

    resolve_authorized_cwd_absolute(effective_input)
}

#[cfg(target_os = "linux")]
fn resolve_authorized_cwd_absolute(
    effective_input: PathBuf,
) -> Result<AuthorizedCwd, ValidationError> {
    use std::ffi::CString;
    use std::mem::MaybeUninit;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
    use std::os::unix::ffi::OsStrExt;

    fn cwd_error(cwd: &Path, details: impl Into<String>) -> ValidationError {
        ValidationError::CwdResolutionFailed {
            cwd: cwd.to_string_lossy().into_owned(),
            details: details.into(),
        }
    }

    fn open_root() -> Result<OwnedFd, std::io::Error> {
        let root = CString::new("/").expect("static path has no nul");
        let fd = unsafe {
            libc::open(
                root.as_ptr(),
                libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(unsafe { OwnedFd::from_raw_fd(fd) })
        }
    }

    fn open_component(parent_fd: RawFd, component: &[u8]) -> Result<OwnedFd, std::io::Error> {
        let component = CString::new(component).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "cwd component contains a nul byte",
            )
        })?;
        let fd = unsafe {
            libc::openat(
                parent_fd,
                component.as_ptr(),
                libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }

        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let mut stat = MaybeUninit::<libc::stat>::uninit();
        if unsafe { libc::fstat(fd.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
            return Err(std::io::Error::last_os_error());
        }

        let stat = unsafe { stat.assume_init() };
        match stat.st_mode & libc::S_IFMT {
            libc::S_IFDIR => Ok(fd),
            libc::S_IFLNK => Err(std::io::Error::from_raw_os_error(libc::ELOOP)),
            _ => Err(std::io::Error::from_raw_os_error(libc::ENOTDIR)),
        }
    }

    fn open_error_details(error: &std::io::Error) -> String {
        match error.raw_os_error() {
            Some(libc::ENOENT) => "path does not exist".to_string(),
            Some(libc::ENOTDIR) => "path is not a directory".to_string(),
            Some(libc::ELOOP) => "path contains a symlink or magic link".to_string(),
            Some(libc::EACCES) => "permission denied".to_string(),
            _ => error.to_string(),
        }
    }

    let cwd_bytes = effective_input.as_os_str().as_bytes();
    if cwd_bytes.starts_with(b"//") {
        return Err(cwd_error(&effective_input, "cwd must not start with '//'"));
    }

    let mut current = open_root()
        .map_err(|error| cwd_error(&effective_input, format!("failed opening '/': {error}")))?;
    let mut label_components = Vec::new();

    for component in cwd_bytes.split(|byte| *byte == b'/') {
        if component.is_empty() {
            continue;
        }

        if component == b"." || component == b".." {
            return Err(cwd_error(
                &effective_input,
                "cwd must not contain '.' or '..' components",
            ));
        }

        let label_component = std::str::from_utf8(component)
            .map_err(|_| cwd_error(&effective_input, "cwd contains a non-UTF-8 component"))?;
        let next = open_component(current.as_raw_fd(), component)
            .map_err(|error| cwd_error(&effective_input, open_error_details(&error)))?;
        current = next;
        label_components.push(label_component.to_string());
    }

    let cwd_label = if label_components.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", label_components.join("/"))
    };

    Ok(AuthorizedCwd {
        fd: current,
        effective_input,
        cwd_label,
    })
}

#[cfg(not(target_os = "linux"))]
fn resolve_authorized_cwd_absolute(
    effective_input: PathBuf,
) -> Result<AuthorizedCwd, ValidationError> {
    Err(ValidationError::CwdResolutionFailed {
        cwd: effective_input.to_string_lossy().into_owned(),
        details: "trusted cwd resolution is only implemented on Linux".to_string(),
    })
}

pub(crate) fn resolve_executable_path(
    command: &str,
    working_directory: &Path,
) -> Result<String, String> {
    if command.contains('/') {
        let path = std::path::Path::new(command);
        let candidate = if path.is_absolute() {
            path.to_path_buf()
        } else {
            working_directory.join(path)
        };
        if !candidate.is_file() {
            return Err(format!("'{}' is not a file", candidate.display()));
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let metadata = candidate.metadata().map_err(|error| {
                format!(
                    "failed reading metadata for '{}': {error}",
                    candidate.display()
                )
            })?;
            if metadata.permissions().mode() & 0o111 == 0 {
                return Err(format!("'{}' is not executable", candidate.display()));
            }
        }

        return Ok(candidate.to_string_lossy().into_owned());
    }

    let path = std::env::var_os("PATH").ok_or_else(|| "PATH is not set".to_string())?;
    resolve_executable_in_path(command, &path)
}

fn resolve_executable_in_path(
    command: &str,
    search_path: &std::ffi::OsStr,
) -> Result<String, String> {
    let server_cwd = std::env::current_dir()
        .map_err(|error| format!("failed to read server working directory: {error}"))?;
    for directory in std::env::split_paths(search_path) {
        let candidate = if directory.is_absolute() {
            directory.join(command)
        } else {
            server_cwd.join(directory).join(command)
        };
        if !candidate.is_file() {
            continue;
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let metadata = candidate.metadata().map_err(|error| {
                format!(
                    "failed reading metadata for '{}': {error}",
                    candidate.display()
                )
            })?;
            if metadata.permissions().mode() & 0o111 == 0 {
                continue;
            }
        }

        return Ok(candidate.to_string_lossy().into_owned());
    }

    Err(format!("'{}' was not found on PATH", command))
}

#[cfg(test)]
fn build_command_env(user_env: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    build_effective_command_env(user_env, ExecutionBackend::Direct, false)
}

fn build_effective_command_env(
    user_env: &BTreeMap<String, String>,
    backend: ExecutionBackend,
    baffle_authorized: bool,
) -> BTreeMap<String, String> {
    let mut command_env = BTreeMap::new();

    for key in ["HOME", "LANG"] {
        if let Ok(value) = std::env::var(key) {
            command_env.insert(key.to_string(), value);
        }
    }

    command_env.extend(
        user_env
            .iter()
            .map(|(key, value)| (key.clone(), value.clone())),
    );

    for key in [
        "PATH",
        "http_proxy",
        "https_proxy",
        "no_proxy",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "NO_PROXY",
    ] {
        command_env.remove(key);
    }

    if let Ok(path) = std::env::var("PATH") {
        command_env.insert("PATH".to_string(), path);
    }

    let http_proxy = std::env::var("http_proxy").ok();
    let https_proxy = std::env::var("https_proxy").ok();
    let no_proxy = std::env::var("no_proxy").ok();

    if let Some(value) = http_proxy.clone() {
        command_env.insert("http_proxy".to_string(), value);
    }
    if let Some(value) = https_proxy.clone() {
        command_env.insert("https_proxy".to_string(), value);
    }
    if let Some(value) = no_proxy.clone() {
        command_env.insert("no_proxy".to_string(), value);
    }

    if let Some(value) = http_proxy {
        command_env.insert("HTTP_PROXY".to_string(), value);
    }
    if let Some(value) = https_proxy {
        command_env.insert("HTTPS_PROXY".to_string(), value);
    }
    if let Some(value) = no_proxy {
        command_env.insert("NO_PROXY".to_string(), value);
    }

    if backend == ExecutionBackend::Bubblewrap {
        command_env.retain(|key, _| {
            let lower = key.to_ascii_lowercase();
            !lower.contains("proxy")
                && !matches!(
                    lower.as_str(),
                    "ssl_cert_file"
                        | "ssl_cert_dir"
                        | "curl_ca_bundle"
                        | "requests_ca_bundle"
                        | "node_extra_ca_certs"
                )
        });
        if baffle_authorized {
            for key in ["http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY"] {
                command_env.insert(key.to_string(), "http://127.0.0.1:3128".to_string());
            }
            for key in [
                "SSL_CERT_FILE",
                "CURL_CA_BUNDLE",
                "REQUESTS_CA_BUNDLE",
                "NODE_EXTRA_CA_CERTS",
            ] {
                command_env.insert(
                    key.to_string(),
                    crate::baffle::SANDBOX_CA_CERTIFICATE.into(),
                );
            }
        }
    }

    command_env
}

pub(crate) fn compute_executable_sha256_hex(path: &str) -> Result<String, String> {
    let mut file = std::fs::File::open(path)
        .map_err(|error| format!("failed opening '{path}' for hashing: {error}"))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];

    loop {
        let bytes_read = file
            .read(&mut buffer)
            .map_err(|error| format!("failed reading '{path}' for hashing: {error}"))?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    let digest = hasher.finalize();
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        let _ = write!(&mut output, "{byte:02x}");
    }
    Ok(output)
}

async fn read_limited<R: tokio::io::AsyncRead + Unpin>(
    mut reader: R,
) -> Result<(Vec<u8>, bool), std::io::Error> {
    let mut output = Vec::new();
    let mut buffer = [0u8; 8192];
    let mut truncated = false;

    loop {
        let bytes_read = reader.read(&mut buffer).await?;
        if bytes_read == 0 {
            break;
        }

        if truncated {
            continue;
        }

        let remaining = MAX_OUTPUT_BYTES.saturating_sub(output.len());
        if bytes_read <= remaining {
            output.extend_from_slice(&buffer[..bytes_read]);
        } else {
            if remaining > 0 {
                output.extend_from_slice(&buffer[..remaining]);
            }
            truncated = true;
        }
    }

    Ok((output, truncated))
}

fn finalize_capture(bytes: Vec<u8>, truncated: bool) -> String {
    let mut value = String::from_utf8_lossy(&bytes).into_owned();
    if truncated {
        value.push_str(TRUNCATION_MARKER);
    }
    value
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    use super::*;
    use crate::policy::PolicyEngine;

    fn check_direct(
        policy_engine: &PolicyEngine,
        default_cwd: &Path,
        input: RunCommandInput,
    ) -> RunCommandCheckOutput {
        check_command_with_backend(policy_engine, default_cwd, ExecutionBackend::Direct, input)
    }

    async fn run_direct(
        policy_engine: &PolicyEngine,
        default_cwd: &Path,
        input: RunCommandInput,
    ) -> Result<RunCommandOutput, ToolError> {
        run_command_with_backend(policy_engine, default_cwd, ExecutionBackend::Direct, input).await
    }

    fn default_cwd_for_tests() -> PathBuf {
        std::env::current_dir().expect("test cwd should resolve")
    }

    fn find_executable(name: &str) -> Option<String> {
        let path = std::env::var_os("PATH")?;
        for dir in std::env::split_paths(&path) {
            let candidate = dir.join(name);
            if candidate.is_file() {
                return Some(candidate.to_string_lossy().into_owned());
            }
        }
        None
    }

    #[cfg(target_os = "linux")]
    fn bubblewrap_capable() -> bool {
        crate::backend::host_has_required_bubblewrap()
    }

    #[cfg(target_os = "linux")]
    fn system_library_directory_for_tests() -> PathBuf {
        for candidate in [
            "/lib64/libc.so.6",
            "/lib/x86_64-linux-gnu/libc.so.6",
            "/lib/aarch64-linux-gnu/libc.so.6",
        ] {
            let path = PathBuf::from(candidate);
            if path.is_file() {
                return std::fs::canonicalize(path.parent().expect("library parent"))
                    .expect("canonical library directory");
            }
        }
        let executable = ["/sbin/ldconfig", "/usr/sbin/ldconfig"]
            .into_iter()
            .find(|path| Path::new(path).is_file())
            .expect("ldconfig executable");
        let output = std::process::Command::new(executable)
            .arg("-p")
            .env_clear()
            .output()
            .expect("read loader cache");
        let output = String::from_utf8_lossy(&output.stdout);
        let line = output
            .lines()
            .find(|line| line.trim_start().starts_with("libc.so.6 "))
            .expect("libc loader cache entry");
        let path = line.split_once("=>").expect("loader cache path").1.trim();
        std::fs::canonicalize(Path::new(path).parent().expect("libc parent"))
            .expect("canonical libc directory")
    }

    fn parse_env_output(output: &str) -> BTreeMap<String, String> {
        output
            .lines()
            .filter_map(|line| {
                line.split_once('=')
                    .map(|(key, value)| (key.to_string(), value.to_string()))
            })
            .collect()
    }

    fn rego_engine_allow_commands(commands: &[&str]) -> PolicyEngine {
        let mut allowed_map = String::new();
        for command in commands {
            let escaped = command.replace('\\', "\\\\").replace('\"', "\\\"");
            allowed_map.push_str(&format!("  \"{escaped}\": true,\n"));
        }

        let main = format!(
            "package sandbox.main\n\ndefault decision := {{\"allow\": false, \"filesystem\": null, \"baffle_session\": null}}\n\nallowed_commands := {{\n{allowed_map}}}\n\ndecision := {{\"allow\": true, \"filesystem\": null, \"baffle_session\": null}} if {{\n  allowed_commands[input.command]\n}}\n"
        );

        PolicyEngine::from_rego_for_tests(&[("main.rego", &main)])
    }

    fn rego_engine_allow_command_in_cwd(command: &str, cwd: &str) -> PolicyEngine {
        let module = format!(
            "package sandbox.main\n\ndefault decision := {{\"allow\": false, \"filesystem\": null, \"baffle_session\": null}}\n\ndecision := {{\"allow\": true, \"filesystem\": null, \"baffle_session\": null}} if {{\n  input.command == {}\n  input.cwd == {}\n}}\n",
            serde_json::to_string(command).expect("command string"),
            serde_json::to_string(cwd).expect("cwd string"),
        );
        PolicyEngine::from_rego_for_tests(&[("main.rego", &module)])
    }

    fn policy_engine_with_selection(
        root: &Path,
        filesystem: Option<&str>,
        baffle_session: Option<&str>,
    ) -> PolicyEngine {
        let policy_dir = root.join("policies");
        let filesystem_dir = root.join("filesystems");
        std::fs::create_dir_all(&policy_dir).expect("create policy directory");
        let decision = serde_json::json!({
            "allow": true,
            "filesystem": filesystem,
            "baffle_session": baffle_session,
        });
        std::fs::write(
            policy_dir.join("main.rego"),
            format!("package sandbox.main\n\ndecision := {decision}\n"),
        )
        .expect("write policy");
        if let Some(profile_name) = filesystem {
            let source = root.join("workspace");
            std::fs::create_dir_all(&source).expect("create mount source");
            std::fs::create_dir_all(&filesystem_dir).expect("create filesystem directory");
            std::fs::write(
                filesystem_dir.join(format!("{profile_name}.toml")),
                format!(
                    "version = 1\n\n[[mounts]]\nsource = {:?}\ntarget = \"/workspace\"\naccess = \"read-only\"\n",
                    source.to_string_lossy()
                ),
            )
            .expect("write profile");
        }
        PolicyEngine::from_sources(Some(policy_dir))
    }

    fn write_executable_script(path: &Path, body: &[u8]) {
        std::fs::write(path, body).expect("write script");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(path).expect("metadata").permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(path, perms).expect("set perms");
        }
    }

    fn compile_rpath_test_command(directory: &Path) -> PathBuf {
        std::fs::create_dir_all(directory).expect("custom library directory");
        let library_source = directory.join("libreview.c");
        let command_source = directory.join("command.c");
        let library = directory.join("libreview.so");
        let command = directory.join("command");
        std::fs::write(&library_source, "int answer(void) { return 42; }\n")
            .expect("write custom library source");
        std::fs::write(
            &command_source,
            "int answer(void); int main(void) { return answer() == 42 ? 0 : 1; }\n",
        )
        .expect("write custom command source");

        let output = std::process::Command::new("cc")
            .args(["-shared", "-fPIC"])
            .arg(&library_source)
            .arg("-o")
            .arg(&library)
            .output()
            .expect("start C compiler for custom shared library");
        assert!(
            output.status.success(),
            "custom library compile failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        let output = std::process::Command::new("cc")
            .arg(&command_source)
            .arg(format!("-L{}", directory.display()))
            .arg("-lreview")
            .arg(format!("-Wl,-rpath,{}", directory.display()))
            .arg("-o")
            .arg(&command)
            .output()
            .expect("start C compiler for custom command");
        assert!(
            output.status.success(),
            "custom command compile failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        command
    }

    #[test]
    fn backend_compatibility_matrix_is_reported_by_check_without_execution() {
        let true_path = find_executable("true").expect("true executable");
        let default_cwd = default_cwd_for_tests();
        let input = || RunCommandInput {
            executable: true_path.clone(),
            args: vec![],
            cwd: None,
            env: None,
        };

        let direct_root = tempfile::tempdir().expect("direct root");
        let direct_engine = policy_engine_with_selection(direct_root.path(), None, None);
        let direct = check_command_with_backend(
            &direct_engine,
            &default_cwd,
            ExecutionBackend::Direct,
            input(),
        );
        assert!(direct.allowed, "{:?}", direct.reason);
        assert_eq!(direct.backend, "direct");
        assert_eq!(direct.filesystem, None);
        assert_eq!(direct.baffle_session, None);

        let missing_profile_root = tempfile::tempdir().expect("missing profile root");
        let missing_profile_engine =
            policy_engine_with_selection(missing_profile_root.path(), None, None);
        let missing_profile = check_command_with_backend(
            &missing_profile_engine,
            &default_cwd,
            ExecutionBackend::Bubblewrap,
            input(),
        );
        assert!(!missing_profile.allowed);
        assert!(
            missing_profile
                .reason
                .as_deref()
                .unwrap()
                .contains("requires a named filesystem profile")
        );
        assert_eq!(missing_profile.backend, "bubblewrap");

        let profile_root = tempfile::tempdir().expect("profile root");
        let profile_engine = policy_engine_with_selection(
            profile_root.path(),
            Some("workspace-readonly"),
            Some("github-readonly.toml"),
        );
        let bubblewrap = check_command_with_backend(
            &profile_engine,
            &default_cwd,
            ExecutionBackend::Bubblewrap,
            input(),
        );
        assert!(bubblewrap.allowed, "{:?}", bubblewrap.reason);
        assert_eq!(bubblewrap.filesystem.as_deref(), Some("workspace-readonly"));
        assert_eq!(
            bubblewrap.baffle_session.as_deref(),
            Some("github-readonly.toml")
        );
        assert_eq!(bubblewrap.backend, "bubblewrap");
        let default_backend = check_command(&profile_engine, &default_cwd, input());
        assert!(default_backend.allowed, "{:?}", default_backend.reason);
        assert_eq!(default_backend.backend, "bubblewrap");
        let serialized = serde_json::to_value(&bubblewrap).expect("serialize check result");
        assert_eq!(
            serialized
                .get("baffle_session")
                .and_then(|value| value.as_str()),
            Some("github-readonly.toml")
        );
        assert!(serialized.get("baffleSession").is_none());

        let incompatible_direct = check_command_with_backend(
            &profile_engine,
            &default_cwd,
            ExecutionBackend::Direct,
            input(),
        );
        assert!(!incompatible_direct.allowed);
        assert!(
            incompatible_direct
                .reason
                .as_deref()
                .unwrap()
                .contains("requires filesystem: null")
        );
        assert_eq!(
            incompatible_direct.filesystem.as_deref(),
            Some("workspace-readonly")
        );
        assert_eq!(
            incompatible_direct.baffle_session.as_deref(),
            Some("github-readonly.toml")
        );
    }

    #[test]
    fn check_reports_a_selected_but_unconfigured_profile() {
        let true_path = find_executable("true").expect("true executable");
        let module = r#"package sandbox.main

decision := {"allow": true, "filesystem": "missing-profile", "baffle_session": null}
"#;
        let engine = PolicyEngine::from_rego_for_tests(&[("main.rego", module)]);
        let decision = check_command_with_backend(
            &engine,
            &default_cwd_for_tests(),
            ExecutionBackend::Bubblewrap,
            RunCommandInput {
                executable: true_path,
                args: vec![],
                cwd: None,
                env: None,
            },
        );
        assert!(!decision.allowed);
        assert_eq!(decision.filesystem.as_deref(), Some("missing-profile"));
        assert_eq!(decision.baffle_session, None);
        assert!(
            decision
                .reason
                .as_deref()
                .unwrap()
                .contains("not configured")
        );
    }

    #[test]
    fn authorized_execution_plan_keeps_its_policy_generation_after_reload() {
        let true_path = find_executable("true").expect("true executable");
        let root = tempfile::tempdir().expect("profile root");
        let engine = policy_engine_with_selection(root.path(), Some("workspace"), None);
        let default_cwd = default_cwd_for_tests();
        let input = || RunCommandInput {
            executable: true_path.clone(),
            args: vec![],
            cwd: None,
            env: None,
        };
        let first =
            authorize_command_request(&engine, &default_cwd, ExecutionBackend::Bubblewrap, input())
                .plan
                .expect("first plan");
        let first_generation = first.invocation.generation.id();

        let other_source = root.path().join("workspace-other");
        let filesystem_dir = root.path().join("filesystems");
        std::fs::create_dir(&other_source).expect("create new profile source");
        std::fs::write(
            filesystem_dir.join("workspace-other.toml"),
            format!(
                "version = 1\n\n[[mounts]]\nsource = {:?}\ntarget = \"/workspace-other\"\naccess = \"read-only\"\n",
                other_source.to_string_lossy()
            ),
        )
        .expect("write new profile");
        let policy_dir = root.path().join("policies");
        std::fs::write(
            policy_dir.join("main.rego"),
            "package sandbox.main\n\ndecision := {\"allow\": true, \"filesystem\": \"workspace-other\", \"baffle_session\": null}\n",
        )
        .expect("update decision");

        let second =
            authorize_command_request(&engine, &default_cwd, ExecutionBackend::Bubblewrap, input())
                .plan
                .expect("second plan");
        assert_ne!(first_generation, second.invocation.generation.id());
        assert_eq!(
            first.filesystem.as_ref().expect("old profile").name,
            "workspace"
        );
        assert_eq!(
            second.filesystem.as_ref().expect("new profile").name,
            "workspace-other"
        );
    }

    #[cfg(unix)]
    #[test]
    fn check_resolves_a_plan_without_spawning_the_authorized_command() {
        let temp = tempfile::tempdir_in(default_cwd_for_tests()).expect("tempdir");
        let script_path = temp.path().join("touch-marker");
        let marker_path = temp.path().join("spawned");
        let script = format!(
            "#!/bin/sh\nprintf '%s|%s|%s' \"$1\" \"$FLAG\" \"$PWD\" > {:?}\n",
            marker_path
        );
        write_executable_script(&script_path, script.as_bytes());
        let policy_engine =
            rego_engine_allow_commands(&[script_path.to_str().expect("script path")]);
        let cwd = temp.path().join("work");
        std::fs::create_dir(&cwd).expect("create cwd");
        let authorization = authorize_command_request(
            &policy_engine,
            &cwd,
            ExecutionBackend::Direct,
            RunCommandInput {
                executable: script_path.to_string_lossy().into_owned(),
                args: vec!["literal argument".to_string()],
                cwd: None,
                env: Some(BTreeMap::from([("FLAG".to_string(), "kept".to_string())])),
            },
        );
        assert!(
            authorization.decision.allowed,
            "{:?}",
            authorization.decision.reason
        );
        let plan = authorization.plan.expect("validated plan");
        assert_eq!(plan.invocation.executable, script_path);
        assert_eq!(plan.invocation.args, vec!["literal argument"]);
        assert_eq!(
            plan.invocation.environment.get("FLAG").map(String::as_str),
            Some("kept")
        );
        assert_eq!(plan.invocation.cwd, cwd);
        assert_eq!(plan.invocation.cwd_label, cwd.to_string_lossy());
        assert!(plan.invocation.generation.id() > 0);
        assert!(!marker_path.exists(), "check must not spawn the command");
    }

    #[test]
    fn bubblewrap_plans_control_proxy_environment_by_baffle_selection() {
        let true_path = find_executable("true").expect("true executable");
        let default_cwd = default_cwd_for_tests();
        let forwarded_env = Some(BTreeMap::from([
            (
                "ALL_PROXY".to_string(),
                "http://untrusted.invalid:8080".to_string(),
            ),
            ("NO_PROXY".to_string(), "*".to_string()),
            (
                "CUSTOM_proxy".to_string(),
                "http://untrusted.invalid:8080".to_string(),
            ),
            ("FLAG".to_string(), "kept".to_string()),
        ]));
        let no_network_root = tempfile::tempdir().expect("no network profile root");
        let no_network_engine =
            policy_engine_with_selection(no_network_root.path(), Some("workspace"), None);
        let no_network = authorize_command_request(
            &no_network_engine,
            &default_cwd,
            ExecutionBackend::Bubblewrap,
            RunCommandInput {
                executable: true_path.clone(),
                args: vec![],
                cwd: None,
                env: forwarded_env.clone(),
            },
        );
        let no_network_plan = no_network.plan.expect("bubblewrap plan");
        assert!(
            no_network_plan
                .invocation
                .environment
                .keys()
                .all(|name| !name.to_ascii_lowercase().ends_with("_proxy"))
        );
        assert_eq!(
            no_network_plan
                .invocation
                .environment
                .get("FLAG")
                .map(String::as_str),
            Some("kept")
        );

        let baffle_root = tempfile::tempdir().expect("Baffle profile root");
        let baffle_engine = policy_engine_with_selection(
            baffle_root.path(),
            Some("workspace"),
            Some("session.toml"),
        );
        let baffle = authorize_command_request(
            &baffle_engine,
            &default_cwd,
            ExecutionBackend::Bubblewrap,
            RunCommandInput {
                executable: true_path,
                args: vec![],
                cwd: None,
                env: forwarded_env,
            },
        );
        let baffle_plan = baffle.plan.expect("Baffle plan");
        for name in ["http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY"] {
            assert_eq!(
                baffle_plan
                    .invocation
                    .environment
                    .get(name)
                    .map(String::as_str),
                Some("http://127.0.0.1:3128")
            );
        }
        assert!(baffle_plan.invocation.environment.keys().all(|name| {
            !name.to_ascii_lowercase().ends_with("_proxy")
                || ["http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY"]
                    .contains(&name.as_str())
        }));
    }

    #[tokio::test]
    async fn bubblewrap_setup_failure_never_falls_back_to_direct() {
        let true_path = find_executable("true").expect("true executable");
        let root = tempfile::tempdir().expect("profile root");
        // The Bubblewrap backend always replaces /tmp with a private tmpfs.
        // Use a host directory there so the authorized CWD is guaranteed to
        // be absent inside the sandbox, including when CI itself runs in /workspace.
        let hidden_cwd = tempfile::tempdir_in("/tmp").expect("hidden cwd");
        let engine = policy_engine_with_selection(root.path(), Some("workspace"), None);
        let error = run_command_with_backend(
            &engine,
            default_cwd_for_tests().as_path(),
            ExecutionBackend::Bubblewrap,
            RunCommandInput {
                executable: true_path,
                args: vec![],
                cwd: Some(hidden_cwd.path().to_string_lossy().into_owned()),
                env: None,
            },
        )
        .await
        .expect_err("unmounted authorized cwd must prevent execution");
        assert!(matches!(error, ToolError::BackendSetup { .. }));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn buffered_execution_preserves_signal_termination_and_exit_128() {
        let shell = match find_executable("sh") {
            Some(path) => path,
            None => return,
        };
        let cwd = default_cwd_for_tests();
        let direct_engine = rego_engine_allow_commands(&[&shell]);
        let invoke = |script: &str| RunCommandInput {
            executable: shell.clone(),
            args: vec!["-c".to_string(), script.to_string()],
            cwd: Some("/".to_string()),
            env: None,
        };

        let output = run_command_with_backend(
            &direct_engine,
            &cwd,
            ExecutionBackend::Direct,
            invoke("kill -TERM $$"),
        )
        .await
        .expect("Direct signal execution");
        assert_eq!(output.exit_code, None);

        let output = run_command_with_backend(
            &direct_engine,
            &cwd,
            ExecutionBackend::Direct,
            invoke("exit 128"),
        )
        .await
        .expect("Direct exit 128 execution");
        assert_eq!(output.exit_code, Some(128));

        if !bubblewrap_capable() {
            return;
        }
        let root = tempfile::tempdir().expect("Bubblewrap policy root");
        let bubblewrap_engine = policy_engine_with_selection(root.path(), Some("minimal"), None);
        let output = run_command_with_backend(
            &bubblewrap_engine,
            &cwd,
            ExecutionBackend::Bubblewrap,
            invoke("kill -TERM $$"),
        )
        .await
        .expect("Bubblewrap signal execution");
        assert_eq!(output.exit_code, None);

        let output = run_command_with_backend(
            &bubblewrap_engine,
            &cwd,
            ExecutionBackend::Bubblewrap,
            invoke("exit 128"),
        )
        .await
        .expect("Bubblewrap exit 128 execution");
        assert_eq!(output.exit_code, Some(128));
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn bubblewrap_uses_custom_rpath_libraries_only_when_the_profile_exposes_them() {
        if !bubblewrap_capable() {
            return;
        }
        let cwd = default_cwd_for_tests();
        let root = tempfile::tempdir_in(&cwd).expect("test root");
        let custom_dir = root.path().join("custom");
        let command = compile_rpath_test_command(&custom_dir);
        assert!(
            std::process::Command::new(&command)
                .status()
                .expect("run custom command on host")
                .success(),
            "custom RPATH command did not run on the host"
        );

        let policy_dir = root.path().join("policies");
        let filesystem_dir = root.path().join("filesystems");
        std::fs::create_dir_all(&policy_dir).expect("policy directory");
        std::fs::create_dir_all(&filesystem_dir).expect("filesystem directory");
        std::fs::write(
            filesystem_dir.join("custom.toml"),
            format!(
                "version = 1\nruntime_paths = [{:?}]\nmounts = []\n",
                custom_dir.join("libreview.so").to_string_lossy(),
            ),
        )
        .expect("write profile with a selected library file");
        std::fs::write(
            filesystem_dir.join("minimal.toml"),
            "version = 1\nmounts = []\n",
        )
        .expect("write minimal profile");

        for profile in ["custom", "minimal"] {
            std::fs::write(
                policy_dir.join("main.rego"),
                format!(
                    "package sandbox.main\n\ndecision := {{\"allow\": true, \"filesystem\": {}, \"baffle_session\": null}}\n",
                    serde_json::to_string(profile).expect("encode filesystem profile")
                ),
            )
            .expect("update policy");
            let engine = PolicyEngine::from_sources(Some(policy_dir.clone()));
            let result = run_command_with_backend(
                &engine,
                &cwd,
                ExecutionBackend::Bubblewrap,
                RunCommandInput {
                    executable: command.to_string_lossy().into_owned(),
                    args: vec![],
                    cwd: Some("/".to_string()),
                    env: None,
                },
            )
            .await;
            if profile == "custom" {
                let output = result.expect("mounted custom RPATH library is available");
                assert_eq!(output.exit_code, Some(0), "{}", output.stderr);
            } else {
                let error = result.expect_err("unmounted custom RPATH library must be rejected");
                assert!(
                    matches!(error, ToolError::BackendSetup { ref details } if details.contains("libreview.so")),
                    "unexpected missing-library error: {error}"
                );
            }
        }
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn bubblewrap_runs_elf_command_with_restricted_runtime_and_private_tmp() {
        use std::os::unix::fs::PermissionsExt;

        let bubblewrap = std::path::Path::new("/usr/bin/bwrap");
        if !bubblewrap.is_file() || !bubblewrap_capable() {
            return;
        }
        let cwd = default_cwd_for_tests();
        let root = tempfile::tempdir_in(&cwd).expect("profile root");
        let workspace = root.path().join("workspace");
        std::fs::create_dir(&workspace).expect("workspace");
        let policy_dir = root.path().join("policies");
        let filesystem_dir = root.path().join("filesystems");
        std::fs::create_dir(&policy_dir).expect("policy directory");
        std::fs::create_dir(&filesystem_dir).expect("filesystem directory");
        std::fs::write(
            policy_dir.join("main.rego"),
            "package sandbox.main\n\ndecision := {\"allow\": true, \"filesystem\": \"workspace\", \"baffle_session\": null}\n",
        )
        .expect("policy");
        std::fs::write(
            filesystem_dir.join("workspace.toml"),
            format!(
                "version = 1\n\n[[mounts]]\nsource = {:?}\ntarget = {:?}\naccess = \"read-only\"\n\n[[mounts]]\nsource = \"/usr/bin\"\ntarget = \"/test-bin\"\naccess = \"read-only\"\n\n[[mounts]]\nsource = {:?}\ntarget = \"/test-lib\"\naccess = \"read-only\"\n",
                workspace.to_string_lossy(),
                workspace.to_string_lossy(),
                system_library_directory_for_tests().to_string_lossy(),
            ),
        )
        .expect("filesystem profile");
        let engine = PolicyEngine::from_sources(Some(policy_dir.clone()));
        let printf = find_executable("printf").expect("printf executable");
        let private_tmp_file = root.path().join("must-not-exist-on-host");
        let output = run_command_impl(
            &engine,
            &cwd,
            RunCommandInput {
                executable: printf,
                args: vec!["sandboxed".to_string()],
                cwd: Some("/".to_string()),
                env: None,
            },
        )
        .await
        .expect("Bubblewrap starts the authorized command");
        assert_eq!(output.stdout, "sandboxed");
        assert_eq!(output.exit_code, Some(0));

        let script = workspace.join("hello.sh");
        std::fs::write(&script, b"#!/bin/sh\nprintf shebang-ok\n").expect("write script");
        let mut script_permissions = std::fs::metadata(&script)
            .expect("script metadata")
            .permissions();
        script_permissions.set_mode(0o755);
        std::fs::set_permissions(&script, script_permissions).expect("script is executable");
        let output = run_command_with_backend(
            &engine,
            &cwd,
            ExecutionBackend::Bubblewrap,
            RunCommandInput {
                executable: script.to_string_lossy().into_owned(),
                args: vec![],
                cwd: Some("/".to_string()),
                env: None,
            },
        )
        .await
        .expect("Bubblewrap starts the authorized shebang command");
        assert_eq!(output.stdout, "shebang-ok");
        assert_eq!(output.exit_code, Some(0));

        let touch = find_executable("touch").expect("touch executable");
        let output = run_command_with_backend(
            &engine,
            &cwd,
            ExecutionBackend::Bubblewrap,
            RunCommandInput {
                executable: touch,
                args: vec![private_tmp_file.to_string_lossy().into_owned()],
                cwd: Some("/".to_string()),
                env: None,
            },
        )
        .await
        .expect("private tmpfs command starts");
        assert_eq!(output.exit_code, Some(0), "{}", output.stderr);
        assert!(
            !private_tmp_file.exists(),
            "sandbox /tmp leaked to the host"
        );

        let test_binary = find_executable("test").expect("test executable");
        let control_socket = root.path().join("host-control.sock");
        let listener =
            std::os::unix::net::UnixListener::bind(&control_socket).expect("host control socket");
        let output = run_command_with_backend(
            &engine,
            &cwd,
            ExecutionBackend::Bubblewrap,
            RunCommandInput {
                executable: test_binary.clone(),
                args: vec!["!".to_string(), "-e".to_string(), "/etc/passwd".to_string()],
                cwd: Some("/".to_string()),
                env: None,
            },
        )
        .await
        .expect("protected path probe starts");
        assert_eq!(output.exit_code, Some(0), "host /etc/passwd was visible");
        let output = run_command_with_backend(
            &engine,
            &cwd,
            ExecutionBackend::Bubblewrap,
            RunCommandInput {
                executable: test_binary,
                args: vec![
                    "!".to_string(),
                    "-S".to_string(),
                    control_socket.to_string_lossy().into_owned(),
                ],
                cwd: Some("/".to_string()),
                env: None,
            },
        )
        .await
        .expect("host socket probe starts");
        assert_eq!(output.exit_code, Some(0), "host control socket was visible");
        drop(listener);

        let write_target = workspace.join("read-only-write");
        let output = run_command_with_backend(
            &engine,
            &cwd,
            ExecutionBackend::Bubblewrap,
            RunCommandInput {
                executable: find_executable("touch").expect("touch executable"),
                args: vec![write_target.to_string_lossy().into_owned()],
                cwd: Some("/".to_string()),
                env: None,
            },
        )
        .await
        .expect("read-only mount command starts");
        assert_ne!(output.exit_code, Some(0));
        assert!(!write_target.exists(), "read-only profile allowed a write");

        let writable_profile = filesystem_dir.join("workspace.toml");
        std::fs::write(
            &writable_profile,
            format!(
                "version = 1\n\n[[mounts]]\nsource = {:?}\ntarget = {:?}\naccess = \"read-write\"\n\n[[mounts]]\nsource = \"/usr/bin\"\ntarget = \"/test-bin\"\naccess = \"read-only\"\n\n[[mounts]]\nsource = {:?}\ntarget = \"/test-lib\"\naccess = \"read-only\"\n",
                workspace.to_string_lossy(),
                workspace.to_string_lossy(),
                system_library_directory_for_tests().to_string_lossy(),
            ),
        )
        .expect("write writable profile");
        let writable_engine = PolicyEngine::from_sources(Some(policy_dir));
        let writable_target = workspace.join("read-write-allowed");
        let output = run_command_with_backend(
            &writable_engine,
            &cwd,
            ExecutionBackend::Bubblewrap,
            RunCommandInput {
                executable: find_executable("touch").expect("touch executable"),
                args: vec![writable_target.to_string_lossy().into_owned()],
                cwd: Some("/".to_string()),
                env: None,
            },
        )
        .await
        .expect("read-write mount command starts");
        assert_eq!(output.exit_code, Some(0), "{}", output.stderr);
        assert!(
            writable_target.exists(),
            "read-write profile rejected a write"
        );

        // Model the Gantry-side HTTP proxy on the host loopback. The command
        // below must reach this proxy from the host, then fail from the
        // Bubblewrap network namespace without the listener seeing a second
        // connection.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("host parent-proxy listener");
        let port = listener.local_addr().expect("listener address").port();
        let (accepted_tx, mut accepted_rx) = tokio::sync::mpsc::unbounded_channel();
        let proxy_task = tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.expect("proxy connection");
                accepted_tx.send(()).expect("proxy acceptance receiver");
                let mut request = [0; 4096];
                let count = stream.read(&mut request).await.expect("read proxy request");
                assert!(
                    request[..count].starts_with(b"GET http://proxy-oracle.invalid/probe "),
                    "unexpected HTTP proxy request: {}",
                    String::from_utf8_lossy(&request[..count])
                );
                tokio::io::AsyncWriteExt::write_all(
                    &mut stream,
                    b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\nproxy-ok",
                )
                .await
                .expect("write proxy response");
            }
        });
        let curl = find_executable("curl").expect("curl executable");
        let proxy_args = vec![
            "--silent".to_string(),
            "--show-error".to_string(),
            "--connect-timeout".to_string(),
            "1".to_string(),
            "--max-time".to_string(),
            "2".to_string(),
            "--proxy".to_string(),
            format!("http://127.0.0.1:{port}"),
            "--noproxy".to_string(),
            String::new(),
            "http://proxy-oracle.invalid/probe".to_string(),
        ];
        let host_curl = curl.clone();
        let host_proxy_args = proxy_args.clone();
        let host_result = tokio::task::spawn_blocking(move || {
            std::process::Command::new(host_curl)
                .args(host_proxy_args)
                .env_clear()
                .output()
        })
        .await
        .expect("host curl task joins")
        .expect("host curl request starts");
        assert!(
            host_result.status.success(),
            "host curl could not reach its parent proxy: {}",
            String::from_utf8_lossy(&host_result.stderr)
        );
        assert_eq!(
            host_result.stdout, b"proxy-ok",
            "host proxy did not return its response"
        );
        assert!(
            accepted_rx.try_recv().is_ok(),
            "host proxy did not accept the unsandboxed control request"
        );

        let output = run_command_with_backend(
            &writable_engine,
            &cwd,
            ExecutionBackend::Bubblewrap,
            RunCommandInput {
                executable: curl,
                args: proxy_args,
                cwd: Some("/".to_string()),
                env: None,
            },
        )
        .await
        .expect("network probe starts inside Bubblewrap");
        assert_ne!(
            output.exit_code,
            Some(0),
            "sandbox reached the host parent proxy: stdout={}, stderr={}",
            output.stdout,
            output.stderr
        );
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(250), accepted_rx.recv())
                .await
                .is_err(),
            "host parent proxy accepted a connection from the sandbox"
        );
        proxy_task.abort();
        let _ = proxy_task.await;

        let cat = find_executable("cat").expect("cat executable");
        let output = run_command_with_backend(
            &writable_engine,
            &cwd,
            ExecutionBackend::Bubblewrap,
            RunCommandInput {
                executable: cat,
                args: vec!["/proc/net/route".to_string()],
                cwd: Some("/".to_string()),
                env: None,
            },
        )
        .await
        .expect("private network route table is readable");
        assert_eq!(output.exit_code, Some(0), "{}", output.stderr);
        assert!(
            output
                .stdout
                .lines()
                .skip(1)
                .all(|route| route.split_whitespace().nth(1) != Some("00000000")),
            "sandbox had an external default route: {}",
            output.stdout
        );

        let shell = find_executable("sh").expect("shell executable");
        let descendant_marker = workspace.join("descendant-survived");
        let shell_script = "(/test-bin/sleep 0.5; /test-bin/touch \"$1\") & exit 0";
        let output = run_command_with_backend(
            &writable_engine,
            &cwd,
            ExecutionBackend::Bubblewrap,
            RunCommandInput {
                executable: shell.clone(),
                args: vec![
                    "-c".to_string(),
                    shell_script.to_string(),
                    "gantry-shell".to_string(),
                    descendant_marker.to_string_lossy().into_owned(),
                ],
                cwd: Some("/".to_string()),
                env: Some(BTreeMap::from([(
                    "LD_LIBRARY_PATH".to_string(),
                    "/test-lib".to_string(),
                )])),
            },
        )
        .await
        .expect("background descendant command starts");
        assert_eq!(output.exit_code, Some(0), "{}", output.stderr);
        tokio::time::sleep(std::time::Duration::from_millis(700)).await;
        assert!(
            !descendant_marker.exists(),
            "sandbox completion left a descendant running"
        );

        let cancelled_marker = workspace.join("cancelled-descendant-survived");
        let mut execution = start_command_process_with_backend(
            &writable_engine,
            &cwd,
            ExecutionBackend::Bubblewrap,
            RunCommandInput {
                executable: shell,
                args: vec![
                    "-c".to_string(),
                    "(/test-bin/sleep 0.5; /test-bin/touch \"$1\")".to_string(),
                    "gantry-shell".to_string(),
                    cancelled_marker.to_string_lossy().into_owned(),
                ],
                cwd: Some("/".to_string()),
                env: Some(BTreeMap::from([(
                    "LD_LIBRARY_PATH".to_string(),
                    "/test-lib".to_string(),
                )])),
            },
        )
        .await
        .expect("cancellable command starts");
        execution.cancel().await;
        tokio::time::sleep(std::time::Duration::from_millis(700)).await;
        assert!(
            !cancelled_marker.exists(),
            "cancellation left a command descendant running"
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn bubblewrap_runs_profiled_interpreters_and_helper_workloads() {
        use std::os::unix::fs::PermissionsExt;

        if !bubblewrap_capable() {
            return;
        }
        let cwd = default_cwd_for_tests();
        let root = tempfile::tempdir_in(&cwd).expect("runtime workload root");
        let workspace = root.path().join("workspace");
        std::fs::create_dir(&workspace).expect("workspace");
        let script = workspace.join("env-python.py");
        std::fs::write(&script, b"#!/usr/bin/env python3\nprint('python-env-ok')\n")
            .expect("write Python env-shebang fixture");
        let mut permissions = std::fs::metadata(&script)
            .expect("Python script metadata")
            .permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&script, permissions).expect("make Python script executable");

        let python = find_executable("python3").expect("python3 installed for workload tests");
        let stdlib_output = std::process::Command::new(&python)
            .args([
                "-c",
                "import sysconfig; print(sysconfig.get_path('stdlib'))",
            ])
            .output()
            .expect("locate Python standard library");
        assert!(
            stdlib_output.status.success(),
            "Python stdlib lookup failed"
        );
        let python_stdlib = String::from_utf8(stdlib_output.stdout)
            .expect("Python stdlib path is UTF-8")
            .trim()
            .to_string();
        let tools = ["node", "git", "gh", "cargo"]
            .into_iter()
            .map(|name| {
                (
                    name,
                    find_executable(name)
                        .unwrap_or_else(|| panic!("{name} installed for runtime workload tests")),
                )
            })
            .collect::<Vec<_>>();

        let policy_dir = root.path().join("policies");
        let filesystem_dir = root.path().join("filesystems");
        std::fs::create_dir(&policy_dir).expect("policy directory");
        std::fs::create_dir(&filesystem_dir).expect("filesystem directory");
        std::fs::write(
            policy_dir.join("main.rego"),
            "package sandbox.main\n\ndecision := {\"allow\": true, \"filesystem\": \"workloads\", \"baffle_session\": null}\n",
        )
        .expect("write policy");
        let profile_path = filesystem_dir.join("workloads.toml");
        let write_profile = |runtime_paths: &[String]| {
            let paths = runtime_paths
                .iter()
                .map(|path| format!("{path:?}"))
                .collect::<Vec<_>>()
                .join(", ");
            std::fs::write(
                &profile_path,
                format!(
                    "version = 1\nruntime_paths = [{paths}]\n\n[[mounts]]\nsource = {:?}\ntarget = {:?}\naccess = \"read-only\"\n",
                    workspace.to_string_lossy(),
                    workspace.to_string_lossy(),
                ),
            )
            .expect("write workload profile");
        };

        write_profile(&[]);
        let missing_helper_engine = PolicyEngine::from_sources(Some(policy_dir.clone()));
        let missing_helper = run_command_with_backend(
            &missing_helper_engine,
            &cwd,
            ExecutionBackend::Bubblewrap,
            RunCommandInput {
                executable: script.to_string_lossy().into_owned(),
                args: vec![],
                cwd: Some(workspace.to_string_lossy().into_owned()),
                env: None,
            },
        )
        .await
        .expect("missing env helper is a command failure, not a backend fallback");
        assert_eq!(missing_helper.exit_code, Some(127));
        assert!(
            missing_helper.stderr.contains("python3"),
            "missing helper error should identify python3: {}",
            missing_helper.stderr
        );

        let runtime_paths = vec![python.clone(), python_stdlib];
        write_profile(&runtime_paths);
        let engine = PolicyEngine::from_sources(Some(policy_dir));

        let env_python = run_command_with_backend(
            &engine,
            &cwd,
            ExecutionBackend::Bubblewrap,
            RunCommandInput {
                executable: script.to_string_lossy().into_owned(),
                args: vec![],
                cwd: Some(workspace.to_string_lossy().into_owned()),
                env: None,
            },
        )
        .await
        .expect("profiled env-shebang Python workload starts");
        assert_eq!(env_python.stdout.trim(), "python-env-ok");
        assert_eq!(env_python.exit_code, Some(0), "{}", env_python.stderr);

        let direct_python = run_command_with_backend(
            &engine,
            &cwd,
            ExecutionBackend::Bubblewrap,
            RunCommandInput {
                executable: python,
                args: vec!["-c".to_string(), "print('python-direct-ok')".to_string()],
                cwd: Some(workspace.to_string_lossy().into_owned()),
                env: None,
            },
        )
        .await
        .expect("profiled Python workload starts");
        assert_eq!(direct_python.stdout.trim(), "python-direct-ok");
        assert_eq!(direct_python.exit_code, Some(0), "{}", direct_python.stderr);

        let node = tools.iter().find(|(name, _)| *name == "node").unwrap();
        let node_output = run_command_with_backend(
            &engine,
            &cwd,
            ExecutionBackend::Bubblewrap,
            RunCommandInput {
                executable: node.1.clone(),
                args: vec![
                    "-e".to_string(),
                    "process.stdout.write('node-ok')".to_string(),
                ],
                cwd: Some(workspace.to_string_lossy().into_owned()),
                env: None,
            },
        )
        .await
        .expect("profiled Node workload starts");
        assert_eq!(node_output.stdout, "node-ok", "{node_output:?}");
        assert_eq!(node_output.exit_code, Some(0), "{}", node_output.stderr);

        let git = tools.iter().find(|(name, _)| *name == "git").unwrap();
        assert!(
            std::process::Command::new(&git.1)
                .args(["init", "--quiet"])
                .current_dir(&workspace)
                .status()
                .expect("initialize Git fixture")
                .success(),
            "Git fixture initialization failed"
        );
        std::fs::write(workspace.join("fixture.txt"), "git workload\n")
            .expect("write Git fixture file");
        let git_output = run_command_with_backend(
            &engine,
            &cwd,
            ExecutionBackend::Bubblewrap,
            RunCommandInput {
                executable: git.1.clone(),
                args: vec!["status".to_string(), "--short".to_string()],
                cwd: Some(workspace.to_string_lossy().into_owned()),
                env: None,
            },
        )
        .await
        .expect("profiled Git workload starts");
        assert!(git_output.stdout.contains("fixture.txt"), "{git_output:?}");
        assert_eq!(git_output.exit_code, Some(0), "{}", git_output.stderr);

        for (name, expected_prefix) in [("gh", "gh version"), ("cargo", "cargo ")] {
            let executable = &tools.iter().find(|(tool, _)| *tool == name).unwrap().1;
            let output = run_command_with_backend(
                &engine,
                &cwd,
                ExecutionBackend::Bubblewrap,
                RunCommandInput {
                    executable: executable.clone(),
                    args: vec!["--version".to_string()],
                    cwd: Some(workspace.to_string_lossy().into_owned()),
                    env: None,
                },
            )
            .await
            .unwrap_or_else(|error| panic!("profiled {name} workload failed to start: {error}"));
            assert!(output.stdout.starts_with(expected_prefix), "{output:?}");
            assert_eq!(output.exit_code, Some(0), "{}", output.stderr);
        }
    }

    #[cfg(unix)]
    #[test]
    fn resolve_executable_path_preserves_symlink_in_path_lookup() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let temp = tempfile::tempdir().expect("tempdir");
        let real_bin = temp.path().join("real-bin");
        std::fs::write(&real_bin, b"#!/bin/sh\necho ok\n").expect("write real bin");
        let mut perms = std::fs::metadata(&real_bin)
            .expect("metadata")
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&real_bin, perms).expect("set perms");

        let link_path = temp.path().join("cargo");
        symlink(&real_bin, &link_path).expect("symlink");

        let resolved =
            resolve_executable_in_path("cargo", temp.path().as_os_str()).expect("resolve");

        assert_eq!(resolved, link_path.to_string_lossy());
        assert!(Path::new(&resolved).is_absolute());
    }

    #[cfg(all(target_os = "linux", unix))]
    #[tokio::test]
    async fn relative_executable_resolves_and_runs_from_requested_cwd() {
        let temp = tempfile::tempdir_in(default_cwd_for_tests()).expect("tempdir");
        let server_cwd = temp.path().join("server");
        let requested_cwd = temp.path().join("requested");
        std::fs::create_dir(&server_cwd).expect("create server cwd");
        std::fs::create_dir(&requested_cwd).expect("create requested cwd");

        let script_path = requested_cwd.join("hello");
        write_executable_script(
            &script_path,
            b"#!/bin/sh\nprintf 'hello from request cwd\\n'\n",
        );
        let requested_label = requested_cwd.to_string_lossy().into_owned();
        let resolved_path = requested_cwd.join("./hello").to_string_lossy().into_owned();
        let policy_module = format!(
            r#"package sandbox.main

default decision := {{"allow": false, "filesystem": null, "baffle_session": null}}

decision := {{"allow": true, "filesystem": null, "baffle_session": null}} if {{
  input.command == "./hello"
  input.path == {}
  input.cwd == {}
}}
"#,
            serde_json::to_string(&resolved_path).expect("resolved path string"),
            serde_json::to_string(&requested_label).expect("cwd string"),
        );
        let policy_engine = PolicyEngine::from_rego_for_tests(&[("main.rego", &policy_module)]);
        let input = || RunCommandInput {
            executable: "./hello".to_string(),
            args: vec![],
            cwd: Some(requested_label.clone()),
            env: None,
        };

        let decision = check_direct(&policy_engine, &server_cwd, input());
        assert!(decision.allowed, "{:?}", decision.reason);
        assert_eq!(
            decision.resolved_path.as_deref(),
            Some(resolved_path.as_str())
        );
        assert_eq!(decision.cwd.as_deref(), Some(requested_label.as_str()));

        let output = run_direct(&policy_engine, &server_cwd, input())
            .await
            .expect("relative executable should run from requested cwd");
        assert_eq!(output.exit_code, Some(0));
        assert_eq!(output.stdout, "hello from request cwd\n");
    }

    #[cfg(all(target_os = "linux", unix))]
    #[test]
    fn relative_executable_resolution_reports_missing_and_non_executable_files() {
        let temp = tempfile::tempdir_in(default_cwd_for_tests()).expect("tempdir");
        let requested_cwd = temp.path().join("requested");
        std::fs::create_dir(&requested_cwd).expect("create requested cwd");

        let missing_error = resolve_executable_path("./missing", &requested_cwd)
            .expect_err("missing relative executable should fail");
        let missing_path = requested_cwd.join("./missing").display().to_string();
        assert!(missing_error.contains(&missing_path));
        assert!(missing_error.contains("is not a file"));

        let non_executable = requested_cwd.join("not-executable");
        std::fs::write(&non_executable, b"#!/bin/sh\nexit 0\n").expect("write file");
        let non_executable_error = resolve_executable_path("./not-executable", &requested_cwd)
            .expect_err("non-executable relative file should fail");
        assert!(non_executable_error.contains("is not executable"));
        let non_executable_path = requested_cwd.join("./not-executable").display().to_string();
        assert!(non_executable_error.contains(&non_executable_path));
    }

    #[test]
    fn build_command_env_merges_user_and_enforces_critical_values() {
        let user_env = BTreeMap::from([
            ("CUSTOM_USER_ENV".to_string(), "allowed".to_string()),
            ("HOME".to_string(), "user-home".to_string()),
            ("LANG".to_string(), "user-lang".to_string()),
            ("PATH".to_string(), "user-path".to_string()),
            ("http_proxy".to_string(), "user-http".to_string()),
            ("https_proxy".to_string(), "user-https".to_string()),
            ("no_proxy".to_string(), "user-no".to_string()),
            ("HTTP_PROXY".to_string(), "user-http-upper".to_string()),
            ("HTTPS_PROXY".to_string(), "user-https-upper".to_string()),
            ("NO_PROXY".to_string(), "user-no-upper".to_string()),
        ]);

        let merged = build_command_env(&user_env);

        assert_eq!(
            merged.get("CUSTOM_USER_ENV").map(String::as_str),
            Some("allowed")
        );
        assert_eq!(merged.get("HOME").map(String::as_str), Some("user-home"));
        assert_eq!(merged.get("LANG").map(String::as_str), Some("user-lang"));

        assert_ne!(merged.get("PATH").map(String::as_str), Some("user-path"));
        if std::env::var_os("PATH").is_some() {
            assert!(merged.contains_key("PATH"));
        } else {
            assert!(!merged.contains_key("PATH"));
        }

        match std::env::var("http_proxy").ok() {
            Some(value) => {
                assert_eq!(merged.get("http_proxy"), Some(&value));
                assert_eq!(merged.get("HTTP_PROXY"), Some(&value));
            }
            None => {
                assert!(!merged.contains_key("http_proxy"));
                assert!(!merged.contains_key("HTTP_PROXY"));
            }
        }

        match std::env::var("https_proxy").ok() {
            Some(value) => {
                assert_eq!(merged.get("https_proxy"), Some(&value));
                assert_eq!(merged.get("HTTPS_PROXY"), Some(&value));
            }
            None => {
                assert!(!merged.contains_key("https_proxy"));
                assert!(!merged.contains_key("HTTPS_PROXY"));
            }
        }

        match std::env::var("no_proxy").ok() {
            Some(value) => {
                assert_eq!(merged.get("no_proxy"), Some(&value));
                assert_eq!(merged.get("NO_PROXY"), Some(&value));
            }
            None => {
                assert!(!merged.contains_key("no_proxy"));
                assert!(!merged.contains_key("NO_PROXY"));
            }
        }
    }

    #[test]
    fn compute_executable_sha256_hex_uses_lowercase_hex() {
        let temp = tempfile::tempdir().expect("tempdir");
        let file_path = temp.path().join("sample.bin");
        std::fs::write(&file_path, b"abc").expect("write file");

        let hash = compute_executable_sha256_hex(file_path.to_string_lossy().as_ref())
            .expect("hash should succeed");
        assert_eq!(
            hash,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[tokio::test]
    async fn check_allows_command_with_resolved_path_and_hash() {
        let temp = tempfile::tempdir().expect("tempdir");
        let script_path = temp.path().join("allowed-check.sh");
        write_executable_script(&script_path, b"#!/bin/sh\necho allowed\n");

        let script = script_path.to_string_lossy().into_owned();
        let expected_hash = compute_executable_sha256_hex(script_path.to_string_lossy().as_ref())
            .expect("hash should succeed");
        let expected_path = script_path.to_string_lossy().into_owned();
        let policy_engine = rego_engine_allow_commands(&[&script]);
        let decision = check_direct(
            &policy_engine,
            default_cwd_for_tests().as_path(),
            RunCommandInput {
                executable: script.clone(),
                args: vec![],
                cwd: None,
                env: None,
            },
        );

        assert!(decision.allowed);
        assert_eq!(decision.reason, None);
        assert_eq!(decision.executable, script);
        assert_eq!(
            decision.resolved_path.as_deref(),
            Some(expected_path.as_str())
        );
        assert_eq!(decision.hash.as_deref(), Some(expected_hash.as_str()));
        assert_eq!(decision.policy_mode, "rego");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn check_allows_and_denies_based_on_explicit_trusted_cwd() {
        let temp = tempfile::tempdir_in(default_cwd_for_tests()).expect("tempdir");
        let allowed_cwd = temp.path().join("allowed");
        let denied_cwd = temp.path().join("denied");
        std::fs::create_dir(&allowed_cwd).expect("create allowed cwd");
        std::fs::create_dir(&denied_cwd).expect("create denied cwd");
        let script_path = temp.path().join("cwd-policy.sh");
        write_executable_script(&script_path, b"#!/bin/sh\necho ok\n");

        let script = script_path.to_string_lossy().into_owned();
        let allowed_label = allowed_cwd.to_string_lossy().into_owned();
        let denied_label = denied_cwd.to_string_lossy().into_owned();
        let policy_engine = rego_engine_allow_command_in_cwd(&script, &allowed_label);

        let allowed = check_direct(
            &policy_engine,
            default_cwd_for_tests().as_path(),
            RunCommandInput {
                executable: script.clone(),
                args: vec![],
                cwd: Some(allowed_label.clone()),
                env: None,
            },
        );
        assert!(allowed.allowed);
        assert_eq!(allowed.cwd.as_deref(), Some(allowed_label.as_str()));

        let denied = check_direct(
            &policy_engine,
            default_cwd_for_tests().as_path(),
            RunCommandInput {
                executable: script,
                args: vec![],
                cwd: Some(denied_label.clone()),
                env: None,
            },
        );
        assert!(!denied.allowed);
        assert_eq!(denied.cwd.as_deref(), Some(denied_label.as_str()));
        assert!(
            denied
                .reason
                .as_deref()
                .expect("reason")
                .contains("Command not allowed")
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn check_exposes_only_trusted_cwd_to_rego() {
        let temp = tempfile::tempdir_in(default_cwd_for_tests()).expect("tempdir");
        let cwd = temp.path().join("work");
        std::fs::create_dir(&cwd).expect("create cwd");
        let script_path = temp.path().join("raw-cwd-field.sh");
        write_executable_script(&script_path, b"#!/bin/sh\necho ok\n");

        let script = script_path.to_string_lossy().into_owned();
        let cwd_with_redundant_slashes = format!("{}/", cwd.to_string_lossy());
        let cwd_label = cwd.to_string_lossy().into_owned();
        let module = format!(
            "package sandbox.main\n\ndefault decision := {{\"allow\": false, \"filesystem\": null, \"baffle_session\": null}}\n\nexpected_keys := {{\"args\", \"command\", \"cwd\", \"env\", \"hash\", \"path\"}}\n\ndecision := {{\"allow\": true, \"filesystem\": null, \"baffle_session\": null}} if {{\n  input.command == {}\n  input.cwd == {}\n  object.keys(input) == expected_keys\n}}\n",
            serde_json::to_string(&script).expect("script string"),
            serde_json::to_string(&cwd_label).expect("cwd string"),
        );
        let policy_engine = PolicyEngine::from_rego_for_tests(&[("main.rego", &module)]);

        let decision = check_direct(
            &policy_engine,
            default_cwd_for_tests().as_path(),
            RunCommandInput {
                executable: script,
                args: vec![],
                cwd: Some(cwd_with_redundant_slashes),
                env: None,
            },
        );

        assert!(decision.allowed);
        assert_eq!(decision.cwd.as_deref(), Some(cwd_label.as_str()));
    }

    #[tokio::test]
    async fn check_uses_default_cwd_as_trusted_policy_input() {
        let temp = tempfile::tempdir_in(default_cwd_for_tests()).expect("tempdir");
        let cwd = temp.path().join("work");
        std::fs::create_dir(&cwd).expect("create cwd");
        let script_path = temp.path().join("cwd-check.sh");
        write_executable_script(&script_path, b"#!/bin/sh\necho allowed\n");

        let script = script_path.to_string_lossy().into_owned();
        let cwd_label = cwd.to_string_lossy().into_owned();
        let module = format!(
            "package sandbox.main\n\ndefault decision := {{\"allow\": false, \"filesystem\": null, \"baffle_session\": null}}\n\ndecision := {{\"allow\": true, \"filesystem\": null, \"baffle_session\": null}} if {{\n  input.command == {}\n  input.cwd == {}\n}}\n",
            serde_json::to_string(&script).expect("script string"),
            serde_json::to_string(&cwd_label).expect("cwd string"),
        );
        let policy_engine = PolicyEngine::from_rego_for_tests(&[("main.rego", &module)]);

        let decision = check_direct(
            &policy_engine,
            &cwd,
            RunCommandInput {
                executable: script,
                args: vec![],
                cwd: None,
                env: None,
            },
        );

        assert!(decision.allowed);
        assert_eq!(decision.cwd.as_deref(), Some(cwd_label.as_str()));
    }

    #[tokio::test]
    async fn check_reports_cwd_resolution_failure() {
        let temp = tempfile::tempdir_in(default_cwd_for_tests()).expect("tempdir");
        let missing_cwd = temp.path().join("missing");
        let policy_engine = rego_engine_allow_commands(&["/bin/does-not-matter"]);

        let decision = check_direct(
            &policy_engine,
            default_cwd_for_tests().as_path(),
            RunCommandInput {
                executable: "definitely-not-a-real-command-for-gantry".to_string(),
                args: vec![],
                cwd: Some(missing_cwd.to_string_lossy().into_owned()),
                env: None,
            },
        );

        assert!(!decision.allowed);
        assert!(decision.cwd.is_none());
        assert!(
            decision
                .reason
                .as_deref()
                .expect("reason")
                .contains("path does not exist")
        );
        assert!(decision.resolved_path.is_none());
        assert!(decision.hash.is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn check_reports_file_cwd_resolution_failure_before_executable_resolution() {
        let temp = tempfile::tempdir_in(default_cwd_for_tests()).expect("tempdir");
        let file_cwd = temp.path().join("not-a-directory");
        std::fs::write(&file_cwd, b"file").expect("write cwd file");
        let policy_engine = rego_engine_allow_commands(&["/bin/does-not-matter"]);

        let decision = check_direct(
            &policy_engine,
            default_cwd_for_tests().as_path(),
            RunCommandInput {
                executable: "definitely-not-a-real-command-for-gantry".to_string(),
                args: vec![],
                cwd: Some(file_cwd.to_string_lossy().into_owned()),
                env: None,
            },
        );

        assert!(!decision.allowed);
        assert!(decision.cwd.is_none());
        assert!(
            decision
                .reason
                .as_deref()
                .expect("reason")
                .contains("path is not a directory")
        );
        assert!(decision.resolved_path.is_none());
        assert!(decision.hash.is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn check_normalizes_root_repeated_and_trailing_slashes() {
        let true_path = match find_executable("true") {
            Some(path) => path,
            None => return,
        };
        let root_policy = rego_engine_allow_command_in_cwd(&true_path, "/");
        let root_decision = check_direct(
            &root_policy,
            default_cwd_for_tests().as_path(),
            RunCommandInput {
                executable: true_path.clone(),
                args: vec![],
                cwd: Some("/".to_string()),
                env: None,
            },
        );
        assert!(root_decision.allowed);
        assert_eq!(root_decision.cwd.as_deref(), Some("/"));

        let temp = tempfile::tempdir_in(default_cwd_for_tests()).expect("tempdir");
        let parent = temp.path().join("parent");
        let child = parent.join("child");
        std::fs::create_dir(&parent).expect("create parent");
        std::fs::create_dir(&child).expect("create child");
        let child_label = child.to_string_lossy().into_owned();
        let child_policy = rego_engine_allow_command_in_cwd(&true_path, &child_label);

        let repeated = format!("{}//child", parent.to_string_lossy());
        let repeated_decision = check_direct(
            &child_policy,
            default_cwd_for_tests().as_path(),
            RunCommandInput {
                executable: true_path.clone(),
                args: vec![],
                cwd: Some(repeated),
                env: None,
            },
        );
        assert!(repeated_decision.allowed);
        assert_eq!(repeated_decision.cwd.as_deref(), Some(child_label.as_str()));

        let trailing_decision = check_direct(
            &child_policy,
            default_cwd_for_tests().as_path(),
            RunCommandInput {
                executable: true_path,
                args: vec![],
                cwd: Some(format!("{child_label}/")),
                env: None,
            },
        );
        assert!(trailing_decision.allowed);
        assert_eq!(trailing_decision.cwd.as_deref(), Some(child_label.as_str()));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn check_rejects_malformed_relative_and_symlink_cwds() {
        let true_path = match find_executable("true") {
            Some(path) => path,
            None => return,
        };
        let policy_engine = rego_engine_allow_commands(&[&true_path]);

        for cwd in ["//foo", "relative-inside-default"] {
            let decision = check_direct(
                &policy_engine,
                default_cwd_for_tests().as_path(),
                RunCommandInput {
                    executable: true_path.clone(),
                    args: vec![],
                    cwd: Some(cwd.to_string()),
                    env: None,
                },
            );

            assert!(!decision.allowed, "cwd {cwd:?} should reject");
            assert!(decision.cwd.is_none(), "cwd {cwd:?} should not resolve");
            assert!(decision.resolved_path.is_none());
            assert!(decision.hash.is_none());
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;

            let temp = tempfile::tempdir_in(default_cwd_for_tests()).expect("tempdir");
            let real = temp.path().join("real");
            let link = temp.path().join("link");
            std::fs::create_dir(&real).expect("create real cwd");
            symlink(&real, &link).expect("create cwd symlink");

            let decision = check_direct(
                &policy_engine,
                default_cwd_for_tests().as_path(),
                RunCommandInput {
                    executable: true_path,
                    args: vec![],
                    cwd: Some(link.to_string_lossy().into_owned()),
                    env: None,
                },
            );

            assert!(!decision.allowed);
            assert!(decision.cwd.is_none());
            assert!(
                decision
                    .reason
                    .as_deref()
                    .expect("reason")
                    .contains("symlink")
            );
            assert!(decision.resolved_path.is_none());
            assert!(decision.hash.is_none());
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn check_rejects_proc_fd_magic_link_cwd() {
        use std::os::fd::AsRawFd;

        let true_path = match find_executable("true") {
            Some(path) => path,
            None => return,
        };
        let proc_fd = Path::new("/proc")
            .join(std::process::id().to_string())
            .join("fd");
        if !proc_fd.exists() {
            return;
        }

        let temp = tempfile::tempdir_in(default_cwd_for_tests()).expect("tempdir");
        let cwd = std::fs::File::open(temp.path()).expect("open tempdir");
        let magic_link_cwd = proc_fd.join(cwd.as_raw_fd().to_string());
        let policy_engine = rego_engine_allow_commands(&[&true_path]);

        let decision = check_direct(
            &policy_engine,
            default_cwd_for_tests().as_path(),
            RunCommandInput {
                executable: true_path,
                args: vec![],
                cwd: Some(magic_link_cwd.to_string_lossy().into_owned()),
                env: None,
            },
        );

        assert!(!decision.allowed);
        assert!(decision.cwd.is_none());
        assert!(
            decision
                .reason
                .as_deref()
                .expect("reason")
                .contains("symlink or magic link")
        );
        assert!(decision.resolved_path.is_none());
        assert!(decision.hash.is_none());
    }

    #[cfg(all(target_os = "linux", unix))]
    #[tokio::test]
    async fn spawn_runs_in_authorized_cwd_not_process_default_cwd() {
        let sh_path = match find_executable("sh") {
            Some(path) => path,
            None => return,
        };
        let temp = tempfile::tempdir_in(default_cwd_for_tests()).expect("tempdir");
        let default_cwd = temp.path().join("default");
        let requested_cwd = temp.path().join("requested");
        std::fs::create_dir(&default_cwd).expect("create default cwd");
        std::fs::create_dir(&requested_cwd).expect("create requested cwd");

        let requested_label = requested_cwd.to_string_lossy().into_owned();
        let policy_engine = rego_engine_allow_command_in_cwd(&sh_path, &requested_label);
        let output = run_direct(
            &policy_engine,
            &default_cwd,
            RunCommandInput {
                executable: sh_path,
                args: vec!["-c".to_string(), "pwd".to_string()],
                cwd: Some(requested_label.clone()),
                env: None,
            },
        )
        .await
        .expect("shell should run");

        assert_eq!(output.exit_code, Some(0));
        assert_eq!(output.stdout.trim_end(), requested_label);
    }

    #[tokio::test]
    async fn executes_allowed_command_successfully() {
        let env_path = match find_executable("env") {
            Some(path) => path,
            None => return,
        };

        let policy_engine = rego_engine_allow_commands(&[&env_path]);
        let output = run_direct(
            &policy_engine,
            default_cwd_for_tests().as_path(),
            RunCommandInput {
                executable: env_path,
                args: vec!["printf".to_string(), "ok".to_string()],
                cwd: None,
                env: None,
            },
        )
        .await
        .expect("command should run");

        assert_eq!(output.exit_code, Some(0));
        assert_eq!(output.stdout, "ok");
        assert_eq!(output.stderr, "");
    }

    #[tokio::test]
    async fn command_runs_with_sanitized_environment() {
        let env_path = match find_executable("env") {
            Some(path) => path,
            None => return,
        };

        let policy_engine = rego_engine_allow_commands(&[&env_path]);
        let output = run_direct(
            &policy_engine,
            default_cwd_for_tests().as_path(),
            RunCommandInput {
                executable: env_path,
                args: vec![],
                cwd: None,
                env: Some(BTreeMap::from([
                    ("CUSTOM_USER_ENV".to_string(), "allowed".to_string()),
                    ("HOME".to_string(), "user-home".to_string()),
                    ("LANG".to_string(), "user-lang".to_string()),
                    ("PATH".to_string(), "user-path".to_string()),
                    ("http_proxy".to_string(), "user-http".to_string()),
                    ("https_proxy".to_string(), "user-https".to_string()),
                    ("no_proxy".to_string(), "user-no".to_string()),
                    ("HTTP_PROXY".to_string(), "user-http-upper".to_string()),
                    ("HTTPS_PROXY".to_string(), "user-https-upper".to_string()),
                    ("NO_PROXY".to_string(), "user-no-upper".to_string()),
                ])),
            },
        )
        .await
        .expect("env should run");

        let command_env = parse_env_output(&output.stdout);

        assert_eq!(
            command_env.get("CUSTOM_USER_ENV").map(String::as_str),
            Some("allowed")
        );
        assert_eq!(
            command_env.get("HOME").map(String::as_str),
            Some("user-home")
        );
        assert_eq!(
            command_env.get("LANG").map(String::as_str),
            Some("user-lang")
        );
        assert!(!command_env.contains_key("PWD"));

        match std::env::var("PATH") {
            Ok(path) => assert_eq!(command_env.get("PATH"), Some(&path)),
            Err(_) => assert!(!command_env.contains_key("PATH")),
        }

        match std::env::var("http_proxy").ok() {
            Some(value) => {
                assert_eq!(command_env.get("http_proxy"), Some(&value));
                assert_eq!(command_env.get("HTTP_PROXY"), Some(&value));
            }
            None => {
                assert!(!command_env.contains_key("http_proxy"));
                assert!(!command_env.contains_key("HTTP_PROXY"));
            }
        }

        match std::env::var("https_proxy").ok() {
            Some(value) => {
                assert_eq!(command_env.get("https_proxy"), Some(&value));
                assert_eq!(command_env.get("HTTPS_PROXY"), Some(&value));
            }
            None => {
                assert!(!command_env.contains_key("https_proxy"));
                assert!(!command_env.contains_key("HTTPS_PROXY"));
            }
        }

        match std::env::var("no_proxy").ok() {
            Some(value) => {
                assert_eq!(command_env.get("no_proxy"), Some(&value));
                assert_eq!(command_env.get("NO_PROXY"), Some(&value));
            }
            None => {
                assert!(!command_env.contains_key("no_proxy"));
                assert!(!command_env.contains_key("NO_PROXY"));
            }
        }
    }

    #[tokio::test]
    async fn blocks_disallowed_command_execution() {
        let executable = std::env::current_exe()
            .expect("current test executable")
            .to_string_lossy()
            .into_owned();
        let policy_engine = rego_engine_allow_commands(&["/bin/does-not-match-this-path"]);
        let error = run_direct(
            &policy_engine,
            default_cwd_for_tests().as_path(),
            RunCommandInput {
                executable,
                args: vec!["blocked".to_string()],
                cwd: None,
                env: None,
            },
        )
        .await
        .expect_err("disallowed command should fail");

        assert!(error.to_string().contains("Command not allowed"));
    }

    #[tokio::test]
    async fn truncates_stdout_at_one_mb() {
        let head_path = match find_executable("head") {
            Some(path) => path,
            None => return,
        };

        let policy_engine = rego_engine_allow_commands(&[&head_path]);
        let output = run_direct(
            &policy_engine,
            default_cwd_for_tests().as_path(),
            RunCommandInput {
                executable: head_path,
                args: vec![
                    "-c".to_string(),
                    (MAX_OUTPUT_BYTES + 5).to_string(),
                    "/dev/zero".to_string(),
                ],
                cwd: None,
                env: None,
            },
        )
        .await
        .expect("head should run");

        assert_eq!(output.exit_code, Some(0));
        assert!(output.stdout.ends_with(TRUNCATION_MARKER));
    }

    #[tokio::test]
    async fn check_denied_by_policy_returns_data_without_spawning() {
        let temp = tempfile::tempdir().expect("tempdir");
        let side_effect_file = temp.path().join("side-effect.txt");
        let script_path = temp.path().join("side-effect.sh");
        write_executable_script(
            &script_path,
            format!(
                "#!/bin/sh\nprintf spawned > {}\n",
                side_effect_file.display()
            )
            .as_bytes(),
        );

        let script = script_path.to_string_lossy().into_owned();
        let policy_engine = rego_engine_allow_commands(&["/bin/does-not-match-this-path"]);
        let decision = check_direct(
            &policy_engine,
            default_cwd_for_tests().as_path(),
            RunCommandInput {
                executable: script,
                args: vec![],
                cwd: None,
                env: None,
            },
        );

        assert!(!decision.allowed);
        assert!(
            decision
                .reason
                .as_deref()
                .expect("reason")
                .contains("Command not allowed")
        );
        assert!(!side_effect_file.exists());
    }

    #[tokio::test]
    async fn check_reports_deny_all_mode() {
        let temp = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            temp.path().join("bad.rego"),
            "package sandbox.main\nallow if",
        )
        .expect("write bad rego");
        let policy_engine = PolicyEngine::from_sources(Some(temp.path().to_path_buf()));

        let env_path = match find_executable("env") {
            Some(path) => path,
            None => return,
        };

        let decision = check_direct(
            &policy_engine,
            default_cwd_for_tests().as_path(),
            RunCommandInput {
                executable: env_path,
                args: vec![],
                cwd: None,
                env: None,
            },
        );

        assert!(!decision.allowed);
        assert!(
            decision
                .reason
                .as_deref()
                .expect("reason")
                .contains("Policy deny-all is active")
        );
        assert_eq!(decision.policy_mode, "deny-all");
    }

    #[tokio::test]
    async fn check_reports_missing_executable() {
        let policy_engine = rego_engine_allow_commands(&["/bin/does-not-matter"]);
        let decision = check_direct(
            &policy_engine,
            default_cwd_for_tests().as_path(),
            RunCommandInput {
                executable: "definitely-not-a-real-command-for-gantry".to_string(),
                args: vec![],
                cwd: None,
                env: None,
            },
        );

        assert!(!decision.allowed);
        assert!(
            decision
                .reason
                .as_deref()
                .expect("reason")
                .contains("was not found on PATH")
        );
        assert!(decision.resolved_path.is_none());
        assert!(decision.hash.is_none());
    }
}
