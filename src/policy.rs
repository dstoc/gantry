use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use regorus::Engine as RegoEngine;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::filesystem::{
    FilesystemProfile, load_profiles_from_sources, profile_files, validate_baffle_filename,
    validate_profile_name,
};

const REGO_DECISION_QUERY: &str = "data.sandbox.main.decision";
static NEXT_GENERATION_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Error, Clone)]
pub enum ValidationError {
    #[error("Policy deny-all is active: {details}")]
    PolicyUnavailable { details: String },
    #[error("Policy evaluation failed for '{command}': {details}")]
    PolicyEvaluationFailed { command: String, details: String },
    #[error("Invalid authorization decision for '{command}': {details}")]
    InvalidDecision { command: String, details: String },
    #[error("Decision is incompatible with backend '{backend}': {details}")]
    IncompatibleBackend { backend: String, details: String },
    #[error("Command not allowed: {0}")]
    CommandNotAllowed(String),
    #[error("Failed to resolve executable path for '{command}': {details}")]
    PathResolutionFailed { command: String, details: String },
    #[error("Failed to compute executable hash for '{command}': {details}")]
    HashResolutionFailed { command: String, details: String },
    #[error("Failed to resolve cwd '{cwd}': {details}")]
    CwdResolutionFailed { cwd: String, details: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyMode {
    Rego,
    DenyAll,
}

#[derive(Debug, Clone)]
struct RegoPolicy {
    engine: RegoEngine,
    module_count: usize,
}

impl RegoPolicy {
    fn evaluate(&self, input: &PolicyEvaluationInput) -> Result<serde_json::Value, String> {
        let mut engine = self.engine.clone();
        let input_value = serde_json::json!({
            "command": input.command,
            "path": input.path,
            "hash": input.hash,
            "args": input.args,
            "env": input.env,
            "cwd": input.cwd,
        });
        engine.set_input(regorus::Value::from(input_value));
        let results = engine
            .eval_query(REGO_DECISION_QUERY.to_string(), false)
            .map_err(|error| error.to_string())?;
        if results.result.len() != 1 {
            return Err(format!(
                "decision query returned {} results; expected exactly one",
                results.result.len()
            ));
        }
        let result = &results.result[0];
        if result.expressions.len() != 1 {
            return Err(format!(
                "decision query returned {} values; expected exactly one",
                result.expressions.len()
            ));
        }
        serde_json::to_value(&result.expressions[0].value).map_err(|error| error.to_string())
    }
}

#[derive(Debug)]
pub(crate) struct PolicyGeneration {
    id: u64,
    mode: PolicyMode,
    rego: Option<RegoPolicy>,
    filesystem_profiles: BTreeMap<String, Arc<FilesystemProfile>>,
    deny_reason: Option<String>,
    fingerprint: Option<PolicyFingerprint>,
}

impl PolicyGeneration {
    fn deny_all(details: impl Into<String>) -> Self {
        Self {
            id: NEXT_GENERATION_ID.fetch_add(1, Ordering::Relaxed),
            mode: PolicyMode::DenyAll,
            rego: None,
            filesystem_profiles: BTreeMap::new(),
            deny_reason: Some(details.into()),
            fingerprint: None,
        }
    }

    fn from_rego(
        policy: RegoPolicy,
        filesystem_profiles: BTreeMap<String, Arc<FilesystemProfile>>,
        fingerprint: Option<PolicyFingerprint>,
    ) -> Self {
        Self {
            id: NEXT_GENERATION_ID.fetch_add(1, Ordering::Relaxed),
            mode: PolicyMode::Rego,
            rego: Some(policy),
            filesystem_profiles,
            deny_reason: None,
            fingerprint,
        }
    }

    pub(crate) fn id(&self) -> u64 {
        self.id
    }
}

#[derive(Debug, Clone)]
struct PolicySources {
    policy_dir: Option<PathBuf>,
    filesystem_dir: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PolicyFingerprint {
    files: Vec<PolicyFileFingerprint>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PolicyFileFingerprint {
    path: PathBuf,
    digest: [u8; 32],
}

#[derive(Debug)]
pub struct PolicyEngine {
    state: RwLock<Arc<PolicyGeneration>>,
    reload_lock: Mutex<()>,
    sources: PolicySources,
}

#[derive(Debug)]
struct CapturedPolicyFile {
    path: PathBuf,
    contents: Vec<u8>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct PolicyDecision {
    pub(crate) allow: bool,
    pub(crate) filesystem: Option<String>,
    pub(crate) baffle_session: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct PolicyAuthorization {
    pub(crate) decision: PolicyDecision,
    pub(crate) filesystem_profile: Option<Arc<FilesystemProfile>>,
    pub(crate) generation: Arc<PolicyGeneration>,
    pub(crate) validation_error: Option<ValidationError>,
}

#[derive(Debug)]
struct PolicyEvaluationInput<'a> {
    command: &'a str,
    path: &'a str,
    hash: &'a str,
    args: &'a [String],
    env: &'a BTreeMap<String, String>,
    cwd: &'a str,
}

impl PolicyEngine {
    pub fn from_sources(policy_dir: Option<PathBuf>) -> Self {
        let filesystem_dir = policy_dir
            .as_ref()
            .map(|directory| directory.parent().unwrap_or(directory).join("filesystems"));
        let sources = PolicySources {
            policy_dir,
            filesystem_dir,
        };

        let snapshot = match load_policy_snapshot(&sources) {
            Ok(snapshot) => {
                if let Some(rego) = &snapshot.rego {
                    tracing::info!(
                        mode = "rego",
                        query = REGO_DECISION_QUERY,
                        modules = rego.module_count,
                        "policy engine initialized",
                    );
                }
                snapshot
            }
            Err(error) => {
                tracing::warn!(error = %error, "policy engine initialized in deny-all mode");
                Arc::new(PolicyGeneration::deny_all(error))
            }
        };

        Self {
            state: RwLock::new(snapshot),
            reload_lock: Mutex::new(()),
            sources,
        }
    }

    #[cfg(test)]
    pub fn from_rego_for_tests(modules: &[(&str, &str)]) -> Self {
        let rego = load_rego_modules(modules).expect("failed to load Rego test modules");
        Self {
            state: RwLock::new(Arc::new(PolicyGeneration::from_rego(
                rego,
                BTreeMap::new(),
                None,
            ))),
            reload_lock: Mutex::new(()),
            sources: PolicySources {
                policy_dir: None,
                filesystem_dir: None,
            },
        }
    }

    pub fn mode(&self) -> PolicyMode {
        self.state
            .read()
            .expect("policy state read lock poisoned")
            .mode
            .clone()
    }

    pub(crate) fn authorize_invocation(
        &self,
        command: &str,
        path: &str,
        hash: &str,
        args: &[String],
        env: &BTreeMap<String, String>,
        cwd: &str,
    ) -> Result<PolicyAuthorization, ValidationError> {
        self.reload_if_changed();

        let generation = self
            .state
            .read()
            .expect("policy state read lock poisoned")
            .clone();
        let evaluation_input = PolicyEvaluationInput {
            command,
            path,
            hash,
            args,
            env,
            cwd,
        };

        let policy_decision =
            match &generation.mode {
                PolicyMode::Rego => {
                    let rego = generation.rego.as_ref().ok_or_else(|| {
                        ValidationError::PolicyUnavailable {
                            details: "internal policy state mismatch".to_string(),
                        }
                    })?;
                    let value = rego.evaluate(&evaluation_input).map_err(|details| {
                        ValidationError::PolicyEvaluationFailed {
                            command: command.to_string(),
                            details,
                        }
                    })?;
                    parse_decision(command, value)?
                }
                PolicyMode::DenyAll => {
                    return Err(ValidationError::PolicyUnavailable {
                        details: generation.deny_reason.clone().unwrap_or_else(|| {
                            "policy state is invalid and command execution is denied".to_string()
                        }),
                    });
                }
            };

        let (filesystem_profile, validation_error) = if policy_decision.allow {
            if let Some(name) = &policy_decision.filesystem {
                match generation.filesystem_profiles.get(name).cloned() {
                    Some(profile) => (Some(profile), None),
                    None => (
                        None,
                        Some(ValidationError::InvalidDecision {
                            command: command.to_string(),
                            details: format!("filesystem profile '{name}' is not configured"),
                        }),
                    ),
                }
            } else {
                (None, None)
            }
        } else {
            (None, None)
        };

        Ok(PolicyAuthorization {
            decision: policy_decision,
            filesystem_profile,
            generation,
            validation_error,
        })
    }

    pub fn validate_invocation(
        &self,
        command: &str,
        path: &str,
        hash: &str,
        args: &[String],
        env: &BTreeMap<String, String>,
        cwd: &str,
    ) -> Result<(), ValidationError> {
        let authorization = self.authorize_invocation(command, path, hash, args, env, cwd)?;
        if let Some(error) = authorization.validation_error {
            Err(error)
        } else if authorization.decision.allow {
            Ok(())
        } else {
            Err(ValidationError::CommandNotAllowed(command.to_string()))
        }
    }

    pub fn reload(&self) {
        let _reload = self
            .reload_lock
            .lock()
            .expect("policy reload lock poisoned");
        self.reload_locked();
    }

    fn reload_locked(&self) {
        match load_policy_snapshot(&self.sources) {
            Ok(snapshot) => {
                if let Some(rego) = &snapshot.rego {
                    tracing::info!(
                        mode = "rego",
                        query = REGO_DECISION_QUERY,
                        modules = rego.module_count,
                        "policy reload succeeded",
                    );
                }
                *self
                    .state
                    .write()
                    .expect("policy state write lock poisoned") = snapshot;
            }
            Err(error) => {
                tracing::error!(error = %error, "policy reload failed; deny-all activated");
                *self
                    .state
                    .write()
                    .expect("policy state write lock poisoned") =
                    Arc::new(PolicyGeneration::deny_all(error.to_string()));
            }
        }
    }

    fn reload_if_changed(&self) {
        if self.sources.policy_dir.is_none() {
            return;
        }

        let current = fingerprint_sources(&self.sources);
        let previous = self.current_fingerprint();
        if current
            .as_ref()
            .is_ok_and(|current| previous.as_ref() == Some(current))
        {
            return;
        }

        let _reload = self
            .reload_lock
            .lock()
            .expect("policy reload lock poisoned");
        let current = fingerprint_sources(&self.sources);
        let previous = self.current_fingerprint();
        match current {
            Ok(current) if previous.as_ref() == Some(&current) => {}
            Ok(_) => self.reload_locked(),
            Err(error) => {
                tracing::error!(error = %error, "policy fingerprint failed; deny-all activated");
                *self
                    .state
                    .write()
                    .expect("policy state write lock poisoned") =
                    Arc::new(PolicyGeneration::deny_all(error));
            }
        }
    }

    fn current_fingerprint(&self) -> Option<PolicyFingerprint> {
        self.state
            .read()
            .expect("policy state read lock poisoned")
            .fingerprint
            .clone()
    }
}

fn load_policy_snapshot(sources: &PolicySources) -> Result<Arc<PolicyGeneration>, String> {
    let captured = capture_policy_files(sources)?;
    let fingerprint = fingerprint_captured_files(&captured);

    let rego_files: Vec<_> = captured
        .iter()
        .filter(|file| file.path.extension().and_then(|ext| ext.to_str()) == Some("rego"))
        .collect();
    let rego = load_rego_files(&rego_files)
        .map_err(|error| format!("rego policy load failed: {error}"))?;

    let profile_files: Vec<_> = captured
        .iter()
        .filter(|file| file.path.extension().and_then(|ext| ext.to_str()) == Some("toml"))
        .map(|file| (file.path.clone(), file.contents.clone()))
        .collect();
    let filesystem_profiles = load_profiles_from_sources(&profile_files)
        .map_err(|error| format!("filesystem profile load failed: {error}"))?
        .into_iter()
        .map(|(name, profile)| (name, Arc::new(profile)))
        .collect();

    // The compiler and profile parser consume one captured byte set. A second capture
    // prevents publishing it if any source was added, removed, or changed during loading.
    let current = capture_policy_files(sources)?;
    if fingerprint_captured_files(&current) != fingerprint {
        return Err("policy sources changed while loading; deny-all activated".to_string());
    }

    Ok(Arc::new(PolicyGeneration::from_rego(
        rego,
        filesystem_profiles,
        Some(fingerprint),
    )))
}

#[cfg(test)]
fn load_rego_modules(modules: &[(&str, &str)]) -> Result<RegoPolicy, String> {
    let mut engine = RegoEngine::new();
    for (name, source) in modules {
        engine
            .add_policy((*name).to_string(), (*source).to_string())
            .map_err(|error| format!("failed compiling '{name}': {error}"))?;
    }

    Ok(RegoPolicy {
        engine,
        module_count: modules.len(),
    })
}

fn load_rego_files(files: &[&CapturedPolicyFile]) -> Result<RegoPolicy, String> {
    if files.is_empty() {
        return Err("no .rego files found under policy directory".to_string());
    }

    let mut engine = RegoEngine::new();
    for file in files {
        let source = std::str::from_utf8(&file.contents)
            .map_err(|error| format!("failed decoding '{}': {error}", file.path.display()))?;

        engine
            .add_policy(file.path.to_string_lossy().into_owned(), source.to_string())
            .map_err(|error| format!("failed compiling '{}': {error}", file.path.display()))?;
    }

    Ok(RegoPolicy {
        engine,
        module_count: files.len(),
    })
}

fn capture_policy_files(sources: &PolicySources) -> Result<Vec<CapturedPolicyFile>, String> {
    let policy_dir = sources
        .policy_dir
        .as_ref()
        .ok_or_else(|| "GANTRY_POLICY_DIR is not configured".to_string())?;
    let mut files = Vec::new();
    collect_rego_files(policy_dir, &mut files).map_err(|error| {
        format!(
            "failed reading policy directory '{}': {error}",
            policy_dir.display()
        )
    })?;

    if files.is_empty() {
        return Err(format!(
            "no .rego files found under policy directory '{}'",
            policy_dir.display()
        ));
    }

    if let Some(directory) = &sources.filesystem_dir {
        files
            .extend(profile_files(directory).map_err(|error| {
                format!("failed reading filesystem profile directory: {error}")
            })?);
    }
    files.sort();

    files
        .into_iter()
        .map(|path| {
            let contents = std::fs::read(&path)
                .map_err(|error| format!("failed reading '{}': {error}", path.display()))?;
            Ok(CapturedPolicyFile { path, contents })
        })
        .collect()
}

fn collect_rego_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), std::io::Error> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();

        if path.is_dir() {
            collect_rego_files(&path, out)?;
            continue;
        }

        if path.extension().and_then(|ext| ext.to_str()) == Some("rego") {
            out.push(path);
        }
    }

    Ok(())
}

fn fingerprint_sources(sources: &PolicySources) -> Result<PolicyFingerprint, String> {
    Ok(fingerprint_captured_files(&capture_policy_files(sources)?))
}

fn fingerprint_captured_files(files: &[CapturedPolicyFile]) -> PolicyFingerprint {
    let fingerprints = files
        .iter()
        .map(|file| PolicyFileFingerprint {
            path: file.path.clone(),
            digest: Sha256::digest(&file.contents).into(),
        })
        .collect();
    PolicyFingerprint {
        files: fingerprints,
    }
}

fn parse_decision(
    command: &str,
    value: serde_json::Value,
) -> Result<PolicyDecision, ValidationError> {
    let invalid = |details: String| ValidationError::InvalidDecision {
        command: command.to_string(),
        details,
    };
    let object = value
        .as_object()
        .ok_or_else(|| invalid("decision must be an object".to_string()))?;
    let allow = object
        .get("allow")
        .and_then(serde_json::Value::as_bool)
        .ok_or_else(|| invalid("decision must contain a boolean 'allow' field".to_string()))?;
    if !allow {
        return Ok(PolicyDecision {
            allow: false,
            filesystem: None,
            baffle_session: None,
        });
    }
    for field in ["filesystem", "baffle_session"] {
        if !object.contains_key(field) {
            return Err(invalid(format!(
                "allowed decision is missing required '{field}' field"
            )));
        }
    }
    if let Some(field) = object
        .keys()
        .find(|key| !["allow", "filesystem", "baffle_session"].contains(&key.as_str()))
    {
        return Err(invalid(format!("unknown decision field '{field}'")));
    }
    for field in ["filesystem", "baffle_session"] {
        let value = object.get(field).expect("required field checked above");
        if !value.is_null() && !value.is_string() {
            return Err(invalid(format!("'{field}' must be a string or null")));
        }
    }
    let decision: PolicyDecision = serde_json::from_value(value).map_err(|error| {
        invalid(format!(
            "decision fields have invalid types or names: {error}"
        ))
    })?;
    if let Some(name) = &decision.filesystem {
        validate_profile_name(name).map_err(invalid)?;
    }
    if let Some(name) = &decision.baffle_session {
        validate_baffle_filename(name).map_err(invalid)?;
    }
    Ok(decision)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use tempfile::tempdir;

    fn write_rego_bundle(dir: &Path, command: &str) {
        std::fs::write(
            dir.join("main.rego"),
            r#"package sandbox.main

default decision := {"allow": false, "filesystem": null, "baffle_session": null}

decision := {"allow": true, "filesystem": null, "baffle_session": null} if {
  data.sandbox[input.command].allow
}
"#,
        )
        .expect("write main rego");

        std::fs::write(
            dir.join("command.rego"),
            format!(
                "package sandbox.{}\n\ndefault allow = false\n\nallow if {{\n  count(input.args) == 0\n  count(object.keys(input.env)) == 0\n  startswith(input.path, \"/\")\n}}\n",
                command
            ),
        )
        .expect("write command rego");
    }

    #[test]
    fn rego_mode_selected_when_policy_dir_is_set() {
        let dir = tempdir().expect("temp rego dir");
        write_rego_bundle(dir.path(), "echo");

        let engine = PolicyEngine::from_sources(Some(dir.path().to_path_buf()));
        assert_eq!(engine.mode(), PolicyMode::Rego);
    }

    #[test]
    fn policy_dir_ignores_non_rego_files() {
        let dir = tempdir().expect("temp rego dir");
        write_rego_bundle(dir.path(), "echo");
        std::fs::write(
            dir.path().join("domains.lst"),
            "this is not rego and should not be parsed\n",
        )
        .expect("write domains list");

        let engine = PolicyEngine::from_sources(Some(dir.path().to_path_buf()));
        assert_eq!(engine.mode(), PolicyMode::Rego);
    }

    #[test]
    fn jj_example_policy_bundle_preserves_allowed_command_shapes() {
        let policy_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/jj/policy");
        assert!(policy_dir.exists(), "missing jj example policy bundle");

        let engine = PolicyEngine::from_sources(Some(policy_dir));
        assert_eq!(engine.mode(), PolicyMode::Rego);

        let hash = "0000000000000000000000000000000000000000000000000000000000000000";
        let empty_env = BTreeMap::new();
        let workspace_add = vec![
            "workspace".to_string(),
            "add".to_string(),
            "../../code-agent/foo".to_string(),
            "--name".to_string(),
            "agent-foo".to_string(),
        ];
        assert!(
            engine
                .validate_invocation(
                    "real_jj",
                    "/opt/tools/bin/real_jj",
                    hash,
                    &workspace_add,
                    &empty_env,
                    "/home/user/workspace/code/cladding",
                )
                .is_ok()
        );

        let mismatched_workspace_name = vec![
            "workspace".to_string(),
            "add".to_string(),
            "../../code-agent/foo".to_string(),
            "--name".to_string(),
            "agent-bar".to_string(),
        ];
        assert!(
            engine
                .validate_invocation(
                    "real_jj",
                    "/opt/tools/bin/real_jj",
                    hash,
                    &mismatched_workspace_name,
                    &empty_env,
                    "/home/user/workspace/code/cladding",
                )
                .is_err()
        );

        let commit = vec![
            "commit".to_string(),
            "-m".to_string(),
            "message".to_string(),
        ];
        assert!(
            engine
                .validate_invocation(
                    "real_jj",
                    "/opt/tools/bin/real_jj",
                    hash,
                    &commit,
                    &empty_env,
                    "/home/user/workspace/code-agent/foo",
                )
                .is_ok()
        );

        let snapshot = vec!["util".to_string(), "snapshot".to_string()];
        assert!(
            engine
                .validate_invocation(
                    "real_jj",
                    "/opt/tools/bin/real_jj",
                    hash,
                    &snapshot,
                    &empty_env,
                    "/home/user/workspace/code-agent/foo",
                )
                .is_ok()
        );

        let status = vec!["status".to_string()];
        assert!(
            engine
                .validate_invocation(
                    "real_jj",
                    "/opt/tools/bin/real_jj",
                    hash,
                    &status,
                    &empty_env,
                    "/home/user/workspace/code-agent/foo",
                )
                .is_err()
        );
    }

    #[test]
    fn invalid_startup_policy_is_deny_all() {
        let dir = tempdir().expect("temp rego dir");
        std::fs::write(
            dir.path().join("bad.rego"),
            "package sandbox.main\nallow if",
        )
        .expect("write bad rego");

        let engine = PolicyEngine::from_sources(Some(dir.path().to_path_buf()));
        assert_eq!(engine.mode(), PolicyMode::DenyAll);
        let err = engine
            .validate_invocation(
                "echo",
                "/usr/bin/echo",
                "0000000000000000000000000000000000000000000000000000000000000000",
                &[],
                &BTreeMap::new(),
                "/",
            )
            .expect_err("deny-all expected");
        assert!(matches!(err, ValidationError::PolicyUnavailable { .. }));
    }

    #[test]
    fn rego_input_contains_command_path_args_env_hash_cwd() {
        let modules = [
            (
                "main.rego",
                r#"package sandbox.main

default decision := {"allow": false, "filesystem": null, "baffle_session": null}

decision := {"allow": true, "filesystem": null, "baffle_session": null} if {
  data.sandbox[input.command].allow
}
"#,
            ),
            (
                "echo.rego",
                r#"package sandbox.echo

default allow = false

allow if {
  input.command == "echo"
  input.args[0] == "ok"
  input.env.FLAG == "1"
  input.hash == "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
  input.cwd == "/workspace"
  startswith(input.path, "/")
}
"#,
            ),
        ];

        let engine = PolicyEngine::from_rego_for_tests(&modules);
        let env = BTreeMap::from([(String::from("FLAG"), String::from("1"))]);
        let args = vec!["ok".to_string()];
        assert!(
            engine
                .validate_invocation(
                    "echo",
                    "/usr/bin/echo",
                    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                    &args,
                    &env,
                    "/workspace",
                )
                .is_ok()
        );

        let err = engine
            .validate_invocation(
                "/usr/bin/echo",
                "/usr/bin/echo",
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                &args,
                &env,
                "/workspace",
            )
            .expect_err("command token should not match when full path is sent");
        assert!(err.to_string().contains("Command not allowed"));
    }

    #[test]
    fn reload_transitions_invalid_to_deny_all_and_recovers() {
        let dir = tempdir().expect("temp rego dir");
        write_rego_bundle(dir.path(), "echo");

        let engine = PolicyEngine::from_sources(Some(dir.path().to_path_buf()));
        assert_eq!(engine.mode(), PolicyMode::Rego);
        assert!(
            engine
                .validate_invocation(
                    "echo",
                    "/usr/bin/echo",
                    "0000000000000000000000000000000000000000000000000000000000000000",
                    &[],
                    &BTreeMap::new(),
                    "/",
                )
                .is_ok()
        );

        std::fs::write(
            dir.path().join("command.rego"),
            "package sandbox.echo\n\ndefault allow = false\nallow if",
        )
        .expect("write invalid rego");

        engine.reload();
        assert_eq!(engine.mode(), PolicyMode::DenyAll);
        assert!(matches!(
            engine
                .validate_invocation(
                    "echo",
                    "/usr/bin/echo",
                    "0000000000000000000000000000000000000000000000000000000000000000",
                    &[],
                    &BTreeMap::new(),
                    "/",
                )
                .expect_err("deny-all expected"),
            ValidationError::PolicyUnavailable { .. }
        ));

        write_rego_bundle(dir.path(), "echo");
        engine.reload();
        assert_eq!(engine.mode(), PolicyMode::Rego);
        assert!(
            engine
                .validate_invocation(
                    "echo",
                    "/usr/bin/echo",
                    "0000000000000000000000000000000000000000000000000000000000000000",
                    &[],
                    &BTreeMap::new(),
                    "/",
                )
                .is_ok()
        );
    }

    #[test]
    fn validation_reloads_policy_when_files_change() {
        let dir = tempdir().expect("temp rego dir");
        write_rego_bundle(dir.path(), "echo");

        let engine = PolicyEngine::from_sources(Some(dir.path().to_path_buf()));
        assert_eq!(engine.mode(), PolicyMode::Rego);
        assert!(
            engine
                .validate_invocation(
                    "echo",
                    "/usr/bin/echo",
                    "0000000000000000000000000000000000000000000000000000000000000000",
                    &[],
                    &BTreeMap::new(),
                    "/",
                )
                .is_ok()
        );

        write_rego_bundle(dir.path(), "printf");

        assert!(
            engine
                .validate_invocation(
                    "printf",
                    "/usr/bin/printf",
                    "0000000000000000000000000000000000000000000000000000000000000000",
                    &[],
                    &BTreeMap::new(),
                    "/",
                )
                .is_ok()
        );
        assert!(
            engine
                .validate_invocation(
                    "echo",
                    "/usr/bin/echo",
                    "0000000000000000000000000000000000000000000000000000000000000000",
                    &[],
                    &BTreeMap::new(),
                    "/",
                )
                .is_err()
        );
    }

    #[test]
    fn missing_policy_dir_is_deny_all() {
        let engine = PolicyEngine::from_sources(None);
        assert_eq!(engine.mode(), PolicyMode::DenyAll);
    }

    fn authorize_test_policy(module: &str) -> Result<PolicyAuthorization, ValidationError> {
        let engine = PolicyEngine::from_rego_for_tests(&[("main.rego", module)]);
        engine.authorize_invocation(
            "echo",
            "/usr/bin/echo",
            "0000000000000000000000000000000000000000000000000000000000000000",
            &[],
            &BTreeMap::new(),
            "/workspace",
        )
    }

    #[test]
    fn structured_decision_requires_explicit_fields_and_valid_types() {
        let valid_nulls = r#"package sandbox.main

decision := {"allow": true, "filesystem": null, "baffle_session": null}
"#;
        let authorization = authorize_test_policy(valid_nulls).expect("explicit nulls are valid");
        assert!(authorization.decision.allow);
        assert_eq!(authorization.decision.filesystem, None);
        assert_eq!(authorization.decision.baffle_session, None);

        let denied =
            authorize_test_policy("package sandbox.main\n\ndecision := {\"allow\": false}")
                .expect("deny decisions only need allow");
        assert!(!denied.decision.allow);

        for (name, decision, reason) in [
            (
                "missing filesystem",
                r#"{"allow": true, "baffle_session": null}"#,
                "missing required 'filesystem'",
            ),
            (
                "missing baffle",
                r#"{"allow": true, "filesystem": null}"#,
                "missing required 'baffle_session'",
            ),
            (
                "wrong allow type",
                r#"{"allow": "yes", "filesystem": null, "baffle_session": null}"#,
                "boolean 'allow'",
            ),
            (
                "wrong filesystem type",
                r#"{"allow": true, "filesystem": 1, "baffle_session": null}"#,
                "string or null",
            ),
            (
                "wrong baffle type",
                r#"{"allow": true, "filesystem": null, "baffle_session": false}"#,
                "string or null",
            ),
            (
                "extra field",
                r#"{"allow": true, "filesystem": null, "baffle_session": null, "backend": "direct"}"#,
                "unknown decision field",
            ),
            (
                "bad profile name",
                r#"{"allow": true, "filesystem": "../root", "baffle_session": null}"#,
                "invalid filesystem profile name",
            ),
            (
                "bad baffle filename",
                r#"{"allow": true, "filesystem": null, "baffle_session": "../secret.toml"}"#,
                "invalid Baffle session filename",
            ),
        ] {
            let module = format!("package sandbox.main\n\ndecision := {decision}");
            let error = authorize_test_policy(&module).expect_err(name);
            assert!(error.to_string().contains(reason), "{name}: {error}");
        }
    }

    #[test]
    fn undefined_and_conflicting_decisions_fail_closed() {
        let undefined = "package sandbox.main\n";
        assert!(matches!(
            authorize_test_policy(undefined),
            Err(ValidationError::PolicyEvaluationFailed { .. })
        ));

        let conflict = r#"package sandbox.main

decision := {"allow": true, "filesystem": null, "baffle_session": null} if { input.command == "echo" }
decision := {"allow": true, "filesystem": "other", "baffle_session": null} if { input.command == "echo" }
"#;
        assert!(matches!(
            authorize_test_policy(conflict),
            Err(ValidationError::PolicyEvaluationFailed { .. })
        ));
    }

    fn write_decision_policy(policy_dir: &Path, filesystem: &str) {
        std::fs::write(
            policy_dir.join("main.rego"),
            format!(
                "package sandbox.main\n\ndecision := {{\"allow\": true, \"filesystem\": \"{filesystem}\", \"baffle_session\": null}}\n"
            ),
        )
        .expect("write policy");
    }

    fn write_bind_profile(directory: &Path, name: &str, source: &Path) {
        std::fs::create_dir_all(directory).expect("create profile directory");
        std::fs::write(
            directory.join(format!("{name}.toml")),
            format!(
                "version = 1\n\n[[mounts]]\nsource = {:?}\ntarget = \"/workspace\"\naccess = \"read-only\"\n",
                source.to_string_lossy()
            ),
        )
        .expect("write profile");
    }

    #[test]
    fn policy_and_filesystem_profiles_publish_as_one_retained_generation() {
        let root = tempdir().expect("temp policy root");
        let policy_dir = root.path().join("policies");
        let filesystem_dir = root.path().join("filesystems");
        let first_source = root.path().join("workspace-one");
        let second_source = root.path().join("workspace-two");
        std::fs::create_dir_all(&policy_dir).expect("create policy directory");
        std::fs::create_dir(&first_source).expect("create first mount source");
        std::fs::create_dir(&second_source).expect("create second mount source");
        write_decision_policy(&policy_dir, "workspace-one");
        write_bind_profile(&filesystem_dir, "workspace-one", &first_source);

        let engine = PolicyEngine::from_sources(Some(policy_dir.clone()));
        let hash = "0000000000000000000000000000000000000000000000000000000000000000";
        let first = engine
            .authorize_invocation("echo", "/usr/bin/echo", hash, &[], &BTreeMap::new(), "/")
            .expect("first generation authorizes");
        let first_id = first.generation.id();
        assert_eq!(first.decision.filesystem.as_deref(), Some("workspace-one"));
        assert!(Arc::ptr_eq(
            first.filesystem_profile.as_ref().expect("profile retained"),
            engine
                .state
                .read()
                .expect("state")
                .filesystem_profiles
                .get("workspace-one")
                .expect("profile in generation"),
        ));

        write_decision_policy(&policy_dir, "workspace-two");
        write_bind_profile(&filesystem_dir, "workspace-two", &second_source);
        let second = engine
            .authorize_invocation("echo", "/usr/bin/echo", hash, &[], &BTreeMap::new(), "/")
            .expect("updated generation authorizes");

        assert_ne!(first_id, second.generation.id());
        assert_eq!(second.decision.filesystem.as_deref(), Some("workspace-two"));
        assert!(
            first
                .generation
                .filesystem_profiles
                .contains_key("workspace-one")
        );
        assert!(
            !first
                .generation
                .filesystem_profiles
                .contains_key("workspace-two")
        );
        assert_eq!(
            second
                .filesystem_profile
                .as_ref()
                .expect("new profile")
                .mounts[0],
            crate::filesystem::FilesystemMount::Bind {
                source: second_source,
                target: PathBuf::from("/workspace"),
                access: crate::filesystem::MountAccess::ReadOnly,
            }
        );
    }

    #[test]
    fn invalid_profile_reload_activates_deny_all() {
        let root = tempdir().expect("temp policy root");
        let policy_dir = root.path().join("policies");
        let filesystem_dir = root.path().join("filesystems");
        let source = root.path().join("workspace");
        std::fs::create_dir_all(&policy_dir).expect("create policy directory");
        std::fs::create_dir(&source).expect("create source");
        write_decision_policy(&policy_dir, "workspace");
        write_bind_profile(&filesystem_dir, "workspace", &source);
        let engine = PolicyEngine::from_sources(Some(policy_dir));
        assert_eq!(engine.mode(), PolicyMode::Rego);

        std::fs::write(
            filesystem_dir.join("workspace.toml"),
            "version = 1\n\n[[mounts]]\nsource = \"/tmp\"\ntarget = \"/workspace\"\naccess = \"invalid\"\n",
        )
        .expect("write invalid profile");
        let error = engine
            .authorize_invocation(
                "echo",
                "/usr/bin/echo",
                "0000000000000000000000000000000000000000000000000000000000000000",
                &[],
                &BTreeMap::new(),
                "/",
            )
            .expect_err("invalid generation denies");
        assert_eq!(engine.mode(), PolicyMode::DenyAll);
        assert!(matches!(error, ValidationError::PolicyUnavailable { .. }));
    }
}
