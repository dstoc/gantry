use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

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
