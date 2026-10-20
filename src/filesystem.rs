use std::collections::BTreeMap;
use std::fs;
use std::path::{Component, Path, PathBuf};

use serde::Deserialize;
use thiserror::Error;

const PROFILE_VERSION: u32 = 1;

#[derive(Debug, Error)]
pub enum FilesystemProfileError {
    #[error("failed to inspect filesystem profile directory '{path}': {source}")]
    Directory {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("filesystem profile directory is a symlink: {0}")]
    SymlinkDirectory(PathBuf),
    #[error("invalid filesystem profile file '{path}': {details}")]
    Invalid { path: PathBuf, details: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FilesystemProfile {
    pub(crate) name: String,
    pub(crate) mounts: Vec<FilesystemMount>,
    pub(crate) runtime_paths: Vec<RuntimePath>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RuntimePath {
    pub(crate) source: PathBuf,
    pub(crate) target: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum FilesystemMount {
    Bind {
        source: PathBuf,
        target: PathBuf,
        access: MountAccess,
    },
    Tmpfs {
        target: PathBuf,
        size_bytes: u64,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MountAccess {
    ReadOnly,
    ReadWrite,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProfileDocument {
    version: u32,
    mounts: Vec<MountDocument>,
    #[serde(default)]
    runtime_paths: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MountDocument {
    #[serde(rename = "type")]
    mount_type: Option<String>,
    source: Option<String>,
    target: String,
    access: Option<String>,
    size: Option<String>,
}

/// List the direct `filesystems/*.toml` profiles associated with a policy directory.
/// A missing directory means no profiles are configured; a selected profile then fails closed.
pub(crate) fn profile_files(directory: &Path) -> Result<Vec<PathBuf>, FilesystemProfileError> {
    let metadata = match fs::symlink_metadata(directory) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(source) => {
            return Err(FilesystemProfileError::Directory {
                path: directory.to_path_buf(),
                source,
            });
        }
    };
    if metadata.file_type().is_symlink() {
        return Err(FilesystemProfileError::SymlinkDirectory(
            directory.to_path_buf(),
        ));
    }

    let entries = fs::read_dir(directory).map_err(|source| FilesystemProfileError::Directory {
        path: directory.to_path_buf(),
        source,
    })?;
    let mut paths = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|source| FilesystemProfileError::Directory {
            path: directory.to_path_buf(),
            source,
        })?;
        let path = entry.path();
        if path.extension().and_then(|value| value.to_str()) == Some("toml") {
            paths.push(path);
        }
    }
    paths.sort();
    for path in &paths {
        let metadata =
            fs::symlink_metadata(path).map_err(|error| invalid(path, error.to_string()))?;
        if !metadata.file_type().is_file() {
            return Err(invalid(
                path,
                "profile must be a regular file, not a symlink or special file",
            ));
        }
    }

    Ok(paths)
}

/// Parse profiles from the exact bytes captured with the Rego source files.
pub(crate) fn load_profiles_from_sources(
    files: &[(PathBuf, Vec<u8>)],
) -> Result<BTreeMap<String, FilesystemProfile>, FilesystemProfileError> {
    let mut profiles = BTreeMap::new();
    for (path, contents) in files {
        let profile = load_profile(path, contents)?;
        if profiles.insert(profile.name.clone(), profile).is_some() {
            return Err(invalid(path, "duplicate profile name"));
        }
    }
    Ok(profiles)
}

fn load_profile(path: &Path, contents: &[u8]) -> Result<FilesystemProfile, FilesystemProfileError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| invalid(path, error.to_string()))?;
    if !metadata.file_type().is_file() {
        return Err(invalid(
            path,
            "profile must be a regular file, not a symlink or special file",
        ));
    }
    let name = path
        .file_stem()
        .and_then(|value| value.to_str())
        .ok_or_else(|| invalid(path, "profile name is not valid UTF-8"))?;
    validate_profile_name(name).map_err(|details| invalid(path, details))?;
    let source = std::str::from_utf8(contents).map_err(|error| invalid(path, error.to_string()))?;
    let document: ProfileDocument =
        toml::from_str(source).map_err(|error| invalid(path, error.to_string()))?;
    if document.version != PROFILE_VERSION {
        return Err(invalid(
            path,
            format!(
                "unsupported version {}; expected {PROFILE_VERSION}",
                document.version
            ),
        ));
    }

    let mut mounts = Vec::with_capacity(document.mounts.len());
    let mut targets: Vec<PathBuf> = Vec::with_capacity(document.mounts.len());
    for mount in document.mounts {
        let target = validate_absolute_path(&mount.target, "target")
            .map_err(|details| invalid(path, details))?;
        validate_mount_target(&target).map_err(|details| invalid(path, details))?;
        for previous in &targets {
            if paths_overlap(previous, &target) {
                return Err(invalid(
                    path,
                    format!(
                        "mount destinations overlap: '{}' and '{}'",
                        previous.display(),
                        target.display()
                    ),
                ));
            }
        }
        targets.push(target.clone());

        let mount_type = mount.mount_type.as_deref().unwrap_or("bind");
        match mount_type {
            "bind" => {
                let source_value = mount
                    .source
                    .ok_or_else(|| invalid(path, "bind mount requires source"))?;
                let source = validate_absolute_path(&source_value, "source")
                    .map_err(|details| invalid(path, details))?;
                validate_mount_source(&source).map_err(|details| invalid(path, details))?;
                let access = match mount.access.as_deref() {
                    Some("read-only") => MountAccess::ReadOnly,
                    Some("read-write") => MountAccess::ReadWrite,
                    Some(value) => {
                        return Err(invalid(
                            path,
                            format!(
                                "invalid mount access '{value}'; expected read-only or read-write"
                            ),
                        ));
                    }
                    None => return Err(invalid(path, "bind mount requires access")),
                };
                if mount.size.is_some() {
                    return Err(invalid(path, "bind mount cannot set size"));
                }
                mounts.push(FilesystemMount::Bind {
                    source,
                    target,
                    access,
                });
            }
            "tmpfs" => {
                if mount.source.is_some() || mount.access.is_some() {
                    return Err(invalid(path, "tmpfs mount cannot set source or access"));
                }
                let size = mount
                    .size
                    .ok_or_else(|| invalid(path, "tmpfs mount requires size"))?;
                let size_bytes =
                    parse_tmpfs_size(&size).map_err(|details| invalid(path, details))?;
                mounts.push(FilesystemMount::Tmpfs { target, size_bytes });
            }
            value => return Err(invalid(path, format!("unsupported mount type '{value}'"))),
        }
    }

    let mut runtime_paths: Vec<RuntimePath> = Vec::with_capacity(document.runtime_paths.len());
    for value in document.runtime_paths {
        let target = validate_absolute_path(&value, "runtime path")
            .map_err(|details| invalid(path, details))?;
        validate_runtime_target(&target).map_err(|details| invalid(path, details))?;
        let source = fs::canonicalize(&target).map_err(|error| {
            invalid(
                path,
                format!(
                    "runtime path '{}' cannot be resolved: {error}",
                    target.display()
                ),
            )
        })?;
        validate_mount_source(&source).map_err(|details| invalid(path, details))?;
        for mount in &mounts {
            let mount_target = match mount {
                FilesystemMount::Bind { target, .. } | FilesystemMount::Tmpfs { target, .. } => {
                    target
                }
            };
            if paths_overlap(mount_target, &target) {
                return Err(invalid(
                    path,
                    format!(
                        "runtime path '{}' overlaps filesystem mount destination '{}'",
                        target.display(),
                        mount_target.display()
                    ),
                ));
            }
        }
        for previous in &runtime_paths {
            if paths_overlap(previous.target.as_path(), &target) {
                return Err(invalid(
                    path,
                    format!(
                        "runtime paths overlap: '{}' and '{}'",
                        previous.target.display(),
                        target.display()
                    ),
                ));
            }
        }
        runtime_paths.push(RuntimePath { source, target });
    }

    Ok(FilesystemProfile {
        name: name.to_string(),
        mounts,
        runtime_paths,
    })
}

#[cfg(test)]
fn load_profiles(
    directory: &Path,
) -> Result<BTreeMap<String, FilesystemProfile>, FilesystemProfileError> {
    let files = profile_files(directory)?;
    let sources = files
        .into_iter()
        .map(|path| {
            let contents = fs::read(&path).map_err(|error| invalid(&path, error.to_string()))?;
            Ok((path, contents))
        })
        .collect::<Result<Vec<_>, FilesystemProfileError>>()?;
    load_profiles_from_sources(&sources)
}

pub(crate) fn validate_profile_name(name: &str) -> Result<(), String> {
    let bytes = name.as_bytes();
    if bytes.is_empty()
        || !bytes[0].is_ascii_lowercase() && !bytes[0].is_ascii_digit()
        || !bytes[bytes.len() - 1].is_ascii_lowercase() && !bytes[bytes.len() - 1].is_ascii_digit()
        || bytes.iter().any(|byte| {
            !(byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-' || *byte == b'_')
        })
    {
        return Err(format!("invalid filesystem profile name '{name}'"));
    }
    Ok(())
}

pub(crate) fn validate_baffle_filename(name: &str) -> Result<(), String> {
    if !name.ends_with(".toml") || name.len() <= ".toml".len() {
        return Err("Baffle session selection must be a .toml filename".to_string());
    }
    let stem = &name[..name.len() - ".toml".len()];
    if stem.is_empty()
        || !stem.as_bytes()[0].is_ascii_alphanumeric()
        || stem
            .as_bytes()
            .iter()
            .any(|byte| !(byte.is_ascii_alphanumeric() || *byte == b'-' || *byte == b'_'))
    {
        return Err(format!("invalid Baffle session filename '{name}'"));
    }
    Ok(())
}

fn validate_absolute_path(value: &str, field: &str) -> Result<PathBuf, String> {
    if !value.starts_with('/') || value.starts_with("//") {
        return Err(format!(
            "{field} path must be absolute and must not start with //: '{value}'"
        ));
    }
    if value != "/" && value.ends_with('/') {
        return Err(format!("{field} path must not end with /: '{value}'"));
    }
    for component in value[1..].split('/') {
        if component.is_empty() || component == "." || component == ".." {
            return Err(format!(
                "{field} path contains an empty, . or .. component: '{value}'"
            ));
        }
    }
    let path = PathBuf::from(value);
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
    {
        return Err(format!("invalid {field} path '{value}'"));
    }
    Ok(path)
}

fn validate_mount_source(source: &Path) -> Result<(), String> {
    let mut current = PathBuf::from("/");
    let components = source.components().filter_map(|component| match component {
        Component::Normal(value) => Some(value),
        _ => None,
    });
    for component in components {
        current.push(component);
        let metadata = fs::symlink_metadata(&current).map_err(|error| {
            format!(
                "mount source '{}' cannot be inspected: {error}",
                source.display()
            )
        })?;
        if metadata.file_type().is_symlink() {
            return Err(format!(
                "mount source '{}' contains a symlink at '{}'",
                source.display(),
                current.display()
            ));
        }
    }
    let metadata = fs::symlink_metadata(source).map_err(|error| {
        format!(
            "mount source '{}' cannot be inspected: {error}",
            source.display()
        )
    })?;
    if !metadata.file_type().is_dir() && !metadata.file_type().is_file() {
        return Err(format!(
            "mount source '{}' must be a regular file or directory",
            source.display()
        ));
    }
    Ok(())
}

fn validate_mount_target(target: &Path) -> Result<(), String> {
    const PROTECTED: &[&str] = &[
        "/", "/bin", "/dev", "/etc", "/lib", "/lib64", "/proc", "/run", "/sbin", "/sys", "/usr",
    ];
    if target == Path::new("/")
        || PROTECTED
            .iter()
            .skip(1)
            .map(Path::new)
            .any(|protected| target.starts_with(protected) || protected.starts_with(target))
    {
        return Err(format!(
            "mount destination '{}' is protected",
            target.display()
        ));
    }
    Ok(())
}

fn validate_runtime_target(target: &Path) -> Result<(), String> {
    const PROTECTED: &[&str] = &["/dev", "/proc", "/run", "/sys"];
    if target == Path::new("/")
        || PROTECTED
            .iter()
            .map(Path::new)
            .any(|protected| paths_overlap(target, protected))
    {
        return Err(format!(
            "runtime path destination '{}' is protected",
            target.display()
        ));
    }
    Ok(())
}

fn paths_overlap(left: &Path, right: &Path) -> bool {
    left.starts_with(right) || right.starts_with(left)
}

fn parse_tmpfs_size(value: &str) -> Result<u64, String> {
    let split = value
        .find(|character: char| !character.is_ascii_digit())
        .unwrap_or(value.len());
    let (number, unit) = value.split_at(split);
    if number.is_empty() {
        return Err(format!("invalid tmpfs size '{value}'"));
    }
    let count = number
        .parse::<u64>()
        .map_err(|_| format!("invalid tmpfs size '{value}'"))?;
    let multiplier = match unit {
        "B" => 1,
        "KiB" => 1024,
        "MiB" => 1024 * 1024,
        "GiB" => 1024 * 1024 * 1024,
        _ => {
            return Err(format!(
                "invalid tmpfs size unit in '{value}'; use B, KiB, MiB or GiB"
            ));
        }
    };
    let bytes = count
        .checked_mul(multiplier)
        .ok_or_else(|| format!("tmpfs size overflows: '{value}'"))?;
    if bytes == 0 {
        return Err("tmpfs size must be greater than zero".to_string());
    }
    Ok(bytes)
}

fn invalid(path: &Path, details: impl Into<String>) -> FilesystemProfileError {
    FilesystemProfileError::Invalid {
        path: path.to_path_buf(),
        details: details.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_profile(directory: &Path, name: &str, text: &str) {
        fs::create_dir_all(directory).expect("create filesystem directory");
        fs::write(directory.join(format!("{name}.toml")), text).expect("write profile");
    }

    #[test]
    fn loads_direct_bind_and_tmpfs_mounts() {
        let root = tempfile::tempdir().expect("temp root");
        let filesystem_dir = root.path().join("filesystems");
        let source = root.path().join("workspace");
        fs::create_dir(&source).expect("create source");
        write_profile(
            &filesystem_dir,
            "workspace-readonly",
            &format!(
                "version = 1\n\n[[mounts]]\nsource = {:?}\ntarget = \"/workspace\"\naccess = \"read-only\"\n\n[[mounts]]\ntype = \"tmpfs\"\ntarget = \"/tmp\"\nsize = \"256MiB\"\n",
                source.to_string_lossy()
            ),
        );
        let profiles = load_profiles(&filesystem_dir).expect("valid profile");
        let profile = profiles.get("workspace-readonly").expect("profile entry");
        assert_eq!(profile.mounts.len(), 2);
        assert!(matches!(
            profile.mounts[0],
            FilesystemMount::Bind {
                access: MountAccess::ReadOnly,
                ..
            }
        ));
        assert!(
            matches!(profile.mounts[1], FilesystemMount::Tmpfs { size_bytes, .. } if size_bytes == 256 * 1024 * 1024)
        );
    }

    #[cfg(unix)]
    #[test]
    fn loads_read_only_runtime_paths_and_resolves_symlink_sources() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().expect("temp root");
        let filesystem_dir = root.path().join("filesystems");
        let helper = root.path().join("python3");
        let helper_alias = root.path().join("python");
        let library_dir = root.path().join("python-stdlib");
        fs::write(&helper, "fixture").expect("write helper");
        symlink(&helper, &helper_alias).expect("create helper alias");
        fs::create_dir(&library_dir).expect("create library directory");
        write_profile(
            &filesystem_dir,
            "runtime",
            &format!(
                "version = 1\nruntime_paths = [{:?}, {:?}]\n\nmounts = []\n",
                helper_alias.to_string_lossy(),
                library_dir.to_string_lossy(),
            ),
        );

        let profiles = load_profiles(&filesystem_dir).expect("valid runtime paths");
        let profile = profiles.get("runtime").expect("profile entry");
        assert_eq!(profile.runtime_paths.len(), 2);
        assert_eq!(profile.runtime_paths[0].source, helper);
        assert_eq!(profile.runtime_paths[0].target, helper_alias);
        assert_eq!(profile.runtime_paths[1].source, library_dir);
        assert_eq!(profile.runtime_paths[1].target, library_dir);
    }

    #[test]
    fn rejects_invalid_and_overlapping_runtime_paths() {
        let root = tempfile::tempdir().expect("temp root");
        let filesystem_dir = root.path().join("filesystems");
        let directory = root.path().join("python");
        fs::create_dir(&directory).expect("create runtime directory");
        let nested = directory.join("stdlib");
        fs::create_dir(&nested).expect("create nested runtime directory");

        for (name, paths, expected) in [
            ("relative-runtime", "[\"python3\"]", "absolute"),
            (
                "missing-runtime",
                "[\"/no/such/gantry-runtime-path\"]",
                "cannot be resolved",
            ),
            (
                "traversal-runtime",
                "[\"/usr/bin/../bin/python3\"]",
                "empty, . or ..",
            ),
            ("protected-runtime", "[\"/proc\"]", "is protected"),
        ] {
            write_profile(
                &filesystem_dir,
                name,
                &format!("version = 1\nruntime_paths = {paths}\nmounts = []\n"),
            );
            let error = load_profiles(&filesystem_dir).expect_err("invalid runtime path rejected");
            assert!(error.to_string().contains(expected), "{error}");
            fs::remove_file(filesystem_dir.join(format!("{name}.toml"))).expect("remove profile");
        }

        write_profile(
            &filesystem_dir,
            "overlapping-runtime",
            &format!(
                "version = 1\nruntime_paths = [{:?}, {:?}]\nmounts = []\n",
                directory.to_string_lossy(),
                nested.to_string_lossy(),
            ),
        );
        let error = load_profiles(&filesystem_dir).expect_err("overlapping paths rejected");
        assert!(error.to_string().contains("runtime paths overlap"));

        fs::remove_file(filesystem_dir.join("overlapping-runtime.toml"))
            .expect("remove overlapping profile");
        write_profile(
            &filesystem_dir,
            "runtime-mount-overlap",
            &format!(
                "version = 1\nruntime_paths = [{:?}]\n\n[[mounts]]\nsource = {:?}\ntarget = {:?}\naccess = \"read-only\"\n",
                directory.to_string_lossy(),
                directory.to_string_lossy(),
                directory.to_string_lossy(),
            ),
        );
        let error = load_profiles(&filesystem_dir).expect_err("runtime mount overlap rejected");
        assert!(
            error
                .to_string()
                .contains("overlaps filesystem mount destination")
        );
    }

    #[test]
    fn rejects_invalid_paths_targets_access_and_sizes() {
        let root = tempfile::tempdir().expect("temp root");
        let filesystem_dir = root.path().join("filesystems");
        let source = root.path().to_string_lossy();
        for (name, target, access, extra, expected) in [
            ("relative", "workspace", "read-only", "", "absolute"),
            (
                "traversal",
                "/workspace/../other",
                "read-only",
                "",
                "empty, . or ..",
            ),
            ("protected", "/proc", "read-only", "", "protected"),
            (
                "protected-child",
                "/proc/private",
                "read-only",
                "",
                "protected",
            ),
            ("access", "/workspace", "read", "", "invalid mount access"),
            (
                "size",
                "/workspace",
                "read-only",
                "size = \"0MiB\"\n",
                "cannot set size",
            ),
        ] {
            let body = format!(
                "version = 1\n\n[[mounts]]\nsource = {source:?}\ntarget = {target:?}\naccess = {access:?}\n{extra}"
            );
            write_profile(&filesystem_dir, name, &body);
            let error = load_profiles(&filesystem_dir).expect_err("invalid profile rejected");
            assert!(error.to_string().contains(expected), "{error}");
            fs::remove_file(filesystem_dir.join(format!("{name}.toml"))).expect("remove profile");
        }

        write_profile(
            &filesystem_dir,
            "tmpfs-size",
            "version = 1\n\n[[mounts]]\ntype = \"tmpfs\"\ntarget = \"/tmp\"\nsize = \"0MiB\"\n",
        );
        let error = load_profiles(&filesystem_dir).expect_err("zero tmpfs size rejected");
        assert!(error.to_string().contains("greater than zero"));

        fs::remove_file(filesystem_dir.join("tmpfs-size.toml")).expect("remove profile");
        write_profile(
            &filesystem_dir,
            "bad-type",
            "version = 1\n\n[[mounts]]\ntype = \"device\"\ntarget = \"/workspace\"\n",
        );
        let error = load_profiles(&filesystem_dir).expect_err("unsupported type rejected");
        assert!(error.to_string().contains("unsupported mount type"));
    }

    #[test]
    fn rejects_overlaps_and_invalid_names() {
        let root = tempfile::tempdir().expect("temp root");
        let filesystem_dir = root.path().join("filesystems");
        let source = root.path().to_string_lossy();
        let body = format!(
            "version = 1\n\n[[mounts]]\nsource = {source:?}\ntarget = \"/workspace\"\naccess = \"read-only\"\n\n[[mounts]]\nsource = {source:?}\ntarget = \"/workspace/nested\"\naccess = \"read-write\"\n"
        );
        write_profile(&filesystem_dir, "overlap", &body);
        assert!(
            load_profiles(&filesystem_dir)
                .expect_err("overlap rejected")
                .to_string()
                .contains("overlap")
        );
        assert!(validate_profile_name("../workspace").is_err());
        assert!(validate_profile_name("workspace").is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_mount_sources() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().expect("temp root");
        let filesystem_dir = root.path().join("filesystems");
        let source = root.path().join("real-source");
        let link = root.path().join("linked-source");
        fs::create_dir(&source).expect("create source");
        symlink(&source, &link).expect("create source symlink");
        let body = format!(
            "version = 1\n\n[[mounts]]\nsource = {:?}\ntarget = \"/workspace\"\naccess = \"read-only\"\n",
            link.to_string_lossy()
        );
        write_profile(&filesystem_dir, "linked", &body);
        assert!(
            load_profiles(&filesystem_dir)
                .expect_err("symlink source rejected")
                .to_string()
                .contains("contains a symlink")
        );
    }

    #[test]
    fn validates_baffle_filenames_as_single_toml_names() {
        assert!(validate_baffle_filename("github-readonly.toml").is_ok());
        for invalid in [
            "../secrets.toml",
            "/tmp/session.toml",
            "session.json",
            "foo/bar.toml",
        ] {
            assert!(validate_baffle_filename(invalid).is_err(), "{invalid}");
        }
    }
}
