#[cfg(target_os = "linux")]
mod linux {
    use std::collections::{BTreeMap, BTreeSet};
    use std::ffi::CString;
    use std::fs;
    use std::io;
    use std::mem::MaybeUninit;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
    use std::path::{Path, PathBuf};
    use std::process::Stdio;

    use base64::Engine as _;
    use tokio::io::{
        AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader,
    };
    use tokio::process::Command;
    use tokio::sync::oneshot;

    use crate::backend::{StartError, runtime::runtime_files};
    use crate::baffle::{
        BaffleRuntimeConfig, BaffleSessionLease, SANDBOX_CA_CERTIFICATE, SANDBOX_SOCKET,
        create_ephemeral_session,
    };
    use crate::execution::{ExecutionExitStatus, ExecutionPlan, RunningExecution};
    use crate::filesystem::{FilesystemMount, MountAccess};

    const SUPERVISOR_TARGET: &str = "/run/gantry-supervisor";
    const FIRST_MOUNT_FD: RawFd = 4;

    #[derive(Debug, serde::Serialize)]
    struct InvocationMessage<'a> {
        executable: &'a Path,
        args: &'a [String],
        cwd: &'a Path,
        environment: &'a BTreeMap<String, String>,
        proxy_socket: Option<&'a Path>,
    }

    #[derive(Debug, serde::Deserialize)]
    #[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
    enum SupervisorMessage {
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

    #[derive(Debug, Clone)]
    enum MountSourceKind {
        ReadOnly,
        ReadWrite,
    }

    struct PinnedMount {
        target: PathBuf,
        kind: MountSourceKind,
        descriptor: OwnedFd,
        is_directory: bool,
    }

    pub async fn start(
        plan: ExecutionPlan,
        baffle: BaffleRuntimeConfig,
    ) -> Result<RunningExecution, StartError> {
        plan.validate_compatibility().map_err(StartError::Setup)?;
        let supervisor = find_supervisor().map_err(StartError::Setup)?;
        let bubblewrap = find_bubblewrap().map_err(StartError::Setup)?;
        validate_bubblewrap(&bubblewrap).map_err(StartError::Setup)?;
        let profile = plan.filesystem.as_ref().ok_or_else(|| {
            StartError::Setup("Bubblewrap execution requires a filesystem profile".to_string())
        })?;
        baffle
            .validate_profile_sources(profile, None)
            .map_err(StartError::Setup)?;

        let ca_certificate = if plan.baffle_session.is_some() {
            Some(
                baffle
                    .validate_for_session()
                    .map_err(StartError::Setup)?
                    .to_path_buf(),
            )
        } else {
            None
        };

        let mut runtime = runtime_files(&plan.invocation.executable, &supervisor, profile)
            .map_err(StartError::Setup)?;
        let supervisor_runtime = runtime
            .iter_mut()
            .find(|file| file.source == supervisor && file.target == supervisor)
            .ok_or_else(|| {
                StartError::Setup(
                    "gantry-supervisor is missing from the runtime baseline".to_string(),
                )
            })?;
        supervisor_runtime.target = PathBuf::from(SUPERVISOR_TARGET);
        ensure_profile_preserves_runtime_paths(profile, &runtime)?;

        let mut mounts = Vec::new();
        for mount in &profile.mounts {
            if let FilesystemMount::Bind {
                source,
                target,
                access,
            } = mount
            {
                let descriptor = open_pinned(source, true).map_err(|error| {
                    StartError::Setup(format!(
                        "failed to pin filesystem profile source '{}': {error}",
                        source.display()
                    ))
                })?;
                let is_directory = descriptor_is_directory(descriptor.as_raw_fd())
                    .map_err(|error| StartError::Setup(error.to_string()))?;
                mounts.push(PinnedMount {
                    target: target.clone(),
                    kind: match access {
                        MountAccess::ReadOnly => MountSourceKind::ReadOnly,
                        MountAccess::ReadWrite => MountSourceKind::ReadWrite,
                    },
                    descriptor,
                    is_directory,
                });
            }
        }

        for file in runtime {
            if runtime_file_is_supplied_by_profile(profile, &file.source, &file.target)? {
                continue;
            }
            let descriptor = open_pinned(&file.source, false).map_err(|error| {
                StartError::Setup(format!(
                    "failed to pin runtime dependency '{}': {error}",
                    file.source.display()
                ))
            })?;
            let is_directory = descriptor_is_directory(descriptor.as_raw_fd())
                .map_err(|error| StartError::Setup(error.to_string()))?;
            mounts.push(PinnedMount {
                target: file.target,
                kind: MountSourceKind::ReadOnly,
                descriptor,
                is_directory,
            });
        }

        if let Some(ca_certificate) = ca_certificate.as_deref() {
            let descriptor = open_pinned(ca_certificate, true).map_err(|error| {
                StartError::Setup(format!(
                    "failed to pin the configured public Baffle CA certificate: {error}"
                ))
            })?;
            validate_public_ca_certificate(descriptor.as_raw_fd()).map_err(StartError::Setup)?;
            let is_directory = descriptor_is_directory(descriptor.as_raw_fd())
                .map_err(|error| StartError::Setup(error.to_string()))?;
            mounts.push(PinnedMount {
                target: PathBuf::from(SANDBOX_CA_CERTIFICATE),
                kind: MountSourceKind::ReadOnly,
                descriptor,
                is_directory,
            });
        }

        let mut baffle_lease: Option<BaffleSessionLease> = None;
        if let Some(filename) = plan.baffle_session.as_deref() {
            let lease = create_ephemeral_session(&baffle, filename)
                .await
                .map_err(StartError::Setup)?;
            baffle
                .validate_profile_sources(profile, Some(lease.socket_path()))
                .map_err(StartError::Setup)?;
            let descriptor = open_pinned(lease.socket_path(), true).map_err(|error| {
                StartError::Setup(format!(
                    "failed to pin the assigned Baffle data socket: {error}"
                ))
            })?;
            if !descriptor_is_socket(descriptor.as_raw_fd())
                .map_err(|error| StartError::Setup(error.to_string()))?
            {
                return Err(StartError::Setup(
                    "Baffle session data endpoint is not a Unix socket".to_string(),
                ));
            }
            mounts.push(PinnedMount {
                target: PathBuf::from(SANDBOX_SOCKET),
                kind: MountSourceKind::ReadOnly,
                descriptor,
                is_directory: false,
            });
            baffle_lease = Some(lease);
        }

        let mut inherited_mount_fds = Vec::with_capacity(mounts.len());
        for (index, mount) in mounts.iter().enumerate() {
            inherited_mount_fds.push(
                duplicate_inheritable(
                    mount.descriptor.as_raw_fd(),
                    256 + mounts.len() as RawFd + index as RawFd,
                )
                .map_err(|error| {
                    StartError::Setup(format!(
                        "failed to prepare filesystem source descriptor: {error}"
                    ))
                })?,
            );
        }

        let mut command = Command::new(&bubblewrap);
        let use_baffle_proxy = baffle_lease.is_some();
        build_bubblewrap_args(&mut command, &mounts, profile);
        command
            .arg("--")
            .arg(SUPERVISOR_TARGET)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .env_clear()
            .kill_on_drop(true);

        let source_fds = inherited_mount_fds
            .iter()
            .map(AsRawFd::as_raw_fd)
            .collect::<Vec<_>>();
        unsafe {
            command.pre_exec(move || {
                if libc::setpgid(0, 0) != 0 {
                    return Err(io::Error::last_os_error());
                }
                libc::close(3);
                for (index, source_fd) in source_fds.iter().enumerate() {
                    if libc::dup2(*source_fd, FIRST_MOUNT_FD + index as RawFd) < 0 {
                        return Err(io::Error::last_os_error());
                    }
                }
                close_fds_after(FIRST_MOUNT_FD + source_fds.len() as RawFd)?;
                Ok(())
            });
        }

        let child = command.spawn().map_err(|error| {
            StartError::Setup(format!("failed to start Bubblewrap launcher: {error}"))
        })?;
        let mut execution = RunningExecution::new_starting(child, true, baffle_lease.take());
        drop(inherited_mount_fds);
        drop(mounts);

        let stdin_result = async {
            let mut stdin = execution
                .child_mut()
                .stdin
                .take()
                .ok_or_else(|| io::Error::other("Bubblewrap launcher stdin pipe is missing"))?;
            let message = InvocationMessage {
                executable: &plan.invocation.executable,
                args: &plan.invocation.args,
                cwd: &plan.invocation.cwd,
                environment: &plan.invocation.environment,
                proxy_socket: use_baffle_proxy.then_some(Path::new(SANDBOX_SOCKET)),
            };
            let bytes = serde_json::to_vec(&message)
                .map_err(|error| io::Error::other(error.to_string()))?;
            stdin.write_all(&bytes).await?;
            stdin.shutdown().await
        }
        .await;
        if let Err(error) = stdin_result {
            terminate_launcher(execution.child_mut()).await;
            return Err(StartError::Setup(format!(
                "failed to send the authorized invocation to the Bubblewrap supervisor: {error}"
            )));
        }

        let stdout = match execution.child_mut().stdout.take() {
            Some(stdout) => stdout,
            None => {
                terminate_launcher(execution.child_mut()).await;
                return Err(StartError::Setup(
                    "Bubblewrap supervisor stdout pipe is missing".to_string(),
                ));
            }
        };
        let mut status_reader = BufReader::new(stdout);
        let mut line = String::new();
        let read_result = status_reader.read_line(&mut line).await;
        let status = match read_result {
            Ok(0) => {
                let diagnostics = launcher_diagnostics(execution.child_mut()).await;
                return Err(StartError::Setup(format!(
                    "Bubblewrap exited before the authorized command started{diagnostics}"
                )));
            }
            Ok(_) => match serde_json::from_str::<SupervisorMessage>(&line) {
                Ok(status) => status,
                Err(error) => {
                    terminate_launcher(execution.child_mut()).await;
                    return Err(StartError::Setup(format!(
                        "Bubblewrap supervisor returned an invalid startup status: {error}"
                    )));
                }
            },
            Err(error) => {
                terminate_launcher(execution.child_mut()).await;
                return Err(StartError::Setup(format!(
                    "failed to read Bubblewrap supervisor startup status: {error}"
                )));
            }
        };
        match status {
            SupervisorMessage::Started => {}
            SupervisorMessage::SetupError { error } => {
                terminate_launcher(execution.child_mut()).await;
                return Err(StartError::Setup(format!(
                    "Bubblewrap command startup failed: {error}"
                )));
            }
            _ => {
                terminate_launcher(execution.child_mut()).await;
                return Err(StartError::Setup(
                    "Bubblewrap supervisor returned an unexpected startup status".to_string(),
                ));
            }
        }

        tracing::debug!(
            executable_hash = %plan.invocation.executable_hash,
            policy_generation = plan.invocation.generation.id(),
            filesystem_profile = %profile.name,
            cwd = %plan.invocation.cwd.display(),
            "Bubblewrap supervisor started authorized invocation",
        );
        let (stdout_reader, stdout_writer) = tokio::io::duplex(16 * 1024);
        let (final_status_tx, final_status_rx) = oneshot::channel();
        tokio::spawn(async move {
            let result = forward_supervisor_output(status_reader, stdout_writer).await;
            let _ = final_status_tx.send(result);
        });
        let stdout: crate::execution::OutputReader = Box::new(stdout_reader);
        let stderr = execution
            .child_mut()
            .stderr
            .take()
            .map(|reader| Box::new(reader) as crate::execution::OutputReader);
        execution.set_streams(Some(stdout), stderr, final_status_rx);
        Ok(execution)
    }

    async fn forward_supervisor_output<R, W>(
        mut reader: R,
        mut stdout: W,
    ) -> Result<ExecutionExitStatus, io::Error>
    where
        R: AsyncBufRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        let mut line = String::new();
        loop {
            line.clear();
            if reader.read_line(&mut line).await? == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "Bubblewrap supervisor exited without command status",
                ));
            }
            match serde_json::from_str::<SupervisorMessage>(&line).map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid Bubblewrap supervisor message: {error}"),
                )
            })? {
                SupervisorMessage::Stdout { data } => {
                    let bytes = base64::engine::general_purpose::STANDARD
                        .decode(data)
                        .map_err(|error| {
                            io::Error::new(
                                io::ErrorKind::InvalidData,
                                format!("invalid encoded supervisor output: {error}"),
                            )
                        })?;
                    stdout.write_all(&bytes).await?;
                }
                SupervisorMessage::Exited { code, signal } => {
                    return ExecutionExitStatus::from_components(code, signal);
                }
                SupervisorMessage::Started | SupervisorMessage::SetupError { .. } => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "unexpected Bubblewrap supervisor status after command startup",
                    ));
                }
            }
        }
    }

    fn build_bubblewrap_args(
        command: &mut Command,
        mounts: &[PinnedMount],
        profile: &crate::filesystem::FilesystemProfile,
    ) {
        let mut directories = BTreeSet::new();
        directories.insert(PathBuf::from("/etc"));
        for mount in mounts {
            if mount.is_directory {
                directories.insert(mount.target.clone());
            }
            add_parent_directories(&mut directories, &mount.target);
        }
        add_parent_directories(&mut directories, Path::new(SUPERVISOR_TARGET));
        directories.remove(Path::new("/proc"));
        directories.remove(Path::new("/dev"));
        directories.remove(Path::new("/run"));
        directories.remove(Path::new("/tmp"));

        command
            .arg("--unshare-user")
            .arg("--unshare-pid")
            .arg("--unshare-net")
            .arg("--unshare-ipc")
            .arg("--unshare-uts")
            .arg("--new-session")
            .arg("--die-with-parent")
            .arg("--as-pid-1")
            .arg("--cap-drop")
            .arg("ALL")
            .arg("--clearenv");

        for directory in directories {
            command.arg("--dir").arg(directory);
        }

        command
            .arg("--dev")
            .arg("/dev")
            .arg("--proc")
            .arg("/proc")
            .arg("--tmpfs")
            .arg("/run");
        if mounts
            .iter()
            .any(|mount| mount.target.starts_with("/run/gantry"))
        {
            command.arg("--dir").arg("/run/gantry");
        }

        let mut has_tmpfs = false;
        for mount in &profile.mounts {
            if let FilesystemMount::Tmpfs { target, size_bytes } = mount {
                command.arg("--size").arg(size_bytes.to_string());
                command.arg("--tmpfs").arg(target);
                if target == Path::new("/tmp") {
                    has_tmpfs = true;
                }
            }
        }
        if !has_tmpfs {
            command.arg("--tmpfs").arg("/tmp");
        }

        for (index, mount) in mounts.iter().enumerate() {
            if mount.is_directory {
                command.arg("--dir").arg(&mount.target);
            }
            let flag = match mount.kind {
                MountSourceKind::ReadOnly => "--ro-bind-fd",
                MountSourceKind::ReadWrite => "--bind-fd",
            };
            command
                .arg(flag)
                .arg((FIRST_MOUNT_FD + index as RawFd).to_string())
                .arg(&mount.target);
        }

        command.arg("--chdir").arg("/");
    }

    fn add_parent_directories(directories: &mut BTreeSet<PathBuf>, target: &Path) {
        let mut parents = target
            .ancestors()
            .skip(1)
            .filter(|path| *path != Path::new("/"));
        let mut collected = parents.by_ref().map(Path::to_path_buf).collect::<Vec<_>>();
        collected.reverse();
        directories.extend(collected);
    }

    fn ensure_profile_preserves_runtime_paths(
        profile: &crate::filesystem::FilesystemProfile,
        runtime: &[crate::backend::runtime::RuntimeFile],
    ) -> Result<(), StartError> {
        for file in runtime {
            for mount in &profile.mounts {
                let FilesystemMount::Bind { source, target, .. } = mount else {
                    continue;
                };
                if !file.target.starts_with(target) {
                    continue;
                }
                let relative = file.target.strip_prefix(target).map_err(|error| {
                    StartError::Setup(format!("invalid runtime mount mapping: {error}"))
                })?;
                let supplied = source.join(relative);
                let expected = fs::canonicalize(&file.source).ok();
                let actual = fs::canonicalize(&supplied).ok();
                if expected.is_none() || expected != actual {
                    return Err(StartError::Setup(format!(
                        "filesystem profile '{}' would replace required runtime path '{}' with different content",
                        profile.name,
                        file.target.display()
                    )));
                }
            }
        }
        Ok(())
    }

    fn runtime_file_is_supplied_by_profile(
        profile: &crate::filesystem::FilesystemProfile,
        source: &Path,
        target: &Path,
    ) -> Result<bool, StartError> {
        for mount in &profile.mounts {
            let FilesystemMount::Bind {
                source: profile_source,
                target: profile_target,
                ..
            } = mount
            else {
                continue;
            };
            if !target.starts_with(profile_target) {
                continue;
            }
            let relative = target.strip_prefix(profile_target).map_err(|error| {
                StartError::Setup(format!("invalid runtime mount mapping: {error}"))
            })?;
            let supplied = profile_source.join(relative);
            return Ok(fs::canonicalize(&supplied).ok() == fs::canonicalize(source).ok());
        }
        Ok(false)
    }

    fn find_bubblewrap() -> Result<PathBuf, String> {
        ["/usr/bin/bwrap", "/bin/bwrap"]
            .into_iter()
            .map(PathBuf::from)
            .find(|path| path.is_file())
            .ok_or_else(|| {
                "Bubblewrap executable was not found at /usr/bin/bwrap or /bin/bwrap".to_string()
            })
    }

    fn validate_bubblewrap(path: &Path) -> Result<(), String> {
        let version = std::process::Command::new(path)
            .arg("--version")
            .env_clear()
            .output()
            .map_err(|error| format!("failed to query Bubblewrap capabilities: {error}"))?;
        if !version.status.success() {
            return Err(format!(
                "Bubblewrap capability query failed with status {}",
                version.status
            ));
        }
        let help = std::process::Command::new(path)
            .arg("--help")
            .env_clear()
            .output()
            .map_err(|error| format!("failed to query Bubblewrap capabilities: {error}"))?;
        let help = String::from_utf8_lossy(&help.stdout);
        for required in ["--ro-bind-fd", "--bind-fd", "--unshare-net", "--as-pid-1"] {
            if !help.contains(required) {
                return Err(format!(
                    "Bubblewrap does not support required capability {required}"
                ));
            }
        }
        Ok(())
    }

    fn find_supervisor() -> Result<PathBuf, String> {
        let current = std::env::current_exe()
            .map_err(|error| format!("failed to locate Gantry executable: {error}"))?;
        let mut candidates = Vec::new();
        if let Some(parent) = current.parent() {
            candidates.push(parent.join("gantry-supervisor"));
            if let Some(grandparent) = parent.parent() {
                candidates.push(grandparent.join("gantry-supervisor"));
            }
        }
        candidates
            .into_iter()
            .find(|path| path.is_file())
            .ok_or_else(|| {
                "gantry-supervisor was not found beside Gantry; install both binaries together"
                    .to_string()
            })
    }

    fn open_pinned(path: &Path, reject_symlinks: bool) -> io::Result<OwnedFd> {
        use std::os::unix::ffi::OsStrExt;

        let path = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains a NUL byte"))?;
        let fd = if reject_symlinks {
            let mut how: libc::open_how = unsafe { std::mem::zeroed() };
            how.flags = (libc::O_PATH | libc::O_CLOEXEC) as u64;
            how.resolve = libc::RESOLVE_NO_SYMLINKS | libc::RESOLVE_NO_MAGICLINKS;
            unsafe {
                libc::syscall(
                    libc::SYS_openat2,
                    libc::AT_FDCWD,
                    path.as_ptr(),
                    &how,
                    std::mem::size_of::<libc::open_how>(),
                ) as RawFd
            }
        } else {
            unsafe { libc::open(path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) }
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }

    fn descriptor_is_directory(fd: RawFd) -> io::Result<bool> {
        let mut stat = MaybeUninit::<libc::stat>::uninit();
        if unsafe { libc::fstat(fd, stat.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let stat = unsafe { stat.assume_init() };
        match stat.st_mode & libc::S_IFMT {
            libc::S_IFDIR => Ok(true),
            libc::S_IFREG => Ok(false),
            libc::S_IFSOCK => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "runtime bind source is a Unix socket",
            )),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "mount source must be a regular file or directory",
            )),
        }
    }

    fn descriptor_is_socket(fd: RawFd) -> io::Result<bool> {
        let mut stat = MaybeUninit::<libc::stat>::uninit();
        if unsafe { libc::fstat(fd, stat.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let stat = unsafe { stat.assume_init() };
        Ok(stat.st_mode & libc::S_IFMT == libc::S_IFSOCK)
    }

    fn validate_public_ca_certificate(fd: RawFd) -> Result<(), String> {
        let contents = fs::read(format!("/proc/self/fd/{fd}")).map_err(|error| {
            format!("failed to read the configured Baffle CA certificate: {error}")
        })?;
        let text = std::str::from_utf8(&contents)
            .map_err(|_| "configured Baffle CA certificate is not UTF-8 PEM".to_string())?;
        if text.contains("PRIVATE KEY") {
            return Err(
                "configured Baffle CA file contains private key material; only public certificates can be mounted".to_string(),
            );
        }

        let mut remainder = text.trim();
        let mut certificates = 0;
        while !remainder.is_empty() {
            let Some(block) = remainder.strip_prefix("-----BEGIN CERTIFICATE-----") else {
                return Err(
                    "configured Baffle CA file must contain only public certificate PEM blocks"
                        .to_string(),
                );
            };
            let end = block.find("-----END CERTIFICATE-----").ok_or_else(|| {
                "configured Baffle CA certificate has an incomplete PEM block".to_string()
            })?;
            remainder = block[end + "-----END CERTIFICATE-----".len()..].trim();
            certificates += 1;
        }
        if certificates == 0 {
            return Err(
                "configured Baffle CA file must contain at least one public certificate"
                    .to_string(),
            );
        }
        Ok(())
    }

    fn duplicate_inheritable(fd: RawFd, minimum: RawFd) -> io::Result<OwnedFd> {
        let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, minimum) };
        if duplicate < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(unsafe { OwnedFd::from_raw_fd(duplicate) })
    }

    unsafe fn close_fds_after(first: RawFd) -> io::Result<()> {
        let result = unsafe { libc::syscall(libc::SYS_close_range, first as u32, u32::MAX, 0u32) };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    async fn terminate_launcher(child: &mut tokio::process::Child) {
        if let Some(pid) = child.id() {
            unsafe {
                libc::kill(-(pid as libc::pid_t), libc::SIGKILL);
            }
        }
        let _ = child.start_kill();
        let _ = child.wait().await;
    }

    async fn launcher_diagnostics(child: &mut tokio::process::Child) -> String {
        if let Some(mut stderr) = child.stderr.take() {
            let mut message = String::new();
            let _ = stderr.read_to_string(&mut message).await;
            let _ = child.wait().await;
            if message.trim().is_empty() {
                String::new()
            } else {
                format!(": {}", message.trim())
            }
        } else {
            let _ = child.wait().await;
            String::new()
        }
    }
}

#[cfg(target_os = "linux")]
pub(super) use linux::start;

#[cfg(not(target_os = "linux"))]
pub(super) async fn start(
    _plan: crate::execution::ExecutionPlan,
    _baffle: crate::baffle::BaffleRuntimeConfig,
) -> Result<crate::execution::RunningExecution, crate::backend::StartError> {
    Err(crate::backend::StartError::Setup(
        "Bubblewrap execution is supported only on Linux".to_string(),
    ))
}
