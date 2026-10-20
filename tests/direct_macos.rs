#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::fs;
use std::os::unix::fs::symlink;
use std::path::Path;

use gantry::{
    ExecutionBackend, PolicyEngine, RunCommandInput, check_command_with_backend,
    run_command_with_backend,
};

fn temp_root() -> tempfile::TempDir {
    #[cfg(target_os = "macos")]
    let base = Path::new("/private/tmp");
    #[cfg(target_os = "linux")]
    let base = Path::new("/tmp");

    tempfile::tempdir_in(base).expect("create CWD integration fixture")
}

fn direct_input(cwd: &str) -> RunCommandInput {
    RunCommandInput {
        executable: "/bin/sh".to_string(),
        args: vec!["-c".to_string(), "test -f authorized-marker".to_string()],
        cwd: Some(cwd.to_string()),
        env: None,
    }
}

#[tokio::test]
async fn direct_executes_in_trusted_cwd_and_rejects_unsafe_cwds() {
    let temp = temp_root();
    let root = temp.path();
    let policies = root.join("policies");
    let filesystems = root.join("filesystems");
    let work = root.join("work");
    fs::create_dir_all(&policies).expect("create policy directory");
    fs::create_dir_all(&filesystems).expect("create filesystems directory");
    fs::create_dir(&work).expect("create requested CWD");
    fs::write(work.join("authorized-marker"), b"marker").expect("write CWD marker");
    let work_label = work.to_string_lossy().into_owned();
    fs::write(
        policies.join("main.rego"),
        format!(
            "package sandbox.main\n\ndefault decision := {{\"allow\": false, \"filesystem\": null, \"baffle_session\": null}}\ndecision := {{\"allow\": true, \"filesystem\": null, \"baffle_session\": null}} if {{\n  input.command == \"/bin/sh\"\n  input.cwd == {}\n}}\n",
            serde_json::to_string(&work_label).expect("encode authorized CWD")
        ),
    )
    .expect("write allow policy");

    let not_directory = root.join("not-directory");
    fs::write(&not_directory, b"file").expect("write non-directory fixture");
    let symlink_cwd = root.join("symlink");
    symlink(&work, &symlink_cwd).expect("create CWD symlink");

    let policy_engine = PolicyEngine::from_sources(Some(policies));
    let repeated_slashes = format!("{work_label}//");
    let decision = check_command_with_backend(
        &policy_engine,
        &work,
        ExecutionBackend::Direct,
        direct_input(&repeated_slashes),
    );
    assert!(decision.allowed, "{:?}", decision.reason);
    assert_eq!(decision.cwd.as_deref(), Some(work_label.as_str()));

    let output = run_command_with_backend(
        &policy_engine,
        &work,
        ExecutionBackend::Direct,
        direct_input(&work_label),
    )
    .await
    .expect("Direct command should start in the authorized CWD");
    assert_eq!(output.exit_code, Some(0), "{}", output.stderr);

    let invalid_cwds = [
        "//foo".to_string(),
        "relative".to_string(),
        format!("{}/./work", root.display()),
        format!("{}/../work", root.display()),
        symlink_cwd.to_string_lossy().into_owned(),
        symlink_cwd.join("child").to_string_lossy().into_owned(),
        root.join("missing").to_string_lossy().into_owned(),
        not_directory.to_string_lossy().into_owned(),
    ];
    for cwd in invalid_cwds {
        let decision = check_command_with_backend(
            &policy_engine,
            &work,
            ExecutionBackend::Direct,
            direct_input(&cwd),
        );
        assert!(!decision.allowed, "CWD {cwd:?} should be rejected");
        assert!(decision.cwd.is_none(), "CWD {cwd:?} must not reach policy");
        assert!(decision.resolved_path.is_none());
        assert!(decision.hash.is_none());
    }
}
