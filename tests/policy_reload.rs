#![cfg(unix)]

use gantry::{PolicyEngine, PolicyMode};
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::Duration;
use tempfile::tempdir;

fn write_decision(policy_dir: &Path, allow: bool) {
    fs::write(
        policy_dir.join("main.rego"),
        format!(
            "package sandbox.main\ndecision := {{\"allow\": {allow}, \"filesystem\": null, \"baffle_session\": null}}\n"
        ),
    )
    .expect("write policy decision");
}

fn validate(engine: &PolicyEngine) -> Result<(), gantry::ValidationError> {
    engine.validate_invocation("echo", "/usr/bin/echo", "hash", &[], &BTreeMap::new(), "/")
}

fn create_gate(path: &Path) {
    let path_c = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(path_c.as_ptr(), 0o600) }, 0);
}

#[test]
fn policy_changed_during_load_is_not_published_with_its_new_fingerprint() {
    let root = tempdir().unwrap();
    let policies = root.path().join("policies");
    fs::create_dir(&policies).unwrap();
    let main = policies.join("main.rego");
    write_decision(&policies, true);

    // Sorting makes the loader capture main.rego before it blocks on this FIFO.
    let gate = policies.join("zz-gate.rego");
    create_gate(&gate);
    let main_for_writer = main.clone();
    let gate_for_writer = gate.clone();
    let writer = thread::spawn(move || {
        let mut handle = fs::OpenOptions::new()
            .write(true)
            .open(&gate_for_writer)
            .unwrap();
        write_decision(main_for_writer.parent().unwrap(), false);
        fs::remove_file(&gate_for_writer).unwrap();
        fs::write(&gate_for_writer, "package gate\nx := true\n").unwrap();
        handle.write_all(b"package gate\nx := true\n").unwrap();
    });

    let engine = PolicyEngine::from_sources(Some(policies));
    writer.join().unwrap();

    assert!(
        validate(&engine).is_err(),
        "the changed deny policy must not reuse the captured allow policy"
    );
    assert!(
        validate(&engine).is_err(),
        "subsequent requests must remain denied"
    );
}

#[test]
fn concurrent_reload_does_not_let_an_older_load_overwrite_a_newer_one() {
    let root = tempdir().unwrap();
    let policies = root.path().join("policies");
    fs::create_dir(&policies).unwrap();
    write_decision(&policies, true);
    let engine = Arc::new(PolicyEngine::from_sources(Some(policies.clone())));

    let gate = policies.join("zz-gate.rego");
    create_gate(&gate);
    let (writer_opened_tx, writer_opened_rx) = mpsc::channel();
    let (release_writer_tx, release_writer_rx) = mpsc::channel();
    let gate_for_writer = gate.clone();
    let writer = thread::spawn(move || {
        let mut handle = fs::OpenOptions::new()
            .write(true)
            .open(&gate_for_writer)
            .unwrap();
        writer_opened_tx.send(()).unwrap();
        release_writer_rx.recv().unwrap();
        handle.write_all(b"package gate\nx := true\n").unwrap();
    });

    let old_engine = Arc::clone(&engine);
    let older_reload = thread::spawn(move || old_engine.reload());
    writer_opened_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("older load should reach the FIFO after reading main.rego");

    write_decision(&policies, false);
    fs::remove_file(&gate).unwrap();
    fs::write(&gate, "package gate\nx := true\n").unwrap();

    let (newer_done_tx, newer_done_rx) = mpsc::channel();
    let new_engine = Arc::clone(&engine);
    let newer_reload = thread::spawn(move || {
        new_engine.reload();
        newer_done_tx.send(()).unwrap();
    });
    let newer_finished_before_release = newer_done_rx
        .recv_timeout(Duration::from_millis(500))
        .is_ok();

    release_writer_tx.send(()).unwrap();
    writer.join().unwrap();
    older_reload.join().unwrap();
    newer_reload.join().unwrap();

    assert!(
        !newer_finished_before_release,
        "reload publication should be serialized behind the older in-flight load"
    );
    assert_eq!(engine.mode(), PolicyMode::Rego);
    assert!(
        validate(&engine).is_err(),
        "the newest deny policy must be active"
    );
}
