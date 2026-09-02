//! Behavioural suite for the real [`SandboxedHostExecutor`] (KRN-002).
//!
//! These tests touch the real filesystem but only inside throwaway temporary
//! directories, and assert the sandbox refuses every path that would escape:
//! lexical `..`, symlinks that resolve outside, and non-file leaves. They also
//! pin the process and network semantics: a spawn runs only an in-sandbox
//! absolute program with no shell, and network configuration is denied.

use std::path::PathBuf;

use atom_privd::{ExecError, HostExecutor, HostOp, OpOutcome, SandboxedHostExecutor};

/// A fresh sandbox roots at a unique temporary directory.
fn sandbox() -> (SandboxedHostExecutor, PathBuf) {
    let root = std::env::temp_dir().join(format!(
        "atom-sandbox-test-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).expect("create sandbox root");
    let executor = SandboxedHostExecutor::new(&root).expect("sandbox opens");
    (executor, root)
}

fn tidy(root: &PathBuf) {
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn write_read_round_trip_lives_inside_the_sandbox() {
    let (mut executor, root) = sandbox();
    let outcome = executor
        .execute(&HostOp::WriteFile {
            path: "/data/app.conf".into(),
            contents: "key = value\n".into(),
        })
        .expect("write inside the sandbox succeeds");
    assert_eq!(outcome.op_kind, "write_file");
    assert_eq!(
        std::fs::read_to_string(root.join("data/app.conf")).expect("file exists on disk"),
        "key = value\n"
    );
    let from_root = root.join("app.conf");
    assert!(!from_root.exists(), "file must not appear at the root");

    let remove = executor
        .execute(&HostOp::RemoveFile {
            path: "/data/app.conf".into(),
        })
        .expect("remove inside the sandbox succeeds");
    assert_eq!(remove.op_kind, "remove_file");
    assert!(!root.join("data/app.conf").exists());
    tidy(&root);
}

#[test]
fn traversal_outside_the_sandbox_is_refused() {
    let (mut executor, root) = sandbox();
    let escape = root
        .parent()
        .expect("temp dir has a parent")
        .join("pwned.txt");
    let _ = std::fs::remove_file(&escape);
    let err = executor
        .execute(&HostOp::WriteFile {
            path: "/../pwned.txt".into(),
            contents: "escaped".into(),
        })
        .expect_err("`..` traversal must be refused");
    assert!(matches!(err, ExecError { .. }));
    assert!(!escape.exists(), "no file may appear outside the sandbox");
    tidy(&root);
}

#[test]
fn symlink_pointing_outside_is_refused_for_write() {
    use std::os::unix::fs::symlink;
    let (mut executor, root) = sandbox();
    let outside = root
        .parent()
        .expect("temp dir has a parent")
        .join("target.txt");
    std::fs::write(&outside, "original").expect("seed outside file");
    symlink(&outside, root.join("hole")).expect("plant a symlink out of the sandbox");

    let err = executor
        .execute(&HostOp::WriteFile {
            path: "/hole".into(),
            contents: "overwrite".into(),
        })
        .expect_err("writing through an escaping symlink must be refused");
    assert!(matches!(err, ExecError { .. }));
    assert_eq!(
        std::fs::read_to_string(&outside).expect("outside file is read"),
        "original",
        "the outside file must be untouched"
    );
    let _ = std::fs::remove_file(&outside);
    tidy(&root);
}

#[test]
fn symlink_pointing_outside_is_refused_for_remove() {
    use std::os::unix::fs::symlink;
    let (mut executor, root) = sandbox();
    let outside = root
        .parent()
        .expect("temp dir has a parent")
        .join("victim.txt");
    std::fs::write(&outside, "precious").expect("seed outside file");
    symlink(&outside, root.join("trap")).expect("plant a symlink out of the sandbox");

    let err = executor
        .execute(&HostOp::RemoveFile {
            path: "/trap".into(),
        })
        .expect_err("removing through an escaping symlink must be refused");
    assert!(matches!(err, ExecError { .. }));
    assert_eq!(
        std::fs::read_to_string(&outside).expect("outside file is read"),
        "precious",
        "the outside file must be untouched"
    );
    let _ = std::fs::remove_file(&outside);
    tidy(&root);
}

#[test]
fn directory_is_cannot_be_removed_by_remove_file() {
    let (mut executor, root) = sandbox();
    std::fs::create_dir_all(root.join("subdir")).expect("seed a directory");
    let err = executor
        .execute(&HostOp::RemoveFile {
            path: "/subdir".into(),
        })
        .expect_err("removing a directory with remove_file must be refused");
    assert!(matches!(err, ExecError { .. }));
    assert!(root.join("subdir").is_dir(), "directory must survive");
    tidy(&root);
}

#[test]
fn spawn_runs_only_an_in_sandbox_program_without_a_shell() {
    use std::os::unix::fs::PermissionsExt;

    let (mut executor, root) = sandbox();
    let script = root.join("probe.sh");
    std::fs::write(&script, "#!/bin/sh\necho \"ran:$1\"\n").expect("write probe program");
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755))
        .expect("make probe executable");

    let err = executor
        .execute(&HostOp::SpawnProcess {
            program: "/usr/bin/env".into(),
            args: vec!["./probe.sh".into()],
        })
        .expect_err("a program outside the sandbox must be refused");
    assert!(matches!(err, ExecError { .. }));

    let outcome = executor
        .execute(&HostOp::SpawnProcess {
            program: "/probe.sh".into(),
            args: vec!["hello".into()],
        })
        .expect("an in-sandbox program spawns");
    assert_eq!(outcome.op_kind, "spawn_process");
    assert!(
        outcome.detail.contains("ran:hello"),
        "captured stdout must be visible in the detail: {}",
        outcome.detail
    );
    tidy(&root);
}

#[test]
fn configure_network_is_deny_by_default() {
    let (mut executor, root) = sandbox();
    let err = executor
        .execute(&HostOp::ConfigureNetwork {
            interface: "eth0".into(),
            allow_cidr: "10.0.0.0/24".into(),
        })
        .expect_err("network configuration must be refused by the sandbox");
    assert!(matches!(err, ExecError { .. }));
    tidy(&root);
}

#[test]
fn sandbox_root_resolves_symlinks_once_at_construction() {
    use std::os::unix::fs::symlink;
    let base = std::env::temp_dir().join(format!(
        "atom-sandbox-link-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&base);
    let real = base.join("real");
    std::fs::create_dir_all(&real).expect("create real root");
    let alias = base.join("alias");
    symlink(&real, &alias).expect("alias the root");

    let mut executor =
        SandboxedHostExecutor::new(&alias).expect("sandbox opens via a symlinked root");
    assert!(executor.root().is_absolute(), "root is canonical");
    assert!(
        !executor.root().ends_with("alias"),
        "root must be the canonical target, not the alias: {}",
        executor.root().display()
    );

    // The sandbox resolves its configuration against the canonical root, so a
    // write lands inside the real target.
    executor
        .execute(&HostOp::WriteFile {
            path: "/marker.txt".into(),
            contents: "x".into(),
        })
        .expect("write through a symlinked root succeeds");
    assert!(
        real.join("marker.txt").exists(),
        "file lands in the real root"
    );
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn outcome_kind_matches_the_op() {
    let (mut executor, root) = sandbox();
    let outcome: OpOutcome = executor
        .execute(&HostOp::WriteFile {
            path: "/a.txt".into(),
            contents: "a".into(),
        })
        .expect("write succeeds");
    assert_eq!(outcome.op_kind, "write_file");
    tidy(&root);
}
