#![cfg(unix)]
use std::{fs, os::unix::fs::PermissionsExt, process::Command};

#[test]
fn omitted_root_uses_current_directory() {
    let root = tempfile::tempdir().unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_quicsyncd"))
        .current_dir(root.path())
        .arg("init")
        .output()
        .unwrap();
    assert!(result.status.success(), "{:?}", result.stderr);
    assert!(root.path().join(".quicsync/identity.key").is_file());
}

#[test]
fn help_version_and_invalid_arguments() {
    for args in [vec!["--help"], vec!["--version"], vec!["serve", "--help"]] {
        let result = Command::new(env!("CARGO_BIN_EXE_quicsyncd"))
            .args(args)
            .output()
            .unwrap();
        assert!(result.status.success());
        assert!(!result.stdout.is_empty());
    }
    for args in [vec![], vec!["unknown"], vec!["init", ".", "extra"]] {
        let result = Command::new(env!("CARGO_BIN_EXE_quicsyncd"))
            .args(args)
            .output()
            .unwrap();
        assert_eq!(result.status.code(), Some(2));
    }
}

#[test]
fn init_prints_a_stable_configuration_pin_and_creates_private_identity() {
    let root = tempfile::tempdir().unwrap();
    let init = || {
        Command::new(env!("CARGO_BIN_EXE_quicsyncd"))
            .arg("init")
            .arg(root.path())
            .output()
            .unwrap()
    };
    let first = init();
    assert!(first.status.success(), "{:?}", first.stderr);
    let pin = String::from_utf8(first.stdout.clone()).unwrap();
    assert_eq!(pin.trim().len(), 64);
    assert!(pin.trim().bytes().all(|b| b.is_ascii_hexdigit()));
    assert_eq!(first.stdout, init().stdout);
    assert_eq!(
        fs::metadata(root.path().join(".quicsync/identity.key"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
}

#[test]
fn missing_configuration_fails_without_starting_an_attempt() {
    let root = tempfile::tempdir().unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_quicsyncd"))
        .arg("serve")
        .arg(root.path())
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(!result.stderr.is_empty());
}
