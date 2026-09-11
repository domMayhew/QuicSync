#![cfg(unix)]

use std::{
    fs::{self, File},
    os::unix::fs::{MetadataExt, symlink},
    path::Path,
};

use quicsync_core::{
    config::{DEFAULT_LIMITS, Limits},
    error::ErrorCode,
    filesystem::paths::{RootHandle, decode_relative_path, resolve_parent},
    types::RelativePath,
};
use tempfile::TempDir;

fn limits() -> Limits {
    DEFAULT_LIMITS
}

fn components(path: &RelativePath) -> Vec<&[u8]> {
    path.components()
        .iter()
        .map(|component| component.as_slice())
        .collect()
}

fn identity(path: &Path) -> (u64, u64) {
    let metadata = fs::metadata(path).unwrap();
    (metadata.dev(), metadata.ino())
}

#[test]
fn supported_relative_paths_decode_into_components() {
    let path = decode_relative_path(b"src/lib/main.rs", &limits()).unwrap();

    assert_eq!(components(&path), [b"src".as_slice(), b"lib", b"main.rs"]);
}

#[test]
fn decoding_preserves_non_utf8_component_bytes() {
    let path = decode_relative_path(b"dir/\xff\xfe", &limits()).unwrap();

    assert_eq!(components(&path), [b"dir".as_slice(), b"\xff\xfe"]);
}

#[test]
fn absolute_and_traversing_paths_are_invalid() {
    for wire in [
        b"/etc/passwd".as_slice(),
        b"/",
        b"..",
        b"../outside",
        b"src/../../outside",
        b".",
        b"src/./main.rs",
        b"",
        b"src//main.rs",
        b"src/",
        b"src/\0/main.rs",
    ] {
        let error = decode_relative_path(wire, &limits()).unwrap_err();
        assert_eq!(
            error.code(),
            ErrorCode::InvalidPath,
            "{:?} must be rejected as an invalid path",
            String::from_utf8_lossy(wire),
        );
    }
}

#[test]
fn protected_administrative_paths_are_denied() {
    for wire in [
        b".quicsync".as_slice(),
        b".quicsync/state.sqlite",
        b".git",
        b".git/config",
        b"nested/.git/config",
        b"nested/.quicsync/staging",
    ] {
        let error = decode_relative_path(wire, &limits()).unwrap_err();
        assert_eq!(
            error.code(),
            ErrorCode::PathConfinementViolation,
            "{:?} must be denied as a protected path",
            String::from_utf8_lossy(wire),
        );
    }
}

#[test]
fn decoding_enforces_configured_path_limits() {
    let long = vec![b'a'; limits().max_path_bytes() + 1];
    let deep = (0..=limits().max_components())
        .map(|_| "a")
        .collect::<Vec<_>>()
        .join("/");

    for wire in [long.as_slice(), deep.as_bytes()] {
        assert_eq!(
            decode_relative_path(wire, &limits()).unwrap_err().code(),
            ErrorCode::ResourceLimitExceeded,
        );
    }
}

#[test]
fn resolution_confines_supported_paths_to_the_root() {
    let root = TempDir::new().unwrap();
    fs::create_dir_all(root.path().join("src/lib")).unwrap();
    let handle = RootHandle::open(root.path()).unwrap();

    let leaf = decode_relative_path(b"src/lib/main.rs", &limits()).unwrap();
    let parent = resolve_parent(&handle, &leaf).unwrap();

    assert_eq!(parent.leaf(), b"main.rs");
    assert_eq!(
        parent.filesystem_identity().unwrap(),
        identity(&root.path().join("src/lib")),
    );
}

#[test]
fn a_single_component_resolves_against_the_root_itself() {
    let root = TempDir::new().unwrap();
    let handle = RootHandle::open(root.path()).unwrap();

    let parent = resolve_parent(
        &handle,
        &decode_relative_path(b"README.md", &limits()).unwrap(),
    )
    .unwrap();

    assert_eq!(parent.leaf(), b"README.md");
    assert_eq!(
        parent.filesystem_identity().unwrap(),
        handle.filesystem_identity().unwrap(),
    );
    assert_eq!(parent.filesystem_identity().unwrap(), identity(root.path()));
}

#[test]
fn resolution_refuses_to_follow_a_symlinked_ancestor() {
    let root = TempDir::new().unwrap();
    let outside = TempDir::new().unwrap();
    fs::create_dir(outside.path().join("secrets")).unwrap();
    fs::create_dir(root.path().join("inside")).unwrap();
    symlink(outside.path(), root.path().join("escape")).unwrap();
    symlink(root.path().join("inside"), root.path().join("loop")).unwrap();
    let handle = RootHandle::open(root.path()).unwrap();

    for wire in [
        b"escape/secrets/file".as_slice(),
        b"escape/file",
        b"loop/file",
    ] {
        let path = decode_relative_path(wire, &limits()).unwrap();
        let error = resolve_parent(&handle, &path).unwrap_err();
        assert_eq!(
            error.code(),
            ErrorCode::PathConfinementViolation,
            "{:?} must not resolve through a symbolic link",
            String::from_utf8_lossy(wire),
        );
    }
}

#[test]
fn resolution_requires_every_ancestor_to_be_a_directory() {
    let root = TempDir::new().unwrap();
    File::create(root.path().join("file")).unwrap();
    let handle = RootHandle::open(root.path()).unwrap();

    let path = decode_relative_path(b"file/child", &limits()).unwrap();

    assert_eq!(
        resolve_parent(&handle, &path).unwrap_err().code(),
        ErrorCode::PathConfinementViolation,
    );
}

#[test]
fn resolution_reports_a_missing_ancestor_as_an_io_failure() {
    let root = TempDir::new().unwrap();
    let handle = RootHandle::open(root.path()).unwrap();

    let path = decode_relative_path(b"absent/child", &limits()).unwrap();

    assert_eq!(
        resolve_parent(&handle, &path).unwrap_err().code(),
        ErrorCode::Io,
    );
}

#[test]
fn resolution_denies_protected_paths_from_any_source() {
    let root = TempDir::new().unwrap();
    fs::create_dir(root.path().join(".git")).unwrap();
    let handle = RootHandle::open(root.path()).unwrap();

    let path = RelativePath::new(vec![b".git".to_vec(), b"config".to_vec()]).unwrap();

    assert_eq!(
        resolve_parent(&handle, &path).unwrap_err().code(),
        ErrorCode::PathConfinementViolation,
    );
}

#[test]
fn opening_a_root_requires_a_real_directory() {
    let root = TempDir::new().unwrap();
    File::create(root.path().join("file")).unwrap();
    symlink(root.path(), root.path().join("link")).unwrap();

    for path in ["file", "link", "absent"] {
        assert_eq!(
            RootHandle::open(&root.path().join(path))
                .unwrap_err()
                .code(),
            ErrorCode::InvalidConfiguration,
        );
    }
}

#[test]
fn resolved_paths_carry_their_context_on_failure() {
    let root = TempDir::new().unwrap();
    let handle = RootHandle::open(root.path()).unwrap();
    let path = decode_relative_path(b"absent/child", &limits()).unwrap();

    let error = resolve_parent(&handle, &path).unwrap_err();

    assert_eq!(error.context().path(), Some(&path));
}
