#![cfg(unix)]

use quicsync_core::{
    filesystem::{paths::RootHandle, staging::StagedFile},
    types::{EntryKind, EntryMetadata, RelativePath},
};
use std::{
    fs,
    io::{self, Read},
    os::unix::fs::{PermissionsExt, symlink},
};
use tempfile::TempDir;

fn path(name: &str) -> RelativePath {
    RelativePath::new(name.split('/').map(|p| p.as_bytes().to_vec()).collect()).unwrap()
}
fn metadata() -> EntryMetadata {
    EntryMetadata::new(EntryKind::RegularFile, 0o751, 10_000_000_000, 999)
}

#[test]
fn completed_content_installs_without_a_result_size_or_digest_check() {
    let directory = TempDir::new().unwrap();
    fs::write(directory.path().join("file"), b"basis").unwrap();
    let root = RootHandle::open(directory.path()).unwrap();
    let staged = StagedFile::receive(&root, b"new bytes".as_slice()).unwrap();
    assert_eq!(fs::read(directory.path().join("file")).unwrap(), b"basis");
    // Metadata size is deliberately unrelated: staging does not verify reconstructed size.
    staged.install(&root, &path("file"), metadata()).unwrap();
    assert_eq!(
        fs::read(directory.path().join("file")).unwrap(),
        b"new bytes"
    );
    let status = fs::metadata(directory.path().join("file")).unwrap();
    assert_eq!(status.permissions().mode() & 0o777, 0o751);
    assert_eq!(
        status
            .modified()
            .unwrap()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        10
    );
    assert_eq!(
        fs::read_dir(directory.path().join(".quicsync"))
            .unwrap()
            .count(),
        0
    );
}

#[test]
fn interrupted_input_does_not_install_and_removes_its_temporary_file() {
    struct Interrupted(bool);
    impl Read for Interrupted {
        fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
            if self.0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "transfer reset",
                ));
            }
            self.0 = true;
            bytes[0] = 42;
            Ok(1)
        }
    }
    let directory = TempDir::new().unwrap();
    fs::write(directory.path().join("file"), b"basis").unwrap();
    let root = RootHandle::open(directory.path()).unwrap();
    assert!(StagedFile::receive(&root, Interrupted(false)).is_err());
    assert_eq!(fs::read(directory.path().join("file")).unwrap(), b"basis");
    assert_eq!(
        fs::read_dir(directory.path().join(".quicsync"))
            .unwrap()
            .count(),
        0
    );
}

#[test]
fn installation_confines_paths_and_staging_does_not_follow_links() {
    let directory = TempDir::new().unwrap();
    let outside = TempDir::new().unwrap();
    let root = RootHandle::open(directory.path()).unwrap();
    symlink(outside.path(), directory.path().join(".quicsync")).unwrap();
    assert!(StagedFile::receive(&root, b"x".as_slice()).is_err());
    fs::remove_file(directory.path().join(".quicsync")).unwrap();
    symlink(outside.path(), directory.path().join("escape")).unwrap();
    let staged = StagedFile::receive(&root, b"x".as_slice()).unwrap();
    assert!(
        staged
            .install(&root, &path("escape/file"), metadata())
            .is_err()
    );
    assert!(!outside.path().join("file").exists());
    let staged = StagedFile::receive(&root, b"x".as_slice()).unwrap();
    assert!(staged.install(&root, &path(".git"), metadata()).is_err());
}
