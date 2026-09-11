#![cfg(unix)]

use std::{
    ffi::CString,
    fs,
    os::unix::{ffi::OsStrExt, fs::symlink},
};

use quicsync_core::{
    config::DEFAULT_LIMITS,
    error::ErrorCode,
    filesystem::scan::scan_root,
    types::{Digest, EntryKind, IndexRecord},
};
use tempfile::TempDir;

fn names(records: &[IndexRecord]) -> Vec<String> {
    records
        .iter()
        .map(|record| {
            record
                .path
                .components()
                .iter()
                .map(|component| String::from_utf8_lossy(component).into_owned())
                .collect::<Vec<_>>()
                .join("/")
        })
        .collect()
}

fn record<'a>(records: &'a [IndexRecord], path: &str) -> &'a IndexRecord {
    records
        .iter()
        .find(|record| {
            record
                .path
                .components()
                .iter()
                .map(|component| String::from_utf8_lossy(component).into_owned())
                .collect::<Vec<_>>()
                .join("/")
                == path
        })
        .unwrap()
}

#[test]
fn stable_files_directories_and_links_are_indexed() {
    let root = TempDir::new().unwrap();
    fs::create_dir(root.path().join("src")).unwrap();
    fs::write(root.path().join("src/main.rs"), b"fn main() {}\n").unwrap();
    symlink("src/main.rs", root.path().join("main-link")).unwrap();

    let records = scan_root(root.path(), &[], &DEFAULT_LIMITS).unwrap();

    assert_eq!(names(&records), ["main-link", "src", "src/main.rs"]);
    assert_eq!(
        record(&records, "src").metadata.kind(),
        EntryKind::Directory,
    );
    let file = record(&records, "src/main.rs");
    assert_eq!(file.metadata.kind(), EntryKind::RegularFile);
    assert_eq!(
        file.digest,
        Some(Digest::from_bytes(
            *blake3::hash(b"fn main() {}\n").as_bytes()
        )),
    );
    assert_eq!(file.symlink_target, None);

    let link = record(&records, "main-link");
    assert_eq!(link.metadata.kind(), EntryKind::Symlink);
    assert_eq!(
        link.symlink_target.as_deref(),
        Some(b"src/main.rs".as_slice())
    );
    assert_eq!(
        link.digest,
        Some(Digest::from_bytes(*blake3::hash(b"src/main.rs").as_bytes())),
    );
}

#[test]
fn gitignore_rules_prune_entries_during_the_same_scan() {
    let root = TempDir::new().unwrap();
    fs::write(root.path().join(".gitignore"), b"target/\n*.log\n").unwrap();
    fs::create_dir(root.path().join("target")).unwrap();
    fs::write(root.path().join("target/output.o"), b"ignored").unwrap();
    fs::write(root.path().join("debug.log"), b"ignored").unwrap();
    fs::write(root.path().join("main.rs"), b"managed").unwrap();

    let records = scan_root(root.path(), &[], &DEFAULT_LIMITS).unwrap();

    assert_eq!(names(&records), [".gitignore", "main.rs"]);
}

#[test]
fn nested_gitignore_rules_apply_only_below_their_scope() {
    let root = TempDir::new().unwrap();
    fs::create_dir(root.path().join("src")).unwrap();
    fs::write(root.path().join("src/.gitignore"), b"generated/\n").unwrap();
    fs::create_dir(root.path().join("src/generated")).unwrap();
    fs::write(root.path().join("src/generated/file.rs"), b"ignored").unwrap();
    fs::create_dir(root.path().join("generated")).unwrap();
    fs::write(root.path().join("generated/file.rs"), b"managed").unwrap();

    let records = scan_root(root.path(), &[], &DEFAULT_LIMITS).unwrap();

    assert_eq!(
        names(&records),
        ["generated", "generated/file.rs", "src", "src/.gitignore",],
    );
}

#[test]
fn protected_administrative_paths_are_never_indexed() {
    let root = TempDir::new().unwrap();
    fs::create_dir(root.path().join(".git")).unwrap();
    fs::write(root.path().join(".git/config"), b"ignored").unwrap();
    fs::create_dir(root.path().join(".quicsync")).unwrap();
    fs::write(root.path().join(".quicsync/state.sqlite"), b"ignored").unwrap();
    fs::write(root.path().join("README.md"), b"managed").unwrap();

    let records = scan_root(root.path(), &[], &DEFAULT_LIMITS).unwrap();

    assert_eq!(names(&records), ["README.md"]);
}

#[test]
fn symlinked_directories_are_recorded_but_not_followed() {
    let root = TempDir::new().unwrap();
    let outside = TempDir::new().unwrap();
    fs::write(outside.path().join("secret.txt"), b"outside").unwrap();
    symlink(outside.path(), root.path().join("outside-link")).unwrap();

    let records = scan_root(root.path(), &[], &DEFAULT_LIMITS).unwrap();

    assert_eq!(names(&records), ["outside-link"]);
    assert_eq!(
        record(&records, "outside-link").metadata.kind(),
        EntryKind::Symlink,
    );
}

#[test]
fn unsupported_filesystem_entries_fail() {
    use std::os::unix::fs::FileTypeExt;

    let root = TempDir::new().unwrap();
    let fifo = root.path().join("fifo");
    let fifo_cstr = CString::new(fifo.as_os_str().as_bytes()).unwrap();
    let created = unsafe { libc::mkfifo(fifo_cstr.as_ptr(), 0o644) == 0 };
    assert!(created, "test setup could not create a FIFO");

    let result = scan_root(root.path(), &[], &DEFAULT_LIMITS);
    assert!(fifo.symlink_metadata().unwrap().file_type().is_fifo());
    assert_eq!(result.unwrap_err().code(), ErrorCode::UnsupportedFilesystem);
}
