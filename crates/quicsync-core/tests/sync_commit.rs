#![cfg(unix)]

use quicsync_core::{
    config::DEFAULT_LIMITS,
    error::QuicSyncError,
    filesystem::{paths::RootHandle, scan::scan_root, staging::StagedFile},
    protocol::messages::{IndexMessage, Operation},
    sync::{commit::PendingCommit, planner::plan},
    types::IndexRecord,
};
use std::{
    fs,
    os::unix::{ffi::OsStringExt, fs::symlink},
    path::{Path, PathBuf},
};
use tempfile::TempDir;
use tokio::sync::mpsc;

async fn sync(source: &Path, destination: &Path) -> Result<(), QuicSyncError> {
    let (source_tx, source_rx) = mpsc::channel(1);
    let (destination_tx, destination_rx) = mpsc::channel(1);
    let (output_tx, mut output_rx) = mpsc::channel(1);
    let source_path = source.to_owned();
    let destination_path = destination.to_owned();
    let install = tokio::task::spawn_blocking(move || {
        let root = RootHandle::open(&destination_path)?;
        let mut commit = PendingCommit::default();
        let mut completed = Vec::new();
        while let Some(operation) = output_rx.blocking_recv() {
            let staged = if let Operation::UpsertFile { record, .. } = &operation {
                let relative: PathBuf = record
                    .path
                    .components()
                    .iter()
                    .cloned()
                    .map(std::ffi::OsString::from_vec)
                    .collect();
                Some(StagedFile::receive(
                    &root,
                    fs::File::open(source_path.join(relative)).unwrap(),
                )?)
            } else {
                None
            };
            completed.push((operation, staged));
        }
        // Exercise arbitrary staging order, including children before parents and
        // replacements before their deletions. Operation IDs must not sort commit.
        for (operation, staged) in completed.into_iter().rev() {
            commit.stage(operation, staged)?;
        }
        Ok::<_, QuicSyncError>(commit)
    });
    let (a, b, p, c) = tokio::join!(
        scan_root(source, &[], &DEFAULT_LIMITS, source_tx),
        scan_root(destination, &[], &DEFAULT_LIMITS, destination_tx),
        plan(source_rx, destination_rx, output_tx),
        install,
    );
    // No success/finalization when any upstream stage fails.
    a?;
    b?;
    p?;
    c.unwrap()?.commit(RootHandle::open(destination)?)
}

async fn index(root: &Path) -> Vec<IndexRecord> {
    let (tx, mut rx) = mpsc::channel::<Result<IndexMessage, QuicSyncError>>(1);
    let collect = async {
        let mut records = Vec::new();
        while let Some(item) = rx.recv().await {
            if let IndexMessage::Record(record) = item.unwrap() {
                records.push(record);
            }
        }
        records
    };
    let (scan, records) = tokio::join!(scan_root(root, &[], &DEFAULT_LIMITS, tx), collect);
    scan.unwrap();
    records
}

#[tokio::test]
async fn reverse_staging_order_handles_nested_deletions_and_type_replacements() {
    let source = TempDir::new().unwrap();
    let destination = TempDir::new().unwrap();
    fs::write(source.path().join("a"), b"directory to file").unwrap();
    fs::create_dir_all(destination.path().join("a/nested")).unwrap();
    fs::write(destination.path().join("a/nested/child"), b"old").unwrap();
    fs::create_dir(source.path().join("b")).unwrap();
    fs::write(source.path().join("b/child"), b"file to directory").unwrap();
    fs::write(destination.path().join("b"), b"old").unwrap();
    symlink("b/child", source.path().join("c")).unwrap();
    fs::create_dir_all(destination.path().join("c/nested")).unwrap();
    fs::write(destination.path().join("c/nested/child"), b"old").unwrap();
    fs::write(source.path().join("d"), b"symlink to file").unwrap();
    symlink("b", destination.path().join("d")).unwrap();
    fs::create_dir_all(destination.path().join("stale/nested")).unwrap();
    fs::write(destination.path().join("stale/nested/child"), b"delete").unwrap();
    sync(source.path(), destination.path()).await.unwrap();
    assert_eq!(index(source.path()).await, index(destination.path()).await);
    // A fresh attempt remains valid after the first attempt.
    sync(source.path(), destination.path()).await.unwrap();
    assert_eq!(index(source.path()).await, index(destination.path()).await);
}

#[tokio::test]
async fn ignored_children_are_preserved_when_parent_removal_cannot_complete() {
    let source = TempDir::new().unwrap();
    let destination = TempDir::new().unwrap();
    for root in [source.path(), destination.path()] {
        fs::write(root.join(".gitignore"), b"local\n").unwrap();
    }
    fs::create_dir(destination.path().join("stale")).unwrap();
    fs::write(destination.path().join("stale/local"), b"preserve").unwrap();
    assert!(sync(source.path(), destination.path()).await.is_err());
    assert_eq!(
        fs::read(destination.path().join("stale/local")).unwrap(),
        b"preserve"
    );
}
