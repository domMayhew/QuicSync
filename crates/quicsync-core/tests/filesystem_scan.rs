#![cfg(unix)]

use std::{
    ffi::CString,
    fs,
    os::unix::{ffi::OsStrExt, fs::symlink},
};

use quicsync_core::{
    config::DEFAULT_LIMITS,
    error::ErrorCode,
    filesystem::scan::scan_root as stream_scan_root,
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

fn scan_root(
    root: &std::path::Path,
    exclusions: &[String],
    limits: &quicsync_core::config::Limits,
) -> Result<Vec<IndexRecord>, quicsync_core::error::QuicSyncError> {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(async {
            let (tx, mut rx) = tokio::sync::mpsc::channel(1);
            let collect = async {
                let mut records = Vec::new();
                let mut ended = false;
                while let Some(item) = rx.recv().await {
                    match item? {
                        quicsync_core::protocol::messages::IndexMessage::Record(record) => {
                            assert!(!ended);
                            records.push(record);
                        }
                        quicsync_core::protocol::messages::IndexMessage::End => ended = true,
                    }
                }
                assert!(ended);
                Ok::<_, quicsync_core::error::QuicSyncError>(records)
            };
            let (result, records) =
                tokio::join!(stream_scan_root(root, exclusions, limits, tx), collect);
            result?;
            records
        })
}

#[tokio::test]
async fn scanner_and_planner_pipeline_without_collecting_indexes() {
    use quicsync_core::{protocol::messages::IndexMessage, sync::planner::plan};
    use tokio::{
        sync::mpsc,
        time::{Duration, timeout},
    };
    let source = TempDir::new().unwrap();
    let destination = TempDir::new().unwrap();
    for n in 0..20 {
        fs::write(source.path().join(format!("file-{n:02}")), b"content").unwrap();
    }
    let (a_tx, a_rx) = mpsc::channel(1);
    let (b_tx, b_rx) = mpsc::channel(1);
    let (out_tx, mut out_rx) = mpsc::channel(1);
    let source_path = source.path().to_owned();
    let a =
        tokio::spawn(
            async move { stream_scan_root(&source_path, &[], &DEFAULT_LIMITS, a_tx).await },
        );
    let destination_path = destination.path().to_owned();
    let b = tokio::spawn(async move {
        stream_scan_root(&destination_path, &[], &DEFAULT_LIMITS, b_tx).await
    });
    let planner = tokio::spawn(plan(a_rx, b_rx, out_tx));
    let first = timeout(Duration::from_secs(2), out_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(first.path().components(), &[b"file-00".to_vec()]);
    // Bounded queues cannot hold the remaining tree while the consumer pauses.
    assert!(!a.is_finished());
    assert!(!planner.is_finished());
    let mut count = 1;
    while timeout(Duration::from_secs(2), out_rx.recv())
        .await
        .unwrap()
        .is_some()
    {
        count += 1;
    }
    assert_eq!(count, 20);
    a.await.unwrap().unwrap();
    b.await.unwrap().unwrap();
    planner.await.unwrap().unwrap();

    let (tx, rx) = mpsc::channel::<Result<IndexMessage, _>>(1);
    drop(rx);
    assert!(
        stream_scan_root(source.path(), &[], &DEFAULT_LIMITS, tx)
            .await
            .is_err()
    );
}

#[test]
fn canonical_components_and_sibling_ignore_scopes_are_preserved() {
    let root = TempDir::new().unwrap();
    fs::create_dir(root.path().join("a")).unwrap();
    fs::write(root.path().join("a/.gitignore"), b"*.tmp\n").unwrap();
    fs::write(root.path().join("a/ignored.tmp"), b"ignored").unwrap();
    fs::write(root.path().join("a/z"), b"managed").unwrap();
    fs::write(root.path().join("a.txt"), b"managed").unwrap();
    fs::create_dir(root.path().join("b")).unwrap();
    fs::write(root.path().join("b/keep.tmp"), b"managed").unwrap();
    let records = scan_root(root.path(), &[], &DEFAULT_LIMITS).unwrap();
    assert_eq!(
        names(&records),
        ["a", "a/.gitignore", "a/z", "a.txt", "b", "b/keep.tmp"]
    );
    assert!(records.windows(2).all(|pair| pair[0].path < pair[1].path));
}

#[test]
fn symlinked_ignore_files_are_not_followed() {
    let root = TempDir::new().unwrap();
    let outside = TempDir::new().unwrap();
    fs::write(outside.path().join("rules"), b"*\n").unwrap();
    symlink(outside.path().join("rules"), root.path().join(".gitignore")).unwrap();
    fs::write(root.path().join("keep"), b"managed").unwrap();
    let records = scan_root(root.path(), &[], &DEFAULT_LIMITS).unwrap();
    assert_eq!(names(&records), [".gitignore", "keep"]);
}
