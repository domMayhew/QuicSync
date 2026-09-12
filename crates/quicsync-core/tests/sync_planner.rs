use quicsync_core::{
    protocol::messages::{IndexMessage, Operation},
    sync::planner::plan as stream_plan,
    types::{Digest, EntryKind, EntryMetadata, IndexRecord, RelativePath},
};

fn path(value: &str) -> RelativePath {
    RelativePath::new(
        value
            .split('/')
            .map(|component| component.as_bytes().to_vec())
            .collect(),
    )
    .unwrap()
}

fn dir(value: &str, mode: u32) -> IndexRecord {
    IndexRecord {
        path: path(value),
        metadata: EntryMetadata::new(EntryKind::Directory, mode, 10, 0),
        digest: None,
        symlink_target: None,
    }
}

fn file(value: &str, digest_byte: u8) -> IndexRecord {
    IndexRecord {
        path: path(value),
        metadata: EntryMetadata::new(EntryKind::RegularFile, 0o644, 10, 4),
        digest: Some(Digest::from_bytes([digest_byte; 32])),
        symlink_target: None,
    }
}

fn symlink(value: &str, target: &[u8]) -> IndexRecord {
    IndexRecord {
        path: path(value),
        metadata: EntryMetadata::new(EntryKind::Symlink, 0o777, 10, target.len() as u64),
        digest: Some(Digest::from_bytes(*blake3::hash(target).as_bytes())),
        symlink_target: Some(target.to_vec()),
    }
}

#[test]
fn source_only_records_are_upserted_by_kind() {
    let plan = plan(
        &[
            symlink("run", b"bin/run"),
            dir("src", 0o755),
            file("src/main.rs", 1),
        ],
        &[],
    );

    assert_eq!(plan.len(), 3);
    assert!(matches!(plan[0], Operation::UpsertSymlink { .. }));
    assert!(matches!(plan[1], Operation::UpsertDirectory { .. }));
    assert!(matches!(plan[2], Operation::UpsertFile { .. }));
}

#[test]
fn destination_only_records_are_deleted() {
    let plan = plan(&[], &[file("old.txt", 1), dir("tmp", 0o755)]);

    assert_eq!(plan.len(), 2);
    assert!(matches!(
        &plan[0],
        Operation::Delete {
            path: operation_path,
            expected_kind: EntryKind::RegularFile,
            ..
        } if operation_path == &path("old.txt")
    ));
    assert!(matches!(
        &plan[1],
        Operation::Delete {
            path: operation_path,
            expected_kind: EntryKind::Directory,
            ..
        } if operation_path == &path("tmp")
    ));
}

#[test]
fn unchanged_records_produce_no_operations() {
    let records = [dir("src", 0o755), file("src/main.rs", 1)];

    let plan = plan(&records, &records);

    assert!(plan.is_empty());
}

#[test]
fn changed_records_are_upserted() {
    let plan = plan(&[file("src/main.rs", 2)], &[file("src/main.rs", 1)]);

    assert_eq!(plan.len(), 1);
    assert!(matches!(
        &plan[0],
        Operation::UpsertFile { record, .. } if record.digest == Some(Digest::from_bytes([2; 32]))
    ));
}

#[test]
fn type_replacements_delete_then_upsert() {
    let plan = plan(&[file("node", 7)], &[dir("node", 0o755)]);

    assert_eq!(plan.len(), 2);
    assert!(matches!(
        &plan[0],
        Operation::Delete {
            path: operation_path,
            expected_kind: EntryKind::Directory,
            ..
        } if operation_path == &path("node")
    ));
    assert!(matches!(&plan[1], Operation::UpsertFile { .. }));
}

#[test]
fn replacement_and_stale_descendants_follow_merge_order() {
    let plan = plan(
        &[file("node", 7)],
        &[dir("node", 0o755), file("node/child", 1)],
    );

    assert_eq!(plan.len(), 3);
    assert!(matches!(
        &plan[0],
        Operation::Delete {
            path: operation_path,
            expected_kind: EntryKind::Directory,
            ..
        } if operation_path == &path("node")
    ));
    assert!(matches!(&plan[1], Operation::UpsertFile { .. }));
    assert!(matches!(
        &plan[2],
        Operation::Delete {
            path: operation_path,
            expected_kind: EntryKind::RegularFile,
            ..
        } if operation_path == &path("node/child")
    ));
}

#[test]
fn operation_ids_are_deterministic_and_monotonic() {
    let plan = plan(&[file("a", 1), file("b", 2)], &[file("c", 3)]);

    let ids = plan
        .iter()
        .map(|operation| operation.id().get())
        .collect::<Vec<_>>();

    assert_eq!(ids, [0, 1, 2]);
    assert_eq!(plan[0].path(), &path("a"));
    assert_eq!(plan[1].path(), &path("b"));
    assert_eq!(plan[2].path(), &path("c"));
}

#[test]
fn merge_walk_follows_canonical_input_order() {
    let plan = plan(
        &[dir("a", 0o755), file("a/file", 1), file("d", 4)],
        &[file("b", 2), file("c", 3)],
    );

    assert_eq!(plan[0].path(), &path("a"));
    assert_eq!(plan[1].path(), &path("a/file"));
    assert_eq!(plan[2].path(), &path("b"));
    assert_eq!(plan[3].path(), &path("c"));
    assert_eq!(plan[4].path(), &path("d"));
}

fn plan(source: &[IndexRecord], destination: &[IndexRecord]) -> Vec<Operation> {
    tokio::runtime::Builder::new_current_thread().build().unwrap().block_on(async {
        let (source_tx, source_rx) = tokio::sync::mpsc::channel(1);
        let (destination_tx, destination_rx) = tokio::sync::mpsc::channel(1);
        let (output_tx, mut output_rx) = tokio::sync::mpsc::channel(1);
        let produce = async {
            let feed = |tx: tokio::sync::mpsc::Sender<_>, records: Vec<IndexRecord>| async move {
                for record in records {
                    tx.send(Ok(IndexMessage::Record(record))).await.unwrap();
                }
                tx.send(Ok(IndexMessage::End)).await.unwrap();
            };
            tokio::join!(feed(source_tx, source.to_vec()), feed(destination_tx, destination.to_vec()));
        };
        let consume = async {
            let mut operations = Vec::new();
            while let Some(operation) = output_rx.recv().await {
                operations.push(operation);
            }
            operations
        };
        let (_, result, operations) = tokio::join!(produce, stream_plan(source_rx, destination_rx, output_tx), consume);
        result.unwrap();
        operations
    })
}

#[tokio::test]
async fn first_operation_arrives_before_either_index_finishes() {
    use tokio::{
        sync::mpsc,
        time::{Duration, timeout},
    };
    let (source_tx, source_rx) = mpsc::channel(1);
    let (destination_tx, destination_rx) = mpsc::channel(1);
    let (output_tx, mut output_rx) = mpsc::channel(1);
    let planner = tokio::spawn(stream_plan(source_rx, destination_rx, output_tx));
    source_tx
        .send(Ok(IndexMessage::Record(file("a", 1))))
        .await
        .unwrap();
    destination_tx
        .send(Ok(IndexMessage::Record(file("z", 2))))
        .await
        .unwrap();
    let first = timeout(Duration::from_secs(1), output_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(first.path(), &path("a"));
    // Both producers are still open, with no end marker sent.
    source_tx.send(Ok(IndexMessage::End)).await.unwrap();
    assert_eq!(output_rx.recv().await.unwrap().path(), &path("z"));
    destination_tx.send(Ok(IndexMessage::End)).await.unwrap();
    planner.await.unwrap().unwrap();
    assert!(output_rx.recv().await.is_none());
}

#[tokio::test]
async fn producer_failure_is_not_an_empty_index() {
    use tokio::sync::mpsc;
    let (source_tx, source_rx) = mpsc::channel(1);
    let (destination_tx, destination_rx) = mpsc::channel(1);
    let (output_tx, mut output_rx) = mpsc::channel(1);
    drop(source_tx);
    destination_tx
        .send(Ok(IndexMessage::Record(file("keep", 1))))
        .await
        .unwrap();
    assert!(
        stream_plan(source_rx, destination_rx, output_tx)
            .await
            .is_err()
    );
    assert!(output_rx.recv().await.is_none());
}

#[tokio::test]
async fn producer_errors_propagate_and_closed_consumers_stop_planning() {
    use quicsync_core::error::{ErrorCode, QuicSyncError};
    use tokio::sync::mpsc;
    let (source_tx, source_rx) = mpsc::channel(1);
    let (_destination_tx, destination_rx) = mpsc::channel(1);
    let (output_tx, _output_rx) = mpsc::channel(1);
    let error = QuicSyncError::new(ErrorCode::Io, None, "scan failed");
    source_tx.send(Err(error.clone())).await.unwrap();
    assert_eq!(
        stream_plan(source_rx, destination_rx, output_tx).await,
        Err(error)
    );

    let (source_tx, source_rx) = mpsc::channel(1);
    let (destination_tx, destination_rx) = mpsc::channel(1);
    let (output_tx, output_rx) = mpsc::channel(1);
    source_tx
        .send(Ok(IndexMessage::Record(file("a", 1))))
        .await
        .unwrap();
    destination_tx.send(Ok(IndexMessage::End)).await.unwrap();
    drop(output_rx);
    assert!(
        stream_plan(source_rx, destination_rx, output_tx)
            .await
            .is_err()
    );
}
