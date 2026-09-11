use quicsync_core::{
    protocol::messages::{Operation, canonical_plan_digest},
    sync::planner::plan,
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

    assert_eq!(plan.operations().len(), 3);
    assert!(matches!(
        plan.operations()[0],
        Operation::UpsertSymlink { .. }
    ));
    assert!(matches!(
        plan.operations()[1],
        Operation::UpsertDirectory { .. }
    ));
    assert!(matches!(plan.operations()[2], Operation::UpsertFile { .. }));
    assert_eq!(plan.digest(), canonical_plan_digest(plan.operations()));
}

#[test]
fn destination_only_records_are_deleted() {
    let plan = plan(&[], &[file("old.txt", 1), dir("tmp", 0o755)]);

    assert_eq!(plan.operations().len(), 2);
    assert!(matches!(
        &plan.operations()[0],
        Operation::Delete {
            path: operation_path,
            expected_kind: EntryKind::RegularFile,
            ..
        } if operation_path == &path("old.txt")
    ));
    assert!(matches!(
        &plan.operations()[1],
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

    assert!(plan.operations().is_empty());
}

#[test]
fn changed_records_are_upserted() {
    let plan = plan(&[file("src/main.rs", 2)], &[file("src/main.rs", 1)]);

    assert_eq!(plan.operations().len(), 1);
    assert!(matches!(
        &plan.operations()[0],
        Operation::UpsertFile { record, .. } if record.digest == Some(Digest::from_bytes([2; 32]))
    ));
}

#[test]
fn type_replacements_delete_then_upsert() {
    let plan = plan(&[file("node", 7)], &[dir("node", 0o755)]);

    assert_eq!(plan.operations().len(), 2);
    assert!(matches!(
        &plan.operations()[0],
        Operation::Delete {
            path: operation_path,
            expected_kind: EntryKind::Directory,
            ..
        } if operation_path == &path("node")
    ));
    assert!(matches!(
        &plan.operations()[1],
        Operation::UpsertFile { .. }
    ));
}

#[test]
fn replacement_and_stale_descendants_follow_merge_order() {
    let plan = plan(
        &[file("node", 7)],
        &[dir("node", 0o755), file("node/child", 1)],
    );

    assert_eq!(plan.operations().len(), 3);
    assert!(matches!(
        &plan.operations()[0],
        Operation::Delete {
            path: operation_path,
            expected_kind: EntryKind::Directory,
            ..
        } if operation_path == &path("node")
    ));
    assert!(matches!(
        &plan.operations()[1],
        Operation::UpsertFile { .. }
    ));
    assert!(matches!(
        &plan.operations()[2],
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
        .operations()
        .iter()
        .map(|operation| operation.id().get())
        .collect::<Vec<_>>();

    assert_eq!(ids, [0, 1, 2]);
    assert_eq!(plan.operations()[0].path(), &path("a"));
    assert_eq!(plan.operations()[1].path(), &path("b"));
    assert_eq!(plan.operations()[2].path(), &path("c"));
}

#[test]
fn merge_walk_follows_canonical_input_order() {
    let plan = plan(
        &[dir("a", 0o755), file("a/file", 1), file("d", 4)],
        &[file("b", 2), file("c", 3)],
    );

    assert_eq!(plan.operations()[0].path(), &path("a"));
    assert_eq!(plan.operations()[1].path(), &path("a/file"));
    assert_eq!(plan.operations()[2].path(), &path("b"));
    assert_eq!(plan.operations()[3].path(), &path("c"));
    assert_eq!(plan.operations()[4].path(), &path("d"));
}
