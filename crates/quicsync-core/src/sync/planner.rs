//! Deterministic synchronization planning.

use crate::{
    protocol::messages::{Operation, canonical_plan_digest},
    types::{Digest, EntryKind, Generation, IndexRecord, OperationId, RelativePath},
};

/// A deterministic plan for making the destination match the source index.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Plan {
    operations: Vec<Operation>,
    digest: Digest,
}

impl Plan {
    pub fn operations(&self) -> &[Operation] {
        &self.operations
    }

    pub fn into_operations(self) -> Vec<Operation> {
        self.operations
    }

    pub const fn digest(&self) -> Digest {
        self.digest
    }
}

/// Compares source and destination indexes and returns the required operations.
///
/// The MVP implementation materializes the operation list, but it assumes callers provide
/// canonical scanner order so planning itself remains a single merge walk.
pub fn plan(source: &[IndexRecord], destination: &[IndexRecord]) -> Plan {
    debug_assert!(is_strictly_ordered(source));
    debug_assert!(is_strictly_ordered(destination));

    let mut planner = Planner::default();
    let mut source_index = 0;
    let mut destination_index = 0;

    while source_index < source.len() || destination_index < destination.len() {
        match (source.get(source_index), destination.get(destination_index)) {
            (Some(source_record), Some(destination_record)) => {
                match source_record.path.cmp(&destination_record.path) {
                    std::cmp::Ordering::Less => {
                        planner.upsert(source_record.clone());
                        source_index += 1;
                    }
                    std::cmp::Ordering::Greater => {
                        planner.delete(
                            destination_record.path.clone(),
                            destination_record.metadata.kind(),
                        );
                        destination_index += 1;
                    }
                    std::cmp::Ordering::Equal => {
                        planner.reconcile(source_record, destination_record);
                        source_index += 1;
                        destination_index += 1;
                    }
                }
            }
            (Some(source_record), None) => {
                planner.upsert(source_record.clone());
                source_index += 1;
            }
            (None, Some(destination_record)) => {
                planner.delete(
                    destination_record.path.clone(),
                    destination_record.metadata.kind(),
                );
                destination_index += 1;
            }
            (None, None) => break,
        }
    }

    planner.finish()
}

#[derive(Default)]
struct Planner {
    operations: Vec<Operation>,
}

impl Planner {
    fn finish(self) -> Plan {
        let digest = canonical_plan_digest(&self.operations);
        Plan {
            operations: self.operations,
            digest,
        }
    }

    fn reconcile(&mut self, source: &IndexRecord, destination: &IndexRecord) {
        if source == destination {
            return;
        }
        if source.metadata.kind() != destination.metadata.kind() {
            self.delete(destination.path.clone(), destination.metadata.kind());
        }
        self.upsert(source.clone());
    }

    fn upsert(&mut self, record: IndexRecord) {
        let id = self.next_operation_id();
        let generation = Generation::new(0);
        let operation = match record.metadata.kind() {
            EntryKind::Directory => Operation::UpsertDirectory {
                id,
                generation,
                record,
            },
            EntryKind::RegularFile => Operation::UpsertFile {
                id,
                generation,
                record,
            },
            EntryKind::Symlink => Operation::UpsertSymlink {
                id,
                generation,
                record,
            },
        };
        self.operations.push(operation);
    }

    fn delete(&mut self, path: RelativePath, expected_kind: EntryKind) {
        let id = self.next_operation_id();
        self.operations.push(Operation::Delete {
            id,
            path,
            expected_kind,
        });
    }

    fn next_operation_id(&self) -> OperationId {
        OperationId::new(self.operations.len() as u64)
    }
}

fn is_strictly_ordered(records: &[IndexRecord]) -> bool {
    records
        .windows(2)
        .all(|pair| pair[0].path < pair[1].path)
}
