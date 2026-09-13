//! Incremental merge planning over independently produced indexes.

use tokio::sync::mpsc::{Receiver, Sender};

use crate::{
    error::{ErrorCode, QuicSyncError},
    protocol::messages::{IndexMessage, Operation},
    types::{EntryKind, IndexRecord, OperationId, Phase},
};

/// Streams operations in canonical merge order with one lookahead record per input.
///
/// Run producers and the consumer concurrently using bounded channels. Inputs must
/// be strictly ordered by path and explicitly end with `End`. A dropped producer
/// is a failure, not evidence that the remaining tree is empty.
/// Operations are discovery order, not commit order: a directory deletion can
/// precede its descendants. The consumer schedules filesystem dependencies.
pub async fn plan(
    mut source: Receiver<Result<IndexMessage, QuicSyncError>>,
    mut destination: Receiver<Result<IndexMessage, QuicSyncError>>,
    output: Sender<Operation>,
) -> Result<(), QuicSyncError> {
    let mut left = read(&mut source).await?;
    let mut right = read(&mut destination).await?;
    let mut next_id = 0;

    loop {
        let (consume_source, consume_destination) = match (&left, &right) {
            (Some(a), Some(b)) => (a.path <= b.path, b.path <= a.path),
            (Some(_), None) => (true, false),
            (None, Some(_)) => (false, true),
            (None, None) => return Ok(()),
        };
        let a = if consume_source { left.take() } else { None };
        let b = if consume_destination {
            right.take()
        } else {
            None
        };
        if a != b {
            let update = b
                .as_ref()
                .is_some_and(|r| r.metadata.kind() == EntryKind::RegularFile);
            if let Some(record) = b
                && a.as_ref().map(|a| a.metadata.kind()) != Some(record.metadata.kind())
            {
                send(
                    &output,
                    Operation::Delete {
                        id: id(&mut next_id),
                        expected_kind: record.metadata.kind(),
                        path: record.path,
                    },
                )
                .await?;
            }
            if let Some(record) = a {
                let id = id(&mut next_id);
                let operation = match record.metadata.kind() {
                    EntryKind::Directory => Operation::UpsertDirectory { id, record },
                    EntryKind::RegularFile => Operation::UpsertFile { id, record, update },
                    EntryKind::Symlink => Operation::UpsertSymlink { id, record },
                };
                send(&output, operation).await?;
            }
        }
        if consume_source {
            left = read(&mut source).await?;
        }
        if consume_destination {
            right = read(&mut destination).await?;
        }
    }
}

async fn read(
    input: &mut Receiver<Result<IndexMessage, QuicSyncError>>,
) -> Result<Option<IndexRecord>, QuicSyncError> {
    match input
        .recv()
        .await
        .ok_or_else(|| failure("index closed before End"))??
    {
        IndexMessage::Record(record) => Ok(Some(record)),
        IndexMessage::End => Ok(None),
    }
}

async fn send(output: &Sender<Operation>, operation: Operation) -> Result<(), QuicSyncError> {
    output
        .send(operation)
        .await
        .map_err(|_| failure("operation consumer closed"))
}

fn id(next: &mut u64) -> OperationId {
    let id = OperationId::new(*next);
    *next += 1;
    id
}

fn failure(message: &str) -> QuicSyncError {
    QuicSyncError::new(ErrorCode::OperationFailed, Some(Phase::Planning), message)
}
