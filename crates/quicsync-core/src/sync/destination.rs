//! Destination-local planning, content requests, staging, then commit.
use crate::{
    config::DestinationConfig,
    error::{ErrorCode, QuicSyncError},
    filesystem::{paths::RootHandle, scan::scan_root, staging::StagingArea},
    protocol::messages::{Control, IndexMessage, Operation},
    sync::{
        Stage,
        commit::PendingCommit,
        planner::plan,
        stage,
        transfer::receive_file,
        wire::{Messages, encode, failure},
    },
    transport::quic::{Connection, DestinationStreams},
};
use std::sync::Arc;
use tokio::{sync::mpsc, task::JoinSet};

pub async fn serve(
    connection: &Connection,
    config: &DestinationConfig,
) -> Result<(), QuicSyncError> {
    let result = serve_inner(connection, config).await;
    if result.is_err() {
        connection.cancel();
    }
    result
}

async fn serve_inner(
    connection: &Connection,
    config: &DestinationConfig,
) -> Result<(), QuicSyncError> {
    let DestinationStreams {
        mut control,
        mut source_index,
        transfers,
    } = connection.accept_session().await?;
    let limits = *config.limits();
    let mut messages = Messages::<Control>::new(&limits);
    let root_id = match messages.next(&mut control).await? {
        Control::StartSync { root_id } => root_id,
        _ => return Err(failure("expected StartSync")),
    };
    let fingerprint = connection.peer_fingerprint()?;
    let configured = config
        .roots()
        .iter()
        .find(|root| {
            root.id().as_str() == root_id
                && root
                    .authorized_peers()
                    .iter()
                    .any(|pin| pin.as_bytes() == fingerprint.as_bytes())
        })
        .ok_or_else(|| {
            QuicSyncError::new(
                ErrorCode::AuthorizationDenied,
                None,
                "peer is not authorized for root",
            )
        })?;
    let root = Arc::new(RootHandle::from_validated(configured.root())?);
    let capacity = limits.max_parallel_transfers();
    let (local_tx, local_rx) = mpsc::channel(capacity);
    let (remote_tx, remote_rx) = mpsc::channel(capacity);
    let (operation_tx, mut operation_rx) = mpsc::channel(capacity);
    let scanning = stage(
        "destination indexing",
        scan_root(configured.root().path(), &[], &limits, local_tx),
    );
    let indexing = async {
        let mut records = Messages::<IndexMessage>::new(&limits);
        loop {
            let record = records.next(&mut source_index).await?;
            let end = record == IndexMessage::End;
            remote_tx.send(Ok(record)).await.map_err(failure)?;
            if end {
                return Ok::<_, QuicSyncError>(());
            }
        }
    };
    let planning = async {
        connection.confirm_handshake().await?;
        control
            .send(&encode(&Control::StartAccepted, &limits)?)
            .await?;
        stage(
            "destination planning",
            plan(remote_rx, local_rx, operation_tx),
        )
        .await?;
        control.send(&encode(&Control::PlanEnd, &limits)?).await
    };
    let requesting = async {
        let area = Arc::new(StagingArea::new(root)?);
        let requests = Stage::start("destination requesting");
        let _staging = Stage::start("destination staging");
        let mut pending = PendingCommit::default();
        let mut jobs = JoinSet::new();
        while let Some(operation) = operation_rx.recv().await {
            if let Operation::UpsertFile { id, record, update } = &operation {
                if jobs.len() >= capacity {
                    let (op, file) = jobs
                        .join_next()
                        .await
                        .expect("nonempty")
                        .map_err(failure)??;
                    pending.stage(op, Some(file))?;
                }
                let stream = transfers.open().await?;
                let area = area.clone();
                let id = *id;
                let path = record.path.clone();
                let update = *update;
                jobs.spawn(async move {
                    let file = receive_file(stream, area, id, path, update, &limits).await?;
                    Ok::<_, QuicSyncError>((operation, file.file))
                });
            } else {
                pending.stage(operation, None)?;
            }
        }
        drop(requests);
        while let Some(result) = jobs.join_next().await {
            let (op, file) = result.map_err(failure)??;
            pending.stage(op, Some(file))?;
        }
        Ok::<_, QuicSyncError>(pending)
    };
    let (_, _, _, pending) = tokio::try_join!(scanning, indexing, planning, requesting)?;
    // Only this stage touches the live tree; any earlier error drops staged content.
    let commit_root = RootHandle::from_validated(configured.root())?;
    stage("destination committing", async {
        tokio::task::spawn_blocking(move || pending.commit(commit_root))
            .await
            .map_err(failure)?
    })
    .await?;
    control
        .send(&encode(&Control::CompleteAck, &limits)?)
        .await?;
    let mut buffer = [0; 1];
    if control.receive(&mut buffer).await?.is_some() {
        return Err(failure("unexpected source control message"));
    }
    Ok(())
}
