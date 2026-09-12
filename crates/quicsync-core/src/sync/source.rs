//! Source index production and concurrent service of destination file requests.
use crate::{
    config::SourceConfig,
    error::QuicSyncError,
    filesystem::{paths::RootHandle, scan::scan_root},
    protocol::messages::{Control, IndexMessage},
    sync::{
        stage,
        transfer::send_file,
        wire::{Messages, encode, failure},
    },
    transport::quic::{Connection, SourceStreams},
};
use std::sync::Arc;
use tokio::{sync::mpsc, task::JoinSet};

pub async fn run(connection: &Connection, config: &SourceConfig) -> Result<(), QuicSyncError> {
    let result = run_inner(connection, config).await;
    if result.is_err() {
        connection.cancel();
    }
    result
}

async fn run_inner(connection: &Connection, config: &SourceConfig) -> Result<(), QuicSyncError> {
    let SourceStreams {
        mut control,
        mut index,
        transfers,
    } = connection.open_session().await?;
    let limits = *config.limits();
    stage(
        "source notification",
        control.send(&encode(
            &Control::StartSync {
                root_id: config.root_id().as_str().to_owned(),
            },
            &limits,
        )?),
    )
    .await?;
    let root = Arc::new(RootHandle::from_validated(config.root())?);
    let (tx, mut rx) = mpsc::channel(limits.max_parallel_transfers());
    let scanning = stage(
        "source indexing",
        scan_root(
            config.root().path(),
            config.global_exclusions(),
            &limits,
            tx,
        ),
    );
    let indexing = async {
        connection.confirm_handshake().await?;
        while let Some(message) = rx.recv().await {
            let message = message?;
            index.send(&encode(&message, &limits)?).await?;
            if message == IndexMessage::End {
                return index.finish().await;
            }
        }
        Err(failure("source index closed without End"))
    };
    let serving = async {
        connection.confirm_handshake().await?;
        let mut messages = Messages::<Control>::new(&limits);
        let mut jobs = JoinSet::new();
        let mut accepted = false;
        let mut planned = false;
        loop {
            tokio::select! {
                message = messages.next(&mut control) => match message? {
                    Control::StartAccepted if !accepted => accepted = true,
                    Control::PlanEnd if accepted && !planned => planned = true,
                    Control::CompleteAck if planned => break,
                    _ => return Err(failure("unexpected destination control message")),
                },
                stream = transfers.accept(), if jobs.len() < limits.max_parallel_transfers() => {
                    let stream = stream?.ok_or_else(|| failure("connection closed before completion"))?;
                    let root = root.clone();
                    jobs.spawn(async move { send_file(stream, root, &limits).await });
                }
                result = jobs.join_next(), if !jobs.is_empty() => {
                    result.expect("nonempty").map_err(failure)??;
                }
            }
        }
        // PlanEnd does not order other QUIC streams; service requests until CompleteAck.
        while let Some(result) = jobs.join_next().await {
            result.map_err(failure)??;
        }
        control.record_completion_ack();
        control.close().await.into_result()
    };
    tokio::try_join!(scanning, indexing, stage("source transferring", serving))?;
    Ok(())
}
