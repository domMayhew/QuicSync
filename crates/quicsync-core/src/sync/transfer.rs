//! Streamed librsync transfer over one QUIC stream per file.

use crate::{
    config::Limits,
    error::{ErrorCode, QuicSyncError},
    filesystem::{
        paths::{RootHandle, open_regular},
        staging::{StagedFile, StagingArea},
    },
    protocol::{
        codec::{self, CodecLimits, Decoder},
        messages::FileTransfer,
    },
    transport::quic::TransferStream,
    types::{OperationId, RelativePath},
};
use std::{
    collections::VecDeque,
    io::{self, Cursor, Read, Seek, SeekFrom},
    sync::Arc,
};
use tokio::sync::mpsc;

const QUEUE: usize = 2;

/// Kept private until all requested transfers have staged successfully.
pub struct ReceivedFile {
    pub id: OperationId,
    pub path: RelativePath,
    pub file: StagedFile,
}

enum Chunk {
    Data(Vec<u8>),
    End,
}
struct Input {
    rx: mpsc::Receiver<Chunk>,
    current: Cursor<Vec<u8>>,
    ended: bool,
}
impl Input {
    fn new(rx: mpsc::Receiver<Chunk>) -> Self {
        Self {
            rx,
            current: Cursor::new(Vec::new()),
            ended: false,
        }
    }
}
impl Read for Input {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        loop {
            let n = self.current.read(out)?;
            if n != 0 || self.ended {
                return Ok(n);
            }
            match self.rx.blocking_recv() {
                Some(Chunk::Data(bytes)) => self.current = Cursor::new(bytes),
                Some(Chunk::End) => self.ended = true,
                None => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "transfer ended without marker",
                    ));
                }
            }
        }
    }
}

fn produce(
    mut reader: impl Read,
    tx: mpsc::Sender<Vec<u8>>,
    chunk_size: usize,
) -> Result<(), QuicSyncError> {
    loop {
        let mut bytes = vec![0; chunk_size];
        let n = reader.read(&mut bytes).map_err(failure)?;
        if n == 0 {
            return Ok(());
        }
        bytes.truncate(n);
        tx.blocking_send(bytes)
            .map_err(|_| failure("transfer consumer closed"))?;
    }
}

/// Source responds to a destination-initiated create or update request.
pub async fn send_file(
    stream: TransferStream,
    root: Arc<RootHandle>,
    limits: &Limits,
) -> Result<(), QuicSyncError> {
    let mut wire = Wire::new(stream, limits)?;
    let (id, path, update) = match wire.next().await? {
        FileTransfer::UpdateRequest { id, path } => (id, path, true),
        FileTransfer::CreateRequest { id, path } => (id, path, false),
        _ => return Err(failure("expected file request")),
    };
    let source = tokio::task::spawn_blocking(move || {
        open_regular(&root, &path)
            .and_then(|file| file.ok_or_else(|| failure("source file missing")))
    })
    .await
    .map_err(failure)??;
    if !update {
        let (tx, mut rx) = mpsc::channel(QUEUE);
        let chunk_size = wire.chunk_size;
        let worker = tokio::task::spawn_blocking(move || produce(source, tx, chunk_size));
        let sending = async {
            while let Some(bytes) = rx.recv().await {
                wire.send(FileTransfer::WholeFile(bytes)).await?;
            }
            Ok::<_, QuicSyncError>(())
        };
        tokio::try_join!(sending, async { worker.await.map_err(failure)? })?;
        wire.send(FileTransfer::TransferEnd).await?;
        wire.stream.finish().await?;
        return match wire.next().await? {
            FileTransfer::TransferAccepted { id: accepted } if id == accepted => Ok(()),
            _ => Err(failure("expected transfer acknowledgment")),
        };
    }
    let (signature_tx, signature_rx) = mpsc::channel(QUEUE);
    let (delta_tx, mut delta_rx) = mpsc::channel(QUEUE);
    let chunk_size = wire.chunk_size;
    let worker = tokio::task::spawn_blocking(move || {
        let mut signature = Input::new(signature_rx);
        let delta = librsync::Delta::new(source, &mut signature).map_err(failure)?;
        produce(delta, delta_tx, chunk_size)
    });
    let exchange = async {
        loop {
            match wire.next().await? {
                FileTransfer::Signature(bytes) => signature_tx
                    .send(Chunk::Data(bytes))
                    .await
                    .map_err(|_| failure("delta worker stopped"))?,
                FileTransfer::SignatureEnd => {
                    signature_tx
                        .send(Chunk::End)
                        .await
                        .map_err(|_| failure("delta worker stopped"))?;
                    break;
                }
                _ => return Err(failure("expected signature")),
            }
        }
        drop(signature_tx);
        while let Some(bytes) = delta_rx.recv().await {
            wire.send(FileTransfer::Delta(bytes)).await?;
        }
        Ok::<_, QuicSyncError>(())
    };
    let (_, result) = tokio::try_join!(exchange, async { worker.await.map_err(failure)? })?;
    let () = result;
    wire.send(FileTransfer::TransferEnd).await?;
    wire.stream.finish().await?;
    match wire.next().await? {
        FileTransfer::TransferAccepted { id: accepted } if id == accepted => Ok(()),
        _ => Err(failure("expected transfer acknowledgment")),
    }
}

/// Destination requests content and streams it into private staging.
pub async fn receive_file(
    stream: TransferStream,
    area: Arc<StagingArea>,
    id: OperationId,
    path: RelativePath,
    update: bool,
    limits: &Limits,
) -> Result<ReceivedFile, QuicSyncError> {
    let mut wire = Wire::new(stream, limits)?;
    wire.send(if update {
        FileTransfer::UpdateRequest {
            id,
            path: path.clone(),
        }
    } else {
        FileTransfer::CreateRequest {
            id,
            path: path.clone(),
        }
    })
    .await?;
    if !update {
        let (tx, rx) = mpsc::channel(QUEUE);
        let worker = tokio::task::spawn_blocking(move || area.receive(Input::new(rx)));
        let receiving = async {
            loop {
                match wire.next().await? {
                    FileTransfer::WholeFile(bytes) => {
                        tx.send(Chunk::Data(bytes)).await.map_err(failure)?
                    }
                    FileTransfer::TransferEnd => {
                        tx.send(Chunk::End).await.map_err(failure)?;
                        return Ok::<_, QuicSyncError>(());
                    }
                    _ => return Err(failure("expected whole-file bytes")),
                }
            }
        };
        let (_, file) = tokio::try_join!(receiving, async { worker.await.map_err(failure)? })?;
        wire.send(FileTransfer::TransferAccepted { id }).await?;
        wire.stream.finish().await?;
        return Ok(ReceivedFile { id, path, file });
    }
    let basis_area = area.clone();
    let basis_path = path.clone();
    let (signature_tx, mut signature_rx) = mpsc::channel(QUEUE);
    let chunk_size = wire.chunk_size;
    let worker = tokio::task::spawn_blocking(move || {
        let mut basis: Box<dyn ReadSeek> = match open_regular(basis_area.root(), &basis_path)? {
            Some(file) => Box::new(file),
            None => return Err(failure("update basis missing")),
        };
        let signature = librsync::Signature::new(&mut basis).map_err(failure)?;
        produce(signature, signature_tx, chunk_size)?;
        basis.seek(SeekFrom::Start(0)).map_err(failure)?;
        Ok::<_, QuicSyncError>(basis)
    });
    let signatures = async {
        while let Some(bytes) = signature_rx.recv().await {
            wire.send(FileTransfer::Signature(bytes)).await?;
        }
        Ok::<_, QuicSyncError>(())
    };
    let (_, basis) = tokio::try_join!(signatures, async { worker.await.map_err(failure)? })?;
    wire.send(FileTransfer::SignatureEnd).await?;

    let (delta_tx, delta_rx) = mpsc::channel(QUEUE);
    let worker = tokio::task::spawn_blocking(move || {
        let patch = librsync::Patch::new(basis, Input::new(delta_rx)).map_err(failure)?;
        area.receive(patch)
    });
    let deltas = async {
        loop {
            match wire.next().await? {
                FileTransfer::Delta(bytes) => delta_tx
                    .send(Chunk::Data(bytes))
                    .await
                    .map_err(|_| failure("patch worker stopped"))?,
                FileTransfer::TransferEnd => {
                    // librsync may finish at its internal terminator without requesting EOF.
                    let _ = delta_tx.send(Chunk::End).await;
                    return Ok::<_, QuicSyncError>(());
                }
                _ => return Err(failure("expected delta")),
            }
        }
    };
    let (_, file) = tokio::try_join!(deltas, async { worker.await.map_err(failure)? })?;
    wire.send(FileTransfer::TransferAccepted { id }).await?;
    wire.stream.finish().await?;
    Ok(ReceivedFile { id, path, file })
}

trait ReadSeek: Read + Seek + Send {}
impl<T: Read + Seek + Send> ReadSeek for T {}

struct Wire {
    stream: TransferStream,
    limits: CodecLimits,
    decoder: Decoder<FileTransfer>,
    pending: VecDeque<FileTransfer>,
    buffer: Vec<u8>,
    chunk_size: usize,
}
impl Wire {
    fn new(stream: TransferStream, limits: &Limits) -> Result<Self, QuicSyncError> {
        let chunk_size = limits
            .max_frame_bytes()
            .checked_sub(32)
            .filter(|n| *n > 0)
            .ok_or_else(|| failure("transfer frame limit is too small"))?
            .min(64 * 1024);
        let limits = CodecLimits::from(limits);
        Ok(Self {
            stream,
            limits,
            decoder: Decoder::new(limits),
            pending: VecDeque::new(),
            buffer: vec![0; chunk_size],
            chunk_size,
        })
    }
    async fn send(&mut self, message: FileTransfer) -> Result<(), QuicSyncError> {
        let bytes = codec::encode(&message, &self.limits).map_err(failure)?;
        self.stream.send(&bytes).await
    }
    async fn next(&mut self) -> Result<FileTransfer, QuicSyncError> {
        loop {
            if let Some(message) = self.pending.pop_front() {
                return Ok(message);
            }
            let n = self
                .stream
                .receive(&mut self.buffer)
                .await?
                .ok_or_else(|| failure("transfer closed before expected message"))?;
            self.pending
                .extend(self.decoder.push(&self.buffer[..n]).map_err(failure)?);
        }
    }
}

fn failure(error: impl std::fmt::Display) -> QuicSyncError {
    QuicSyncError::new(
        ErrorCode::OperationFailed,
        None,
        format!("delta transfer: {error}"),
    )
}
