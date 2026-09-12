use crate::{
    config::Limits,
    error::{ErrorCode, QuicSyncError},
    protocol::codec::{self, CodecLimits, Decoder, WireMessage},
    transport::quic::{ControlChannel, IndexReader},
};
use std::{collections::VecDeque, future::Future};

pub(super) fn failure(error: impl std::fmt::Display) -> QuicSyncError {
    QuicSyncError::new(ErrorCode::OperationFailed, None, error.to_string())
}

pub(super) fn encode<T: WireMessage>(
    message: &T,
    limits: &Limits,
) -> Result<Vec<u8>, QuicSyncError> {
    codec::encode(message, &CodecLimits::from(limits)).map_err(failure)
}

pub(super) trait Input {
    fn receive(
        &mut self,
        buffer: &mut [u8],
    ) -> impl Future<Output = Result<Option<usize>, QuicSyncError>> + Send;
}
impl Input for ControlChannel {
    async fn receive(&mut self, buffer: &mut [u8]) -> Result<Option<usize>, QuicSyncError> {
        ControlChannel::receive(self, buffer).await
    }
}
impl Input for IndexReader {
    async fn receive(&mut self, buffer: &mut [u8]) -> Result<Option<usize>, QuicSyncError> {
        IndexReader::receive(self, buffer).await
    }
}

pub(super) struct Messages<T> {
    decoder: Decoder<T>,
    pending: VecDeque<T>,
    buffer: Vec<u8>,
}
impl<T: WireMessage> Messages<T> {
    pub fn new(limits: &Limits) -> Self {
        Self {
            decoder: Decoder::new(CodecLimits::from(limits)),
            pending: VecDeque::new(),
            buffer: vec![0; limits.max_frame_bytes().min(64 * 1024)],
        }
    }
    pub async fn next(&mut self, stream: &mut impl Input) -> Result<T, QuicSyncError> {
        loop {
            if let Some(message) = self.pending.pop_front() {
                return Ok(message);
            }
            let n = stream
                .receive(&mut self.buffer)
                .await?
                .ok_or_else(|| failure("stream closed before expected message"))?;
            self.pending
                .extend(self.decoder.push(&self.buffer[..n]).map_err(failure)?);
        }
    }
}
