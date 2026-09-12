//! Bounded canonical wire encoding and incremental decoding.

use std::{fmt, marker::PhantomData};

use crate::{
    config::Limits,
    protocol::messages::{
        CURRENT_VERSION, Control, FileBasis, FileTransfer, IndexMessage, Operation,
        ProtocolVersion, WireErrorCode, WireFailure,
    },
    types::{Digest, EntryKind, EntryMetadata, IndexRecord, OperationId, Phase, RelativePath},
};

const MAX_VARINT_BYTES: usize = 10;
const VERSION_BYTES: usize = 2;
const KIND_BYTES: usize = 1;

/// Local bounds applied to every encoded and decoded value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CodecLimits {
    max_frame_bytes: usize,
    max_path_bytes: usize,
    max_components: usize,
    max_collection_items: usize,
}

impl CodecLimits {
    pub const fn new(
        max_frame_bytes: usize,
        max_path_bytes: usize,
        max_components: usize,
        max_collection_items: usize,
    ) -> Result<Self, CodecError> {
        if max_frame_bytes < KIND_BYTES + VERSION_BYTES {
            return Err(CodecError::InvalidLimits);
        }
        if max_path_bytes == 0
            || max_path_bytes > max_frame_bytes
            || max_components == 0
            || max_collection_items == 0
        {
            return Err(CodecError::InvalidLimits);
        }
        Ok(Self {
            max_frame_bytes,
            max_path_bytes,
            max_components,
            max_collection_items,
        })
    }

    pub const fn max_frame_bytes(self) -> usize {
        self.max_frame_bytes
    }
}

impl Default for CodecLimits {
    fn default() -> Self {
        Self::from(&Limits::default())
    }
}

impl From<&Limits> for CodecLimits {
    fn from(limits: &Limits) -> Self {
        Self {
            max_frame_bytes: limits.max_frame_bytes(),
            max_path_bytes: limits.max_path_bytes(),
            max_components: limits.max_components(),
            max_collection_items: limits.max_components(),
        }
    }
}

/// A canonical framing or payload violation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CodecError {
    InvalidLimits,
    FrameTooLarge { declared: u64, maximum: usize },
    VarintOverflow,
    NonCanonicalVarint,
    UnexpectedEof,
    TrailingBytes,
    UnknownMessageKind(u8),
    UnsupportedVersion(ProtocolVersion),
    InvalidValue(&'static str),
    DuplicateValue(&'static str),
    NonCanonicalOrder(&'static str),
    LimitExceeded(&'static str),
}

impl fmt::Display for CodecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimits => formatter.write_str("invalid codec limits"),
            Self::FrameTooLarge { declared, maximum } => {
                write!(
                    formatter,
                    "frame length {declared} exceeds local limit {maximum}"
                )
            }
            Self::VarintOverflow => formatter.write_str("varint overflows u64"),
            Self::NonCanonicalVarint => formatter.write_str("varint is not minimally encoded"),
            Self::UnexpectedEof => formatter.write_str("unexpected end of frame"),
            Self::TrailingBytes => formatter.write_str("frame contains trailing bytes"),
            Self::UnknownMessageKind(kind) => write!(formatter, "unknown message kind {kind}"),
            Self::UnsupportedVersion(version) => {
                write!(formatter, "unsupported protocol version {}", version.get())
            }
            Self::InvalidValue(name) => write!(formatter, "invalid {name}"),
            Self::DuplicateValue(name) => write!(formatter, "duplicate {name}"),
            Self::NonCanonicalOrder(name) => write!(formatter, "noncanonical {name} order"),
            Self::LimitExceeded(name) => write!(formatter, "{name} exceeds local limit"),
        }
    }
}

impl std::error::Error for CodecError {}

/// A message category with stable kind tags and canonical payload fields.
pub trait WireMessage: Sized {
    fn kind(&self) -> u8;
    fn encode_fields(&self, writer: &mut Writer<'_>) -> Result<(), CodecError>;
    fn decode_fields(kind: u8, reader: &mut Reader<'_>) -> Result<Self, CodecError>;
}

/// Encodes one complete length-delimited frame.
pub fn encode<T: WireMessage>(value: &T, limits: &CodecLimits) -> Result<Vec<u8>, CodecError> {
    let mut payload = Vec::new();
    payload.push(value.kind());
    payload.extend_from_slice(&CURRENT_VERSION.get().to_le_bytes());
    let mut writer = Writer {
        bytes: payload,
        limits,
    };
    value.encode_fields(&mut writer)?;
    if writer.bytes.len() > limits.max_frame_bytes {
        return Err(CodecError::FrameTooLarge {
            declared: writer.bytes.len() as u64,
            maximum: limits.max_frame_bytes,
        });
    }

    let mut frame = Vec::with_capacity(MAX_VARINT_BYTES + writer.bytes.len());
    put_varint(writer.bytes.len() as u64, &mut frame);
    frame.extend_from_slice(&writer.bytes);
    Ok(frame)
}

/// Decodes exactly one complete frame and rejects bytes after it.
pub fn decode<T: WireMessage>(wire: &[u8], limits: &CodecLimits) -> Result<T, CodecError> {
    let (declared, header_len) = parse_varint(wire)?;
    check_frame_length(declared, limits)?;
    let payload_len = usize::try_from(declared).map_err(|_| CodecError::FrameTooLarge {
        declared,
        maximum: limits.max_frame_bytes,
    })?;
    let end = header_len
        .checked_add(payload_len)
        .ok_or(CodecError::FrameTooLarge {
            declared,
            maximum: limits.max_frame_bytes,
        })?;
    if wire.len() < end {
        return Err(CodecError::UnexpectedEof);
    }
    if wire.len() != end {
        return Err(CodecError::TrailingBytes);
    }
    decode_payload(&wire[header_len..end], limits)
}

/// Incrementally decodes arbitrary input chunks while buffering at most one frame.
pub struct Decoder<T> {
    limits: CodecLimits,
    header: [u8; MAX_VARINT_BYTES],
    header_len: usize,
    expected: Option<usize>,
    payload: Vec<u8>,
    marker: PhantomData<T>,
}

impl<T: WireMessage> Decoder<T> {
    pub fn new(limits: CodecLimits) -> Self {
        Self {
            limits,
            header: [0; MAX_VARINT_BYTES],
            header_len: 0,
            expected: None,
            payload: Vec::new(),
            marker: PhantomData,
        }
    }

    pub fn buffered_len(&self) -> usize {
        self.header_len + self.payload.len()
    }

    pub fn push(&mut self, mut input: &[u8]) -> Result<Vec<T>, CodecError> {
        let mut messages = Vec::new();
        while !input.is_empty() {
            if self.expected.is_none() {
                let byte = input[0];
                input = &input[1..];
                if self.header_len == MAX_VARINT_BYTES {
                    self.reset();
                    return Err(CodecError::VarintOverflow);
                }
                self.header[self.header_len] = byte;
                self.header_len += 1;
                if byte & 0x80 == 0 {
                    let declared = match parse_varint(&self.header[..self.header_len]) {
                        Ok((value, _)) => value,
                        Err(error) => {
                            self.reset();
                            return Err(error);
                        }
                    };
                    if let Err(error) = check_frame_length(declared, &self.limits) {
                        self.reset();
                        return Err(error);
                    }
                    let expected = declared as usize;
                    self.expected = Some(expected);
                    self.payload.reserve(expected);
                }
            }

            if let Some(expected) = self.expected {
                let needed = expected - self.payload.len();
                let take = needed.min(input.len());
                self.payload.extend_from_slice(&input[..take]);
                input = &input[take..];
                if self.payload.len() == expected {
                    let decoded = decode_payload::<T>(&self.payload, &self.limits);
                    self.reset();
                    messages.push(decoded?);
                }
            }
        }
        Ok(messages)
    }

    pub fn finish(self) -> Result<(), CodecError> {
        if self.header_len == 0 && self.payload.is_empty() && self.expected.is_none() {
            Ok(())
        } else {
            Err(CodecError::UnexpectedEof)
        }
    }

    fn reset(&mut self) {
        self.header_len = 0;
        self.expected = None;
        self.payload.clear();
    }
}

fn check_frame_length(declared: u64, limits: &CodecLimits) -> Result<(), CodecError> {
    if declared > limits.max_frame_bytes as u64 {
        return Err(CodecError::FrameTooLarge {
            declared,
            maximum: limits.max_frame_bytes,
        });
    }
    if declared < (KIND_BYTES + VERSION_BYTES) as u64 {
        return Err(CodecError::InvalidValue("frame length"));
    }
    Ok(())
}

fn decode_payload<T: WireMessage>(payload: &[u8], limits: &CodecLimits) -> Result<T, CodecError> {
    let mut reader = Reader::new(payload, limits);
    let kind = reader.u8()?;
    let version = ProtocolVersion::new(reader.u16()?);
    if version != CURRENT_VERSION {
        return Err(CodecError::UnsupportedVersion(version));
    }
    let value = T::decode_fields(kind, &mut reader)?;
    reader.finish()?;
    Ok(value)
}

fn put_varint(mut value: u64, output: &mut Vec<u8>) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        output.push(byte);
        if value == 0 {
            break;
        }
    }
}

fn parse_varint(input: &[u8]) -> Result<(u64, usize), CodecError> {
    let mut value = 0_u64;
    for (index, byte) in input.iter().copied().enumerate().take(MAX_VARINT_BYTES) {
        if index == 9 && byte > 1 {
            return Err(CodecError::VarintOverflow);
        }
        value |= u64::from(byte & 0x7f) << (index * 7);
        if byte & 0x80 == 0 {
            if index > 0 && byte == 0 {
                return Err(CodecError::NonCanonicalVarint);
            }
            return Ok((value, index + 1));
        }
    }
    if input.len() >= MAX_VARINT_BYTES {
        Err(CodecError::VarintOverflow)
    } else {
        Err(CodecError::UnexpectedEof)
    }
}

/// Canonical payload writer exposed only through [`WireMessage`].
pub struct Writer<'a> {
    bytes: Vec<u8>,
    limits: &'a CodecLimits,
}

impl Writer<'_> {
    fn u8(&mut self, value: u8) {
        self.bytes.push(value);
    }
    fn u16(&mut self, value: u16) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }
    fn u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }
    fn u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }
    fn i128(&mut self, value: i128) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }
    fn raw(&mut self, value: &[u8]) {
        self.bytes.extend_from_slice(value);
    }
    fn length(&mut self, value: usize) {
        put_varint(value as u64, &mut self.bytes);
    }
    fn bytes(&mut self, value: &[u8]) {
        self.length(value.len());
        self.raw(value);
    }
    fn string(&mut self, value: &str) {
        self.bytes(value.as_bytes());
    }
    fn digest(&mut self, value: Digest) {
        self.raw(value.as_bytes());
    }

    fn path(&mut self, path: &RelativePath) -> Result<(), CodecError> {
        if path.components().len() > self.limits.max_components {
            return Err(CodecError::LimitExceeded("path components"));
        }
        let total = path
            .components()
            .iter()
            .try_fold(0_usize, |total, component| {
                total
                    .checked_add(component.len())
                    .ok_or(CodecError::LimitExceeded("path bytes"))
            })?;
        if total > self.limits.max_path_bytes {
            return Err(CodecError::LimitExceeded("path bytes"));
        }
        self.length(path.components().len());
        for component in path.components() {
            self.bytes(component);
        }
        Ok(())
    }

    fn optional<T>(
        &mut self,
        value: Option<T>,
        write: impl FnOnce(&mut Self, T) -> Result<(), CodecError>,
    ) -> Result<(), CodecError> {
        match value {
            Some(value) => {
                self.u8(1);
                write(self, value)
            }
            None => {
                self.u8(0);
                Ok(())
            }
        }
    }

    fn record(&mut self, value: &IndexRecord) -> Result<(), CodecError> {
        self.path(&value.path)?;
        self.entry_kind(value.metadata.kind());
        self.u32(value.metadata.mode());
        self.i128(value.metadata.mtime_ns());
        self.u64(value.metadata.size());
        self.optional(value.digest, |writer, digest| {
            writer.digest(digest);
            Ok(())
        })?;
        self.optional(value.symlink_target.as_deref(), |writer, bytes| {
            writer.bytes(bytes);
            Ok(())
        })
    }

    fn entry_kind(&mut self, value: EntryKind) {
        self.u8(match value {
            EntryKind::Directory => 1,
            EntryKind::RegularFile => 2,
            EntryKind::Symlink => 3,
        });
    }

    fn operation(&mut self, value: &Operation) -> Result<(), CodecError> {
        match value {
            Operation::UpsertDirectory { id, record } => self.upsert(1, *id, record),
            Operation::UpsertFile { id, record } => self.upsert(2, *id, record),
            Operation::UpsertSymlink { id, record } => self.upsert(3, *id, record),
            Operation::Delete {
                id,
                path,
                expected_kind,
            } => {
                self.u8(4);
                self.u64(id.get());
                self.path(path)?;
                self.entry_kind(*expected_kind);
                Ok(())
            }
        }
    }

    fn upsert(&mut self, tag: u8, id: OperationId, record: &IndexRecord) -> Result<(), CodecError> {
        self.u8(tag);
        self.u64(id.get());
        self.record(record)
    }

    fn failure(&mut self, value: &WireFailure) -> Result<(), CodecError> {
        self.u16(value.code as u16);
        self.string(&value.message);
        self.u8(phase_tag(value.phase));
        self.optional(value.operation_id, |writer, id| {
            writer.u64(id.get());
            Ok(())
        })?;
        self.optional(value.path.as_ref(), |writer, path| writer.path(path))
    }
}

/// Canonical payload reader exposed only through [`WireMessage`].
pub struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
    limits: &'a CodecLimits,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8], limits: &'a CodecLimits) -> Self {
        Self {
            bytes,
            offset: 0,
            limits,
        }
    }
    fn take(&mut self, length: usize) -> Result<&'a [u8], CodecError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(CodecError::UnexpectedEof)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(CodecError::UnexpectedEof)?;
        self.offset = end;
        Ok(value)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], CodecError> {
        Ok(self.take(N)?.try_into().expect("length checked"))
    }
    fn u8(&mut self) -> Result<u8, CodecError> {
        Ok(self.array::<1>()?[0])
    }
    fn u16(&mut self) -> Result<u16, CodecError> {
        Ok(u16::from_le_bytes(self.array()?))
    }
    fn u32(&mut self) -> Result<u32, CodecError> {
        Ok(u32::from_le_bytes(self.array()?))
    }
    fn u64(&mut self) -> Result<u64, CodecError> {
        Ok(u64::from_le_bytes(self.array()?))
    }
    fn i128(&mut self) -> Result<i128, CodecError> {
        Ok(i128::from_le_bytes(self.array()?))
    }
    fn length(&mut self) -> Result<usize, CodecError> {
        let (value, used) = parse_varint(&self.bytes[self.offset..])?;
        self.offset += used;
        usize::try_from(value).map_err(|_| CodecError::LimitExceeded("length"))
    }
    fn bounded_length(&mut self, maximum: usize, name: &'static str) -> Result<usize, CodecError> {
        let length = self.length()?;
        if length > maximum {
            Err(CodecError::LimitExceeded(name))
        } else {
            Ok(length)
        }
    }
    fn bytes(&mut self) -> Result<Vec<u8>, CodecError> {
        let length = self.bounded_length(self.limits.max_frame_bytes, "field bytes")?;
        Ok(self.take(length)?.to_vec())
    }
    fn string(&mut self) -> Result<String, CodecError> {
        String::from_utf8(self.bytes()?).map_err(|_| CodecError::InvalidValue("UTF-8 string"))
    }
    fn digest(&mut self) -> Result<Digest, CodecError> {
        Ok(Digest::from_bytes(self.array()?))
    }
    fn optional<T>(
        &mut self,
        read: impl FnOnce(&mut Self) -> Result<T, CodecError>,
    ) -> Result<Option<T>, CodecError> {
        match self.u8()? {
            0 => Ok(None),
            1 => read(self).map(Some),
            _ => Err(CodecError::InvalidValue("optional tag")),
        }
    }
    fn path(&mut self) -> Result<RelativePath, CodecError> {
        let count = self.bounded_length(self.limits.max_components, "path components")?;
        if count == 0 {
            return Err(CodecError::InvalidValue("relative path"));
        }
        let mut total = 0_usize;
        let mut components = Vec::with_capacity(count);
        for _ in 0..count {
            let remaining = self.limits.max_path_bytes - total;
            let length = self.bounded_length(remaining, "path bytes")?;
            total += length;
            components.push(self.take(length)?.to_vec());
        }
        RelativePath::new(components).map_err(|_| CodecError::InvalidValue("relative path"))
    }
    fn entry_kind(&mut self) -> Result<EntryKind, CodecError> {
        match self.u8()? {
            1 => Ok(EntryKind::Directory),
            2 => Ok(EntryKind::RegularFile),
            3 => Ok(EntryKind::Symlink),
            _ => Err(CodecError::InvalidValue("entry kind")),
        }
    }
    fn record(&mut self) -> Result<IndexRecord, CodecError> {
        let path = self.path()?;
        let kind = self.entry_kind()?;
        let mode = self.u32()?;
        let mtime_ns = self.i128()?;
        let size = self.u64()?;
        let digest = self.optional(Self::digest)?;
        let symlink_target = self.optional(Self::bytes)?;
        Ok(IndexRecord {
            path,
            metadata: EntryMetadata::new(kind, mode, mtime_ns, size),
            digest,
            symlink_target,
        })
    }
    fn operation(&mut self) -> Result<Operation, CodecError> {
        let tag = self.u8()?;
        let id = OperationId::new(self.u64()?);
        match tag {
            1..=3 => {
                let record = self.record()?;
                Ok(match tag {
                    1 => Operation::UpsertDirectory { id, record },
                    2 => Operation::UpsertFile { id, record },
                    _ => Operation::UpsertSymlink { id, record },
                })
            }
            4 => Ok(Operation::Delete {
                id,
                path: self.path()?,
                expected_kind: self.entry_kind()?,
            }),
            _ => Err(CodecError::InvalidValue("operation tag")),
        }
    }
    fn failure(&mut self) -> Result<WireFailure, CodecError> {
        Ok(WireFailure {
            code: wire_error(self.u16()?)?,
            message: self.string()?,
            phase: phase(self.u8()?)?,
            operation_id: self.optional(|reader| Ok(OperationId::new(reader.u64()?)))?,
            path: self.optional(Self::path)?,
        })
    }
    fn finish(&self) -> Result<(), CodecError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(CodecError::TrailingBytes)
        }
    }
}

impl WireMessage for Control {
    fn kind(&self) -> u8 {
        match self {
            Self::StartSync { .. } => 3,
            Self::StartAccepted => 7,
            Self::Operation(_) => 10,
            Self::PlanEnd => 11,
            Self::CompleteAck => 13,
            Self::Failure(_) => 15,
        }
    }
    fn encode_fields(&self, writer: &mut Writer<'_>) -> Result<(), CodecError> {
        match self {
            Self::StartSync { root_id } => {
                writer.string(root_id);
                Ok(())
            }
            Self::StartAccepted | Self::PlanEnd | Self::CompleteAck => Ok(()),
            Self::Operation(operation) => writer.operation(operation),
            Self::Failure(failure) => writer.failure(failure),
        }
    }
    fn decode_fields(kind: u8, reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        match kind {
            3 => Ok(Self::StartSync {
                root_id: reader.string()?,
            }),
            7 => Ok(Self::StartAccepted),
            10 => Ok(Self::Operation(reader.operation()?)),
            11 => Ok(Self::PlanEnd),
            13 => Ok(Self::CompleteAck),
            15 => Ok(Self::Failure(reader.failure()?)),
            _ => Err(CodecError::UnknownMessageKind(kind)),
        }
    }
}

impl WireMessage for IndexMessage {
    fn kind(&self) -> u8 {
        match self {
            Self::Record(_) => 1,
            Self::End => 2,
        }
    }
    fn encode_fields(&self, writer: &mut Writer<'_>) -> Result<(), CodecError> {
        match self {
            Self::Record(record) => writer.record(record),
            Self::End => Ok(()),
        }
    }
    fn decode_fields(kind: u8, reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        match kind {
            1 => Ok(Self::Record(reader.record()?)),
            2 => Ok(Self::End),
            _ => Err(CodecError::UnknownMessageKind(kind)),
        }
    }
}

impl WireMessage for FileTransfer {
    fn kind(&self) -> u8 {
        match self {
            Self::FileRequest { .. } => 1,
            Self::SignatureHeader { .. } => 2,
            Self::SignatureBlock { .. } => 3,
            Self::DeltaHeader => 4,
            Self::Copy { .. } => 5,
            Self::Literal(_) => 6,
            Self::DeltaEnd => 7,
            Self::TransferAccepted { .. } => 8,
            Self::Failure(_) => 9,
        }
    }
    fn encode_fields(&self, writer: &mut Writer<'_>) -> Result<(), CodecError> {
        match self {
            Self::FileRequest { id, path, basis } => {
                writer.u64(id.get());
                writer.path(path)?;
                writer.optional(*basis, |writer, basis| {
                    writer.u64(basis.size);
                    Ok(())
                })
            }
            Self::SignatureHeader {
                basis_size,
                block_size,
                block_count,
            } => {
                writer.u64(*basis_size);
                writer.u32(*block_size);
                writer.u32(*block_count);
                Ok(())
            }
            Self::SignatureBlock { weak, strong } => {
                writer.u32(*weak);
                writer.digest(*strong);
                Ok(())
            }
            Self::DeltaHeader => Ok(()),
            Self::Copy {
                basis_offset,
                length,
            } => {
                writer.u64(*basis_offset);
                writer.u32(*length);
                Ok(())
            }
            Self::Literal(bytes) => {
                writer.bytes(bytes);
                Ok(())
            }
            Self::DeltaEnd => Ok(()),
            Self::TransferAccepted { id } => {
                writer.u64(id.get());
                Ok(())
            }
            Self::Failure(failure) => writer.failure(failure),
        }
    }
    fn decode_fields(kind: u8, reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        match kind {
            1 => Ok(Self::FileRequest {
                id: OperationId::new(reader.u64()?),
                path: reader.path()?,
                basis: reader.optional(|reader| {
                    Ok(FileBasis {
                        size: reader.u64()?,
                    })
                })?,
            }),
            2 => Ok(Self::SignatureHeader {
                basis_size: reader.u64()?,
                block_size: reader.u32()?,
                block_count: reader.u32()?,
            }),
            3 => Ok(Self::SignatureBlock {
                weak: reader.u32()?,
                strong: reader.digest()?,
            }),
            4 => Ok(Self::DeltaHeader),
            5 => Ok(Self::Copy {
                basis_offset: reader.u64()?,
                length: reader.u32()?,
            }),
            6 => Ok(Self::Literal(reader.bytes()?)),
            7 => Ok(Self::DeltaEnd),
            8 => Ok(Self::TransferAccepted {
                id: OperationId::new(reader.u64()?),
            }),
            9 => Ok(Self::Failure(reader.failure()?)),
            _ => Err(CodecError::UnknownMessageKind(kind)),
        }
    }
}

fn phase_tag(value: Phase) -> u8 {
    match value {
        Phase::Handshake => 1,
        Phase::Policy => 2,
        Phase::Indexing => 3,
        Phase::Planning => 4,
        Phase::Transferring => 5,
        Phase::ReadyToCommit => 6,
        Phase::Committing => 7,
        Phase::Complete => 8,
        Phase::Failed => 9,
    }
}
fn phase(value: u8) -> Result<Phase, CodecError> {
    match value {
        1 => Ok(Phase::Handshake),
        2 => Ok(Phase::Policy),
        3 => Ok(Phase::Indexing),
        4 => Ok(Phase::Planning),
        5 => Ok(Phase::Transferring),
        6 => Ok(Phase::ReadyToCommit),
        7 => Ok(Phase::Committing),
        8 => Ok(Phase::Complete),
        9 => Ok(Phase::Failed),
        _ => Err(CodecError::InvalidValue("phase")),
    }
}
fn wire_error(value: u16) -> Result<WireErrorCode, CodecError> {
    match value {
        1 => Ok(WireErrorCode::IncompatibleProtocol),
        2 => Ok(WireErrorCode::InvalidMessage),
        3 => Ok(WireErrorCode::Unauthorized),
        4 => Ok(WireErrorCode::InvalidPath),
        5 => Ok(WireErrorCode::IntegrityFailure),
        6 => Ok(WireErrorCode::ResourceLimit),
        7 => Ok(WireErrorCode::UnsupportedFilesystem),
        8 => Ok(WireErrorCode::Cancelled),
        9 => Ok(WireErrorCode::Internal),
        _ => Err(CodecError::InvalidValue("wire error code")),
    }
}
