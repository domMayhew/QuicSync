//! Fixed-version messages for a single streamed sync attempt.

use crate::types::{Digest, EntryKind, IndexRecord, OperationId, Phase, RelativePath};

/// The first protocol version specified by QuicSync.
pub const CURRENT_VERSION: ProtocolVersion = ProtocolVersion::new(1);

/// A protocol version advertised during the handshake.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ProtocolVersion(u16);

impl ProtocolVersion {
    pub const fn new(value: u16) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u16 {
        self.0
    }
}

/// Messages carried by the session's control stream.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Control {
    StartSync {
        root_id: String,
    },
    StartAccepted,
    Operation(Operation),
    /// No more operations follow; carries no count or integrity manifest.
    PlanEnd,
    CompleteAck,
    Failure(WireFailure),
}

/// One item on the ordered destination-index stream.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IndexMessage {
    Record(IndexRecord),
    End,
}

/// A deterministic change in a synchronization plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Operation {
    UpsertDirectory {
        id: OperationId,
        record: IndexRecord,
    },
    UpsertFile {
        id: OperationId,
        record: IndexRecord,
    },
    UpsertSymlink {
        id: OperationId,
        record: IndexRecord,
    },
    Delete {
        id: OperationId,
        path: RelativePath,
        expected_kind: EntryKind,
    },
}

impl Operation {
    pub const fn id(&self) -> OperationId {
        match self {
            Self::UpsertDirectory { id, .. }
            | Self::UpsertFile { id, .. }
            | Self::UpsertSymlink { id, .. }
            | Self::Delete { id, .. } => *id,
        }
    }

    pub const fn path(&self) -> &RelativePath {
        match self {
            Self::UpsertDirectory { record, .. }
            | Self::UpsertFile { record, .. }
            | Self::UpsertSymlink { record, .. } => &record.path,
            Self::Delete { path, .. } => path,
        }
    }
}

/// A destination file that may be used as the basis for a delta.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileBasis {
    pub size: u64,
}

/// Messages on one bounded file-transfer stream.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FileTransfer {
    FileRequest {
        id: OperationId,
        path: RelativePath,
        basis: Option<FileBasis>,
    },
    SignatureHeader {
        basis_size: u64,
        block_size: u32,
        block_count: u32,
    },
    SignatureBlock {
        weak: u32,
        strong: Digest,
    },
    DeltaHeader,
    Copy {
        basis_offset: u64,
        length: u32,
    },
    Literal(Vec<u8>),
    DeltaEnd,
    TransferAccepted {
        id: OperationId,
    },
    Failure(WireFailure),
}

/// Stable failure codes carried across the protocol boundary.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u16)]
pub enum WireErrorCode {
    IncompatibleProtocol = 1,
    InvalidMessage = 2,
    Unauthorized = 3,
    InvalidPath = 4,
    IntegrityFailure = 5,
    ResourceLimit = 6,
    UnsupportedFilesystem = 7,
    Cancelled = 8,
    Internal = 9,
}

/// Bounded, safe-to-disclose failure information.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WireFailure {
    pub code: WireErrorCode,
    pub message: String,
    pub phase: Phase,
    pub operation_id: Option<OperationId>,
    pub path: Option<RelativePath>,
}
