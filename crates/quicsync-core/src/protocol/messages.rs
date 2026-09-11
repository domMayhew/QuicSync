//! Versioned, wire-neutral protocol data and canonical manifest digests.

use std::{collections::BTreeSet, fmt};

use crate::types::{
    Digest, EntryKind, Generation, IndexRecord, OperationId, Phase, RelativePath, SessionId,
};

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

/// Whether a peer can safely ignore a value that it does not understand.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Requirement {
    Required,
    Optional,
}

/// A capability's stable numeric code and compatibility requirement.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Capability {
    code: u16,
    requirement: Requirement,
}

impl Capability {
    pub const fn new(code: u16, requirement: Requirement) -> Self {
        Self { code, requirement }
    }

    pub const fn known(code: CapabilityCode, requirement: Requirement) -> Self {
        Self::new(code as u16, requirement)
    }

    pub const fn code(self) -> u16 {
        self.code
    }

    pub const fn requirement(self) -> Requirement {
        self.requirement
    }
}

/// Capabilities understood by this implementation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u16)]
pub enum CapabilityCode {
    StatusQuery = 1,
    DeltaTransfer = 2,
}

impl CapabilityCode {
    const fn from_wire(code: u16) -> Option<Self> {
        match code {
            1 => Some(Self::StatusQuery),
            2 => Some(Self::DeltaTransfer),
            _ => None,
        }
    }
}

/// A version or required extension cannot be interpreted safely.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompatibilityError {
    NoCommonVersion,
    UnknownRequiredValue(u16),
    DuplicateCapability(u16),
}

impl fmt::Display for CompatibilityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoCommonVersion => formatter.write_str("peers have no common protocol version"),
            Self::UnknownRequiredValue(code) => {
                write!(formatter, "unknown required protocol value {code}")
            }
            Self::DuplicateCapability(code) => {
                write!(formatter, "capability {code} was advertised more than once")
            }
        }
    }
}

impl std::error::Error for CompatibilityError {}

/// Selects the highest protocol version supported by both peers.
pub fn negotiate_version(
    offered: &[ProtocolVersion],
    supported: &[ProtocolVersion],
) -> Result<ProtocolVersion, CompatibilityError> {
    offered
        .iter()
        .filter(|version| supported.contains(version))
        .copied()
        .max()
        .ok_or(CompatibilityError::NoCommonVersion)
}

/// Validates capability compatibility and returns the understood subset.
///
/// Unknown optional capabilities are deliberately omitted. Unknown required
/// capabilities fail negotiation, so adding an extension never silently
/// changes the meaning of a session.
pub fn validate_capabilities(
    capabilities: &[Capability],
) -> Result<Vec<CapabilityCode>, CompatibilityError> {
    let mut seen = BTreeSet::new();
    let mut known = Vec::new();

    for capability in capabilities {
        if !seen.insert(capability.code) {
            return Err(CompatibilityError::DuplicateCapability(capability.code));
        }
        match CapabilityCode::from_wire(capability.code) {
            Some(code) => known.push(code),
            None => {
                validate_extension(capability.code, capability.requirement, &[])?;
            }
        }
    }

    known.sort_unstable();
    Ok(known)
}

/// Applies the compatibility rule shared by extensible message and enum codes.
///
/// The return value is `true` when the code is understood and `false` when an
/// unknown optional code should be ignored. An unknown required code is always
/// an error. The codec uses this rule after decoding a raw numeric code.
pub fn validate_extension(
    code: u16,
    requirement: Requirement,
    known_codes: &[u16],
) -> Result<bool, CompatibilityError> {
    if known_codes.contains(&code) {
        Ok(true)
    } else if requirement == Requirement::Optional {
        Ok(false)
    } else {
        Err(CompatibilityError::UnknownRequiredValue(code))
    }
}

/// Messages carried by the session's control stream.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Control {
    ClientHello {
        versions: Vec<ProtocolVersion>,
        capabilities: Vec<Capability>,
        nonce: [u8; 32],
    },
    ServerHello {
        version: ProtocolVersion,
        capabilities: Vec<Capability>,
        nonce: [u8; 32],
    },
    StartSync {
        session_id: SessionId,
        root_id: String,
    },
    PolicyBegin,
    PolicyRuleFile(PolicyRuleFile),
    PolicyEnd {
        policy_digest: Digest,
    },
    StartAccepted,
    StartStatus(SessionStatus),
    PlanBegin,
    Operation(Operation),
    PlanEnd {
        operation_count: u64,
        plan_digest: Digest,
    },
    CommitRequest {
        plan_digest: Digest,
    },
    CompleteAck {
        manifest_digest: Digest,
    },
    Cancel {
        reason: CancelReason,
    },
    Failure(WireFailure),
}

/// A source policy file and the directory at which its rules take effect.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyRuleFile {
    /// `None` denotes the synchronization root.
    pub scope: Option<RelativePath>,
    pub contents: Vec<u8>,
    pub digest: Digest,
}

/// Messages that delimit and describe the source's policy snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PolicyMessage {
    Begin,
    RuleFile(PolicyRuleFile),
    End { policy_digest: Digest },
}

/// The durable state returned when an existing session is queried.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SessionStatus {
    InProgress,
    ReadyToCommit,
    Committing,
    Complete { manifest_digest: Digest },
    Failed { error_code: WireErrorCode },
}

/// One item on the ordered destination-index stream.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IndexMessage {
    Record(IndexRecord),
    End { count: u64, manifest_digest: Digest },
}

/// A deterministic change in a synchronization plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Operation {
    UpsertDirectory {
        id: OperationId,
        generation: Generation,
        record: IndexRecord,
    },
    UpsertFile {
        id: OperationId,
        generation: Generation,
        record: IndexRecord,
    },
    UpsertSymlink {
        id: OperationId,
        generation: Generation,
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

    pub const fn generation(&self) -> Option<Generation> {
        match self {
            Self::UpsertDirectory { generation, .. }
            | Self::UpsertFile { generation, .. }
            | Self::UpsertSymlink { generation, .. } => Some(*generation),
            Self::Delete { .. } => None,
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
    pub digest: Digest,
}

/// Messages on one bounded file-transfer stream.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FileTransfer {
    FileRequest {
        id: OperationId,
        generation: Generation,
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
    DeltaHeader {
        result_size: u64,
        result_digest: Digest,
    },
    Copy {
        basis_offset: u64,
        length: u32,
    },
    Literal(Vec<u8>),
    DeltaEnd,
    TransferAccepted {
        id: OperationId,
        generation: Generation,
        digest: Digest,
    },
    Failure(WireFailure),
}

/// Positive acknowledgments with an unambiguous durable meaning.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Acknowledgment {
    StartAccepted,
    TransferAccepted {
        id: OperationId,
        generation: Generation,
        digest: Digest,
    },
    Complete {
        manifest_digest: Digest,
    },
}

/// A peer-visible reason for cancelling a session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CancelReason {
    UserRequested,
    SourceChanged,
    Superseded,
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

/// Whether a failure can safely be retried.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WireRetry {
    Never,
    NewSession,
    QueryThenRetry,
}

/// Bounded, safe-to-disclose failure information.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WireFailure {
    pub code: WireErrorCode,
    pub message: String,
    pub retry: WireRetry,
    pub phase: Phase,
    pub operation_id: Option<OperationId>,
    pub path: Option<RelativePath>,
}

/// Computes the manifest of an operation set in canonical operation-ID order.
///
/// Operation IDs define plan order, so callers may provide any in-memory
/// iteration order without changing the digest.
pub fn canonical_plan_digest(operations: &[Operation]) -> Digest {
    let mut canonical = operations.iter().collect::<Vec<_>>();
    canonical.sort_by_key(|operation| {
        (
            operation.id(),
            operation.generation().map_or(0, Generation::get),
        )
    });

    let mut encoder = CanonicalEncoder::new(b"quicsync-plan-v1");
    encoder.u64(canonical.len() as u64);
    for operation in canonical {
        encoder.operation(operation);
    }
    encoder.finish()
}

/// Computes an order-sensitive digest of a policy snapshot.
pub fn canonical_policy_digest(rules: &[PolicyRuleFile]) -> Digest {
    let mut encoder = CanonicalEncoder::new(b"quicsync-policy-v1");
    encoder.u64(rules.len() as u64);
    for rule in rules {
        encoder.optional_path(rule.scope.as_ref());
        encoder.bytes(&rule.contents);
        encoder.digest(rule.digest);
    }
    encoder.finish()
}

/// Computes an order-sensitive digest of a canonical index stream.
pub fn canonical_index_digest(records: &[IndexRecord]) -> Digest {
    let mut encoder = CanonicalEncoder::new(b"quicsync-index-v1");
    encoder.u64(records.len() as u64);
    for record in records {
        encoder.record(record);
    }
    encoder.finish()
}

struct CanonicalEncoder(blake3::Hasher);

impl CanonicalEncoder {
    fn new(domain: &[u8]) -> Self {
        let mut encoder = Self(blake3::Hasher::new());
        encoder.bytes(domain);
        encoder
    }

    fn finish(self) -> Digest {
        Digest::from_bytes(*self.0.finalize().as_bytes())
    }

    fn u8(&mut self, value: u8) {
        self.0.update(&[value]);
    }

    fn u32(&mut self, value: u32) {
        self.0.update(&value.to_le_bytes());
    }

    fn u64(&mut self, value: u64) {
        self.0.update(&value.to_le_bytes());
    }

    fn bytes(&mut self, value: &[u8]) {
        self.u64(value.len() as u64);
        self.0.update(value);
    }

    fn digest(&mut self, value: Digest) {
        self.0.update(value.as_bytes());
    }

    fn path(&mut self, value: &RelativePath) {
        self.u64(value.components().len() as u64);
        for component in value.components() {
            self.bytes(component);
        }
    }

    fn optional_path(&mut self, value: Option<&RelativePath>) {
        match value {
            Some(path) => {
                self.u8(1);
                self.path(path);
            }
            None => self.u8(0),
        }
    }

    fn optional_digest(&mut self, value: Option<Digest>) {
        match value {
            Some(digest) => {
                self.u8(1);
                self.digest(digest);
            }
            None => self.u8(0),
        }
    }

    fn optional_bytes(&mut self, value: Option<&[u8]>) {
        match value {
            Some(bytes) => {
                self.u8(1);
                self.bytes(bytes);
            }
            None => self.u8(0),
        }
    }

    fn entry_kind(&mut self, value: EntryKind) {
        self.u8(match value {
            EntryKind::Directory => 1,
            EntryKind::RegularFile => 2,
            EntryKind::Symlink => 3,
        });
    }

    fn record(&mut self, value: &IndexRecord) {
        self.path(&value.path);
        self.entry_kind(value.metadata.kind());
        self.u32(value.metadata.mode());
        self.0.update(&value.metadata.mtime_ns().to_le_bytes());
        self.u64(value.metadata.size());
        self.optional_digest(value.digest);
        self.optional_bytes(value.symlink_target.as_deref());
    }

    fn operation(&mut self, value: &Operation) {
        match value {
            Operation::UpsertDirectory {
                id,
                generation,
                record,
            } => self.upsert(1, *id, *generation, record),
            Operation::UpsertFile {
                id,
                generation,
                record,
            } => self.upsert(2, *id, *generation, record),
            Operation::UpsertSymlink {
                id,
                generation,
                record,
            } => self.upsert(3, *id, *generation, record),
            Operation::Delete {
                id,
                path,
                expected_kind,
            } => {
                self.u8(4);
                self.u64(id.get());
                self.path(path);
                self.entry_kind(*expected_kind);
            }
        }
    }

    fn upsert(&mut self, tag: u8, id: OperationId, generation: Generation, record: &IndexRecord) {
        self.u8(tag);
        self.u64(id.get());
        self.u32(generation.get());
        self.record(record);
    }
}
