//! Wire-neutral values shared by QuicSync's subsystems.

use std::fmt;

/// Identifies an operation within a session plan.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct OperationId(u64);

impl OperationId {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

impl From<u64> for OperationId {
    fn from(value: u64) -> Self {
        Self::new(value)
    }
}

/// Whole-file (or symlink-target) BLAKE3 hash used to detect index changes.
/// Not a transfer-integrity check or a librsync block checksum.
/// TODO(HME-453): revisit full-tree hashing before settling the long-term change
/// detector; see docs/architecture.md, "Review Notes (HME-453)", for its I/O cost
/// and the metadata-only comparison tradeoff.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Digest([u8; 32]);

impl Digest {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub const fn into_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl From<[u8; 32]> for Digest {
    fn from(value: [u8; 32]) -> Self {
        Self::from_bytes(value)
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Why a sequence of raw path components is not a valid relative path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PathError {
    EmptyPath,
    EmptyComponent,
    CurrentDirectory,
    ParentDirectory,
    Separator,
    Nul,
}

impl fmt::Display for PathError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::EmptyPath => "path has no components",
            Self::EmptyComponent => "path contains an empty component",
            Self::CurrentDirectory => "path contains a current-directory component",
            Self::ParentDirectory => "path contains a parent-directory component",
            Self::Separator => "path component contains a separator",
            Self::Nul => "path component contains a NUL byte",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for PathError {}

/// A non-empty, root-relative sequence of raw Unix filename components.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RelativePath(Vec<Vec<u8>>);

impl RelativePath {
    pub fn new(components: Vec<Vec<u8>>) -> Result<Self, PathError> {
        if components.is_empty() {
            return Err(PathError::EmptyPath);
        }

        for component in &components {
            if component.is_empty() {
                return Err(PathError::EmptyComponent);
            }
            if component == b"." {
                return Err(PathError::CurrentDirectory);
            }
            if component == b".." {
                return Err(PathError::ParentDirectory);
            }
            if component.contains(&b'/') {
                return Err(PathError::Separator);
            }
            if component.contains(&0) {
                return Err(PathError::Nul);
            }
        }

        Ok(Self(components))
    }

    pub fn components(&self) -> &[Vec<u8>] {
        &self.0
    }

    pub fn into_components(self) -> Vec<Vec<u8>> {
        self.0
    }
}

/// The portable entry kinds supported by the synchronization model.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum EntryKind {
    Directory,
    RegularFile,
    Symlink,
}

/// Portable metadata for one managed filesystem entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EntryMetadata {
    kind: EntryKind,
    mode: u32,
    mtime_ns: i128,
    size: u64,
}

impl EntryMetadata {
    pub const fn new(kind: EntryKind, mode: u32, mtime_ns: i128, size: u64) -> Self {
        Self {
            kind,
            mode,
            mtime_ns,
            size,
        }
    }

    pub const fn kind(self) -> EntryKind {
        self.kind
    }

    pub const fn mode(self) -> u32 {
        self.mode
    }

    pub const fn mtime_ns(self) -> i128 {
        self.mtime_ns
    }

    pub const fn size(self) -> u64 {
        self.size
    }
}

/// One canonical entry in a filesystem index.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IndexRecord {
    pub path: RelativePath,
    pub metadata: EntryMetadata,
    pub digest: Option<Digest>,
    pub symlink_target: Option<Vec<u8>>,
}

/// A synchronization session's protocol phase.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Phase {
    Handshake,
    Policy,
    Indexing,
    Planning,
    Transferring,
    ReadyToCommit,
    Committing,
    Complete,
    Failed,
}
