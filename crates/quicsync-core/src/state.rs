//! Durable, replay-safe synchronization session state.

use std::{
    error::Error,
    fmt,
    path::Path,
    sync::{Mutex, MutexGuard},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};

use crate::{
    error::ErrorCode,
    types::{Digest, Generation, OperationId, Phase, SessionId},
};

const SCHEMA_VERSION: u32 = 1;
pub const MAX_JOURNAL_PAGE_SIZE: usize = 1_024;

/// The non-secret identity tuple used to deduplicate destination sessions.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct SessionKey {
    peer_fingerprint: [u8; 32],
    root_id: String,
    session_id: SessionId,
}

impl SessionKey {
    pub fn new(
        peer_fingerprint: [u8; 32],
        root_id: impl Into<String>,
        session_id: SessionId,
    ) -> Result<Self, StateError> {
        let root_id = root_id.into();
        if root_id.is_empty() || root_id.len() > 255 || root_id.contains('\0') {
            return Err(StateError::InvalidRootId);
        }
        Ok(Self {
            peer_fingerprint,
            root_id,
            session_id,
        })
    }

    pub const fn peer_fingerprint(&self) -> &[u8; 32] {
        &self.peer_fingerprint
    }
    pub fn root_id(&self) -> &str {
        &self.root_id
    }
    pub const fn session_id(&self) -> SessionId {
        self.session_id
    }
}

/// Durable status returned when a client queries or reclaims a session ID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionState {
    InProgress { phase: Phase },
    ReadyToCommit,
    Committing,
    Complete { manifest_digest: Digest },
    Failed { error_code: ErrorCode },
}

impl SessionState {
    pub const fn phase(self) -> Phase {
        match self {
            Self::InProgress { phase } => phase,
            Self::ReadyToCommit => Phase::ReadyToCommit,
            Self::Committing => Phase::Committing,
            Self::Complete { .. } => Phase::Complete,
            Self::Failed { .. } => Phase::Failed,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClaimResult {
    Claimed,
    Existing(SessionState),
}

/// Replay metadata for one planned operation.
///
/// This contains only identifiers and a canonical descriptor digest. File content, symlink
/// targets, credentials, and private key bytes cannot be passed to the state layer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JournalEntry {
    operation_id: OperationId,
    generation: Generation,
    descriptor_digest: Digest,
}

impl JournalEntry {
    pub const fn new(
        operation_id: OperationId,
        generation: Generation,
        descriptor_digest: Digest,
    ) -> Self {
        Self {
            operation_id,
            generation,
            descriptor_digest,
        }
    }
    pub const fn operation_id(self) -> OperationId {
        self.operation_id
    }
    pub const fn generation(self) -> Generation {
        self.generation
    }
    pub const fn descriptor_digest(self) -> Digest {
        self.descriptor_digest
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GenerationResult {
    Recorded,
    Replay,
    Superseded,
}

#[derive(Debug)]
pub enum StateError {
    Database(rusqlite::Error),
    InvalidRootId,
    MissingSession,
    CorruptState(&'static str),
    InvalidTransition {
        from: Phase,
        to: Phase,
    },
    PhaseConflict {
        expected: Phase,
        actual: Phase,
    },
    GenerationConflict {
        operation: OperationId,
        generation: Generation,
    },
    StaleGeneration {
        operation: OperationId,
        current: Generation,
        received: Generation,
    },
    LockPoisoned,
    InvalidTimestamp,
    InvalidPageSize,
}

impl fmt::Display for StateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Database(error) => write!(formatter, "session state database error: {error}"),
            Self::InvalidRootId => {
                formatter.write_str("root ID is empty, too long, or contains NUL")
            }
            Self::MissingSession => formatter.write_str("session has not been claimed"),
            Self::CorruptState(message) => write!(formatter, "session state is corrupt: {message}"),
            Self::InvalidTransition { from, to } => write!(
                formatter,
                "invalid session phase transition from {from:?} to {to:?}"
            ),
            Self::PhaseConflict { expected, actual } => write!(
                formatter,
                "session phase changed: expected {expected:?}, found {actual:?}"
            ),
            Self::GenerationConflict {
                operation,
                generation,
            } => write!(
                formatter,
                "operation {} generation {} has a different descriptor",
                operation.get(),
                generation.get()
            ),
            Self::StaleGeneration {
                operation,
                current,
                received,
            } => write!(
                formatter,
                "operation {} generation {} is older than {}",
                operation.get(),
                received.get(),
                current.get()
            ),
            Self::LockPoisoned => formatter.write_str("session state database lock is poisoned"),
            Self::InvalidTimestamp => {
                formatter.write_str("retention timestamp is outside the supported range")
            }
            Self::InvalidPageSize => formatter.write_str("journal page size is outside 1..=1024"),
        }
    }
}

impl Error for StateError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Database(error) => Some(error),
            _ => None,
        }
    }
}

impl From<rusqlite::Error> for StateError {
    fn from(value: rusqlite::Error) -> Self {
        Self::Database(value)
    }
}

pub type StateResult<T> = Result<T, StateError>;

pub trait StateStore: Send + Sync {
    fn claim_session(&self, key: &SessionKey) -> StateResult<ClaimResult>;
    fn session_status(&self, key: &SessionKey) -> StateResult<Option<SessionState>>;
    fn transition_phase(&self, key: &SessionKey, expected: Phase, next: Phase) -> StateResult<()>;
    fn record_generation(
        &self,
        key: &SessionKey,
        entry: JournalEntry,
    ) -> StateResult<GenerationResult>;
    fn operation_journal(
        &self,
        key: &SessionKey,
        after: Option<OperationId>,
        limit: usize,
    ) -> StateResult<Vec<JournalEntry>>;
    fn record_complete(&self, key: &SessionKey, manifest_digest: Digest) -> StateResult<()>;
    fn record_failed(&self, key: &SessionKey, error_code: ErrorCode) -> StateResult<()>;
    fn prune_terminal_before(&self, cutoff: SystemTime) -> StateResult<usize>;
}

/// SQLite implementation configured for WAL durability and concurrent readers.
pub struct SqliteStateStore {
    connection: Mutex<Connection>,
}

impl SqliteStateStore {
    pub fn open(path: impl AsRef<Path>) -> StateResult<Self> {
        let mut connection = Connection::open(path)?;
        connection.busy_timeout(Duration::from_secs(5))?;
        connection.pragma_update(None, "foreign_keys", true)?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "synchronous", "FULL")?;
        migrate(&mut connection)?;
        Ok(Self {
            connection: Mutex::new(connection),
        })
    }

    fn connection(&self) -> StateResult<MutexGuard<'_, Connection>> {
        self.connection.lock().map_err(|_| StateError::LockPoisoned)
    }
}

impl StateStore for SqliteStateStore {
    fn claim_session(&self, key: &SessionKey) -> StateResult<ClaimResult> {
        let now = unix_millis(SystemTime::now())?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let inserted = transaction.execute(
            "INSERT OR IGNORE INTO sessions (peer_fingerprint, root_id, session_id, phase, failure_code, manifest_digest, created_at_ms, updated_at_ms)
             VALUES (?1, ?2, ?3, ?4, NULL, NULL, ?5, ?5)",
            params![key.peer_fingerprint.as_slice(), key.root_id, key.session_id.as_bytes().as_slice(), phase_code(Phase::Handshake), now],
        )?;
        let result = if inserted == 1 {
            ClaimResult::Claimed
        } else {
            ClaimResult::Existing(
                query_status(&transaction, key)?.ok_or(StateError::MissingSession)?,
            )
        };
        transaction.commit()?;
        Ok(result)
    }

    fn session_status(&self, key: &SessionKey) -> StateResult<Option<SessionState>> {
        let connection = self.connection()?;
        query_status(&connection, key)
    }

    fn transition_phase(&self, key: &SessionKey, expected: Phase, next: Phase) -> StateResult<()> {
        if !valid_transition(expected, next) {
            return Err(StateError::InvalidTransition {
                from: expected,
                to: next,
            });
        }
        let now = unix_millis(SystemTime::now())?;
        let connection = self.connection()?;
        let changed = connection.execute(
            "UPDATE sessions SET phase = ?1, updated_at_ms = ?2
             WHERE peer_fingerprint = ?3 AND root_id = ?4 AND session_id = ?5 AND phase = ?6",
            params![
                phase_code(next),
                now,
                key.peer_fingerprint.as_slice(),
                key.root_id,
                key.session_id.as_bytes().as_slice(),
                phase_code(expected)
            ],
        )?;
        if changed == 1 {
            return Ok(());
        }
        let actual = query_status(&connection, key)?
            .ok_or(StateError::MissingSession)?
            .phase();
        Err(StateError::PhaseConflict { expected, actual })
    }

    fn record_generation(
        &self,
        key: &SessionKey,
        entry: JournalEntry,
    ) -> StateResult<GenerationResult> {
        let now = unix_millis(SystemTime::now())?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let state = query_status(&transaction, key)?.ok_or(StateError::MissingSession)?;
        if !matches!(state.phase(), Phase::Planning | Phase::Transferring) {
            return Err(StateError::PhaseConflict {
                expected: Phase::Planning,
                actual: state.phase(),
            });
        }
        let operation_bytes = entry.operation_id.get().to_be_bytes();
        let existing: Option<(u32, Vec<u8>)> = transaction.query_row(
            "SELECT generation, descriptor_digest FROM operations
             WHERE peer_fingerprint = ?1 AND root_id = ?2 AND session_id = ?3 AND operation_id = ?4",
            params![key.peer_fingerprint.as_slice(), key.root_id, key.session_id.as_bytes().as_slice(), operation_bytes.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        ).optional()?;
        let result = match existing {
            None => {
                insert_operation(&transaction, key, entry, now)?;
                GenerationResult::Recorded
            }
            Some((generation, _)) if entry.generation.get() < generation => {
                return Err(StateError::StaleGeneration {
                    operation: entry.operation_id,
                    current: Generation::new(generation),
                    received: entry.generation,
                });
            }
            Some((generation, digest)) if entry.generation.get() == generation => {
                if digest.as_slice() != entry.descriptor_digest.as_bytes() {
                    return Err(StateError::GenerationConflict {
                        operation: entry.operation_id,
                        generation: entry.generation,
                    });
                }
                GenerationResult::Replay
            }
            Some(_) => {
                transaction.execute(
                    "UPDATE operations SET generation = ?1, descriptor_digest = ?2, updated_at_ms = ?3
                     WHERE peer_fingerprint = ?4 AND root_id = ?5 AND session_id = ?6 AND operation_id = ?7",
                    params![entry.generation.get(), entry.descriptor_digest.as_bytes().as_slice(), now, key.peer_fingerprint.as_slice(), key.root_id, key.session_id.as_bytes().as_slice(), operation_bytes.as_slice()],
                )?;
                GenerationResult::Superseded
            }
        };
        transaction.execute(
            "UPDATE sessions SET updated_at_ms = ?1 WHERE peer_fingerprint = ?2 AND root_id = ?3 AND session_id = ?4",
            params![now, key.peer_fingerprint.as_slice(), key.root_id, key.session_id.as_bytes().as_slice()],
        )?;
        transaction.commit()?;
        Ok(result)
    }

    fn operation_journal(
        &self,
        key: &SessionKey,
        after: Option<OperationId>,
        limit: usize,
    ) -> StateResult<Vec<JournalEntry>> {
        if limit == 0 || limit > MAX_JOURNAL_PAGE_SIZE {
            return Err(StateError::InvalidPageSize);
        }
        let connection = self.connection()?;
        if query_status(&connection, key)?.is_none() {
            return Err(StateError::MissingSession);
        }
        let mut statement = connection.prepare(
            "SELECT operation_id, generation, descriptor_digest FROM operations
             WHERE peer_fingerprint = ?1 AND root_id = ?2 AND session_id = ?3
               AND (?4 IS NULL OR operation_id > ?4)
             ORDER BY operation_id LIMIT ?5",
        )?;
        let after = after.map(|operation| operation.get().to_be_bytes().to_vec());
        let rows = statement.query_map(
            params![
                key.peer_fingerprint.as_slice(),
                key.root_id,
                key.session_id.as_bytes().as_slice(),
                after,
                limit,
            ],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, u32>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            },
        )?;
        rows.map(|row| {
            let (operation, generation, digest) = row?;
            Ok(JournalEntry::new(
                OperationId::new(u64::from_be_bytes(fixed_bytes(&operation, "operation ID")?)),
                Generation::new(generation),
                Digest::from_bytes(fixed_bytes(&digest, "operation digest")?),
            ))
        })
        .collect()
    }

    fn record_complete(&self, key: &SessionKey, manifest_digest: Digest) -> StateResult<()> {
        let now = unix_millis(SystemTime::now())?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed = transaction.execute(
            "UPDATE sessions SET phase = ?1, manifest_digest = ?2, failure_code = NULL, updated_at_ms = ?3
             WHERE peer_fingerprint = ?4 AND root_id = ?5 AND session_id = ?6 AND phase = ?7",
            params![phase_code(Phase::Complete), manifest_digest.as_bytes().as_slice(), now, key.peer_fingerprint.as_slice(), key.root_id, key.session_id.as_bytes().as_slice(), phase_code(Phase::Committing)],
        )?;
        if changed != 1 {
            let actual = query_status(&transaction, key)?
                .ok_or(StateError::MissingSession)?
                .phase();
            return Err(StateError::PhaseConflict {
                expected: Phase::Committing,
                actual,
            });
        }
        transaction.commit()?;
        Ok(())
    }

    fn record_failed(&self, key: &SessionKey, error_code: ErrorCode) -> StateResult<()> {
        let now = unix_millis(SystemTime::now())?;
        let connection = self.connection()?;
        let changed = connection.execute(
            "UPDATE sessions SET phase = ?1, failure_code = ?2, manifest_digest = NULL, updated_at_ms = ?3
             WHERE peer_fingerprint = ?4 AND root_id = ?5 AND session_id = ?6 AND phase NOT IN (?7, ?8)",
            params![phase_code(Phase::Failed), error_code.as_str(), now, key.peer_fingerprint.as_slice(), key.root_id, key.session_id.as_bytes().as_slice(), phase_code(Phase::Complete), phase_code(Phase::Failed)],
        )?;
        if changed == 1 {
            return Ok(());
        }
        let actual = query_status(&connection, key)?
            .ok_or(StateError::MissingSession)?
            .phase();
        Err(StateError::PhaseConflict {
            expected: Phase::Handshake,
            actual,
        })
    }

    fn prune_terminal_before(&self, cutoff: SystemTime) -> StateResult<usize> {
        let cutoff = unix_millis(cutoff)?;
        let connection = self.connection()?;
        Ok(connection.execute(
            "DELETE FROM sessions WHERE phase IN (?1, ?2) AND updated_at_ms < ?3",
            params![
                phase_code(Phase::Complete),
                phase_code(Phase::Failed),
                cutoff
            ],
        )?)
    }
}

fn migrate(connection: &mut Connection) -> StateResult<()> {
    // Take the writer lock before inspecting the version so concurrent first opens cannot both
    // decide to apply the same migration.
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let version: u32 = transaction.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if version > SCHEMA_VERSION {
        return Err(StateError::CorruptState(
            "database schema is newer than this binary",
        ));
    }
    if version == 0 {
        transaction.execute_batch(
            "CREATE TABLE sessions (
                peer_fingerprint BLOB NOT NULL CHECK(length(peer_fingerprint) = 32),
                root_id TEXT NOT NULL CHECK(length(root_id) BETWEEN 1 AND 255),
                session_id BLOB NOT NULL CHECK(length(session_id) = 16),
                phase INTEGER NOT NULL CHECK(phase BETWEEN 0 AND 8),
                failure_code TEXT,
                manifest_digest BLOB CHECK(manifest_digest IS NULL OR length(manifest_digest) = 32),
                created_at_ms INTEGER NOT NULL,
                updated_at_ms INTEGER NOT NULL,
                PRIMARY KEY (peer_fingerprint, root_id, session_id),
                CHECK((phase = 7) = (manifest_digest IS NOT NULL)),
                CHECK((phase = 8) = (failure_code IS NOT NULL))
            ) WITHOUT ROWID;
            CREATE TABLE operations (
                peer_fingerprint BLOB NOT NULL,
                root_id TEXT NOT NULL,
                session_id BLOB NOT NULL,
                operation_id BLOB NOT NULL CHECK(length(operation_id) = 8),
                generation INTEGER NOT NULL CHECK(generation BETWEEN 0 AND 4294967295),
                descriptor_digest BLOB NOT NULL CHECK(length(descriptor_digest) = 32),
                updated_at_ms INTEGER NOT NULL,
                PRIMARY KEY (peer_fingerprint, root_id, session_id, operation_id),
                FOREIGN KEY (peer_fingerprint, root_id, session_id)
                    REFERENCES sessions(peer_fingerprint, root_id, session_id) ON DELETE CASCADE
            ) WITHOUT ROWID;
            CREATE INDEX sessions_terminal_retention ON sessions(phase, updated_at_ms) WHERE phase IN (7, 8);
            PRAGMA user_version = 1;",
        )?;
    }
    transaction.commit()?;
    Ok(())
}

fn query_status(connection: &Connection, key: &SessionKey) -> StateResult<Option<SessionState>> {
    let row: Option<(u8, Option<Vec<u8>>, Option<String>)> = connection
        .query_row(
            "SELECT phase, manifest_digest, failure_code FROM sessions
         WHERE peer_fingerprint = ?1 AND root_id = ?2 AND session_id = ?3",
            params![
                key.peer_fingerprint.as_slice(),
                key.root_id,
                key.session_id.as_bytes().as_slice()
            ],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    row.map(|(phase, digest, failure)| decode_state(phase, digest, failure))
        .transpose()
}

fn decode_state(
    phase: u8,
    digest: Option<Vec<u8>>,
    failure: Option<String>,
) -> StateResult<SessionState> {
    let phase = decode_phase(phase)?;
    match phase {
        Phase::ReadyToCommit => Ok(SessionState::ReadyToCommit),
        Phase::Committing => Ok(SessionState::Committing),
        Phase::Complete => Ok(SessionState::Complete {
            manifest_digest: Digest::from_bytes(fixed_bytes(
                &digest.ok_or(StateError::CorruptState("completed session has no digest"))?,
                "manifest digest",
            )?),
        }),
        Phase::Failed => Ok(SessionState::Failed {
            error_code: ErrorCode::try_from(
                failure
                    .as_deref()
                    .ok_or(StateError::CorruptState("failed session has no error code"))?,
            )
            .map_err(|_| StateError::CorruptState("failed session has an unknown error code"))?,
        }),
        phase => Ok(SessionState::InProgress { phase }),
    }
}

fn insert_operation(
    transaction: &Transaction<'_>,
    key: &SessionKey,
    entry: JournalEntry,
    now: i64,
) -> StateResult<()> {
    let operation = entry.operation_id.get().to_be_bytes();
    transaction.execute(
        "INSERT INTO operations (peer_fingerprint, root_id, session_id, operation_id, generation, descriptor_digest, updated_at_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![key.peer_fingerprint.as_slice(), key.root_id, key.session_id.as_bytes().as_slice(), operation.as_slice(), entry.generation.get(), entry.descriptor_digest.as_bytes().as_slice(), now],
    )?;
    Ok(())
}

fn unix_millis(time: SystemTime) -> StateResult<i64> {
    let millis = time
        .duration_since(UNIX_EPOCH)
        .map_err(|_| StateError::InvalidTimestamp)?
        .as_millis();
    i64::try_from(millis).map_err(|_| StateError::InvalidTimestamp)
}

const fn phase_code(phase: Phase) -> u8 {
    match phase {
        Phase::Handshake => 0,
        Phase::Policy => 1,
        Phase::Indexing => 2,
        Phase::Planning => 3,
        Phase::Transferring => 4,
        Phase::ReadyToCommit => 5,
        Phase::Committing => 6,
        Phase::Complete => 7,
        Phase::Failed => 8,
    }
}

fn decode_phase(value: u8) -> StateResult<Phase> {
    match value {
        0 => Ok(Phase::Handshake),
        1 => Ok(Phase::Policy),
        2 => Ok(Phase::Indexing),
        3 => Ok(Phase::Planning),
        4 => Ok(Phase::Transferring),
        5 => Ok(Phase::ReadyToCommit),
        6 => Ok(Phase::Committing),
        7 => Ok(Phase::Complete),
        8 => Ok(Phase::Failed),
        _ => Err(StateError::CorruptState("session has an unknown phase")),
    }
}

const fn valid_transition(from: Phase, to: Phase) -> bool {
    matches!(
        (from, to),
        (Phase::Handshake, Phase::Policy)
            | (Phase::Policy, Phase::Indexing)
            | (Phase::Indexing, Phase::Planning)
            | (Phase::Planning, Phase::Transferring)
            | (Phase::Transferring, Phase::ReadyToCommit)
            | (Phase::ReadyToCommit, Phase::Committing)
    )
}

fn fixed_bytes<const N: usize>(bytes: &[u8], name: &'static str) -> StateResult<[u8; N]> {
    bytes.try_into().map_err(|_| StateError::CorruptState(name))
}
