use std::{
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Barrier},
    thread,
    time::{Duration, SystemTime},
};

use quicsync_core::{
    error::ErrorCode,
    state::{
        ClaimResult, GenerationResult, JournalEntry, SessionKey, SessionState, SqliteStateStore,
        StateError, StateStore,
    },
    types::{Digest, Generation, OperationId, Phase, SessionId},
};
use rusqlite::Connection;

struct TestDatabase {
    directory: PathBuf,
    path: PathBuf,
}

impl TestDatabase {
    fn new(name: &str) -> Self {
        let directory = std::env::temp_dir().join(format!(
            "quicsync-state-{name}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join("state.sqlite");
        Self { directory, path }
    }

    fn open(&self) -> SqliteStateStore {
        SqliteStateStore::open(&self.path).unwrap()
    }
}

impl Drop for TestDatabase {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.directory).unwrap();
    }
}

fn session(seed: u8) -> SessionKey {
    SessionKey::new(
        [seed; 32],
        format!("root-{seed}"),
        SessionId::from_bytes([seed; 16]),
    )
    .unwrap()
}

fn advance_to_committing(store: &impl StateStore, key: &SessionKey) {
    for (expected, next) in [
        (Phase::Handshake, Phase::Policy),
        (Phase::Policy, Phase::Indexing),
        (Phase::Indexing, Phase::Planning),
        (Phase::Planning, Phase::Transferring),
        (Phase::Transferring, Phase::ReadyToCommit),
        (Phase::ReadyToCommit, Phase::Committing),
    ] {
        store.transition_phase(key, expected, next).unwrap();
    }
}

#[test]
fn opens_in_wal_mode_and_applies_versioned_migrations() {
    let database = TestDatabase::new("migrations");
    let store = database.open();
    drop(store);

    let connection = Connection::open(&database.path).unwrap();
    let journal_mode: String = connection
        .query_row("PRAGMA journal_mode", [], |row| row.get(0))
        .unwrap();
    let version: u32 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .unwrap();

    assert_eq!(journal_mode, "wal");
    assert!(version > 0);
}

#[test]
fn exactly_one_concurrent_claim_can_start_work() {
    let database = TestDatabase::new("claims");
    let key = session(1);
    let barrier = Arc::new(Barrier::new(8));

    let handles: Vec<_> = (0..8)
        .map(|_| {
            let path = database.path.clone();
            let key = key.clone();
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                let store = SqliteStateStore::open(path).unwrap();
                store.claim_session(&key).unwrap()
            })
        })
        .collect();

    let results: Vec<_> = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect();
    assert_eq!(
        results
            .iter()
            .filter(|result| **result == ClaimResult::Claimed)
            .count(),
        1
    );
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(
                result,
                ClaimResult::Existing(SessionState::InProgress { .. })
            ))
            .count(),
        7
    );
}

#[test]
fn phase_and_completion_survive_restart() {
    let database = TestDatabase::new("restart");
    let key = session(2);
    let digest = Digest::from_bytes([0x5a; 32]);

    {
        let store = database.open();
        assert_eq!(store.claim_session(&key).unwrap(), ClaimResult::Claimed);
        advance_to_committing(&store, &key);
        store.record_complete(&key, digest).unwrap();
    }

    let reopened = database.open();
    assert_eq!(
        reopened.session_status(&key).unwrap(),
        Some(SessionState::Complete {
            manifest_digest: digest
        })
    );
    assert_eq!(
        reopened.claim_session(&key).unwrap(),
        ClaimResult::Existing(SessionState::Complete {
            manifest_digest: digest
        })
    );
}

#[test]
fn completion_is_an_atomic_terminal_transition() {
    let database = TestDatabase::new("completion");
    let store = database.open();
    let key = session(3);
    store.claim_session(&key).unwrap();

    assert!(matches!(
        store.record_complete(&key, Digest::from_bytes([1; 32])),
        Err(StateError::PhaseConflict { .. })
    ));
    advance_to_committing(&store, &key);
    store
        .record_complete(&key, Digest::from_bytes([2; 32]))
        .unwrap();
    assert!(matches!(
        store.record_complete(&key, Digest::from_bytes([3; 32])),
        Err(StateError::PhaseConflict { .. })
    ));
}

#[test]
fn journal_accepts_only_replay_safe_generations() {
    let database = TestDatabase::new("journal");
    let key = session(4);
    let store = database.open();
    store.claim_session(&key).unwrap();
    store
        .transition_phase(&key, Phase::Handshake, Phase::Policy)
        .unwrap();
    store
        .transition_phase(&key, Phase::Policy, Phase::Indexing)
        .unwrap();
    store
        .transition_phase(&key, Phase::Indexing, Phase::Planning)
        .unwrap();

    let initial = JournalEntry::new(
        OperationId::new(7),
        Generation::new(1),
        Digest::from_bytes([1; 32]),
    );
    assert_eq!(
        store.record_generation(&key, initial).unwrap(),
        GenerationResult::Recorded
    );
    assert_eq!(
        store.record_generation(&key, initial).unwrap(),
        GenerationResult::Replay
    );

    let conflicting = JournalEntry::new(
        OperationId::new(7),
        Generation::new(1),
        Digest::from_bytes([2; 32]),
    );
    assert!(matches!(
        store.record_generation(&key, conflicting),
        Err(StateError::GenerationConflict { .. })
    ));

    let stale = JournalEntry::new(
        OperationId::new(7),
        Generation::new(0),
        Digest::from_bytes([3; 32]),
    );
    assert!(matches!(
        store.record_generation(&key, stale),
        Err(StateError::StaleGeneration { .. })
    ));

    let replacement = JournalEntry::new(
        OperationId::new(7),
        Generation::new(2),
        Digest::from_bytes([4; 32]),
    );
    assert_eq!(
        store.record_generation(&key, replacement).unwrap(),
        GenerationResult::Superseded
    );
    let last = JournalEntry::new(
        OperationId::new(u64::MAX),
        Generation::new(1),
        Digest::from_bytes([5; 32]),
    );
    assert_eq!(
        store.record_generation(&key, last).unwrap(),
        GenerationResult::Recorded
    );
    drop(store);

    let reopened = database.open();
    assert_eq!(
        reopened.operation_journal(&key, None, 1).unwrap(),
        vec![replacement],
    );
    assert_eq!(
        reopened
            .operation_journal(&key, Some(replacement.operation_id()), 1)
            .unwrap(),
        vec![last],
    );
    assert!(matches!(
        reopened.operation_journal(&key, None, 0),
        Err(StateError::InvalidPageSize)
    ));
}

#[test]
fn failures_are_queryable_and_terminal() {
    let database = TestDatabase::new("failure");
    let store = database.open();
    let key = session(5);
    store.claim_session(&key).unwrap();
    store
        .record_failed(&key, ErrorCode::IntegrityMismatch)
        .unwrap();

    assert_eq!(
        store.session_status(&key).unwrap(),
        Some(SessionState::Failed {
            error_code: ErrorCode::IntegrityMismatch
        })
    );
    assert!(matches!(
        store.transition_phase(&key, Phase::Failed, Phase::Handshake),
        Err(StateError::InvalidTransition { .. })
    ));
}

#[test]
fn retention_removes_only_terminal_sessions() {
    let database = TestDatabase::new("retention");
    let store = database.open();
    let active = session(6);
    let finished = session(7);
    store.claim_session(&active).unwrap();
    store.claim_session(&finished).unwrap();
    store
        .record_failed(&finished, ErrorCode::Cancelled)
        .unwrap();

    thread::sleep(Duration::from_millis(2));
    let removed = store.prune_terminal_before(SystemTime::now()).unwrap();

    assert_eq!(removed, 1);
    assert!(store.session_status(&active).unwrap().is_some());
    assert_eq!(store.session_status(&finished).unwrap(), None);
}

#[test]
fn durable_schema_has_no_payload_or_private_key_storage() {
    let database = TestDatabase::new("schema");
    database.open();
    let connection = Connection::open(&database.path).unwrap();
    let mut statement = connection
        .prepare("SELECT sql FROM sqlite_schema WHERE type = 'table' AND sql IS NOT NULL")
        .unwrap();
    let schema = statement
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
        .join(" ")
        .to_ascii_lowercase();

    for forbidden in ["private_key", "secret_key", "file_content", "payload"] {
        assert!(!schema.contains(forbidden), "schema contains {forbidden}");
    }
}

#[test]
fn invalid_database_parent_is_reported() {
    let database = TestDatabase::new("missing-parent");
    let path = database.directory.join("missing").join("state.sqlite");
    assert!(SqliteStateStore::open(&path).is_err());
    assert!(!Path::new(&path).exists());
}
