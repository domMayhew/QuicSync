## System shape

QuicSync is a Rust workspace with shared behavior in `quicsync-core` and two thin binaries:

```text
quicsync/
├── crates/quicsync-core/src/{config,auth,state,error}.rs
├── crates/quicsync-core/src/protocol/{messages,codec,session}.rs
├── crates/quicsync-core/src/transport/quic.rs
├── crates/quicsync-core/src/filesystem/{ignore,scan,metadata,paths,staging}.rs
├── crates/quicsync-core/src/sync/{planner,transfer,source,destination,commit}.rs
├── apps/quicsync/src/main.rs
├── apps/quicsyncd/src/main.rs
└── tests/{integration,fixtures}/
```

`quicsync` loads one source-root configuration, connects, and calls `sync::source::run`. `quicsyncd` loads destination roots and peer authorization, accepts QUIC sessions, and calls `sync::destination::serve`. The binaries contain no sync logic.

Dependencies flow from configuration, authentication, state, and errors into filesystem/protocol; `sync` composes filesystem, protocol, and transport. Filesystem code never depends on QUIC, and transport never interprets operations. Source and destination coordinate only through typed messages.

## Reading guide

The **source** is the developer’s machine and the **destination** is the machine that runs or tests the code. A **root** is the directory being synchronized. The **root ID** is a configured nickname for that directory, so the machines agree which root to use without exchanging local paths.

A **peer pin** is the expected fingerprint of the other machine’s public key—the same idea as checking a unique ID before trusting someone. **TLS** encrypts the connection and proves each machine’s identity; **QUIC** is the network protocol that carries several independent streams over that encrypted connection.

A **session** is one sync attempt. An **index** is the ordered list of managed files, directories, and links. A **digest** is a short cryptographic fingerprint used to detect changes or corruption. A **manifest** is a digest of a complete index or plan. A **delta** describes how to rebuild a changed file by reusing unchanged pieces at the destination and sending only the new pieces.

Where this document says “descriptor-relative,” it means filesystem work starts from an already-open handle to the destination root rather than trusting a path string that another process could change. **Staging** is a private temporary area where incoming files are verified before they replace live files.

## Global invariants

The MVP is not a production-readiness milestone. It is a working implementation for comparing QuicSync's likely performance shape against rsync under known, normal conditions: configured peers are running, the network is stable, both roots use equivalent ignore policy, and the source tree does not intentionally change during the sync. Resilience, recovery, platform edge cases, and strategy tuning are later milestones unless a ticket explicitly pulls a narrow piece into MVP.

 1. **The source is authoritative only for its managed path set.** QuicSync is one-way, but it must not treat every destination path as source-owned. This prevents ordinary syncs from overwriting or deleting destination-local files that Git-ignore policy excludes from the managed set.
 2. **For the MVP, each side evaluates Git-ignore rules during its own single filesystem traversal.** `.quicsync` **and** `.git` **administrative paths are always excluded.** Source and destination roots are expected to have equivalent ignore files and configured exclusions; if they differ, sync results are undefined until the resilience phase adds deterministic source-policy transmission. State and Git metadata must never be transfer or deletion targets.
 3. **Wire paths are relative component sequences. Absolute paths, empty components,** `.`**, and** `..` **are invalid.** A protocol path is `["src", "lib", "main.rs"]`, not an OS path string. This makes traversal attempts unrepresentable and avoids platform-specific parsing, so resolution remains beneath the configured root.
 4. **Traversal never follows symbolic links.** Following a link could read, overwrite, or delete outside the sync root, or make source and destination trees mean different things. A link is copied as a link with its raw target.
 5. **Every destination operation is directory-descriptor-relative and revalidates ancestors at use time; lexical path checks alone are insufficient.** A process can replace a checked directory with a symlink between validation and write/delete. Working from an open root directory and refusing symlink ancestors prevents that time-of-check/time-of-use escape.
 6. **Incoming files are reconstructed and cryptographically verified in session staging before the live tree changes.** Delta-transfer faults, network faults, implementation defects, or a changed basis must not put partial or incorrect bytes in the live tree. Staging allows exact size/digest validation and atomic per-file installation.
 7. **A completion acknowledgment means the complete accepted plan was committed and durable completion state recorded.** The source needs one unambiguous success signal. Durable state before acknowledgment lets a retry query a lost response rather than rerun the session.
 8. **A failed commit can leave a mixed-version tree; the next sync must converge it. Transaction-wide rollback is not an MVP guarantee.** Whole-tree atomic replacement conflicts with the speed and minimal-stack goals. This avoids a false transaction promise while requiring a later authoritative sync to repair all partial operations.
 9. **Memory is bounded independently of tree size: indexes, signatures, plans, and content stream or spill to session state.** Large codebases and branch changes are target workloads. Accumulating any of these structures in RAM would fail under exactly those workloads; backpressure also prevents a fast producer from overwhelming its peer.
10. **Linux and macOS share one wire model. Unsupported names, metadata, types, and destination collisions fail before destructive commit.** The protocol must not silently reinterpret trees across different case, Unicode, timestamp, or naming rules. Preflight failure avoids partial changes and perpetual resync from unrepresentable metadata.

## Shared domain model

```rust
type SessionId = [u8; 16];
type Digest = [u8; 32]; // BLAKE3
type OperationId = u64;
type Generation = u32;

struct RelativePath(Vec<Vec<u8>>);
enum EntryKind { Directory, RegularFile, Symlink }
struct EntryMetadata { kind: EntryKind, mode: u32, mtime_ns: i128, size: u64 }
struct IndexRecord {
  path: RelativePath, metadata: EntryMetadata,
  digest: Option<Digest>, symlink_target: Option<Vec<u8>>
}
```

Regular-file digests cover content bytes; symlink digests cover raw target bytes; directories have no content digest. Index records are strictly ordered by unsigned bytewise path-component order. Ownership, hard-link identity, sparse layout, ACLs, extended attributes, resource forks, flags, and special files are outside the model.

## `config`

**What it does**

```rust
struct Limits { max_frame_bytes: usize, max_path_bytes: usize, max_components: usize,
  max_parallel_hashes: usize, max_parallel_transfers: usize, max_inflight_bytes: usize }
fn load_source(root: &Path) -> Result<SourceConfig>;
fn load_destination(root: &Path) -> Result<DestinationConfig>;
```

Configuration is the local setup QuicSync reads before a sync. For the source, it says which root to copy, which destination address to contact, which destination public-key fingerprint to trust, optional extra ignore patterns, and safety limits. For the destination, it says which roots it may expose and which source fingerprints may write to each one. The limits cap message/path size, parallel work, and buffered network data so a peer cannot consume unbounded resources.

`load_source` and `load_destination` return validated settings only: they do not connect to a machine or change files. They open the configured root without following a final symbolic link, retain its filesystem identity for later checks, reject duplicate root nicknames and unclear permissions, and check that `.quicsync` and private keys are owned by the current user and not writable by others. Private keys use `0600`, meaning only their owner may read or write them. Invalid setup fails before any network or filesystem mutation.

## `auth`

**Role and interface**

```rust
struct Identity { public_key: PublicKey, private_key: PrivateKey, certificate_chain: Vec<Certificate> }
impl Identity { fn load_or_create(dir: &Path) -> Result<Self>; fn fingerprint(&self) -> Fingerprint; }
fn client_tls(identity: &Identity, expected: &PeerPin) -> Result<ClientTls>;
fn server_tls(identity: &Identity, allowed: &[PeerPin]) -> Result<ServerTls>;
fn authorize(peer: Fingerprint, root_id: &str, direction: Direction) -> Result<Authorization>;
```

QUIC uses TLS 1.3 with mutual authentication. A certificate is accepted only when its public key matches the configured pin; hostnames and system PKI are not substitutes. Authorization binds authenticated peer, root ID, and source-to-destination direction. Keys use the OS CSPRNG; initial exchange is manual and displays fingerprints for out-of-band comparison. Mutating traffic is forbidden in 0-RTT (the MVP may disable it). Authentication failure does not reveal root paths or other peers.

## Protocol

### `protocol::messages`

This module defines versioned, serializable data only.

```rust
enum Control {
  ClientHello { versions, capabilities, nonce }, ServerHello { version, capabilities, nonce },
  StartSync { session_id, root_id }, PolicyBegin, PolicyRuleFile { scope, contents, digest },
  PolicyEnd { policy_digest }, StartAccepted, StartStatus { state }, PlanBegin,
  Operation(Operation), PlanEnd { operation_count, plan_digest },
  CommitRequest { plan_digest }, CompleteAck { manifest_digest }, Cancel { reason }, Failure(WireError)
}
enum Operation {
  UpsertDirectory { id, generation, record }, UpsertFile { id, generation, record },
  UpsertSymlink { id, generation, record }, Delete { id, path, expected_kind }
}
```

The index stream contains ordered `IndexRecord` values followed by `IndexEnd { count, manifest_digest }`. Transfer streams contain a `FileRequest`, optional rsync signature header/blocks, delta header, bounded `Copy`/`Literal` instructions, `DeltaEnd`, and `TransferAccepted`. Policy messages are versioned data reserved for the resilience phase; the MVP does not wait for a transmitted source-policy snapshot before destination indexing. Required unknown messages, capabilities, or enum values fail the session; optional additions are ignored only when the negotiated version permits it.

### `protocol::codec`

```rust
trait Encoder { async fn send<T: WireEncode>(&mut self, value: &T) -> Result<()>; }
trait Decoder { async fn recv<T: WireDecode>(&mut self) -> Result<T>; }
```

A frame is `varint length | message kind | versioned payload`. Length is checked before allocation and against negotiated local limits. The wire specification fixes byte order, integer widths, enum tags, optional fields, collection limits, and nesting. Decode rejects trailing bytes, forbidden duplicate fields, invalid paths, oversized collections, and noncanonical forms. Golden byte vectors protect compatibility.

### `protocol::session`

```rust
enum Phase { Handshake, Policy, Indexing, Planning, Transferring, ReadyToCommit, Committing, Complete, Failed }
struct Session { id: SessionId, peer: Fingerprint, root_id: String, negotiated: Capabilities, phase: Phase }
impl Session { async fn client_handshake(...) -> Result<Self>; async fn server_handshake(...) -> Result<Self>; fn accept(&mut self, event: ProtocolEvent) -> Result<()>; }
```

The TLS transcript binds both nonces, peer identities, selected version/capabilities, root ID, and session ID. The state machine defines valid messages and streams; out-of-order input fails the session. The destination durably claims `(peer fingerprint, root ID, session ID)` before indexing. Reuse never starts another scan: it returns `InProgress`, `Complete`, or `Failed`; completed status includes the stored acknowledgment. A source with an indeterminate result queries the old ID or starts a new full reconciliation.

## `transport::quic`

```rust
struct TransportBounds { max_frame_bytes: usize, max_parallel_transfers: usize, max_inflight_bytes: usize }
struct SourceStreams { control: ControlChannel, destination_index: IndexReader, transfers: TransferOpener }
struct DestinationStreams { control: ControlChannel, index: IndexWriter, transfers: TransferAcceptor }
enum Completion { Acknowledged, Unknown }
async fn connect(cfg: &SourceConfig, identity: &Identity, cancel: CancellationToken) -> Result<Connection>;
fn listen(cfg: &DestinationConfig, identity: &Identity, cancel: CancellationToken) -> Result<Listener>;
impl Connection {
  async fn open_session(&self) -> Result<SourceStreams>;
  async fn accept_session(&self) -> Result<DestinationStreams>;
}
```

One long-lived bidirectional control stream carries phase changes; the destination index uses one unidirectional stream; each file uses a bidirectional transfer stream. For the MVP, the transport must let configured peers exchange control messages, indexes, and file data for a stable sync. Saturation behavior, shared cancellation, strict bounded-resource guarantees, and ambiguous-acknowledgment recovery are resilience or hardening concerns.

## Filesystem

### `filesystem::ignore`

```rust
struct IgnorePolicy { rules: Vec<ScopedRuleSet>, digest: Digest }
impl IgnorePolicy {
  fn with_configured_exclusions(exclusions: &[String]) -> Result<Self>;
  fn add_ignore_contents(&mut self, scope: Option<RelativePath>, contents: Vec<u8>) -> Result<()>;
  fn decision(&self, path: &RelativePath, kind: EntryKind) -> IgnoreDecision;
}
```

Ignore policy is built as part of the same traversal that produces an index. When the scanner enters a directory, it extends the inherited matcher with that directory's `.gitignore` file before deciding which children to index or descend into. Configured exclusions are root-scoped rules. Matching follows Git semantics for anchoring, escaping, negation, and excluded ancestors through the `ignore` crate. `.quicsync` and `.git` are protected before matcher evaluation, so negation cannot re-include them. Ignored paths are not indexed, created, updated, or deleted; ignored destination-only paths survive because the destination scanner omits them before planning. Ignore files are managed unless an earlier rule excludes them. The MVP assumes source and destination ignore files match; detecting or correcting divergence is a resilience-phase concern.

### `filesystem::paths`

```rust
struct RootHandle(OwnedFd);
struct ValidatedParent { dir: OwnedFd, leaf: Vec<u8> }
fn decode_relative_path(wire: &[u8], limits: &Limits) -> Result<RelativePath>;
fn resolve_parent(root: &RootHandle, path: &RelativePath) -> Result<ValidatedParent>;
```

Paths are raw Unix bytes. Components are non-empty and contain neither slash nor NUL. Resolution walks from a held root descriptor with `openat`-style no-follow calls; each ancestor must still be a directory. Creation, stat, unlink, chmod, timestamp changes, and rename are descriptor-relative. Staging and root must share a filesystem. Preflight detects case-folding and Unicode-normalization collisions and rejects paths that destination limits cannot represent.

### `filesystem::metadata` and `scan`

```rust
fn read_entry(parent: &OwnedFd, name: &[u8]) -> Result<EntryMetadata>;
fn digest_file(file: &File, cancel: &CancellationToken) -> Result<Digest>;
fn matches_snapshot(before: &Snapshot, after: &Snapshot) -> bool;
fn scan(root: RootHandle, configured_exclusions: &[String], limits: ScanLimits, cancel: CancellationToken) -> Result<impl IndexStream>;
```

Regular files open without following symlinks and are hashed for transfer comparison. Symlink targets are raw bytes. Mode/mtime differences produce metadata changes. The traversal extends the current ignore matcher whenever it encounters a `.gitignore` file, then prunes ignored children before enqueueing or indexing them. For the MVP, scanning a directory that does not change during traversal must produce the metadata needed for diffing and transfer. Parallel traversal, strict canonical raw-byte ordering, bounded queues, non-UTF-8 coverage, and changed-file reconciliation are later hardening unless they are needed to make performance benchmarking representative.

### `filesystem::staging`

```rust
struct Stager { session_dir: OwnedFd }
impl Stager {
  fn create(root: &RootHandle, session: SessionId) -> Result<Self>;
  async fn reconstruct_file(...) -> Result<StagedFile>;
  fn stage_symlink(...) -> Result<StagedEntry>;
  fn verify(&self, expected: &IndexRecord) -> Result<()>;
  fn discard_generation(&self, id: OperationId, generation: Generation) -> Result<()>;
}
```

Staging is private `.quicsync/staging/<session-id>`. Every operation generation has an implementation-controlled temporary name. Files are reconstructed through held descriptors, validated for expected length and digest, assigned final mode/mtime, flushed, and renamed atomically within staging. A newer generation supersedes the older one. Aborted sessions clean up best-effort; startup garbage collection removes abandoned sessions not represented as active state.

## Sync modules

### `sync::planner`

```rust
fn plan(source: impl Stream<Item = IndexRecord>, destination: impl Stream<Item = IndexRecord>) -> impl Stream<Item = Result<Operation>>;
```

The planner merge-walks ordered indexes: source-only paths upsert; destination-only paths delete; type changes are structural replacements; equal content with differing metadata is metadata-only. It records dependency order and spills to session state when necessary. Operations have deterministic IDs and a digest over canonical operations. Commit order is: remove objects blocking source ancestors/type replacements (deepest first); create directories (shallowest); install verified files/symlinks; apply file/symlink metadata; apply directory metadata (deepest first); delete remaining stale paths (deepest first).

### `sync::transfer`

```rust
trait TransferStrategy {
  async fn send_file(&self, source: StableSourceFile, basis: BasisRequest, sink: &mut TransferStream) -> Result<TransferReceipt>;
}
```

For the MVP, regular-file content always uses the delta-transfer protocol. The destination uses its current regular file, when suitable, as an optional basis and streams fixed-block rolling/strong signatures; otherwise it reports no basis and the same delta stream carries literal content. The source emits copy/literal instructions from the indexed source bytes. Copy ranges must fit the declared basis; reconstructed size and BLAKE3 must equal the indexed source record. Symlinks are not file transfers: their raw target bytes are carried in the index/operation record and staged directly. Choosing between delta and whole-file transfer based on file size, round-trip time, throughput, or CPU cost is an optimization-phase concern.

### `sync::source` and `sync::destination`

```rust
async fn run(cfg: SourceConfig, transport: SessionStreams, state: SourceState, cancel: CancellationToken) -> Result<SyncOutcome>;
async fn serve(auth: Authorization, transport: SessionStreams, state: StateStore, cancel: CancellationToken) -> Result<()>;
```

Source: authenticate/negotiate; send `StartSync`; scan locally while receiving destination index; plan and transfer with bounded parallelism; request commit; report completion. If a source file changes after it is indexed or while it is read, the MVP may transfer the earlier observed bytes; detecting or reconciling source changes is a resilience concern.

Destination: authorize the configured peer; scan immediately using its local ignore policy; validate operation paths and limits; generate signatures and stage content; verify the accepted plan and staged entries; commit on request; report completion. Replay/restart handling, durable status queries, cancellation workflows, and corruption-recovery workflows are resilience concerns.

### `sync::commit`

```rust
fn commit(root: &RootHandle, stager: &Stager, plan: &OperationJournal, cancel: &CancellationToken) -> Result<CommitResult>;
```

Commit starts only after complete-plan and payload verification. Every operation resolves its parent again from the held root descriptor. Files/symlinks use same-filesystem atomic rename. Non-empty directory replacement waits for planned descendants to be removed. Cancellation before commit leaves live state untouched; during commit it stops between operations, records failure, and leaves a tree that a later sync converges. File data/state are flushed before completion; directories are synced where supported.

## `state` and `error`

```rust
enum SessionState { InProgress, ReadyToCommit, Committing, Complete { manifest_digest: Digest }, Failed { error_code: ErrorCode } }
trait StateStore { fn claim_session(&self, key: SessionKey) -> Result<ClaimResult>; fn append_operation(&self, id: SessionId, op: &Operation) -> Result<()>; fn record_complete(&self, id: SessionId, digest: Digest) -> Result<()>; fn session_status(&self, key: SessionKey) -> Result<Option<SessionState>>; }
```

SQLite in `.quicsync/state.sqlite` is the default: session claims, phases, and journals need atomic updates. Use WAL and versioned migrations. Claims/completion survive restart; retention is configurable. State stores no private key material or file content.

Errors have a stable machine code, safe peer-visible message, detailed local diagnostic, retry class (`Never`, `NewSession`, `QueryThenRetry`), phase, and optional operation/path context. Protocol failures send one bounded `Failure` where possible, then reset streams. Authentication, confinement, integrity, and unsupported-filesystem errors are never downgraded.

## End-to-end sync trace

1. Source connects with mutual TLS; peers negotiate version/capabilities and bind the session transcript.
2. Source sends `StartSync`; destination authorizes the configured peer and root.
3. Source and destination start policy-filtered scans immediately, each extending its matcher with `.gitignore` files encountered during its own traversal.
4. Destination streams its index; source merge-walks both indexes into a deterministic operation plan.
5. Destination supplies optional basis signatures; source transfers regular-file content through the delta protocol. Destination stages and verifies every generation.
6. Source sends `PlanEnd`; destination verifies the plan and all staged content. Source sends `CommitRequest`.
7. If the source changed during the sync, MVP results are unspecified; a later sync or resilience work handles convergence.
8. Destination revalidates descriptors, applies the ordered plan, persists completion, then sends `CompleteAck` with final manifest digest.

This trace preserves the global invariants: only the locally policy-filtered managed set changes; no unverified content reaches the live root; replay cannot duplicate work; and a missing acknowledgment remains safely indeterminate.

## TDD contract suite

* Ignore fixtures match `git check-ignore`, including nested rules, negation, escaping, configured exclusions, traversal-time matcher extension, and ignored destination-only paths.
* Path tests reject absolute, traversal, empty, NUL, oversized, and symlink-ancestor paths; concurrent symlink replacement cannot escape root.
* Scanner tests cover stable trees and ignore filtering; randomized worker completion, strict canonical raw-byte ordering, bounded buffering, and changed-file behavior belong to later hardening unless needed for representative benchmark results.
* Planner property tests produce deterministic, dependency-valid plans for arbitrary trees.
* Codec golden vectors, malformed-frame fuzzing, and session-state tests preserve wire and ordering contracts.
* Transfer property tests reconstruct random source bytes from random bases; corrupt signatures, delta instructions, and staged content fail verification.
* MVP integration tests cover empty/full trees, metadata-only updates, symlinks, type replacements, deletions, and delta transfer over loopback. Source mutation, disconnect before/during commit, replay, lost acknowledgment, backpressure, case/normalization collisions, non-UTF-8 names, timestamp limits, and unsupported filesystem objects belong to Resilience or platform hardening.

### Integration test plan

The existing suite is a contract checklist; this section defines the environments and release coverage. Benchmarks are tracked separately, but the MVP should preserve enough streaming/indexing shape that benchmarking can assess whether QuicSync is likely to outperform rsync.

**Routine integration environment.** Run the real source CLI/core and destination daemon against two independent temporary roots and a loopback QUIC endpoint. Each root has separate configuration, identity, state, staging, and Git fixtures; tests must not share filesystem handles or state. This exercises production serialization, TLS, QUIC streams, staging, and commit behavior without requiring two physical machines.

**Fault injection.** Resilience-phase tests use a controllable local transport harness or proxy for deterministic blocked readers, stream resets, connection loss, dropped acknowledgment, restart, and constrained stream/inflight limits. Mocks are appropriate for unit boundaries, but end-to-end tests should still cover the production QUIC transport and filesystem implementation.

**Platform interoperability.** Separate physical machines are not needed for ordinary CI or the MVP. Before a real release, and after filesystem/protocol/transport/auth/commit changes, run Linux→Linux, macOS→macOS, Linux→macOS, and macOS→Linux on real filesystems. Include case-sensitive and normal case-insensitive macOS volumes where available. This covers naming/normalization, permissions, and system-call behavior a single-host suite cannot reproduce.

**MVP scenarios.** Test convergence for empty/full stable trees, metadata-only changes, symlinks, type replacements, deletions, and delta transfers. Preserve a regression fixture for correctness or security defects found while building the MVP.

**Later scenarios.** Source mutation during scan/policy/transfer, interruption before and during commit, replay and lost acknowledgment, malformed or corrupt policy/index/plan/signature/delta/staging data, resource backpressure, and unsupported/colliding destination paths belong to Resilience or platform hardening.

### Dependency decisions

## Dependency decisions

Use these selections as the starting dependency set. Pin compatible minor versions in the lockfile and review updates for security, platform support, and license changes.

| Area | Selection | Intended use |
| -- | -- | -- |
| Async runtime | `tokio` | QUIC I/O, timers, cancellation, bounded channels, and workflow concurrency. Keep hashing and blocking filesystem work off I/O tasks. |
| Cancellation | `tokio-util` | `CancellationToken`, re-exported from `transport`, is the one shared signal that stops every producer and consumer of a session. |
| QUIC transport | `quinn` with Rustls integration | Connections and independent streams. QuicSync’s protocol remains above Quinn so it is replaceable. |
| TLS and identity | `rustls` and `rcgen` | TLS 1.3, mutual client certificates, self-signed setup certificates, and configured peer fingerprint checks. Keep verifier/pinning code inside `auth`. |
| Content fingerprints | `blake3` | Stream hashes for files, indexes, policies, plans, and verification. |
| Git-ignore matching and traversal | `ignore` plus `jwalk` | Use `ignore` for Git-compatible matching as the scanner discovers `.gitignore` files during its single traversal. Use JWalk for parallel, work-stealing directory enumeration. Configure JWalk with an explicit raw-byte filename comparator; never rely on default filesystem order. Its output must match QuicSync's canonical depth-first bytewise path order. |
| Safe Unix filesystem work | `rustix`; optionally `cap-std` for non-critical helpers | Use `openat`-style directory-relative, no-follow operations for the root resolver, staging, rename, and deletion. Do not rely only on `std::fs` string paths. |
| Delta transfer | `librsync`, behind `TransferStrategy` | Streaming signatures, deltas, and patching for regular files. QuicSync owns framing, cancellation, basis checks, staging, and final BLAKE3 verification. Strategy selection between delta and whole-file transfer belongs to the optimization phase, not the MVP. |
| Durable state | `rusqlite` with `bundled` | Session claims, operation journals, and completion in a known SQLite build; QuicSync configures WAL. |
| Wire buffers/format | `bytes` and a small hand-written codec | Bounded buffers while QuicSync explicitly defines canonical framing, versions, limits, and malformed-input behavior. |
| Test support | `tempfile`, `proptest`, `cargo-fuzz` with `libfuzzer-sys` | Isolated roots, generated tree/plan/delta cases, and fuzzing. Build the controllable network-fault proxy as test-only QuicSync code. |

For each dependency, record the exact version, license, enabled features, platform build requirements, abstraction boundary, and replacement rationale in `Cargo.toml` and the release checklist. Add tests for each safety property delegated to a dependency: mutual authentication, peer pinning, no-follow confinement, Git-ignore parity, JWalk canonical raw-byte ordering (including non-UTF-8 names), bounded buffering, delta reconstruction, and SQLite crash/restart behavior. Rerun the integration and Linux/macOS interoperability suites before any major upgrade or replacement.
