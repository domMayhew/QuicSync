# QuicSync Technical Architecture

Use the project description in Linear to understand the purpose of the project and the framework to use when making decisions. The project description answers, "Who is this for? What does it do? What matters, and what does not? What is the goal that all work in this project must serve?"

## Pipeline

Assume that QuicSync is already installed and running on the destination machine.

1. Notification: Source machine notifies the configured destination immediately and start both scans independently.
2. Indexing: Both machines traverse each tree once, discovering scoped ignore rules and index records together. Source streams records in canonical path-component order to Destination as traversal proceeds.
3. Planning: Destination compares the source index with its own index as records arrive, and generates a Plan (a stream of Operations). An operation can be to create, delete, or update a file.
4. Requesting: Destination processes each operation as it is created. Each create operation becomes a Request for the whole file and is sent to Source immediately. No Request is required for deletion operations — Destination will keep an in-memory record of deletion operations to be applied during the "Committing" stage. Each update operation becomes a request for delta/patch instructions. These requests use rsync's delta transfer protocol, so any data/metadata required (e.g. checksums/signatures) will be sent with the Request.
5. Transferring: Source processes each Request as it arrives and streams Transfer Instructions to Destination. A Transfer Instruction for files that need to be created are simply the whole file, and Transfer Instructions for files that need to be updated are the delta instructions required by rsync's delta transfer protocol.
6. Staging: Destination applies the Transfer Instructions as they arrive to temporary, staging files (leave the actual directory untouched at this stage).
7. Committing: Once Destination has received and staged all Transfer Instructions, Destination moves (commits) each staged file to the working directory and applies the deletion Operations recorded in the Planning stage.

Use bounded channels and incremental reads/writes between stages. Back pressure must suspend producers, not accumulate whole trees, plans, or file contents. Bounded transfer concurrency is sufficient for the POC; elaborate resource accounting and scheduler tuning can wait.

Source owns the authoritative content, not planning. Destination owns comparison,
request scheduling, staging, and commit. Neither scan waits for the other scan to
finish. Planning, requests, signatures, transfer, and staging overlap; committing
is deliberately gated on successful planning and completion of all staging.

Deferred deletions, staged-file references, and pending metadata changes are
in-memory commit bookkeeping proportional to changed paths. This is an explicit
exception to bounded inter-stage queues, not a buffered plan used to delay
requests. File contents stay on disk. No durable journal is required.

## Workspace

The Rust workspace has shared behavior in `quicsync-core` and thin `quicsync`
and `quicsyncd` binaries.

- `config`: configured source/destination roots, address, peer pins, exclusions,
  and simple local limits.
- `auth`: local identities, pinned QUIC/TLS peer authentication, root authorization.
- `filesystem::{paths,ignore,scan,metadata,staging}`: confined paths, single-pass
  ignore evaluation and scanning, metadata, and temporary-file reconstruction.
- `protocol::{messages,codec,session}`: framed messages and minimal in-memory
  coordination for a single attempt.
- `transport::quic`: control, source index, and per-file transfer streams.
- `sync::{planner,transfer,source,destination,commit}`: concurrent pipeline stages.

## Filesystem model

Supported paths are relative component sequences. Reject absolute paths, empty components, `.`, and `..`. Retain the existing root-confinement protections. Always protect `.git` and `.quicsync`, even when ignore negations would match. Never follow symbolic links. Copy links using their target metadata.

Regular files, directories, and symlinks are supported in the POC, including creating/deleting directories and replacing directories with files or links (and vice versa). Preserve file content, relative paths, modification times, and POSIX mode bits where supported. Ownership, hard-link identity, sparse layout, ACLs, extended attributes, special files, and broad platform collision handling are not required. Linux and macOS are the intended platforms; a failing unsupported case may abort the POC.

Assume stable source files and destination basis files during an attempt.
Changes during scanning or transfer have unspecified results in the POC.
Do not re-index or retransmit automatically.

### Ignore rules and scanner

Use the `ignore` crate for matching. At each directory, extend that directory's
inherited matcher with its local `.gitignore` before filtering children. The
same traversal discovers ignore files and generates the index; no preliminary
ignore-file search or source-policy snapshot is allowed.

Each side evaluates its own rules and configured exclusions. If the policies
differ, results are undefined for the POC. Ignored source paths are not sent;
ignored destination-only paths are preserved because they never enter the
destination index.

Emit strict unsigned bytewise path-component order without a final whole-tree
sort. Per-directory sorting is compatible with streaming. Parallel traversal
(such as jwalk) must preserve order and directory-scoped matchers and should be
introduced where it improves measured latency. Independent source/destination
scans and overlap with planning/transfers are required now.

### Planner

On Destination, the planner merge-walks the received Source index and local
index as two ordered asynchronous inputs and emits operations
through a bounded channel. It does not collect, sort, hash, journal, or count
a complete plan. Input errors fail the attempt. An explicit index end marker
distinguishes normal completion from an interrupted producer.

Operation IDs may correlate an operation with its concurrent file stream.
They are not replay protection or durable recovery records. Index/plan end
markers have no digest or count.

Merge order is discovery order, not necessarily filesystem execution order.
For example, deleting a directory is discovered before deleting its children.
The destination schedules child deletion before parent removal and handles
type replacements before installing descendants. It may retain pending
directory dependencies for commit; unrelated file transfers must keep progressing.
Regular-file operations must distinguish creates from updates so the requester
can select whole-file bytes or delta instructions without probing the network.
A type replacement without a regular-file basis is a create, not an update.

### Delta transfer and staging

Use librsync 0.2.6 (default features disabled) for regular-file updates.
The maintainer approved the bundled LGPL-2.1 C implementation. Signature/delta
bytes use the library format inside bounded QUIC frames; parsing and matching
stay in librsync. Blocking workers connect to the network through bounded channels.
Destination requests a whole-file stream for creates. For updates, Destination
streams basis signatures with its request; Source constructs and streams the
delta. Librsync loads a per-active-file signature table before delta generation;
this does not gate other files or index production. Symlinks use target metadata
without delta processing. Adaptive strategy selection for updates, file-size
cutoffs, RTT or throughput probes belong only in Optimizations.

Rsync block checksums are needed to identify matching blocks. They are distinct
from optional whole-file change-detection hashes and from an extra integrity
check after reconstruction. Do not remove checksums the delta algorithm needs.

Given the same basis and delta, reconstruction is deterministic. Rely on QUIC's
authenticated reliable delivery for transport integrity. The POC does not
require hashing reconstructed files, comparing their final size with an expected
size, or exchanging whole-file verification digests. Such checks could detect
bugs or a changing basis, but they are not required now or promised as a later
recovery feature. Retain sizes and bounds that the delta algorithm, framing,
or filesystem metadata actually needs.

Stream reconstruction into a temporary file so the live basis is not overwritten
while copy instructions still need it. Stream creates into temporary files too.
An interrupted stream is an error, not a completed file. Keep the live tree
untouched, including deletions, directory changes, links, and metadata, until
planning succeeds and all requested transfers have been received and staged.
Private staging under `.quicsync` is the only filesystem mutation before commit.

Commit then installs staged files and applies deferred changes in filesystem
dependency order. This staging barrier is required; a digest/verification barrier,
fsync journal, durable completion record, and transaction-wide atomicity are not.
Failure during commit may leave partial changes; the user starts a fresh sync.

## Wire and connection model

Use configured peers running the same POC protocol. A fixed wire version is
sufficient; capability negotiation and extensible compatibility machinery are
not required. Frame lengths and valid paths remain necessary for decoding.

Source opens the control stream for notification. Its index travels to
Destination on an ordered unidirectional stream. Destination keeps the operation
stream local and opens an independent bidirectional stream for each file request.
Requests and update signatures travel to Source; bytes/deltas return on that
stream. Destination sends PlanEnd after successful planning and CompleteAck only
after all staging and commit work succeeds.

Conceptual messages:

```text
Control: Source -> Destination: StartSync(root)
         Destination -> Source: StartAccepted, PlanEnd, CompleteAck
         Either direction: Failure(error)
Index:   Source -> Destination: Record(record), End
File:    Destination -> Source: CreateRequest(path) | UpdateRequest(path)
         Destination -> Source, updates only: Signature(bytes), SignatureEnd
         Source -> Destination: WholeFile(bytes) | Delta(bytes), TransferEnd
```

Per-file IDs correlate concurrent work. TransferAccepted acknowledges successful
per-file staging, not installation; CompleteAck follows the session commit.

`PlanEnd` means only that planning has ended. `Index::End` means only
that no more records follow. They do not prove anything about another QUIC
stream. Completion still waits for all started transfers and filesystem work.
A reset or disconnect before an expected end marker fails the attempt.
No application-level plan/index manifest, operation count, or result digest
is required. No separate commit-request exchange is required.

QUIC early data (0-RTT) can be replayed. Ordinary post-handshake application
data is not the same replay concern. Use 0-RTT sync notification in the POC when
TLS resumption permits it; a cold connection needs a handshake. Retaining TLS
resumption material is not resuming a failed sync. Only the notification needs
early data, not filesystem mutation. The reusable SourceClient retains TLS tickets
in memory; the CLI's manual interactive mode keeps it alive across fresh syncs.
A one-shot process starts cold. Rejected early data fails the attempt without an
automatic retransmission. Replay-triggered scanning is an accepted
POC risk. In Resilience/MVP, request IDs are solely for suppressing these repeated
scans/DoS. Their design must cover the relevant
early-data replay window; it does not justify operation journals or resumption.
An optional request ID is distinct from an ephemeral file operation ID.

## Failure model and milestones

On error, fail the attempt and report it. The user may start a new sync.
No automatic retry, corruption recovery, resumable attempt, lost-ack query,
or rollback workflow is planned in any milestone. Source-authoritative
reconciliation does not imply the ability to repair an undetectable same-metadata
content change: a future explicit forced resync can be considered separately
if normal change detection is insufficient. It is not a POC recovery subsystem.

- **POC:** aggressively parallelized, streamed Rust/QUIC pipeline for stable
  supported trees over normal WAN connections, with a destination daemon and
  manual setup. Report start and stop of every pipeline stage; polished reporting
  is unnecessary. Streaming is part of the experiment, not deferred tuning.
- **Benchmarking:** compare with rsync across repository, file, and change sizes;
  measure end-to-end time, time to first index record, index completion, and
  throughput in bytes/time and files/time. Validate final bytes in tests.
- **Use filesystem watching:** maintain an index with OS filesystem hooks so it
  is ready before a sync. Do not automatically sync when files change.
- **Resilience/MVP:** selected unsupported cases, changing-file behavior, divergent
  ignore policy without a preliminary scan, and 0-RTT replay/DoS protection if
  early data is enabled. Fail-fast behavior remains valid. No retry/recovery system.
- **Optimizations:** measured traversal/concurrency improvements, Git
  assistance, and adaptive delta versus whole-file decisions.
- **UX improvements:** easier setup and clearer feedback after concept validation.

## Validation and outstanding cleanup

Tests verify exact resulting bytes outside the transfer hot path, normal
creates/updates/deletions, protected/ignored paths, and error propagation.
Pipeline tests must demonstrate that a first operation/payload arrives before
the upstream index/plan is complete. Use small bounded channels to expose
accidental full-stage buffering. Test malformed/truncated framing as an ordinary
failure, without building corruption-recovery or resume workflows.

HME-434 streams planning and HME-448 streams filesystem indexing on a blocking
worker through bounded channels, with per-directory sorting and active-scope
ignore rules. The scanner still hashes files for change detection; that is distinct
from reconstructed-file verification. Transport already frames records incrementally.
HME-447 removes durable state, generations, retry/status machinery, capability
negotiation, policy manifests and whole-file verification fields.
The revised project and issue descriptions supersede older implementation notes:

- HME-433 shares a private staging-directory descriptor across completed files;
  completed files are closed until commit instead of retaining one descriptor each.
- HME-434 emits create/update intent with file operations on Destination.
- HME-435 uses Destination-initiated whole-file creates and delta updates.
- HME-436 retains staged-file references and deferred changes in PendingCommit;
  only explicit commit invokes the dependency-ordered live-tree installer.
- HME-437/HME-438 stream Source's index to Destination and serve Destination's
  concurrent requests on Source. Source waits for Destination's completion ack.
- HME-450 enables notification-only 0-RTT with cached TLS tickets. Index sends,
  requests, and commit wait for handshake confirmation. HME-429 will add replay
  request IDs in Resilience/MVP.
- HME-443/HME-444 provide manual identity initialization, source sync commands,
  and a destination daemon. Each stage reports start and stop, including when
  cancelled. The daemon serializes sync attempts, not stages within an attempt,
  to avoid concurrent writers to a root.
- The scanner is currently serial within each root, not jwalk. Preserve streaming
  and scoped ignores when adding measured traversal parallelism.

Tests must cover whole-file creates, delta updates, first payload before index
completion, and unchanged live paths until the staging barrier, including a
failure after an earlier file has staged. Commit-order tests must still cover
nested deletions and directory/file replacements.

Do not use legacy code or completed ticket acceptance criteria to reintroduce
superseded requirements. Linear project/milestone descriptions define scope;
this repository document holds technical details. The former Linear architecture
resource is archived and is no longer a second maintained copy.
