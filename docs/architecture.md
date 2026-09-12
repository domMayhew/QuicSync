# QuicSync Technical Architecture

## Purpose and decision authority

QuicSync is a performance proof of concept (POC): measure whether QUIC and a
streamed, pipelined sync can beat rsync's latency for small to medium changes in
medium to large codebases over ordinary WAN connections. Getting the first
useful records and file bytes moving promptly is essential to the experiment.
A working implementation that waits for complete indexes or a complete plan
does not validate this concept.

The CLI may be rough, setup manual, and unsupported inputs may fail immediately.
Production readiness, broad filesystem coverage, and polished UX are not POC
requirements. These decisions supersede earlier MVP descriptions and legacy
code that implemented a more elaborate recovery protocol.

The source machine is the source of truth. On failure, the user starts a fresh
sync from the source. Automatic retry, resumption, corruption recovery, operation
journals, durable plans, persisted completion results, status queries, generations,
and rollback are not requirements, including in Resilience. A failed sync may
leave a mixed destination tree. Do not add infrastructure to recover the old
attempt.

## Pipeline

1. Notify the configured destination promptly and start both scans independently.
2. Traverse each tree once, discovering scoped ignore rules and index records
   together. Emit records in canonical path-component order as traversal proceeds.
3. Stream the destination index over QUIC. Merge it with the local source index
   incrementally, retaining only lookahead records.
4. Emit each operation immediately. Start signature generation and file transfer
   as soon as that operation and its prerequisites are available.
5. Reconstruct into temporary files and install completed files when their local
   dependencies permit. Schedule deletions and directory metadata by filesystem
   dependencies. No complete-plan verification barrier is required.
6. After the plan end marker and all outstanding work complete, acknowledge
   completion to the source. The acknowledgment is not persisted.

Use bounded channels and incremental reads/writes between stages. Backpressure
must suspend producers, not accumulate whole trees, plans, or file contents.
A delta library may need a per-file signature table; document that constraint
and keep it isolated to active files. Do not turn a per-file prerequisite into
a whole-session barrier. Bounded transfer concurrency is sufficient for the POC;
elaborate resource accounting and scheduler tuning can wait.

## Workspace and ownership

The Rust workspace has shared behavior in `quicsync-core` and thin `quicsync`
and `quicsyncd` binaries. Filesystem code does not depend on QUIC. Transport
carries typed messages but does not interpret filesystem operations.

- `config`: configured source/destination roots, address, peer pins, exclusions,
  and simple local limits.
- `auth`: local identities, pinned QUIC/TLS peer authentication, root authorization.
- `filesystem::{paths,ignore,scan,metadata,staging}`: confined paths, single-pass
  ignore evaluation and scanning, metadata, and temporary-file reconstruction.
- `protocol::{messages,codec,session}`: framed messages and minimal in-memory
  coordination for a single attempt.
- `transport::quic`: control, destination index, and per-file transfer streams.
- `sync::{planner,transfer,source,destination,commit}`: concurrent pipeline stages.

The existing `state` module and legacy protocol recovery fields are cleanup
debt, not architectural requirements. Do not integrate their SQLite journals
or durable session lifecycle into new orchestration.

## Filesystem model

Supported paths are relative component sequences. Reject absolute paths, empty
components, `.`, and `..`. Retain the existing root-confinement protections.
Always protect `.git` and `.quicsync`, even when ignore negations would match.
Never follow symbolic links. Copy links using their target metadata.

Regular files, directories, and links are sufficient. Preserve file content,
relative paths, modification times, and POSIX mode bits where supported.
Ownership, hard-link identity, sparse layout, ACLs, extended attributes, special
files, and broad platform collision handling are not required. Linux and macOS
are the intended platforms; a failing unsupported case may abort the POC.

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

The planner merge-walks two ordered asynchronous inputs and emits operations
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
directory dependencies; unrelated file transfers must keep progressing.

### Delta transfer and staging

Use an established rsync-style delta library for every regular-file transfer.
An absent basis produces an all-literal delta through the same path. Symlinks
use target metadata. Whole-file strategy selection, file-size cutoffs, RTT or
throughput probes belong only in Optimizations.

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
while copy instructions still need it. Install it after successful delta-stream
completion. An interrupted stream is an error, not a completed file. No fsync
journal, transaction-wide staging barrier, or durable completion record is needed.

## Wire and connection model

Use configured peers running the same POC protocol. A fixed wire version is
sufficient; capability negotiation and extensible compatibility machinery are
not required. Frame lengths and valid paths remain necessary for decoding.

One control stream carries start, operations, end, failures, and completion.
The destination index has an ordered unidirectional stream; each active file
has an independent bidirectional transfer stream.

Conceptual messages:

```text
Control: StartSync(root), Operation(op), PlanEnd, CompleteAck, Failure(error)
Index:   Record(record), End
File:    Request, SignatureHeader/Blocks, DeltaHeader, Copy/Literal, DeltaEnd
```

`PlanEnd` means only that no more operations follow. `Index::End` means only
that no more records follow. They do not prove anything about another QUIC
stream. Completion still waits for all started transfers and filesystem work.
A reset or disconnect before an expected end marker fails the attempt.
No application-level plan/index manifest, operation count, or result digest
is required. Any temporary `CommitRequest` marker in existing code carries
no digest and must not delay starting transfers.

QUIC early data (0-RTT) can be replayed. Ordinary post-handshake application
data is not the same replay concern. Disable mutating 0-RTT in the POC.
If early sync notifications are enabled in Resilience, request IDs are solely
for suppressing replay-triggered scans/DoS. Their design must cover the relevant
early-data replay window; it does not justify operation journals or resumption.
An optional request ID is distinct from an ephemeral file operation ID.

## Failure model and milestones

On error, fail the attempt and report it. The user may start a new sync.
No automatic retry, corruption recovery, resumable attempt, lost-ack query,
or rollback workflow is planned in any milestone. Source-authoritative
reconciliation does not imply the ability to repair an undetectable same-metadata
content change: a future explicit forced resync can be considered separately
if normal change detection is insufficient. It is not a POC recovery subsystem.

- **POC:** working QUIC pipeline for stable supported trees, manual setup, basic
  start/completion output. Streaming is part of the experiment, not deferred tuning.
- **Benchmarking:** compare with rsync; measure total latency, time to first
  index record, operation and payload, stage overlap, bytes and CPU for representative
  small/medium changes. Validate final bytes independently in tests/benchmarks.
- **Resilience:** selected unsupported cases, changing-file behavior, divergent
  ignore policy without a preliminary scan, and 0-RTT replay/DoS protection if
  early data is enabled. Fail-fast behavior remains valid. No retry/recovery system.
- **Optimizations:** measured traversal/concurrency improvements, watchers/Git
  assistance, and adaptive delta versus whole-file decisions.
- **UX improvements:** easier setup and clearer feedback after concept validation.

## Validation and outstanding cleanup

Tests verify exact resulting bytes outside the transfer hot path, normal
creates/updates/deletions, protected/ignored paths, and error propagation.
Pipeline tests must demonstrate that a first operation/payload arrives before
the upstream index/plan is complete. Use small bounded channels to expose
accidental full-stage buffering. Test malformed/truncated framing as an ordinary
failure, without building corruption-recovery or resume workflows.

Existing code is ahead of this intended scope in some areas and behind it in
streaming. Track cleanup explicitly: convert the materialized scanner and any
remaining stages to streamed production; remove unused durable state, generations,
retry/status machinery, capability negotiation and whole-file verification fields.
Do not use legacy code or completed ticket acceptance criteria to reintroduce
superseded requirements. Keep this file and the Linear architecture resource identical.
