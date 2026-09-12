# Project intent

QuicSync is a performance POC, not a production-readiness MVP. Validate whether
QUIC plus streamed, pipelined stages improves latency versus rsync for small to
medium changes in medium to large codebases over typical WAN connections.

- Stream scanning, indexes, planning, signatures, deltas, and file writes as much
  as possible. Begin downstream work before upstream completion. Use bounded
  channels and per-file concurrency; do not collect whole indexes or plans.
- Collect scoped ignore rules during the same filesystem traversal as indexing,
  using the ignore crate. Both sides scan independently. Different ignore policies
  have undefined results for the POC. Protect .git and .quicsync; never follow links.
- The source is authoritative. Fail fast; the user starts a fresh sync on failure.
  Do not add automatic retries, corruption recovery, resumption, operation journals,
  durable plans/completion, generations, status queries, or rollback, even under
  Resilience. Existing implementations of these are cleanup debt.
- PlanEnd and index End are plain markers, with no count or digest. Keep explicit
  completion distinct from an interrupted stream. Rely on QUIC/TLS transport integrity.
- No required reconstructed-file size/digest verification. Keep block checksums
  and sizes needed by delta matching, bounds, framing, or metadata. Verify resulting
  bytes in tests, not through mandatory extra production hashing passes.
- Request IDs are only a future 0-RTT replay/DoS concern, not recovery state. Disable
  mutating early data for the POC. Ephemeral operation IDs may correlate file streams.
- Use delta for every regular file, with literals when no basis exists. Use an
  established library. Adaptive whole-file selection and RTT/throughput probes
  belong in Optimizations. Do not add capability negotiation for the POC.
- Rough CLI UX, manual setup, stable-tree assumptions, and unsupported edge cases
  are acceptable. Preserve existing root-confinement protections.
- Follow docs/architecture.md and keep the Linear architecture resource in sync.
  Correct conflicting ticket descriptions instead of restoring obsolete requirements.
- Build each ticket on the latest working branch; commit it on a focused branch.
  PR creation is not required. Continue independently until a real user decision
  is needed. Build and run relevant tests before pushing.
