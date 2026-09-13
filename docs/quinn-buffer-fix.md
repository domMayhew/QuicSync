# Quinn Receive-Buffer Fix (HME-454)

Quinn-proto 0.11.17 can terminate an ordinary backpressured stream with
`too many gaps in stream buffer`. Its assembler retains well-utilized chunks
without coalescing them, then checks their count against the gap limit. Contiguous
data can therefore trigger the guard when the reader pauses.

An 8 MiB loopback transfer with default QuicSync bounds and a 500 ms receiver
pause reproduced the exact error. The test is
`a_backpressured_large_transfer_remains_readable` in `quic_transport.rs`.

## Temporary Dependency Override

Cargo patches only `quinn-proto` to the upstream 0.11.x maintenance commit
[b826169](https://github.com/quinn-rs/quinn/commit/b826169972971a4a18a7a7d32694d7d90483068b),
which coalesces contiguous small chunks during compaction. The published Quinn
API crate stays unchanged. The override uses a full immutable revision, not a
moving branch. Remove it and the scoped cargo-deny Git-source exception once
a compatible crates.io release contains the fix; retain the regression test.

This is the existing runtime dependency under MIT OR Apache-2.0, with no new
features or intended target changes. Its transitive dependency declarations are
unchanged from the release. The maintenance revision also includes intervening
packet/MTU/DATAGRAM fixes; it is not a private single-commit fork. Runtime
compaction copies contiguous chunks when needed, instead of failing the
connection. No measured compile-time or binary-size comparison was performed.

The upstream repository is active and contains regression coverage for both
contiguous chunks and malicious gaps. Local cargo-audit is unavailable; CI's
advisory/license/source checks remain enabled. No claim of a complete security
audit is made.

Downgrading before the guard would discard its memory-exhaustion protection.
Shrinking receive windows could constrain throughput, and adding eager whole-file
buffering would undermine backpressure. Neither is used. This fix adds no retries,
application recovery, or reconstructed-file verification.

Rebuild both executables with `cargo build --locked --workspace --bins` and
restart the daemon to use the new dependency. Already running daemons retain
their old code.
