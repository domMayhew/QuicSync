# Indexing Investigation

The reported 20 ms rsync versus 1.02 s QuicSync comparison used different
inputs. The rsync command excluded `nixpkgs`, leaving four regular files.
QuicSync indexed that subtree too: 41,254 regular files, 69,715 records,
and 160,828,097 regular-file bytes. The rsync source also lacked a trailing
slash, so its destination was `nix_dest/nix` rather than `nix_dest`.

Read-only measurements on the development host, 2026-09-13:

| Measurement | Observed elapsed time |
| --- | --- |
| Release scanner, full tree, queue 4, three runs | 0.87-1.17 s |
| Release scanner, full tree, queue 256, three runs | 0.90-0.91 s |
| Release scanner, excluding nixpkgs, three runs | 0.06-0.43 ms |
| rsync full tree, metadata comparison, dry run | 0.56 s |
| rsync excluding nixpkgs, dry run | 0.045 s |

Scanner measurements include traversal, ignore processing, metadata reads,
full-file hashing and bounded-channel handoff to a draining consumer. They
exclude network, planning and transfer. Rsync measurements are dry runs, not
actual changed-file transfer benchmarks. Runs were sequential with uncontrolled
warm caches. These numbers locate the workload mismatch; they are not a speedup
claim or an isolated measurement of hashing cost.

## Reproduce Scanner Measurements

```sh
cargo run --locked --release -p quicsync-core --example scan_profile -- ~/programming/nix 3 4
cargo run --locked --release -p quicsync-core --example scan_profile -- ~/programming/nix 3 256
cargo run --locked --release -p quicsync-core --example scan_profile -- ~/programming/nix 3 4 nixpkgs/
```

Arguments are root, run count, queue capacity, then optional Git-ignore patterns.
The example outputs one JSON object per run. It uses the production scanner and
local scoped `.gitignore` files, always protects `.git` and `.quicsync`, and
does not load source.toml's configured exclusions: pass those patterns explicitly.
The first-record duration measures arrival at the local consumer. Logical bytes
are indexed file sizes, not bytes transferred over QUIC. A single scanner worker
runs per root; this example measures that existing behavior.

## Interpreting Rsync

Rsync's [incremental recursion](https://download.samba.org/pub/rsync/rsync.1#opt--inc-recursive)
starts transferring while it discovers subsequent directories. It rebuilds its
file list per run; incremental does not mean an index remembered from a previous
invocation. QuicSync also streams its index, plan and transfers as work proceeds.
Rsync normally decides whether to transfer using size and mtime, whereas QuicSync
currently reads and hashes every regular file on both peers. Local rsync also
defaults to whole-file transfer; that distinction matters when comparing a
changed tiny file against QuicSync's delta request.

For the next end-to-end comparison, use the same source contents, destination
baseline, exclusions and source trailing slash. Restore the same edit outside
each timed run. Capture exact commands, versions and release profile. Compare
metadata and checksum rsync variants separately. HME-456 tracks the process
harness; HME-457 tracks pipeline event instrumentation.

Parallel traversal with jwalk remains a candidate. Measure it while preserving
one-pass scoped-ignore discovery, canonical streamed output and bounded
prefetch. Also measure avoiding full-file hashes for metadata-matching entries,
with its same-size/same-mtime limitation made explicit. The current queue-size
experiment alone does not justify changing the scanner/network handoff.
