# POC Validation (HME-452)

## Reproduce Local Smoke

On Linux, with Bash and GNU coreutils/diffutils:

```sh
cargo build --locked --workspace --bins
bash scripts/poc-smoke.sh
```

The script creates disposable source/destination roots and independent identities,
starts the daemon from its destination directory on an ephemeral loopback UDP
port, and cleans up its process and files on exit. It never uses the repository's
local `.quicsync` configuration. Set `KEEP_SMOKE_FILES=1` to retain roots/logs.
For release binaries or a custom Cargo target directory, set `QUICSYNC_BIN` and
`QUICSYNCD_BIN` to absolute binary paths.

It checks six completed attempts with one persistent daemon: initial creation,
no changes, small edits and deletions, medium edits, and two interactive attempts.
External tree comparison checks file bytes, directory existence, and symlink
targets. Additional assertions check an executable mode, preservation of ignored
and protected destination paths, no transfer of ignored source paths, an unchanged
file's inode, and stage start/stop messages. This is process-level correctness
coverage; the gated library tests separately prove payload can precede index End.
CI runs this smoke test after the workspace tests.

HME-454 adds an 8 MiB file to exercise a larger whole-file create followed by a
delta update. The local timing table below predates that addition.

## Local Evidence

Tested binaries at d3b52f4 (including the HME-443 CLI changes), debug profile,
on the development Linux host over loopback. Synthetic fixture: 2,048 files
of 4,097 bytes in 64 directories, plus an empty directory and a symlink.
The medium change appends 8,194 bytes to 127 files, approximately 1 MiB.
All six attempts passed external checks.

One observed run, not a benchmark:

| Attempt | Source index stage | Source total |
| --- | --- | --- |
| Initial | 163 ms | 1,008 ms |
| No changes | 160 ms | 166 ms |
| Small edits/deletions | 159 ms | 165 ms |
| Medium edits | 154 ms | 249 ms |
| Interactive edit | 149 ms | 154 ms |
| Interactive unchanged | 152 ms | 155 ms |

Stage timers include backpressure and overlap; they are not isolated CPU or disk
measurements. This repetitive synthetic dataset, debug build, and loopback link
are not representative WAN performance evidence. No rsync comparison was made.

## Still Required

HME-452 remains open until a representative medium/large repository is tested
over a real stable WAN. A remote host, disposable destination root, and authorized
dataset are needed. Run matching release binaries, start `quicsyncd serve` in
the remote destination directory, and configure the source with its reachable
address and pin. Preserve the same ignore policy on both sides.

Record revision, toolchain/build profile, OS/CPU/filesystem, repository file/byte
counts, change sizes, network environment, exact commands, external content
comparison, and both peers' stage logs for initial/no-change/small/medium attempts.
Keep the daemon running and include interactive attempts. Do not infer 0-RTT
acceptance merely from CLI timings; cold/resumed behavior has separate tests.
Systematic comparison with rsync belongs to Benchmarking, not this smoke test.
