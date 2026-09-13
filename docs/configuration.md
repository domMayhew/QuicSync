# Configuration

QuicSync reads configuration before opening a network connection or changing a
sync root. The setup directory must be owned by the current user and must not be
writable by group or other users. Its `identity.key` must have mode `0600`.

A source root uses `.quicsync/source.toml`:

```toml
root_id = "website"
destination = "192.0.2.10:4433"
peer_pin = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
global_exclusions = ["target/", "*.local"]

[limits]
max_parallel_hashes = 4
max_parallel_transfers = 4
```

A destination setup uses `.quicsync/destination.toml`. Root paths may be
absolute or relative to the setup directory:

```toml
listen_address = "0.0.0.0:4433"

[[roots]]
id = "website"
path = "/srv/website"
authorized_peers = [
  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
]
```

Pins are 64-character SHA-256 fingerprints. Root IDs contain only ASCII
letters, digits, `.`, `-`, and `_`. QuicSync rejects unknown fields, duplicate
root IDs and pins, symbolic-link roots, insecure administrative permissions,
and zero or excessive resource limits. Omitted limits use conservative local
defaults; peer input cannot replace them.

Available limits are `max_frame_bytes`, `max_path_bytes`, `max_components`,
`max_parallel_hashes`, `max_parallel_transfers`, and `max_inflight_bytes`.

## Running the POC

Run `quicsync init` from the source directory and `quicsyncd init` from
the destination directory (on the destination host) to create
private identities and print the compact fingerprints used in the configuration.
Create the TOML files above with mode `0600`; initialization does not generate
configuration or exchange pins automatically.

From the destination directory, start `quicsyncd serve`. Then run
`quicsync sync` from the source directory. All commands default to the current
directory; an optional explicit directory argument is also supported.
For a destination rooted in its setup directory, use `path = "."`.
For remote hosts, set the source's `destination` to the destination host's
reachable address and allow UDP on the configured port. A loopback address
only works when both processes run on the same host.
The daemon handles one attempt at a time; indexing, planning, transfer, and
staging within that attempt run concurrently. It continues accepting fresh
attempts after an error. Neither peer retries a failed attempt automatically.

For repeated manual measurements, use `quicsync interactive` in the source directory.
Each Enter starts a fresh sync; EOF exits. The process retains TLS session
tickets in memory so subsequent notifications can use 0-RTT. A new one-shot
process starts cold; tickets are not persisted to disk. Rejected early data
fails the attempt. The daemon must remain running to retain its TLS session
cache. Filesystem watching and automatic synchronization are not implemented.

Stage start/stop messages go to stderr. Completed files remain in private staging
until all transfers finish; then the daemon commits file, directory, and symlink
changes. Staging is not a transaction or rollback system.
