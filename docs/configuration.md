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
