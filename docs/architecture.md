# Architecture

QuicSync is a Cargo workspace with one shared library and two thin executable
entry points:

```text
crates/
├── quicsync-core/  shared library and all synchronization behavior
├── quicsync/       command-line client entry point
└── quicsyncd/      daemon entry point
tests/
└── fixtures/       deterministic integration-test filesystem trees
```

Both executables depend on `quicsync-core`. The core crate does not depend on
either executable, and executable crates contain only process-level wiring;
synchronization behavior belongs in core.

## Core modules

- `config` validates source and destination configuration.
- `error` defines errors shared across core operations.
- `filesystem` owns local filesystem access.
- `protocol` defines wire messages and protocol versions.
- `state` persists synchronization session state.
- `sync` coordinates synchronization through module interfaces.
- `transport` owns transport abstractions and QUIC integration.

The filesystem module must remain independent of transport. It works with
local data and paths; transport works with protocol data. Coordination between
them belongs in `sync`, which keeps storage and network concerns replaceable
and independently testable.
