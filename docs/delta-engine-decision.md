# Delta engine decision for HME-435

Status: maintainer decision needed before selecting the dependency.

## Proposed choice

Use librsync 0.2.6 with default features disabled. Its Rust Signature, Delta and
Patch adapters consume Read/Seek inputs and produce Read outputs. Run them on
blocking workers connected to bounded channels; frame chunks of the library's
signature/delta byte streams over QUIC. Do not duplicate the library's parser or
materialize complete files/deltas in application memory.

Delta construction loads one basis signature table before matching that file.
This is a per-active-file prerequisite, not an index/plan barrier. Bound active
file concurrency. With no destination basis, generate a signature for an empty
reader and use the same delta path, producing literal content.

The signature stream's clean end must be distinguished from a reset. Likewise,
only successful delta completion makes StagedFile ready for installation. No
extra result digest/size check or recovery state is required.

## Dependency evidence

Inspected Cargo's downloaded sources for librsync 0.2.6 and librsync-sys 0.1.4:

- The Rust wrapper and sys package metadata declare MIT/Apache-2.0.
- The bundled librsync C source README and COPYING declare LGPL version 2.1.
- librsync-sys/build.rs compiles the bundled C sources into librsync.a using cc.
  It does not simply use an optionally installed shared library.
- A C compiler is therefore needed on Linux and macOS. Default logging is
  optional and not needed for the POC; disable default features.
- The crate metadata alone is insufficient to describe the transitive licensing
  impact. Keep the bundled notices and review distribution obligations before
  enabling this dependency. No license-policy exception has been added.

The repository dependency policy requires explicit maintainer review for
weak-copyleft dependencies. The decision is whether to accept the bundled LGPL
implementation for this POC or keep the implementation permissively licensed.
This note is dependency evidence, not a determination of legal obligations.

## Alternatives considered

fast_rsync 0.2.0 is a pure-Rust implementation, but its signature/diff APIs accept
whole-file byte slices. Its delta output can be written incrementally, but that
does not remove the whole-file input requirement. Mapping a file avoids copying
it into a Vec; it does not provide the incremental Read interface requested here.
Do not silently substitute a batch implementation.

A different permissively licensed streaming engine remains an option, but none
has been selected. Hand-writing delta matching is contrary to the requirement
to use an established engine.

## Sources

- [librsync streaming API](https://docs.rs/librsync/0.2.6/librsync/)
- [Rust wrapper repository](https://github.com/mbrt/librsync-rs)
- [Native librsync repository and license](https://github.com/librsync/librsync)
- [fast_rsync API](https://docs.rs/fast_rsync/0.2.0/fast_rsync/)
- [Repository dependency policy](dependency-policy.md)
