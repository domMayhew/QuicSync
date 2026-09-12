# QuicSync

QuicSync is a Rust performance proof of concept for low-latency file sync over
QUIC. It tests whether streaming and pipelining scanning, indexing, planning,
and delta transfer can outperform rsync for small to medium changes in medium
to large codebases. Each stage starts producing useful work before its input
is complete.

The source is authoritative. Failures stop the attempt; the user starts a fresh
sync. Automatic retries, resumption, corruption recovery, journals, and durable
completion tracking are not planned, even for Resilience. Rough CLI output and
manual setup are acceptable. Streaming is required for the experiment.

## Prerequisites

- [Rust](https://www.rust-lang.org/tools/install) stable, including Cargo and
  rustfmt
- Clippy (`rustup component add clippy`)
- Git

Use the toolchain pinned by the repository when a `rust-toolchain.toml` file is
present.

## Build and test

From the repository root, run:

```shell
cargo build --workspace --all-targets
cargo test --workspace --all-targets
```

Before opening a pull request, also run the formatting and lint checks:

```shell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

The workspace and crate responsibilities are described in the
[architecture documentation](docs/architecture.md).

Source and destination setup files are documented in the
[configuration guide](docs/configuration.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the development workflow and pull
request expectations. Dependency changes must follow the
[dependency policy](docs/dependency-policy.md), and all changes are subject to
the [merge requirements](docs/merge-requirements.md).

Maintainers preparing a release must complete the
[release checklist](docs/release-checklist.md).

## Security

Do not report vulnerabilities in a public issue. Follow the private reporting
process in [SECURITY.md](SECURITY.md).

## Ownership and license

Repository ownership and review routing are defined in
[.github/CODEOWNERS](.github/CODEOWNERS). QuicSync is licensed under the
[MIT License](LICENSE).
