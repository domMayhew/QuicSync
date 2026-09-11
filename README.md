# QuicSync

QuicSync is an early-stage Rust project for transferring and synchronizing data
over QUIC. The repository is currently establishing its foundations; interfaces
and workflows may change before the first release.

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
