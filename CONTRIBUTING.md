# Contributing to QuicSync

Thank you for helping improve QuicSync.

## Before starting

For a substantial change, open an issue first so its scope and design can be
agreed before implementation. Search existing issues and pull requests to avoid
duplicate work. Security vulnerabilities must use the private process in
[SECURITY.md](SECURITY.md), not an issue.

## Development workflow

1. Fork or branch from the latest default branch.
2. Keep each change focused and add or update tests with behavior changes.
3. Follow existing Rust conventions and avoid unrelated formatting changes.
4. Run the local checks below.
5. Open a pull request explaining the problem, approach, testing, and any
   compatibility or security impact.

```shell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets
cargo build --workspace --all-targets
```

The workspace manifest is tracked separately and these commands become runnable
when it lands. If a pull request cannot run a required check, explain why in the
pull request.

## Pull requests

- Link the relevant issue when one exists.
- Keep commits and the final diff reviewable; separate unrelated changes.
- Update user, operator, or policy documentation when behavior changes.
- Document new dependencies, enabled features, and license review as required by
  the [dependency policy](docs/dependency-policy.md).
- Respond to review feedback and keep required checks passing.

All changes, including maintainer changes, follow the
[merge requirements](docs/merge-requirements.md). The
[CODEOWNERS file](.github/CODEOWNERS) identifies the responsible reviewers.

## Commit messages

Use a short imperative subject that describes the change. Add a body when the
motivation or a non-obvious tradeoff would otherwise be lost.

By contributing, you agree that your contribution is licensed under the
repository's [MIT License](LICENSE).
