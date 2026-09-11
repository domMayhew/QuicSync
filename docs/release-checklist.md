# Release checklist

Use this checklist for every QuicSync release. Track the completed checklist in
the release pull request or release issue.

## Prepare

- [ ] Confirm the intended commit, version, and release scope.
- [ ] Review merged changes for compatibility, security, migration, and
      user-facing impact.
- [ ] Update the changelog or release notes, including breaking changes and
      upgrade steps.
- [ ] Set the version consistently in manifests and generated metadata.
- [ ] Confirm dependency changes meet the dependency policy and required notices
      are current.
- [ ] Confirm supported platforms and minimum toolchain versions are documented.

## Verify

- [ ] Run `cargo fmt --all -- --check`.
- [ ] Run
      `cargo clippy --workspace --all-targets --all-features -- -D warnings`.
- [ ] Run `cargo test --workspace --all-targets`.
- [ ] Run `cargo build --workspace --all-targets --release`.
- [ ] Run `cargo audit` and assess every advisory.
- [ ] Verify required CI checks pass on the exact release commit.
- [ ] Smoke-test release artifacts on each supported platform.
- [ ] Confirm artifacts contain the correct version and license information.

## Publish

- [ ] Merge the release pull request under the normal merge requirements.
- [ ] Create a signed, annotated version tag from the verified commit.
- [ ] Build and publish artifacts through the approved release workflow.
- [ ] Verify artifact checksums and signatures, where provided.
- [ ] Publish release notes and link artifacts from the repository release.
- [ ] Verify a clean installation or download from each published channel.

## Follow up

- [ ] Announce the release through the appropriate project channels.
- [ ] Monitor vulnerability reports, installation failures, and regressions.
- [ ] Record follow-up issues and decide whether a patch release is required.
- [ ] Update the supported-version table in `SECURITY.md` when support changes.
