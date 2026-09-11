const CI: &str = include_str!("../../../.github/workflows/ci.yml");

fn job(name: &str) -> &str {
    let marker = format!("  {name}:\n");
    let start = CI
        .find(&marker)
        .unwrap_or_else(|| panic!("missing required CI job `{name}`"));
    let remainder = &CI[start + marker.len()..];
    let end = remainder
        .find(|character: char| !character.is_whitespace())
        .and_then(|_| {
            remainder
                .match_indices('\n')
                .map(|(index, _)| index + 1)
                .find(|&index| {
                    let line = &remainder[index..];
                    line.starts_with("  ")
                        && line
                            .as_bytes()
                            .get(2)
                            .is_some_and(|character| *character != b' ' && *character != b'#')
                })
        })
        .unwrap_or(remainder.len());

    &remainder[..end]
}

#[test]
fn merge_quality_gates_are_blocking_and_use_the_lockfile() {
    let expected_commands = [
        ("format", "cargo fmt --all -- --check"),
        (
            "clippy",
            "cargo clippy --locked --workspace --all-targets --all-features -- -D warnings",
        ),
        ("build", "cargo build --locked --workspace --all-targets"),
        ("test", "cargo test --locked --workspace --all-targets"),
        ("dependency-policy", "cargo deny check bans sources"),
        ("vulnerability-policy", "cargo audit --deny warnings"),
        ("license-policy", "cargo deny check licenses"),
    ];

    for (name, command) in expected_commands {
        let definition = job(name);
        assert!(
            definition.contains(command),
            "CI job `{name}` must run `{command}`"
        );
        assert!(
            !definition.contains("continue-on-error: true"),
            "CI job `{name}` must block merges"
        );
        assert!(
            !definition.contains("if: ${{ vars."),
            "CI job `{name}` must run"
        );
    }
}

#[test]
fn release_binaries_are_retained_as_artifacts() {
    let definition = job("artifacts");

    assert!(definition.contains("cargo build --locked --release --workspace --bins"));
    assert!(definition.contains("uses: actions/upload-artifact@"));
    assert!(definition.contains("path: dist/"));
    assert!(!definition.contains("continue-on-error: true"));
}

#[test]
fn every_pull_request_runs_the_quality_workflow() {
    assert!(CI.contains("  pull_request:\n"));
    assert!(!CI.contains("paths-ignore:"));
}

#[test]
fn workflow_reserves_future_validation_jobs() {
    assert!(job("fuzz").contains("if: ${{ vars.ENABLE_FUZZ == 'true' }}"));
    assert!(job("platform").contains("if: ${{ vars.ENABLE_PLATFORM == 'true' }}"));
}
