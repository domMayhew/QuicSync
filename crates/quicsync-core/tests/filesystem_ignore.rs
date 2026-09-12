use quicsync_core::{
    filesystem::ignore::{IgnoreDecision, IgnorePolicy},
    types::{EntryKind, RelativePath},
};

fn path(wire: &[&[u8]]) -> RelativePath {
    RelativePath::new(wire.iter().map(|component| component.to_vec()).collect()).unwrap()
}

fn file_path(name: &[u8]) -> RelativePath {
    path(&[name])
}

#[test]
fn source_gitignore_rules_exclude_transfer_candidates() {
    let mut policy = IgnorePolicy::empty();
    policy
        .add_ignore_contents(None, b"target/\n*.log\n!important.log\n".to_vec())
        .unwrap();

    assert_eq!(
        policy.decision(&file_path(b"debug.log"), EntryKind::RegularFile),
        IgnoreDecision::Ignored,
    );
    assert_eq!(
        policy.decision(&file_path(b"important.log"), EntryKind::RegularFile),
        IgnoreDecision::Managed,
    );
    assert_eq!(
        policy.decision(&file_path(b"main.rs"), EntryKind::RegularFile),
        IgnoreDecision::Managed,
    );
    assert_eq!(
        policy.decision(&file_path(b"target"), EntryKind::Directory),
        IgnoreDecision::Ignored,
    );
}

#[test]
fn ignored_destination_only_paths_stay_out_of_the_managed_set() {
    let mut policy = IgnorePolicy::empty();
    policy
        .add_ignore_contents(None, b"local-only/\n*.cache\n".to_vec())
        .unwrap();

    for ignored in [
        (file_path(b"local-only"), EntryKind::Directory),
        (file_path(b"build.cache"), EntryKind::RegularFile),
    ] {
        assert!(!policy.manages(&ignored.0, ignored.1));
    }
}

#[test]
fn administrative_paths_are_protected_even_when_negated() {
    let mut policy = IgnorePolicy::empty();
    policy
        .add_ignore_contents(None, b"!.git/\n!.quicsync/\n".to_vec())
        .unwrap();

    for protected in [
        file_path(b".git"),
        path(&[b"src", b".git", b"config"]),
        file_path(b".quicsync"),
        path(&[b"nested", b".quicsync", b"state.sqlite"]),
    ] {
        assert_eq!(
            policy.decision(&protected, EntryKind::Directory),
            IgnoreDecision::Protected,
        );
    }
}

#[test]
fn nested_gitignore_files_apply_from_their_directory() {
    let mut policy = IgnorePolicy::empty();
    policy
        .add_ignore_contents(Some(file_path(b"src")), b"generated/\n".to_vec())
        .unwrap();

    assert_eq!(
        policy.decision(&path(&[b"src", b"generated"]), EntryKind::Directory),
        IgnoreDecision::Ignored,
    );
    assert_eq!(
        policy.decision(&file_path(b"generated"), EntryKind::Directory),
        IgnoreDecision::Managed,
    );
}

#[test]
fn configured_exclusions_are_root_scoped_policy_rules() {
    let policy =
        IgnorePolicy::with_configured_exclusions(&["tmp/".to_owned(), "*.local".to_owned()])
            .unwrap();

    assert_eq!(
        policy.decision(&file_path(b"tmp"), EntryKind::Directory),
        IgnoreDecision::Ignored,
    );
    assert_eq!(
        policy.decision(&file_path(b"machine.local"), EntryKind::RegularFile),
        IgnoreDecision::Ignored,
    );
}
