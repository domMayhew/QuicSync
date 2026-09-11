//! Filesystem indexing for stable MVP sync roots.

use std::{
    ffi::OsString,
    fs,
    os::unix::ffi::{OsStrExt, OsStringExt},
    path::{Path, PathBuf},
};

use crate::{
    config::{Limits, ValidatedRoot},
    error::{ErrorCode, ErrorContext, QuicSyncError},
    filesystem::{
        ignore::{IgnoreDecision, IgnorePolicy},
        metadata,
    },
    types::{Digest, EntryKind, IndexRecord, RelativePath},
};

/// Scans a validated root path into deterministic root-relative index records.
pub fn scan_validated_root(
    root: &ValidatedRoot,
    configured_exclusions: &[String],
    limits: &Limits,
) -> Result<Vec<IndexRecord>, QuicSyncError> {
    scan_root(root.path(), configured_exclusions, limits)
}

/// Scans `root` into root-relative index records.
///
/// This MVP scanner is intentionally synchronous and assumes the tree is stable while it runs.
pub fn scan_root(
    root: &Path,
    configured_exclusions: &[String],
    limits: &Limits,
) -> Result<Vec<IndexRecord>, QuicSyncError> {
    let mut policy = IgnorePolicy::with_configured_exclusions(configured_exclusions)?;
    let mut records = Vec::new();
    scan_directory(root, None, &mut policy, limits, &mut records)?;
    records.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(records)
}

fn scan_directory(
    root: &Path,
    scope: Option<&RelativePath>,
    policy: &mut IgnorePolicy,
    limits: &Limits,
    records: &mut Vec<IndexRecord>,
) -> Result<(), QuicSyncError> {
    let directory = root.join(relative_to_path(scope));
    let ignore_file = directory.join(".gitignore");
    if ignore_file.is_file() {
        let contents = fs::read(&ignore_file).map_err(|error| {
            QuicSyncError::new(
                ErrorCode::Io,
                None,
                format!("cannot read '{}': {error}", ignore_file.display()),
            )
        })?;
        policy.add_ignore_contents(scope.cloned(), contents)?;
    }

    let mut entries = fs::read_dir(&directory)
        .map_err(|error| {
            QuicSyncError::new(
                ErrorCode::Io,
                None,
                format!("cannot read directory '{}': {error}", directory.display()),
            )
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| {
            QuicSyncError::new(
                ErrorCode::Io,
                None,
                format!(
                    "cannot enumerate directory '{}': {error}",
                    directory.display()
                ),
            )
        })?;
    entries.sort_by(|left, right| {
        left.file_name()
            .as_bytes()
            .cmp(right.file_name().as_bytes())
    });

    for entry in entries {
        let name = entry.file_name().as_bytes().to_vec();
        let path = append_component(scope, name, limits)?;
        let full_path = entry.path();
        let (entry_metadata, symlink_target) = metadata::metadata_for(&full_path)
            .map_err(|error| error.with_context(ErrorContext::default().with_path(path.clone())))?;

        match policy.decision(&path, entry_metadata.kind()) {
            IgnoreDecision::Managed => {}
            IgnoreDecision::Ignored | IgnoreDecision::Protected => continue,
        }

        let digest = digest_for(&full_path, entry_metadata.kind(), symlink_target.as_deref())?;
        records.push(IndexRecord {
            path: path.clone(),
            metadata: entry_metadata,
            digest,
            symlink_target,
        });

        if entry_metadata.kind() == EntryKind::Directory {
            scan_directory(root, Some(&path), policy, limits, records)?;
        }
    }

    Ok(())
}

fn digest_for(
    full_path: &Path,
    kind: EntryKind,
    symlink_target: Option<&[u8]>,
) -> Result<Option<Digest>, QuicSyncError> {
    match kind {
        EntryKind::Directory => Ok(None),
        EntryKind::RegularFile => metadata::digest_file(full_path).map(Some),
        EntryKind::Symlink => Ok(symlink_target.map(metadata::digest_symlink_target)),
    }
}

fn append_component(
    prefix: Option<&RelativePath>,
    component: Vec<u8>,
    limits: &Limits,
) -> Result<RelativePath, QuicSyncError> {
    let mut components = prefix
        .map(|path| path.components().to_vec())
        .unwrap_or_default();
    components.push(component);
    if components.len() > limits.max_components() {
        return Err(limit_exceeded(format!(
            "path of {} components exceeds the {}-component limit",
            components.len(),
            limits.max_components(),
        )));
    }
    let path_bytes = components
        .iter()
        .map(Vec::len)
        .sum::<usize>()
        .saturating_add(components.len().saturating_sub(1));
    if path_bytes > limits.max_path_bytes() {
        return Err(limit_exceeded(format!(
            "path of {path_bytes} bytes exceeds the {}-byte limit",
            limits.max_path_bytes(),
        )));
    }

    RelativePath::new(components).map_err(|error| {
        QuicSyncError::new(
            ErrorCode::InvalidPath,
            None,
            format!("invalid directory entry path: {error}"),
        )
    })
}

fn relative_to_path(path: Option<&RelativePath>) -> PathBuf {
    path.map_or_else(PathBuf::new, |path| components_to_path(path.components()))
}

fn components_to_path(components: &[Vec<u8>]) -> PathBuf {
    let mut path = PathBuf::new();
    for component in components {
        path.push(OsString::from_vec(component.clone()));
    }
    path
}

fn limit_exceeded(diagnostic: String) -> QuicSyncError {
    QuicSyncError::new(ErrorCode::ResourceLimitExceeded, None, diagnostic)
}
