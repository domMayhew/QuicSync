//! Streamed filesystem indexing for stable POC sync roots.

use std::{
    ffi::OsString,
    fs,
    os::unix::ffi::{OsStrExt, OsStringExt},
    path::{Path, PathBuf},
};

use tokio::sync::mpsc::Sender;

use crate::{
    config::{Limits, ValidatedRoot},
    error::{ErrorCode, ErrorContext, QuicSyncError},
    filesystem::{
        ignore::{IgnoreDecision, IgnorePolicy},
        metadata,
    },
    protocol::messages::IndexMessage,
    types::{Digest, EntryKind, IndexRecord, RelativePath},
};

/// Runs blocking traversal off the async runtime and streams canonical records.
pub async fn scan_validated_root(
    root: &ValidatedRoot,
    configured_exclusions: &[String],
    limits: &Limits,
    output: Sender<Result<IndexMessage, QuicSyncError>>,
) -> Result<(), QuicSyncError> {
    scan_root(root.path(), configured_exclusions, limits, output).await
}

/// Produces records through a bounded channel while consumers run concurrently.
///
/// The caller must join this future and consume the channel concurrently. Filesystem
/// work runs on a blocking worker. Success emits End; errors never emit End.
/// Memory holds the active directories' sorted entries and ignore rules, not an index.
pub async fn scan_root(
    root: &Path,
    configured_exclusions: &[String],
    limits: &Limits,
    output: Sender<Result<IndexMessage, QuicSyncError>>,
) -> Result<(), QuicSyncError> {
    let root = root.to_owned();
    let exclusions = configured_exclusions.to_vec();
    let limits = *limits;
    tokio::task::spawn_blocking(move || {
        let result = (|| {
            let mut policy = IgnorePolicy::with_configured_exclusions(&exclusions)?;
            scan_directory(&root, None, &mut policy, &limits, &output)?;
            emit(&output, IndexMessage::End)
        })();
        if let Err(error) = &result {
            let _ = output.blocking_send(Err(error.clone()));
        }
        result
    })
    .await
    .map_err(|error| {
        QuicSyncError::new(
            ErrorCode::OperationFailed,
            None,
            format!("scanner worker failed: {error}"),
        )
    })?
}

fn emit(
    output: &Sender<Result<IndexMessage, QuicSyncError>>,
    message: IndexMessage,
) -> Result<(), QuicSyncError> {
    output
        .blocking_send(Ok(message))
        .map_err(|_| QuicSyncError::new(ErrorCode::OperationFailed, None, "index consumer closed"))
}

fn scan_directory(
    root: &Path,
    scope: Option<&RelativePath>,
    policy: &mut IgnorePolicy,
    limits: &Limits,
    output: &Sender<Result<IndexMessage, QuicSyncError>>,
) -> Result<(), QuicSyncError> {
    let directory = root.join(relative_to_path(scope));
    let checkpoint = policy.checkpoint();
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

    // Discover ignore files from this directory's enumeration, without following links.
    if let Some(entry) = entries
        .iter()
        .find(|entry| entry.file_name() == ".gitignore")
    {
        let metadata = fs::symlink_metadata(entry.path()).map_err(|error| {
            QuicSyncError::new(
                ErrorCode::Io,
                None,
                format!("cannot inspect ignore file: {error}"),
            )
        })?;
        if metadata.is_file() {
            let contents = fs::read(entry.path()).map_err(|error| {
                QuicSyncError::new(
                    ErrorCode::Io,
                    None,
                    format!("cannot read ignore file: {error}"),
                )
            })?;
            policy.add_ignore_contents(scope.cloned(), contents)?;
        }
    }

    for entry in entries {
        if output.is_closed() {
            return Err(QuicSyncError::new(
                ErrorCode::OperationFailed,
                None,
                "index consumer closed",
            ));
        }
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
        emit(
            output,
            IndexMessage::Record(IndexRecord {
                path: path.clone(),
                metadata: entry_metadata,
                digest,
                symlink_target,
            }),
        )?;

        if entry_metadata.kind() == EntryKind::Directory {
            scan_directory(root, Some(&path), policy, limits, output)?;
        }
    }

    policy.restore(checkpoint);
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
