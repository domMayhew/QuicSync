//! Filesystem metadata and content digests.

use std::{
    fs::{self, File, Metadata},
    io::Read,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::Path,
};

use crate::{
    error::{ErrorCode, QuicSyncError},
    types::{Digest, EntryKind, EntryMetadata},
};

pub fn metadata_for(path: &Path) -> Result<(EntryMetadata, Option<Vec<u8>>), QuicSyncError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        QuicSyncError::new(
            ErrorCode::Io,
            None,
            format!("cannot inspect '{}': {error}", path.display()),
        )
    })?;
    metadata_from(path, &metadata)
}

pub fn metadata_from(
    path: &Path,
    metadata: &Metadata,
) -> Result<(EntryMetadata, Option<Vec<u8>>), QuicSyncError> {
    let file_type = metadata.file_type();
    let kind = if file_type.is_dir() {
        EntryKind::Directory
    } else if file_type.is_file() {
        EntryKind::RegularFile
    } else if file_type.is_symlink() {
        EntryKind::Symlink
    } else {
        return Err(QuicSyncError::new(
            ErrorCode::UnsupportedFilesystem,
            None,
            format!("unsupported filesystem entry '{}'", path.display()),
        ));
    };

    let symlink_target = if kind == EntryKind::Symlink {
        Some(read_symlink_target(path)?)
    } else {
        None
    };
    let size = symlink_target
        .as_ref()
        .map_or(metadata.len(), |target| target.len() as u64);

    Ok((
        EntryMetadata::new(
            kind,
            metadata.permissions().mode() & 0o7777,
            mtime_ns(metadata),
            size,
        ),
        symlink_target,
    ))
}

pub fn digest_file(path: &Path) -> Result<Digest, QuicSyncError> {
    let mut file = File::open(path).map_err(|error| {
        QuicSyncError::new(
            ErrorCode::Io,
            None,
            format!("cannot open file '{}': {error}", path.display()),
        )
    })?;
    let mut hasher = blake3::Hasher::new();
    let mut buffer = [0; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(|error| {
            QuicSyncError::new(
                ErrorCode::Io,
                None,
                format!("cannot read file '{}': {error}", path.display()),
            )
        })?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(Digest::from_bytes(*hasher.finalize().as_bytes()))
}

pub fn digest_symlink_target(target: &[u8]) -> Digest {
    Digest::from_bytes(*blake3::hash(target).as_bytes())
}

fn read_symlink_target(path: &Path) -> Result<Vec<u8>, QuicSyncError> {
    use std::os::unix::ffi::OsStringExt;

    fs::read_link(path)
        .map(|target| target.into_os_string().into_vec())
        .map_err(|error| {
            QuicSyncError::new(
                ErrorCode::Io,
                None,
                format!("cannot read symbolic link '{}': {error}", path.display()),
            )
        })
}

fn mtime_ns(metadata: &Metadata) -> i128 {
    (metadata.mtime() as i128 * 1_000_000_000) + metadata.mtime_nsec() as i128
}
