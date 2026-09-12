//! Confined relative-path validation and resolution.
//!
//! A wire path is a sequence of raw Unix filename components, never an OS path string, so
//! traversal is unrepresentable once decoding succeeds. [`decode_relative_path`] is the lexical
//! gate: it rejects absolute paths, empty components, `.`, `..`, NUL, administrative paths, and
//! anything larger than the configured limits.
//!
//! [`resolve_parent`] is the filesystem gate. It walks from a held root descriptor with
//! `openat`-style no-follow calls, so every ancestor must still be a real directory beneath the
//! root and a symbolic link can never redirect resolution outside it. Callers receive the parent
//! descriptor and the leaf name, and perform their operation relative to that descriptor.

use std::{
    ffi::CString,
    os::fd::{AsFd, BorrowedFd, OwnedFd},
    path::Path,
};

use rustix::{
    fs::{Mode, OFlags},
    io::Errno,
};

use crate::{
    config::{Limits, ValidatedRoot},
    error::{ErrorCode, ErrorContext, QuicSyncError},
    types::RelativePath,
};

/// Components QuicSync never indexes, transfers, or mutates, at any depth.
///
/// `.quicsync` holds local state, staging, and private keys; `.git` holds the repository metadata
/// that makes the two trees mean the same thing. Neither is a transfer or deletion target, so they
/// are refused here rather than relying on every caller to filter them.
pub const PROTECTED_COMPONENTS: [&[u8]; 2] = [b".quicsync", b".git"];

const DIRECTORY_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);

/// An open descriptor for a configured root directory.
#[derive(Debug)]
pub struct RootHandle(OwnedFd);

impl RootHandle {
    /// Opens `path` as a root without following a final symbolic link.
    pub fn open(path: &Path) -> Result<Self, QuicSyncError> {
        rustix::fs::open(path, DIRECTORY_FLAGS, Mode::empty())
            .map(Self)
            .map_err(|error| {
                QuicSyncError::new(
                    ErrorCode::InvalidConfiguration,
                    None,
                    format!("cannot open root '{}': {error}", path.display()),
                )
            })
    }

    /// Reopens the root a validated configuration already proved is a directory.
    pub fn from_validated(root: &ValidatedRoot) -> Result<Self, QuicSyncError> {
        Self::open(root.path())
    }

    pub fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }

    /// The device and inode the root resolved to, for later identity revalidation.
    pub fn filesystem_identity(&self) -> Result<(u64, u64), QuicSyncError> {
        filesystem_identity(self.0.as_fd())
    }
}

/// A parent directory descriptor and the leaf name an operation applies to.
#[derive(Debug)]
pub struct ValidatedParent {
    directory: OwnedFd,
    leaf: Vec<u8>,
}

impl ValidatedParent {
    pub fn as_fd(&self) -> BorrowedFd<'_> {
        self.directory.as_fd()
    }

    pub fn leaf(&self) -> &[u8] {
        &self.leaf
    }

    /// The device and inode of the resolved parent directory.
    pub fn filesystem_identity(&self) -> Result<(u64, u64), QuicSyncError> {
        filesystem_identity(self.directory.as_fd())
    }
}

/// Validates raw wire bytes as a root-relative path within the configured limits.
pub fn decode_relative_path(wire: &[u8], limits: &Limits) -> Result<RelativePath, QuicSyncError> {
    if wire.len() > limits.max_path_bytes() {
        return Err(limit_exceeded(format!(
            "path of {} bytes exceeds the {}-byte limit",
            wire.len(),
            limits.max_path_bytes(),
        )));
    }

    let components: Vec<Vec<u8>> = wire
        .split(|byte| *byte == b'/')
        .map(<[u8]>::to_vec)
        .collect();
    if components.len() > limits.max_components() {
        return Err(limit_exceeded(format!(
            "path of {} components exceeds the {}-component limit",
            components.len(),
            limits.max_components(),
        )));
    }

    // An absolute path, a trailing slash, and a doubled separator all surface as an empty
    // component, so `RelativePath` rejects them without a separate leading-slash check.
    let path = RelativePath::new(components).map_err(|error| {
        QuicSyncError::new(
            ErrorCode::InvalidPath,
            None,
            format!("invalid path: {error}"),
        )
    })?;
    reject_protected(&path)?;
    Ok(path)
}

/// Resolves `path`'s parent from the held root descriptor without following symbolic links.
pub fn resolve_parent(
    root: &RootHandle,
    path: &RelativePath,
) -> Result<ValidatedParent, QuicSyncError> {
    reject_protected(path)?;

    let (leaf, ancestors) = path
        .components()
        .split_last()
        .expect("a relative path has at least one component");
    let mut directory = duplicate(root.as_fd(), path)?;
    for ancestor in ancestors {
        directory = open_directory(directory.as_fd(), ancestor, path)?;
    }

    Ok(ValidatedParent {
        directory,
        leaf: leaf.clone(),
    })
}

fn open_directory(
    parent: BorrowedFd<'_>,
    component: &[u8],
    path: &RelativePath,
) -> Result<OwnedFd, QuicSyncError> {
    let name = CString::new(component.to_vec()).expect("a validated component has no NUL");
    rustix::fs::openat(parent, name.as_c_str(), DIRECTORY_FLAGS, Mode::empty()).map_err(|error| {
        // `O_NOFOLLOW` turns a symbolic-link ancestor into `ELOOP` and `O_DIRECTORY` turns any
        // other non-directory into `ENOTDIR`. Both mean resolution would have left the root.
        let code = match error {
            Errno::LOOP | Errno::NOTDIR => ErrorCode::PathConfinementViolation,
            _ => ErrorCode::Io,
        };
        QuicSyncError::new(
            code,
            None,
            format!(
                "cannot resolve path component '{}': {error}",
                String::from_utf8_lossy(component),
            ),
        )
        .with_context(ErrorContext::default().with_path(path.clone()))
    })
}

fn duplicate(descriptor: BorrowedFd<'_>, path: &RelativePath) -> Result<OwnedFd, QuicSyncError> {
    rustix::io::dup(descriptor).map_err(|error| {
        QuicSyncError::new(
            ErrorCode::Io,
            None,
            format!("cannot duplicate the root descriptor: {error}"),
        )
        .with_context(ErrorContext::default().with_path(path.clone()))
    })
}

fn filesystem_identity(descriptor: BorrowedFd<'_>) -> Result<(u64, u64), QuicSyncError> {
    let status = rustix::fs::fstat(descriptor).map_err(|error| {
        QuicSyncError::new(
            ErrorCode::Io,
            None,
            format!("cannot inspect a resolved directory: {error}"),
        )
    })?;
    Ok((status.st_dev, status.st_ino))
}

fn reject_protected(path: &RelativePath) -> Result<(), QuicSyncError> {
    for component in path.components() {
        if PROTECTED_COMPONENTS.contains(&component.as_slice()) {
            return Err(QuicSyncError::new(
                ErrorCode::PathConfinementViolation,
                None,
                format!(
                    "path component '{}' is administratively protected",
                    String::from_utf8_lossy(component),
                ),
            )
            .with_context(ErrorContext::default().with_path(path.clone())));
        }
    }
    Ok(())
}

fn limit_exceeded(diagnostic: String) -> QuicSyncError {
    QuicSyncError::new(ErrorCode::ResourceLimitExceeded, None, diagnostic)
}

/// Opens a regular file without following links; absent paths or non-files have no basis.
/// This also permits a new source subtree where a destination ancestor is still a file.
pub fn open_regular(
    root: &RootHandle,
    path: &RelativePath,
) -> Result<Option<std::fs::File>, QuicSyncError> {
    reject_protected(path)?;
    let (leaf, ancestors) = path.components().split_last().expect("validated path");
    let mut directory = duplicate(root.as_fd(), path)?;
    for ancestor in ancestors {
        let name = CString::new(ancestor.as_slice()).unwrap();
        directory =
            match rustix::fs::openat(&directory, name.as_c_str(), DIRECTORY_FLAGS, Mode::empty()) {
                Ok(fd) => fd,
                Err(Errno::NOENT | Errno::NOTDIR | Errno::LOOP) => return Ok(None),
                Err(error) => {
                    return Err(QuicSyncError::new(
                        ErrorCode::Io,
                        None,
                        format!("open file ancestor: {error}"),
                    ));
                }
            };
    }
    let name = CString::new(leaf.as_slice()).unwrap();
    let fd = match rustix::fs::openat(
        &directory,
        name.as_c_str(),
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(Errno::NOENT | Errno::LOOP) => return Ok(None),
        Err(error) => {
            return Err(QuicSyncError::new(
                ErrorCode::Io,
                None,
                format!("open file: {error}"),
            ));
        }
    };
    let file = std::fs::File::from(fd);
    if !file
        .metadata()
        .map_err(|error| QuicSyncError::new(ErrorCode::Io, None, error.to_string()))?
        .is_file()
    {
        return Ok(None);
    }
    Ok(Some(file))
}
