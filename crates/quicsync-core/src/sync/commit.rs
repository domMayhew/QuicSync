//! Filesystem installation after staging, ordered only by filesystem dependencies.

use crate::{
    error::{ErrorCode, ErrorContext, QuicSyncError},
    filesystem::{
        paths::{RootHandle, resolve_parent},
        staging::{StagedFile, set_file_metadata},
    },
    protocol::messages::Operation,
    types::{EntryKind, IndexRecord, RelativePath},
};
use rustix::fs::{AtFlags, Mode, OFlags, Timespec, Timestamps, UTIME_OMIT};
use std::{ffi::CString, fs::File, os::unix::ffi::OsStringExt, path::PathBuf};

/// In-memory changes retained while transfers stage. Dropping this leaves live paths untouched.
#[derive(Default)]
pub struct PendingCommit {
    changes: Vec<(Operation, Option<StagedFile>)>,
}

impl PendingCommit {
    pub fn stage(
        &mut self,
        operation: Operation,
        file: Option<StagedFile>,
    ) -> Result<(), QuicSyncError> {
        if matches!(&operation, Operation::UpsertFile { .. }) != file.is_some() {
            return Err(failure("only file upserts require a staged file"));
        }
        self.changes.push((operation, file));
        Ok(())
    }

    /// Caller invokes on a blocking worker only after planning and all transfers succeed.
    /// Independent paths have no required order; IDs are not used for scheduling.
    pub fn commit(self, root: RootHandle) -> Result<(), QuicSyncError> {
        let installer = Installer { root };
        let mut deletions = Vec::new();
        let mut directories = Vec::new();
        let mut contents = Vec::new();
        for (operation, file) in self.changes {
            match operation {
                Operation::Delete {
                    path,
                    expected_kind,
                    ..
                } => {
                    deletions.push((path, expected_kind));
                }
                Operation::UpsertDirectory { record, .. } => directories.push(record),
                _ => contents.push((operation, file)),
            }
        }
        // Remove children before parents, including directory-to-file replacements.
        deletions.sort_by_key(|(path, _)| std::cmp::Reverse(path.components().len()));
        for (path, kind) in deletions {
            installer.unlink(
                &path,
                if kind == EntryKind::Directory {
                    AtFlags::REMOVEDIR
                } else {
                    AtFlags::empty()
                },
            )?;
        }
        // Create writable parents before children. No path or operation-ID sorting.
        directories.sort_by_key(|record| record.path.components().len());
        for record in &directories {
            let parent = resolve_parent(&installer.root, &record.path)?;
            let leaf = CString::new(parent.leaf()).unwrap();
            match rustix::fs::mkdirat(parent.as_fd(), leaf.as_c_str(), Mode::from_raw_mode(0o700)) {
                Ok(()) | Err(rustix::io::Errno::EXIST) => {}
                Err(error) => return Err(failure(error)),
            }
            let fd = rustix::fs::openat(
                parent.as_fd(),
                leaf.as_c_str(),
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(failure)?;
            rustix::fs::fchmod(&fd, Mode::from_raw_mode(record.metadata.mode() | 0o700))
                .map_err(failure)?;
        }
        // Independent payloads install in staging-completion order.
        for (operation, file) in contents {
            match operation {
                Operation::UpsertFile { record, .. } => {
                    file.expect("validated during staging").install(
                        &installer.root,
                        &record.path,
                        record.metadata,
                    )?;
                }
                Operation::UpsertSymlink { record, .. } => installer.symlink(record)?,
                _ => unreachable!("partitioned above"),
            }
        }
        // Child installation changes parent mtimes; restore directory metadata last.
        for record in directories.into_iter().rev() {
            let parent = resolve_parent(&installer.root, &record.path)?;
            let leaf = CString::new(parent.leaf()).unwrap();
            let fd = rustix::fs::openat(
                parent.as_fd(),
                leaf.as_c_str(),
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(failure)?;
            set_file_metadata(&File::from(fd), record.metadata)?;
        }
        Ok(())
    }
}

struct Installer {
    root: RootHandle,
}

impl Installer {
    fn unlink(&self, path: &RelativePath, flags: AtFlags) -> Result<(), QuicSyncError> {
        let parent = resolve_parent(&self.root, path)?;
        let leaf = CString::new(parent.leaf()).unwrap();
        rustix::fs::unlinkat(parent.as_fd(), leaf.as_c_str(), flags).map_err(|error| {
            let local_path: PathBuf = path
                .components()
                .iter()
                .cloned()
                .map(std::ffi::OsString::from_vec)
                .collect();
            let hint = if error == rustix::io::Errno::NOTEMPTY {
                "; remaining children may be ignored or protected; they were not removed"
            } else {
                ""
            };
            failure(format!("remove {local_path:?}: {error}{hint}"))
                .with_context(ErrorContext::default().with_path(path.clone()))
        })
    }

    fn symlink(&self, record: IndexRecord) -> Result<(), QuicSyncError> {
        let target = CString::new(
            record
                .symlink_target
                .ok_or_else(|| failure("missing symlink target"))?,
        )
        .map_err(failure)?;
        let parent = resolve_parent(&self.root, &record.path)?;
        let leaf = CString::new(parent.leaf()).unwrap();
        match rustix::fs::unlinkat(parent.as_fd(), leaf.as_c_str(), AtFlags::empty()) {
            Ok(()) | Err(rustix::io::Errno::NOENT) => {}
            Err(error) => return Err(failure(error)),
        }
        rustix::fs::symlinkat(target.as_c_str(), parent.as_fd(), leaf.as_c_str())
            .map_err(failure)?;
        let nanos = record.metadata.mtime_ns();
        let times = Timestamps {
            last_access: Timespec {
                tv_sec: 0,
                tv_nsec: UTIME_OMIT,
            },
            last_modification: Timespec {
                tv_sec: nanos
                    .div_euclid(1_000_000_000)
                    .try_into()
                    .map_err(failure)?,
                tv_nsec: nanos
                    .rem_euclid(1_000_000_000)
                    .try_into()
                    .map_err(failure)?,
            },
        };
        rustix::fs::utimensat(
            parent.as_fd(),
            leaf.as_c_str(),
            &times,
            AtFlags::SYMLINK_NOFOLLOW,
        )
        .map_err(failure)
    }
}

fn failure(error: impl std::fmt::Display) -> QuicSyncError {
    QuicSyncError::new(
        ErrorCode::OperationFailed,
        None,
        format!("install: {error}"),
    )
}
