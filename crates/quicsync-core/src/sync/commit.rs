//! Incremental filesystem installation in canonical discovery order.

use crate::{
    error::{ErrorCode, QuicSyncError},
    filesystem::{
        paths::{RootHandle, resolve_parent},
        staging::{StagedFile, set_file_metadata},
    },
    protocol::messages::Operation,
    types::{EntryKind, EntryMetadata, IndexRecord, RelativePath},
};
use rustix::fs::{AtFlags, Mode, OFlags, Timespec, Timestamps, UTIME_OMIT};
use std::{ffi::CString, fs::File};

/// Holds only active directory dependencies; ordinary files install immediately.
///
/// Run on a blocking worker. Transfer scheduling is independent: supply a staged
/// file with each UpsertFile once its transfer finishes. The operation input must
/// retain planner order, even when transfers finish out of order.
pub struct Committer {
    root: RootHandle,
    pending: Vec<Directory>,
    previous: Option<RelativePath>,
}

struct Directory {
    path: RelativePath,
    actions: Vec<Action>,
}
enum Action {
    Delete,
    Metadata(EntryMetadata),
    File(StagedFile, EntryMetadata),
    Symlink(IndexRecord),
}

impl Committer {
    pub fn new(root: RootHandle) -> Self {
        Self {
            root,
            pending: Vec::new(),
            previous: None,
        }
    }

    pub fn apply(
        &mut self,
        operation: Operation,
        file: Option<StagedFile>,
    ) -> Result<(), QuicSyncError> {
        let path = operation.path().clone();
        if self
            .previous
            .as_ref()
            .is_some_and(|previous| previous > &path)
        {
            return Err(failure("operations are not in canonical discovery order"));
        }
        if matches!(&operation, Operation::UpsertFile { .. }) != file.is_some() {
            return Err(failure("only file upserts require a staged file"));
        }
        while self
            .pending
            .last()
            .is_some_and(|directory| !path.components().starts_with(directory.path.components()))
        {
            self.finish_directory()?;
        }
        self.previous = Some(path.clone());
        match operation {
            Operation::Delete {
                expected_kind: EntryKind::Directory,
                ..
            } => {
                self.defer(path, Action::Delete);
            }
            Operation::Delete { .. } => self.unlink(&path, AtFlags::empty())?,
            Operation::UpsertDirectory { record, .. } => {
                let parent = resolve_parent(&self.root, &path)?;
                let leaf = CString::new(parent.leaf()).unwrap();
                match rustix::fs::mkdirat(
                    parent.as_fd(),
                    leaf.as_c_str(),
                    Mode::from_raw_mode(0o700),
                ) {
                    Ok(()) | Err(rustix::io::Errno::EXIST) => {}
                    Err(error) => return Err(failure(error)),
                }
                // Open without following links and keep the directory writable while adding children.
                let fd = rustix::fs::openat(
                    parent.as_fd(),
                    leaf.as_c_str(),
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map_err(failure)?;
                rustix::fs::fchmod(&fd, Mode::from_raw_mode(record.metadata.mode() | 0o700))
                    .map_err(failure)?;
                self.defer(path, Action::Metadata(record.metadata));
            }
            Operation::UpsertFile { record, .. } => {
                let file = file.expect("checked above");
                if self.replacing_directory(&path) {
                    self.defer(path, Action::File(file, record.metadata));
                } else {
                    file.install(&self.root, &path, record.metadata)?;
                }
            }
            Operation::UpsertSymlink { record, .. } => {
                if self.replacing_directory(&path) {
                    self.defer(path, Action::Symlink(record));
                } else {
                    self.symlink(record)?;
                }
            }
        }
        Ok(())
    }

    /// Called only after PlanEnd and successful completion of all supplied transfers.
    pub fn finish(mut self) -> Result<(), QuicSyncError> {
        while !self.pending.is_empty() {
            self.finish_directory()?;
        }
        Ok(())
    }

    fn replacing_directory(&self, path: &RelativePath) -> bool {
        self.pending.last().is_some_and(|directory| {
            &directory.path == path
                && directory
                    .actions
                    .iter()
                    .any(|action| matches!(action, Action::Delete))
        })
    }

    fn defer(&mut self, path: RelativePath, action: Action) {
        if let Some(directory) = self.pending.last_mut() {
            if directory.path == path {
                directory.actions.push(action);
                return;
            }
        }
        self.pending.push(Directory {
            path,
            actions: vec![action],
        });
    }

    fn finish_directory(&mut self) -> Result<(), QuicSyncError> {
        let directory = self.pending.pop().expect("checked by caller");
        for action in directory.actions {
            match action {
                Action::Delete => self.unlink(&directory.path, AtFlags::REMOVEDIR)?,
                Action::File(file, metadata) => {
                    file.install(&self.root, &directory.path, metadata)?
                }
                Action::Symlink(record) => self.symlink(record)?,
                Action::Metadata(metadata) => {
                    let parent = resolve_parent(&self.root, &directory.path)?;
                    let leaf = CString::new(parent.leaf()).unwrap();
                    let fd = rustix::fs::openat(
                        parent.as_fd(),
                        leaf.as_c_str(),
                        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                        Mode::empty(),
                    )
                    .map_err(failure)?;
                    set_file_metadata(&File::from(fd), metadata)?;
                }
            }
        }
        Ok(())
    }

    fn unlink(&self, path: &RelativePath, flags: AtFlags) -> Result<(), QuicSyncError> {
        let parent = resolve_parent(&self.root, path)?;
        let leaf = CString::new(parent.leaf()).unwrap();
        rustix::fs::unlinkat(parent.as_fd(), leaf.as_c_str(), flags).map_err(failure)
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
