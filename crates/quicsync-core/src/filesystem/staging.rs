//! Temporary-file reconstruction and per-file installation, without recovery state.

use std::{
    ffi::CString,
    fs::{File, FileTimes},
    io::{self, Read},
    os::fd::OwnedFd,
    sync::Arc,
    time::{Duration, UNIX_EPOCH},
};

use ring::rand::{SecureRandom, SystemRandom};
use rustix::fs::{AtFlags, Mode, OFlags};

use crate::{
    error::{ErrorCode, QuicSyncError},
    filesystem::paths::{RootHandle, resolve_parent},
    types::{EntryKind, EntryMetadata, RelativePath},
};

/// One shared descriptor for every pending file in a sync.
pub struct StagingArea {
    root: Arc<RootHandle>,
    directory: Arc<OwnedFd>,
}
impl StagingArea {
    pub fn new(root: Arc<RootHandle>) -> Result<Self, QuicSyncError> {
        let directory = Arc::new(staging_directory(&root)?);
        Ok(Self { root, directory })
    }
    pub fn root(&self) -> &RootHandle {
        &self.root
    }
    pub fn receive(&self, content: impl Read) -> Result<StagedFile, QuicSyncError> {
        StagedFile::receive_in(self.directory.clone(), content)
    }
}

/// A completely written temporary file. Drop removes it unless installation succeeds.
pub struct StagedFile {
    directory: Arc<OwnedFd>,
    name: CString,
    installed: bool,
}

impl StagedFile {
    /// Copy an incremental reconstruction reader into a private temporary file.
    ///
    /// Call from a blocking worker. The reader must report an interrupted transfer
    /// as an error rather than EOF. No expected size or digest is required.
    pub fn receive(root: &RootHandle, content: impl Read) -> Result<Self, QuicSyncError> {
        Self::receive_in(Arc::new(staging_directory(root)?), content)
    }

    fn receive_in(directory: Arc<OwnedFd>, mut content: impl Read) -> Result<Self, QuicSyncError> {
        let mut random = [0_u8; 16];
        SystemRandom::new()
            .fill(&mut random)
            .map_err(|_| failure("random filename unavailable"))?;
        let name = CString::new(format!(
            "incoming-{}",
            random
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        ))
        .unwrap();
        let descriptor = rustix::fs::openat(
            &*directory,
            name.as_c_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )
        .map_err(failure)?;
        let staged = Self {
            directory,
            name,
            installed: false,
        };
        let mut file = File::from(descriptor);
        io::copy(&mut content, &mut file).map_err(failure)?;
        Ok(staged)
    }

    /// Install one completed file through the confined destination parent descriptor.
    pub fn install(
        mut self,
        root: &RootHandle,
        path: &RelativePath,
        metadata: EntryMetadata,
    ) -> Result<(), QuicSyncError> {
        if metadata.kind() != EntryKind::RegularFile {
            return Err(failure(
                "regular-file staging requires regular-file metadata",
            ));
        }
        let descriptor = rustix::fs::openat(
            &*self.directory,
            self.name.as_c_str(),
            OFlags::WRONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(failure)?;
        set_file_metadata(&File::from(descriptor), metadata)?;
        let parent = resolve_parent(root, path)?;
        let leaf = CString::new(parent.leaf()).unwrap();
        rustix::fs::renameat(
            &*self.directory,
            self.name.as_c_str(),
            parent.as_fd(),
            leaf.as_c_str(),
        )
        .map_err(failure)?;
        self.installed = true;
        Ok(())
    }
}

impl Drop for StagedFile {
    fn drop(&mut self) {
        if !self.installed {
            let _ = rustix::fs::unlinkat(&*self.directory, self.name.as_c_str(), AtFlags::empty());
        }
    }
}

pub(crate) fn set_file_metadata(file: &File, metadata: EntryMetadata) -> Result<(), QuicSyncError> {
    rustix::fs::fchmod(file, Mode::from_raw_mode(metadata.mode())).map_err(failure)?;
    let nanos = metadata.mtime_ns();
    let magnitude = nanos.unsigned_abs();
    let seconds = u64::try_from(magnitude / 1_000_000_000).map_err(failure)?;
    let offset = Duration::new(seconds, (magnitude % 1_000_000_000) as u32);
    let modified = if nanos < 0 {
        UNIX_EPOCH.checked_sub(offset)
    } else {
        UNIX_EPOCH.checked_add(offset)
    }
    .ok_or_else(|| failure("mtime is outside supported range"))?;
    file.set_times(FileTimes::new().set_modified(modified))
        .map_err(failure)
}

fn staging_directory(root: &RootHandle) -> Result<OwnedFd, QuicSyncError> {
    match rustix::fs::mkdirat(root.as_fd(), ".quicsync", Mode::from_raw_mode(0o700)) {
        Ok(()) | Err(rustix::io::Errno::EXIST) => {}
        Err(error) => return Err(failure(error)),
    }
    let fd = rustix::fs::openat(
        root.as_fd(),
        ".quicsync",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(failure)?;
    let stat = rustix::fs::fstat(&fd).map_err(failure)?;
    if stat.st_uid != rustix::process::geteuid().as_raw() || stat.st_mode & 0o077 != 0 {
        return Err(failure(
            "staging directory must be private and owned by the current user",
        ));
    }
    Ok(fd)
}

fn failure(error: impl std::fmt::Display) -> QuicSyncError {
    QuicSyncError::new(ErrorCode::Io, None, format!("staging: {error}"))
}
