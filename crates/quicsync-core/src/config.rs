//! Validated source and destination configuration.

use std::{
    collections::HashSet,
    fs::{self, File, Metadata, OpenOptions},
    io::Read,
    net::SocketAddr,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

use serde::Deserialize;

use crate::error::{ErrorCode, QuicSyncError};

const ADMIN_DIRECTORY: &str = ".quicsync";
const PRIVATE_KEY: &str = "identity.key";
const SOURCE_CONFIG: &str = "source.toml";
const DESTINATION_CONFIG: &str = "destination.toml";

const MAX_FRAME_BYTES: usize = 1024 * 1024 * 1024;
const MAX_PATH_BYTES: usize = 1024 * 1024;
const MAX_COMPONENTS: usize = 4096;
const MAX_PARALLEL_WORK: usize = 1024;
const MAX_INFLIGHT_BYTES: usize = 16 * 1024 * 1024 * 1024;

/// Locally enforced resource limits. These values are never raised by peer input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    max_frame_bytes: usize,
    max_path_bytes: usize,
    max_components: usize,
    max_parallel_hashes: usize,
    max_parallel_transfers: usize,
    max_inflight_bytes: usize,
}

pub const DEFAULT_LIMITS: Limits = Limits {
    max_frame_bytes: 16 * 1024 * 1024,
    max_path_bytes: 16 * 1024,
    max_components: 256,
    max_parallel_hashes: 4,
    max_parallel_transfers: 4,
    max_inflight_bytes: 64 * 1024 * 1024,
};

impl Default for Limits {
    fn default() -> Self {
        DEFAULT_LIMITS
    }
}

impl Limits {
    pub const fn max_frame_bytes(&self) -> usize {
        self.max_frame_bytes
    }

    pub const fn max_path_bytes(&self) -> usize {
        self.max_path_bytes
    }

    pub const fn max_components(&self) -> usize {
        self.max_components
    }

    pub const fn max_parallel_hashes(&self) -> usize {
        self.max_parallel_hashes
    }

    pub const fn max_parallel_transfers(&self) -> usize {
        self.max_parallel_transfers
    }

    pub const fn max_inflight_bytes(&self) -> usize {
        self.max_inflight_bytes
    }

    fn validate(self) -> ConfigResult<Self> {
        validate_limit("max_frame_bytes", self.max_frame_bytes, MAX_FRAME_BYTES)?;
        validate_limit("max_path_bytes", self.max_path_bytes, MAX_PATH_BYTES)?;
        validate_limit("max_components", self.max_components, MAX_COMPONENTS)?;
        validate_limit(
            "max_parallel_hashes",
            self.max_parallel_hashes,
            MAX_PARALLEL_WORK,
        )?;
        validate_limit(
            "max_parallel_transfers",
            self.max_parallel_transfers,
            MAX_PARALLEL_WORK,
        )?;
        validate_limit(
            "max_inflight_bytes",
            self.max_inflight_bytes,
            MAX_INFLIGHT_BYTES,
        )?;
        if self.max_path_bytes > self.max_frame_bytes {
            return Err(invalid("max_path_bytes cannot exceed max_frame_bytes"));
        }
        Ok(self)
    }
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawLimits {
    max_frame_bytes: Option<usize>,
    max_path_bytes: Option<usize>,
    max_components: Option<usize>,
    max_parallel_hashes: Option<usize>,
    max_parallel_transfers: Option<usize>,
    max_inflight_bytes: Option<usize>,
}

impl RawLimits {
    fn resolve(self) -> ConfigResult<Limits> {
        Limits {
            max_frame_bytes: self
                .max_frame_bytes
                .unwrap_or(DEFAULT_LIMITS.max_frame_bytes),
            max_path_bytes: self.max_path_bytes.unwrap_or(DEFAULT_LIMITS.max_path_bytes),
            max_components: self.max_components.unwrap_or(DEFAULT_LIMITS.max_components),
            max_parallel_hashes: self
                .max_parallel_hashes
                .unwrap_or(DEFAULT_LIMITS.max_parallel_hashes),
            max_parallel_transfers: self
                .max_parallel_transfers
                .unwrap_or(DEFAULT_LIMITS.max_parallel_transfers),
            max_inflight_bytes: self
                .max_inflight_bytes
                .unwrap_or(DEFAULT_LIMITS.max_inflight_bytes),
        }
        .validate()
    }
}

/// A validated, protocol-safe root nickname.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct RootId(String);

impl RootId {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn parse(value: String) -> ConfigResult<Self> {
        if value.is_empty()
            || value.len() > 128
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            return Err(invalid(
                "root ID must be 1-128 ASCII letters, digits, '.', '-' or '_'",
            ));
        }
        Ok(Self(value))
    }
}

/// A SHA-256 public-key fingerprint configured out of band.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PeerPin([u8; 32]);

impl PeerPin {
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    fn parse(value: &str) -> ConfigResult<Self> {
        if value.len() != 64 {
            return Err(invalid("peer pin must contain 64 hexadecimal characters"));
        }
        let mut bytes = [0; 32];
        for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
            bytes[index] = (hex_digit(pair[0])? << 4) | hex_digit(pair[1])?;
        }
        Ok(Self(bytes))
    }
}

/// An opened directory that was verified not to be a symbolic link.
#[derive(Debug)]
pub struct ValidatedRoot {
    path: PathBuf,
    directory: File,
    device: u64,
    inode: u64,
}

impl ValidatedRoot {
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn metadata(&self) -> std::io::Result<Metadata> {
        self.directory.metadata()
    }

    pub const fn filesystem_identity(&self) -> (u64, u64) {
        (self.device, self.inode)
    }
}

#[derive(Debug)]
pub struct SourceConfig {
    root: ValidatedRoot,
    root_id: RootId,
    destination: SocketAddr,
    peer_pin: PeerPin,
    global_exclusions: Vec<String>,
    limits: Limits,
    private_key: PathBuf,
}

impl SourceConfig {
    pub const fn root(&self) -> &ValidatedRoot {
        &self.root
    }

    pub const fn root_id(&self) -> &RootId {
        &self.root_id
    }

    pub const fn destination(&self) -> SocketAddr {
        self.destination
    }

    pub const fn peer_pin(&self) -> PeerPin {
        self.peer_pin
    }

    pub fn global_exclusions(&self) -> &[String] {
        &self.global_exclusions
    }

    pub const fn limits(&self) -> &Limits {
        &self.limits
    }

    pub fn private_key(&self) -> &Path {
        &self.private_key
    }
}

#[derive(Debug)]
pub struct DestinationRoot {
    id: RootId,
    root: ValidatedRoot,
    authorized_peers: Vec<PeerPin>,
}

impl DestinationRoot {
    pub const fn id(&self) -> &RootId {
        &self.id
    }

    pub const fn root(&self) -> &ValidatedRoot {
        &self.root
    }

    pub fn authorized_peers(&self) -> &[PeerPin] {
        &self.authorized_peers
    }
}

#[derive(Debug)]
pub struct DestinationConfig {
    listen_address: SocketAddr,
    roots: Vec<DestinationRoot>,
    limits: Limits,
    private_key: PathBuf,
}

impl DestinationConfig {
    pub const fn listen_address(&self) -> SocketAddr {
        self.listen_address
    }

    pub fn roots(&self) -> &[DestinationRoot] {
        &self.roots
    }

    pub const fn limits(&self) -> &Limits {
        &self.limits
    }

    pub fn private_key(&self) -> &Path {
        &self.private_key
    }

    pub fn authorize(&self, peer: PeerPin, root_id: &str) -> bool {
        self.roots
            .iter()
            .any(|root| root.id.as_str() == root_id && root.authorized_peers.contains(&peer))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSourceConfig {
    root_id: String,
    destination: String,
    peer_pin: String,
    #[serde(default)]
    global_exclusions: Vec<String>,
    #[serde(default)]
    limits: RawLimits,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDestinationConfig {
    listen_address: String,
    roots: Vec<RawDestinationRoot>,
    #[serde(default)]
    limits: RawLimits,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDestinationRoot {
    id: String,
    path: PathBuf,
    authorized_peers: Vec<String>,
}

pub fn load_source(root: &Path) -> ConfigResult<SourceConfig> {
    let root = open_root(root)?;
    let admin = validate_admin_directory(root.path())?;
    let private_key = validate_private_key(&admin)?;
    let raw: RawSourceConfig = read_toml(&admin.join(SOURCE_CONFIG))?;
    let global_exclusions = validate_exclusions(raw.global_exclusions)?;

    Ok(SourceConfig {
        root,
        root_id: RootId::parse(raw.root_id)?,
        destination: parse_address("destination", &raw.destination)?,
        peer_pin: PeerPin::parse(&raw.peer_pin)?,
        global_exclusions,
        limits: raw.limits.resolve()?,
        private_key,
    })
}

pub fn load_destination(setup_root: &Path) -> ConfigResult<DestinationConfig> {
    let setup_root = open_root(setup_root)?;
    let admin = validate_admin_directory(setup_root.path())?;
    let private_key = validate_private_key(&admin)?;
    let raw: RawDestinationConfig = read_toml(&admin.join(DESTINATION_CONFIG))?;
    if raw.roots.is_empty() {
        return Err(invalid("at least one destination root is required"));
    }

    let mut ids = HashSet::new();
    let mut identities = HashSet::new();
    let mut roots = Vec::with_capacity(raw.roots.len());
    for raw_root in raw.roots {
        let id = RootId::parse(raw_root.id)?;
        if !ids.insert(id.clone()) {
            return Err(invalid(format!("duplicate root ID '{}'", id.as_str())));
        }
        if raw_root.authorized_peers.is_empty() {
            return Err(invalid(format!(
                "destination root '{}' has no authorized peers",
                id.as_str()
            )));
        }
        let path = if raw_root.path.is_absolute() {
            raw_root.path
        } else {
            setup_root.path().join(raw_root.path)
        };
        let root = open_root(&path)?;
        if !identities.insert(root.filesystem_identity()) {
            return Err(invalid(
                "the same destination root is configured more than once",
            ));
        }
        let mut authorized_peers = Vec::with_capacity(raw_root.authorized_peers.len());
        let mut pins = HashSet::new();
        for value in raw_root.authorized_peers {
            let pin = PeerPin::parse(&value)?;
            if !pins.insert(pin) {
                return Err(invalid(format!(
                    "destination root '{}' contains a duplicate peer pin",
                    id.as_str()
                )));
            }
            authorized_peers.push(pin);
        }
        roots.push(DestinationRoot {
            id,
            root,
            authorized_peers,
        });
    }

    Ok(DestinationConfig {
        listen_address: parse_address("listen_address", &raw.listen_address)?,
        roots,
        limits: raw.limits.resolve()?,
        private_key,
    })
}

type ConfigResult<T> = Result<T, QuicSyncError>;

fn invalid(diagnostic: impl Into<String>) -> QuicSyncError {
    QuicSyncError::new(ErrorCode::InvalidConfiguration, None, diagnostic)
}

fn validate_limit(name: &str, value: usize, maximum: usize) -> ConfigResult<()> {
    if value == 0 || value > maximum {
        return Err(invalid(format!("{name} must be between 1 and {maximum}")));
    }
    Ok(())
}

fn parse_address(name: &str, value: &str) -> ConfigResult<SocketAddr> {
    value
        .parse()
        .map_err(|error| invalid(format!("invalid {name}: {error}")))
}

fn validate_exclusions(values: Vec<String>) -> ConfigResult<Vec<String>> {
    let mut unique = HashSet::new();
    for value in &values {
        if value.is_empty() || value.contains('\0') {
            return Err(invalid(
                "global exclusions must be non-empty and contain no NUL",
            ));
        }
        if !unique.insert(value.clone()) {
            return Err(invalid("global exclusions must not contain duplicates"));
        }
    }
    Ok(values)
}

fn hex_digit(value: u8) -> ConfigResult<u8> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(invalid("peer pin contains a non-hexadecimal character")),
    }
}

fn open_root(path: &Path) -> ConfigResult<ValidatedRoot> {
    reject_symlink(path, "root")?;
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| invalid(format!("cannot open root '{}': {error}", path.display())))?;
    let metadata = directory
        .metadata()
        .map_err(|error| invalid(format!("cannot inspect root '{}': {error}", path.display())))?;
    if !metadata.is_dir() {
        return Err(invalid(format!(
            "root '{}' is not a directory",
            path.display()
        )));
    }
    Ok(ValidatedRoot {
        path: path.to_path_buf(),
        device: metadata.dev(),
        inode: metadata.ino(),
        directory,
    })
}

fn validate_admin_directory(root: &Path) -> ConfigResult<PathBuf> {
    let path = root.join(ADMIN_DIRECTORY);
    reject_symlink(&path, "administrative directory")?;
    let metadata = fs::metadata(&path).map_err(|error| {
        invalid(format!(
            "cannot inspect administrative directory '{}': {error}",
            path.display()
        ))
    })?;
    if !metadata.is_dir() {
        return Err(invalid(format!(
            "administrative path '{}' is not a directory",
            path.display()
        )));
    }
    validate_owner(&path, &metadata)?;
    if metadata.permissions().mode() & 0o022 != 0 {
        return Err(invalid(format!(
            "administrative directory '{}' is writable by another user",
            path.display()
        )));
    }
    Ok(path)
}

fn validate_private_key(admin: &Path) -> ConfigResult<PathBuf> {
    let path = admin.join(PRIVATE_KEY);
    let file = open_secure_file(&path)?;
    let metadata = file
        .metadata()
        .map_err(|error| invalid(format!("cannot inspect private key: {error}")))?;
    if metadata.permissions().mode() & 0o777 != 0o600 {
        return Err(invalid(format!(
            "private key '{}' must have mode 0600",
            path.display()
        )));
    }
    Ok(path)
}

fn read_toml<T: for<'de> Deserialize<'de>>(path: &Path) -> ConfigResult<T> {
    let mut file = open_secure_file(path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .map_err(|error| invalid(format!("cannot read '{}': {error}", path.display())))?;
    toml::from_str(&contents)
        .map_err(|error| invalid(format!("cannot parse '{}': {error}", path.display())))
}

fn open_secure_file(path: &Path) -> ConfigResult<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| invalid(format!("cannot open '{}': {error}", path.display())))?;
    let metadata = file
        .metadata()
        .map_err(|error| invalid(format!("cannot inspect '{}': {error}", path.display())))?;
    if !metadata.is_file() {
        return Err(invalid(format!(
            "'{}' is not a regular file",
            path.display()
        )));
    }
    validate_owner(path, &metadata)?;
    if metadata.permissions().mode() & 0o022 != 0 {
        return Err(invalid(format!(
            "'{}' is writable by another user",
            path.display()
        )));
    }
    Ok(file)
}

fn validate_owner(path: &Path, metadata: &Metadata) -> ConfigResult<()> {
    // SAFETY: `geteuid` has no preconditions and does not mutate process state.
    let effective_user = unsafe { libc::geteuid() };
    if metadata.uid() != effective_user {
        return Err(invalid(format!(
            "'{}' is not owned by the current user",
            path.display()
        )));
    }
    Ok(())
}

fn reject_symlink(path: &Path, description: &str) -> ConfigResult<()> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        invalid(format!(
            "cannot inspect {description} '{}': {error}",
            path.display()
        ))
    })?;
    if metadata.file_type().is_symlink() {
        return Err(invalid(format!(
            "{description} '{}' must not be a symbolic link",
            path.display()
        )));
    }
    Ok(())
}
