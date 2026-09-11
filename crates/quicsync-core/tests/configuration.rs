#![cfg(unix)]

use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt, symlink},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use quicsync_core::{
    config::{DEFAULT_LIMITS, load_destination, load_source},
    error::ErrorCode,
};

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

struct TestDir(PathBuf);

impl TestDir {
    fn new() -> Self {
        let sequence = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("quicsync-config-{}-{sequence}", std::process::id()));
        fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn write_private(path: &Path, contents: &str) {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(contents.as_bytes()).unwrap();
}

fn source_setup(config: &str) -> TestDir {
    let root = TestDir::new();
    let admin = root.path().join(".quicsync");
    fs::create_dir(&admin).unwrap();
    fs::set_permissions(&admin, fs::Permissions::from_mode(0o700)).unwrap();
    write_private(&admin.join("identity.key"), "secret");
    write_private(&admin.join("source.toml"), config);
    root
}

fn destination_setup(config: impl FnOnce(&Path, &Path) -> String) -> (TestDir, PathBuf, PathBuf) {
    let setup = TestDir::new();
    let first = setup.path().join("first");
    let second = setup.path().join("second");
    fs::create_dir(&first).unwrap();
    fs::create_dir(&second).unwrap();
    let admin = setup.path().join(".quicsync");
    fs::create_dir(&admin).unwrap();
    fs::set_permissions(&admin, fs::Permissions::from_mode(0o700)).unwrap();
    write_private(&admin.join("identity.key"), "secret");
    write_private(&admin.join("destination.toml"), &config(&first, &second));
    (setup, first, second)
}

const PIN_A: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const PIN_B: &str = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

#[test]
fn loads_and_types_a_complete_source_configuration() {
    let root = source_setup(&format!(
        r#"
root_id = "website"
destination = "127.0.0.1:4433"
peer_pin = "{PIN_A}"
global_exclusions = ["target/", "*.local"]

[limits]
max_frame_bytes = 1048576
max_path_bytes = 2048
max_components = 64
max_parallel_hashes = 2
max_parallel_transfers = 3
max_inflight_bytes = 8388608
"#
    ));

    let config = load_source(root.path()).unwrap();

    assert_eq!(config.root_id().as_str(), "website");
    assert_eq!(config.destination().to_string(), "127.0.0.1:4433");
    assert_eq!(config.peer_pin().as_bytes()[0], 0x01);
    assert_eq!(config.global_exclusions(), ["target/", "*.local"]);
    assert_eq!(config.limits().max_parallel_transfers(), 3);
    assert!(config.root().metadata().unwrap().is_dir());
}

#[test]
fn defaults_source_limits_locally() {
    let root = source_setup(&format!(
        "root_id = \"website\"\ndestination = \"127.0.0.1:4433\"\npeer_pin = \"{PIN_A}\"\n"
    ));

    assert_eq!(*load_source(root.path()).unwrap().limits(), DEFAULT_LIMITS);
}

#[test]
fn rejects_a_source_root_that_is_a_symlink() {
    let real = source_setup(&format!(
        "root_id = \"website\"\ndestination = \"127.0.0.1:4433\"\npeer_pin = \"{PIN_A}\"\n"
    ));
    let holder = TestDir::new();
    let link = holder.path().join("root");
    symlink(real.path(), &link).unwrap();

    let error = load_source(&link).unwrap_err();

    assert_eq!(error.code(), ErrorCode::InvalidConfiguration);
}

#[test]
fn rejects_insecure_administrative_permissions() {
    let root = source_setup(&format!(
        "root_id = \"website\"\ndestination = \"127.0.0.1:4433\"\npeer_pin = \"{PIN_A}\"\n"
    ));
    fs::set_permissions(
        root.path().join(".quicsync"),
        fs::Permissions::from_mode(0o770),
    )
    .unwrap();

    let error = load_source(root.path()).unwrap_err();

    assert_eq!(error.code(), ErrorCode::InvalidConfiguration);
}

#[test]
fn rejects_a_private_key_without_mode_0600() {
    let root = source_setup(&format!(
        "root_id = \"website\"\ndestination = \"127.0.0.1:4433\"\npeer_pin = \"{PIN_A}\"\n"
    ));
    fs::set_permissions(
        root.path().join(".quicsync/identity.key"),
        fs::Permissions::from_mode(0o640),
    )
    .unwrap();

    let error = load_source(root.path()).unwrap_err();

    assert_eq!(error.code(), ErrorCode::InvalidConfiguration);
}

#[test]
fn rejects_zero_and_unreasonably_large_limits() {
    for limit in ["max_parallel_transfers = 0", "max_frame_bytes = 1073741825"] {
        let root = source_setup(&format!(
            "root_id = \"website\"\ndestination = \"127.0.0.1:4433\"\npeer_pin = \"{PIN_A}\"\n[limits]\n{limit}\n"
        ));
        assert_eq!(
            load_source(root.path()).unwrap_err().code(),
            ErrorCode::InvalidConfiguration
        );
    }
}

#[test]
fn loads_destination_roots_and_authorization() {
    let (setup, _, _) = destination_setup(|first, second| {
        format!(
            r#"
listen_address = "127.0.0.1:4433"

[[roots]]
id = "website"
path = "{}"
authorized_peers = ["{PIN_A}"]

[[roots]]
id = "docs"
path = "{}"
authorized_peers = ["{PIN_B}"]
"#,
            first.display(),
            second.display()
        )
    });

    let config = load_destination(setup.path()).unwrap();

    assert_eq!(config.listen_address().to_string(), "127.0.0.1:4433");
    assert_eq!(config.roots().len(), 2);
    assert!(config.authorize(config.roots()[0].authorized_peers()[0], "website"));
    assert!(!config.authorize(config.roots()[1].authorized_peers()[0], "website"));
}

#[test]
fn rejects_duplicate_destination_root_ids_before_returning_configuration() {
    let (setup, _, _) = destination_setup(|first, second| {
        format!(
            r#"
listen_address = "127.0.0.1:4433"
[[roots]]
id = "same"
path = "{}"
authorized_peers = ["{PIN_A}"]
[[roots]]
id = "same"
path = "{}"
authorized_peers = ["{PIN_B}"]
"#,
            first.display(),
            second.display()
        )
    });

    let error = load_destination(setup.path()).unwrap_err();

    assert_eq!(error.code(), ErrorCode::InvalidConfiguration);
}

#[test]
fn rejects_symlink_destination_roots() {
    let setup = TestDir::new();
    let real = setup.path().join("real");
    let link = setup.path().join("linked");
    fs::create_dir(&real).unwrap();
    symlink(&real, &link).unwrap();
    let admin = setup.path().join(".quicsync");
    fs::create_dir(&admin).unwrap();
    fs::set_permissions(&admin, fs::Permissions::from_mode(0o700)).unwrap();
    write_private(&admin.join("identity.key"), "secret");
    write_private(
        &admin.join("destination.toml"),
        &format!(
            "listen_address = \"127.0.0.1:4433\"\n[[roots]]\nid = \"linked\"\npath = \"{}\"\nauthorized_peers = [\"{PIN_A}\"]\n",
            link.display()
        ),
    );

    assert_eq!(
        load_destination(setup.path()).unwrap_err().code(),
        ErrorCode::InvalidConfiguration
    );
}
