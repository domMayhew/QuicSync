use std::{fs, io::Cursor, sync::Arc};

use quicsync_core::{
    auth::{Authorizer, Direction, Identity, PeerGrant, PeerPin, client_tls, server_tls},
    error::ErrorCode,
};
use tempfile::tempdir;

use rustls::{ClientConnection, ServerConnection, pki_types::ServerName};

#[test]
fn identities_are_created_once_and_have_stable_public_key_fingerprints() {
    let directory = tempdir().unwrap();
    let first = Identity::load_or_create(directory.path()).unwrap();
    let second = Identity::load_or_create(directory.path()).unwrap();

    assert_eq!(first.fingerprint(), second.fingerprint());
    assert_eq!(first.fingerprint().to_string().len(), 95);
    assert_eq!(
        first.fingerprint().to_string().parse(),
        Ok(first.fingerprint())
    );
    assert_eq!(
        first
            .fingerprint()
            .to_string()
            .replace(':', "")
            .to_lowercase()
            .parse(),
        Ok(first.fingerprint())
    );
    assert!("00:11".parse::<quicsync_core::auth::Fingerprint>().is_err());
    assert_eq!(
        quicsync_core::auth::Fingerprint::from_certificate_der(first.certificate_der()).unwrap(),
        first.fingerprint()
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(directory.path().join("identity.key"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
}

#[test]
fn tls_is_mutual_pin_only_and_allows_early_notification() {
    let client = Identity::load_or_create(tempdir().unwrap().path()).unwrap();
    let server = Identity::load_or_create(tempdir().unwrap().path()).unwrap();

    let client_config = client_tls(&client, PeerPin::new(server.fingerprint())).unwrap();
    let server_config = server_tls(&server, [PeerPin::new(client.fingerprint())]).unwrap();

    assert!(client_config.enable_early_data);
    assert_eq!(server_config.max_early_data_size, u32::MAX);

    complete_handshake(
        client_config,
        server_config,
        "not-in-the-certificate.example",
    )
    .unwrap();
}

#[test]
fn hostname_or_a_different_certificate_cannot_substitute_for_the_pin() {
    let client = Identity::load_or_create(tempdir().unwrap().path()).unwrap();
    let server = Identity::load_or_create(tempdir().unwrap().path()).unwrap();
    let substitute = Identity::load_or_create(tempdir().unwrap().path()).unwrap();

    let client_config = client_tls(&client, PeerPin::new(substitute.fingerprint())).unwrap();
    let server_config = server_tls(&server, [PeerPin::new(client.fingerprint())]).unwrap();

    assert!(complete_handshake(client_config, server_config, "localhost").is_err());

    let client_config = client_tls(&client, PeerPin::new(server.fingerprint())).unwrap();
    let server_config = server_tls(&server, [PeerPin::new(substitute.fingerprint())]).unwrap();
    assert!(complete_handshake(client_config, server_config, "localhost").is_err());
}

#[cfg(unix)]
#[test]
fn identity_loading_rejects_a_symlinked_private_key() {
    use std::os::unix::fs::symlink;

    let directory = tempdir().unwrap();
    Identity::load_or_create(directory.path()).unwrap();
    let key = directory.path().join("identity.key");
    let moved_key = directory.path().join("moved.key");
    fs::rename(&key, &moved_key).unwrap();
    symlink(&moved_key, &key).unwrap();

    let error = Identity::load_or_create(directory.path()).err().unwrap();
    assert_eq!(error.code(), ErrorCode::InvalidConfiguration);
}

#[test]
fn only_the_pinned_peer_can_write_its_configured_root() {
    let alice = Identity::load_or_create(tempdir().unwrap().path()).unwrap();
    let mallory = Identity::load_or_create(tempdir().unwrap().path()).unwrap();
    let authorizer = Authorizer::new([PeerGrant::new(
        PeerPin::new(alice.fingerprint()),
        "website",
        Direction::SourceToDestination,
    )])
    .unwrap();

    let authorization = authorizer
        .authorize(
            alice.fingerprint(),
            "website",
            Direction::SourceToDestination,
        )
        .unwrap();
    assert_eq!(authorization.root_id(), "website");

    for (peer, root, direction) in [
        (
            mallory.fingerprint(),
            "website",
            Direction::SourceToDestination,
        ),
        (
            alice.fingerprint(),
            "private-root",
            Direction::SourceToDestination,
        ),
        (
            alice.fingerprint(),
            "website",
            Direction::DestinationToSource,
        ),
    ] {
        let error = authorizer.authorize(peer, root, direction).unwrap_err();
        assert_eq!(error.code(), ErrorCode::AuthorizationDenied);
        assert_eq!(
            error.peer_error().to_string(),
            "authorization_denied: request rejected"
        );
        assert!(!error.peer_error().to_string().contains(root));
    }
}

#[test]
fn malformed_or_ambiguous_grants_are_rejected() {
    let identity = Identity::load_or_create(tempdir().unwrap().path()).unwrap();
    let pin = PeerPin::new(identity.fingerprint());

    assert!(Authorizer::new([PeerGrant::new(pin, "", Direction::SourceToDestination)]).is_err());
    assert!(
        Authorizer::new([
            PeerGrant::new(pin, "root", Direction::SourceToDestination),
            PeerGrant::new(pin, "root", Direction::SourceToDestination),
        ])
        .is_err()
    );
}

fn complete_handshake(
    client_config: rustls::ClientConfig,
    server_config: rustls::ServerConfig,
    server_name: &'static str,
) -> Result<(), rustls::Error> {
    let mut client = ClientConnection::new(
        Arc::new(client_config),
        ServerName::try_from(server_name).unwrap(),
    )
    .unwrap();
    let mut server = ServerConnection::new(Arc::new(server_config)).unwrap();

    for _ in 0..8 {
        let mut client_bytes = Vec::new();
        client.write_tls(&mut client_bytes).unwrap();
        if !client_bytes.is_empty() {
            server.read_tls(&mut Cursor::new(client_bytes)).unwrap();
            server.process_new_packets()?;
        }

        let mut server_bytes = Vec::new();
        server.write_tls(&mut server_bytes).unwrap();
        if !server_bytes.is_empty() {
            client.read_tls(&mut Cursor::new(server_bytes)).unwrap();
            client.process_new_packets()?;
        }

        if !client.is_handshaking() && !server.is_handshaking() {
            return Ok(());
        }
    }

    panic!("TLS handshake did not finish");
}
