#![cfg(unix)]

use std::{
    fs::{self, OpenOptions},
    io::Write as _,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _},
    path::Path,
    time::Duration,
};

use quicsync_core::{
    auth::{Identity, PeerPin, client_tls, server_tls},
    config::{DEFAULT_LIMITS, load_destination, load_source},
    error::ErrorCode,
    transport::{
        CancellationToken,
        quic::{
            Completion, Connection, DestinationStreams, Listener, SourceStreams, TransportBounds,
            connect, connect_to, listen, listen_on,
        },
    },
};
use tempfile::{TempDir, tempdir};
use tokio::time::timeout;

const FRAME_BYTES: usize = 4096;
const INFLIGHT_BYTES: usize = 256 * 1024;
const PARALLEL_TRANSFERS: usize = 2;

fn bounds() -> TransportBounds {
    TransportBounds::new(FRAME_BYTES, PARALLEL_TRANSFERS, INFLIGHT_BYTES).unwrap()
}

fn loopback() -> SocketAddr {
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
}

/// A connected source and destination over loopback QUIC with test-sized bounds.
struct Pair {
    source: Connection,
    destination: Connection,
    cancel: CancellationToken,
    _listener: Listener,
    _directories: (TempDir, TempDir),
}

async fn connected_pair() -> Pair {
    connected_pair_with(bounds(), bounds()).await
}

async fn connected_pair_with(
    source_bounds: TransportBounds,
    destination_bounds: TransportBounds,
) -> Pair {
    let source_directory = tempdir().unwrap();
    let destination_directory = tempdir().unwrap();
    let source_identity = Identity::load_or_create(source_directory.path()).unwrap();
    let destination_identity = Identity::load_or_create(destination_directory.path()).unwrap();
    let cancel = CancellationToken::new();

    let listener = listen_on(
        loopback(),
        server_tls(
            &destination_identity,
            [PeerPin::new(source_identity.fingerprint())],
        )
        .unwrap(),
        destination_bounds,
        cancel.clone(),
    )
    .unwrap();
    let address = listener.local_address().unwrap();

    let client = client_tls(
        &source_identity,
        PeerPin::new(destination_identity.fingerprint()),
    )
    .unwrap();
    let accepting = tokio::spawn({
        let listener = listener.clone();
        async move { listener.accept().await }
    });
    let source = connect_to(address, client, source_bounds, cancel.clone())
        .await
        .unwrap();
    let destination = accepting.await.unwrap().unwrap();

    assert_eq!(
        source.peer_fingerprint().unwrap(),
        destination_identity.fingerprint()
    );
    assert_eq!(
        destination.peer_fingerprint().unwrap(),
        source_identity.fingerprint()
    );

    Pair {
        source,
        destination,
        cancel,
        _listener: listener,
        _directories: (source_directory, destination_directory),
    }
}

/// Opens both halves of a session and consumes the marker frame that starts it.
async fn session(pair: &Pair) -> (SourceStreams, DestinationStreams) {
    let mut source = pair.source.open_session().await.unwrap();
    source.control.send(b"start").await.unwrap();
    let mut destination = pair.destination.accept_session().await.unwrap();

    let mut buffer = [0; FRAME_BYTES];
    let read = destination
        .control
        .receive(&mut buffer)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buffer[..read], b"start");

    (source, destination)
}

#[test]
fn bounds_are_derived_from_local_configuration_limits() {
    let derived = TransportBounds::from_limits(&DEFAULT_LIMITS);

    assert_eq!(derived.max_frame_bytes(), DEFAULT_LIMITS.max_frame_bytes());
    assert_eq!(
        derived.max_parallel_transfers(),
        DEFAULT_LIMITS.max_parallel_transfers()
    );
    assert_eq!(
        derived.max_inflight_bytes(),
        DEFAULT_LIMITS.max_inflight_bytes()
    );
    assert_eq!(
        TransportBounds::new(0, 1, 1).unwrap_err().code(),
        ErrorCode::InvalidConfiguration
    );
}

#[tokio::test]
async fn a_pinned_peer_completes_a_control_round_trip() {
    let pair = connected_pair().await;

    let mut source = pair.source.open_session().await.unwrap();
    source.control.send(b"client-hello").await.unwrap();
    let mut destination = pair.destination.accept_session().await.unwrap();

    let mut buffer = [0; FRAME_BYTES];
    let read = destination
        .control
        .receive(&mut buffer)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buffer[..read], b"client-hello");

    destination.control.send(b"server-hello").await.unwrap();
    let read = source.control.receive(&mut buffer).await.unwrap().unwrap();
    assert_eq!(&buffer[..read], b"server-hello");
}

#[tokio::test]
async fn an_unpinned_peer_cannot_connect() {
    let destination_directory = tempdir().unwrap();
    let destination_identity = Identity::load_or_create(destination_directory.path()).unwrap();
    let expected = Identity::load_or_create(tempdir().unwrap().path()).unwrap();
    let unknown = Identity::load_or_create(tempdir().unwrap().path()).unwrap();
    let cancel = CancellationToken::new();

    let listener = listen_on(
        loopback(),
        server_tls(
            &destination_identity,
            [PeerPin::new(expected.fingerprint())],
        )
        .unwrap(),
        bounds(),
        cancel.clone(),
    )
    .unwrap();
    let address = listener.local_address().unwrap();
    tokio::spawn({
        let listener = listener.clone();
        async move { listener.accept().await }
    });

    // The destination rejects the client certificate after its own handshake completes, so the
    // rejection surfaces either at connect time or on the first control exchange.
    let error = match connect_to(
        address,
        client_tls(&unknown, PeerPin::new(destination_identity.fingerprint())).unwrap(),
        bounds(),
        cancel,
    )
    .await
    {
        Err(error) => error,
        Ok(connection) => {
            let mut streams = connection.open_session().await.unwrap();
            let _ = streams.control.send(b"client-hello").await;
            streams
                .control
                .receive(&mut [0; 64])
                .await
                .expect_err("an unpinned peer must not complete a session")
        }
    };

    assert_eq!(error.code(), ErrorCode::AuthenticationFailed);
}

#[tokio::test]
async fn frames_larger_than_the_local_limit_are_refused_before_transmission() {
    let pair = connected_pair().await;
    let mut source = pair.source.open_session().await.unwrap();

    let error = source
        .control
        .send(&vec![0; FRAME_BYTES + 1])
        .await
        .unwrap_err();

    assert_eq!(error.code(), ErrorCode::ResourceLimitExceeded);
}

#[tokio::test]
async fn the_destination_index_streams_in_bounded_chunks() {
    let total = 4 * 1024 * 1024;
    let pair = connected_pair().await;
    let (mut source, mut destination) = session(&pair).await;

    let writer = tokio::spawn(async move {
        let chunk = vec![7; FRAME_BYTES];
        let mut written = 0;
        while written < total {
            destination.index.send(&chunk).await.unwrap();
            written += chunk.len();
        }
        destination.index.finish().await.unwrap();
        destination
    });

    // A single small buffer receives the whole index: buffering never grows with it.
    let mut buffer = [0; 1024];
    let mut received = 0;
    while let Some(read) = source.destination_index.receive(&mut buffer).await.unwrap() {
        assert!(read <= buffer.len());
        assert!(buffer[..read].iter().all(|byte| *byte == 7));
        received += read;
    }

    assert_eq!(received, total);
    writer.await.unwrap();
}

#[tokio::test]
async fn control_stays_responsive_while_transfers_are_saturated() {
    let pair = connected_pair().await;
    let (mut source, mut destination) = session(&pair).await;

    // Saturate every permitted transfer with a peer that never reads them.
    let mut saturating = Vec::new();
    for _ in 0..PARALLEL_TRANSFERS {
        let mut stream = source.transfers.open().await.unwrap();
        saturating.push(tokio::spawn(async move {
            let chunk = vec![1; FRAME_BYTES];
            while stream.send(&chunk).await.is_ok() {}
        }));
    }
    assert_eq!(source.transfers.available_permits(), 0);

    // A further transfer must wait rather than allocate another stream.
    let blocked = tokio::spawn({
        let transfers = source.transfers.clone();
        async move { transfers.open().await }
    });
    tokio::time::sleep(Duration::from_millis(250)).await;
    assert!(!blocked.is_finished());

    let mut buffer = [0; FRAME_BYTES];
    for _ in 0..8 {
        timeout(Duration::from_secs(5), source.control.send(b"ping"))
            .await
            .expect("control send stalled behind transfers")
            .unwrap();
        let read = timeout(
            Duration::from_secs(5),
            destination.control.receive(&mut buffer),
        )
        .await
        .expect("control receive stalled behind transfers")
        .unwrap()
        .unwrap();
        assert_eq!(&buffer[..read], b"ping");

        timeout(Duration::from_secs(5), destination.control.send(b"pong"))
            .await
            .expect("control send stalled behind transfers")
            .unwrap();
        let read = timeout(Duration::from_secs(5), source.control.receive(&mut buffer))
            .await
            .expect("control receive stalled behind transfers")
            .unwrap()
            .unwrap();
        assert_eq!(&buffer[..read], b"pong");
    }

    pair.cancel.cancel();
    for task in saturating {
        task.await.unwrap();
    }
    assert_eq!(
        blocked.await.unwrap().unwrap_err().code(),
        ErrorCode::Cancelled
    );
}

#[tokio::test]
async fn a_released_transfer_permit_admits_the_next_transfer() {
    // The destination permits more streams than the source does, so only the source's own
    // parallelism bound can delay the third transfer.
    let pair = connected_pair_with(
        bounds(),
        TransportBounds::new(FRAME_BYTES, 8, INFLIGHT_BYTES).unwrap(),
    )
    .await;
    let (source, _destination) = session(&pair).await;

    let first = source.transfers.open().await.unwrap();
    let second = source.transfers.open().await.unwrap();
    assert_eq!(source.transfers.available_permits(), 0);

    let waiting = tokio::spawn({
        let transfers = source.transfers.clone();
        async move { transfers.open().await }
    });
    drop(first);

    let third = timeout(Duration::from_secs(5), waiting)
        .await
        .expect("a released permit must admit the waiting transfer")
        .unwrap();
    assert!(third.is_ok());
    drop(second);
}

#[tokio::test]
async fn transfer_streams_round_trip_between_peers() {
    let pair = connected_pair().await;
    let (source, destination) = session(&pair).await;

    let mut outgoing = source.transfers.open().await.unwrap();
    outgoing.send(b"file-request").await.unwrap();
    outgoing.finish().await.unwrap();

    let mut incoming = destination.transfers.accept().await.unwrap().unwrap();
    let mut buffer = [0; FRAME_BYTES];
    let read = incoming.receive(&mut buffer).await.unwrap().unwrap();
    assert_eq!(&buffer[..read], b"file-request");
    assert_eq!(incoming.receive(&mut buffer).await.unwrap(), None);
}

#[tokio::test]
async fn accepting_transfers_ends_when_the_source_closes_its_session() {
    let pair = connected_pair().await;
    let (source, destination) = session(&pair).await;

    drop(source);
    drop(pair.source);

    let accepted = timeout(Duration::from_secs(5), destination.transfers.accept())
        .await
        .expect("a closed session must end the accept loop")
        .unwrap();
    assert!(accepted.is_none());
}

#[tokio::test]
async fn cancellation_stops_producers_and_consumers_on_every_stream() {
    let pair = connected_pair().await;
    let (mut source, mut destination) = session(&pair).await;
    let mut transfer = source.transfers.open().await.unwrap();

    pair.cancel.cancel();

    let mut buffer = [0; FRAME_BYTES];
    assert_eq!(
        source
            .control
            .receive(&mut buffer)
            .await
            .unwrap_err()
            .code(),
        ErrorCode::Cancelled
    );
    assert_eq!(
        transfer.send(b"literal").await.unwrap_err().code(),
        ErrorCode::Cancelled
    );
    assert_eq!(
        source.transfers.open().await.unwrap_err().code(),
        ErrorCode::Cancelled
    );
    assert_eq!(
        destination.index.send(b"record").await.unwrap_err().code(),
        ErrorCode::Cancelled
    );
}

#[tokio::test]
async fn losing_the_connection_cancels_the_shared_token() {
    let pair = connected_pair().await;
    let source = pair.source.open_session().await.unwrap();

    drop(pair.destination);

    timeout(Duration::from_secs(10), pair.cancel.cancelled())
        .await
        .expect("connection loss must cancel every task sharing the session");
    assert!(source.control.completion().is_unknown());
}

#[tokio::test]
async fn a_clean_close_without_a_completion_acknowledgment_stays_indeterminate() {
    let pair = connected_pair().await;
    let mut source = pair.source.open_session().await.unwrap();
    source.control.send(b"commit-request").await.unwrap();

    assert_eq!(source.control.completion(), Completion::Unknown);
    let completion = source.close().await;

    assert_eq!(completion, Completion::Unknown);
    assert_eq!(
        completion.into_result().unwrap_err().code(),
        ErrorCode::CompletionUnknown
    );
}

#[tokio::test]
async fn an_observed_completion_acknowledgment_is_reported_as_complete() {
    let pair = connected_pair().await;
    let mut source = pair.source.open_session().await.unwrap();
    source.control.send(b"commit-request").await.unwrap();

    source.control.record_completion_ack();

    assert_eq!(source.control.completion(), Completion::Acknowledged);
    let completion = source.close().await;
    assert_eq!(completion, Completion::Acknowledged);
    completion.into_result().unwrap();
}

#[tokio::test]
async fn configured_peers_connect_through_loaded_configuration() {
    let source_root = tempdir().unwrap();
    let destination_root = tempdir().unwrap();
    let source_identity = Identity::load_or_create(&administrative(source_root.path())).unwrap();
    let destination_identity =
        Identity::load_or_create(&administrative(destination_root.path())).unwrap();
    let managed = destination_root.path().join("managed");
    fs::create_dir(&managed).unwrap();

    write_private(
        &administrative(destination_root.path()).join("destination.toml"),
        &format!(
            r#"
listen_address = "127.0.0.1:0"

[[roots]]
id = "website"
path = "managed"
authorized_peers = ["{}"]
"#,
            compact(&source_identity)
        ),
    );
    let destination_config = load_destination(destination_root.path()).unwrap();
    let cancel = CancellationToken::new();
    let listener = listen(&destination_config, &destination_identity, cancel.clone()).unwrap();
    let address = listener.local_address().unwrap();

    write_private(
        &administrative(source_root.path()).join("source.toml"),
        &format!(
            r#"
root_id = "website"
destination = "{address}"
peer_pin = "{}"
"#,
            compact(&destination_identity)
        ),
    );
    let source_config = load_source(source_root.path()).unwrap();

    let accepting = tokio::spawn(async move { listener.accept().await });
    let source = connect(&source_config, &source_identity, cancel)
        .await
        .unwrap();
    let destination = accepting.await.unwrap().unwrap();

    assert_eq!(
        destination.peer_fingerprint().unwrap(),
        source_identity.fingerprint()
    );
    assert_eq!(
        source.peer_fingerprint().unwrap(),
        destination_identity.fingerprint()
    );
}

fn administrative(root: &Path) -> std::path::PathBuf {
    let admin = root.join(".quicsync");
    if !admin.exists() {
        fs::create_dir(&admin).unwrap();
        fs::set_permissions(&admin, fs::Permissions::from_mode(0o700)).unwrap();
    }
    admin
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

fn compact(identity: &Identity) -> String {
    identity
        .fingerprint()
        .to_string()
        .replace(':', "")
        .to_lowercase()
}
