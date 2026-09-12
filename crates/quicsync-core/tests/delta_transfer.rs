#![cfg(unix)]
use quicsync_core::{
    auth::{Identity, PeerPin, client_tls, server_tls},
    config::{DEFAULT_LIMITS, Limits},
    filesystem::{paths::RootHandle, staging::StagingArea},
    protocol::{
        codec::{CodecLimits, Decoder, encode},
        messages::FileTransfer,
    },
    sync::transfer::{receive_file, send_file},
    transport::{
        CancellationToken,
        quic::{DestinationStreams, SourceStreams, connect_to, listen_on},
    },
    types::{EntryKind, EntryMetadata, OperationId, RelativePath},
};
use std::{
    fs,
    io::{Cursor, Read},
    sync::Arc,
    time::Duration,
};
use tempfile::TempDir;

async fn pair() -> (SourceStreams, DestinationStreams) {
    let a = TempDir::new().unwrap();
    let b = TempDir::new().unwrap();
    let ai = Identity::load_or_create(a.path()).unwrap();
    let bi = Identity::load_or_create(b.path()).unwrap();
    let bounds = quicsync_core::transport::quic::TransportBounds::from_limits(&DEFAULT_LIMITS);
    let listener = listen_on(
        "127.0.0.1:0".parse().unwrap(),
        server_tls(&bi, [PeerPin::new(ai.fingerprint())]).unwrap(),
        bounds,
        CancellationToken::new(),
    )
    .unwrap();
    let (source, destination) = tokio::join!(
        connect_to(
            listener.local_address().unwrap(),
            client_tls(&ai, PeerPin::new(bi.fingerprint())).unwrap(),
            bounds,
            CancellationToken::new()
        ),
        listener.accept(),
    );
    let source = source.unwrap();
    let destination = destination.unwrap();
    let mut a = source.open_session().await.unwrap();
    a.control.send(b"start").await.unwrap();
    let mut b = destination.accept_session().await.unwrap();
    b.control.receive(&mut [0; 64]).await.unwrap();
    (a, b)
}

#[tokio::test]
async fn real_quic_delta_transfers_reconstruct_changed_empty_and_new_files() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let (source, destination) = pair().await;
        let input = TempDir::new().unwrap();
        let output = TempDir::new().unwrap();
        let root = Arc::new(RootHandle::open(output.path()).unwrap());
        let basis = (0..2_000_000).map(|n| (n % 251) as u8).collect::<Vec<_>>();
        let mut changed = basis.clone();
        changed.splice(8000..8010, b"inserted text here".iter().copied());
        for (old, new) in [
            (Some(basis), changed),
            (Some(vec![42; 32]), Vec::new()),
            (None, vec![7; 200_000]),
            (None, Vec::new()),
        ] {
            fs::write(input.path().join("file"), &new).unwrap();
            let update = old.is_some();
            let original = old.clone();
            if let Some(old) = old {
                fs::write(output.path().join("file"), old).unwrap();
            } else {
                let _ = fs::remove_file(output.path().join("file"));
            }
            let source_root = Arc::new(RootHandle::open(input.path()).unwrap());
            let path = RelativePath::new(vec![b"file".to_vec()]).unwrap();
            let sending = async {
                send_file(
                    source.transfers.accept().await.unwrap().unwrap(),
                    source_root,
                    &DEFAULT_LIMITS,
                )
                .await
            };
            let receiving = async {
                receive_file(
                    destination.transfers.open().await.unwrap(),
                    Arc::new(StagingArea::new(root.clone()).unwrap()),
                    OperationId::new(1),
                    path.clone(),
                    update,
                    &DEFAULT_LIMITS,
                )
                .await
            };
            let (sent, received) = tokio::join!(sending, receiving);
            sent.unwrap();
            let received = received.unwrap();
            assert_eq!(received.path, path);
            assert_eq!(fs::read(output.path().join("file")).ok(), original);
            received
                .file
                .install(
                    &root,
                    &path,
                    EntryMetadata::new(EntryKind::RegularFile, 0o644, 0, new.len() as u64),
                )
                .unwrap();
            assert_eq!(fs::read(output.path().join("file")).unwrap(), new);
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn clean_transport_eof_without_delta_end_does_not_accept_a_file() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let (source, destination) = pair().await;
        let output = TempDir::new().unwrap();
        let root = Arc::new(RootHandle::open(output.path()).unwrap());
        fs::write(output.path().join("file"), b"basis").unwrap();
        let sender = async {
            let mut wire = source.transfers.accept().await.unwrap().unwrap();
            let codec = CodecLimits::from(&Limits::default());
            let mut decoder = Decoder::<FileTransfer>::new(codec);
            let mut buffer = [0; 8192];
            let mut signature = Vec::new();
            'signature: loop {
                let n = wire.receive(&mut buffer).await.unwrap().unwrap();
                for message in decoder.push(&buffer[..n]).unwrap() {
                    match message {
                        FileTransfer::UpdateRequest { .. } => {}
                        FileTransfer::Signature(bytes) => signature.extend(bytes),
                        FileTransfer::SignatureEnd => break 'signature,
                        _ => panic!("unexpected message"),
                    }
                }
            }
            let mut delta =
                librsync::Delta::new(b"content".as_slice(), &mut Cursor::new(signature)).unwrap();
            let mut bytes = Vec::new();
            delta.read_to_end(&mut bytes).unwrap();
            wire.send(&encode(&FileTransfer::Delta(bytes), &codec).unwrap())
                .await
                .unwrap();
            wire.finish().await.unwrap();
            // Keep the stream alive long enough for the peer to read the clean EOF.
            let _ = wire.receive(&mut buffer).await;
        };
        let receiver = async {
            let wire = destination.transfers.open().await.unwrap();
            assert!(
                receive_file(
                    wire,
                    Arc::new(StagingArea::new(root.clone()).unwrap()),
                    OperationId::new(1),
                    RelativePath::new(vec![b"file".to_vec()]).unwrap(),
                    true,
                    &DEFAULT_LIMITS
                )
                .await
                .is_err()
            );
        };
        tokio::join!(sender, receiver);
        assert_eq!(fs::read(output.path().join("file")).unwrap(), b"basis");
    })
    .await
    .unwrap();
}
