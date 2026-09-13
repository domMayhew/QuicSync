#![cfg(unix)]
use quicsync_core::{
    auth::{Identity, PeerPin, client_tls, server_tls},
    config::{DEFAULT_LIMITS, DestinationConfig, SourceConfig, load_destination, load_source},
    filesystem::{paths::RootHandle, scan::scan_root},
    protocol::{
        codec::{CodecLimits, Decoder, encode},
        messages::{Control, IndexMessage},
    },
    sync::{destination, source, transfer::send_file},
    transport::{
        CancellationToken,
        quic::{Connection, Listener, TransportBounds, connect_to, listen_on},
    },
    types::{EntryKind, EntryMetadata, IndexRecord, RelativePath},
};
use std::{
    fs,
    io::Write,
    os::unix::fs::{OpenOptionsExt, symlink},
    path::Path,
    sync::Arc,
    time::Duration,
};
use tempfile::TempDir;
use tokio::sync::mpsc;

fn hex(pin: quicsync_core::auth::Fingerprint) -> String {
    pin.as_bytes().iter().map(|b| format!("{b:02x}")).collect()
}

fn private(path: &Path, text: &str) {
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap()
        .write_all(text.as_bytes())
        .unwrap();
}

struct Pair {
    input: TempDir,
    output: TempDir,
    source: Connection,
    destination: Connection,
    source_config: SourceConfig,
    destination_config: DestinationConfig,
    _listener: Listener,
}

async fn pair() -> Pair {
    let input = TempDir::new().unwrap();
    let output = TempDir::new().unwrap();
    let a = Identity::load_or_create(&input.path().join(".quicsync")).unwrap();
    let b = Identity::load_or_create(&output.path().join(".quicsync")).unwrap();
    let bounds = TransportBounds::from_limits(&DEFAULT_LIMITS);
    let listener = listen_on(
        "127.0.0.1:0".parse().unwrap(),
        server_tls(&b, [PeerPin::new(a.fingerprint())]).unwrap(),
        bounds,
        CancellationToken::new(),
    )
    .unwrap();
    let address = listener.local_address().unwrap();
    private(
        &input.path().join(".quicsync/source.toml"),
        &format!(
            "root_id = \"repo\"\ndestination = \"{address}\"\npeer_pin = \"{}\"\n[limits]\nmax_parallel_transfers = 2\n",
            hex(b.fingerprint())
        ),
    );
    private(
        &output.path().join(".quicsync/destination.toml"),
        &format!(
            "listen_address = \"127.0.0.1:4433\"\n[limits]\nmax_parallel_transfers = 2\n[[roots]]\nid = \"repo\"\npath = \"{}\"\nauthorized_peers = [\"{}\"]\n",
            output.path().display(),
            hex(a.fingerprint())
        ),
    );
    let source_config = load_source(input.path()).unwrap();
    let destination_config = load_destination(output.path()).unwrap();
    let (source, destination) = tokio::join!(
        connect_to(
            address,
            client_tls(&a, PeerPin::new(b.fingerprint())).unwrap(),
            bounds,
            CancellationToken::new()
        ),
        listener.accept()
    );
    Pair {
        input,
        output,
        source: source.unwrap(),
        destination: destination.unwrap(),
        source_config,
        destination_config,
        _listener: listener,
    }
}

async fn index(root: &Path) -> Vec<IndexRecord> {
    let (tx, mut rx) =
        mpsc::channel::<Result<IndexMessage, quicsync_core::error::QuicSyncError>>(1);
    let collect = async {
        let mut result = Vec::new();
        while let Some(record) = rx.recv().await {
            if let IndexMessage::Record(record) = record.unwrap() {
                result.push(record);
            }
        }
        result
    };
    let (scan, records) = tokio::join!(scan_root(root, &[], &DEFAULT_LIMITS, tx), collect);
    scan.unwrap();
    records
}

#[tokio::test]
async fn real_source_and_destination_converge_with_parallel_requests() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let p = pair().await;
        for root in [p.input.path(), p.output.path()] {
            fs::write(root.join(".gitignore"), b"local\n").unwrap();
            fs::create_dir(root.join(".git")).unwrap();
            fs::write(root.join(".git/keep"), b"protected").unwrap();
        }
        fs::write(p.output.path().join("local"), b"preserve").unwrap();
        fs::create_dir_all(p.input.path().join("new/nested")).unwrap();
        fs::create_dir_all(p.output.path().join("stale/nested")).unwrap();
        fs::write(p.output.path().join("stale/nested/file"), b"delete").unwrap();
        fs::create_dir_all(p.output.path().join("a/child")).unwrap();
        fs::write(p.output.path().join("a/child/file"), b"old").unwrap();
        fs::write(p.input.path().join("a"), b"directory to file").unwrap();
        fs::write(p.output.path().join("b"), b"file to directory").unwrap();
        fs::create_dir(p.input.path().join("b")).unwrap();
        fs::write(p.input.path().join("b/file"), b"new").unwrap();
        symlink("b/file", p.input.path().join("link")).unwrap();
        for n in 0..12 {
            fs::write(
                p.input.path().join(format!("new/nested/{n:02}")),
                vec![n; 100_000],
            )
            .unwrap();
        }
        fs::write(p.output.path().join("update"), vec![7; 500_000]).unwrap();
        fs::write(
            p.input.path().join("update"),
            [vec![7; 400_000], b"changed".to_vec()].concat(),
        )
        .unwrap();
        let (a, b) = tokio::join!(
            source::run(&p.source, &p.source_config),
            destination::serve(&p.destination, &p.destination_config)
        );
        a.unwrap();
        b.unwrap();
        assert_eq!(index(p.input.path()).await, index(p.output.path()).await);
        assert_eq!(
            fs::read(p.output.path().join("local")).unwrap(),
            b"preserve"
        );
        assert_eq!(
            fs::read(p.output.path().join(".git/keep")).unwrap(),
            b"protected"
        );
    })
    .await
    .unwrap();
}

async fn gated_index(fail: bool) {
    let p = pair().await;
    fs::write(p.input.path().join("a"), b"new content").unwrap();
    fs::write(p.output.path().join("a"), b"old content").unwrap();
    fs::write(p.output.path().join("z"), b"delete after staging").unwrap();
    let mut streams = p.source.open_session().await.unwrap();
    let codec = CodecLimits::from(&DEFAULT_LIMITS);
    streams
        .control
        .send(
            &encode(
                &Control::StartSync {
                    root_id: "repo".into(),
                },
                &codec,
            )
            .unwrap(),
        )
        .await
        .unwrap();
    let server =
        tokio::spawn(
            async move { destination::serve(&p.destination, &p.destination_config).await },
        );
    let record = IndexRecord {
        path: RelativePath::new(vec![b"a".to_vec()]).unwrap(),
        metadata: EntryMetadata::new(EntryKind::RegularFile, 0o644, 0, 11),
        digest: Some(quicsync_core::types::Digest::from_bytes(
            *blake3::hash(b"new content").as_bytes(),
        )),
        symlink_target: None,
    };
    streams
        .index
        .send(&encode(&IndexMessage::Record(record), &codec).unwrap())
        .await
        .unwrap();
    // A complete payload/ack while index End is withheld proves transfer overlaps indexing/planning.
    let stream = streams.transfers.accept().await.unwrap().unwrap();
    send_file(
        stream,
        Arc::new(RootHandle::open(p.input.path()).unwrap()),
        &DEFAULT_LIMITS,
    )
    .await
    .unwrap();
    assert_eq!(fs::read(p.output.path().join("a")).unwrap(), b"old content");
    assert_eq!(
        fs::read(p.output.path().join("z")).unwrap(),
        b"delete after staging"
    );
    assert!(!server.is_finished());
    if fail {
        streams.index.finish().await.unwrap();
        assert!(server.await.unwrap().is_err());
        assert_eq!(fs::read(p.output.path().join("a")).unwrap(), b"old content");
        assert!(p.output.path().join("z").exists());
    } else {
        streams
            .index
            .send(&encode(&IndexMessage::End, &codec).unwrap())
            .await
            .unwrap();
        streams.index.finish().await.unwrap();
        let mut decoder = Decoder::<Control>::new(codec);
        let mut buffer = [0; 4096];
        let mut planned = false;
        'control: loop {
            let n = streams.control.receive(&mut buffer).await.unwrap().unwrap();
            for message in decoder.push(&buffer[..n]).unwrap() {
                match message {
                    Control::StartAccepted => {}
                    Control::PlanEnd => planned = true,
                    Control::CompleteAck => {
                        assert!(planned);
                        break 'control;
                    }
                    _ => panic!("unexpected control message"),
                }
            }
        }
        streams.control.record_completion_ack();
        streams.close().await.into_result().unwrap();
        server.await.unwrap().unwrap();
        assert_eq!(fs::read(p.output.path().join("a")).unwrap(), b"new content");
        assert!(!p.output.path().join("z").exists());
    }
}

#[tokio::test]
async fn payload_precedes_index_end_but_live_changes_wait_for_commit() {
    tokio::time::timeout(Duration::from_secs(10), gated_index(false))
        .await
        .unwrap();
}

#[tokio::test]
async fn failed_index_after_a_staged_transfer_leaves_live_tree_untouched() {
    tokio::time::timeout(Duration::from_secs(10), gated_index(true))
        .await
        .unwrap();
}

#[tokio::test]
async fn cold_then_resumed_notification_runs_two_fresh_syncs() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let p = pair().await;
        let identity = Identity::load_or_create(&p.input.path().join(".quicsync")).unwrap();
        let client =
            quicsync_core::transport::quic::SourceClient::new(&p.source_config, &identity).unwrap();
        for resumed in [false, true] {
            fs::write(
                p.input.path().join("file"),
                if resumed { b"second" } else { b"first!" },
            )
            .unwrap();
            let (a, b) = tokio::join!(
                client.connect(CancellationToken::new()),
                p._listener.accept_early()
            );
            let a = a.unwrap();
            let b = b.unwrap();
            assert_eq!(a.attempted_early_data(), resumed);
            // Source indexing and serving independently wait on the same gate.
            // Exercise simultaneous callers for both cold and resumed sessions.
            let handshake_waiters = async {
                let mut tasks = tokio::task::JoinSet::new();
                for connection in [&a, &b] {
                    for _ in 0..8 {
                        let connection = connection.clone();
                        tasks.spawn(async move { connection.confirm_handshake().await });
                    }
                }
                while let Some(result) = tasks.join_next().await {
                    result.unwrap().unwrap();
                }
            };
            let (sent, received, ()) = tokio::join!(
                source::run(&a, &p.source_config),
                destination::serve(&b, &p.destination_config),
                handshake_waiters
            );
            assert!(
                sent.is_ok() && received.is_ok(),
                "source={sent:?}; destination={received:?}"
            );
            assert_eq!(
                fs::read(p.input.path().join("file")).unwrap(),
                fs::read(p.output.path().join("file")).unwrap()
            );
        }
    })
    .await
    .unwrap();
}
