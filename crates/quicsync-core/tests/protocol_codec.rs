use quicsync_core::protocol::{
    codec::{CodecError, CodecLimits, Decoder, decode, encode},
    messages::{Control, FileTransfer, IndexMessage, ProtocolVersion},
};

fn limits() -> CodecLimits {
    CodecLimits::new(128, 32, 4, 4).unwrap()
}

#[test]
fn golden_vectors_fix_the_canonical_wire_format() {
    assert_eq!(encode(&Control::PlanEnd, &limits()).unwrap(), [3, 11, 1, 0]);
    assert_eq!(
        encode(
            &Control::StartSync {
                root_id: "root".into(),
            },
            &limits(),
        )
        .unwrap(),
        [8, 3, 1, 0, 4, b'r', b'o', b'o', b't']
    );
}

#[test]
fn control_messages_round_trip() {
    let messages = [
        Control::StartSync {
            root_id: "root".into(),
        },
        Control::StartAccepted,
        Control::PlanEnd,
        Control::CompleteAck,
    ];

    for message in messages {
        let encoded = encode(&message, &limits()).unwrap();
        assert_eq!(decode::<Control>(&encoded, &limits()).unwrap(), message);
    }
}

#[test]
fn incremental_decoder_accepts_every_chunk_boundary() {
    let first = encode(&Control::PlanEnd, &limits()).unwrap();
    let second = encode(&Control::StartAccepted, &limits()).unwrap();
    let wire = [first, second].concat();

    for split in 0..=wire.len() {
        let mut decoder = Decoder::<Control>::new(limits());
        let mut decoded = decoder.push(&wire[..split]).unwrap();
        decoded.extend(decoder.push(&wire[split..]).unwrap());
        decoder.finish().unwrap();
        assert_eq!(decoded, [Control::PlanEnd, Control::StartAccepted]);
    }
}

#[test]
fn oversized_declarations_are_rejected_from_the_header_alone() {
    let mut decoder = Decoder::<Control>::new(limits());
    assert_eq!(decoder.buffered_len(), 0);
    assert_eq!(
        decoder.push(&[0x81, 0x01]),
        Err(CodecError::FrameTooLarge {
            declared: 129,
            maximum: 128
        })
    );
    assert_eq!(decoder.buffered_len(), 0);
}

#[test]
fn malformed_noncanonical_and_trailing_input_is_rejected() {
    assert_eq!(
        decode::<Control>(&[0x83, 0x00, 4, 1, 0], &limits()),
        Err(CodecError::NonCanonicalVarint)
    );
    assert_eq!(
        decode::<Control>(&[4, 11, 1, 0, 0], &limits()),
        Err(CodecError::TrailingBytes)
    );
    assert_eq!(
        decode::<Control>(&[3, 4, 2, 0], &limits()),
        Err(CodecError::UnsupportedVersion(ProtocolVersion::new(2)))
    );
}

#[test]
fn invalid_utf8_and_unknown_messages_are_rejected() {
    assert_eq!(
        decode::<Control>(&[5, 3, 1, 0, 1, 0xff], &limits()),
        Err(CodecError::InvalidValue("UTF-8 string"))
    );
    assert_eq!(
        decode::<Control>(&[3, 255, 1, 0], &limits()),
        Err(CodecError::UnknownMessageKind(255))
    );
}

#[test]
fn stream_categories_use_distinct_message_kinds() {
    let index = IndexMessage::End;
    let transfer = FileTransfer::Delta(vec![1, 2, 3]);

    assert_eq!(
        decode(&encode(&index, &limits()).unwrap(), &limits()),
        Ok(index)
    );
    assert_eq!(
        decode(&encode(&transfer, &limits()).unwrap(), &limits()),
        Ok(transfer)
    );
}

#[test]
fn finish_rejects_truncated_headers_and_payloads() {
    let mut header = Decoder::<Control>::new(limits());
    header.push(&[0x83]).unwrap();
    assert_eq!(header.finish(), Err(CodecError::UnexpectedEof));

    let mut payload = Decoder::<Control>::new(limits());
    payload.push(&[3, 4]).unwrap();
    assert_eq!(payload.finish(), Err(CodecError::UnexpectedEof));
}

#[test]
fn operations_and_transfer_messages_round_trip_without_recovery_fields() {
    use quicsync_core::{
        protocol::messages::Operation,
        types::{EntryKind, EntryMetadata, IndexRecord, OperationId, RelativePath},
    };
    let id = OperationId::new(4);
    let path = RelativePath::new(vec![b"file".to_vec()]).unwrap();
    for kind in [
        EntryKind::RegularFile,
        EntryKind::Directory,
        EntryKind::Symlink,
    ] {
        let record = IndexRecord {
            path: path.clone(),
            metadata: EntryMetadata::new(kind, 0o755, -1, 0),
            digest: None,
            symlink_target: None,
        };
        let op = match kind {
            EntryKind::RegularFile => Operation::UpsertFile { id, record },
            EntryKind::Directory => Operation::UpsertDirectory { id, record },
            EntryKind::Symlink => Operation::UpsertSymlink { id, record },
        };
        let message = Control::Operation(op);
        assert_eq!(
            decode::<Control>(&encode(&message, &limits()).unwrap(), &limits()).unwrap(),
            message
        );
    }
    let messages = [
        FileTransfer::FileRequest { id, path },
        FileTransfer::Signature(vec![1, 2, 3]),
        FileTransfer::SignatureEnd,
        FileTransfer::Delta(vec![1, 2, 3]),
        FileTransfer::DeltaEnd,
        FileTransfer::TransferAccepted { id },
    ];
    for message in messages {
        assert_eq!(
            decode::<FileTransfer>(&encode(&message, &limits()).unwrap(), &limits()).unwrap(),
            message
        );
    }
}
