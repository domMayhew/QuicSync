use quicsync_core::{
    protocol::{
        codec::{CodecError, CodecLimits, Decoder, decode, encode},
        messages::{
            CURRENT_VERSION, Capability, Control, FileTransfer, IndexMessage, ProtocolVersion,
            Requirement,
        },
    },
    types::SessionId,
};

fn limits() -> CodecLimits {
    CodecLimits::new(128, 32, 4, 4).unwrap()
}

#[test]
fn golden_vectors_fix_the_canonical_wire_format() {
    assert_eq!(
        encode(&Control::PolicyBegin, &limits()).unwrap(),
        [3, 4, 1, 0]
    );
    assert_eq!(
        encode(
            &Control::StartSync {
                session_id: SessionId::from_bytes([0x11; 16]),
                root_id: "root".into(),
            },
            &limits(),
        )
        .unwrap(),
        [
            24, 3, 1, 0, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            0x11, 0x11, 0x11, 0x11, 4, b'r', b'o', b'o', b't',
        ]
    );
}

#[test]
fn control_messages_round_trip() {
    let messages = [
        Control::ClientHello {
            versions: vec![ProtocolVersion::new(1), ProtocolVersion::new(2)],
            capabilities: vec![Capability::new(7, Requirement::Optional)],
            nonce: [3; 32],
        },
        Control::StartAccepted,
        Control::PlanEnd,
        Control::CommitRequest,
        Control::CompleteAck,
    ];

    for message in messages {
        let encoded = encode(&message, &limits()).unwrap();
        assert_eq!(decode::<Control>(&encoded, &limits()).unwrap(), message);
    }
}

#[test]
fn incremental_decoder_accepts_every_chunk_boundary() {
    let first = encode(&Control::PolicyBegin, &limits()).unwrap();
    let second = encode(&Control::StartAccepted, &limits()).unwrap();
    let wire = [first, second].concat();

    for split in 0..=wire.len() {
        let mut decoder = Decoder::<Control>::new(limits());
        let mut decoded = decoder.push(&wire[..split]).unwrap();
        decoded.extend(decoder.push(&wire[split..]).unwrap());
        decoder.finish().unwrap();
        assert_eq!(decoded, [Control::PolicyBegin, Control::StartAccepted]);
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
        decode::<Control>(&[4, 4, 1, 0, 0], &limits()),
        Err(CodecError::TrailingBytes)
    );
    assert_eq!(
        decode::<Control>(&[3, 4, 2, 0], &limits()),
        Err(CodecError::UnsupportedVersion(ProtocolVersion::new(2)))
    );
}

#[test]
fn collections_are_bounded_before_their_elements_are_read() {
    // ClientHello, version 1, followed by a version count of five.
    let wire = [4, 1, 1, 0, 5];
    assert_eq!(
        decode::<Control>(&wire, &limits()),
        Err(CodecError::LimitExceeded("collection items"))
    );
}

#[test]
fn duplicate_capabilities_and_invalid_utf8_are_rejected() {
    let duplicate = Control::ClientHello {
        versions: vec![CURRENT_VERSION],
        capabilities: vec![
            Capability::new(7, Requirement::Optional),
            Capability::new(7, Requirement::Optional),
        ],
        nonce: [0; 32],
    };
    assert_eq!(
        encode(&duplicate, &limits()),
        Err(CodecError::DuplicateValue("capability"))
    );

    let mut duplicate_wire = vec![45, 1, 1, 0, 1, 1, 0, 2, 7, 0, 1, 7, 0, 1];
    duplicate_wire.extend_from_slice(&[0; 32]);
    assert_eq!(
        decode::<Control>(&duplicate_wire, &limits()),
        Err(CodecError::DuplicateValue("capability"))
    );

    let invalid_root = [
        21, 3, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff,
    ];
    assert_eq!(
        decode::<Control>(&invalid_root, &limits()),
        Err(CodecError::InvalidValue("UTF-8 string"))
    );
}

#[test]
fn unordered_set_fields_are_noncanonical() {
    let hello = Control::ClientHello {
        versions: vec![ProtocolVersion::new(2), ProtocolVersion::new(1)],
        capabilities: Vec::new(),
        nonce: [0; 32],
    };
    assert_eq!(
        encode(&hello, &limits()),
        Err(CodecError::NonCanonicalOrder("protocol version"))
    );
}

#[test]
fn stream_categories_use_distinct_message_kinds() {
    let index = IndexMessage::End;
    let transfer = FileTransfer::Literal(vec![1, 2, 3]);

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
