use quicsync_core::{
    protocol::messages::{
        Capability, CapabilityCode, CompatibilityError, Control, FileTransfer, Operation,
        ProtocolVersion, Requirement, canonical_plan_digest, negotiate_version,
        validate_capabilities, validate_extension,
    },
    types::{Digest, EntryKind, EntryMetadata, Generation, IndexRecord, OperationId, RelativePath},
};

fn file_operation(id: u64, name: &[u8], digest_byte: u8) -> Operation {
    Operation::UpsertFile {
        id: OperationId::new(id),
        generation: Generation::new(0),
        record: IndexRecord {
            path: RelativePath::new(vec![name.to_vec()]).unwrap(),
            metadata: EntryMetadata::new(EntryKind::RegularFile, 0o644, 10, 4),
            digest: Some(Digest::from_bytes([digest_byte; 32])),
            symlink_target: None,
        },
    }
}

#[test]
fn negotiation_selects_the_highest_mutually_supported_version() {
    let selected = negotiate_version(
        &[ProtocolVersion::new(1), ProtocolVersion::new(3)],
        &[ProtocolVersion::new(2), ProtocolVersion::new(3)],
    );

    assert_eq!(selected, Ok(ProtocolVersion::new(3)));
    assert_eq!(
        negotiate_version(&[ProtocolVersion::new(1)], &[ProtocolVersion::new(2)]),
        Err(CompatibilityError::NoCommonVersion)
    );
}

#[test]
fn unknown_required_capabilities_fail_and_unknown_optional_ones_are_ignored() {
    let capabilities = [
        Capability::known(CapabilityCode::StatusQuery, Requirement::Required),
        Capability::new(9_999, Requirement::Optional),
    ];

    assert_eq!(
        validate_capabilities(&capabilities),
        Ok(vec![CapabilityCode::StatusQuery])
    );
    assert_eq!(
        validate_capabilities(&[Capability::new(9_999, Requirement::Required)]),
        Err(CompatibilityError::UnknownRequiredValue(9_999))
    );
}

#[test]
fn the_requiredness_rule_also_applies_to_extensible_messages_and_enums() {
    assert_eq!(
        validate_extension(10, Requirement::Required, &[10]),
        Ok(true)
    );
    assert_eq!(
        validate_extension(11, Requirement::Optional, &[10]),
        Ok(false)
    );
    assert_eq!(
        validate_extension(11, Requirement::Required, &[10]),
        Err(CompatibilityError::UnknownRequiredValue(11))
    );
}

#[test]
fn equivalent_plans_have_the_same_canonical_digest() {
    let first = file_operation(1, b"a", 1);
    let second = file_operation(2, b"b", 2);

    assert_eq!(
        canonical_plan_digest(&[first.clone(), second.clone()]),
        canonical_plan_digest(&[second, first])
    );
}

#[test]
fn canonical_plan_digest_covers_operation_contents() {
    let digest = canonical_plan_digest(&[file_operation(1, b"a", 1)]);
    assert_eq!(
        digest.to_string(),
        "f9f2eaac7a5f1ebb4cd935fd65778f8af9bc21b2a1815c43b6068f046330bf88"
    );
    assert_ne!(digest, canonical_plan_digest(&[file_operation(1, b"a", 2)]));
}

#[test]
fn protocol_categories_carry_validated_paths_and_shared_identifiers() {
    let operation = file_operation(7, b"src", 3);
    let path = operation.path().clone();
    let control = Control::Operation(operation);
    let transfer = FileTransfer::FileRequest {
        id: OperationId::new(7),
        generation: Generation::new(0),
        path,
        basis: None,
    };

    assert!(matches!(control, Control::Operation(_)));
    assert!(matches!(transfer, FileTransfer::FileRequest { .. }));
}
