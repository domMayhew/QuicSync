use quicsync_core::types::{
    Digest, EntryKind, EntryMetadata, IndexRecord, OperationId, PathError, RelativePath,
};

#[test]
fn identifiers_and_digests_preserve_their_wire_values() {
    let operation = OperationId::new(42);
    let digest = Digest::from_bytes([0x22; 32]);
    assert_eq!(operation.get(), 42);
    assert_eq!(digest.as_bytes(), &[0x22; 32]);
}

#[test]
fn relative_paths_use_raw_validated_components() {
    let path = RelativePath::new(vec![b"src".to_vec(), vec![0xff], b"main.rs".to_vec()])
        .expect("raw non-UTF-8 names are supported");

    assert_eq!(
        path.components(),
        [b"src".as_slice(), &[0xff], b"main.rs".as_slice()]
    );

    for (components, expected) in [
        (vec![], PathError::EmptyPath),
        (vec![vec![]], PathError::EmptyComponent),
        (vec![b".".to_vec()], PathError::CurrentDirectory),
        (vec![b"..".to_vec()], PathError::ParentDirectory),
        (vec![b"a/b".to_vec()], PathError::Separator),
        (vec![b"a\0b".to_vec()], PathError::Nul),
    ] {
        assert_eq!(RelativePath::new(components), Err(expected));
    }
}

#[test]
fn paths_sort_by_unsigned_component_bytes() {
    let mut paths = [
        RelativePath::new(vec![vec![0xff]]).unwrap(),
        RelativePath::new(vec![b"a".to_vec(), b"b".to_vec()]).unwrap(),
        RelativePath::new(vec![b"a".to_vec()]).unwrap(),
    ];

    paths.sort();

    assert_eq!(paths[0].components(), [b"a".as_slice()]);
    assert_eq!(paths[1].components(), [b"a".as_slice(), b"b".as_slice()]);
    assert_eq!(paths[2].components(), [&[0xff][..]]);
}

#[test]
fn index_records_carry_portable_metadata_and_content_identity() {
    let record = IndexRecord {
        path: RelativePath::new(vec![b"bin".to_vec()]).unwrap(),
        metadata: EntryMetadata::new(EntryKind::RegularFile, 0o755, 123, 4096),
        digest: Some(Digest::from_bytes([7; 32])),
        symlink_target: None,
    };

    assert_eq!(record.metadata.kind(), EntryKind::RegularFile);
    assert_eq!(record.metadata.mode(), 0o755);
    assert_eq!(record.metadata.mtime_ns(), 123);
    assert_eq!(record.metadata.size(), 4096);
}
