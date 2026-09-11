use quicsync_core::{
    error::{ErrorCode, ErrorContext, QuicSyncError, RetryClass},
    types::{OperationId, Phase, RelativePath, SessionId},
};

#[test]
fn stable_codes_round_trip_without_using_display_strings() {
    for code in ErrorCode::ALL {
        assert_eq!(ErrorCode::try_from(code.as_str()), Ok(*code));
    }
    assert!(ErrorCode::try_from("the disk made a funny noise").is_err());
}

#[test]
fn local_errors_retain_phase_and_structured_context() {
    let path = RelativePath::new(vec![b"private".to_vec(), b"key.pem".to_vec()]).unwrap();
    let context = ErrorContext::default()
        .with_session(SessionId::from_bytes([9; 16]))
        .with_operation(OperationId::new(17))
        .with_path(path.clone());
    let error = QuicSyncError::new(
        ErrorCode::IntegrityMismatch,
        Some(Phase::Transferring),
        "digest mismatch: expected secret local diagnostic",
    )
    .with_context(context.clone());

    assert_eq!(error.phase(), Some(Phase::Transferring));
    assert_eq!(error.context(), &context);
    assert_eq!(error.context().path(), Some(&path));
    assert!(error.local_diagnostic().contains("expected secret"));
}

#[test]
fn sensitive_peer_errors_expose_only_code_and_safe_fixed_text() {
    let forbidden = [
        "/Users/alice/source",
        "PRIVATE KEY",
        "authorized-peer-fingerprint",
    ];

    for code in [
        ErrorCode::AuthenticationFailed,
        ErrorCode::AuthorizationDenied,
        ErrorCode::PathConfinementViolation,
        ErrorCode::IntegrityMismatch,
    ] {
        let diagnostic = forbidden.join(" ");
        let local = QuicSyncError::new(code, Some(Phase::Handshake), diagnostic);
        let peer = local.peer_error();
        let rendered = peer.to_string();

        assert_eq!(peer.code(), code);
        assert_eq!(peer.retry_class(), RetryClass::Never);
        assert!(forbidden.iter().all(|secret| !rendered.contains(secret)));
        assert!(
            forbidden
                .iter()
                .all(|secret| !peer.message().contains(secret))
        );
    }
}

#[test]
fn retry_classes_are_part_of_the_code_contract() {
    assert_eq!(
        ErrorCode::IntegrityMismatch.retry_class(),
        RetryClass::Never
    );
    assert_eq!(
        ErrorCode::PathConfinementViolation.retry_class(),
        RetryClass::Never
    );
    assert_eq!(
        ErrorCode::UnsupportedFilesystem.retry_class(),
        RetryClass::Never
    );
    assert_eq!(
        ErrorCode::TransportUnavailable.retry_class(),
        RetryClass::NewSession
    );
    assert_eq!(
        ErrorCode::CompletionUnknown.retry_class(),
        RetryClass::QueryThenRetry
    );
}
