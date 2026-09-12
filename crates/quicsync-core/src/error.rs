//! Stable errors shared across core operations and peer boundaries.

use std::{fmt, str::FromStr};

use crate::types::{OperationId, Phase, RelativePath};

/// A stable, machine-readable failure category.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum ErrorCode {
    InvalidConfiguration,
    AuthenticationFailed,
    AuthorizationDenied,
    ProtocolViolation,
    UnsupportedProtocol,
    InvalidPath,
    PathConfinementViolation,
    IntegrityMismatch,
    UnsupportedFilesystem,
    ResourceLimitExceeded,
    OperationFailed,
    Io,
    TransportUnavailable,
    CompletionUnknown,
    Cancelled,
    Internal,
}

impl ErrorCode {
    pub const ALL: &'static [Self] = &[
        Self::InvalidConfiguration,
        Self::AuthenticationFailed,
        Self::AuthorizationDenied,
        Self::ProtocolViolation,
        Self::UnsupportedProtocol,
        Self::InvalidPath,
        Self::PathConfinementViolation,
        Self::IntegrityMismatch,
        Self::UnsupportedFilesystem,
        Self::ResourceLimitExceeded,
        Self::OperationFailed,
        Self::Io,
        Self::TransportUnavailable,
        Self::CompletionUnknown,
        Self::Cancelled,
        Self::Internal,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidConfiguration => "invalid_configuration",
            Self::AuthenticationFailed => "authentication_failed",
            Self::AuthorizationDenied => "authorization_denied",
            Self::ProtocolViolation => "protocol_violation",
            Self::UnsupportedProtocol => "unsupported_protocol",
            Self::InvalidPath => "invalid_path",
            Self::PathConfinementViolation => "path_confinement_violation",
            Self::IntegrityMismatch => "integrity_mismatch",
            Self::UnsupportedFilesystem => "unsupported_filesystem",
            Self::ResourceLimitExceeded => "resource_limit_exceeded",
            Self::OperationFailed => "operation_failed",
            Self::Io => "io_error",
            Self::TransportUnavailable => "transport_unavailable",
            Self::CompletionUnknown => "completion_unknown",
            Self::Cancelled => "cancelled",
            Self::Internal => "internal_error",
        }
    }

    const fn peer_message(self) -> &'static str {
        match self {
            Self::InvalidConfiguration => "local configuration is invalid",
            Self::AuthenticationFailed | Self::AuthorizationDenied => "request rejected",
            Self::ProtocolViolation => "protocol violation",
            Self::UnsupportedProtocol => "protocol is not supported",
            Self::InvalidPath | Self::PathConfinementViolation => "path is invalid",
            Self::IntegrityMismatch => "content verification failed",
            Self::UnsupportedFilesystem => "filesystem operation is not supported",
            Self::ResourceLimitExceeded => "resource limit exceeded",
            Self::OperationFailed => "operation failed",
            Self::Io => "input/output operation failed",
            Self::TransportUnavailable => "transport is unavailable",
            Self::CompletionUnknown => "completion status is unknown",
            Self::Cancelled => "operation cancelled",
            Self::Internal => "internal error",
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Returned when a received machine code is unknown to this version.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnknownErrorCode(String);

impl UnknownErrorCode {
    pub fn value(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for UnknownErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "unknown error code: {}", self.0)
    }
}

impl std::error::Error for UnknownErrorCode {}

impl FromStr for ErrorCode {
    type Err = UnknownErrorCode;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .iter()
            .copied()
            .find(|code| code.as_str() == value)
            .ok_or_else(|| UnknownErrorCode(value.to_owned()))
    }
}

impl TryFrom<&str> for ErrorCode {
    type Error = UnknownErrorCode;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        value.parse()
    }
}

/// Structured local context that must never be copied into a peer error.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ErrorContext {
    operation: Option<OperationId>,
    path: Option<RelativePath>,
}

impl ErrorContext {
    pub fn with_operation(mut self, operation: OperationId) -> Self {
        self.operation = Some(operation);
        self
    }

    pub fn with_path(mut self, path: RelativePath) -> Self {
        self.path = Some(path);
        self
    }

    pub const fn operation(&self) -> Option<OperationId> {
        self.operation
    }

    pub fn path(&self) -> Option<&RelativePath> {
        self.path.as_ref()
    }
}

/// A detailed local error. Its diagnostic and context are intentionally local-only.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuicSyncError {
    code: ErrorCode,
    phase: Option<Phase>,
    diagnostic: String,
    context: ErrorContext,
}

impl QuicSyncError {
    pub fn new(code: ErrorCode, phase: Option<Phase>, diagnostic: impl Into<String>) -> Self {
        Self {
            code,
            phase,
            diagnostic: diagnostic.into(),
            context: ErrorContext::default(),
        }
    }

    pub fn with_context(mut self, context: ErrorContext) -> Self {
        self.context = context;
        self
    }

    pub const fn code(&self) -> ErrorCode {
        self.code
    }

    pub const fn phase(&self) -> Option<Phase> {
        self.phase
    }

    pub const fn context(&self) -> &ErrorContext {
        &self.context
    }

    pub fn local_diagnostic(&self) -> &str {
        &self.diagnostic
    }

    pub const fn peer_error(&self) -> PeerError {
        PeerError {
            code: self.code,
            phase: self.phase,
        }
    }
}

impl fmt::Display for QuicSyncError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.diagnostic)
    }
}

impl std::error::Error for QuicSyncError {}

/// The deliberately restricted error representation safe to send to a peer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeerError {
    code: ErrorCode,
    phase: Option<Phase>,
}

impl PeerError {
    pub const fn code(self) -> ErrorCode {
        self.code
    }

    pub const fn phase(self) -> Option<Phase> {
        self.phase
    }

    pub const fn message(self) -> &'static str {
        self.code.peer_message()
    }
}

impl fmt::Display for PeerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message())
    }
}
