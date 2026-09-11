//! Transport abstractions.

pub mod quic;

/// The shared signal that stops every producer and consumer bound to one session.
pub use tokio_util::sync::CancellationToken;
