//! QUIC connections and session streams.
//!
//! One long-lived bidirectional control stream carries phase changes, the source index uses
//! one unidirectional stream, and each file uses its own bidirectional transfer stream. Stream
//! counts, pending opens, and buffered bytes are bounded locally, so memory never grows with the
//! size of the synchronized tree. Nothing here interprets message payloads: the transport moves
//! bounded byte chunks and leaves framing and meaning to `protocol`.
//!
//! A clean close is not success. Completion stays [`Completion::Unknown`] until the caller records
//! an observed `CompleteAck`. Report an unknown outcome; the user can start a fresh sync.

use std::{
    future::Future,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use quinn::{
    ClosedStream, ConnectionError, Endpoint, ReadError, RecvStream, SendStream, TransportConfig,
    VarInt, WriteError,
    crypto::rustls::{QuicClientConfig, QuicServerConfig},
};
use rustls::{ClientConfig, ServerConfig, pki_types::CertificateDer};
use tokio::sync::{Mutex, OnceCell, OwnedSemaphorePermit, Semaphore};

use crate::{
    auth::{self, Fingerprint, Identity, PeerPin},
    config::{DestinationConfig, Limits, SourceConfig},
    error::{ErrorCode, QuicSyncError},
    transport::CancellationToken,
    types::Phase,
};

/// The application protocol negotiated during the TLS handshake.
pub const ALPN: &[u8] = b"quicsync/1";

/// Pinning replaces name verification, so one fixed placeholder name is presented.
const SERVER_NAME: &str = "quicsync.invalid";
const SESSION_CLOSED: VarInt = VarInt::from_u32(0);
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const KEEP_ALIVE: Duration = Duration::from_secs(5);

/// Locally enforced transport bounds. Peer input never raises them.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransportBounds {
    max_frame_bytes: usize,
    max_parallel_transfers: usize,
    max_inflight_bytes: usize,
}

impl TransportBounds {
    pub fn new(
        max_frame_bytes: usize,
        max_parallel_transfers: usize,
        max_inflight_bytes: usize,
    ) -> Result<Self, QuicSyncError> {
        if max_frame_bytes == 0 || max_parallel_transfers == 0 || max_inflight_bytes == 0 {
            return Err(QuicSyncError::new(
                ErrorCode::InvalidConfiguration,
                None,
                "transport bounds must all be greater than zero",
            ));
        }
        Ok(Self {
            max_frame_bytes,
            max_parallel_transfers,
            max_inflight_bytes,
        })
    }

    pub fn from_limits(limits: &Limits) -> Self {
        Self {
            max_frame_bytes: limits.max_frame_bytes(),
            max_parallel_transfers: limits.max_parallel_transfers(),
            max_inflight_bytes: limits.max_inflight_bytes(),
        }
    }

    pub const fn max_frame_bytes(self) -> usize {
        self.max_frame_bytes
    }

    pub const fn max_parallel_transfers(self) -> usize {
        self.max_parallel_transfers
    }

    pub const fn max_inflight_bytes(self) -> usize {
        self.max_inflight_bytes
    }

    /// Translates the bounds into QUIC stream and flow-control limits.
    fn tuning(self) -> TransportConfig {
        let transfers = self.max_parallel_transfers as u64;
        let inflight = self.max_inflight_bytes as u64;
        // The control stream shares the connection window with every transfer, so no transfer may
        // claim more than its share of it. Saturated transfers therefore cannot starve control.
        let per_stream = (inflight / (transfers + 1)).max(self.max_frame_bytes as u64);

        let mut config = TransportConfig::default();
        config.max_concurrent_bidi_streams(varint(transfers + 1));
        config.max_concurrent_uni_streams(varint(1));
        config.receive_window(varint(inflight));
        config.stream_receive_window(varint(per_stream));
        config.send_window(inflight);
        config.datagram_receive_buffer_size(None);
        config.datagram_send_buffer_size(0);
        config.max_idle_timeout(Some(IDLE_TIMEOUT.try_into().expect("idle timeout fits")));
        config.keep_alive_interval(Some(KEEP_ALIVE));
        config
    }
}

/// Whether a session ended with an observed completion acknowledgment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Completion {
    Acknowledged,
    Unknown,
}

impl Completion {
    pub const fn is_acknowledged(self) -> bool {
        matches!(self, Self::Acknowledged)
    }

    pub const fn is_unknown(self) -> bool {
        matches!(self, Self::Unknown)
    }

    /// A session without an acknowledgment is indeterminate, however cleanly the transport closed.
    pub fn into_result(self) -> Result<(), QuicSyncError> {
        match self {
            Self::Acknowledged => Ok(()),
            Self::Unknown => Err(QuicSyncError::new(
                ErrorCode::CompletionUnknown,
                Some(Phase::Complete),
                "session closed without a completion acknowledgment",
            )),
        }
    }
}

/// Connects to the configured destination with this identity, accepting only the configured pin.
pub async fn connect(
    config: &SourceConfig,
    identity: &Identity,
    cancel: CancellationToken,
) -> Result<Connection, QuicSyncError> {
    let pin = PeerPin::new(Fingerprint::from_bytes(*config.peer_pin().as_bytes()));
    connect_to(
        config.destination(),
        auth::client_tls(identity, pin)?,
        TransportBounds::from_limits(config.limits()),
        cancel,
    )
    .await
}

/// Connects to `address`, presenting `tls` and enforcing `bounds` locally.
pub async fn connect_to(
    address: SocketAddr,
    tls: ClientConfig,
    bounds: TransportBounds,
    cancel: CancellationToken,
) -> Result<Connection, QuicSyncError> {
    dial(address, tls, bounds, cancel, false).await
}

/// Reuse this client for fresh syncs to retain TLS tickets in memory.
pub struct SourceClient {
    address: SocketAddr,
    tls: ClientConfig,
    bounds: TransportBounds,
}
impl SourceClient {
    pub fn new(config: &SourceConfig, identity: &Identity) -> Result<Self, QuicSyncError> {
        let pin = PeerPin::new(Fingerprint::from_bytes(*config.peer_pin().as_bytes()));
        Ok(Self {
            address: config.destination(),
            tls: auth::client_tls(identity, pin)?,
            bounds: TransportBounds::from_limits(config.limits()),
        })
    }
    pub async fn connect(&self, cancel: CancellationToken) -> Result<Connection, QuicSyncError> {
        connect_early_to(self.address, self.tls.clone(), self.bounds, cancel).await
    }
}

/// Attempts early notification when the supplied TLS configuration has a cached ticket.
/// Rejected early data fails the attempt; it is not retransmitted automatically.
pub async fn connect_early_to(
    address: SocketAddr,
    tls: ClientConfig,
    bounds: TransportBounds,
    cancel: CancellationToken,
) -> Result<Connection, QuicSyncError> {
    dial(address, tls, bounds, cancel, true).await
}

async fn dial(
    address: SocketAddr,
    mut tls: ClientConfig,
    bounds: TransportBounds,
    cancel: CancellationToken,
    early: bool,
) -> Result<Connection, QuicSyncError> {
    tls.alpn_protocols = vec![ALPN.to_vec()];
    let crypto = QuicClientConfig::try_from(tls).map_err(|error| {
        configuration_error(format!("client TLS is unusable for QUIC: {error}"))
    })?;
    let mut client = quinn::ClientConfig::new(Arc::new(crypto));
    client.transport_config(Arc::new(bounds.tuning()));

    let unspecified = if address.is_ipv4() {
        SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
    } else {
        SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))
    };
    let endpoint = Endpoint::client(unspecified)
        .map_err(|error| unavailable_error(format!("bind client endpoint: {error}")))?;
    let connecting = endpoint
        .connect_with(client, address, SERVER_NAME)
        .map_err(|error| unavailable_error(format!("start connection: {error}")))?;
    let connecting = if early {
        match connecting.into_0rtt() {
            Ok((connection, handshake)) => {
                return Ok(Connection::new_early(
                    endpoint,
                    connection,
                    bounds,
                    cancel,
                    Some(handshake),
                    true,
                ));
            }
            Err(connecting) => connecting,
        }
    } else {
        connecting
    };
    let connection = guarded(&cancel, "connect to destination", connecting).await?;
    Ok(Connection::new(endpoint, connection, bounds, cancel))
}

/// Binds the configured listen address for the peers pinned by the destination configuration.
pub fn listen(
    config: &DestinationConfig,
    identity: &Identity,
    cancel: CancellationToken,
) -> Result<Listener, QuicSyncError> {
    let pins = config
        .roots()
        .iter()
        .flat_map(|root| root.authorized_peers())
        .map(|pin| PeerPin::new(Fingerprint::from_bytes(*pin.as_bytes())));
    listen_on(
        config.listen_address(),
        auth::server_tls(identity, pins)?,
        TransportBounds::from_limits(config.limits()),
        cancel,
    )
}

/// Binds `address`, presenting `tls` and enforcing `bounds` locally.
pub fn listen_on(
    address: SocketAddr,
    mut tls: ServerConfig,
    bounds: TransportBounds,
    cancel: CancellationToken,
) -> Result<Listener, QuicSyncError> {
    tls.alpn_protocols = vec![ALPN.to_vec()];
    let crypto = QuicServerConfig::try_from(tls).map_err(|error| {
        configuration_error(format!("server TLS is unusable for QUIC: {error}"))
    })?;
    let mut server = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    server.transport_config(Arc::new(bounds.tuning()));

    let endpoint = Endpoint::server(server, address)
        .map_err(|error| unavailable_error(format!("bind server endpoint: {error}")))?;
    Ok(Listener {
        endpoint,
        bounds,
        cancel,
    })
}

/// An endpoint accepting sessions from pinned peers.
#[derive(Clone, Debug)]
pub struct Listener {
    endpoint: Endpoint,
    bounds: TransportBounds,
    cancel: CancellationToken,
}

impl Listener {
    pub fn local_address(&self) -> Result<SocketAddr, QuicSyncError> {
        self.endpoint
            .local_addr()
            .map_err(|error| unavailable_error(format!("read local address: {error}")))
    }

    /// Completes one mutually authenticated handshake.
    pub async fn accept(&self) -> Result<Connection, QuicSyncError> {
        self.accept_mode(false).await
    }

    /// Accepts notification before the handshake finishes. Confirm before serving requests.
    pub async fn accept_early(&self) -> Result<Connection, QuicSyncError> {
        self.accept_mode(true).await
    }

    async fn accept_mode(&self, early: bool) -> Result<Connection, QuicSyncError> {
        let incoming =
            guarded_infallible(&self.cancel, "accept connection", self.endpoint.accept())
                .await?
                .ok_or_else(|| unavailable_error("endpoint stopped accepting connections"))?;
        let connecting = incoming
            .accept()
            .map_err(|error| error.describe("accept connection"))?;
        let connecting = if early {
            match connecting.into_0rtt() {
                Ok((connection, handshake)) => {
                    return Ok(Connection::new_early(
                        self.endpoint.clone(),
                        connection,
                        self.bounds,
                        self.cancel.child_token(),
                        Some(handshake),
                        false,
                    ));
                }
                Err(connecting) => connecting,
            }
        } else {
            connecting
        };
        let connection = guarded(&self.cancel, "accept connection", connecting).await?;
        // Each accepted session gets its own token: losing one must not stop the others.
        Ok(Connection::new(
            self.endpoint.clone(),
            connection,
            self.bounds,
            self.cancel.child_token(),
        ))
    }

    /// Stops accepting new connections.
    pub fn close(&self) {
        self.endpoint.close(SESSION_CLOSED, b"");
    }
}

/// Per-connection state shared by every stream of one session.
struct Session {
    // Held so the endpoint driver outlives the connection it serves.
    _endpoint: Endpoint,
    connection: quinn::Connection,
    bounds: TransportBounds,
    cancel: CancellationToken,
    transfer_permits: Arc<Semaphore>,
    early_handshake: Mutex<Option<quinn::ZeroRttAccepted>>,
    handshake_accepted: OnceCell<bool>,
    // True only for an outgoing/client connection that attempted TLS 0-RTT.
    // Incoming/server connections cannot interpret Quinn's acceptance flag.
    attempted_early: bool,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("bounds", &self.bounds)
            .field("attempted_early", &self.attempted_early)
            .finish_non_exhaustive()
    }
}

impl Session {
    /// Whether the connection ended with QuicSync's own clean close rather than a failure.
    fn closed_cleanly(&self) -> bool {
        match self.connection.close_reason() {
            Some(ConnectionError::ApplicationClosed(close)) => close.error_code == SESSION_CLOSED,
            Some(ConnectionError::LocallyClosed) => true,
            _ => false,
        }
    }

    /// Why an operation stopped: a lost connection explains itself, otherwise it was cancelled.
    fn interrupted(&self, action: &str) -> QuicSyncError {
        match self.connection.close_reason() {
            Some(error) if !self.closed_cleanly() => error.describe(action),
            _ => cancelled(action),
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.connection.close(SESSION_CLOSED, b"");
    }
}

/// An authenticated QUIC connection to one pinned peer.
#[derive(Clone, Debug)]
pub struct Connection(Arc<Session>);

impl Connection {
    fn new(
        endpoint: Endpoint,
        connection: quinn::Connection,
        bounds: TransportBounds,
        cancel: CancellationToken,
    ) -> Self {
        Self::new_early(endpoint, connection, bounds, cancel, None, false)
    }

    fn new_early(
        endpoint: Endpoint,
        connection: quinn::Connection,
        bounds: TransportBounds,
        cancel: CancellationToken,
        handshake: Option<quinn::ZeroRttAccepted>,
        outgoing_early: bool,
    ) -> Self {
        // Anything that ends the connection other than our own close cancels every producer and
        // consumer sharing this session. The watcher holds a connection handle, which
        // `Session::drop` closes, so the task always finishes.
        let watched = connection.clone();
        let losing = cancel.clone();
        tokio::spawn(async move {
            if !matches!(watched.closed().await, ConnectionError::LocallyClosed) {
                losing.cancel();
            }
        });

        Self(Arc::new(Session {
            _endpoint: endpoint,
            connection,
            bounds,
            cancel,
            transfer_permits: Arc::new(Semaphore::new(bounds.max_parallel_transfers)),
            attempted_early: outgoing_early,
            early_handshake: Mutex::new(handshake),
            handshake_accepted: OnceCell::new(),
        }))
    }

    pub fn attempted_early_data(&self) -> bool {
        self.0.attempted_early
    }

    /// Only StartSync may precede this gate. Rejection is a failed attempt, not a retry.
    pub async fn confirm_handshake(&self) -> Result<(), QuicSyncError> {
        let accepted = self
            .0
            .handshake_accepted
            .get_or_try_init(|| async {
                // OnceCell runs only one initializer at a time. The mutex gives
                // that initializer mutable access to the handshake future; no
                // code acquires these locks in reverse order. Cancellation drops
                // the guard, allowing a later initializer after an error.
                let mut handshake = self.0.early_handshake.lock().await;
                match handshake.as_mut() {
                    Some(handshake) => tokio::select! {
                        accepted = handshake => Ok(accepted),
                        _ = self.0.cancel.cancelled() => Err(self.0.interrupted("handshake")),
                    },
                    None => Ok(true),
                }
            })
            .await?;
        if let Some(error) = self.0.connection.close_reason() {
            return Err(error.describe("handshake"));
        }
        // Quinn exposes an acceptance flag only for clients; the server value is unspecified.
        if *accepted || !self.0.attempted_early {
            Ok(())
        } else {
            Err(unavailable_error(
                "early notification rejected; start a fresh sync",
            ))
        }
    }

    /// The authenticated public-key fingerprint presented by the peer.
    pub fn peer_fingerprint(&self) -> Result<Fingerprint, QuicSyncError> {
        let identity = self
            .0
            .connection
            .peer_identity()
            .ok_or_else(|| authentication_error("peer presented no certificate"))?;
        let certificates = identity
            .downcast::<Vec<CertificateDer<'static>>>()
            .map_err(|_| authentication_error("peer identity is not a certificate chain"))?;
        let end_entity = certificates
            .first()
            .ok_or_else(|| authentication_error("peer certificate chain is empty"))?;
        Fingerprint::from_certificate_der(end_entity.as_ref())
    }

    pub fn bounds(&self) -> TransportBounds {
        self.0.bounds
    }

    pub fn cancellation(&self) -> &CancellationToken {
        &self.0.cancel
    }

    /// Opens the source side of a session: control now, index and transfers on demand.
    pub async fn open_session(&self) -> Result<SourceStreams, QuicSyncError> {
        let (send, recv) =
            guarded_in(&self.0, "open control stream", self.0.connection.open_bi()).await?;
        let index = guarded_in(&self.0, "open index stream", self.0.connection.open_uni()).await?;
        Ok(SourceStreams {
            control: ControlChannel::new(self.0.clone(), send, recv),
            index: IndexWriter {
                session: self.0.clone(),
                stream: index,
            },
            transfers: TransferAcceptor {
                session: self.0.clone(),
            },
        })
    }

    /// Accepts the destination side of a session once the source sends its first control bytes.
    pub async fn accept_session(&self) -> Result<DestinationStreams, QuicSyncError> {
        let (send, recv) = guarded_in(
            &self.0,
            "accept control stream",
            self.0.connection.accept_bi(),
        )
        .await?;
        Ok(DestinationStreams {
            control: ControlChannel::new(self.0.clone(), send, recv),
            source_index: IndexReader {
                session: self.0.clone(),
                stream: None,
                finished: false,
            },
            transfers: TransferOpener {
                session: self.0.clone(),
            },
        })
    }

    /// Cancels the session and closes the connection.
    pub fn cancel(&self) {
        self.0.cancel.cancel();
        self.0.connection.close(SESSION_CLOSED, b"");
    }
}

/// The source sends its index and accepts file requests.
#[derive(Debug)]
pub struct SourceStreams {
    pub control: ControlChannel,
    pub index: IndexWriter,
    pub transfers: TransferAcceptor,
}

impl SourceStreams {
    /// Closes the session and reports whether completion was ever acknowledged.
    pub async fn close(self) -> Completion {
        self.control.close().await
    }
}

/// The destination receives the source index and opens file requests.
#[derive(Debug)]
pub struct DestinationStreams {
    pub control: ControlChannel,
    pub source_index: IndexReader,
    pub transfers: TransferOpener,
}

impl DestinationStreams {
    /// Closes the session and reports whether completion was ever acknowledged.
    pub async fn close(self) -> Completion {
        self.control.close().await
    }
}

/// The long-lived bidirectional stream carrying phase changes.
#[derive(Debug)]
pub struct ControlChannel {
    session: Arc<Session>,
    send: SendStream,
    recv: RecvStream,
    completion: Completion,
    finished: bool,
}

impl ControlChannel {
    fn new(session: Arc<Session>, send: SendStream, recv: RecvStream) -> Self {
        Self {
            session,
            send,
            recv,
            completion: Completion::Unknown,
            finished: false,
        }
    }

    /// Sends one frame, refusing anything larger than the local frame limit.
    pub async fn send(&mut self, frame: &[u8]) -> Result<(), QuicSyncError> {
        send_bounded(&self.session, &mut self.send, frame, "send control frame").await
    }

    /// Reads up to `buffer.len()` bytes, returning `None` once the peer finished the stream.
    pub async fn receive(&mut self, buffer: &mut [u8]) -> Result<Option<usize>, QuicSyncError> {
        receive_bounded(
            &self.session,
            &mut self.recv,
            &mut self.finished,
            buffer,
            "receive control bytes",
        )
        .await
    }

    /// Records that a `CompleteAck` was decoded from this stream.
    pub fn record_completion_ack(&mut self) {
        self.completion = Completion::Acknowledged;
    }

    pub const fn completion(&self) -> Completion {
        self.completion
    }

    pub async fn close(mut self) -> Completion {
        if self.send.finish().is_ok() {
            // Wait for the peer to take the remaining bytes so closing does not discard them.
            let _ = guarded_in(&self.session, "flush control stream", self.send.stopped()).await;
        }
        self.completion
    }
}

/// The unidirectional stream a destination writes its index to.
#[derive(Debug)]
pub struct IndexWriter {
    session: Arc<Session>,
    stream: SendStream,
}

impl IndexWriter {
    /// Sends one chunk, refusing anything larger than the local frame limit.
    pub async fn send(&mut self, chunk: &[u8]) -> Result<(), QuicSyncError> {
        send_bounded(&self.session, &mut self.stream, chunk, "send index bytes").await
    }

    pub async fn finish(&mut self) -> Result<(), QuicSyncError> {
        self.stream
            .finish()
            .map_err(|error| error.describe("finish index stream"))
    }
}

/// The unidirectional stream a source reads the destination index from.
#[derive(Debug)]
pub struct IndexReader {
    session: Arc<Session>,
    stream: Option<RecvStream>,
    finished: bool,
}

impl IndexReader {
    /// Reads up to `buffer.len()` bytes, accepting the single index stream on first use.
    pub async fn receive(&mut self, buffer: &mut [u8]) -> Result<Option<usize>, QuicSyncError> {
        if self.finished {
            return Ok(None);
        }
        if self.stream.is_none() {
            let stream = guarded_in(
                &self.session,
                "accept index stream",
                self.session.connection.accept_uni(),
            )
            .await?;
            self.stream = Some(stream);
        }
        let stream = self.stream.as_mut().expect("index stream accepted");
        receive_bounded(
            &self.session,
            stream,
            &mut self.finished,
            buffer,
            "receive index bytes",
        )
        .await
    }
}

/// Opens per-file transfer streams, never exceeding the configured parallelism.
#[derive(Clone, Debug)]
pub struct TransferOpener {
    session: Arc<Session>,
}

impl TransferOpener {
    /// How many further transfers may start before an open has to wait.
    pub fn available_permits(&self) -> usize {
        self.session.transfer_permits.available_permits()
    }

    /// Waits for a transfer permit and then opens one bidirectional stream.
    pub async fn open(&self) -> Result<TransferStream, QuicSyncError> {
        let permit = reserve(&self.session).await?;
        let (send, recv) = guarded_in(
            &self.session,
            "open transfer stream",
            self.session.connection.open_bi(),
        )
        .await?;
        Ok(TransferStream::new(
            self.session.clone(),
            send,
            recv,
            permit,
        ))
    }
}

/// Accepts per-file transfer streams, never exceeding the configured parallelism.
#[derive(Clone, Debug)]
pub struct TransferAcceptor {
    session: Arc<Session>,
}

impl TransferAcceptor {
    /// How many further transfers may be accepted before the peer has to wait.
    pub fn available_permits(&self) -> usize {
        self.session.transfer_permits.available_permits()
    }

    /// Waits for a transfer permit and then accepts one stream, or `None` once the peer is done.
    pub async fn accept(&self) -> Result<Option<TransferStream>, QuicSyncError> {
        let permit = reserve(&self.session).await?;
        match guarded_in(
            &self.session,
            "accept transfer stream",
            self.session.connection.accept_bi(),
        )
        .await
        {
            Ok((send, recv)) => Ok(Some(TransferStream::new(
                self.session.clone(),
                send,
                recv,
                permit,
            ))),
            // Only QuicSync's own clean close ends the loop; a lost connection stays an error.
            Err(_) if self.session.closed_cleanly() => Ok(None),
            Err(error) => Err(error),
        }
    }
}

/// One bidirectional stream carrying a single file's request, signature, and delta.
#[derive(Debug)]
pub struct TransferStream {
    session: Arc<Session>,
    send: SendStream,
    recv: RecvStream,
    finished: bool,
    // Released on drop, admitting the next waiting transfer.
    _permit: OwnedSemaphorePermit,
}

impl TransferStream {
    fn new(
        session: Arc<Session>,
        send: SendStream,
        recv: RecvStream,
        permit: OwnedSemaphorePermit,
    ) -> Self {
        Self {
            session,
            send,
            recv,
            finished: false,
            _permit: permit,
        }
    }

    /// Sends one chunk, refusing anything larger than the local frame limit.
    pub async fn send(&mut self, chunk: &[u8]) -> Result<(), QuicSyncError> {
        send_bounded(&self.session, &mut self.send, chunk, "send transfer bytes").await
    }

    /// Reads up to `buffer.len()` bytes, returning `None` once the peer finished the stream.
    pub async fn receive(&mut self, buffer: &mut [u8]) -> Result<Option<usize>, QuicSyncError> {
        receive_bounded(
            &self.session,
            &mut self.recv,
            &mut self.finished,
            buffer,
            "receive transfer bytes",
        )
        .await
    }

    pub async fn finish(&mut self) -> Result<(), QuicSyncError> {
        self.send
            .finish()
            .map_err(|error| error.describe("finish transfer stream"))
    }
}

async fn reserve(session: &Session) -> Result<OwnedSemaphorePermit, QuicSyncError> {
    guarded_in(
        session,
        "reserve transfer capacity",
        session.transfer_permits.clone().acquire_owned(),
    )
    .await
}

async fn send_bounded(
    session: &Session,
    stream: &mut SendStream,
    chunk: &[u8],
    action: &'static str,
) -> Result<(), QuicSyncError> {
    if chunk.len() > session.bounds.max_frame_bytes {
        return Err(QuicSyncError::new(
            ErrorCode::ResourceLimitExceeded,
            None,
            format!(
                "{} bytes exceed the local frame limit of {}",
                chunk.len(),
                session.bounds.max_frame_bytes
            ),
        ));
    }
    guarded_in(session, action, stream.write_all(chunk)).await
}

async fn receive_bounded(
    session: &Session,
    stream: &mut RecvStream,
    finished: &mut bool,
    buffer: &mut [u8],
    action: &'static str,
) -> Result<Option<usize>, QuicSyncError> {
    if *finished {
        return Ok(None);
    }
    let bound = buffer.len().min(session.bounds.max_frame_bytes);
    if bound == 0 {
        return Ok(Some(0));
    }
    let read = guarded_in(session, action, stream.read(&mut buffer[..bound])).await?;
    if read.is_none() {
        *finished = true;
    }
    Ok(read)
}

/// Awaits a fallible transport operation unless the shared cancellation fires first.
async fn guarded<T, E: TransportFailure>(
    cancel: &CancellationToken,
    action: &'static str,
    future: impl Future<Output = Result<T, E>>,
) -> Result<T, QuicSyncError> {
    if cancel.is_cancelled() {
        return Err(cancelled(action));
    }
    tokio::select! {
        biased;
        () = cancel.cancelled() => Err(cancelled(action)),
        result = future => result.map_err(|error| error.describe(action)),
    }
}

/// Awaits a session operation unless the shared cancellation or a lost connection stops it.
async fn guarded_in<T, E: TransportFailure>(
    session: &Session,
    action: &'static str,
    future: impl Future<Output = Result<T, E>>,
) -> Result<T, QuicSyncError> {
    if session.cancel.is_cancelled() {
        return Err(session.interrupted(action));
    }
    tokio::select! {
        biased;
        () = session.cancel.cancelled() => Err(session.interrupted(action)),
        result = future => result.map_err(|error| error.describe(action)),
    }
}

/// Awaits an infallible transport operation unless the shared cancellation fires first.
async fn guarded_infallible<T>(
    cancel: &CancellationToken,
    action: &'static str,
    future: impl Future<Output = T>,
) -> Result<T, QuicSyncError> {
    if cancel.is_cancelled() {
        return Err(cancelled(action));
    }
    tokio::select! {
        biased;
        () = cancel.cancelled() => Err(cancelled(action)),
        value = future => Ok(value),
    }
}

/// Maps one transport failure onto QuicSync's stable error codes.
trait TransportFailure {
    fn describe(self, action: &str) -> QuicSyncError;
}

impl TransportFailure for ConnectionError {
    fn describe(self, action: &str) -> QuicSyncError {
        let rejected_handshake = match &self {
            Self::TransportError(error) => is_crypto(u64::from(error.code)),
            Self::ConnectionClosed(close) => is_crypto(u64::from(close.error_code)),
            _ => false,
        };
        if rejected_handshake {
            return authentication_error(format!("{action}: peer rejected the TLS handshake"));
        }
        unavailable_error(format!("{action}: {self}"))
    }
}

impl TransportFailure for WriteError {
    fn describe(self, action: &str) -> QuicSyncError {
        match self {
            Self::ConnectionLost(error) => error.describe(action),
            other => unavailable_error(format!("{action}: {other}")),
        }
    }
}

impl TransportFailure for ReadError {
    fn describe(self, action: &str) -> QuicSyncError {
        match self {
            Self::ConnectionLost(error) => error.describe(action),
            other => unavailable_error(format!("{action}: {other}")),
        }
    }
}

impl TransportFailure for quinn::StoppedError {
    fn describe(self, action: &str) -> QuicSyncError {
        match self {
            Self::ConnectionLost(error) => error.describe(action),
            other => unavailable_error(format!("{action}: {other}")),
        }
    }
}

impl TransportFailure for ClosedStream {
    fn describe(self, action: &str) -> QuicSyncError {
        unavailable_error(format!("{action}: {self}"))
    }
}

impl TransportFailure for tokio::sync::AcquireError {
    fn describe(self, action: &str) -> QuicSyncError {
        QuicSyncError::new(
            ErrorCode::Internal,
            None,
            format!("{action}: transfer capacity is no longer available"),
        )
    }
}

/// QUIC encodes TLS alerts as transport error codes in `0x100..0x200`.
const fn is_crypto(code: u64) -> bool {
    code >= 0x100 && code < 0x200
}

fn varint(value: u64) -> VarInt {
    VarInt::from_u64(value).unwrap_or(VarInt::MAX)
}

fn cancelled(action: &str) -> QuicSyncError {
    QuicSyncError::new(
        ErrorCode::Cancelled,
        None,
        format!("{action}: session was cancelled"),
    )
}

fn unavailable_error(diagnostic: impl Into<String>) -> QuicSyncError {
    QuicSyncError::new(ErrorCode::TransportUnavailable, None, diagnostic)
}

fn authentication_error(diagnostic: impl Into<String>) -> QuicSyncError {
    QuicSyncError::new(
        ErrorCode::AuthenticationFailed,
        Some(Phase::Handshake),
        diagnostic,
    )
}

fn configuration_error(diagnostic: impl Into<String>) -> QuicSyncError {
    QuicSyncError::new(ErrorCode::InvalidConfiguration, None, diagnostic)
}
