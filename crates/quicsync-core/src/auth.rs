//! Mutual authentication, peer pinning, and root authorization.

use std::{
    collections::HashSet,
    fmt,
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
    str::FromStr,
    sync::Arc,
};

use ring::{
    rand::{SecureRandom, SystemRandom},
    signature::{Ed25519KeyPair, KeyPair as _},
};
use rustls::{
    CertificateError, ClientConfig, DigitallySignedStruct, DistinguishedName, Error, ServerConfig,
    SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::{WebPkiSupportedAlgorithms, verify_tls12_signature, verify_tls13_signature},
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime},
    server::danger::{ClientCertVerified, ClientCertVerifier},
    version::TLS13,
};
use sha2::{Digest as _, Sha256};

use crate::{
    error::{ErrorCode, QuicSyncError},
    types::Phase,
};

const CERTIFICATE_FILE: &str = "identity.crt";
const PRIVATE_KEY_FILE: &str = "identity.key";

/// A SHA-256 fingerprint of a peer's DER-encoded SubjectPublicKeyInfo.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Fingerprint([u8; 32]);

impl Fingerprint {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Extracts a fingerprint from a peer certificate after a TLS handshake.
    pub fn from_certificate_der(certificate: &[u8]) -> Result<Self, QuicSyncError> {
        fingerprint_certificate(certificate).map_err(|()| {
            QuicSyncError::new(
                ErrorCode::AuthenticationFailed,
                Some(Phase::Handshake),
                "peer supplied a malformed certificate",
            )
        })
    }
}

/// Returned when a configured public-key fingerprint is malformed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FingerprintParseError;

impl fmt::Display for FingerprintParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("fingerprint must contain exactly 32 hexadecimal bytes")
    }
}

impl std::error::Error for FingerprintParseError {}

impl FromStr for Fingerprint {
    type Err = FingerprintParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let compact = if value.len() == 95 {
            let groups: Vec<_> = value.split(':').collect();
            if groups.len() != 32 || groups.iter().any(|group| group.len() != 2) {
                return Err(FingerprintParseError);
            }
            groups.concat()
        } else if value.len() == 64 {
            value.to_owned()
        } else {
            return Err(FingerprintParseError);
        };

        let mut bytes = [0; 32];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&compact[index * 2..index * 2 + 2], 16)
                .map_err(|_| FingerprintParseError)?;
        }
        Ok(Self(bytes))
    }
}

impl fmt::Debug for Fingerprint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, byte) in self.0.iter().enumerate() {
            if index != 0 {
                formatter.write_str(":")?;
            }
            write!(formatter, "{byte:02X}")?;
        }
        Ok(())
    }
}

/// A locally persisted certificate and private key.
pub struct Identity {
    certificate: CertificateDer<'static>,
    private_key: PrivateKeyDer<'static>,
    fingerprint: Fingerprint,
}

impl Identity {
    /// Loads an identity, creating it with the OS CSPRNG when neither file exists.
    pub fn load_or_create(directory: &Path) -> Result<Self, QuicSyncError> {
        fs::create_dir_all(directory)
            .map_err(|error| identity_error("create identity directory", error))?;
        if !fs::symlink_metadata(directory)
            .map_err(|error| identity_error("inspect identity directory", error))?
            .file_type()
            .is_dir()
        {
            return Err(configuration_error(
                "identity directory must not be a symbolic link",
            ));
        }
        set_directory_permissions(directory)?;

        let certificate_path = directory.join(CERTIFICATE_FILE);
        let private_key_path = directory.join(PRIVATE_KEY_FILE);
        match (certificate_path.exists(), private_key_path.exists()) {
            (true, true) => Self::load(&certificate_path, &private_key_path),
            (false, false) => Self::create(&certificate_path, &private_key_path),
            _ => Err(configuration_error(
                "identity certificate and private key must either both exist or both be absent",
            )),
        }
    }

    pub const fn fingerprint(&self) -> Fingerprint {
        self.fingerprint
    }

    pub fn certificate_der(&self) -> &[u8] {
        self.certificate.as_ref()
    }

    fn load(certificate_path: &Path, private_key_path: &Path) -> Result<Self, QuicSyncError> {
        check_regular_file(certificate_path, "identity certificate")?;
        check_regular_file(private_key_path, "identity private key")?;
        check_private_key_permissions(private_key_path)?;
        let certificate = fs::read(certificate_path)
            .map_err(|error| identity_error("read identity certificate", error))?;
        let private_key = fs::read(private_key_path)
            .map_err(|error| identity_error("read identity private key", error))?;
        Self::from_der(certificate, private_key)
    }

    fn create(certificate_path: &Path, private_key_path: &Path) -> Result<Self, QuicSyncError> {
        let random = SystemRandom::new();
        let private_key_der = Ed25519KeyPair::generate_pkcs8(&random)
            .map_err(|_| configuration_error("generate identity key"))?
            .as_ref()
            .to_vec();
        let key_pair = Ed25519KeyPair::from_pkcs8(&private_key_der)
            .map_err(|_| configuration_error("parse generated identity key"))?;
        let certificate_der = self_signed_certificate(&key_pair, &random)?;

        write_new_private_key(private_key_path, &private_key_der)?;
        if let Err(error) = write_new(certificate_path, &certificate_der) {
            let _ = fs::remove_file(private_key_path);
            return Err(error);
        }

        Self::from_der(certificate_der, private_key_der)
    }

    fn from_der(certificate: Vec<u8>, private_key: Vec<u8>) -> Result<Self, QuicSyncError> {
        let key_pair = Ed25519KeyPair::from_pkcs8(&private_key)
            .map_err(|_| configuration_error("parse identity private key"))?;
        let certificate_fingerprint = fingerprint_certificate(&certificate)
            .map_err(|()| configuration_error("parse identity certificate"))?;
        let key_fingerprint = fingerprint_spki(&ed25519_spki(key_pair.public_key().as_ref()));
        if certificate_fingerprint != key_fingerprint {
            return Err(configuration_error(
                "identity certificate does not match identity private key",
            ));
        }

        Ok(Self {
            certificate: CertificateDer::from(certificate),
            private_key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(private_key)),
            fingerprint: key_fingerprint,
        })
    }
}

/// A public-key fingerprint accepted for a TLS connection.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PeerPin(Fingerprint);

impl PeerPin {
    pub const fn new(fingerprint: Fingerprint) -> Self {
        Self(fingerprint)
    }

    pub const fn fingerprint(self) -> Fingerprint {
        self.0
    }
}

impl FromStr for PeerPin {
    type Err = FingerprintParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        value.parse().map(Self::new)
    }
}

/// The direction in which a peer may synchronize a root.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Direction {
    SourceToDestination,
    DestinationToSource,
}

/// A configured permission for one peer, root ID, and direction.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct PeerGrant {
    pin: PeerPin,
    root_id: String,
    direction: Direction,
}

impl PeerGrant {
    pub fn new(pin: PeerPin, root_id: impl Into<String>, direction: Direction) -> Self {
        Self {
            pin,
            root_id: root_id.into(),
            direction,
        }
    }
}

/// The unforgeable result of a successful root authorization check.
#[derive(Debug)]
pub struct Authorization {
    peer: Fingerprint,
    root_id: String,
    direction: Direction,
}

impl Authorization {
    pub const fn peer(&self) -> Fingerprint {
        self.peer
    }

    pub fn root_id(&self) -> &str {
        &self.root_id
    }

    pub const fn direction(&self) -> Direction {
        self.direction
    }
}

/// A deny-by-default set of peer/root/direction grants.
pub struct Authorizer {
    grants: HashSet<PeerGrant>,
}

impl Authorizer {
    pub fn new(grants: impl IntoIterator<Item = PeerGrant>) -> Result<Self, QuicSyncError> {
        let mut validated = HashSet::new();
        for grant in grants {
            validate_root_id(&grant.root_id)?;
            if !validated.insert(grant) {
                return Err(configuration_error("duplicate peer authorization grant"));
            }
        }
        Ok(Self { grants: validated })
    }

    pub fn authorize(
        &self,
        peer: Fingerprint,
        root_id: &str,
        direction: Direction,
    ) -> Result<Authorization, QuicSyncError> {
        let requested = PeerGrant::new(PeerPin::new(peer), root_id, direction);
        if self.grants.contains(&requested) {
            Ok(Authorization {
                peer,
                root_id: root_id.to_owned(),
                direction,
            })
        } else {
            Err(QuicSyncError::new(
                ErrorCode::AuthorizationDenied,
                Some(Phase::Handshake),
                "peer is not authorized for requested root and direction",
            ))
        }
    }
}

/// Builds a TLS 1.3 client configuration that presents this identity and accepts only the pin.
pub fn client_tls(identity: &Identity, expected: PeerPin) -> Result<ClientConfig, QuicSyncError> {
    let provider = rustls::crypto::ring::default_provider();
    let verifier = Arc::new(PinnedServerVerifier::new(expected, &provider));
    let mut config = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&TLS13])
        .map_err(tls_configuration_error)?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(
            vec![identity.certificate.clone()],
            identity.private_key.clone_key(),
        )
        .map_err(tls_configuration_error)?;
    config.enable_early_data = false;
    Ok(config)
}

/// Builds a TLS 1.3 server configuration requiring a client with an allowed pin.
pub fn server_tls(
    identity: &Identity,
    allowed: impl IntoIterator<Item = PeerPin>,
) -> Result<ServerConfig, QuicSyncError> {
    let pins: HashSet<_> = allowed.into_iter().map(PeerPin::fingerprint).collect();
    if pins.is_empty() {
        return Err(configuration_error(
            "server TLS requires at least one allowed peer pin",
        ));
    }

    let provider = rustls::crypto::ring::default_provider();
    let verifier = Arc::new(PinnedClientVerifier::new(pins, &provider));
    let mut config = ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&TLS13])
        .map_err(tls_configuration_error)?
        .with_client_cert_verifier(verifier)
        .with_single_cert(
            vec![identity.certificate.clone()],
            identity.private_key.clone_key(),
        )
        .map_err(tls_configuration_error)?;
    config.max_early_data_size = 0;
    Ok(config)
}

#[derive(Debug)]
struct PinnedServerVerifier {
    expected: Fingerprint,
    algorithms: WebPkiSupportedAlgorithms,
}

impl PinnedServerVerifier {
    fn new(expected: PeerPin, provider: &rustls::crypto::CryptoProvider) -> Self {
        Self {
            expected: expected.fingerprint(),
            algorithms: provider.signature_verification_algorithms,
        }
    }
}

impl ServerCertVerifier for PinnedServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        verify_pin(end_entity, |fingerprint| fingerprint == self.expected)?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls12_signature(message, certificate, signature, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls13_signature(message, certificate, signature, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

#[derive(Debug)]
struct PinnedClientVerifier {
    allowed: HashSet<Fingerprint>,
    algorithms: WebPkiSupportedAlgorithms,
    hints: Vec<DistinguishedName>,
}

impl PinnedClientVerifier {
    fn new(allowed: HashSet<Fingerprint>, provider: &rustls::crypto::CryptoProvider) -> Self {
        Self {
            allowed,
            algorithms: provider.signature_verification_algorithms,
            hints: Vec::new(),
        }
    }
}

impl ClientCertVerifier for PinnedClientVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &self.hints
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, Error> {
        verify_pin(end_entity, |fingerprint| {
            self.allowed.contains(&fingerprint)
        })?;
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls12_signature(message, certificate, signature, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls13_signature(message, certificate, signature, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

fn verify_pin(
    certificate: &CertificateDer<'_>,
    accepted: impl FnOnce(Fingerprint) -> bool,
) -> Result<(), Error> {
    let fingerprint = fingerprint_certificate(certificate.as_ref())
        .map_err(|_| Error::InvalidCertificate(CertificateError::BadEncoding))?;
    if accepted(fingerprint) {
        Ok(())
    } else {
        Err(Error::InvalidCertificate(CertificateError::UnknownIssuer))
    }
}

fn fingerprint_certificate(certificate: &[u8]) -> Result<Fingerprint, ()> {
    let (certificate_tag, certificate_value, remaining) = der_value(certificate)?;
    if certificate_tag != 0x30 || !remaining.is_empty() {
        return Err(());
    }

    let (tbs_tag, mut tbs, _) = der_value(certificate_value)?;
    if tbs_tag != 0x30 {
        return Err(());
    }
    if tbs.first() == Some(&0xa0) {
        tbs = der_value(tbs)?.2;
    }

    // serial, signature, issuer, validity, and subject precede SubjectPublicKeyInfo.
    for _ in 0..5 {
        tbs = der_value(tbs)?.2;
    }
    let spki_start = tbs;
    let (spki_tag, _, spki_remaining) = der_value(spki_start)?;
    if spki_tag != 0x30 {
        return Err(());
    }
    let spki_length = spki_start.len() - spki_remaining.len();
    Ok(fingerprint_spki(&spki_start[..spki_length]))
}

fn der_value(input: &[u8]) -> Result<(u8, &[u8], &[u8]), ()> {
    let (&tag, after_tag) = input.split_first().ok_or(())?;
    let (&first_length, after_first_length) = after_tag.split_first().ok_or(())?;
    let (length, value_and_remaining) = if first_length & 0x80 == 0 {
        (usize::from(first_length), after_first_length)
    } else {
        let length_bytes = usize::from(first_length & 0x7f);
        if length_bytes == 0 || length_bytes > std::mem::size_of::<usize>() {
            return Err(());
        }
        let (encoded_length, rest) = after_first_length
            .split_at_checked(length_bytes)
            .ok_or(())?;
        if encoded_length[0] == 0 {
            return Err(());
        }
        let length = encoded_length
            .iter()
            .try_fold(0usize, |length, byte| {
                length
                    .checked_mul(256)
                    .and_then(|length| length.checked_add(usize::from(*byte)))
            })
            .ok_or(())?;
        if length < 128 {
            return Err(());
        }
        (length, rest)
    };
    let (value, remaining) = value_and_remaining.split_at_checked(length).ok_or(())?;
    Ok((tag, value, remaining))
}

fn fingerprint_spki(spki: &[u8]) -> Fingerprint {
    Fingerprint(Sha256::digest(spki).into())
}

fn self_signed_certificate(
    key_pair: &Ed25519KeyPair,
    random: &SystemRandom,
) -> Result<Vec<u8>, QuicSyncError> {
    const ED25519_ALGORITHM: &[u8] = &[0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70];
    const EMPTY_NAME: &[u8] = &[0x30, 0x00];
    const VALIDITY: &[u8] = &[
        0x30, 0x1e, 0x17, 0x0d, b'2', b'5', b'0', b'1', b'0', b'1', b'0', b'0', b'0', b'0', b'0',
        b'0', b'Z', 0x17, 0x0d, b'4', b'9', b'1', b'2', b'3', b'1', b'2', b'3', b'5', b'9', b'5',
        b'9', b'Z',
    ];

    let mut serial = [0; 16];
    random
        .fill(&mut serial)
        .map_err(|_| configuration_error("generate certificate serial number"))?;
    serial[0] &= 0x7f;
    if serial[0] == 0 {
        serial[0] = 1;
    }

    let version = der(0xa0, &der(0x02, &[2]));
    let serial = der(0x02, &serial);
    let spki = ed25519_spki(key_pair.public_key().as_ref());
    let tbs = der_sequence(&[
        &version,
        &serial,
        ED25519_ALGORITHM,
        EMPTY_NAME,
        VALIDITY,
        EMPTY_NAME,
        &spki,
    ]);
    let signature = key_pair.sign(&tbs);
    let mut signature_bits = Vec::with_capacity(signature.as_ref().len() + 1);
    signature_bits.push(0);
    signature_bits.extend_from_slice(signature.as_ref());
    let signature = der(0x03, &signature_bits);

    Ok(der_sequence(&[&tbs, ED25519_ALGORITHM, &signature]))
}

fn ed25519_spki(public_key: &[u8]) -> Vec<u8> {
    const ED25519_ALGORITHM: &[u8] = &[0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70];
    let mut public_key_bits = Vec::with_capacity(public_key.len() + 1);
    public_key_bits.push(0);
    public_key_bits.extend_from_slice(public_key);
    let public_key_bits = der(0x03, &public_key_bits);
    der_sequence(&[ED25519_ALGORITHM, &public_key_bits])
}

fn der_sequence(values: &[&[u8]]) -> Vec<u8> {
    let length = values.iter().map(|value| value.len()).sum();
    let mut contents = Vec::with_capacity(length);
    for value in values {
        contents.extend_from_slice(value);
    }
    der(0x30, &contents)
}

fn der(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(value.len() + 6);
    encoded.push(tag);
    if value.len() < 128 {
        encoded.push(value.len() as u8);
    } else {
        let bytes = value.len().to_be_bytes();
        let first = bytes
            .iter()
            .position(|byte| *byte != 0)
            .unwrap_or(bytes.len() - 1);
        encoded.push(0x80 | (bytes.len() - first) as u8);
        encoded.extend_from_slice(&bytes[first..]);
    }
    encoded.extend_from_slice(value);
    encoded
}

fn validate_root_id(root_id: &str) -> Result<(), QuicSyncError> {
    if root_id.is_empty()
        || root_id.len() > 255
        || root_id.bytes().any(|byte| {
            !byte.is_ascii_alphanumeric() && byte != b'-' && byte != b'_' && byte != b'.'
        })
    {
        return Err(configuration_error(
            "root ID must be 1-255 ASCII letters, digits, dots, dashes, or underscores",
        ));
    }
    Ok(())
}

fn write_new(path: &Path, contents: &[u8]) -> Result<(), QuicSyncError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    let mut file = options
        .open(path)
        .map_err(|error| identity_error("create identity file", error))?;
    file.write_all(contents)
        .and_then(|()| file.sync_all())
        .map_err(|error| identity_error("persist identity file", error))
}

#[cfg(unix)]
fn write_new_private_key(path: &Path, contents: &[u8]) -> Result<(), QuicSyncError> {
    use std::os::unix::fs::OpenOptionsExt;

    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    let mut file = options
        .open(path)
        .map_err(|error| identity_error("create identity private key", error))?;
    file.write_all(contents)
        .and_then(|()| file.sync_all())
        .map_err(|error| identity_error("persist identity private key", error))
}

#[cfg(not(unix))]
fn write_new_private_key(path: &Path, contents: &[u8]) -> Result<(), QuicSyncError> {
    write_new(path, contents)
}

#[cfg(unix)]
fn set_directory_permissions(directory: &Path) -> Result<(), QuicSyncError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let metadata = fs::symlink_metadata(directory)
        .map_err(|error| identity_error("inspect identity directory", error))?;
    if metadata.uid() != rustix::process::geteuid().as_raw() {
        return Err(configuration_error(
            "identity directory must be owned by the current user",
        ));
    }

    fs::set_permissions(directory, fs::Permissions::from_mode(0o700))
        .map_err(|error| identity_error("secure identity directory", error))
}

#[cfg(not(unix))]
fn set_directory_permissions(_directory: &Path) -> Result<(), QuicSyncError> {
    Ok(())
}

#[cfg(unix)]
fn check_private_key_permissions(path: &Path) -> Result<(), QuicSyncError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let metadata = fs::metadata(path)
        .map_err(|error| identity_error("inspect identity private key", error))?;
    if metadata.uid() != rustix::process::geteuid().as_raw() {
        return Err(configuration_error(
            "identity private key must be owned by the current user",
        ));
    }
    let mode = metadata.permissions().mode();
    if mode & 0o077 != 0 {
        return Err(configuration_error(
            "identity private key must not be accessible by group or other users",
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_private_key_permissions(_path: &Path) -> Result<(), QuicSyncError> {
    Ok(())
}

fn check_regular_file(path: &Path, name: &str) -> Result<(), QuicSyncError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| identity_error("inspect identity file", error))?;
    if !metadata.file_type().is_file() {
        return Err(configuration_error(format!(
            "{name} must be a regular file"
        )));
    }
    Ok(())
}

fn identity_error(action: &str, error: std::io::Error) -> QuicSyncError {
    configuration_error(format!("{action}: {error}"))
}

fn tls_configuration_error(error: Error) -> QuicSyncError {
    configuration_error(format!("configure TLS: {error}"))
}

fn configuration_error(diagnostic: impl Into<String>) -> QuicSyncError {
    QuicSyncError::new(ErrorCode::InvalidConfiguration, None, diagnostic)
}
