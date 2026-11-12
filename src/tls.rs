//! The mTLS listener (`--https-listen`, docs/tee.md): the node's API over TLS 1.3, to clients that
//! present a certificate from the operator's CA (`--client-ca`).
//!
//! The server's key and certificates are made in the node's vault by `eth-mpc-signer identity`:
//! - a node CA (self-signed; its key is used once and dropped);
//! - a server certificate it signs for the names given with `--tls-san`.
//!
//! Clients pin the node CA, which `GET /attestation` returns. The attested keys include the
//! SubjectPublicKeyInfo hash of the server key, so a client can check that the key it talks to is
//! the attested one.
//!
//! Handshakes run in their own tasks, at most [MAX_HANDSHAKES] at once, each for at most
//! [HANDSHAKE_TIMEOUT]: a slow or silent client delays nobody else.
//!
//! **Revoked clients** ([Revocations], `--revoked-client-certs`). A certificate listed by the
//! SHA-256 of its DER is refused:
//! - as a client's leaf or intermediate, in the handshake;
//! - as a CA of the client CA file: it no longer issues clients.
//!
//! The list is read again while the server runs. A change applies to new handshakes at once. A
//! connection whose client it revokes is closed at its next read.

use crate::attestation::Keys;
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, PublicKeyData as _,
};
use rustls::{
    CertificateError, ClientConfig, DigitallySignedStruct, DistinguishedName, RootCertStore,
    ServerConfig, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::{CryptoProvider, aws_lc_rs},
    pki_types::{
        CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime,
        pem::PemObject as _,
    },
    server::{
        WebPkiClientVerifier,
        danger::{ClientCertVerified, ClientCertVerifier},
    },
};
use std::{
    collections::HashSet,
    future::Future,
    io,
    net::SocketAddr,
    path::{Path, PathBuf},
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{TcpListener, TcpStream},
    sync::{Semaphore, mpsc, watch},
};
use tokio_rustls::{TlsAcceptor, server::TlsStream};
use zeroize::Zeroizing;

/// Handshakes in progress at most.
pub const MAX_HANDSHAKES: usize = 64;
/// How long a handshake may take.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// A server key and its certificates, as `identity` makes them.
pub struct Made {
    /// PKCS#8 DER of the server key (sealed in the vault).
    pub key: Zeroizing<Vec<u8>>,
    /// The server certificate, then the node CA (PEM).
    pub chain: String,
}

/// A new server key, a new node CA, and a server certificate for `names` (IP addresses or DNS
/// names), valid for a century: clients pin the CA, not a validity period.
pub fn make(names: &[String]) -> Result<Made, String> {
    let error = |err: rcgen::Error| err.to_string();
    let ca_key = KeyPair::generate().map_err(error)?;
    let mut ca = CertificateParams::new(Vec::<String>::new()).map_err(error)?;
    ca.distinguished_name
        .push(DnType::CommonName, "eth-mpc-signer node CA");
    ca.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    ca.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    ca.not_before = rcgen::date_time_ymd(2026, 1, 1);
    ca.not_after = rcgen::date_time_ymd(2126, 1, 1);
    let ca_certificate = ca.self_signed(&ca_key).map_err(error)?;
    let issuer = Issuer::new(ca, ca_key);

    let key = KeyPair::generate().map_err(error)?;
    let mut server = CertificateParams::new(names.to_vec()).map_err(error)?;
    server
        .distinguished_name
        .push(DnType::CommonName, "eth-mpc-signer node");
    server.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    server.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    server.not_before = rcgen::date_time_ymd(2026, 1, 1);
    server.not_after = rcgen::date_time_ymd(2126, 1, 1);
    let certificate = server.signed_by(&key, &issuer).map_err(error)?;
    Ok(Made {
        key: Zeroizing::new(key.serialize_der()),
        chain: format!("{}{}", certificate.pem(), ca_certificate.pem()),
    })
}

/// The SubjectPublicKeyInfo (DER) of a PKCS#8 key: what attestation binds.
pub fn spki(key: &[u8]) -> Result<Vec<u8>, String> {
    KeyPair::try_from(key)
        .map(|key| key.subject_public_key_info())
        .map_err(|err| format!("TLS key: {err}"))
}

/// The SubjectPublicKeyInfo (DER) of a certificate (DER): what a client compares with the attested
/// key of a node it reached.
pub fn certificate_spki(certificate: &[u8]) -> Result<Vec<u8>, String> {
    let certificate = CertificateDer::from(certificate);
    let parsed = webpki::EndEntityCert::try_from(&certificate)
        .map_err(|err| format!("certificate: {err}"))?;
    Ok(parsed.subject_public_key_info().as_ref().to_vec())
}

/// Certificates from PEM.
pub fn certificates(pem: &str) -> Result<Vec<CertificateDer<'static>>, String> {
    let certificates = CertificateDer::pem_slice_iter(pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| format!("PEM: {err}"))?;
    if certificates.is_empty() {
        return Err("PEM: no certificate".into());
    }
    Ok(certificates)
}

/// How often a revocation list file is read again ([Revocations::from_file]).
pub const REVOCATIONS_RELOAD: Duration = Duration::from_secs(5);

/// The SHA-256 of a certificate's DER: how a revocation list names it.
pub fn fingerprint(certificate: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(
        ::aws_lc_rs::digest::digest(&::aws_lc_rs::digest::SHA256, certificate).as_ref(),
    );
    out
}

/// A revocation list: one certificate per line, the SHA-256 of its DER in hex, with or without
/// colons. `openssl x509 -noout -fingerprint -sha256` prints such a line (after
/// `sha256 Fingerprint=`), which is taken as it is. Blank lines and `#` comments are skipped.
pub fn parse_revocations(text: &str) -> Result<HashSet<[u8; 32]>, String> {
    let mut revoked = HashSet::new();
    for (index, line) in text.lines().enumerate() {
        let line = line.split('#').next().unwrap_or_default().trim();
        if line.is_empty() {
            continue;
        }
        let value = match line.split_once('=') {
            Some((label, value)) if label.trim().eq_ignore_ascii_case("sha256 fingerprint") => {
                value.trim()
            }
            Some(_) => return Err(format!("line {}: not a SHA-256 fingerprint", index + 1)),
            None => line,
        };
        let digits: String = value.chars().filter(|c| *c != ':').collect();
        let bytes = hex::decode(&digits)
            .ok()
            .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
            .ok_or_else(|| {
                format!(
                    "line {}: not a SHA-256 fingerprint (64 hex digits)",
                    index + 1
                )
            })?;
        revoked.insert(bytes);
    }
    Ok(revoked)
}

/// The certificates a server refuses as clients (`--revoked-client-certs`): the list in force,
/// which [Revocations::from_file] keeps up to date with its file.
#[derive(Clone, Debug)]
pub struct Revocations(watch::Receiver<Arc<HashSet<[u8; 32]>>>);

impl Revocations {
    /// None revoked.
    pub fn none() -> Self {
        Self::fixed(HashSet::new())
    }

    /// These, for good.
    pub fn fixed(revoked: HashSet<[u8; 32]>) -> Self {
        Self(watch::channel(Arc::new(revoked)).1)
    }

    /// The list in `path`, read now: an error if it cannot be read or parsed. The future,
    /// spawned by the caller, reads it again every `every` while a server uses the list; a
    /// change is logged. A file that later cannot be read or parsed leaves the list in force,
    /// with a warning.
    pub fn from_file(
        path: &Path,
        every: Duration,
    ) -> Result<(Self, impl Future<Output = ()> + Send + 'static), String> {
        let read = |path: &Path| {
            std::fs::read_to_string(path)
                .map_err(|err| err.to_string())
                .and_then(|text| parse_revocations(&text))
                .map_err(|err| format!("{}: {err}", path.display()))
        };
        let (sender, receiver) = watch::channel(Arc::new(read(path)?));
        let path: PathBuf = path.to_path_buf();
        let reload = async move {
            let mut interval = tokio::time::interval(every);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                interval.tick().await;
                if sender.is_closed() {
                    return;
                }
                match read(&path) {
                    Ok(revoked) if revoked != **sender.borrow() => {
                        tracing::info!(revoked = revoked.len(), path = %path.display(), "revoked client certificates: the list changed");
                        sender.send_replace(Arc::new(revoked));
                    }
                    Ok(_) => {}
                    Err(err) => {
                        tracing::warn!(%err, "revoked client certificates: the list in force stays")
                    }
                }
            }
        };
        Ok((Self(receiver), reload))
    }

    /// The list in force.
    pub fn current(&self) -> Arc<HashSet<[u8; 32]>> {
        self.0.borrow().clone()
    }
}

/// A revocation list, by the certificates' SHA-256.
type Revoked = Arc<HashSet<[u8; 32]>>;

/// A client verifier that refuses revoked certificates before the operator CA's checks.
#[derive(Debug)]
struct Revoking {
    roots: Vec<CertificateDer<'static>>,
    provider: Arc<CryptoProvider>,
    revoked: Revocations,
    /// Every root's verifier: hints, signatures and schemes, which revocation does not change.
    all: Arc<dyn ClientCertVerifier>,
    /// The verifier of the roots the list in force does not revoke, and that list.
    current: Mutex<(Revoked, Arc<dyn ClientCertVerifier>)>,
}

fn client_verifier(
    roots: &[CertificateDer<'static>],
    provider: &Arc<CryptoProvider>,
    revoked: &HashSet<[u8; 32]>,
) -> Result<Arc<dyn ClientCertVerifier>, String> {
    let mut store = RootCertStore::empty();
    for root in roots {
        if !revoked.contains(&fingerprint(root)) {
            store
                .add(root.clone())
                .map_err(|err| format!("client CA: {err}"))?;
        }
    }
    WebPkiClientVerifier::builder_with_provider(Arc::new(store), provider.clone())
        .build()
        .map_err(|err| format!("client CA (every one revoked?): {err}"))
}

impl Revoking {
    fn new(
        roots: Vec<CertificateDer<'static>>,
        provider: Arc<CryptoProvider>,
        revoked: Revocations,
    ) -> Result<Self, String> {
        let all = client_verifier(&roots, &provider, &HashSet::new())?;
        let list = revoked.current();
        let current = client_verifier(&roots, &provider, &list)?;
        Ok(Self {
            roots,
            provider,
            revoked,
            all,
            current: Mutex::new((list, current)),
        })
    }

    /// The verifier for the list in force, made again when the list changed.
    fn current(&self) -> Result<Arc<dyn ClientCertVerifier>, rustls::Error> {
        let list = self.revoked.current();
        let mut current = self
            .current
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !Arc::ptr_eq(&current.0, &list) {
            let verifier = client_verifier(&self.roots, &self.provider, &list)
                .map_err(rustls::Error::General)?;
            *current = (list, verifier);
        }
        Ok(current.1.clone())
    }
}

impl ClientCertVerifier for Revoking {
    fn offer_client_auth(&self) -> bool {
        self.all.offer_client_auth()
    }

    fn client_auth_mandatory(&self) -> bool {
        self.all.client_auth_mandatory()
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        self.all.root_hint_subjects()
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        let revoked = self.revoked.current();
        if let Some(listed) = std::iter::once(end_entity)
            .chain(intermediates)
            .map(|certificate| fingerprint(certificate))
            .find(|fingerprint| revoked.contains(fingerprint))
        {
            tracing::warn!(certificate = %hex::encode(listed), "TLS: a revoked client certificate refused");
            return Err(rustls::Error::InvalidCertificate(CertificateError::Revoked));
        }
        self.current()?
            .verify_client_cert(end_entity, intermediates, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.all.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.all.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.all.supported_verify_schemes()
    }
}

/// The server's TLS configuration: TLS 1.3 only, a client certificate from `client_ca` required,
/// none that `revoked` lists.
pub fn server_config(
    key: &[u8],
    chain: &str,
    client_ca: &str,
    revoked: &Revocations,
) -> Result<Arc<ServerConfig>, String> {
    server_config_versions(key, chain, client_ca, false, revoked)
}

/// [server_config], also offering TLS 1.2 with `tls12` (Teku speaks only TLS 1.2 to an external
/// signer; rustls offers it with ECDHE key exchange and AEAD ciphers only).
pub fn server_config_versions(
    key: &[u8],
    chain: &str,
    client_ca: &str,
    tls12: bool,
    revoked: &Revocations,
) -> Result<Arc<ServerConfig>, String> {
    let provider = Arc::new(aws_lc_rs::default_provider());
    let verifier = Arc::new(Revoking::new(
        certificates(client_ca)?,
        provider.clone(),
        revoked.clone(),
    )?);
    let versions: &[&rustls::SupportedProtocolVersion] = if tls12 {
        &[&rustls::version::TLS13, &rustls::version::TLS12]
    } else {
        &[&rustls::version::TLS13]
    };
    let config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(versions)
        .map_err(|err| err.to_string())?
        .with_client_cert_verifier(verifier)
        .with_single_cert(
            certificates(chain)?,
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.to_vec())),
        )
        .map_err(|err| format!("server certificate: {err}"))?;
    Ok(Arc::new(config))
}

/// A client's TLS configuration: TLS 1.3, the server checked by `verifier`, and the client
/// certificate `chain` with its `key` (PEM files' contents).
pub fn client_config(
    chain: &[u8],
    key: &[u8],
    verifier: Arc<dyn ServerCertVerifier>,
) -> Result<ClientConfig, String> {
    let chain = CertificateDer::pem_slice_iter(chain)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| format!("client certificate: {err}"))?;
    let key = PrivateKeyDer::from_pem_slice(key).map_err(|err| format!("client key: {err}"))?;
    ClientConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|err| err.to_string())?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(chain, key)
        .map_err(|err| format!("client certificate: {err}"))
}

/// Accepts any server certificate whose key signs the handshake. For a client that checks the key
/// after the answer, against a node's attestation (`Keys::serves`): `mpc-admin attest`, and the
/// gateway's attestation requests.
#[derive(Debug)]
pub struct AnyServerKey(Arc<CryptoProvider>);

impl AnyServerKey {
    pub fn new() -> Arc<Self> {
        Arc::new(Self(Arc::new(aws_lc_rs::default_provider())))
    }
}

/// Accepts only the server key a node's attestation names ([AttestedServerKey::pin]); none before.
/// The gateway's connections to a sealed node, once its attestation verified.
#[derive(Debug)]
pub struct AttestedServerKey {
    provider: Arc<CryptoProvider>,
    keys: std::sync::RwLock<Option<Keys>>,
}

impl AttestedServerKey {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            provider: Arc::new(aws_lc_rs::default_provider()),
            keys: std::sync::RwLock::new(None),
        })
    }

    /// From now on, only the TLS key `keys` attest.
    pub fn pin(&self, keys: Keys) {
        *self
            .keys
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(keys);
    }
}

/// The handshake's signature, checked with `provider`: the server holds its certificate's key.
fn handshake_signatures(provider: &CryptoProvider) -> &rustls::crypto::WebPkiSupportedAlgorithms {
    &provider.signature_verification_algorithms
}

macro_rules! handshake_checks {
    () => {
        fn verify_tls12_signature(
            &self,
            message: &[u8],
            certificate: &CertificateDer<'_>,
            signature: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls12_signature(
                message,
                certificate,
                signature,
                handshake_signatures(self.provider()),
            )
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            certificate: &CertificateDer<'_>,
            signature: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls13_signature(
                message,
                certificate,
                signature,
                handshake_signatures(self.provider()),
            )
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            handshake_signatures(self.provider()).supported_schemes()
        }
    };
}

impl AnyServerKey {
    fn provider(&self) -> &CryptoProvider {
        &self.0
    }
}

impl AttestedServerKey {
    fn provider(&self) -> &CryptoProvider {
        &self.provider
    }
}

impl ServerCertVerifier for AnyServerKey {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    handshake_checks!();
}

impl ServerCertVerifier for AttestedServerKey {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let keys = self
            .keys
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match keys.as_ref() {
            Some(keys) if keys.serves(end_entity.as_ref()) => Ok(ServerCertVerified::assertion()),
            Some(_) => Err(rustls::Error::General(
                "the server's key is not the attested one".into(),
            )),
            None => Err(rustls::Error::General(
                "the server is not attested yet".into(),
            )),
        }
    }

    handshake_checks!();
}

/// An accepted connection. Once the list in force revokes a certificate its client presented, it
/// is closed at its next read.
pub struct Connection {
    tls: TlsStream<TcpStream>,
    /// The fingerprints of the certificates the client presented.
    chain: Vec<[u8; 32]>,
    revoked: Revocations,
    closed: bool,
}

impl Connection {
    fn new(tls: TlsStream<TcpStream>, revoked: Revocations) -> Self {
        let chain = tls
            .get_ref()
            .1
            .peer_certificates()
            .unwrap_or_default()
            .iter()
            .map(|certificate| fingerprint(certificate))
            .collect();
        Self {
            tls,
            chain,
            revoked,
            closed: false,
        }
    }

    /// Whether the list in force revokes this client (checked again only when it changed).
    fn revoked(&mut self) -> bool {
        if !self.closed && self.revoked.0.has_changed().unwrap_or(false) {
            let revoked = self.revoked.0.borrow_and_update().clone();
            self.closed = self.chain.iter().any(|link| revoked.contains(link));
            if self.closed {
                tracing::warn!("TLS: closing a connection whose client certificate is revoked");
            }
        }
        self.closed
    }
}

impl AsyncRead for Connection {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.revoked() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "the client certificate is revoked",
            )));
        }
        Pin::new(&mut this.tls).poll_read(cx, buf)
    }
}

impl AsyncWrite for Connection {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().tls).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().tls).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().tls).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().tls).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.tls.is_write_vectored()
    }
}

/// Accepted TLS connections, for `axum::serve`.
pub struct Listener {
    connections: mpsc::Receiver<(Connection, SocketAddr)>,
    local: SocketAddr,
}

impl Listener {
    /// Bind `address` and accept connections in the background; `revoked` is the list
    /// `config` was made with, which closes the connections of clients it revokes later.
    pub async fn bind(
        address: SocketAddr,
        config: Arc<ServerConfig>,
        revoked: Revocations,
    ) -> io::Result<Self> {
        let tcp = TcpListener::bind(address).await?;
        let local = tcp.local_addr()?;
        let (sender, connections) = mpsc::channel(MAX_HANDSHAKES);
        let acceptor = TlsAcceptor::from(config);
        let permits = Arc::new(Semaphore::new(MAX_HANDSHAKES));
        tokio::spawn(async move {
            loop {
                let Ok(permit) = permits.clone().acquire_owned().await else {
                    return;
                };
                let (stream, peer) = match tcp.accept().await {
                    Ok(accepted) => accepted,
                    Err(err) => {
                        tracing::warn!(%err, "TLS listener: accept failed");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                };
                let acceptor = acceptor.clone();
                let forward = sender.clone();
                let revoked = revoked.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    match tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await {
                        Ok(Ok(tls)) => {
                            let _ = forward.send((Connection::new(tls, revoked), peer)).await;
                        }
                        Ok(Err(err)) => tracing::debug!(%peer, %err, "TLS handshake refused"),
                        Err(_) => tracing::debug!(%peer, "TLS handshake timed out"),
                    }
                });
                if sender.is_closed() {
                    return;
                }
            }
        });
        Ok(Self { connections, local })
    }
}

impl axum::serve::Listener for Listener {
    type Io = Connection;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        match self.connections.recv().await {
            Some(connection) => connection,
            // The accept task never ends while this receiver exists.
            None => std::future::pending().await,
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        Ok(self.local)
    }
}

#[cfg(test)]
#[path = "../tests/unit/tls.rs"]
mod tests;
