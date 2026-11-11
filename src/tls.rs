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

use crate::attestation::Keys;
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, PublicKeyData as _,
};
use rustls::{
    ClientConfig, DigitallySignedStruct, RootCertStore, ServerConfig, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::{CryptoProvider, aws_lc_rs},
    pki_types::{
        CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime,
        pem::PemObject as _,
    },
    server::WebPkiClientVerifier,
};
use std::{io, net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{Semaphore, mpsc},
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

/// The server's TLS configuration: TLS 1.3 only, a client certificate from `client_ca` required.
pub fn server_config(
    key: &[u8],
    chain: &str,
    client_ca: &str,
) -> Result<Arc<ServerConfig>, String> {
    server_config_versions(key, chain, client_ca, false)
}

/// [server_config], also offering TLS 1.2 with `tls12` (Teku speaks only TLS 1.2 to an external
/// signer; rustls offers it with ECDHE key exchange and AEAD ciphers only).
pub fn server_config_versions(
    key: &[u8],
    chain: &str,
    client_ca: &str,
    tls12: bool,
) -> Result<Arc<ServerConfig>, String> {
    let provider = Arc::new(aws_lc_rs::default_provider());
    let mut roots = RootCertStore::empty();
    for certificate in certificates(client_ca)? {
        roots
            .add(certificate)
            .map_err(|err| format!("client CA: {err}"))?;
    }
    let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone())
        .build()
        .map_err(|err| format!("client CA: {err}"))?;
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

/// Accepted TLS connections, for `axum::serve`.
pub struct Listener {
    connections: mpsc::Receiver<(TlsStream<TcpStream>, SocketAddr)>,
    local: SocketAddr,
}

impl Listener {
    /// Bind `address` and accept connections in the background.
    pub async fn bind(address: SocketAddr, config: Arc<ServerConfig>) -> io::Result<Self> {
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
                tokio::spawn(async move {
                    let _permit = permit;
                    match tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await {
                        Ok(Ok(tls)) => {
                            let _ = forward.send((tls, peer)).await;
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
    type Io = TlsStream<TcpStream>;
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
