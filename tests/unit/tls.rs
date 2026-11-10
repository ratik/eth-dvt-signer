use super::*;
use rustls::ClientConfig;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio_rustls::TlsConnector;

fn block_on<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(future)
}

/// An operator CA and a client certificate it signs (PEM CA, chain, PKCS#8 key).
fn operator() -> (String, Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let ca_key = KeyPair::generate().unwrap();
    let mut ca = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_pem = ca.self_signed(&ca_key).unwrap().pem();
    let issuer = Issuer::new(ca, ca_key);
    let key = KeyPair::generate().unwrap();
    let mut client = CertificateParams::new(Vec::<String>::new()).unwrap();
    client.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let certificate = client.signed_by(&key, &issuer).unwrap();
    (
        ca_pem,
        vec![certificate.der().clone()],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
    )
}

/// A client that pins `node_chain`'s CA, with `identity` as its certificate if any.
fn client(
    node_chain: &str,
    identity: Option<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>,
) -> TlsConnector {
    let mut roots = RootCertStore::empty();
    let chain = certificates(node_chain).unwrap();
    roots.add(chain.last().unwrap().clone()).unwrap();
    let builder = ClientConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots);
    let config = match identity {
        Some((chain, key)) => builder.with_client_auth_cert(chain, key).unwrap(),
        None => builder.with_no_client_auth(),
    };
    TlsConnector::from(Arc::new(config))
}

/// One request over TLS to an echo-style server: the server's certificate and the reply.
async fn exchange(
    connector: TlsConnector,
    address: SocketAddr,
) -> Result<(CertificateDer<'static>, Vec<u8>), String> {
    let tcp = TcpStream::connect(address)
        .await
        .map_err(|err| err.to_string())?;
    let name = rustls::pki_types::ServerName::try_from("127.0.0.1").unwrap();
    let mut tls = connector
        .connect(name, tcp)
        .await
        .map_err(|err| err.to_string())?;
    let certificate = tls.get_ref().1.peer_certificates().unwrap()[0].clone();
    tls.write_all(b"ping")
        .await
        .map_err(|err| err.to_string())?;
    let mut reply = Vec::new();
    tls.read_to_end(&mut reply)
        .await
        .map_err(|err| err.to_string())?;
    if reply.is_empty() {
        return Err("no reply: the server closed the connection".into());
    }
    Ok((certificate, reply))
}

#[test]
fn only_clients_of_the_operator_ca_reach_the_attested_key() {
    block_on(async {
        let made = make(&["127.0.0.1".to_string()]).unwrap();
        let (ca, client_chain, client_key) = operator();
        let config = server_config(&made.key, &made.chain, &ca).unwrap();
        let mut listener = Listener::bind("127.0.0.1:0".parse().unwrap(), config)
            .await
            .unwrap();
        let address = axum::serve::Listener::local_addr(&listener).unwrap();
        tokio::spawn(async move {
            loop {
                let (mut tls, _) = axum::serve::Listener::accept(&mut listener).await;
                tokio::spawn(async move {
                    let mut request = [0u8; 4];
                    if tls.read_exact(&mut request).await.is_ok() {
                        let _ = tls.write_all(b"pong").await;
                        let _ = tls.shutdown().await;
                    }
                });
            }
        });

        // A client of the operator CA reaches the node, and the key it sees is the attested one.
        let (certificate, reply) = exchange(
            client(&made.chain, Some((client_chain, client_key))),
            address,
        )
        .await
        .unwrap();
        assert_eq!(reply, b"pong");
        let attested = spki(&made.key).unwrap();
        assert!(
            certificate
                .as_ref()
                .windows(attested.len())
                .any(|window| window == attested.as_slice()),
            "the served certificate carries the attested key"
        );

        // Without a client certificate, or with one from another CA, nothing gets through.
        assert!(exchange(client(&made.chain, None), address).await.is_err());
        let (_, other_chain, other_key) = operator();
        assert!(
            exchange(client(&made.chain, Some((other_chain, other_key))), address)
                .await
                .is_err()
        );
    });
}

#[test]
fn a_made_chain_is_a_server_certificate_then_its_ca() {
    let made = make(&["10.0.0.2".to_string(), "node-2.example".to_string()]).unwrap();
    let chain = certificates(&made.chain).unwrap();
    assert_eq!(chain.len(), 2);
    assert!(spki(&made.key).is_ok());
    assert!(server_config(&made.key, &made.chain, "not pem").is_err());
    assert!(certificates("").is_err());
}
