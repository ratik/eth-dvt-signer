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
        let config = server_config(&made.key, &made.chain, &ca, &Revocations::none()).unwrap();
        let mut listener =
            Listener::bind("127.0.0.1:0".parse().unwrap(), config, Revocations::none())
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
    assert!(server_config(&made.key, &made.chain, "not pem", &Revocations::none()).is_err());
    assert!(certificates("").is_err());
}

/// A CA: its PEM, its DER and its issuer.
fn ca() -> (String, CertificateDer<'static>, Issuer<'static, KeyPair>) {
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let certificate = params.self_signed(&key).unwrap();
    (
        certificate.pem(),
        certificate.der().clone(),
        Issuer::new(params, key),
    )
}

/// An intermediate CA under `issuer`: its DER and its issuer.
fn intermediate(
    issuer: &Issuer<'_, KeyPair>,
) -> (CertificateDer<'static>, Issuer<'static, KeyPair>) {
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let certificate = params.signed_by(&key, issuer).unwrap();
    (certificate.der().clone(), Issuer::new(params, key))
}

/// A client certificate `issuer` signs, presented with `intermediates`.
fn leaf(
    issuer: &Issuer<'_, KeyPair>,
    intermediates: &[CertificateDer<'static>],
) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let certificate = params.signed_by(&key, issuer).unwrap();
    let mut chain = vec![certificate.der().clone()];
    chain.extend(intermediates.iter().cloned());
    (
        chain,
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
    )
}

/// A server on `made`'s key that answers each 4-byte request with `pong`, on one connection
/// for as long as the client keeps it.
async fn pong_server(made: &Made, client_ca: &str, revoked: Revocations) -> SocketAddr {
    let config = server_config(&made.key, &made.chain, client_ca, &revoked).unwrap();
    let mut listener = Listener::bind("127.0.0.1:0".parse().unwrap(), config, revoked)
        .await
        .unwrap();
    let address = axum::serve::Listener::local_addr(&listener).unwrap();
    tokio::spawn(async move {
        loop {
            let (mut tls, _) = axum::serve::Listener::accept(&mut listener).await;
            tokio::spawn(async move {
                let mut request = [0u8; 4];
                while tls.read_exact(&mut request).await.is_ok() {
                    if tls.write_all(b"pong").await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    address
}

type Session = tokio_rustls::client::TlsStream<TcpStream>;

async fn connect(
    made: &Made,
    address: SocketAddr,
    identity: &(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>),
) -> std::io::Result<Session> {
    let tcp = TcpStream::connect(address).await?;
    let name = rustls::pki_types::ServerName::try_from("127.0.0.1").unwrap();
    client(
        &made.chain,
        Some((identity.0.clone(), identity.1.clone_key())),
    )
    .connect(name, tcp)
    .await
}

/// One request on `session`: whether `pong` came back. (In TLS 1.3 a refused client
/// certificate shows here, after the client's side of the handshake.)
async fn ping(session: &mut Session) -> bool {
    let mut reply = [0u8; 4];
    session.write_all(b"ping").await.is_ok()
        && tokio::time::timeout(Duration::from_secs(5), session.read_exact(&mut reply))
            .await
            .is_ok_and(|read| read.is_ok())
        && &reply == b"pong"
}

async fn reaches(
    made: &Made,
    address: SocketAddr,
    identity: &(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>),
) -> bool {
    match connect(made, address, identity).await {
        Ok(mut session) => ping(&mut session).await,
        Err(_) => false,
    }
}

#[test]
fn a_revocation_list_names_certificates_by_their_sha256() {
    let a = fingerprint(b"a");
    let b = fingerprint(b"b");
    let colons = |bytes: &[u8; 32]| {
        bytes
            .iter()
            .map(|byte| format!("{byte:02X}"))
            .collect::<Vec<_>>()
            .join(":")
    };
    let text = format!(
        "# revoked 2026-11-12\n\n{}\nsha256 Fingerprint={}  # openssl's line\n",
        hex::encode(a),
        colons(&b)
    );
    assert_eq!(parse_revocations(&text).unwrap(), HashSet::from([a, b]));
    assert_eq!(
        parse_revocations(&format!("SHA256 Fingerprint={}\n", colons(&a))).unwrap(),
        HashSet::from([a])
    );
    for bad in [
        "abcd\n",
        "sha1 Fingerprint=AB:CD\n",
        &format!("{}00\n", hex::encode(a)),
        "not hex at all, sixty-four characters long, more or less, really\n",
    ] {
        assert!(parse_revocations(bad).is_err(), "{bad}");
    }
}

#[test]
fn revoked_leaves_intermediates_and_cas_are_refused() {
    block_on(async {
        let made = make(&["127.0.0.1".to_string()]).unwrap();
        let (ca_pem, _, ca_issuer) = ca();
        let (other_pem, other_der, other_issuer) = ca();
        let (sub, sub_issuer) = intermediate(&ca_issuer);
        let a = leaf(&ca_issuer, &[]);
        let b = leaf(&ca_issuer, &[]);
        let c = leaf(&sub_issuer, std::slice::from_ref(&sub));
        let d = leaf(&other_issuer, &[]);
        let client_ca = format!("{ca_pem}{other_pem}");

        let open = pong_server(&made, &client_ca, Revocations::none()).await;
        for identity in [&a, &b, &c, &d] {
            assert!(reaches(&made, open, identity).await);
        }

        // A's leaf, the intermediate C presents, and the second CA.
        let revoked = Revocations::fixed(HashSet::from([
            fingerprint(&a.0[0]),
            fingerprint(&sub),
            fingerprint(&other_der),
        ]));
        let closed = pong_server(&made, &client_ca, revoked).await;
        assert!(!reaches(&made, closed, &a).await, "a revoked leaf");
        assert!(
            reaches(&made, closed, &b).await,
            "another leaf of the same CA"
        );
        assert!(
            !reaches(&made, closed, &c).await,
            "a leaf under a revoked intermediate"
        );
        assert!(!reaches(&made, closed, &d).await, "a leaf of a revoked CA");

        // Every CA revoked: no configuration.
        let all = Revocations::fixed(HashSet::from([
            fingerprint(&certificates(&ca_pem).unwrap()[0]),
            fingerprint(&other_der),
        ]));
        assert!(server_config(&made.key, &made.chain, &client_ca, &all).is_err());
    });
}

#[test]
fn a_changed_list_closes_open_connections_and_refuses_new_ones() {
    block_on(async {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("tls-revoked-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let list = dir.join("revoked-client-certs");
        std::fs::write(&list, "# none yet\n").unwrap();

        let made = make(&["127.0.0.1".to_string()]).unwrap();
        let (ca_pem, _, ca_issuer) = ca();
        let a = leaf(&ca_issuer, &[]);
        let b = leaf(&ca_issuer, &[]);
        let (revoked, reload) = Revocations::from_file(&list, Duration::from_millis(50)).unwrap();
        tokio::spawn(reload);
        let address = pong_server(&made, &ca_pem, revoked.clone()).await;
        let mut a_open = connect(&made, address, &a).await.unwrap();
        let mut b_open = connect(&made, address, &b).await.unwrap();
        assert!(ping(&mut a_open).await && ping(&mut b_open).await);

        let a_print = fingerprint(&a.0[0]);
        let wait_for = |wanted: bool| {
            let revoked = revoked.clone();
            async move {
                for _ in 0..100 {
                    if revoked.current().contains(&a_print) == wanted {
                        return;
                    }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                panic!("the list was not read again");
            }
        };
        std::fs::write(&list, format!("{}\n", hex::encode(a_print))).unwrap();
        wait_for(true).await;
        assert!(
            !ping(&mut a_open).await,
            "A's open connection closes at its next request"
        );
        assert!(ping(&mut b_open).await, "B's stays");
        assert!(!reaches(&made, address, &a).await);
        assert!(reaches(&made, address, &b).await);

        // A broken file keeps the list in force; an empty one lifts it.
        std::fs::write(&list, "not a fingerprint\n").unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(revoked.current().contains(&a_print));
        std::fs::write(&list, "").unwrap();
        wait_for(false).await;
        assert!(reaches(&made, address, &a).await);

        assert!(Revocations::from_file(&dir.join("missing"), Duration::from_secs(1)).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    });
}
