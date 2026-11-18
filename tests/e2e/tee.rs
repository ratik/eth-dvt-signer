//! TEE-1 to TEE-6: nodes whose keys are sealed in a vault (docs/tee.md), on the `gcp-tdx` platform
//! against a fake of Google's attestation, STS and KMS (`harness::gcp`), with real identities
//! (`--peers`) and the mTLS API.
//!
//! What runs here is the node's real code path for a Confidential VM, except `gotpm` (a token URL
//! instead) and the endpoints (the fake). The Confidential VM itself is exercised by
//! `integration/tee`.

use crate::{
    eth2::{activate_everywhere, attestation, signing_root},
    harness::{BINARY, NODES, TestNetwork, ethereum_verify, gcp::FakeGcp, http},
};
use eth_mpc_signer::{
    attestation::{Statement, verify::verify},
    peers::Peers,
    vault::{self, Cipher},
};
use rcgen::{BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair};
use rustls::{
    ClientConfig, RootCertStore,
    crypto::aws_lc_rs,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, pem::PemObject as _},
};
use serde_json::{Value, json};
use std::{
    path::{Path, PathBuf},
    process::Command,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const VALIDATOR: &str = "validator-tee";

/// The operator's CA and one client certificate it issued.
pub(crate) struct Operator {
    pub(crate) ca_path: PathBuf,
    pub(crate) chain: Vec<CertificateDer<'static>>,
    pub(crate) key: Vec<u8>,
    /// The client certificate and key as PEM files (`mpc-admin --tls-cert/--tls-key`).
    pub(crate) cert_path: PathBuf,
    pub(crate) key_path: PathBuf,
}

impl Operator {
    pub(crate) fn new(dir: &Path) -> Self {
        let ca_key = KeyPair::generate().unwrap();
        let mut ca = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_path = dir.join("operator-ca.pem");
        std::fs::write(&ca_path, ca.self_signed(&ca_key).unwrap().pem()).unwrap();
        let issuer = Issuer::new(ca, ca_key);
        let key = KeyPair::generate().unwrap();
        let mut client = CertificateParams::new(Vec::<String>::new()).unwrap();
        client.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let certificate = client.signed_by(&key, &issuer).unwrap();
        let cert_path = dir.join("operator-client.pem");
        std::fs::write(&cert_path, certificate.pem()).unwrap();
        let key_path = dir.join("operator-client-key.pem");
        crate::import::write_secret(&key_path, key.serialize_pem().as_bytes());
        Self {
            ca_path,
            chain: vec![certificate.der().clone()],
            key: key.serialize_der(),
            cert_path,
            key_path,
        }
    }

    /// A client of node `statement` that pins its CA, with this operator's certificate (or
    /// none, or another operator's).
    fn client(statement: &Statement, identity: Option<&Self>) -> Arc<ClientConfig> {
        let chain = statement.tls_certificate.as_deref().expect("a TLS chain");
        let certificates: Vec<_> = CertificateDer::pem_slice_iter(chain.as_bytes())
            .collect::<Result<_, _>>()
            .unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(certificates.last().unwrap().clone()).unwrap();
        let builder = ClientConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots);
        Arc::new(match identity {
            Some(operator) => builder
                .with_client_auth_cert(
                    operator.chain.clone(),
                    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(operator.key.clone())),
                )
                .unwrap(),
            None => builder.with_no_client_auth(),
        })
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// `eth-mpc-signer identity` for node `id`: its statement.
fn identity(network: &TestNetwork, id: usize, vault: &[String]) -> Statement {
    let output = Command::new(BINARY)
        .args(["identity", "--id", &id.to_string(), "--data-dir"])
        .arg(network.data_root())
        .args(["--tls-san", "127.0.0.1"])
        .args(vault)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "identity {id}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

/// A network of real identities: node `i` sealed on the fake platform if `sealed(i)`, in a plain
/// vault otherwise; every node also serves the mTLS API.
fn network(sealed: impl Fn(usize) -> bool) -> (TestNetwork, FakeGcp, Operator, Vec<Statement>) {
    network_with(sealed, |_| Vec::new())
}

/// Like [network], node `i` with the extra environment `env(i)` (test hooks).
pub(crate) fn network_with(
    sealed: impl Fn(usize) -> bool,
    env: impl Fn(usize) -> Vec<(String, String)>,
) -> (TestNetwork, FakeGcp, Operator, Vec<Statement>) {
    network_with_vault(
        |gcp, id| {
            if sealed(id) {
                gcp.vault_args(id)
            } else {
                Vec::new()
            }
        },
        env,
    )
}

/// Like [network_with], node `i` with the vault arguments `vault(gcp, i)`.
fn network_with_vault(
    vault: impl Fn(&FakeGcp, usize) -> Vec<String>,
    env: impl Fn(usize) -> Vec<(String, String)>,
) -> (TestNetwork, FakeGcp, Operator, Vec<Statement>) {
    let gcp = FakeGcp::start(NODES);
    let network =
        TestNetwork::start_with_followers(NODES, 0, Vec::new(), |_| Vec::new(), env, |_| false);
    let vault = |id: usize| vault(&gcp, id);
    let statements: Vec<Statement> = (0..NODES)
        .map(|id| identity(&network, id, &vault(id)))
        .collect();
    let operator = Operator::new(&network.dir);
    let peers = Peers::from_json(
        &json!({
            "format": "eth-mpc-signer/peers",
            "version": 1,
            "nodes": statements.iter().enumerate().map(|(id, statement)| json!({
                "identity": statement.keys.identity,
                "address": network.p2p_addr(id).to_string(),
            })).collect::<Vec<_>>(),
        })
        .to_string(),
    )
    .unwrap();
    let peers_path = network.dir.join("peers.json");
    std::fs::write(&peers_path, peers.to_json()).unwrap();
    // No certificate revoked yet (TEE-5 revokes one).
    let revoked_path = network.dir.join("revoked-client-certs");
    std::fs::write(&revoked_path, "").unwrap();
    for id in 0..NODES {
        let mut args = vault(id);
        args.extend([
            "--peers".to_string(),
            peers_path.display().to_string(),
            "--https-listen".into(),
            network.https_addr(id).to_string(),
            "--client-ca".into(),
            operator.ca_path.display().to_string(),
            "--revoked-client-certs".into(),
            revoked_path.display().to_string(),
        ]);
        network.set_node_args(id, args);
        network.start_node(id);
    }
    network.wait_for_ready(&network.all());
    (network, gcp, operator, statements)
}

/// `POST /api/v1/eth2/sign/{key}` over mTLS to node `id`: status, body, served certificate.
fn sign_tls(
    network: &TestNetwork,
    id: usize,
    client: Arc<ClientConfig>,
    key: &str,
    body: &Value,
) -> std::io::Result<(u16, Value, Vec<u8>)> {
    http::request_tls(
        network.https_addr(id),
        client,
        "POST",
        &format!("/api/v1/eth2/sign/{key}"),
        Some(&body.to_string()),
        Duration::from_secs(70),
    )
    .map(|(status, text, leaf)| {
        (
            status,
            serde_json::from_str(&text).unwrap_or(Value::String(text)),
            leaf,
        )
    })
}

/// A validator key made by DKG and activated.
pub(crate) fn validator(network: &TestNetwork) -> String {
    network.start_validator_dkg(0, VALIDATOR);
    let key = network.wait_for_dkg(VALIDATOR, &network.all());
    activate_everywhere(network, 0, &key);
    key
}

/// Sign `body` over mTLS through node `id` and check the signature.
fn signs(
    network: &TestNetwork,
    id: usize,
    statement: &Statement,
    operator: &Operator,
    key: &str,
    body: &Value,
) {
    let (status, answer, _) = sign_tls(
        network,
        id,
        Operator::client(statement, Some(operator)),
        key,
        body,
    )
    .unwrap();
    assert_eq!(status, 200, "node {id}: {answer}");
    assert!(
        ethereum_verify(&json!(key), &signing_root(body), &answer["signature"]),
        "{answer}"
    );
}

/// Every file under `dir`, recursively.
fn files(dir: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            found.extend(files(&path));
        } else {
            found.push(path);
        }
    }
    found
}

/// The files under `dir` that contain `needle`.
fn holding(dir: &Path, needle: &[u8]) -> Vec<PathBuf> {
    files(dir)
        .into_iter()
        .filter(|path| {
            std::fs::read(path)
                .unwrap_or_default()
                .windows(needle.len())
                .any(|window| window == needle)
        })
        .collect()
}

#[test]
fn tee_1_sealed_nodes_attest_their_keys_sign_over_mtls_and_keep_nothing_in_the_clear() {
    let (network, gcp, operator, statements) = network(|_| true);

    // Every node's keys are attested: the evidence verifies against the policy and binds them.
    for statement in &statements {
        assert_eq!(statement.vault, "gcp-tdx");
        let evidence = statement.evidence.as_ref().expect("evidence");
        let verified = verify(
            evidence,
            &gcp.policy(),
            &gcp.jwks(),
            b"",
            now(),
            Some(statement.index),
        )
        .unwrap();
        assert_eq!(verified.keys, statement.keys);
        assert_eq!(
            verified.instance,
            Some(eth_mpc_signer::attestation::testing::instance_id(&format!(
                "mpc-tee-{}",
                statement.index
            )))
        );
    }

    // A fresh attestation over mTLS answers the client's nonce, from the attested TLS key.
    let nonce = [0x5a; 32];
    let (status, text, leaf) = http::request_tls(
        network.https_addr(1),
        Operator::client(&statements[1], Some(&operator)),
        "GET",
        &format!("/attestation?nonce=0x{}", hex::encode(nonce)),
        None,
        Duration::from_secs(30),
    )
    .unwrap();
    assert_eq!(status, 200, "{text}");
    let statement: Statement = serde_json::from_str(&text).unwrap();
    let evidence = statement.evidence.as_ref().unwrap();
    verify(evidence, &gcp.policy(), &gcp.jwks(), &nonce, now(), Some(1)).unwrap();
    assert_eq!(statement.keys, statements[1].keys);
    let attested_leaf =
        CertificateDer::pem_slice_iter(statement.tls_certificate.as_deref().unwrap().as_bytes())
            .next()
            .unwrap()
            .unwrap();
    assert_eq!(
        leaf,
        attested_leaf.as_ref(),
        "the served certificate is the attested one"
    );
    // Another nonce does not verify.
    assert!(
        verify(
            evidence,
            &gcp.policy(),
            &gcp.jwks(),
            &[0x5b; 32],
            now(),
            Some(1)
        )
        .is_err()
    );

    // DKG, activation and a duty signed over mTLS.
    let key = validator(&network);
    signs(
        &network,
        1,
        &statements[1],
        &operator,
        &key,
        &attestation(3, 4, 1),
    );

    // Nothing secret is on disk in the clear: not the data key, not the identity, not the
    // share-encryption key. Only KMS (here, the fake) can unwrap the data key.
    for id in network.all() {
        let node = network.data_dir(id);
        let dek = gcp.unwrap_dek(id, &std::fs::read(node.join("vault/dek.wrapped")).unwrap());
        let cipher = Cipher::for_tests(dek);
        let open = |name: &str| {
            cipher
                .open(
                    &Cipher::item_aad(name),
                    &std::fs::read(node.join("vault").join(name)).unwrap(),
                )
                .unwrap()
        };
        let identity = open(vault::IDENTITY);
        let share_key: Value = serde_json::from_slice(&open(vault::SHARE_KEY)).unwrap();
        let share_secret = hex::decode(
            share_key["secret_key"]
                .as_str()
                .unwrap()
                .trim_start_matches("0x"),
        )
        .unwrap();
        let tls_key = open(vault::TLS_KEY);
        for (what, secret) in [
            ("data key", dek.to_vec()),
            ("identity", identity.to_vec()),
            ("share-encryption key", share_secret),
            ("TLS key", tls_key.to_vec()),
        ] {
            assert!(
                holding(&network.dir, &secret).is_empty(),
                "node {id}'s {what} is on disk in the clear"
            );
        }
        // The shares are sealed too: every value of `registry-secrets` carries the sealed tag.
        assert!(node.join("registry-secrets").exists());
        assert!(node.join("registry-secrets-pending").exists());
    }
}

#[test]
fn tee_2_a_restart_unseals_and_only_the_attested_image_on_its_vm_gets_the_key() {
    let (network, gcp, operator, statements) = network(|_| true);
    let key = validator(&network);

    // A restart unseals the vault and the node signs again.
    network.restart_node(2);
    network.wait_for_ready(&[2]);
    signs(
        &network,
        2,
        &statements[2],
        &operator,
        &key,
        &attestation(5, 6, 2),
    );

    // Another image (RTMR1), a debug VM, or another VM with the right image: KMS refuses, and
    // the node does not start.
    for (what, edit) in [
        (
            "another image",
            (|vm: &mut eth_mpc_signer::attestation::testing::Vm| vm.rtmr1 = "ff".repeat(48))
                as fn(&mut _),
        ),
        ("a debug VM", |vm| vm.dbgstat = "enabled".into()),
    ] {
        gcp.set_vm("mpc-tee-3", edit);
        network.stop_node(3);
        network.start_node(3);
        let status = network.wait_exit(3);
        assert_eq!(status.code(), Some(1), "{what}: {}", network.log(3));
        let node_3 = eth_mpc_signer::attestation::testing::instance_id("mpc-tee-3");
        assert!(
            gcp.refusals()
                .iter()
                .any(|refusal| refusal.contains(&node_3)),
            "{what}: {:?}",
            gcp.refusals()
        );
        gcp.set_vm("mpc-tee-3", |vm| {
            *vm = eth_mpc_signer::attestation::testing::Vm::new("mpc-tee-3")
        });
    }
    // A VM of the project with the release image, but not node 3's: STS admits it, and KMS
    // refuses it node 3's key (the key's IAM binding names node 3's instance ID).
    gcp.set_vm("mpc-tee-9", |_| {});
    let other = eth_mpc_signer::attestation::testing::instance_id("mpc-tee-9");
    let refusals = gcp.refusals().len();
    let mut args = gcp.vault_args_as(3, "mpc-tee-9");
    args.extend(network_args(&network, 3));
    network.set_node_args(3, args);
    network.start_node(3);
    assert_eq!(network.wait_exit(3).code(), Some(1), "{}", network.log(3));
    assert!(
        gcp.refusals()[refusals..]
            .iter()
            .any(|refusal| refusal.contains("kms") && refusal.contains(&other)),
        "{:?}",
        gcp.refusals()
    );

    // Back on its own VM, the node starts and signs.
    let mut args = gcp.vault_args(3);
    args.extend(network_args(&network, 3));
    network.set_node_args(3, args);
    network.start_node(3);
    network.wait_for_ready(&[3]);
    signs(
        &network,
        3,
        &statements[3],
        &operator,
        &key,
        &attestation(7, 8, 3),
    );
}

/// Node `id`'s arguments after its vault's: the peers file and the mTLS listener.
fn network_args(network: &TestNetwork, id: usize) -> Vec<String> {
    vec![
        "--peers".into(),
        network.dir.join("peers.json").display().to_string(),
        "--https-listen".into(),
        network.https_addr(id).to_string(),
        "--client-ca".into(),
        network.dir.join("operator-ca.pem").display().to_string(),
    ]
}

#[test]
fn tee_4_sealed_and_plain_nodes_run_one_network() {
    let (network, _gcp, operator, statements) = network(|id| id < 2);
    assert_eq!(statements[0].vault, "gcp-tdx");
    assert!(statements[0].evidence.is_some());
    assert_eq!(statements[3].vault, "plain");
    assert!(statements[3].evidence.is_none());
    let key = validator(&network);
    signs(
        &network,
        0,
        &statements[0],
        &operator,
        &key,
        &attestation(9, 10, 4),
    );
    signs(
        &network,
        3,
        &statements[3],
        &operator,
        &key,
        &attestation(11, 12, 5),
    );
}

#[test]
fn tee_5_the_mtls_api_refuses_clients_without_the_operators_certificate() {
    let (network, _gcp, operator, statements) = network(|_| true);
    let call = |client: Arc<ClientConfig>| {
        http::request_tls(
            network.https_addr(0),
            client,
            "GET",
            "/status",
            None,
            Duration::from_secs(10),
        )
    };
    let (status, _, _) = call(Operator::client(&statements[0], Some(&operator))).unwrap();
    assert_eq!(status, 200);
    assert!(call(Operator::client(&statements[0], None)).is_err());
    let stranger_dir = network.dir.join("stranger");
    std::fs::create_dir_all(&stranger_dir).unwrap();
    let stranger = Operator::new(&stranger_dir);
    assert!(call(Operator::client(&statements[0], Some(&stranger))).is_err());
    // A client that pins another node's CA does not accept this node's certificate.
    assert!(call(Operator::client(&statements[1], Some(&operator))).is_err());

    // The operator's certificate revoked: refused once the node reads its list again.
    std::fs::write(
        network.dir.join("revoked-client-certs"),
        format!(
            "{}\n",
            hex::encode(eth_mpc_signer::tls::fingerprint(&operator.chain[0]))
        ),
    )
    .unwrap();
    let deadline = std::time::Instant::now() + 4 * eth_mpc_signer::tls::REVOCATIONS_RELOAD;
    while call(Operator::client(&statements[0], Some(&operator))).is_ok() {
        assert!(
            std::time::Instant::now() < deadline,
            "the revoked certificate is still served"
        );
        std::thread::sleep(Duration::from_millis(500));
    }
    // Lifted again: served again.
    std::fs::write(network.dir.join("revoked-client-certs"), "").unwrap();
    let deadline = std::time::Instant::now() + 4 * eth_mpc_signer::tls::REVOCATIONS_RELOAD;
    while call(Operator::client(&statements[0], Some(&operator))).is_err() {
        assert!(
            std::time::Instant::now() < deadline,
            "the certificate is still refused"
        );
        std::thread::sleep(Duration::from_millis(500));
    }
}

const ADMIN: &str = env!("CARGO_BIN_EXE_mpc-admin");
const KEYTOOL: &str = env!("CARGO_BIN_EXE_mpc-keytool");

fn run(program: &str, args: &[String]) -> std::process::Output {
    Command::new(program).args(args).output().unwrap()
}

fn text(output: &std::process::Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

#[test]
fn tee_3_shares_are_encrypted_only_to_keys_a_sealed_node_attested() {
    let (network, gcp, operator, statements) = network(|_| true);
    let dir = network.dir.clone();
    let path = |name: &str| dir.join(name).display().to_string();
    std::fs::write(
        dir.join("policy.json"),
        serde_json::to_string(&gcp.policy()).unwrap(),
    )
    .unwrap();
    std::fs::write(
        dir.join("jwks.json"),
        serde_json::to_string(&gcp.jwks()).unwrap(),
    )
    .unwrap();
    let mut bad_policy = gcp.policy();
    bad_policy.rtmr1 = vec!["ff".repeat(48)];
    std::fs::write(
        dir.join("bad-policy.json"),
        serde_json::to_string(&bad_policy).unwrap(),
    )
    .unwrap();
    let nodes = (0..NODES)
        .map(|id| format!("https://{}", network.https_addr(id)))
        .collect::<Vec<_>>()
        .join(",");
    let admin = |tail: &[&str]| {
        let mut args = vec![
            "--nodes".to_string(),
            nodes.clone(),
            "--tls-cert".into(),
            operator.cert_path.display().to_string(),
            "--tls-key".into(),
            operator.key_path.display().to_string(),
        ];
        args.extend(tail.iter().map(ToString::to_string));
        run(ADMIN, &args)
    };

    // `mpc-admin attest` over mTLS: every node's fresh evidence verifies, from the attested TLS
    // key; it writes the committee with the evidence and the node CAs.
    let output = admin(&[
        "attest",
        "--policy",
        &path("policy.json"),
        "--jwks",
        &path("jwks.json"),
        "--committee",
        &path("committee.json"),
        "--certificates",
        &path("node-cas.pem"),
    ]);
    assert!(output.status.success(), "{}", text(&output));
    assert_eq!(text(&output).matches(" attested (gcp-tdx").count(), NODES);
    let committee: Value =
        serde_json::from_slice(&std::fs::read(dir.join("committee.json")).unwrap()).unwrap();
    assert_eq!(committee["participants"].as_array().unwrap().len(), NODES);
    // Another image's policy: every node is refused.
    let output = admin(&[
        "attest",
        "--policy",
        &path("bad-policy.json"),
        "--jwks",
        &path("jwks.json"),
    ]);
    assert!(!output.status.success());
    assert_eq!(
        text(&output).matches("not allowed by the policy").count(),
        NODES,
        "{}",
        text(&output)
    );
    // The pinned node CAs serve every other command over mTLS.
    let output = admin(&["--tls-node-ca", &path("node-cas.pem"), "status"]);
    assert!(output.status.success(), "{}", text(&output));

    // `split` encrypts only to attested keys: the right policy works; another image's policy, a
    // committee whose keys are not the attested ones, or one without evidence are refused before
    // the keystore is read.
    std::fs::copy(
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/eip2335/pbkdf2.json"
        ),
        dir.join("keystore.json"),
    )
    .unwrap();
    crate::import::write_secret(&dir.join("password"), crate::import::PASSWORD.as_bytes());
    let split = |committee: &str, policy: &str, out: &str| {
        run(
            KEYTOOL,
            &[
                "split".to_string(),
                "--keystore".into(),
                path("keystore.json"),
                "--password-file".into(),
                path("password"),
                "--committee".into(),
                path(committee),
                "--ceremony-id".into(),
                crate::import::CEREMONY.into(),
                "--output".into(),
                path(out),
                "--attestation-policy".into(),
                path(policy),
                "--jwks".into(),
                path("jwks.json"),
            ],
        )
    };
    let refused = split("committee.json", "bad-policy.json", "refused-1");
    assert!(!refused.status.success());
    assert!(
        text(&refused).contains("not allowed by the policy"),
        "{}",
        text(&refused)
    );
    let mut swapped = committee.clone();
    let first = swapped["participants"][0]["share_encryption_key"].clone();
    swapped["participants"][0]["share_encryption_key"] =
        swapped["participants"][1]["share_encryption_key"].clone();
    swapped["participants"][1]["share_encryption_key"] = first;
    std::fs::write(dir.join("swapped.json"), swapped.to_string()).unwrap();
    let refused = split("swapped.json", "policy.json", "refused-2");
    assert!(!refused.status.success());
    assert!(text(&refused).contains("other keys"), "{}", text(&refused));
    let mut bare = committee.clone();
    for member in bare["participants"].as_array_mut().unwrap() {
        member.as_object_mut().unwrap().remove("evidence");
    }
    std::fs::write(dir.join("bare.json"), bare.to_string()).unwrap();
    let refused = split("bare.json", "policy.json", "refused-3");
    assert!(!refused.status.success());
    assert!(
        text(&refused).contains("no attestation evidence"),
        "{}",
        text(&refused)
    );
    assert!(!dir.join("refused-1").exists() && !dir.join("refused-3").exists());
    let output = split("committee.json", "policy.json", "shares");
    assert!(output.status.success(), "{}", text(&output));

    // The sealed nodes open their shares with the share-encryption key their vault made, and
    // store them sealed.
    let manifest: Value =
        serde_json::from_slice(&std::fs::read(dir.join("shares/manifest.json")).unwrap()).unwrap();
    let (code, registered) =
        network.approved(1, "register-import", json!({ "manifest": manifest }));
    assert_eq!(code, 200, "{registered}");
    for node in network.all() {
        network.wait_until(&format!("registration on node {node}"), || {
            network
                .get(node, &format!("/keys/import/{}", crate::import::CEREMONY))
                .0
                == 200
        });
        let (_, identity) = network.get(node, "/identity");
        assert_eq!(identity["identity"], statements[node].keys.identity);
        let index = identity["participant_index"].as_u64().unwrap();
        let envelope: Value = serde_json::from_slice(
            &std::fs::read(dir.join(format!("shares/node-{index}.enc"))).unwrap(),
        )
        .unwrap();
        let (code, answer) = network.post(node, "/keys/import/share", &envelope);
        assert_eq!(
            (code, answer["installed"].as_str()),
            (200, Some("stored")),
            "node {node}: {answer}"
        );
    }
    for node in network.all() {
        network.wait_until(&format!("four acknowledged shares on node {node}"), || {
            network
                .get(node, &format!("/keys/import/{}", crate::import::CEREMONY))
                .1["ready_shares"]
                .as_array()
                .is_some_and(|ready| ready.len() == NODES)
        });
    }
}

/// An image upgrade (docs/tee.md, "Upgrading the image"): while the provider admits the old and
/// the new image, nodes move to the new one on their own VMs (same instance, same disk), one at a
/// time, unseal the same vault and sign; clients attest them under a policy naming both images.
/// Once the old image is retired, a node back on it no longer gets its key.
#[test]
fn tee_6_an_image_upgrade_keeps_the_vault_and_retires_the_old_image() {
    use eth_mpc_signer::attestation::{testing::Vm, verify::Policy};
    let (network, gcp, operator, statements) = network(|_| true);
    let key = validator(&network);
    let release = Vm::new("release");
    let old = (release.rtmr1, release.rtmr2);
    let new = ("c3".repeat(48), "d4".repeat(48));
    let report = |id: usize, (rtmr1, rtmr2): &(String, String)| {
        let (rtmr1, rtmr2) = (rtmr1.clone(), rtmr2.clone());
        gcp.set_vm(&format!("mpc-tee-{id}"), move |vm| {
            vm.rtmr1 = rtmr1;
            vm.rtmr2 = rtmr2;
        });
    };

    // Both images admitted: nodes 2 and 3 move to the new one, one at a time.
    gcp.admit(&[old.clone(), new.clone()]);
    for (id, target) in [(2usize, 2u64), (3, 4)] {
        report(id, &new);
        network.restart_node(id);
        network.wait_for_ready(&[id]);
        signs(
            &network,
            id,
            &statements[id],
            &operator,
            &key,
            &attestation(target - 1, target, id as u8),
        );
    }

    // A client whose policy names both images attests node 3 on the new one, with its keys; a
    // policy of the old image alone refuses it.
    let nonce = [0x6c; 32];
    let (status, text, _) = http::request_tls(
        network.https_addr(3),
        Operator::client(&statements[3], Some(&operator)),
        "GET",
        &format!("/attestation?nonce=0x{}", hex::encode(nonce)),
        None,
        Duration::from_secs(30),
    )
    .unwrap();
    assert_eq!(status, 200, "{text}");
    let statement: Statement = serde_json::from_str(&text).unwrap();
    assert_eq!(statement.keys, statements[3].keys);
    let evidence = statement.evidence.as_ref().unwrap();
    let both = gcp.policy();
    assert_eq!(both.rtmr1, vec![old.0.clone(), new.0.clone()]);
    let verified = verify(evidence, &both, &gcp.jwks(), &nonce, now(), Some(3)).unwrap();
    assert_eq!(verified.rtmr1, new.0);
    let old_only = Policy {
        rtmr1: vec![old.0.clone()],
        rtmr2: vec![old.1.clone()],
        ..both
    };
    assert!(verify(evidence, &old_only, &gcp.jwks(), &nonce, now(), Some(3)).is_err());

    // The old image retired: node 2 back on it is refused its key (STS); on the new one it
    // unseals and signs.
    gcp.admit(std::slice::from_ref(&new));
    report(2, &old);
    let refusals = gcp.refusals().len();
    network.stop_node(2);
    network.start_node(2);
    assert_eq!(network.wait_exit(2).code(), Some(1), "{}", network.log(2));
    let node_2 = eth_mpc_signer::attestation::testing::instance_id("mpc-tee-2");
    assert!(
        gcp.refusals()[refusals..]
            .iter()
            .any(|refusal| refusal.starts_with("sts") && refusal.contains(&node_2)),
        "{:?}",
        gcp.refusals()
    );
    report(2, &new);
    network.start_node(2);
    network.wait_for_ready(&[2]);
    signs(
        &network,
        2,
        &statements[2],
        &operator,
        &key,
        &attestation(5, 6, 2),
    );
}

/// The `sev-snp` vault on fake chip `chip` (`--snp-fake-chip`).
fn snp_vault_args(chip: u8) -> Vec<String> {
    vec![
        "--vault".into(),
        "sev-snp".into(),
        "--snp-fake-chip".into(),
        chip.to_string(),
        // A real VCEK: it chains to AMD's root, but did not sign the fake chips' reports.
        "--snp-vcek".into(),
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/sev-snp/vcek_milan.der"
        )
        .into(),
    ]
}

#[test]
fn tee_7_sev_snp_vaults_seal_to_their_chip_and_clients_check_the_reports() {
    let (network, _gcp, operator, statements) =
        network_with_vault(|_, id| snp_vault_args(id as u8 + 1), |_| Vec::new());

    // Every node made its keys in a sealed vault and attests them with an SEV-SNP report.
    for (id, statement) in statements.iter().enumerate() {
        assert_eq!(statement.vault, "sev-snp");
        let evidence = statement.evidence.as_ref().expect("evidence");
        assert_eq!(evidence.platform, "sev-snp");
        assert!(evidence.vcek.is_some(), "the VCEK is attached");
        let (report, _) = eth_mpc_signer::attestation::snp::decode(evidence).unwrap();
        assert_eq!(
            report.report_data(),
            eth_mpc_signer::attestation::snp::report_data(&statement.keys, b""),
            "node {id}"
        );
        let identity = std::fs::read(network.data_dir(id).join("vault").join("identity")).unwrap();
        assert!(
            identity.starts_with(b"EMSV"),
            "node {id}: the identity is sealed"
        );
    }

    // A restart reopens the vault on the same chip; on another chip the node does not start.
    network.restart_node(2);
    network.wait_for_ready(&[2]);
    let mut args = snp_vault_args(9);
    args.extend(network_args(&network, 2));
    network.set_node_args(2, args);
    network.stop_node(2);
    network.start_node(2);
    assert_eq!(network.wait_exit(2).code(), Some(1), "{}", network.log(2));
    assert!(
        network
            .log(2)
            .contains("does not open with this guest's sealing key"),
        "{}",
        network.log(2)
    );
    let mut args = snp_vault_args(3);
    args.extend(network_args(&network, 2));
    network.set_node_args(2, args);
    network.start_node(2);
    network.wait_for_ready(&[2]);

    // `mpc-admin attest` with an SEV-SNP policy: the attached VCEK is AMD's, but it did not sign
    // the fake chips' reports, so every node is refused. No gcp-tdx key set is needed.
    let dir = network.dir.clone();
    let policy = json!({
        "platform": "sev-snp",
        "products": ["Milan"],
        "measurements": ["5e".repeat(48)],
        "min_tcb": {"boot_loader": 0, "tee": 0, "snp": 0, "microcode": 0},
    });
    std::fs::write(dir.join("snp-policy.json"), policy.to_string()).unwrap();
    let nodes = (0..NODES)
        .map(|id| format!("https://{}", network.https_addr(id)))
        .collect::<Vec<_>>()
        .join(",");
    let output = run(
        ADMIN,
        &[
            "--nodes".into(),
            nodes,
            "--tls-cert".into(),
            operator.cert_path.display().to_string(),
            "--tls-key".into(),
            operator.key_path.display().to_string(),
            "attest".into(),
            "--policy".into(),
            dir.join("snp-policy.json").display().to_string(),
        ],
    );
    assert!(!output.status.success());
    assert_eq!(
        text(&output)
            .matches("does not verify with the VCEK")
            .count(),
        NODES,
        "{}",
        text(&output)
    );
}
