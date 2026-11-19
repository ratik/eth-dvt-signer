//! The gateway (`mpc-gateway`, docs/gateway.md) in front of sealed nodes on the fake GCP:
//! - **GW-1:** signing through attested nodes over mTLS, each signature checked; the log and the
//!   metrics;
//! - **GW-2:** a slow node is hedged, a wrong signature is never passed on, a stopped node is failed
//!   over;
//! - **GW-3:** a node is used only while its attestation verifies (another image, another
//!   configuration);
//! - **GW-4:** validator clients need the gateway's client CA; TLS 1.2 only when allowed.

use crate::{
    eth2::{CHAIN, attestation, signing_root},
    harness::{NODES, TestNetwork, ethereum_verify, fork_schedule, gcp::FakeGcp, http},
    tee::{Operator, network_with, validator},
};
use eth_dvt_signer::attestation::{testing::Vm, verify::Policy};
use rustls::{
    ClientConfig, RootCertStore,
    crypto::aws_lc_rs,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, pem::PemObject as _},
};
use serde_json::{Value, json};
use std::{
    net::{SocketAddr, TcpListener},
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const GATEWAY: &str = env!("CARGO_BIN_EXE_mpc-gateway");
const TIMEOUT: Duration = Duration::from_secs(60);

struct Gateway {
    child: Child,
    address: SocketAddr,
    metrics: SocketAddr,
    log: PathBuf,
    output: PathBuf,
}

impl Drop for Gateway {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Gateway {
    fn records(&self) -> Vec<Value> {
        std::fs::read_to_string(&self.log)
            .unwrap_or_default()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    fn last(&self) -> Value {
        self.records().pop().expect("a request record")
    }

    fn metrics(&self) -> String {
        http::request(self.metrics, "GET", "/metrics", None, TIMEOUT)
            .map(|(_, body)| body)
            .unwrap_or_default()
    }

    fn output(&self) -> String {
        std::fs::read_to_string(&self.output).unwrap_or_default()
    }

    /// `POST /api/v1/eth2/sign/{key}` through the gateway (plain HTTP).
    fn sign(&self, key: &str, body: &Value) -> (u16, Value) {
        let (status, text) = http::request_with(
            self.address,
            "POST",
            &format!("/api/v1/eth2/sign/{key}"),
            &[("Accept", "application/json")],
            Some(&body.to_string()),
            TIMEOUT,
        )
        .unwrap();
        (
            status,
            serde_json::from_str(&text).unwrap_or(Value::String(text)),
        )
    }
}

fn free_address() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}

fn node_url(network: &TestNetwork, id: usize) -> String {
    format!("https://{}", network.https_addr(id))
}

fn usable(metrics: &str, url: &str) -> Option<bool> {
    let line = format!("mpc_gateway_node_usable{{node=\"{url}\"}} ");
    metrics
        .lines()
        .find_map(|l| l.strip_prefix(&line))
        .map(|value| value.trim() == "1")
}

/// The fake platform's policy, each node's configuration pinned to `rtmr3(i)`.
fn policy(gcp: &FakeGcp, rtmr3: impl Fn(u64) -> String) -> Policy {
    Policy {
        rtmr3: Some((0..NODES as u64).map(|i| (i, vec![rtmr3(i)])).collect()),
        ..gcp.policy()
    }
}

/// The configuration a fake VM reports.
fn release_rtmr3(_: u64) -> String {
    "00".repeat(48)
}

static STARTED: AtomicUsize = AtomicUsize::new(0);

/// `mpc-gateway` in front of `nodes`, with `policy` and the fake issuer's key set, and `extra`
/// flags; returns once `ready` (by default: `/upcheck` over plain HTTP) answers 200.
fn start(
    network: &TestNetwork,
    gcp: &FakeGcp,
    operator: &Operator,
    nodes: &[usize],
    policy: &Policy,
    extra: &[String],
    tls: Option<Arc<ClientConfig>>,
) -> Gateway {
    let n = STARTED.fetch_add(1, Ordering::SeqCst);
    let dir = &network.dir;
    let policy_path = dir.join(format!("gateway-{n}-policy.json"));
    std::fs::write(&policy_path, serde_json::to_string(policy).unwrap()).unwrap();
    let jwks_path = dir.join(format!("gateway-{n}-jwks.json"));
    std::fs::write(&jwks_path, serde_json::to_string(&gcp.jwks()).unwrap()).unwrap();
    let (address, metrics) = (free_address(), free_address());
    let log = dir.join(format!("gateway-{n}.jsonl"));
    let output = dir.join(format!("gateway-{n}.log"));
    let file = std::fs::File::create(&output).unwrap();
    let nodes: Vec<String> = nodes.iter().map(|&id| node_url(network, id)).collect();
    let child = Command::new(GATEWAY)
        .args(["--listen", &address.to_string()])
        .args(["--metrics-listen", &metrics.to_string()])
        .args(["--nodes", &nodes.join(",")])
        .arg("--tls-cert")
        .arg(&operator.cert_path)
        .arg("--tls-key")
        .arg(&operator.key_path)
        .arg("--policy")
        .arg(&policy_path)
        .arg("--jwks")
        .arg(&jwks_path)
        .arg("--request-log")
        .arg(&log)
        .args(["--eth-genesis-time", "0", "--eth-seconds-per-slot", "1"])
        .args(["--eth-genesis-validators-root", CHAIN])
        .args(["--eth-fork-schedule", &fork_schedule()])
        .args(extra)
        .env("RUST_LOG", "info")
        .stdout(file.try_clone().unwrap())
        .stderr(file)
        .stdin(Stdio::null())
        .spawn()
        .unwrap();
    let gateway = Gateway {
        child,
        address,
        metrics,
        log,
        output,
    };
    let deadline = Instant::now() + TIMEOUT;
    loop {
        let up = match &tls {
            None => http::request(address, "GET", "/upcheck", None, TIMEOUT)
                .is_ok_and(|(status, _)| status == 200),
            Some(config) => {
                http::request_tls(address, config.clone(), "GET", "/upcheck", None, TIMEOUT)
                    .is_ok_and(|(status, _, _)| status == 200)
            }
        };
        if up {
            return gateway;
        }
        assert!(
            Instant::now() < deadline,
            "the gateway never got usable: {}",
            gateway.output()
        );
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn wait_for(what: &str, gateway: &Gateway, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + TIMEOUT;
    while !done() {
        assert!(
            Instant::now() < deadline,
            "{what}: {}\n{}",
            gateway.metrics(),
            gateway.output()
        );
        std::thread::sleep(Duration::from_millis(500));
    }
}

fn signed(key: &str, body: &Value, answer: &Value) -> bool {
    ethereum_verify(&json!(key), &signing_root(body), &answer["signature"])
}

#[test]
fn gateway_1_signs_through_attested_sealed_nodes_and_checks_each_signature() {
    let (network, gcp, operator, _) = network_with(|_| true, |_| Vec::new());
    let key = validator(&network);
    let gateway = start(
        &network,
        &gcp,
        &operator,
        &[0, 1, 2, 3],
        &policy(&gcp, release_rtmr3),
        &[],
        None,
    );
    let metrics = gateway.metrics();
    for id in 0..NODES {
        assert_eq!(
            usable(&metrics, &node_url(&network, id)),
            Some(true),
            "{metrics}"
        );
    }

    let body = attestation(1, 2, 1);
    let (status, answer) = gateway.sign(&key, &body);
    assert_eq!(status, 200, "{answer}");
    assert!(signed(&key, &body, &answer));
    let record = gateway.last();
    assert_eq!(record["type"], "ATTESTATION");
    assert_eq!(record["status"], 200);
    assert_eq!(record["attempts"][0]["backend"], node_url(&network, 0));
    assert_eq!(record["attempts"][0]["status"], 200);

    let (status, keys) = http::request(
        gateway.address,
        "GET",
        "/api/v1/eth2/publicKeys",
        None,
        TIMEOUT,
    )
    .unwrap();
    assert_eq!(status, 200);
    assert!(keys.contains(&key), "{keys}");
    assert!(
        gateway
            .metrics()
            .contains("mpc_gateway_requests_total{type=\"ATTESTATION\",status=\"200\"} 1")
    );
}

#[test]
fn gateway_2_hedges_a_slow_node_and_never_passes_on_a_wrong_signature() {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let hooks = std::env::temp_dir().join(format!("gw2-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&hooks).unwrap();
    let (pause, corrupt) = (hooks.join("pause"), hooks.join("corrupt"));
    let env = |id: usize| -> Vec<(String, String)> {
        if id != 0 {
            return Vec::new();
        }
        vec![
            ("ETH_MPC_SIGNER_PAUSE_AT".into(), "received".into()),
            (
                "ETH_MPC_SIGNER_PAUSE_FILE".into(),
                pause.display().to_string(),
            ),
            (
                "ETH_MPC_SIGNER_CORRUPT_SIGNATURE_FILE".into(),
                corrupt.display().to_string(),
            ),
        ]
    };
    let (network, gcp, operator, _) = network_with(|_| true, env);
    let key = validator(&network);
    // A node's own signing can take seconds while the suite runs in parallel: attempts time out
    // only after 30 s, and each step starts once no node is tried last any more.
    let flags = |hedge: &str| -> Vec<String> {
        vec![
            "--hedge-after-ms".into(),
            hedge.into(),
            "--node-timeout-ms".into(),
            "30000".into(),
        ]
    };
    let settle =
        || std::thread::sleep(eth_dvt_signer::gateway::nodes::DOWN_FOR + Duration::from_secs(1));
    let pinned = policy(&gcp, release_rtmr3);

    // Node 0 holds every request it coordinates: after 300 ms the gateway asks the next node too,
    // and the first answer is the gateway's.
    let hedging = start(
        &network,
        &gcp,
        &operator,
        &[0, 1, 2, 3],
        &pinned,
        &flags("300"),
        None,
    );
    std::fs::write(&pause, b"").unwrap();
    let body = attestation(1, 2, 1);
    let began = Instant::now();
    let (status, answer) = hedging.sign(&key, &body);
    assert_eq!(status, 200, "{answer}");
    assert!(signed(&key, &body, &answer));
    assert!(began.elapsed() < Duration::from_secs(20));
    let record = hedging.last();
    let attempts = record["attempts"].as_array().unwrap();
    assert_eq!(attempts.len(), 1, "{record}");
    assert_ne!(attempts[0]["backend"], node_url(&network, 0), "{record}");
    assert_eq!(attempts[0]["hedged"], true);
    std::fs::remove_file(&pause).unwrap();
    drop(hedging);

    // Node 0 returns its signature corrupted: the gateway does not pass it on, and another node's
    // signature (the same: consensus accepted the duty once) is the answer. No hedging here, so
    // that node 0 answers first.
    let gateway = start(
        &network,
        &gcp,
        &operator,
        &[0, 1, 2, 3],
        &pinned,
        &flags("20000"),
        None,
    );
    settle();
    std::fs::write(&corrupt, b"").unwrap();
    let body = attestation(3, 4, 2);
    let (status, answer) = gateway.sign(&key, &body);
    assert_eq!(status, 200, "{answer}");
    assert!(signed(&key, &body, &answer));
    let record = gateway.last();
    let attempts = record["attempts"].as_array().unwrap();
    assert_eq!(attempts[0]["backend"], node_url(&network, 0), "{record}");
    assert_eq!(attempts[0]["invalid_signature"], true, "{record}");
    let last = attempts.last().unwrap();
    assert_eq!(last["status"], 200, "{record}");
    assert_ne!(last["backend"], node_url(&network, 0), "{record}");
    assert!(gateway.metrics().contains(&format!(
        "mpc_gateway_invalid_signatures_total{{node=\"{}\"}} 1",
        node_url(&network, 0)
    )));
    std::fs::remove_file(&corrupt).unwrap();

    // Node 1 stopped (node 0 is tried last for a while): node 1 fails, and a node after it signs.
    network.stop_node(1);
    settle();
    let body = attestation(5, 6, 3);
    let (status, answer) = gateway.sign(&key, &body);
    assert_eq!(status, 200, "{answer}");
    assert!(signed(&key, &body, &answer));
    let record = gateway.last();
    let attempts = record["attempts"].as_array().unwrap();
    assert_eq!(attempts[0]["backend"], node_url(&network, 1), "{record}");
    assert!(attempts[0]["error"].is_string(), "{record}");
    let last = attempts.last().unwrap();
    assert_eq!(last["status"], 200, "{record}");
    assert!(
        ![node_url(&network, 0), node_url(&network, 1)]
            .contains(&last["backend"].as_str().unwrap().to_string()),
        "{record}"
    );
    let _ = std::fs::remove_dir_all(&hooks);
}

#[test]
fn gateway_3_uses_a_node_only_while_its_attestation_verifies() {
    let (network, gcp, operator, _) = network_with(|_| true, |_| Vec::new());
    let key = validator(&network);
    // Node 3's configuration is not the one the policy pins for it: never used.
    let pinned = policy(&gcp, |id| {
        if id == 3 {
            "33".repeat(48)
        } else {
            release_rtmr3(id)
        }
    });
    let gateway = start(
        &network,
        &gcp,
        &operator,
        &[0, 1, 2, 3],
        &pinned,
        &["--attest-every-secs".into(), "10".into()],
        None,
    );
    let metrics = gateway.metrics();
    assert_eq!(usable(&metrics, &node_url(&network, 3)), Some(false));
    assert!(gateway.output().contains("another configuration"));

    // Node 0 now reports another image: at its next check it is no longer used.
    gcp.set_vm("mpc-tee-0", |vm| vm.rtmr1 = "ff".repeat(48));
    let url = node_url(&network, 0);
    wait_for("node 0 dropped", &gateway, || {
        usable(&gateway.metrics(), &url) == Some(false)
    });
    let body = attestation(1, 2, 1);
    let (status, answer) = gateway.sign(&key, &body);
    assert_eq!(status, 200, "{answer}");
    assert!(signed(&key, &body, &answer));
    assert_eq!(
        gateway.last()["attempts"][0]["backend"],
        node_url(&network, 1)
    );

    // Back on the release image: it is used again.
    gcp.set_vm("mpc-tee-0", |vm| *vm = Vm::new("mpc-tee-0"));
    wait_for("node 0 back", &gateway, || {
        usable(&gateway.metrics(), &url) == Some(true)
    });
    let body = attestation(3, 4, 2);
    let (status, answer) = gateway.sign(&key, &body);
    assert_eq!(status, 200, "{answer}");
    assert_eq!(gateway.last()["attempts"][0]["backend"], url);
}

/// A client of the gateway's TLS listener: its CA pinned, a client certificate if any, TLS 1.2
/// alone if `tls12_only`.
fn client(
    ca: &CertificateDer<'static>,
    identity: Option<&Operator>,
    tls12_only: bool,
) -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots.add(ca.clone()).unwrap();
    let versions: &[&rustls::SupportedProtocolVersion] = if tls12_only {
        &[&rustls::version::TLS12]
    } else {
        &[&rustls::version::TLS13]
    };
    let builder = ClientConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
        .with_protocol_versions(versions)
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

#[test]
fn gateway_4_validator_clients_need_a_certificate_of_its_client_ca() {
    let (network, gcp, operator, _) = network_with(|_| true, |_| Vec::new());
    let server = eth_dvt_signer::tls::make(&["127.0.0.1".into()]).unwrap();
    let key_path = network.dir.join("gateway-server-key.pem");
    std::fs::write(
        &key_path,
        rcgen::KeyPair::try_from(server.key.as_slice())
            .unwrap()
            .serialize_pem(),
    )
    .unwrap();
    let chain_path = network.dir.join("gateway-server.pem");
    std::fs::write(&chain_path, &server.chain).unwrap();
    let ca = CertificateDer::pem_slice_iter(server.chain.as_bytes())
        .last()
        .unwrap()
        .unwrap();
    let vc_dir = network.dir.join("validator-client");
    std::fs::create_dir_all(&vc_dir).unwrap();
    let vc = Operator::new(&vc_dir);
    let other_dir = network.dir.join("other-client");
    std::fs::create_dir_all(&other_dir).unwrap();
    let other = Operator::new(&other_dir);
    let listen = |tls12: bool| -> Vec<String> {
        let mut args = vec![
            "--listen-tls-cert".to_string(),
            chain_path.display().to_string(),
            "--listen-tls-key".into(),
            key_path.display().to_string(),
            "--listen-client-ca".into(),
            vc.ca_path.display().to_string(),
        ];
        if tls12 {
            args.push("--listen-tls12".into());
        }
        args
    };
    let upcheck = |gateway: &Gateway, config: Arc<ClientConfig>| {
        http::request_tls(gateway.address, config, "GET", "/upcheck", None, TIMEOUT)
            .map(|(status, _, _)| status)
    };

    let gateway = start(
        &network,
        &gcp,
        &operator,
        &[0, 1, 2, 3],
        &policy(&gcp, release_rtmr3),
        &listen(false),
        Some(client(&ca, Some(&vc), false)),
    );
    assert_eq!(
        upcheck(&gateway, client(&ca, Some(&vc), false)).unwrap(),
        200
    );
    // No certificate, another CA's, TLS 1.2: no answer.
    assert!(upcheck(&gateway, client(&ca, None, false)).is_err());
    assert!(upcheck(&gateway, client(&ca, Some(&other), false)).is_err());
    assert!(upcheck(&gateway, client(&ca, Some(&vc), true)).is_err());
    drop(gateway);

    // With `--listen-tls12`, a TLS 1.2 client gets in too.
    let gateway = start(
        &network,
        &gcp,
        &operator,
        &[0, 1, 2, 3],
        &policy(&gcp, release_rtmr3),
        &listen(true),
        Some(client(&ca, Some(&vc), true)),
    );
    assert_eq!(
        upcheck(&gateway, client(&ca, Some(&vc), true)).unwrap(),
        200
    );
    drop(gateway);

    // A revoked validator client: refused once the gateway reads its list again.
    let revoked = network.dir.join("gateway-revoked-client-certs");
    std::fs::write(&revoked, "").unwrap();
    let mut args = listen(false);
    args.extend([
        "--listen-revoked-client-certs".to_string(),
        revoked.display().to_string(),
    ]);
    let gateway = start(
        &network,
        &gcp,
        &operator,
        &[0, 1, 2, 3],
        &policy(&gcp, release_rtmr3),
        &args,
        Some(client(&ca, Some(&vc), false)),
    );
    std::fs::write(
        &revoked,
        format!(
            "{}\n",
            hex::encode(eth_dvt_signer::tls::fingerprint(&vc.chain[0]))
        ),
    )
    .unwrap();
    let deadline = std::time::Instant::now() + 4 * eth_dvt_signer::tls::REVOCATIONS_RELOAD;
    while upcheck(&gateway, client(&ca, Some(&vc), false)).is_ok() {
        assert!(
            std::time::Instant::now() < deadline,
            "the revoked validator client is still served"
        );
        std::thread::sleep(Duration::from_millis(500));
    }
}
