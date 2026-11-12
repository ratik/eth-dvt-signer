//! Unit tests of `crate::gateway` against fake nodes on loopback (`http://`, development keys): the
//! hedged failover, the signature check, refusals, unusable nodes and the log's shape.

use super::*;
use crate::{
    dkg::{Variant, signing::ETHEREUM_DST},
    eth::web3signer::duty_request,
};
use axum::{extract::Path as AxumPath, routing::get};
use commonware_codec::Encode as _;
use commonware_cryptography::bls12381::primitives::{
    group::{Private, Scalar},
    ops,
};
use serde_json::{Value, json};
use std::sync::atomic::AtomicUsize;

/// What a fake node does with a signing request.
#[derive(Clone, Copy)]
enum Behaviour {
    /// Sign it, after `delay` milliseconds.
    Sign(u64),
    /// Sign another root.
    WrongSignature,
    /// Answer this status.
    Status(u16),
    /// Answer this status the first time, then sign.
    StatusThenSign(u16),
}

struct Fake {
    url: String,
    requests: Arc<AtomicUsize>,
}

fn private() -> Private {
    Private::new(Scalar::from_u64(31337))
}

fn validator() -> String {
    format!(
        "0x{}",
        hex::encode(ops::compute_public::<Variant>(&private()).encode())
    )
}

fn attestation() -> Bytes {
    Bytes::from(include_str!("../fixtures/web3signer/attestation.json"))
}

/// A fake node on loopback, signing for [Network::MAINNET] (or another chain).
async fn fake(behaviour: Behaviour, network: NetworkJson) -> Fake {
    let requests = Arc::new(AtomicUsize::new(0));
    let counter = requests.clone();
    let router = Router::new()
        .route(
            "/eth/network",
            get(move || {
                let network = network.clone();
                async move { axum::Json(network) }
            }),
        )
        .route(
            "/api/v1/eth2/sign/{identifier}",
            post(move |AxumPath(identifier): AxumPath<String>, body: Bytes| {
                let counter = counter.clone();
                async move {
                    let earlier = counter.fetch_add(1, Ordering::SeqCst);
                    let (request, _) =
                        duty_request(&identifier, &body, Some(&Network::MAINNET)).unwrap();
                    let mut root = request.signing_root();
                    match behaviour {
                        Behaviour::Sign(delay) => {
                            tokio::time::sleep(Duration::from_millis(delay)).await;
                        }
                        Behaviour::WrongSignature => root[0] ^= 1,
                        Behaviour::StatusThenSign(_) if earlier > 0 => {}
                        Behaviour::Status(status) | Behaviour::StatusThenSign(status) => {
                            return (
                                StatusCode::from_u16(status).unwrap(),
                                axum::Json(json!({"error": "refused"})),
                            )
                                .into_response();
                        }
                    }
                    let signature = ops::sign::<Variant>(&private(), ETHEREUM_DST, &root);
                    axum::Json(
                        json!({"signature": format!("0x{}", hex::encode(signature.encode()))}),
                    )
                    .into_response()
                }
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    Fake { url, requests }
}

async fn start(fakes: &[&Fake], hedge_after: Duration) -> Arc<Gateway> {
    let gateway = Gateway::new(Config {
        nodes: fakes.iter().map(|fake| fake.url.clone()).collect(),
        client_certificate: None,
        policy: None,
        jwks: None,
        allow_unattested: true,
        network: Network::MAINNET,
        hedge_after,
        node_timeout: Duration::from_secs(5),
        request_deadline: Duration::from_secs(10),
        attest_every: Duration::from_secs(60),
        request_log: None,
        requests: None,
    })
    .unwrap();
    gateway.check_all().await;
    gateway
}

async fn sign(gateway: &Gateway) -> (Answer, Vec<log::Attempt>) {
    let key = validator();
    gateway
        .sign(
            &format!("/api/v1/eth2/sign/{key}"),
            &key,
            vec![("accept", "application/json".into())],
            attestation(),
        )
        .await
}

fn run<F: std::future::Future<Output = ()>>(test: F) {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(test);
}

fn signed(answer: &Answer) -> bool {
    let (request, _) = duty_request(&validator(), &attestation(), Some(&Network::MAINNET)).unwrap();
    let signature: Value = serde_json::from_slice(&answer.body).unwrap();
    let signature = hex::decode(&signature["signature"].as_str().unwrap()[2..]).unwrap();
    answer.status == 200
        && crate::eth::web3signer::verify_signature(
            &request.validator,
            &request.signing_root(),
            &signature,
        )
}

#[test]
fn the_first_node_signs() {
    run(async {
        let network = Network::MAINNET.to_json();
        let (first, second) = (
            fake(Behaviour::Sign(0), network.clone()).await,
            fake(Behaviour::Sign(0), network).await,
        );
        let gateway = start(&[&first, &second], Duration::from_secs(1)).await;
        let (answer, attempts) = sign(&gateway).await;
        assert!(signed(&answer));
        assert_eq!(attempts.len(), 1);
        assert_eq!(second.requests.load(Ordering::SeqCst), 0);
    });
}

/// A coordinator's signature that does not verify is never passed on: the next node signs.
#[test]
fn a_wrong_signature_is_not_passed_on() {
    run(async {
        let network = Network::MAINNET.to_json();
        let (faulty, honest) = (
            fake(Behaviour::WrongSignature, network.clone()).await,
            fake(Behaviour::Sign(0), network).await,
        );
        let gateway = start(&[&faulty, &honest], Duration::from_secs(1)).await;
        let (answer, attempts) = sign(&gateway).await;
        assert!(signed(&answer));
        assert_eq!(attempts.len(), 2);
        assert!(attempts[0].invalid_signature);
        assert_eq!(attempts[1].backend, honest.url);
        // The faulty node is tried last for a while.
        assert_eq!(gateway.order()[0].url, honest.url);
        assert!(
            gateway
                .metrics
                .encode()
                .contains("invalid_signatures_total")
        );
    });
}

#[test]
fn a_refusal_is_final_and_unavailability_fails_over() {
    run(async {
        let network = Network::MAINNET.to_json();
        let (refusing, other) = (
            fake(Behaviour::Status(412), network.clone()).await,
            fake(Behaviour::Sign(0), network.clone()).await,
        );
        let gateway = start(&[&refusing, &other], Duration::from_secs(1)).await;
        let (answer, attempts) = sign(&gateway).await;
        assert_eq!(answer.status, 412);
        assert_eq!(attempts.len(), 1);
        assert_eq!(other.requests.load(Ordering::SeqCst), 0);

        let (unavailable, available) = (
            fake(Behaviour::Status(503), network.clone()).await,
            fake(Behaviour::Sign(0), network).await,
        );
        let gateway = start(&[&unavailable, &available], Duration::from_secs(1)).await;
        let (answer, attempts) = sign(&gateway).await;
        assert!(signed(&answer));
        assert_eq!(
            attempts.iter().map(|a| a.status).collect::<Vec<_>>(),
            vec![Some(503), Some(200)]
        );
    });
}

/// A node that has not answered after `hedge_after` gets the next node asked too: the first
/// answer wins, long before the slow node's.
#[test]
fn a_slow_node_is_hedged() {
    run(async {
        let network = Network::MAINNET.to_json();
        let (slow, fast) = (
            fake(Behaviour::Sign(3000), network.clone()).await,
            fake(Behaviour::Sign(0), network).await,
        );
        let gateway = start(&[&slow, &fast], Duration::from_millis(100)).await;
        let began = Instant::now();
        let (answer, attempts) = sign(&gateway).await;
        assert!(signed(&answer));
        assert!(
            began.elapsed() < Duration::from_secs(2),
            "{:?}",
            began.elapsed()
        );
        assert_eq!(attempts.len(), 1);
        assert!(attempts[0].hedged);
        assert_eq!(attempts[0].backend, fast.url);
        assert!(
            gateway
                .metrics
                .encode()
                .contains("mpc_gateway_hedges_total 1")
        );
    });
}

/// A node of another chain is never used; with none left, the gateway answers 503 itself.
#[test]
fn a_node_of_another_chain_is_not_used() {
    run(async {
        let other = fake(Behaviour::Sign(0), Network::HOODI.to_json()).await;
        let gateway = start(&[&other], Duration::from_secs(1)).await;
        assert!(!gateway.nodes()[0].usable());
        assert!(
            gateway.nodes()[0]
                .reason()
                .unwrap()
                .contains("another chain")
        );
        let (answer, attempts) = sign(&gateway).await;
        assert_eq!(answer.status, 503);
        assert!(attempts.is_empty());
        assert_eq!(other.requests.load(Ordering::SeqCst), 0);
    });
}

/// The log's record has the development proxy's shape, which the devnet report reads.
#[test]
fn the_log_has_the_proxys_shape() {
    let key = validator();
    let path = format!("/api/v1/eth2/sign/{key}");
    let attempts = [log::Attempt {
        backend: "http://127.0.0.1:1".into(),
        status: Some(200),
        error: None,
        ms: 12.345,
        hedged: false,
        invalid_signature: false,
    }];
    let body = attestation();
    let record = Entry {
        id: 7,
        ts: 1.5,
        ms: 13.0,
        method: "POST",
        path: &path,
        client: Some("Lighthouse/v8.3.2"),
        status: 200,
        attempts: &attempts,
        body: &body,
    }
    .to_json();
    assert_eq!(record["type"], "ATTESTATION");
    assert_eq!(record["slot"], 32);
    assert_eq!(record["validator"], key);
    assert_eq!(
        record["signing_root"],
        "0x548c9a015f4c96cb8b1ddbbdfca85846f85bf9f344a434c140f378cdfb5341f0"
    );
    assert_eq!(record["fork_version"], "0x00000001");
    assert_eq!(record["attempts"][0]["status"], 200);
    assert_eq!(record["attempts"][0]["ms"], 12.35);
    assert!(record["attempts"][0].get("hedged").is_none());
    assert_eq!(record["client"], "Lighthouse/v8.3.2");
}

/// Every node answers 504 at first (consensus is waiting for a stopped leader): each is asked once
/// more after the others, and the second answer signs.
#[test]
fn a_node_that_could_not_finish_is_asked_again() {
    run(async {
        let network = Network::MAINNET.to_json();
        let (first, second) = (
            fake(Behaviour::StatusThenSign(504), network.clone()).await,
            fake(Behaviour::StatusThenSign(504), network).await,
        );
        let gateway = start(&[&first, &second], Duration::from_secs(1)).await;
        let (answer, attempts) = sign(&gateway).await;
        assert!(signed(&answer));
        assert_eq!(
            attempts
                .iter()
                .map(|a| (a.backend.clone(), a.status))
                .collect::<Vec<_>>(),
            vec![
                (first.url.clone(), Some(504)),
                (second.url.clone(), Some(504)),
                (first.url.clone(), Some(200)),
            ]
        );

        // Never more than twice each: a node that keeps answering 503 ends the request.
        let network = Network::MAINNET.to_json();
        let busy = fake(Behaviour::Status(503), network).await;
        let gateway = start(&[&busy], Duration::from_secs(1)).await;
        let (answer, attempts) = sign(&gateway).await;
        assert_eq!(answer.status, 503);
        assert_eq!(attempts.len(), 2);
        assert_eq!(busy.requests.load(Ordering::SeqCst), 2);
    });
}
