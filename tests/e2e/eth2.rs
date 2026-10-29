//! E2E-ETH-1 to E2E-ETH-6: the Web3Signer API on a real four-process network, with requests shaped
//! as Lighthouse sends them (`tests/fixtures/web3signer`), slashing protection, restarts, crashes
//! and a lagging node.

use crate::{
    failures::ask,
    harness::{
        NODES, TestNetwork, ethereum_verify, http,
        peer::{FakePeer, Responder},
        root, unhex,
    },
    rollback::CONSENSUS_JOURNAL,
};
use eth_mpc_signer::{
    eth::{
        duty::format_root,
        types::Root,
        web3signer::{parse_identifier, parse_request},
    },
    signer::wire::{self, Refusal, Request},
};
use serde_json::{Value, json};
use std::{path::Path, time::Duration};

/// The validator key's ceremony.
const VALIDATOR: &str = "validator-eth";

/// The chain of the fixtures (their `genesis_validators_root`).
pub(crate) const CHAIN: &str = "0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673";

/// Every supported duty.
const FIXTURES: [&str; 10] = [
    "block_v2_electra.json",
    "attestation.json",
    "randao_reveal.json",
    "aggregation_slot.json",
    "aggregate_and_proof_phase0.json",
    "aggregate_and_proof_electra.json",
    "sync_committee_message.json",
    "sync_committee_selection_proof.json",
    "contribution_and_proof.json",
    "voluntary_exit.json",
];

/// Requests produced by Lighthouse v8.3.2's own code, one per supported duty and fork.
const LIGHTHOUSE: [&str; 14] = [
    "block_v2_bellatrix.json",
    "block_v2_capella.json",
    "block_v2_deneb.json",
    "block_v2_electra.json",
    "block_v2_fulu.json",
    "attestation.json",
    "randao_reveal.json",
    "aggregation_slot.json",
    "aggregate_and_proof_phase0.json",
    "aggregate_and_proof_electra.json",
    "sync_committee_message.json",
    "sync_committee_selection_proof.json",
    "contribution_and_proof.json",
    "voluntary_exit.json",
];

fn lighthouse(name: &str) -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/lighthouse")
        .join(name);
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn fixture(name: &str) -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/web3signer")
        .join(name);
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

/// The signing root of a request, as the signer computes it.
pub(crate) fn signing_root(body: &Value) -> Root {
    let request = parse_request(body.to_string().as_bytes()).unwrap();
    request.duty.signing_root(&request.fork)
}

/// `body` with the `signingRoot` a client computes for it (Lighthouse always sends one).
fn with_root(mut body: Value) -> Value {
    body["signingRoot"] = json!(format_root(&signing_root(&body)));
    body
}

fn hex32(byte: u8) -> String {
    format_root(&[byte; 32])
}

/// A block proposal at `slot`; `body` changes its contents (and root).
pub(crate) fn block(slot: u64, body: u8) -> Value {
    let mut request = fixture("block_v2_electra.json");
    let header = &mut request["beacon_block"]["block_header"];
    header["slot"] = json!(slot.to_string());
    header["body_root"] = json!(hex32(body));
    with_root(request)
}

/// An attestation from `source` to `target`; `vote` changes its data (and root).
pub(crate) fn attestation(source: u64, target: u64, vote: u8) -> Value {
    let mut request = fixture("attestation.json");
    let data = &mut request["attestation"];
    data["slot"] = json!((target * 32).to_string());
    data["beacon_block_root"] = json!(hex32(vote));
    data["source"]["epoch"] = json!(source.to_string());
    data["target"]["epoch"] = json!(target.to_string());
    data["target"]["root"] = json!(hex32(vote));
    with_root(request)
}

/// `POST /validators/activate` on node `via`.
fn activate(network: &TestNetwork, via: usize, key: &str, chain: &str) -> (u16, Value) {
    let body = json!({ "public_key": key, "genesis_validators_root": chain });
    network.post(via, "/validators/activate", &body)
}

/// The activation of `key` as node `node` has it (`GET /validators`), if any.
pub(crate) fn activation(network: &TestNetwork, node: usize, key: &str) -> Option<Value> {
    let (status, validators) = network.get(node, "/validators");
    assert_eq!(status, 200, "{validators}");
    validators
        .as_array()
        .unwrap()
        .iter()
        .find(|validator| validator["public_key"] == key && validator["status"] == "active")
        .cloned()
}

/// Activate `key` for [CHAIN] through node `via` and wait until every node has applied it.
fn activate_everywhere(network: &TestNetwork, via: usize, key: &str) -> Value {
    let (status, activated) = activate(network, via, key, CHAIN);
    assert_eq!(status, 200, "{activated}");
    assert_eq!(activated["status"], "active", "{activated}");
    assert_eq!(activated["genesis_validators_root"], CHAIN, "{activated}");
    for node in network.all() {
        network.wait_until(&format!("activation on node {node}"), || {
            activation(network, node, key).is_some()
        });
        assert_eq!(activation(network, node, key).as_ref(), Some(&activated));
    }
    activated
}

/// A network with a completed validator ceremony, its key activated for [CHAIN]; returns it and
/// the validator public key.
pub(crate) fn validator_network() -> (TestNetwork, String) {
    let network = TestNetwork::start(NODES);
    network.wait_for_ready(&network.all());
    network.start_validator_dkg(0, VALIDATOR);
    let key = network.wait_for_dkg(VALIDATOR, &network.all());
    activate_everywhere(&network, 0, &key);
    (network, key)
}

fn sign(network: &TestNetwork, via: usize, key: &str, body: &Value) -> (u16, Value) {
    network.eth2_sign(via, key, body)
}

/// Sign `body` through `via` and check the signature against `key` and the request's root.
pub(crate) fn signed(network: &TestNetwork, via: usize, key: &str, body: &Value) -> Value {
    let (status, answer) = sign(network, via, key, body);
    assert_eq!(status, 200, "node {via}: {answer} for {body}");
    let root: Root = signing_root(body);
    assert!(
        ethereum_verify(&json!(key), &root, &answer["signature"]),
        "{answer}"
    );
    answer["signature"].clone()
}

/// Expect slashing protection to refuse `body` through `via` with `reason`.
pub(crate) fn refused(network: &TestNetwork, via: usize, key: &str, body: &Value, reason: &str) {
    let (status, answer) = sign(network, via, key, body);
    assert_eq!(status, 412, "node {via}: {answer}");
    assert_eq!(answer["refusal"]["reason"], reason, "{answer}");
    assert!(answer.get("signature").is_none());
}

/// Whether node `node` logged applying `body`'s duty with `decision`.
fn applied(network: &TestNetwork, node: usize, body: &Value, decision: &str) -> bool {
    let root = format_root(&signing_root(body));
    network.log(node).lines().any(|line| {
        line.contains("applied validator duty")
            && line.contains(&root)
            && line.contains(&format!("decision={decision}"))
    })
}

/// E2E-ETH-1: every supported duty signed through the Web3Signer API, verified with blst against
/// the validator key; the API's error cases; purposes kept apart.
#[test]
fn e2e_eth_1_web3signer_signs_every_supported_duty() {
    let network = TestNetwork::start(NODES);
    network.wait_for_ready(&network.all());
    let (status, keys) = network.get(0, "/api/v1/eth2/publicKeys");
    assert_eq!((status, keys), (200, json!([])));

    network.start_validator_dkg(0, VALIDATOR);
    let key = network.wait_for_dkg(VALIDATOR, &network.all());
    // A development key is not a validator key.
    network.start_dkg(1, "development");
    network.wait_for_dkg("development", &network.all());

    // Not activated: listed as inactive, not offered, not signed.
    let (status, validators) = network.get(2, "/validators");
    assert_eq!(status, 200, "{validators}");
    assert_eq!(
        validators,
        json!([{ "public_key": key, "ceremony_id": VALIDATOR, "origin": "dkg", "status": "inactive", "generation": 0 }])
    );
    let (status, keys) = network.get(2, "/api/v1/eth2/publicKeys");
    assert_eq!((status, keys), (200, json!([])));
    let (status, answer) = sign(&network, 3, &key, &fixture("attestation.json"));
    assert_eq!(status, 404, "{answer}");
    assert!(
        answer["error"].as_str().unwrap().contains("not activated"),
        "{answer}"
    );

    // Activation: bad input, an unknown key, then the key for the fixtures' chain.
    let (status, answer) = activate(&network, 0, &key, "0x1234");
    assert_eq!(status, 400, "{answer}");
    let (status, answer) = activate(&network, 0, &format!("0x{}", "ab".repeat(48)), CHAIN);
    assert_eq!(status, 404, "{answer}");
    let activated = activate_everywhere(&network, 1, &key);
    assert!(activated["activated_at"].as_u64().is_some(), "{activated}");
    for node in network.all() {
        let (status, keys) = network.get(node, "/api/v1/eth2/publicKeys");
        assert_eq!((status, keys), (200, json!([key])), "node {node}");
    }
    // Immutable: the same activation again changes nothing, another chain is refused.
    let (status, again) = activate(&network, 3, &key, CHAIN);
    assert_eq!((status, &again), (200, &activated));
    // Deposit signing is off unless a node is started with `--enable-deposit-signing`.
    let (status, answer) = sign(&network, 0, &key, &deposit(&key, 1));
    assert_eq!(status, 400, "{answer}");
    assert!(
        answer["error"].as_str().unwrap().contains("disabled"),
        "{answer}"
    );
    let (status, answer) = activate(&network, 2, &key, &hex32(0x42));
    assert_eq!(status, 409, "{answer}");
    assert_eq!(answer["refusal"]["reason"], "other_chain", "{answer}");
    assert_eq!(
        answer["refusal"]["genesis_validators_root"], CHAIN,
        "{answer}"
    );

    let mut signatures = Vec::new();
    for (index, name) in FIXTURES.iter().enumerate() {
        let body = fixture(name);
        let signature = signed(&network, index % NODES, &key, &body);
        // The client's root is the one the signer computed.
        let root = &body["signingRoot"];
        assert_eq!(
            root.as_str(),
            Some(format_root(&signing_root(&body)).as_str())
        );
        signatures.push(signature);
    }

    // Requests produced by Lighthouse v8.3.2's own code (`tests/fixtures/lighthouse`): signed,
    // and the signature verifies for the root Lighthouse computed. Its Altair request (a whole
    // block) is refused.
    for (index, name) in LIGHTHOUSE.iter().enumerate() {
        let body = lighthouse(name);
        let root: Root = unhex(&body["signingRoot"]).try_into().unwrap();
        let (status, answer) = sign(&network, index % NODES, &key, &body);
        assert_eq!(status, 200, "{name}: {answer}");
        assert!(
            ethereum_verify(&json!(key), &root, &answer["signature"]),
            "{name}: {answer}"
        );
    }
    let (status, answer) = sign(
        &network,
        0,
        &key,
        &lighthouse("block_v2_altair_full_block.json"),
    );
    assert_eq!(status, 400, "{answer}");

    // Repeated through another node: the same signature. Without `Accept: application/json`, the
    // signature as text.
    let body = fixture("attestation.json");
    let (status, content_type, text) = network
        .eth2_call(3, &format!("/api/v1/eth2/sign/{key}"), &[], &body)
        .unwrap();
    assert_eq!(status, 200, "{text}");
    assert!(content_type.starts_with("text/plain"), "{content_type}");
    assert_eq!(json!(text), signatures[1]);

    // Errors: unknown key (also the development key), bad identifier, malformed and unsupported
    // requests, a signing root that is not the duty's.
    let (_, development) = network.get(0, "/dkg/public-key/development");
    for unknown in [
        format!("0x{}", "ab".repeat(48)),
        development["public_key"].as_str().unwrap().to_string(),
    ] {
        let (status, answer) = sign(&network, 0, &unknown, &fixture("randao_reveal.json"));
        assert_eq!(status, 404, "{answer}");
    }
    let (status, answer) = sign(&network, 1, "0x1234", &fixture("randao_reveal.json"));
    assert_eq!(status, 400, "{answer}");
    let mut missing_fork = fixture("attestation.json");
    missing_fork.as_object_mut().unwrap().remove("fork_info");
    let registration = json!({
        "type": "VALIDATOR_REGISTRATION",
        "signingRoot": "0xe4d2b3dd1e23807b90af0b1768cc7de12d4353320adb486f1bdaeed6b67009ea",
        "validator_registration": {
            "fee_recipient": "0x6fdfab408c56b6105a76eff5c0435d09fc6ed7a9",
            "gas_limit": "30000000",
            "timestamp": "1700000000",
            "pubkey": key,
        },
    });
    for (body, what) in [
        (json!("not a request"), "not an object"),
        (missing_fork, "missing fork_info"),
        (registration, "unsupported type"),
    ] {
        let (status, answer) = sign(&network, 2, &key, &body);
        assert_eq!(status, 400, "{what}: {answer}");
    }
    let mut mismatch = block(5, 1);
    mismatch["signingRoot"] = json!(hex32(0xee));
    let (status, answer) = sign(&network, 2, &key, &mismatch);
    assert_eq!(status, 400, "{answer}");
    assert!(
        answer["error"].as_str().unwrap().contains("signing root"),
        "{answer}"
    );
    // Nothing was authorized for it: the right root signs.
    signed(&network, 2, &key, &block(5, 1));

    // The development API cannot use the validator key, and the id cannot change purpose.
    let (status, answer) = network.sign(0, VALIDATOR, 1, root(0xaa));
    assert_eq!(status, 403, "{answer}");
    assert_eq!(answer["result"], "VALIDATOR_KEY");
    let (status, answer) = network.post(1, "/dkg/start", &json!({ "ceremony_id": VALIDATOR }));
    assert_eq!(status, 409, "{answer}");
}

/// E2E-ETH-2: slashing protection over HTTP: double proposals, double votes and surround votes are
/// refused (412) on every node, and of two conflicting duties sent at once through different
/// nodes exactly one is signed.
#[test]
fn e2e_eth_2_slashing_protection() {
    let (network, key) = validator_network();

    signed(&network, 0, &key, &block(10, 1));
    for via in network.all() {
        refused(&network, via, &key, &block(10, 2), "double_proposal");
    }

    signed(&network, 1, &key, &attestation(2, 5, 1));
    refused(&network, 2, &key, &attestation(2, 5, 2), "double_vote");
    refused(&network, 3, &key, &attestation(1, 6, 1), "surrounds_signed");
    refused(
        &network,
        0,
        &key,
        &attestation(3, 4, 1),
        "surrounded_by_signed",
    );
    signed(&network, 1, &key, &attestation(5, 6, 1));
    let (status, answer) = sign(&network, 1, &key, &attestation(9, 8, 1));
    assert_eq!(status, 400, "source after target: {answer}");

    // Two conflicting requests at once, through different nodes.
    let pairs = [
        (block(20, 1), block(20, 2)),
        (attestation(6, 8, 1), attestation(6, 8, 2)),
    ];
    for (a, b) in &pairs {
        let (x, y) = std::thread::scope(|scope| {
            let x = scope.spawn(|| sign(&network, 1, &key, a));
            let y = scope.spawn(|| sign(&network, 3, &key, b));
            (x.join().unwrap(), y.join().unwrap())
        });
        let loser = match (x.0, y.0) {
            (200, 412) => b,
            (412, 200) => a,
            other => panic!("expected 200 and 412, got {other:?}: {} / {}", x.1, y.1),
        };
        for node in network.all() {
            let (status, answer) = sign(&network, node, &key, loser);
            assert_eq!(status, 412, "node {node}: {answer}");
        }
    }
}

/// E2E-ETH-3: the slashing history survives a restart of every node.
#[test]
fn e2e_eth_3_history_survives_full_restart() {
    let (network, key) = validator_network();
    let signature = signed(&network, 0, &key, &block(10, 1));
    signed(&network, 1, &key, &attestation(2, 5, 1));

    for node in network.all() {
        network.stop_node(node);
    }
    for node in network.all() {
        network.restart_node(node);
    }
    network.wait_for_ready(&network.all());
    for node in network.all() {
        let (_, keys) = network.get(node, "/api/v1/eth2/publicKeys");
        assert_eq!(keys, json!([key]));
    }

    assert_eq!(signed(&network, 2, &key, &block(10, 1)), signature);
    refused(&network, 3, &key, &block(10, 2), "double_proposal");
    refused(&network, 0, &key, &attestation(1, 6, 1), "surrounds_signed");
    signed(&network, 1, &key, &attestation(5, 6, 1));
}

fn crash_at(point: &str) -> Vec<(String, String)> {
    vec![("ETH_MPC_SIGNER_CRASH_AT".into(), point.into())]
}

/// Wait until node `node` applied everything node `with` had applied.
fn wait_caught_up(network: &TestNetwork, node: usize, with: usize) {
    let target = network.height(with).unwrap();
    network.wait_until(&format!("node {node} to catch up"), || {
        network.height(node).is_some_and(|height| height >= target)
    });
}

/// Node 1 crashes at `point` while applying the block that authorizes a proposal at `slot`. After
/// its restart it refuses the conflicting proposal and its partial signature of the authorized
/// one is usable (node 2 is frozen, so signing needs node 1).
fn crash_while_applying(network: &TestNetwork, key: &str, point: &str, slot: u64) {
    network.restart_node_with(1, crash_at(point));
    network.wait_for_ready(&[1]);
    wait_caught_up(network, 1, 2);

    let signature = signed(network, 0, key, &block(slot, 1));
    assert!(!network.wait_exit(1).success());
    assert!(network.count(1, &format!("test hook: crashing at {point}")) > 0);

    network.restart_node_with(1, Vec::new());
    network.wait_until("node 1 to refuse the conflicting proposal", || {
        let (status, answer) = sign(network, 1, key, &block(slot, 2));
        assert_ne!(status, 200, "node 1 signed a double proposal: {answer}");
        status == 412
    });
    network.freeze(2);
    let again = sign(network, 3, key, &block(slot, 1));
    network.thaw(2);
    assert_eq!(again.0, 200, "{}", again.1);
    assert_eq!(again.1["signature"], signature);
}

/// E2E-ETH-4: crashes right before and right after a duty's block is durably applied.
#[test]
fn e2e_eth_4_crash_around_duty_application() {
    let (network, key) = validator_network();
    crash_while_applying(&network, &key, "before-apply-authorization", 30);
    crash_while_applying(&network, &key, "after-apply-authorization", 31);
}

/// E2E-ETH-5: a request that fails after consensus authorized it (the coordinator crashed holding
/// two partials, or the client hung up) does not undo the authorization: the conflict stays
/// refused and the duty is signed when asked again.
#[test]
fn e2e_eth_5_failed_requests_keep_their_authorization() {
    let (network, key) = validator_network();
    network.restart_node_with(0, crash_at("partials-2"));
    network.wait_for_ready(&[0]);
    wait_caught_up(&network, 0, 3);

    let proposal = block(40, 1);
    let path = format!("/api/v1/eth2/sign/{key}");
    let lost = network.eth2_call(0, &path, &[("Accept", "application/json")], &proposal);
    assert!(!matches!(lost, Ok((200, _, _))), "{lost:?}");
    assert!(!network.wait_exit(0).success());
    assert!(network.count(0, "test hook: crashing at partials-2") > 0);

    refused(&network, 2, &key, &block(40, 2), "double_proposal");
    let signature = signed(&network, 1, &key, &proposal);
    network.restart_node_with(0, Vec::new());
    network.wait_for_ready(&[0]);
    refused(&network, 0, &key, &block(40, 2), "double_proposal");
    assert_eq!(signed(&network, 0, &key, &proposal), signature);

    // A client that hangs up once consensus authorized its duty (the coordinator is paused there
    // until the client is gone).
    let pause = network.dir.join("pause-authorized");
    std::fs::write(&pause, b"").unwrap();
    network.restart_node_with(
        1,
        vec![
            ("ETH_MPC_SIGNER_PAUSE_AT".into(), "authorized".into()),
            (
                "ETH_MPC_SIGNER_PAUSE_FILE".into(),
                pause.display().to_string(),
            ),
        ],
    );
    network.wait_for_ready(&[1]);
    let paused = network.count(1, "test hook: paused");
    let vote = attestation(3, 4, 1);
    let stream = http::open(network.http_addr(1), "POST", &path, &vote.to_string()).unwrap();
    network.wait_until("the coordinator to pause once authorized", || {
        network.count(1, "test hook: paused") > paused
    });
    drop(stream);
    std::fs::remove_file(&pause).unwrap();
    assert!(applied(&network, 1, &vote, "Accepted"));
    refused(&network, 3, &key, &attestation(3, 4, 2), "double_vote");
    signed(&network, 3, &key, &vote);
}

/// E2E-ETH-6: node 3 holds finalized blocks unapplied (it keeps voting): it never signs a duty
/// that conflicts with one it has not applied yet, and refuses it once caught up.
#[test]
fn e2e_eth_6_lagging_node_never_signs_a_conflict() {
    let (network, key) = validator_network();
    let hold = network.dir.join("hold-3");
    network.restart_node_with(
        3,
        vec![(
            "ETH_MPC_SIGNER_HOLD_FILE".into(),
            hold.display().to_string(),
        )],
    );
    network.wait_for_ready(&network.all());
    wait_caught_up(&network, 3, 0);

    std::fs::write(&hold, b"").unwrap();
    network.wait_until("node 3 to hold blocks", || {
        network.count(3, "test hook: holding block execution") > 0
    });
    let proposal = block(50, 1);
    signed(&network, 0, &key, &proposal);
    let conflict = block(50, 2);
    let (status, answer) = std::thread::scope(|scope| {
        let request = scope.spawn(|| sign(&network, 3, &key, &conflict));
        std::thread::sleep(Duration::from_secs(3));
        std::fs::remove_file(&hold).unwrap();
        request.join().unwrap()
    });
    eprintln!("lagging node answered {status}: {answer}");
    assert!(
        matches!(status, 412 | 503 | 504),
        "a lagging node answered {status}: {answer}"
    );
    network.wait_until("node 3 to apply the proposal", || {
        applied(&network, 3, &proposal, "Accepted")
    });
    refused(&network, 3, &key, &conflict, "double_proposal");
    for node in network.all() {
        assert!(
            !applied(&network, node, &conflict, "Accepted"),
            "node {node} authorized the conflict"
        );
    }
}

/// E2E-ETH-7: node 3 is rolled back to storage from before a block proposal was authorized (all
/// but its consensus journal, a supported recovery). It never signs the conflicting proposal: it
/// refuses or waits until it has replayed the history, then refuses with 412, and its partial
/// signature of the authorized proposal is usable again.
#[test]
fn e2e_eth_7_rolled_back_node_never_signs_a_conflict() {
    let (network, key) = validator_network();
    network.stop_node(3);
    network.snapshot(3, "before-proposal");
    network.restart_node(3);
    network.wait_for_ready(&[3]);
    let signature = signed(&network, 0, &key, &block(60, 1));

    network.stop_node(3);
    network.restore_keeping(3, "before-proposal", &[crate::rollback::CONSENSUS_JOURNAL]);
    network.restart_node(3);
    network.wait_until("node 3 to refuse the conflicting proposal", || {
        let (status, answer) = sign(&network, 3, &key, &block(60, 2));
        assert_ne!(
            status, 200,
            "a rolled-back node signed a double proposal: {answer}"
        );
        status == 412
    });
    network.freeze(2);
    let again = sign(&network, 0, &key, &block(60, 1));
    network.thaw(2);
    assert_eq!(again.0, 200, "{}", again.1);
    assert_eq!(again.1["signature"], signature);
}

/// Fault-model boundary (L-1, docs/slashing-protection.md): every node rolled back to storage
/// from before a block proposal. No node remembers it, so the conflicting proposal is authorized
/// and signed: a slashable pair. Undetectable without slashing history the rollback cannot reach;
/// kept as an explicit, failing reproducer.
#[test]
#[ignore = "known limitation (docs/slashing-protection.md): a whole-network rollback forgets slashing history"]
fn e2e_eth_l1_whole_network_rollback_signs_a_double_proposal() {
    let (network, key) = validator_network();
    for node in network.all() {
        network.stop_node(node);
        network.snapshot(node, &format!("before-proposal-{node}"));
    }
    for node in network.all() {
        network.restart_node(node);
    }
    network.wait_for_ready(&network.all());
    signed(&network, 0, &key, &block(70, 1));

    for node in network.all() {
        network.stop_node(node);
        network.restore(node, &format!("before-proposal-{node}"));
    }
    for node in network.all() {
        network.restart_node(node);
    }
    network.wait_for_ready(&network.all());
    let (status, answer) = sign(&network, 1, &key, &block(70, 2));
    assert_ne!(
        status, 200,
        "double proposal signed after a whole-network rollback: {answer}"
    );
}

/// E2E-ETH-8: node 3 is rolled back to storage from before the validator's activation (all but its
/// consensus journal). It replays the activation; until then it signs nothing for the key, and
/// never for another chain; the activation cannot be changed through it.
#[test]
fn e2e_eth_8_recovery_cannot_reset_the_chain_identity() {
    let network = TestNetwork::start(NODES);
    network.wait_for_ready(&network.all());
    network.start_validator_dkg(0, VALIDATOR);
    let key = network.wait_for_dkg(VALIDATOR, &network.all());
    network.stop_node(3);
    network.snapshot(3, "before-activation");
    network.restart_node(3);
    network.wait_for_ready(&[3]);

    let activated = activate_everywhere(&network, 0, &key);
    let signature = signed(&network, 0, &key, &block(80, 1));

    network.stop_node(3);
    network.restore_keeping(3, "before-activation", &[CONSENSUS_JOURNAL]);
    network.restart_node(3);
    let mut other_chain = fixture("block_v2_electra.json");
    other_chain["fork_info"]["genesis_validators_root"] = json!(hex32(0x42));
    other_chain["beacon_block"]["block_header"]["slot"] = json!("81");
    let other_chain = with_root(other_chain);
    network.wait_until("node 3 to replay the activation", || {
        let (status, answer) = sign(&network, 3, &key, &other_chain);
        assert_ne!(
            status, 200,
            "a rolled-back node signed for another chain: {answer}"
        );
        activation(&network, 3, &key).is_some()
    });
    assert_eq!(activation(&network, 3, &key), Some(activated));
    refused(&network, 3, &key, &other_chain, "other_chain");
    let (status, answer) = activate(&network, 3, &key, &hex32(0x42));
    assert_eq!(status, 409, "{answer}");
    // The activation does not mean it has replayed everything after it: while it still has a
    // backlog, a duty it does not know yet would be a new authorization, which it refuses (503).
    wait_caught_up(&network, 3, 0);
    assert_eq!(signed(&network, 3, &key, &block(80, 1)), signature);
}

/// E2E-ETH-9: authorization binding on the wire. A scripted peer with node 3's identity (real p2p
/// credentials) asks the other nodes for partial signatures under every kind of reference.
#[test]
fn e2e_eth_9_signing_requests_are_bound_to_their_authorization() {
    let (network, key) = validator_network();
    network.start_dkg(0, "development");
    network.wait_for_dkg("development", &network.all());
    let proposal = block(90, 1);
    signed(&network, 0, &key, &proposal);
    let signing_root = signing_root(&proposal);
    let validator = parse_identifier(&key).unwrap();
    for node in 0..3 {
        network.wait_until(&format!("the proposal applied on node {node}"), || {
            applied(&network, node, &proposal, "Accepted")
        });
    }

    network.stop_node(3);
    let silent: Responder = Box::new(|_, _, _| Vec::new());
    let peer = FakePeer::start(&network, 3, &[], silent);
    let id = |name: &str| eth_mpc_signer::dkg::CeremonyId::new(name).unwrap();
    let refused = |answer: wire::Message| match answer {
        wire::Message::Refused { reason, .. } => Some(reason),
        _ => None,
    };
    for node in 0..3 {
        // The genuine reference: a partial signature.
        let genuine = Request::duty(id(VALIDATOR), validator, signing_root);
        assert!(matches!(
            ask(&network, &peer, node, &genuine),
            wire::Message::Partial { .. }
        ));
        // The same root as a development request, nonce 0 or another: another purpose.
        for nonce in [0, 7] {
            let development = Request::new(id(VALIDATOR), nonce, signing_root);
            assert_eq!(
                refused(ask(&network, &peer, node, &development)),
                Some(Refusal::WrongPurpose)
            );
        }
        // A development key's ceremony asked for the validator's duty: another purpose.
        let development_key = Request::duty(id("development"), validator, signing_root);
        assert_eq!(
            refused(ask(&network, &peer, node, &development_key)),
            Some(Refusal::WrongPurpose)
        );
        // Under another key, or for another root: not authorized.
        let other_key = Request::duty(id(VALIDATOR), [0xab; 48], signing_root);
        let other_root = Request::duty(id(VALIDATOR), validator, root(0xee));
        for request in [other_key, other_root] {
            assert_eq!(
                refused(ask(&network, &peer, node, &request)),
                Some(Refusal::NotAuthorized)
            );
        }
    }
}

/// A `DEPOSIT` request for `pubkey` with withdrawal credentials `credentials` (all bytes).
fn deposit(pubkey: &str, credentials: u8) -> Value {
    with_root(json!({
        "type": "DEPOSIT",
        "deposit": {
            "pubkey": pubkey,
            "withdrawal_credentials": hex32(credentials),
            "amount": "32000000000",
            "genesis_fork_version": "0x10000038",
        },
    }))
}

/// E2E-ETH-10: validator onboarding. With `--enable-deposit-signing`, an activated validator key
/// signs one deposit message of its own key, verified with blst; the same message again returns
/// the same signature; other withdrawal credentials, or another key, are refused.
#[test]
fn e2e_eth_10_one_deposit_message_per_validator() {
    let network =
        TestNetwork::start_with_args(NODES, vec!["--enable-deposit-signing".into()], |_| {
            Vec::new()
        });
    network.wait_for_ready(&network.all());
    network.start_validator_dkg(0, VALIDATOR);
    let key = network.wait_for_dkg(VALIDATOR, &network.all());

    // Not activated: nothing, not even a deposit.
    let (status, answer) = sign(&network, 1, &key, &deposit(&key, 1));
    assert_eq!(status, 404, "{answer}");
    activate_everywhere(&network, 0, &key);

    let signature = signed(&network, 2, &key, &deposit(&key, 1));
    assert_eq!(signed(&network, 3, &key, &deposit(&key, 1)), signature);
    refused(&network, 0, &key, &deposit(&key, 2), "too_many_roots");
    refused(
        &network,
        1,
        &key,
        &deposit(&format!("0x{}", "ab".repeat(48)), 1),
        "deposit_for_another_key",
    );
}
