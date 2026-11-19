//! E2E-RSH: share generations of a validator key (resharing, docs/resharing.md) on real processes:
//! a reshare that keeps the key and refreshes every share, its activation through consensus,
//! signing before, during and after, crashes at every step, invalid participants, and an imported
//! key.

use crate::{
    eth2::{CHAIN, activation, attestation, block, refused, signed, signing_root},
    harness::{NODES, TestNetwork, peer::FakePeer},
    import::{
        ACKNOWLEDGED, CEREMONY as IMPORTED, PUBKEY as IMPORTED_KEY, import_network, interchange,
        original_signature, split,
    },
};
use commonware_codec::{DecodeExt as _, Encode as _};
use commonware_cryptography::{Signer as _, ed25519::PrivateKey, sha256::Digest};
use eth_dvt_signer::{
    dkg::ceremony::ReadyAck,
    engine,
    types::{Command, Transaction},
};
use serde_json::{Value, json};

const VALIDATOR: &str = "validator-eth";

pub(crate) fn crash_at(point: &str) -> Vec<(String, String)> {
    vec![("ETH_MPC_SIGNER_CRASH_AT".into(), point.into())]
}

/// A network (node `i` with the environment `env(i)`) with the activated DKG validator key
/// [VALIDATOR]; returns it and the key.
pub(crate) fn validator_network_with(
    env: impl Fn(usize) -> Vec<(String, String)>,
) -> (TestNetwork, String) {
    let network = TestNetwork::start_with(NODES, env);
    network.wait_for_ready(&network.all());
    network.start_validator_dkg(0, VALIDATOR);
    let key = network.wait_for_dkg(VALIDATOR, &network.all());
    let (status, activated) = network.approved(
        0,
        "activate",
        json!({ "public_key": key, "genesis_validators_root": CHAIN }),
    );
    assert_eq!(status, 200, "{activated}");
    for node in network.all() {
        network.wait_until(&format!("activation on node {node}"), || {
            activation(&network, node, &key).is_some()
        });
    }
    (network, key)
}

/// `POST /validators/reshare` on node `via`.
fn reshare(network: &TestNetwork, via: usize, key: &str, name: &str) -> (u16, Value) {
    network.post(
        via,
        "/validators/reshare",
        &json!({ "public_key": key, "ceremony_id": name }),
    )
}

fn start_reshare(network: &TestNetwork, via: usize, key: &str, name: &str) -> Value {
    let (status, started) = reshare(network, via, key, name);
    assert_eq!(status, 200, "{started}");
    started
}

/// `POST /validators/reshare/{action}` (`activate` or `abort`) on node `via`.
pub(crate) fn generation_call(
    network: &TestNetwork,
    via: usize,
    action: &str,
    key: &str,
    name: &str,
) -> (u16, Value) {
    network.post(
        via,
        &format!("/validators/reshare/{action}"),
        &json!({ "public_key": key, "ceremony_id": name }),
    )
}

pub(crate) fn reshare_status(network: &TestNetwork, node: usize, name: &str) -> Value {
    let (status, body) = network.get(node, &format!("/validators/reshare/{name}"));
    assert_eq!(status, 200, "{body}");
    body
}

/// Wait until every node reports the reshare `name` in `state`.
fn wait_reshare(network: &TestNetwork, name: &str, state: &str) {
    for node in network.all() {
        network.wait_until(&format!("reshare {name} {state} on node {node}"), || {
            reshare_status(network, node, name)["status"] == state
        });
    }
}

/// `(generation, active ceremony)` of `key` on node `node`.
pub(crate) fn generation(network: &TestNetwork, node: usize, key: &str) -> (u64, String) {
    let validator = activation(network, node, key).expect("an active validator");
    (
        validator["generation"].as_u64().unwrap(),
        validator["ceremony_id"].as_str().unwrap().to_string(),
    )
}

pub(crate) fn wait_generation(
    network: &TestNetwork,
    nodes: &[usize],
    key: &str,
    expected: (u64, &str),
) {
    for &node in nodes {
        network.wait_until(&format!("generation {expected:?} on node {node}"), || {
            let (generation, ceremony) = generation(network, node, key);
            (generation, ceremony.as_str()) == expected
        });
    }
}

pub(crate) fn dkg_status(network: &TestNetwork, node: usize, name: &str) -> Value {
    let (status, body) = network.get(node, &format!("/dkg/status/{name}"));
    assert_eq!(status, 200, "{body}");
    body
}

/// Start the reshare `name` of `key`, wait until every new share is acknowledged, activate it
/// through `via`, and wait until every node signs with it.
fn reshare_and_activate(network: &TestNetwork, via: usize, key: &str, name: &str, generation: u64) {
    start_reshare(network, via, key, name);
    wait_reshare(network, name, "ready");
    let (status, activated) = generation_call(network, via, "activate", key, name);
    assert_eq!(status, 200, "{activated}");
    assert_eq!(activated["status"], "active", "{activated}");
    wait_generation(network, &network.all(), key, (generation, name));
}

/// E2E-RSH-1: a DKG key reshared. Generation 0 signs before and during the reshare; after the
/// activation every node signs with generation 1: the same key and signatures, other shares and
/// verification shares, and the same slashing history (conflicts refused, repeats identical). One
/// keyholder offline, then back with the new generation.
#[test]
fn e2e_rsh_1_a_reshare_refreshes_every_share_and_keeps_the_key_and_history() {
    let (network, key) = validator_network_with(|_| Vec::new());
    let g0 = dkg_status(&network, 0, VALIDATOR);
    let first = signed(&network, 0, &key, &block(10, 1));
    signed(&network, 1, &key, &attestation(1, 2, 1));
    signed(&network, 2, &key, &attestation(2, 5, 1));

    let started = start_reshare(&network, 1, &key, "validator-eth-g1");
    assert_eq!(started["from_round"], g0["round"], "{started}");
    assert_eq!(started["validator_public_key"], key, "{started}");
    // One reshare of a key at a time; an unknown key; a key that is not activated is refused.
    assert_eq!(reshare(&network, 2, &key, "validator-eth-g1b").0, 409);
    assert_eq!(
        reshare(&network, 2, &format!("0x{}", "ab".repeat(48)), "unknown-g1").0,
        404
    );
    wait_reshare(&network, "validator-eth-g1", "ready");

    // Not activated yet: generation 0 still signs.
    for node in network.all() {
        assert_eq!(generation(&network, node, &key), (0, VALIDATOR.to_string()));
    }
    signed(&network, 3, &key, &block(11, 1));

    let (status, activated) = generation_call(&network, 3, "activate", &key, "validator-eth-g1");
    assert_eq!(status, 200, "{activated}");
    wait_generation(&network, &network.all(), &key, (1, "validator-eth-g1"));
    // Idempotent; the active generation cannot be aborted.
    assert_eq!(
        generation_call(&network, 0, "activate", &key, "validator-eth-g1").0,
        200
    );
    let (status, refused_abort) = generation_call(&network, 0, "abort", &key, "validator-eth-g1");
    assert_eq!(
        (status, refused_abort["refusal"]["reason"].as_str()),
        (409, Some("active")),
        "{refused_abort}"
    );

    // The same key; every verification share and the generation id changed; every node holds its
    // new share and erased the old one.
    let g1 = dkg_status(&network, 0, "validator-eth-g1");
    assert_eq!(g1["public_key"], g0["public_key"]);
    assert_eq!(g1["public_key"], key);
    assert_ne!(g1["generation_id"], g0["generation_id"]);
    let (before, after) = (
        g0["verification_shares"].as_array().unwrap(),
        g1["verification_shares"].as_array().unwrap(),
    );
    assert_eq!(before.len(), NODES);
    for (old, new) in before.iter().zip(after) {
        assert_ne!(old, new, "every verification share changes");
    }
    for node in network.all() {
        assert_eq!(
            dkg_status(&network, node, "validator-eth-g1")["share"],
            "stored"
        );
        // The keyholder learns of the activation right after its block is durable.
        network.wait_until(&format!("node {node} to retire generation 0"), || {
            dkg_status(&network, node, VALIDATOR)["share"] == "retired"
        });
    }

    // The same history: a repeat gives the same signature, conflicts and surround votes are
    // refused, new duties sign with generation 1.
    assert_eq!(signed(&network, 1, &key, &block(10, 1)), first);
    refused(&network, 2, &key, &block(10, 2), "double_proposal");
    refused(&network, 3, &key, &attestation(1, 2, 2), "double_vote");
    refused(&network, 0, &key, &attestation(0, 6, 1), "surrounds_signed");
    refused(
        &network,
        1,
        &key,
        &attestation(3, 4, 1),
        "surrounded_by_signed",
    );
    let body = block(12, 1);
    signed(&network, 0, &key, &body);
    let root = format!("0x{}", hex::encode(signing_root(&body)));
    network.wait_until("node 0 to log the generation it signed with", || {
        network.log(0).lines().any(|line| {
            line.contains("signed validator duty")
                && line.contains(&root)
                && line.contains("generation=validator-eth-g1")
        })
    });

    // One keyholder offline: three sign; it restarts with generation 1.
    network.stop_node(3);
    signed(&network, 0, &key, &block(13, 1));
    network.restart_node(3);
    network.wait_for_ready(&[3]);
    wait_generation(&network, &[3], &key, (1, "validator-eth-g1"));
    // Node 2 frozen: the signature needs node 3's new share (a stable node coordinates).
    network.freeze(2);
    signed(&network, 0, &key, &block(14, 1));
    network.thaw(2);
}

/// E2E-RSH-2: a reshare interrupted by a keyholder crash: generation 0 keeps signing; the node
/// restarts and resumes its dealing (same seed); the completed reshare is aborted instead of
/// activated (generation 0 stays), then another reshare completes and is activated.
#[test]
fn e2e_rsh_2_failure_before_activation_keeps_the_previous_generation() {
    let (network, key) = validator_network_with(|node| {
        if node == 2 {
            crash_at("reshare-after-seed")
        } else {
            Vec::new()
        }
    });
    start_reshare(&network, 0, &key, "validator-eth-g1");
    assert!(!network.wait_exit(2).success());
    assert!(network.count(2, "test hook: crashing at reshare-after-seed") > 0);
    // Three keyholders, generation 0.
    signed(&network, 1, &key, &block(20, 1));
    let (status, early) = generation_call(&network, 0, "activate", &key, "validator-eth-g1");
    assert_eq!(
        (status, early["refusal"]["reason"].as_str()),
        (409, Some("not_completed")),
        "{early}"
    );

    network.restart_node_with(2, Vec::new());
    wait_reshare(&network, "validator-eth-g1", "ready");
    let (status, aborted) = generation_call(&network, 1, "abort", &key, "validator-eth-g1");
    assert_eq!(status, 200, "{aborted}");
    assert_eq!(aborted["status"], "aborted", "{aborted}");
    let (status, refused_activation) =
        generation_call(&network, 0, "activate", &key, "validator-eth-g1");
    assert_eq!(
        (status, refused_activation["refusal"]["reason"].as_str()),
        (409, Some("aborted")),
        "{refused_activation}"
    );
    for node in network.all() {
        assert_eq!(generation(&network, node, &key), (0, VALIDATOR.to_string()));
        network.wait_until(&format!("node {node} to erase the aborted share"), || {
            dkg_status(&network, node, "validator-eth-g1")["share"] != "stored"
        });
    }
    signed(&network, 2, &key, &block(21, 1));

    reshare_and_activate(&network, 3, &key, "validator-eth-g2", 1);
    signed(&network, 2, &key, &block(22, 1));
    refused(&network, 0, &key, &block(20, 2), "double_proposal");
}

/// E2E-RSH-3: crashes around the activation: right after node 1 durably applied it (before its
/// keyholder learnt of it), right before node 3 applied the next one; three keyholders sign with
/// the new generation meanwhile, and each restarted node signs with it.
#[test]
fn e2e_rsh_3_crash_around_activation() {
    let (network, key) = validator_network_with(|_| Vec::new());
    let first = signed(&network, 0, &key, &block(30, 1));

    start_reshare(&network, 0, &key, "validator-eth-g1");
    wait_reshare(&network, "validator-eth-g1", "ready");
    network.restart_node_with(1, crash_at("after-apply-activation"));
    network.wait_for_ready(&[1]);
    let (status, activated) = generation_call(&network, 0, "activate", &key, "validator-eth-g1");
    assert_eq!(status, 200, "{activated}");
    assert!(!network.wait_exit(1).success());
    assert!(network.count(1, "test hook: crashing at after-apply-activation") > 0);
    wait_generation(&network, &[0, 2, 3], &key, (1, "validator-eth-g1"));
    signed(&network, 2, &key, &block(31, 1));
    network.restart_node_with(1, Vec::new());
    network.wait_for_ready(&[1]);
    wait_generation(&network, &[1], &key, (1, "validator-eth-g1"));
    network.wait_until("node 1 to retire generation 0", || {
        dkg_status(&network, 1, VALIDATOR)["share"] == "retired"
    });
    network.freeze(3);
    signed(&network, 0, &key, &block(32, 1));
    network.thaw(3);

    start_reshare(&network, 2, &key, "validator-eth-g2");
    wait_reshare(&network, "validator-eth-g2", "ready");
    network.restart_node_with(3, crash_at("before-apply-activation"));
    network.wait_for_ready(&[3]);
    let (status, activated) = generation_call(&network, 0, "activate", &key, "validator-eth-g2");
    assert_eq!(status, 200, "{activated}");
    assert!(!network.wait_exit(3).success());
    wait_generation(&network, &[0, 1, 2], &key, (2, "validator-eth-g2"));
    signed(&network, 1, &key, &block(33, 1));
    network.restart_node_with(3, Vec::new());
    network.wait_for_ready(&[3]);
    wait_generation(&network, &[3], &key, (2, "validator-eth-g2"));
    network.freeze(0);
    signed(&network, 1, &key, &block(34, 1));
    network.thaw(0);
    assert_eq!(signed(&network, 2, &key, &block(30, 1)), first);
    refused(&network, 3, &key, &block(30, 2), "double_proposal");
}

/// The session digest of a reshare, as its status gives it.
pub(crate) fn session(status: &Value) -> Digest {
    let bytes = hex::decode(status["session"].as_str().unwrap().trim_start_matches("0x")).unwrap();
    Digest::decode(bytes).unwrap()
}

/// A share acknowledgement of reshare `round`, signed with node `node`'s identity, as a
/// transaction for the mempool.
pub(crate) fn acknowledgement(node: u64, round: u64, session: Digest, id: u64) -> Vec<u8> {
    let ack = ReadyAck::sign(&PrivateKey::from_seed(node), round, session);
    Transaction {
        id,
        command: Command::ShareReady(Box::new(ack)),
    }
    .encode()
    .to_vec()
}

/// E2E-RSH-4: invalid participants. A scripted peer in node 3's place sends malformed dealings,
/// acknowledges nothing and acknowledges its share before there is one: the reshare cannot
/// complete, its activation is refused, generation 0 keeps signing, and the reshare is aborted.
/// Then node 3 stores its new share of the next reshare and crashes before acknowledging it; a
/// peer with its identity acknowledges for it. Consensus checks the signature and cannot see a
/// share, so the acknowledgement counts and the generation activates: the three other new shares
/// sign, and node 3 signs with its stored share once back. A false acknowledgement costs
/// availability, never safety.
#[test]
fn e2e_rsh_4_invalid_participants_never_activate_an_unauthorized_generation() {
    let (network, key) = validator_network_with(|_| Vec::new());
    let first = signed(&network, 0, &key, &block(40, 1));

    // 1. Node 3 replaced by a peer that sends garbage dealings and acknowledges nothing.
    network.stop_node(3);
    let peer = FakePeer::start(&network, 3, &[], Box::new(|_, _, _| Vec::new()));
    let started = start_reshare(&network, 0, &key, "validator-eth-g1");
    let round = started["round"].as_u64().unwrap();
    let mut garbage = vec![0u8]; // the `Dealing` tag
    garbage.extend(round.encode());
    garbage.extend([0x42; 300]);
    let early = acknowledgement(3, round, session(&started), 1);
    // Sent until the peer's connection is up and node 0 has seen them.
    network.wait_until("node 0 to reject the peer's malformed dealings", || {
        for to in 0..3 {
            peer.send_on(engine::DKG_CHANNEL, to, garbage.clone());
        }
        peer.send_on(engine::MEMPOOL_CHANNEL, 0, early.clone());
        network.count(0, "invalid dkg message") > 0
    });
    signed(&network, 1, &key, &block(41, 1));
    std::thread::sleep(std::time::Duration::from_secs(3));
    let status = reshare_status(&network, 0, "validator-eth-g1");
    assert_eq!(status["status"], "in_progress", "{status}");
    assert_eq!(status["ready_shares"], json!([]), "{status}");
    let (code, refusal) = generation_call(&network, 1, "activate", &key, "validator-eth-g1");
    assert_eq!(
        (code, refusal["refusal"]["reason"].as_str()),
        (409, Some("not_completed")),
        "{refusal}"
    );
    assert_eq!(generation(&network, 0, &key), (0, VALIDATOR.to_string()));
    let (code, aborted) = generation_call(&network, 2, "abort", &key, "validator-eth-g1");
    assert_eq!(code, 200, "{aborted}");
    drop(peer);

    // 2. Node 3 back; it stores its share of the next reshare and crashes before acknowledging.
    network.restart_node_with(3, crash_at("reshare-after-share-stored"));
    network.wait_for_ready(&[3]);
    let started = start_reshare(&network, 0, &key, "validator-eth-g2");
    let round = started["round"].as_u64().unwrap();
    assert!(!network.wait_exit(3).success());
    network.wait_until("three acknowledgements", || {
        reshare_status(&network, 0, "validator-eth-g2")["ready_shares"]
            .as_array()
            .is_some_and(|ready| ready.len() == 3)
    });
    let status = reshare_status(&network, 0, "validator-eth-g2");
    assert_eq!(status["status"], "awaiting_shares", "{status}");
    let (code, refusal) = generation_call(&network, 1, "activate", &key, "validator-eth-g2");
    assert_eq!(
        (code, refusal["refusal"]["reason"].as_str()),
        (409, Some("not_ready")),
        "{refusal}"
    );
    let peer = FakePeer::start(&network, 3, &[], Box::new(|_, _, _| Vec::new()));
    let ack = acknowledgement(3, round, session(&status), 2);
    network.wait_until("the impersonated acknowledgement to count", || {
        peer.send_on(engine::MEMPOOL_CHANNEL, 0, ack.clone());
        reshare_status(&network, 0, "validator-eth-g2")["status"] == "ready"
    });
    for node in 1..3 {
        network.wait_until(&format!("the reshare ready on node {node}"), || {
            reshare_status(&network, node, "validator-eth-g2")["status"] == "ready"
        });
    }
    let (code, activated) = generation_call(&network, 1, "activate", &key, "validator-eth-g2");
    assert_eq!(code, 200, "{activated}");
    wait_generation(&network, &[0, 1, 2], &key, (1, "validator-eth-g2"));
    signed(&network, 2, &key, &block(42, 1));
    assert_eq!(signed(&network, 0, &key, &block(40, 1)), first);
    drop(peer);

    network.restart_node_with(3, Vec::new());
    network.wait_for_ready(&[3]);
    wait_generation(&network, &[3], &key, (1, "validator-eth-g2"));
    assert_eq!(
        dkg_status(&network, 3, "validator-eth-g2")["share"],
        "stored"
    );
    network.freeze(1);
    signed(&network, 0, &key, &block(43, 1));
    network.thaw(1);
}

/// E2E-RSH-5: an imported key (EIP-2335 vector, EIP-3076 history) reshared: the same key and the
/// original key's signatures, the imported floors still refuse, the import state stays.
#[test]
fn e2e_rsh_5_imported_key() {
    let (network, dir) = import_network();
    let (manifest, envelopes) = split(&network, &dir, IMPORTED, "shares");
    assert_eq!(
        network
            .approved(0, "register-import", json!({ "manifest": manifest }))
            .0,
        200
    );
    for (node, envelope) in envelopes.iter().enumerate() {
        // Each node installs once it applied the registration.
        network.wait_until(&format!("the registration on node {node}"), || {
            network.get(node, &format!("/keys/import/{IMPORTED}")).0 == 200
        });
        let (status, installed) = network.post(node, "/keys/import/share", envelope);
        assert_eq!(status, 200, "{installed}");
    }
    let history = interchange(
        IMPORTED_KEY,
        CHAIN,
        json!([{"slot": "100"}]),
        json!([{"source_epoch": "10", "target_epoch": "11"}]),
    );
    let (status, imported) = network.approved(1, "import-history", json!({"interchange": history}));
    assert_eq!(status, 200, "{imported}");
    network.wait_until("every share acknowledged", || {
        let (_, status) = network.get(0, &format!("/keys/import/{IMPORTED}"));
        status["ready_shares"]
            .as_array()
            .is_some_and(|ready| ready.len() == NODES)
    });
    let acknowledgment: Value = serde_json::from_str(ACKNOWLEDGED).unwrap();
    let (status, activated) = network.approved(
        0,
        "activate",
        json!({"public_key": IMPORTED_KEY, "genesis_validators_root": CHAIN, "acknowledgment": acknowledgment}),
    );
    assert_eq!(status, 200, "{activated}");
    for node in network.all() {
        network.wait_until(&format!("activation on node {node}"), || {
            activation(&network, node, IMPORTED_KEY).is_some()
        });
    }
    let before = block(101, 1);
    assert_eq!(
        signed(&network, 0, IMPORTED_KEY, &before),
        json!(original_signature(&signing_root(&before)))
    );

    reshare_and_activate(&network, 2, IMPORTED_KEY, "imported-g1", 1);
    let reshared = activation(&network, 0, IMPORTED_KEY).unwrap();
    assert_eq!(reshared["origin"], "imported", "{reshared}");
    assert_eq!(reshared["public_key"], IMPORTED_KEY);
    // Still the original key's signatures, with the new shares.
    let after = block(102, 1);
    assert_eq!(
        signed(&network, 1, IMPORTED_KEY, &after),
        json!(original_signature(&signing_root(&after)))
    );
    assert_eq!(
        signed(&network, 3, IMPORTED_KEY, &before),
        json!(original_signature(&signing_root(&before)))
    );
    // The imported floors and the import state stay.
    refused(
        &network,
        2,
        IMPORTED_KEY,
        &block(100, 1),
        "block_at_or_below_imported",
    );
    refused(
        &network,
        0,
        IMPORTED_KEY,
        &attestation(10, 11, 1),
        "target_at_or_below_imported",
    );
    let (_, status) = network.get(1, &format!("/keys/import/{IMPORTED}"));
    assert_eq!(
        status["history"]["floors"],
        json!({"block_slot": 100, "source_epoch": 10, "target_epoch": 11}),
        "{status}"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Node 2 crashes at `point` during a reshare (or its activation, or its first partial signature
/// with the new generation), restarts without the hook, and the reshare completes and activates;
/// every node signs with the new generation, node 2 included, and the history holds.
fn crash_during_reshare(point: &str) {
    let (network, key) = validator_network_with(|node| {
        if node == 2 {
            crash_at(point)
        } else {
            Vec::new()
        }
    });
    let first = signed(&network, 0, &key, &block(50, 1));
    start_reshare(&network, 0, &key, "validator-eth-g1");
    let crash = |network: &TestNetwork| {
        assert!(!network.wait_exit(2).success());
        assert!(network.count(2, &format!("test hook: crashing at {point}")) > 0);
        network.restart_node_with(2, Vec::new());
        network.wait_for_ready(&[2]);
    };
    let at_activation = point.ends_with("-activation");
    let at_partial = point == "new-generation-partial";
    if !at_activation && !at_partial {
        crash(&network);
    }
    wait_reshare(&network, "validator-eth-g1", "ready");
    let (status, activated) = generation_call(&network, 1, "activate", &key, "validator-eth-g1");
    assert_eq!(status, 200, "{activated}");
    if at_activation {
        wait_generation(&network, &[0, 1, 3], &key, (1, "validator-eth-g1"));
        signed(&network, 0, &key, &block(51, 1));
        crash(&network);
    }
    wait_generation(&network, &network.all(), &key, (1, "validator-eth-g1"));
    if at_partial {
        signed(&network, 0, &key, &block(52, 1));
        crash(&network);
    }
    // Node 3 frozen: the signature needs node 2's new share (a stable node coordinates).
    network.freeze(3);
    signed(&network, 0, &key, &block(53, 1));
    network.thaw(3);
    assert_eq!(signed(&network, 1, &key, &block(50, 1)), first);
    refused(&network, 2, &key, &block(50, 2), "double_proposal");
}

macro_rules! crash_points {
    ($($name:ident => $point:literal,)*) => {$(
        /// E2E-RSH-CRASH: [crash_during_reshare] at this point.
        #[test]
        fn $name() {
            crash_during_reshare($point);
        }
    )*};
}

crash_points! {
    e2e_rsh_crash_before_dealing => "reshare-before-dealing",
    e2e_rsh_crash_after_seed => "reshare-after-seed",
    e2e_rsh_crash_after_dealings_sent => "reshare-after-dealings-sent",
    e2e_rsh_crash_after_first_dealing => "reshare-after-first-dealing",
    e2e_rsh_crash_after_all_dealings => "reshare-after-all-dealings",
    e2e_rsh_crash_after_share_stored => "reshare-after-share-stored",
    e2e_rsh_crash_after_ready => "reshare-after-ready",
    e2e_rsh_crash_before_activation => "before-apply-activation",
    e2e_rsh_crash_after_activation => "after-apply-activation",
    e2e_rsh_crash_at_first_new_partial => "new-generation-partial",
}
