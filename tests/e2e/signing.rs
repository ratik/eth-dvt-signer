//! E2E-1 to E2E-3: signing through HTTP on a real four-process network.

use crate::{
    KEY,
    harness::{NODES, TestNetwork, ethereum_verify, root, unhex},
};
use serde_json::Value;

/// A network with a completed ceremony; returns it and the group public key.
pub fn network_with_key() -> (TestNetwork, Value) {
    let network = TestNetwork::start(NODES);
    network.wait_for_ready(&network.all());
    network.start_dkg(0, KEY);
    let key = network.wait_for_dkg(KEY, &network.all());
    (network, Value::String(key))
}

/// E2E-1: cold start to a verified signature.
#[test]
fn cold_start_to_signature() {
    let network = TestNetwork::start(NODES);
    network.wait_for_ready(&network.all());

    // Signing needs a key.
    let (status, body) = network.sign(0, KEY, 100, root(0xa1));
    assert_eq!(status, 404, "{body}");
    assert_eq!(body["result"], "UNKNOWN_CEREMONY");

    let started = network.start_dkg(0, KEY);
    assert_eq!(started["status"], "in_progress");
    let key = network.wait_for_dkg(KEY, &network.all());

    // Every node serves the same public key, a valid 48-byte Ethereum key.
    for id in network.all() {
        let (status, body) = network.get(id, &format!("/dkg/public-key/{KEY}"));
        assert_eq!(status, 200, "{body}");
        assert_eq!(body["public_key"], key.as_str());
    }
    let key = Value::String(key);
    assert_eq!(unhex(&key).len(), 48);

    let (status, signed) = network.sign(0, KEY, 100, root(0xa1));
    assert_eq!(status, 200, "{signed}");
    assert_eq!(signed["result"], "SIGNED");
    assert_eq!(signed["authorization"], "NEW");
    assert_eq!(signed["signers"].as_array().unwrap().len(), 3);
    assert_eq!(unhex(&signed["signature"]).len(), 96);
    assert!(ethereum_verify(&key, &root(0xa1), &signed["signature"]));
    assert!(!ethereum_verify(&key, &root(0xa2), &signed["signature"]));

    // The authorization is finalized on every node.
    let height = signed["height"].as_u64().unwrap();
    for id in network.all() {
        network.wait_until(&format!("authorization on node {id}"), || {
            let (status, body) = network.get(id, &format!("/authorizations/{KEY}/100"));
            status == 200 && body["height"].as_u64() == Some(height)
        });
    }
}

/// E2E-2: an identical request reuses the authorization and returns the same signature.
#[test]
fn identical_requests_are_idempotent() {
    let (network, key) = network_with_key();
    let (status, first) = network.sign(0, KEY, 100, root(0xa1));
    assert_eq!(status, 200, "{first}");
    assert_eq!(first["authorization"], "NEW");

    for via in [0, 1, 3] {
        let (status, again) = network.sign(via, KEY, 100, root(0xa1));
        assert_eq!(status, 200, "{again}");
        assert_eq!(again["authorization"], "EXISTING");
        assert_eq!(again["height"], first["height"]);
        assert_eq!(again["signature"], first["signature"]);
    }
    assert!(ethereum_verify(&key, &root(0xa1), &first["signature"]));

    // One authorization on every node.
    for id in network.all() {
        network.wait_until(&format!("authorization on node {id}"), || {
            network.get(id, &format!("/authorizations/{KEY}/100")).0 == 200
        });
        assert_eq!(network.get(id, "/status").1["authorizations"], 1);
    }
}

/// E2E-3: conflicting payloads for one `(ceremony, nonce)`: exactly one is ever signed.
#[test]
fn conflicting_requests_have_one_winner() {
    let (network, key) = network_with_key();

    let (a, b) = std::thread::scope(|scope| {
        let a = scope.spawn(|| network.sign(0, KEY, 100, root(0xaa)));
        let b = scope.spawn(|| network.sign(3, KEY, 100, root(0xbb)));
        (a.join().unwrap(), b.join().unwrap())
    });
    let (winner, signed, loser, rejected) = match (a.0, b.0) {
        (200, 409) => (0xaa, a.1, 0xbb, b.1),
        (409, 200) => (0xbb, b.1, 0xaa, a.1),
        other => panic!("expected 200 and 409, got {other:?}: {} / {}", a.1, b.1),
    };
    assert_eq!(rejected["result"], "REJECTED", "{rejected}");
    assert_eq!(rejected["height"], signed["height"]);
    assert!(ethereum_verify(&key, &root(winner), &signed["signature"]));

    // Every node keeps the winner and refuses the loser, on every path the API exposes.
    for id in network.all() {
        network.wait_until(&format!("authorization on node {id}"), || {
            let (status, body) = network.get(id, &format!("/authorizations/{KEY}/100"));
            status == 200 && unhex(&body["payload_hash"]) == root(winner)
        });
        let (status, body) = network.sign(id, KEY, 100, root(loser));
        assert_eq!(status, 409, "{body}");
        assert!(body.get("signature").is_none());
    }
}
