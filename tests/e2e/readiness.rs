//! R1, R6: what a restarting node claims about itself (`GET /ready`), and what it does.

use crate::{
    KEY,
    failures::{ask, index_of, request, wait_applied},
    harness::{
        TestNetwork, ethereum_verify,
        peer::{FakePeer, Responder},
        root,
    },
    signing::network_with_key,
};
use eth_mpc_signer::{
    readiness::BACKLOG_TOLERANCE,
    signer::wire::{self, Refusal},
};
use serde_json::{Value, json};
use std::collections::BTreeSet;

/// Every readiness field. None claims more than the node can observe (nothing like "synchronized
/// with the network").
const FIELDS: [&str; 11] = [
    "state",
    "reasons",
    "can_submit_authorization",
    "can_sign_authorized",
    "startup_checks",
    "applied_height",
    "known_finalized_height",
    "last_block_age_ms",
    "state_height_at_start",
    "unavailable_shares",
    "consensus",
];

fn signers(body: &Value) -> Vec<u64> {
    body["signers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|index| index.as_u64().unwrap())
        .collect()
}

fn reasons(network: &TestNetwork, node: usize) -> Vec<String> {
    network.readiness(node)["reasons"]
        .as_array()
        .unwrap()
        .iter()
        .map(|reason| reason.as_str().unwrap().to_string())
        .collect()
}

/// R1: a node restarted with intact storage becomes ready, resumes consensus above its durable
/// floor, and signs: its partial for an existing authorization, and new authorizations.
#[test]
fn r1_normal_restart_becomes_ready() {
    let (network, key) = network_with_key();
    let (status, first) = network.sign(0, KEY, 100, root(0xaa));
    assert_eq!(status, 200, "{first}");
    wait_applied(&network, &network.all(), 100);
    network.wait_for_ready(&[3]);
    let before = network.readiness(3);
    assert_eq!(before["reasons"], json!([]), "{before}");
    let index_3 = u64::from(index_of(&network, 3));

    network.stop_node(3);
    network.restart_node(3);
    network.wait_for_ready(&[3]);

    let readiness = network.readiness(3);
    let fields: BTreeSet<&str> = readiness
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(fields, FIELDS.into_iter().collect(), "{readiness}");
    assert_eq!(readiness["state"], "ready");
    assert_eq!(readiness["startup_checks"], "passed");
    assert_eq!(readiness["can_submit_authorization"], true);
    assert_eq!(readiness["consensus"]["voting"], true);
    assert_eq!(readiness["consensus"]["journal_missing_at_start"], false);
    // Consensus resumed above the last finalization processed before the restart, which is at
    // most one block behind the state (marshal's acknowledgement follows the state commit).
    let at_start = readiness["state_height_at_start"].as_u64().unwrap();
    let floor = readiness["consensus"]["floor_height"].as_u64().unwrap();
    assert!(
        at_start >= before["applied_height"].as_u64().unwrap(),
        "{readiness}"
    );
    assert!(floor <= at_start && at_start - floor <= 1, "{readiness}");
    assert!(readiness["consensus"]["floor_view"].as_u64().unwrap() >= floor);

    // Its partial is needed (node 1 frozen), and it authorizes again.
    network.freeze(1);
    let (status, again) = network.sign(0, KEY, 100, root(0xaa));
    network.thaw(1);
    assert_eq!(status, 200, "{again}");
    assert!(signers(&again).contains(&index_3), "{again}");
    assert_eq!(again["signature"], first["signature"]);
    let (status, new) = network.sign(3, KEY, 101, root(0xbb));
    assert_eq!(status, 200, "{new}");
    assert_eq!(new["authorization"], "NEW");
    assert!(ethereum_verify(&key, &root(0xbb), &new["signature"]));
    assert_eq!(network.blocked_for_equivocation(3), Vec::<usize>::new());
}

/// R6: node 3 restarts while node 2 is unavailable. It becomes ready only once consensus
/// finalizes again (which needs its votes), signs nothing it has not applied, and when a second
/// node goes away every running node reports the stall instead of assuming liveness.
#[test]
fn r6_recovery_with_one_offline_peer() {
    let (network, key) = network_with_key();
    let (status, first) = network.sign(0, KEY, 100, root(0xaa));
    assert_eq!(status, 200, "{first}");
    wait_applied(&network, &network.all(), 100);
    let index_3 = u64::from(index_of(&network, 3));

    network.stop_node(2);
    network.stop_node(3);
    network.restart_node(3);
    network.wait_for_ready(&[0, 1, 3]);
    // Ready means no backlog beyond the blocks on their way to the executor.
    let readiness = network.readiness(3);
    let lag = readiness["known_finalized_height"].as_u64().unwrap()
        - readiness["applied_height"].as_u64().unwrap();
    assert!(lag <= BACKLOG_TOLERANCE, "{readiness}");

    // Asked by node 2's identity, it signs nothing it has not applied.
    let silent: Responder = Box::new(|_, _, _| Vec::new());
    let peer = FakePeer::start(&network, 2, &[], silent);
    let unknown = request(777, root(0xdd));
    let conflicting = request(100, root(0xbb));
    assert_eq!(
        ask(&network, &peer, 3, &unknown),
        wire::Message::Refused {
            request: unknown.id,
            reason: Refusal::NotAuthorized
        }
    );
    assert_eq!(
        ask(&network, &peer, 3, &conflicting),
        wire::Message::Refused {
            request: conflicting.id,
            reason: Refusal::Conflict
        }
    );

    // The three sign, node 3 included (it is needed).
    let (status, signed) = network.sign(3, KEY, 101, root(0xbb));
    assert_eq!(status, 200, "{signed}");
    assert!(signers(&signed).contains(&index_3), "{signed}");
    assert!(ethereum_verify(&key, &root(0xbb), &signed["signature"]));

    // A second node away: nothing can be finalized. The running nodes say so; new
    // authorizations are refused at once; an applied one fails in bounded time (two signers).
    network.stop_node(1);
    for node in [0, 3] {
        network.wait_until(&format!("node {node} to report the stall"), || {
            reasons(&network, node).contains(&"no_recent_finalization".to_string())
        });
    }
    let (status, body) = network.sign(0, KEY, 102, root(0xcc));
    assert_eq!(status, 503, "{body}");
    assert_eq!(body["result"], "NOT_READY");
    assert_eq!(body["reasons"], json!(["no_recent_finalization"]));
    let (status, body) = network.sign(3, KEY, 100, root(0xaa));
    assert_eq!(status, 504, "{body}");
    assert_eq!(body["result"], "SIGNING_TIMEOUT");
    assert_eq!(body["valid_partials"], 2);
    assert_eq!(
        ask(&network, &peer, 3, &unknown),
        wire::Message::Refused {
            request: unknown.id,
            reason: Refusal::NotAuthorized
        }
    );

    // Three again: consensus resumes, and so does authorization.
    network.restart_node(1);
    network.wait_for_ready(&[0, 1, 3]);
    let (status, body) = network.sign(0, KEY, 102, root(0xcc));
    assert_eq!(status, 200, "{body}");
    assert!(ethereum_verify(&key, &root(0xcc), &body["signature"]));
}
