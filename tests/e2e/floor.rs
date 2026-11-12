//! The restart floor (audit L-1, `eth::horizon::RestartFloor`) on real processes, with duties of
//! the current slots of the test chain (1-second slots from the Unix epoch). Every other E2E test
//! runs without it (the harness sets `ETH_MPC_SIGNER_NO_RESTART_FLOOR`: their duties are of slots
//! long past); these set it to `0`.
//!
//! - A whole-network rollback (every node restored to storage from before a block proposal and
//!   restarted) no longer signs the conflicting proposal: every keyholder's floor covers its slot.
//!   The failing reproducer `eth2::e2e_eth_l1` keeps showing that the replicated state alone
//!   forgets it (it runs without the floor).
//! - A restart of every node: a retry of a duty authorized before it signs again; a new duty of
//!   the current slot or epoch does not; the next slot's block and the next epoch's attestation
//!   do. The time until then is printed.
//! - A restart of one node: the other three sign every duty, the current slot's included.
//!
//! Elsewhere: the floor's arithmetic in `tests/unit/eth/horizon.rs`.

use crate::{
    eth2::{CHAIN, activation, attestation, block, sign, signed},
    harness::{NODES, TestNetwork},
};
use serde_json::json;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const VALIDATOR: &str = "validator-floor";
const REFUSED: &str = "not signing a duty at or below this process's restart floor";

/// The test chain's current slot (genesis at the Unix epoch, 1-second slots).
fn slot() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Four nodes with the restart floor, and an activated validator key.
fn start() -> (TestNetwork, String) {
    let network = TestNetwork::start_with(NODES, |_| {
        vec![("ETH_MPC_SIGNER_NO_RESTART_FLOOR".into(), "0".into())]
    });
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

/// The restart floor node `node`'s current process logged at its start.
fn floor_of(network: &TestNetwork, node: usize) -> u64 {
    let log = network.log(node);
    let line = log
        .lines()
        .rev()
        .find(|line| line.contains("restart floor:"))
        .unwrap_or_else(|| network.fail(&format!("node {node} logged no restart floor")));
    line.split_whitespace()
        .find_map(|field| field.strip_prefix("slot="))
        .and_then(|slot| slot.parse().ok())
        .unwrap_or_else(|| network.fail(&format!("no slot in {line:?}")))
}

/// The floors of `nodes`' current processes.
fn floors(network: &TestNetwork, nodes: &[usize]) -> Vec<u64> {
    nodes.iter().map(|node| floor_of(network, *node)).collect()
}

/// Wait until `slot` has passed on the test chain.
fn wait_past(network: &TestNetwork, slot: u64) {
    network.wait_until(&format!("slot {slot} to pass"), || self::slot() > slot);
}

fn restart_every_node(network: &TestNetwork) {
    for node in network.all() {
        network.stop_node(node);
    }
    for node in network.all() {
        network.restart_node(node);
    }
    network.wait_for_ready(&network.all());
}

/// L-1 with the floor: every node is rolled back to storage from before a block proposal and
/// restarted. The rolled-back state authorizes the conflicting proposal (it forgot the first),
/// and every keyholder refuses it: the slot is at or below its floor. Later slots sign again.
#[test]
fn floor_1_a_whole_network_rollback_does_not_sign_a_double_proposal() {
    let (network, key) = start();
    for node in network.all() {
        network.stop_node(node);
        network.snapshot(node, &format!("before-proposal-{node}"));
    }
    for node in network.all() {
        network.restart_node(node);
    }
    network.wait_for_ready(&network.all());
    let all = network.all();
    wait_past(&network, *floors(&network, &all).iter().max().unwrap());
    let proposed = slot();
    signed(&network, 0, &key, &block(proposed, 1));

    for node in network.all() {
        network.stop_node(node);
        network.restore(node, &format!("before-proposal-{node}"));
    }
    let seen: Vec<usize> = network
        .all()
        .iter()
        .map(|node| network.count(*node, REFUSED))
        .collect();
    for node in network.all() {
        network.restart_node(node);
    }
    network.wait_for_ready(&network.all());
    let rolled_back = floors(&network, &all);
    assert!(
        rolled_back.iter().all(|floor| *floor >= proposed),
        "every floor covers slot {proposed}: {rolled_back:?}"
    );
    let (status, answer) = sign(&network, 1, &key, &block(proposed, 2));
    assert_ne!(
        status, 200,
        "double proposal signed after a whole-network rollback: {answer}"
    );
    network.wait_until("the keyholders to refuse it for their floors", || {
        network
            .all()
            .iter()
            .zip(&seen)
            .filter(|(node, seen)| network.count(**node, REFUSED) > **seen)
            .count()
            >= 2
    });
    wait_past(&network, *rolled_back.iter().max().unwrap());
    signed(&network, 2, &key, &block(slot(), 1));
}

/// A restart of every node (an R3 reconfiguration, a simultaneous upgrade): what was authorized
/// before it signs again; a new block of a slot at or below the floor, or a new attestation of its
/// epoch, does not; the next slot's block does at once, the next epoch's attestation once it
/// starts.
#[test]
fn floor_2_a_restart_of_every_node_costs_at_most_the_current_epoch() {
    let (network, key) = start();
    let all = network.all();
    wait_past(&network, *floors(&network, &all).iter().max().unwrap());
    let before = block(slot(), 1);
    let signature = signed(&network, 0, &key, &before);

    restart_every_node(&network);
    let ready = Instant::now();
    let restarted = floors(&network, &all);
    let (lowest, highest) = (
        *restarted.iter().min().unwrap(),
        *restarted.iter().max().unwrap(),
    );
    // Every floor's slot has started: what follows is decided by the floors, not the horizon.
    network.wait_until(&format!("slot {highest} to start"), || slot() >= highest);
    // Loaded at start: signed again, the same signature.
    assert_eq!(signed(&network, 1, &key, &before), signature);
    // New, at or below every floor: refused by the keyholders.
    let seen: Vec<usize> = all
        .iter()
        .map(|node| network.count(*node, REFUSED))
        .collect();
    // Refused for good (412, the keyholders' protection), not unavailable (503).
    let (status, answer) = sign(&network, 2, &key, &block(lowest, 7));
    assert_eq!(status, 412, "a new block at the floor: {answer}");
    assert_eq!(answer["protection"], "restart_floor", "{answer}");
    let epoch = lowest / 32;
    let (status, answer) = sign(&network, 3, &key, &attestation(epoch - 1, epoch, 1));
    assert_eq!(
        status, 412,
        "a new attestation of the floor's epoch: {answer}"
    );
    assert_eq!(answer["protection"], "restart_floor", "{answer}");
    // Enough floor refusals that three cannot sign (a keyholder may not have the authorization
    // yet, and say so).
    let floored = answer["refusals"].as_object().map_or(0, |refusals| {
        refusals
            .values()
            .filter(|reason| *reason == "restart_floor")
            .count()
    });
    assert!(floored >= 2, "{answer}");
    assert!(
        all.iter()
            .zip(&seen)
            .all(|(node, seen)| network.count(*node, REFUSED) > *seen),
        "every keyholder refused for its floor"
    );
    // Above every floor: the next slot's block at once, the next epoch's attestation once it
    // starts.
    wait_past(&network, highest);
    signed(&network, 0, &key, &block(slot(), 1));
    let next = highest / 32 + 1;
    network.wait_until(&format!("epoch {next} to start"), || slot() >= next * 32);
    signed(&network, 1, &key, &attestation(next - 1, next, 1));
    println!(
        "a restart of every node: floors at slots {lowest}..={highest} (epoch {epoch}); the next \
         epoch's attestation signed {} s after the nodes were ready",
        ready.elapsed().as_secs()
    );
}

/// A restart of one node (a rolling upgrade, a crash): the other three keyholders sign every
/// duty, those of the restarted node's floor slot and epoch included; it refuses its partials.
#[test]
fn floor_3_a_restart_of_one_node_costs_nothing() {
    let (network, key) = start();
    // The other nodes started an epoch earlier (32-second epochs here; on a real network they
    // started long before): their floors are of an earlier epoch than node 3's will be.
    let others = floors(&network, &[0, 1, 2]);
    let next = others.iter().max().unwrap() / 32 + 1;
    network.wait_until(&format!("epoch {next} to start"), || slot() >= next * 32);
    let seen = network.count(3, REFUSED);
    network.stop_node(3);
    network.restart_node(3);
    network.wait_for_ready(&[3]);
    let floor = floor_of(&network, 3);
    assert!(
        others.iter().all(|other| *other / 32 < floor / 32),
        "{others:?} {floor}"
    );
    network.wait_until(&format!("slot {floor} to start"), || slot() >= floor);
    signed(&network, 0, &key, &block(floor, 1));
    let epoch = floor / 32;
    signed(&network, 1, &key, &attestation(epoch - 1, epoch, 1));
    network.wait_until("node 3 to refuse its partials for its floor", || {
        network.count(3, REFUSED) > seen
    });
    // Within a deadline: nothing waited for node 3.
    let started = Instant::now();
    signed(&network, 2, &key, &block(floor + 1, 1));
    assert!(started.elapsed() < Duration::from_secs(10));
}
