//! Audit A3-A6, C1, C2: deterministic crashes at the boundaries of the signing path.

use crate::{
    KEY,
    failures::{index_of, wait_applied},
    harness::{TestNetwork, ethereum_verify, root, unhex},
    signing::network_with_key,
};
use serde_json::Value;

fn crash_at(point: &str) -> Vec<(String, String)> {
    vec![("ETH_MPC_SIGNER_CRASH_AT".into(), point.into())]
}

fn signers(body: &Value) -> Vec<u32> {
    body["signers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|index| index.as_u64().unwrap() as u32)
        .collect()
}

/// Wait until node `node` has caught up with node `with` (so it is connected and current).
fn wait_caught_up(network: &TestNetwork, node: usize, with: usize) {
    let target = network.height(with).unwrap();
    network.wait_until(&format!("node {node} to catch up"), || {
        network.height(node).is_some_and(|height| height >= target)
    });
}

fn authorization(network: &TestNetwork, node: usize, nonce: u64) -> Option<(Vec<u8>, u64)> {
    let (status, body) = network.get(node, &format!("/authorizations/{KEY}/{nonce}"));
    (status == 200).then(|| {
        (
            unhex(&body["payload_hash"]),
            body["height"].as_u64().unwrap(),
        )
    })
}

/// Sign `(KEY, 100, A)` through node 0 while `frozen` is frozen, so that `victim`'s partial is
/// needed; `victim` must crash (a hook), then `frozen` is thawed.
fn sign_needing(network: &TestNetwork, victim: usize, frozen: usize) -> (u16, Value) {
    network.freeze(frozen);
    std::thread::scope(|scope| {
        let signing = scope.spawn(|| network.sign(0, KEY, 100, root(0xaa)));
        let exit = network.wait_exit(victim);
        network.thaw(frozen);
        assert!(!exit.success(), "node {victim}: {exit}");
        signing.join().unwrap()
    })
}

/// After the crash, node `victim` must restore `(KEY, 100) -> A`, refuse B, and sign A (it is
/// needed: `freeze` is frozen).
fn check_recovered_signer(network: &TestNetwork, victim: usize, freeze: usize, signed: &Value) {
    let index = index_of(network, victim);
    network.wait_until("the victim to restore the authorization", || {
        authorization(network, victim, 100).is_some()
    });
    assert_eq!(
        authorization(network, victim, 100),
        authorization(network, 0, 100)
    );
    let (status, body) = network.sign(victim, KEY, 100, root(0xbb));
    assert_eq!(status, 409, "{body}");

    network.freeze(freeze);
    let coordinator = (0..4)
        .find(|node| *node != victim && *node != freeze)
        .unwrap();
    let (status, body) = network.sign(coordinator, KEY, 100, root(0xaa));
    network.thaw(freeze);
    assert_eq!(status, 200, "{body}");
    assert!(signers(&body).contains(&index), "{body}");
    assert_eq!(body["signature"], signed["signature"]);
}

/// A3: node 1 crashes after consensus finalized the authorization, before applying it. It never
/// signs from the finalized-but-not-applied block, and replays it after restart.
#[test]
fn a3_crash_before_applying_authorization() {
    let (network, key) = network_with_key();
    let index_1 = index_of(&network, 1);
    network.restart_node_with(1, crash_at("before-apply-authorization"));
    network.wait_for_ready(&[1]);
    wait_caught_up(&network, 1, 2);

    let (status, signed) = network.sign(0, KEY, 100, root(0xaa));
    assert_eq!(status, 200, "{signed}");
    assert!(ethereum_verify(&key, &root(0xaa), &signed["signature"]));
    assert!(
        !signers(&signed).contains(&index_1),
        "node 1 signed without applying: {signed}"
    );
    assert!(!network.wait_exit(1).success());
    assert!(network.count(1, "test hook: crashing at before-apply-authorization") > 0);

    network.restart_node_with(1, Vec::new());
    // It crashed holding the block, unapplied: the state and the durable floor are below it.
    let height = signed["height"].as_u64().unwrap();
    let (at_start, floor) = recovery_point(&network, 1);
    assert_eq!(at_start, height - 1);
    assert!(floor <= at_start, "floor {floor}, state {at_start}");
    check_recovered_signer(&network, 1, 2, &signed);
}

/// The state height at startup and the finalized height consensus resumed above.
fn recovery_point(network: &TestNetwork, node: usize) -> (u64, u64) {
    let readiness = network.readiness(node);
    (
        readiness["state_height_at_start"].as_u64().unwrap(),
        readiness["consensus"]["floor_height"].as_u64().unwrap(),
    )
}

/// A4: node 1 crashes right after the authorization is durable, before its signer learns about
/// it. After restart the signer is seeded from disk.
#[test]
fn a4_crash_after_applying_before_signer_learns() {
    let (network, _) = network_with_key();
    let index_1 = index_of(&network, 1);
    network.restart_node_with(1, crash_at("after-apply-authorization"));
    network.wait_for_ready(&[1]);
    wait_caught_up(&network, 1, 2);

    let (status, signed) = network.sign(0, KEY, 100, root(0xaa));
    assert_eq!(status, 200, "{signed}");
    assert!(!signers(&signed).contains(&index_1), "{signed}");
    assert!(!network.wait_exit(1).success());
    assert!(network.count(1, "test hook: crashing at after-apply-authorization") > 0);

    network.restart_node_with(1, Vec::new());
    // Applied but not acknowledged: the state has the block, the floor (acknowledged progress
    // only) does not; marshal delivers it again and it is skipped.
    let height = signed["height"].as_u64().unwrap();
    let (at_start, floor) = recovery_point(&network, 1);
    assert_eq!(at_start, height);
    assert!(floor < height, "floor {floor} from unacknowledged progress");
    check_recovered_signer(&network, 1, 2, &signed);
}

/// A5 / C1: node 2 crashes when asked for its partial, before answering. The coordinator already
/// has its own partial and completes with the others; the authorization is not repeated.
#[test]
fn a5_c1_participant_crash_before_sending_partial() {
    let (network, key) = network_with_key();
    let index_2 = index_of(&network, 2);
    network.restart_node_with(2, crash_at("before-partial-send"));
    network.wait_for_ready(&[2]);
    wait_caught_up(&network, 2, 1);

    // Node 3 is frozen, so node 0 needs node 2, which crashes instead of answering; then node 3
    // comes back and the request completes.
    let (status, signed) = sign_needing(&network, 2, 3);
    assert_eq!(status, 200, "{signed}");
    assert!(ethereum_verify(&key, &root(0xaa), &signed["signature"]));
    assert!(!signers(&signed).contains(&index_2));
    assert!(network.count(2, "test hook: crashing at before-partial-send") > 0);
    wait_applied(&network, &[0, 1, 3], 100);
    assert_eq!(network.status(0)["authorizations"], 1);

    network.restart_node_with(2, Vec::new());
    check_recovered_signer(&network, 2, 3, &signed);
    assert_eq!(
        network.status(0)["authorizations"],
        1,
        "authorization not repeated"
    );
}

/// A6: node 2 crashes right after sending its partial. Signing succeeds with whatever three valid
/// partials arrive, and the signature is the one any three give.
#[test]
fn a6_participant_crash_after_sending_partial() {
    let (network, key) = network_with_key();
    network.restart_node_with(2, crash_at("after-partial-send"));
    network.wait_for_ready(&[2]);
    wait_caught_up(&network, 2, 1);

    // Node 3 is frozen, so node 0 needs node 2's partial; node 2 sends it and crashes. Whether
    // the partial made it or not, the request completes once node 3 is back.
    let (status, signed) = sign_needing(&network, 2, 3);
    assert_eq!(status, 200, "{signed}");
    assert!(ethereum_verify(&key, &root(0xaa), &signed["signature"]));
    assert!(network.count(2, "test hook: crashing at after-partial-send") > 0);

    network.restart_node_with(2, Vec::new());
    check_recovered_signer(&network, 2, 3, &signed);
}

/// C2: the coordinator crashes holding exactly two valid partials; another node takes the same
/// request without a new authorization and without stored partials.
#[test]
fn c2_coordinator_crash_retry_elsewhere() {
    let (network, key) = network_with_key();
    network.restart_node_with(0, crash_at("partials-2"));
    network.wait_for_ready(&[0]);
    wait_caught_up(&network, 0, 3);

    let lost = network.try_call(
        0,
        "POST",
        "/sign",
        Some(&crate::harness::sign_body(KEY, 100, root(0xaa))),
    );
    assert!(!matches!(lost, Ok((200, _))), "{lost:?}");
    assert!(!network.wait_exit(0).success());
    assert!(network.count(0, "test hook: crashing at partials-2") > 0);

    wait_applied(&network, &[1], 100);
    let (_, height) = authorization(&network, 1, 100).unwrap();
    let (status, signed) = network.sign(1, KEY, 100, root(0xaa));
    assert_eq!(status, 200, "{signed}");
    assert_eq!(signed["authorization"], "EXISTING");
    assert_eq!(signed["height"].as_u64(), Some(height));
    assert!(ethereum_verify(&key, &root(0xaa), &signed["signature"]));
    assert_eq!(network.status(1)["authorizations"], 1);
}
