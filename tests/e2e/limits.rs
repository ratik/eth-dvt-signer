//! Audit E1/E2: timeouts when consensus or signers are missing.

use crate::{
    KEY,
    failures::wait_applied,
    harness::{ethereum_verify, root},
    rollback::network_with_key_args,
    signing::network_with_key,
};
use std::time::{Duration, Instant};

/// E1: consensus cannot finalize (two nodes down): the request times out, but the submitted command
/// is not cancelled. Once consensus is back it is finalized, and a retry reuses it.
#[test]
fn e1_authorization_timeout() {
    let (network, key) = network_with_key_args(&["--authorization-timeout", "5"]);
    network.stop_node(2);
    network.stop_node(3);

    let start = Instant::now();
    let (status, body) = network.sign(0, KEY, 300, root(0xaa));
    let elapsed = start.elapsed();
    assert_eq!(status, 504, "{body}");
    assert_eq!(body["result"], "AUTHORIZATION_TIMEOUT");
    assert!(
        elapsed >= Duration::from_secs(5) && elapsed < Duration::from_secs(20),
        "{elapsed:?}"
    );
    assert_eq!(network.get(0, &format!("/authorizations/{KEY}/300")).0, 404);

    network.restart_node(2);
    network.restart_node(3);
    network.wait_for_ready(&[2, 3]);
    wait_applied(&network, &network.all(), 300);
    let (_, authorization) = network.get(1, &format!("/authorizations/{KEY}/300"));

    let (status, signed) = network.sign(1, KEY, 300, root(0xaa));
    assert_eq!(status, 200, "{signed}");
    assert_eq!(signed["authorization"], "EXISTING");
    assert_eq!(signed["height"], authorization["height"]);
    assert!(ethereum_verify(&key, &root(0xaa), &signed["signature"]));
    assert_eq!(network.status(1)["authorizations"], 1);
}

/// E2: fewer than three signers after the authorization: a bounded, retryable error that keeps
/// the authorization; signing works once they are back.
#[test]
fn e2_insufficient_signers() {
    let (network, key) = network_with_key();
    let (status, first) = network.sign(0, KEY, 100, root(0xaa));
    assert_eq!(status, 200, "{first}");
    wait_applied(&network, &network.all(), 100);

    network.stop_node(2);
    network.stop_node(3);
    let start = Instant::now();
    let (status, body) = network.sign(0, KEY, 100, root(0xaa));
    assert_eq!(status, 504, "{body}");
    assert_eq!(body["result"], "SIGNING_TIMEOUT");
    assert_eq!(body["valid_partials"], 2);
    assert_eq!(body["height"], first["height"]);
    assert!(
        start.elapsed() < Duration::from_secs(15),
        "{:?}",
        start.elapsed()
    );
    assert_eq!(network.get(0, &format!("/authorizations/{KEY}/100")).0, 200);

    network.restart_node(2);
    network.restart_node(3);
    network.wait_for_ready(&[2, 3]);
    let (status, again) = network.sign(0, KEY, 100, root(0xaa));
    assert_eq!(status, 200, "{again}");
    assert_eq!(again["signature"], first["signature"]);
    assert!(ethereum_verify(&key, &root(0xaa), &again["signature"]));
}
