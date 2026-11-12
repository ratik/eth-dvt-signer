//! E2E-4 to E2E-6: an offline node, a coordinator crash, a full network restart; and the manual
//! recovery of a node behind the retained history.

use crate::{
    KEY,
    harness::{TestNetwork, ethereum_verify, root, unhex},
    signing::network_with_key,
};
use serde_json::Value;

/// Share index of node `id` (from its own view of the ceremony).
fn index_of(network: &TestNetwork, id: usize) -> u64 {
    let (_, body) = network.get(id, &format!("/dkg/status/{KEY}"));
    body["participant_index"].as_u64().unwrap()
}

fn signers(body: &Value) -> Vec<u64> {
    body["signers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|index| index.as_u64().unwrap())
        .collect()
}

fn authorizations(network: &TestNetwork, id: usize) -> u64 {
    network.get(id, "/status").1["authorizations"]
        .as_u64()
        .unwrap()
}

/// E2E-4: one node offline; signing goes on, and the node catches up when it returns.
#[test]
fn one_node_offline() {
    let (network, key) = network_with_key();
    let index_3 = index_of(&network, 3);
    network.stop_node(3);

    let (status, signed) = network.sign(0, KEY, 100, root(0x10));
    assert_eq!(status, 200, "{signed}");
    assert_eq!(signed["authorization"], "NEW");
    assert!(!signers(&signed).contains(&index_3));
    assert!(ethereum_verify(&key, &root(0x10), &signed["signature"]));

    // Node 3 restarts, catches up on the authorization, and signs in place of another node.
    network.restart_node(3);
    let height = signed["height"].as_u64().unwrap();
    network.wait_until("node 3 to catch up", || {
        network.height(3).is_some_and(|h| h >= height)
            && network.get(3, &format!("/authorizations/{KEY}/100")).0 == 200
    });
    network.stop_node(1);
    let (status, signed) = network.sign(3, KEY, 101, root(0x11));
    assert_eq!(status, 200, "{signed}");
    assert!(signers(&signed).contains(&index_3));
    assert!(ethereum_verify(&key, &root(0x11), &signed["signature"]));
}

/// E2E-5 (and 10.4): the coordinator crashes after the authorization is durable, or holding two
/// partial signatures. The retry reuses the authorization and regenerates the partials.
#[test]
fn coordinator_crash_keeps_authorization() {
    let (network, key) = network_with_key();
    let before = authorizations(&network, 1);

    for (nonce, crash_at) in [(100, "authorized"), (101, "partials-2")] {
        network.restart_node_with(0, vec![("ETH_MPC_SIGNER_CRASH_AT".into(), crash_at.into())]);
        network.wait_for_ready(&[0]);
        let result = network.try_call(
            0,
            "POST",
            "/sign",
            Some(&crate::harness::sign_body(KEY, nonce, root(nonce as u8))),
        );
        assert!(
            !matches!(result, Ok((200, _))),
            "the coordinator should have crashed: {result:?}"
        );
        let status = network.wait_exit(0);
        assert!(!status.success(), "crash hook {crash_at}: {status}");

        // The authorization was finalized and survives on the other nodes.
        let mut height = None;
        network.wait_until("the authorization on node 1", || {
            let (status, body) = network.get(1, &format!("/authorizations/{KEY}/{nonce}"));
            height = body["height"].as_u64();
            status == 200
        });

        // Restarted without the hook, the same request completes without a new authorization.
        network.restart_node_with(0, Vec::new());
        network.wait_for_ready(&[0]);
        let (status, signed) = network.sign(0, KEY, nonce, root(nonce as u8));
        assert_eq!(status, 200, "{signed}");
        assert_eq!(signed["authorization"], "EXISTING");
        assert_eq!(signed["height"].as_u64(), height);
        assert!(ethereum_verify(
            &key,
            &root(nonce as u8),
            &signed["signature"]
        ));
    }
    assert_eq!(authorizations(&network, 1), before + 2);
}

/// E2E-6: stop all four nodes, restart them on their storage.
#[test]
fn full_network_restart() {
    let (network, key) = network_with_key();
    let (status, a) = network.sign(1, KEY, 100, root(0xa0));
    assert_eq!(status, 200, "{a}");

    for id in network.all() {
        network.stop_node(id);
    }
    for id in network.all() {
        network.restart_node(id);
    }
    network.wait_for_ready(&network.all());

    // Same key, shares restored, old authorization still signs (identically).
    let restored = network.wait_for_dkg(KEY, &network.all());
    assert_eq!(Value::String(restored), key);
    let (status, again) = network.sign(2, KEY, 100, root(0xa0));
    assert_eq!(status, 200, "{again}");
    assert_eq!(again["authorization"], "EXISTING");
    assert_eq!(again["signature"], a["signature"]);

    let (status, b) = network.sign(3, KEY, 200, root(0xb0));
    assert_eq!(status, 200, "{b}");
    assert_eq!(b["authorization"], "NEW");
    assert!(ethereum_verify(&key, &root(0xa0), &a["signature"]));
    assert!(ethereum_verify(&key, &root(0xb0), &b["signature"]));

    // Nonce 100 stays bound to payload A.
    let (status, rejected) = network.sign(0, KEY, 100, root(0xb0));
    assert_eq!(status, 409, "{rejected}");
    assert_eq!(rejected["result"], "REJECTED");
    let (_, authorization) = network.get(0, &format!("/authorizations/{KEY}/100"));
    assert_eq!(unhex(&authorization["payload_hash"]), root(0xa0));
}

/// A node behind by more than the retained history cannot backfill from its peers. It is restored
/// from a stopped healthy node's copy of every partition except its own key share
/// (`registry-secrets`) and consensus journal (`registry-consensus`), as docs/recovery.md (§6)
/// describes.
#[test]
fn lagging_node_restored_from_peer_copy() {
    let (network, key) = network_with_key();
    let index_3 = index_of(&network, 3);
    network.stop_node(3);
    let (status, signed) = network.sign(0, KEY, 100, root(0x10));
    assert_eq!(status, 200, "{signed}");

    // A consistent copy needs node 0 stopped: consensus pauses meanwhile (only 1 and 2 run).
    network.stop_node(0);
    network.snapshot(0, "healthy");
    network.restart_node(0);
    network.restore_keeping(3, "healthy", &["registry-secrets", "registry-consensus"]);
    network.restart_node(3);
    network.wait_for_ready(&network.all());

    // Node 3 starts from node 0's state, then applies blocks it fetches from its peers.
    let (status, authorization) = network.get(3, &format!("/authorizations/{KEY}/100"));
    assert_eq!(status, 200, "{authorization}");
    assert_eq!(authorization["height"], signed["height"]);
    let restored = network.height(3).unwrap();
    network.wait_until("node 3 to apply new blocks", || {
        network.height(3).is_some_and(|height| height > restored)
    });

    // It signs with its own share: node 1 is frozen, so node 3's partial is needed.
    network.freeze(1);
    let (status, again) = network.sign(3, KEY, 100, root(0x10));
    network.thaw(1);
    assert_eq!(status, 200, "{again}");
    assert!(signers(&again).contains(&index_3), "{again}");
    assert_eq!(again["signature"], signed["signature"]);

    let (status, new) = network.sign(3, KEY, 101, root(0x11));
    assert_eq!(status, 200, "{new}");
    assert!(ethereum_verify(&key, &root(0x11), &new["signature"]));
    for node in network.all() {
        network.wait_until(&format!("node {node} to apply nonce 101"), || {
            authorizations(&network, node) == 2
        });
    }
    assert_eq!(network.blocked_for_equivocation(3), Vec::<usize>::new());
    assert_eq!(network.count(3, "blocks are missing"), 0);
}
