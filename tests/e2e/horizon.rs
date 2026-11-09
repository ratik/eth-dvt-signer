//! P0: the time horizon of signing (`eth::horizon`) on real processes. The test chain has
//! 1-second slots from the Unix epoch (`harness`), so the current slot is the current Unix second
//! and an epoch lasts 32 seconds.

use crate::{
    eth2::{block, fixture, hex32, sign, signed, validator_network, with_root},
    harness::TestNetwork,
    reshare::validator_network_with,
};
use serde_json::{Value, json};
use std::time::{SystemTime, UNIX_EPOCH};

fn now_slot() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// An attestation of `slot`, with `source` and `target` epochs; `vote` changes its root.
fn vote(slot: u64, source: u64, target: u64, vote: u8) -> Value {
    let mut request = fixture("attestation.json");
    let data = &mut request["attestation"];
    data["slot"] = json!(slot.to_string());
    data["beacon_block_root"] = json!(hex32(vote));
    data["source"]["epoch"] = json!(source.to_string());
    data["target"]["epoch"] = json!(target.to_string());
    data["target"]["root"] = json!(hex32(vote));
    with_root(request)
}

/// Node `node`'s slashing-protection history of `key` (its EIP-3076 export).
fn history(network: &TestNetwork, node: usize, key: &str) -> Value {
    let (status, body) = network.get(node, &format!("/slashing-protection/export/{key}"));
    assert_eq!(status, 200, "{body}");
    body
}

/// Every node's history of `key`, once they all hold the same. A signature returns once three
/// nodes applied its duty, so the fourth may still be applying it: compare them all again until
/// they agree.
fn agreed_history(network: &TestNetwork, key: &str) -> Value {
    let mut agreed = None;
    network.wait_until("every node to hold the same history", || {
        let histories: Vec<Value> = network
            .all()
            .into_iter()
            .map(|node| history(network, node, key))
            .collect();
        let same = histories.windows(2).all(|pair| pair[0] == pair[1]);
        if same {
            agreed = histories.into_iter().next();
        }
        same
    });
    agreed.expect("agreed")
}

/// `body` through node `via` is refused as beyond the horizon, for `reason`.
fn beyond(network: &TestNetwork, via: usize, key: &str, body: &Value, reason: &str) {
    let (status, answer) = sign(network, via, key, body);
    assert_eq!(status, 412, "node {via}: {answer}");
    assert_eq!(answer["beyond"]["reason"], reason, "{answer}");
    assert!(answer.get("signature").is_none(), "{answer}");
}

/// P0 tests 1 to 5, 11 and 12: duties sign from their slot, and a duty implausibly far ahead
/// is refused without changing any node's history, after which the next real vote signs.
#[test]
fn horizon_1_duties_sign_from_their_slot() {
    let (network, key) = validator_network();
    let slot = now_slot();
    let epoch = slot / 32;
    // 1, 2: a proposal and an attestation of the current slot and epoch.
    signed(&network, 0, &key, &block(slot, 1));
    signed(&network, 1, &key, &vote(slot, epoch - 1, epoch, 1));
    let before = agreed_history(&network, &key);

    // 4: thousands of epochs ahead, in every field or in the target alone; 5: a proposal a
    // minute ahead.
    let far = now_slot() + 32 * 5_000;
    beyond(
        &network,
        2,
        &key,
        &vote(far, epoch + 4_999, epoch + 5_000, 2),
        "future_slot",
    );
    beyond(
        &network,
        2,
        &key,
        &vote(now_slot(), epoch, epoch + 5_000, 3),
        "future_epoch",
    );
    beyond(&network, 0, &key, &block(now_slot() + 60, 2), "future_slot");
    // 11: nothing recorded anywhere.
    assert_eq!(agreed_history(&network, &key), before);

    // 3, 12: the next epoch's first vote, a second before its slot starts (within the leeway),
    // signs after the refused ones.
    let next = (epoch + 1) * 32;
    network.wait_until("a second before the next epoch", || now_slot() + 1 >= next);
    signed(&network, 3, &key, &vote(next, epoch, epoch + 1, 4));
}

/// P0 test 6: a faulty coordinator and leader (node 1, its own horizon switched off) submits and
/// proposes a far-future attestation. The others leave it out of their blocks and refuse to vote
/// for node 1's: it is never authorized, consensus goes on, and the next vote signs.
#[test]
fn horizon_2_a_faulty_leader_cannot_commit_a_far_future_duty() {
    let (network, key) = validator_network_with(|node| {
        if node == 1 {
            vec![("ETH_MPC_SIGNER_NO_HORIZON".into(), "1".into())]
        } else {
            Vec::new()
        }
    });
    let epoch = now_slot() / 32;
    signed(&network, 0, &key, &vote(now_slot(), epoch - 1, epoch, 1));
    let before = agreed_history(&network, &key);

    let far = now_slot() + 32 * 5_000;
    let (status, answer) = sign(&network, 1, &key, &vote(far, epoch, epoch + 5_000, 2));
    assert_ne!(status, 200, "{answer}");
    network.wait_until("an honest voter to refuse node 1's block", || {
        [0, 2, 3].iter().any(|node| {
            network
                .log(*node)
                .contains("refusing a block with a transaction beyond the horizon")
        })
    });
    assert!(
        [0, 2, 3].iter().any(|node| network
            .log(*node)
            .contains("dropping a transaction beyond the horizon")),
        "an honest leader drops it from its mempool"
    );
    assert_eq!(agreed_history(&network, &key), before);
    let height = network.height(0).unwrap();
    network.wait_until("consensus to go on", || {
        network
            .height(2)
            .is_some_and(|applied| applied > height + 2)
    });
    let next = epoch + 1;
    network.wait_until("the next epoch", || now_slot() / 32 >= next);
    signed(&network, 2, &key, &vote(now_slot(), epoch, next, 3));
}

/// P0 tests 7, 8 and 9: one node's clock behind, moved back, or jumped a day ahead. The other
/// three are a quorum and three keyholders: duties of the current slot sign; the node behind
/// refuses them itself; the node ahead admits a duty an hour ahead, which the others never vote
/// for. Corrected and restarted, it signs with them again, with the same history.
#[test]
fn horizon_3_clocks_that_disagree() {
    let offset = std::env::temp_dir().join(format!(
        "eth-mpc-signer-clock-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::write(&offset, "0").unwrap();
    let path = offset.display().to_string();
    let (network, key) = validator_network_with(move |node| {
        if node == 3 {
            vec![("ETH_MPC_SIGNER_CLOCK_OFFSET_FILE".into(), path.clone())]
        } else {
            Vec::new()
        }
    });

    // 7, 8: node 3's clock moves a minute back while it runs.
    std::fs::write(&offset, "-60").unwrap();
    signed(&network, 0, &key, &block(now_slot(), 1));
    let epoch = now_slot() / 32;
    beyond(
        &network,
        3,
        &key,
        &vote(now_slot(), epoch - 1, epoch, 1),
        "future_slot",
    );
    signed(&network, 1, &key, &vote(now_slot(), epoch - 1, epoch, 1));
    let before = agreed_history(&network, &key);

    // 9: it jumps a day ahead. Its coordinator submits a proposal an hour ahead (its clock
    // says it started); nobody else votes for it.
    std::fs::write(&offset, "86400").unwrap();
    let (status, answer) = sign(&network, 3, &key, &block(now_slot() + 3_600, 2));
    assert_ne!(status, 200, "{answer}");
    assert_eq!(agreed_history(&network, &key), before);
    signed(&network, 2, &key, &block(now_slot(), 3));

    // Corrected and restarted.
    std::fs::write(&offset, "0").unwrap();
    network.restart_node(3);
    network.wait_for_ready(&[3]);
    let next = epoch + 1;
    network.wait_until("the next epoch", || now_slot() / 32 >= next);
    signed(&network, 3, &key, &vote(now_slot(), epoch, next, 4));
    agreed_history(&network, &key);
    let _ = std::fs::remove_file(&offset);
}
