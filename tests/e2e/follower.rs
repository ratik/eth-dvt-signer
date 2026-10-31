//! FOL-1 to FOL-5 (R2): a node outside the consensus committee follows it without voting. It
//! applies every finalized block itself, each finalization checked against the unchanged committee,
//! and submits transactions through the committee's mempools.

use crate::{
    KEY,
    harness::{TestNetwork, root},
};
use serde_json::{Value, json};
use std::time::{Duration, Instant};

/// Consensus voters: nodes `0..VOTERS`.
pub const VOTERS: usize = 4;
/// The non-voting node.
pub const FOLLOWER: usize = 4;

/// Four voters and one follower (node 4), the follower started only if `follower_started`.
pub fn network_with_follower(
    env: impl Fn(usize) -> Vec<(String, String)>,
    follower_started: bool,
) -> TestNetwork {
    TestNetwork::start_with_followers(
        VOTERS,
        1,
        Vec::new(),
        |_| Vec::new(),
        env,
        |id| id < VOTERS || follower_started,
    )
}

pub fn voters() -> Vec<usize> {
    (0..VOTERS).collect()
}

/// Highest height of the given nodes that answer.
fn max_height(network: &TestNetwork, nodes: &[usize]) -> u64 {
    nodes
        .iter()
        .filter_map(|id| network.height(*id))
        .max()
        .unwrap_or(0)
}

/// What every node must agree on about a ceremony (its share and index are node-local).
fn ceremony_state(network: &TestNetwork, id: usize, ceremony: &str) -> Value {
    let (status, mut body) = network.get(id, &format!("/dkg/status/{ceremony}"));
    assert_eq!(status, 200, "{body}");
    let object = body.as_object_mut().unwrap();
    object.remove("share");
    object.remove("participant_id");
    object.remove("participant_index");
    body
}

/// FOL-1: a follower started late joins the running network, catches up from genesis and follows
/// it, without being a voter and without a signing API.
#[test]
fn fol_1_follower_joins_without_voting() {
    let network = network_with_follower(|_| Vec::new(), false);
    network.wait_for_ready(&voters());
    network.wait_until("some history", || max_height(&network, &voters()) >= 5);

    network.start_node(FOLLOWER);
    let behind = max_height(&network, &voters());
    network.wait_for_ready(&[FOLLOWER]);
    network.wait_until("the follower to catch up", || {
        network
            .height(FOLLOWER)
            .is_some_and(|height| height >= behind)
    });
    assert!(
        network
            .log(FOLLOWER)
            .contains("following consensus without voting"),
        "{}",
        network.log(FOLLOWER)
    );

    // Voters vote; the follower does not, and has no committee index.
    for id in voters() {
        assert_eq!(network.readiness(id)["consensus"]["voting"], true);
    }
    assert_eq!(network.readiness(FOLLOWER)["consensus"]["voting"], false);
    let (_, identity) = network.get(FOLLOWER, "/identity");
    assert!(identity["participant_index"].is_null(), "{identity}");

    // It keeps following.
    let at = network.height(FOLLOWER).unwrap();
    network.wait_until("the follower to apply new blocks", || {
        network
            .height(FOLLOWER)
            .is_some_and(|height| height >= at + 3)
    });

    // It coordinates no signing: no Web3Signer signing, no raw signing.
    let (status, body) = network.eth2_sign(FOLLOWER, &format!("0x{}", "ab".repeat(48)), &json!({}));
    assert_eq!(status, 403, "{body}");
    let (status, body) = network.sign(FOLLOWER, KEY, 1, root(0x01));
    assert_eq!(status, 403, "{body}");
}

/// FOL-2: the follower applies the same finalized blocks and reaches the same replicated state:
/// ceremonies, validator keys and authorizations.
#[test]
fn fol_2_follower_applies_the_same_state() {
    let network = network_with_follower(|_| Vec::new(), true);
    network.wait_for_ready(&network.all());

    network.start_dkg(0, KEY);
    let key = network.wait_for_dkg(KEY, &voters());
    network.start_validator_dkg(1, "fol-2-validator");
    network.wait_for_dkg("fol-2-validator", &voters());
    let (status, signed) = network.sign(0, KEY, 7, root(0x07));
    assert_eq!(status, 200, "{signed}");
    let height = signed["height"].as_u64().unwrap();

    network.wait_until("the follower to apply the authorization", || {
        network.height(FOLLOWER).is_some_and(|at| at >= height)
    });
    for ceremony in [KEY, "fol-2-validator"] {
        let expected = ceremony_state(&network, 0, ceremony);
        for id in network.all() {
            assert_eq!(
                ceremony_state(&network, id, ceremony),
                expected,
                "node {id}"
            );
        }
    }
    assert_eq!(ceremony_state(&network, FOLLOWER, KEY)["public_key"], key);
    // Not a player of these ceremonies: it holds no share of them.
    let (_, status) = network.get(FOLLOWER, &format!("/dkg/status/{KEY}"));
    assert_eq!(status["share"], "pending", "{status}");

    let (_, authorization) = network.get(0, &format!("/authorizations/{KEY}/7"));
    let (_, validators) = network.get(0, "/validators");
    for id in network.all() {
        assert_eq!(
            network.get(id, &format!("/authorizations/{KEY}/7")).1,
            authorization
        );
        assert_eq!(network.get(id, "/validators").1, validators, "node {id}");
    }
}

/// FOL-3: the follower restarts (after missing blocks, and right away), catches up and keeps
/// following.
#[test]
fn fol_3_follower_restarts_and_catches_up() {
    let network = network_with_follower(|_| Vec::new(), true);
    network.wait_for_ready(&network.all());
    network.start_dkg(0, KEY);
    network.wait_for_dkg(KEY, &voters());

    network.stop_node(FOLLOWER);
    for nonce in 1..=3 {
        let (status, body) = network.sign(0, KEY, nonce, root(nonce as u8));
        assert_eq!(status, 200, "{body}");
    }
    let missed = max_height(&network, &voters());
    network.wait_until("blocks the follower misses", || {
        max_height(&network, &voters()) >= missed + 5
    });

    network.start_node(FOLLOWER);
    let tip = max_height(&network, &voters());
    network.wait_for_ready(&[FOLLOWER]);
    network.wait_until("the follower to catch up", || {
        network.height(FOLLOWER).is_some_and(|height| height >= tip)
    });
    for nonce in 1..=3 {
        let (status, body) = network.get(FOLLOWER, &format!("/authorizations/{KEY}/{nonce}"));
        assert_eq!(status, 200, "{body}");
    }

    let before = network.height(FOLLOWER).unwrap();
    network.restart_node(FOLLOWER);
    network.wait_for_ready(&[FOLLOWER]);
    network.wait_until("the follower to follow again", || {
        network
            .height(FOLLOWER)
            .is_some_and(|height| height >= before + 3)
    });
    assert_eq!(network.readiness(FOLLOWER)["consensus"]["voting"], false);
}

/// FOL-4: a transaction submitted on the follower reaches a block through the committee's
/// mempools. Its first gossip is dropped (test hook): only the follower's later gossip carries it.
#[test]
fn fol_4_follower_submits_a_transaction() {
    let network = network_with_follower(
        |id| {
            if id == FOLLOWER {
                vec![("ETH_MPC_SIGNER_DROP_FIRST_GOSSIP".into(), "1".into())]
            } else {
                Vec::new()
            }
        },
        true,
    );
    network.wait_for_ready(&network.all());

    // `POST /dkg/start` answers once the start is finalized.
    let started = network.start_dkg(FOLLOWER, "fol-4");
    assert_eq!(started["status"], "in_progress", "{started}");
    assert!(
        network
            .log(FOLLOWER)
            .contains("gossiping an unfinalized transaction again"),
        "the first gossip was dropped: the transaction must have gone out again"
    );
    // The committee runs the ceremony it started; every node, the follower included, sees it.
    let key = network.wait_for_dkg("fol-4", &voters());
    network.wait_until("the follower to see the ceremony completed", || {
        ceremony_state(&network, FOLLOWER, "fol-4")["status"] == "completed"
    });
    assert_eq!(
        ceremony_state(&network, FOLLOWER, "fol-4")["public_key"],
        key
    );
}

/// FOL-5: the follower cannot vote, propose or count toward a quorum: with two voters stopped,
/// the two left and the follower (three nodes) finalize nothing, until a third voter returns.
#[test]
fn fol_5_follower_cannot_vote_or_propose() {
    let network = network_with_follower(|_| Vec::new(), true);
    network.wait_for_ready(&network.all());
    network.wait_until("some blocks", || {
        network.height(FOLLOWER).is_some_and(|height| height >= 5)
    });

    network.stop_node(2);
    network.stop_node(3);
    // Let in-flight views end, then watch: nothing is finalized for a long while.
    std::thread::sleep(Duration::from_secs(4));
    let stalled = max_height(&network, &[0, 1, FOLLOWER]);
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(12) {
        assert_eq!(
            max_height(&network, &[0, 1, FOLLOWER]),
            stalled,
            "a quorum formed with two voters and the follower"
        );
        std::thread::sleep(Duration::from_millis(250));
    }

    network.restart_node(2);
    network.wait_until("consensus to resume with three voters", || {
        network
            .height(FOLLOWER)
            .is_some_and(|height| height >= stalled + 3)
    });

    // Leaders are committee members only: the follower never proposed a block.
    assert_eq!(network.count(FOLLOWER, "proposing a block"), 0);
    assert!(network.count(0, "proposing a block") > 0);
}
