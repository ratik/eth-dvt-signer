//! Audit A1/A2: storage rollback. Node storage is restored to older bytes (a snapshot taken while
//! the node was stopped), then the network is asked to authorize and sign a conflicting payload.
//!
//! A1 and A2 roll back everything but the consensus journal: the replicated state, the key share,
//! the block archive and marshal's progress. Restoring the journal too makes the node forget its
//! own consensus votes, so it may vote twice in one view and be blocked by its peers (L-10 in
//! docs/audit.md): `a1_full_restore_never_signs_conflict` covers that case.

use crate::{
    KEY,
    failures::{index_of, request, wait_applied},
    harness::{
        NODES, TestNetwork, ethereum_verify,
        peer::{FakePeer, Responder},
        root, unhex,
    },
};
use eth_mpc_signer::signer::wire::{self, Refusal};
use serde_json::Value;
use std::time::{Duration, Instant};

/// A network whose nodes wait at most `secs` for a new authorization (so a stale coordinator
/// answers instead of hanging), with a completed ceremony.
/// The consensus journal partition (the node's own votes), see the module documentation.
pub const CONSENSUS_JOURNAL: &str = "registry-consensus";

pub fn network_with_key_args(args: &[&str]) -> (TestNetwork, Value) {
    let network = TestNetwork::start_with_args(
        crate::harness::NODES,
        args.iter().map(|arg| arg.to_string()).collect(),
        |_| Vec::new(),
    );
    network.wait_for_ready(&network.all());
    network.start_dkg(0, KEY);
    let key = network.wait_for_dkg(KEY, &network.all());
    (network, Value::String(key))
}

fn hold_env(network: &TestNetwork, node: usize) -> (std::path::PathBuf, Vec<(String, String)>) {
    let hold = network.dir.join(format!("hold-{node}"));
    (
        hold.clone(),
        vec![(
            "ETH_MPC_SIGNER_HOLD_FILE".into(),
            hold.display().to_string(),
        )],
    )
}

/// Node `node` refuses new authorizations, for (at least) `reason`.
pub fn assert_not_ready(network: &TestNetwork, node: usize, reason: &str) {
    let readiness = network.readiness(node);
    assert_ne!(readiness["state"], "ready", "{readiness}");
    assert_eq!(readiness["can_submit_authorization"], false, "{readiness}");
    assert_eq!(readiness["can_sign_authorized"], true, "{readiness}");
    assert!(
        readiness["reasons"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r == reason),
        "{readiness}"
    );
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

/// A1: node 3 is rolled back to storage from before `(KEY, 100)` was authorized for A (all but the
/// consensus journal). It must not authorize or sign B, before or after catching up, and the
/// network must keep A.
#[test]
fn a1_single_node_rollback() {
    let (network, key) = network_with_key_args(&["--authorization-timeout", "5"]);
    network.stop_node(3);
    network.snapshot(3, "before-a");
    network.restart_node(3);
    network.wait_for_ready(&[3]);

    let (status, signed_a) = network.sign(0, KEY, 100, root(0xaa));
    assert_eq!(status, 200, "{signed_a}");
    wait_applied(&network, &network.all(), 100);
    let authorized = authorization(&network, 0, 100).unwrap();

    // Roll node 3 back to the old bytes and keep it from applying blocks: it is stale but serves.
    network.stop_node(3);
    network.restore_keeping(3, "before-a", &[CONSENSUS_JOURNAL]);
    let (hold, env) = hold_env(&network, 3);
    std::fs::write(&hold, b"").unwrap();
    network.restart_node_with(3, env);
    network.wait_until("node 3 to serve HTTP", || network.height(3).is_some());
    assert_eq!(
        authorization(&network, 3, 100),
        None,
        "stale read: node 3 is behind"
    );

    // As a signer, the stale node refuses: node 2 is frozen, so node 0 needs node 3.
    let index_3 = index_of(&network, 3);
    network.freeze(2);
    let (status, body) = network.sign(0, KEY, 100, root(0xaa));
    network.thaw(2);
    assert_eq!(status, 504, "{body}");
    assert_eq!(
        body["refusals"][index_3.to_string()],
        "not_authorized",
        "{body}"
    );

    // As a coordinator, the stale node does not submit B: it has applied nothing since it started,
    // so it cannot see the outcome of a command, and says so instead of waiting for one.
    assert_not_ready(&network, 3, "no_block_since_start");
    let (status, body) = network.sign(3, KEY, 100, root(0xbb));
    assert_eq!(status, 503, "{body}");
    assert_eq!(body["result"], "NOT_READY", "{body}");
    assert!(body.get("signature").is_none(), "{body}");

    // A peer (node 2's identity) asks the stale node directly for B and for A.
    network.stop_node(2);
    let silent: Responder = Box::new(|_, _, _| Vec::new());
    let peer = FakePeer::start(&network, 2, &[], silent);
    let ask_b = request(100, root(0xbb));
    let ask_a = request(100, root(0xaa));
    for asked in [&ask_b, &ask_a] {
        assert_eq!(
            crate::failures::ask(&network, &peer, 3, asked),
            wire::Message::Refused {
                request: asked.id,
                reason: Refusal::NotAuthorized
            }
        );
    }

    // Let node 3 catch up: it replays the finalized history and ends with A, as the others.
    std::fs::remove_file(&hold).unwrap();
    network.wait_until("node 3 to re-apply the authorization", || {
        authorization(&network, 3, 100).is_some()
    });
    assert_eq!(authorization(&network, 3, 100), Some(authorized.clone()));
    for node in [0, 1, 3] {
        assert_eq!(authorization(&network, node, 100), Some(authorized.clone()));
    }

    // The parked request for B is answered with a conflict, never a partial; A is signed.
    let start = Instant::now();
    let mut b_answer = None;
    while start.elapsed() < Duration::from_secs(10) && b_answer.is_none() {
        if let Some((3, message)) = peer.recv(Duration::from_millis(100)) {
            match &message {
                wire::Message::Partial { request, .. } if *request == ask_b.id => {
                    panic!("node 3 signed the conflicting payload")
                }
                wire::Message::Refused { request, .. } if *request == ask_b.id => {
                    b_answer = Some(message)
                }
                _ => {}
            }
        }
    }
    assert_eq!(
        crate::failures::ask(&network, &peer, 3, &ask_b),
        wire::Message::Refused {
            request: ask_b.id,
            reason: Refusal::Conflict
        }
    );
    assert!(matches!(
        crate::failures::ask(&network, &peer, 3, &ask_a),
        wire::Message::Partial { .. }
    ));

    // Recovered: it reports itself ready (it applies what consensus finalizes).
    network.wait_for_ready(&[3]);

    // Through HTTP, B is rejected everywhere and A still signs, identically, including through
    // node 3 (which now needs nodes 0 and 1).
    for node in [0, 1, 3] {
        let (status, body) = network.sign(node, KEY, 100, root(0xbb));
        assert_eq!(status, 409, "node {node}: {body}");
    }
    let (status, again) = network.sign(3, KEY, 100, root(0xaa));
    assert_eq!(status, 200, "{again}");
    assert_eq!(again["signature"], signed_a["signature"]);
    assert!(ethereum_verify(&key, &root(0xaa), &again["signature"]));
    assert_eq!(network.blocked_for_equivocation(3), Vec::<usize>::new());
}

/// A1 with the whole data directory restored, consensus journal included (L-7 in docs/audit.md).
/// Node 3 no longer knows which consensus votes it cast and, depending on timing, votes against one
/// of them; the peers that see it block it (for an hour). Either way it must never sign B, and the
/// intact nodes keep signing A.
#[test]
fn a1_full_restore_never_signs_conflict() {
    let (network, key) = network_with_key_args(&["--authorization-timeout", "5"]);
    network.stop_node(3);
    network.snapshot(3, "before-a");
    network.restart_node(3);
    network.wait_for_ready(&[3]);
    let (status, signed_a) = network.sign(0, KEY, 100, root(0xaa));
    assert_eq!(status, 200, "{signed_a}");
    wait_applied(&network, &network.all(), 100);
    let authorized = authorization(&network, 0, 100).unwrap();

    network.stop_node(3);
    network.restore(3, "before-a");
    let (hold, env) = hold_env(&network, 3);
    std::fs::write(&hold, b"").unwrap();
    network.restart_node_with(3, env);
    network.wait_until("node 3 to serve HTTP", || network.height(3).is_some());
    assert_eq!(
        authorization(&network, 3, 100),
        None,
        "stale read: node 3 is behind"
    );
    // The durable floor was rolled back with everything else: it does not know of A.
    let floor = network.readiness(3)["consensus"]["floor_height"].as_u64();
    assert!(floor.is_none_or(|floor| floor < authorized.1), "{floor:?}");

    // Stale, and possibly cut off: B through node 3 is not signed; the intact nodes sign A.
    assert_not_ready(&network, 3, "no_block_since_start");
    let (status, body) = network.sign(3, KEY, 100, root(0xbb));
    assert_eq!(status, 503, "{body}");
    assert!(body.get("signature").is_none(), "{body}");
    let (status, again) = network.sign(0, KEY, 100, root(0xaa));
    assert_eq!(status, 200, "{again}");
    assert_eq!(again["signature"], signed_a["signature"]);

    // Released, node 3 converges to A unless peers blocked it for equivocating.
    std::fs::remove_file(&hold).unwrap();
    network.wait_until("node 3 to re-apply the authorization or be blocked", || {
        authorization(&network, 3, 100).is_some() || !network.blocked_for_equivocation(3).is_empty()
    });
    if let Some(applied) = authorization(&network, 3, 100) {
        assert_eq!(applied, authorized);
    }
    for node in network.all() {
        let (status, body) = network.sign(node, KEY, 100, root(0xbb));
        assert_ne!(status, 200, "node {node} signed B: {body}");
        assert!(body.get("signature").is_none(), "{body}");
        if node != 3 {
            assert_eq!(status, 409, "node {node}: {body}");
        }
    }
    let blocked = network.blocked_for_equivocation(3);
    println!("a1 full restore: node 3 blocked for equivocation by {blocked:?}");
    if blocked.is_empty() {
        network.wait_for_ready(&[3]);
        let (status, again) = network.sign(3, KEY, 100, root(0xaa));
        assert_eq!(status, 200, "{again}");
        assert_eq!(again["signature"], signed_a["signature"]);
    } else if blocked.len() == NODES - 1 {
        // Cut off from every peer: it must not keep claiming that it follows consensus.
        network.wait_until("cut-off node 3 to report that it is not ready", || {
            network.readiness(3)["state"] != "ready"
        });
    }
    let (status, again) = network.sign(1, KEY, 100, root(0xaa));
    assert_eq!(status, 200, "{again}");
    assert_eq!(again["signature"], signed_a["signature"]);
    assert!(ethereum_verify(&key, &root(0xaa), &again["signature"]));
    for node in network.all() {
        assert_eq!(network.count(node, "panicked"), 0, "node {node} panicked");
    }
}

/// A2: two nodes (2 and 3) are rolled back together (all but the consensus journal), beyond
/// `f = 1`. The two intact nodes keep the finalized history; the rolled-back ones must converge to
/// it, not to a conflicting one.
///
/// Liveness here is eventual only: two simultaneous failures exceed `f = 1`. If the restored
/// nodes missed the certificate of the view the others are in, consensus waits for the next
/// nullify retry, which carries it (`timeout_retry`, 3 s). The authorization timeout leaves room
/// for that wait; the time to recover is printed.
#[test]
fn a2_two_node_rollback() {
    let (network, key) = network_with_key_args(&["--authorization-timeout", "15"]);
    for node in [2, 3] {
        network.stop_node(node);
        network.snapshot(node, &format!("before-a-{node}"));
        network.restart_node(node);
    }
    network.wait_for_ready(&network.all());
    let (status, signed_a) = network.sign(0, KEY, 100, root(0xaa));
    assert_eq!(status, 200, "{signed_a}");
    wait_applied(&network, &network.all(), 100);
    let authorized = authorization(&network, 0, 100).unwrap();

    for node in [2, 3] {
        network.stop_node(node);
        network.restore_keeping(node, &format!("before-a-{node}"), &[CONSENSUS_JOURNAL]);
    }
    for node in [2, 3] {
        network.restart_node(node);
    }
    let restarted = Instant::now();
    for node in [2, 3] {
        network.wait_until(&format!("node {node} to serve HTTP"), || {
            network.height(node).is_some()
        });
    }

    // Right away (the restored nodes are still behind), through every node, B is never signed.
    let results = std::thread::scope(|scope| {
        let network = &network;
        let handles: Vec<_> = [2, 3, 0]
            .into_iter()
            .map(|node| scope.spawn(move || (node, network.sign(node, KEY, 100, root(0xbb)))))
            .collect();
        handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>()
    });
    for (node, (status, body)) in results {
        assert_ne!(status, 200, "node {node} signed B: {body}");
        assert!(body.get("signature").is_none());
    }

    // The rolled-back nodes converge to the finalized history: A, at the same height.
    for node in [2, 3] {
        network.wait_until(
            &format!("node {node} to re-apply the authorization"),
            || authorization(&network, node, 100).is_some(),
        );
    }
    for node in network.all() {
        assert_eq!(
            authorization(&network, node, 100),
            Some(authorized.clone()),
            "node {node}"
        );
        let (status, body) = network.sign(node, KEY, 100, root(0xbb));
        assert_eq!(status, 409, "node {node}: {body}");
    }
    let (status, again) = network.sign(2, KEY, 100, root(0xaa));
    assert_eq!(status, 200, "{again}");
    assert_eq!(again["signature"], signed_a["signature"]);

    // Consensus is still live and every node agrees on the state. Node 3 authorizes once it has
    // applied everything it knows of (until then it answers `NOT_READY`).
    network.wait_for_ready(&network.all());
    let requested = Instant::now();
    let (status, new) = network.sign(3, KEY, 101, root(0xcc));
    assert_eq!(status, 200, "{new}");
    println!(
        "a2: new authorization signed {} ms after the rolled-back nodes restarted (request {} ms)",
        restarted.elapsed().as_millis(),
        requested.elapsed().as_millis()
    );
    assert!(ethereum_verify(&key, &root(0xcc), &new["signature"]));
    wait_applied(&network, &network.all(), 101);
    let counts: Vec<_> = network
        .all()
        .into_iter()
        .map(|node| network.status(node)["authorizations"].clone())
        .collect();
    assert!(
        counts.windows(2).all(|pair| pair[0] == pair[1]),
        "{counts:?}"
    );
    for node in network.all() {
        assert_eq!(network.count(node, "panicked"), 0, "node {node} panicked");
        assert_eq!(network.blocked_for_equivocation(node), Vec::<usize>::new());
    }
}

/// Fault-model boundary: every node rolled back (a quorum). Nothing on any node remembers that
/// nonce 100 was authorized for A, so B gets authorized and signed: two valid signatures for one
/// `(ceremony, nonce)`. Not detectable without state outside the nodes (see docs/audit.md); kept as
/// an explicit, failing reproducer.
#[test]
#[ignore = "known limitation (docs/audit.md): rolling back a quorum of nodes is undetected"]
fn a2_whole_network_rollback() {
    let (network, _) = network_with_key_args(&[]);
    for node in network.all() {
        network.stop_node(node);
        network.snapshot(node, &format!("before-a-{node}"));
    }
    for node in network.all() {
        network.restart_node(node);
    }
    network.wait_for_ready(&network.all());
    let (status, body) = network.sign(0, KEY, 100, root(0xaa));
    assert_eq!(status, 200, "{body}");

    for node in network.all() {
        network.stop_node(node);
        network.restore(node, &format!("before-a-{node}"));
    }
    for node in network.all() {
        network.restart_node(node);
    }
    network.wait_for_ready(&network.all());
    let (status, body) = network.sign(1, KEY, 100, root(0xbb));
    assert_ne!(
        status, 200,
        "conflicting signature for nonce 100 after a whole-network rollback: {body}"
    );
}

/// Views node `node`'s consensus resumed at, one per start (`consensus initialized`).
fn resumed_views(network: &TestNetwork, node: usize) -> Vec<u64> {
    network
        .log(node)
        .lines()
        .filter(|line| line.contains("consensus initialized"))
        .map(|line| {
            let view = line.split("observed_view=").nth(1).unwrap();
            view.split_whitespace().next().unwrap().parse().unwrap()
        })
        .collect()
}

/// Journal-only rollback: node 3 gets back a consensus journal from before it voted in many views,
/// while its state and marshal progress stay current. It resumes right above its durable
/// finalized floor, never at the old journal's view: it cannot vote again at or below the floor.
/// It is stopped at a quiet point (just after applying a block, while the next leader still waits
/// for transactions), so it cast no vote above the floor either, and nothing it forgot can be
/// repeated: its peers do not block it.
#[test]
fn journal_only_rollback_resumes_above_floor() {
    let (network, key) = network_with_key_args(&[]);
    network.stop_node(3);
    network.snapshot(3, "old-journal");
    network.restart_node(3);
    network.wait_for_ready(&[3]);
    let old_view = *resumed_views(&network, 3).last().unwrap();

    let (status, signed) = network.sign(0, KEY, 100, root(0xaa));
    assert_eq!(status, 200, "{signed}");
    wait_applied(&network, &network.all(), 100);
    let height = network.height(3).unwrap();
    network.wait_until("node 3 to vote in more views", || {
        network
            .height(3)
            .is_some_and(|applied| applied >= height + 5)
    });

    // Quiet point: node 3 just applied a block; 300 ms lets marshal persist the acknowledgement,
    // well before the next leader proposes (an idle leader waits 1.5 s).
    let applied = network.height(3).unwrap();
    network.wait_until("node 3 to apply a new block", || {
        network.height(3).is_some_and(|now| now > applied)
    });
    std::thread::sleep(Duration::from_millis(300));
    network.stop_node(3);
    network.restore_partition(3, "old-journal", CONSENSUS_JOURNAL);
    network.restart_node(3);
    network.wait_for_ready(&[3]);

    let readiness = network.readiness(3);
    let floor_view = readiness["consensus"]["floor_view"].as_u64().unwrap();
    let resumed = *resumed_views(&network, 3).last().unwrap();
    assert!(
        floor_view > old_view,
        "the old journal is below the floor: {readiness}"
    );
    assert_eq!(
        resumed,
        floor_view + 1,
        "resumed above the floor, not at view {old_view}"
    );
    assert_eq!(network.blocked_for_equivocation(3), Vec::<usize>::new());

    network.freeze(1);
    let (status, again) = network.sign(0, KEY, 100, root(0xaa));
    network.thaw(1);
    assert_eq!(status, 200, "{again}");
    assert_eq!(again["signature"], signed["signature"]);
    let (status, body) = network.sign(3, KEY, 100, root(0xbb));
    assert_eq!(status, 409, "{body}");
    let (status, new) = network.sign(3, KEY, 101, root(0xcc));
    assert_eq!(status, 200, "{new}");
    assert!(ethereum_verify(&key, &root(0xcc), &new["signature"]));
}
