//! Readiness tolerance versus authorization safety: node 3 knows of one, two or three finalized
//! blocks it has not applied (one of them authorizes `(KEY, nonce) -> A`), and is asked to
//! authorize and sign a conflicting B.
//!
//! The lag is exact: node 3 holds from the first block carrying a transaction, and while the lag
//! is set up leaders propose only blocks carrying new transactions (test hooks), so the finalized
//! blocks after node 3's last applied one are exactly A's and the markers'. Consensus stays live
//! throughout. Node 1 is replaced by a scripted byzantine signer: it signs whatever it is asked,
//! with its real share, and does not vote.

use crate::{
    KEY,
    failures::{ask, index_of, request, wait_applied},
    harness::{
        TestNetwork, ethereum_verify,
        peer::{FakePeer, Responder},
        root, unhex,
    },
    signing::network_with_key,
};
use commonware_codec::Encode as _;
use commonware_cryptography::sha256::Digest;
use eth_dvt_signer::{
    dkg::signing::Message,
    signer::wire::{self, Refusal},
};
use rand::{RngExt as _, SeedableRng as _, rngs::StdRng};
use serde_json::{Value, json};
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

/// Authorized and applied everywhere before node 3 starts lagging.
const APPLIED_NONCE: u64 = 50;

struct Lagging {
    network: TestNetwork,
    key: Value,
    /// Node 1's identity: signs anything, records every partial signature sent to it.
    peer: FakePeer,
    partials: Arc<Mutex<Vec<(usize, Digest)>>>,
    hold: PathBuf,
    /// While it exists, no empty block is proposed.
    no_empty_blocks: PathBuf,
}

fn hex(payload: [u8; 32]) -> String {
    format!("0x{}", ::hex::encode(payload))
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

/// Wait until node 3 has applied every block it knows of (ready alone allows a small lag), so the
/// next hold starts at the next transaction.
fn wait_caught_up(network: &TestNetwork) {
    network.wait_for_ready(&[0, 2, 3]);
    // No transaction is pending anywhere (each is in a block its node applied: a request rejected
    // by consensus in a later block than the winner's cannot still be finalized, and held, once
    // the hold is armed again), and node 3 applied everything it knows of.
    network.wait_until("no pending transaction, node 3 caught up", || {
        [0, 2, 3]
            .iter()
            .all(|node| network.status(*node)["mempool"] == 0)
            && {
                let readiness = network.readiness(3);
                readiness["applied_height"] == readiness["known_finalized_height"]
            }
    });
}

fn lagging_network() -> Lagging {
    let (network, key) = network_with_key();
    let (status, body) = network.sign(0, KEY, APPLIED_NONCE, root(0x50));
    assert_eq!(status, 200, "{body}");
    wait_applied(&network, &network.all(), APPLIED_NONCE);

    network.stop_node(1);
    let partials = Arc::new(Mutex::new(Vec::new()));
    let seen = partials.clone();
    let responder: Responder = Box::new(move |shares, from, message| match message {
        wire::Message::Request(request) => {
            let partial = Message::Ethereum(request.payload_hash).partial_sign(&shares[0]);
            let reply = wire::Message::Partial {
                request: request.id,
                partial,
            };
            vec![(from, reply.encode().to_vec())]
        }
        wire::Message::Partial { request, .. } => {
            seen.lock().unwrap().push((from, *request));
            Vec::new()
        }
        wire::Message::Refused { .. } => Vec::new(),
    });
    let peer = FakePeer::start(&network, 1, &[0], responder);

    let hold = network.dir.join("hold-3");
    let no_empty_blocks = network.dir.join("no-empty-blocks");
    let paused = (
        "ETH_MPC_SIGNER_NO_EMPTY_BLOCKS_FILE".to_string(),
        no_empty_blocks.display().to_string(),
    );
    for node in [0, 2] {
        network.restart_node_with(node, vec![paused.clone()]);
    }
    network.restart_node_with(
        3,
        vec![
            paused,
            (
                "ETH_MPC_SIGNER_HOLD_FILE".into(),
                hold.display().to_string(),
            ),
            ("ETH_MPC_SIGNER_HOLD_FROM".into(), "transactions".into()),
        ],
    );
    wait_caught_up(&network);
    std::fs::write(&hold, b"").unwrap();
    Lagging {
        network,
        key,
        peer,
        partials,
        hold,
        no_empty_blocks,
    }
}

impl Lagging {
    /// Authorize `(KEY, nonce) -> payload` through node 0 in a block node 3 holds, then `blocks - 1`
    /// markers (other authorizations), each in the next block. With empty blocks paused, node 3
    /// then knows of exactly `blocks` finalized blocks it has not applied. Returns node 0's answer
    /// and the height of A's block.
    fn lag(&self, nonce: u64, payload: [u8; 32], blocks: u64) -> (Value, u64) {
        let network = &self.network;
        std::fs::write(&self.no_empty_blocks, b"").unwrap();
        let (status, signed) = network.sign(0, KEY, nonce, payload);
        assert_eq!(status, 200, "{signed}");
        let height = signed["height"].as_u64().unwrap();
        for marker in 1..blocks {
            let (status, body) = network.sign(0, KEY, nonce * 100 + marker, root(0x0f));
            assert_eq!(status, 200, "{body}");
            assert_eq!(body["height"], height + marker, "{body}");
        }
        let tip = height + blocks - 1;
        network.wait_until(&format!("node 3 to learn of block {tip}"), || {
            network.readiness(3)["known_finalized_height"] == tip
        });
        assert_eq!(network.height(0), Some(tip));
        let readiness = network.readiness(3);
        assert_eq!(readiness["applied_height"], height - 1, "{readiness}");
        // Marshal reports the tip a moment before delivering the block to the executor.
        network.wait_until(&format!("node 3 to hold block {height}"), || {
            network.count(
                3,
                &format!("test hook: holding finalized block height={height}"),
            ) == 1
        });
        (signed, height)
    }

    /// Empty blocks again (an idle network finalizes one every ~1.6 s).
    fn resume_blocks(&self) {
        let _ = std::fs::remove_file(&self.no_empty_blocks);
    }

    fn release(&self) {
        let _ = std::fs::remove_file(&self.hold);
    }

    /// Whether any node logged a recovered signature for `payload`.
    fn signed_anywhere(&self, payload: [u8; 32]) -> bool {
        let payload = hex(payload);
        (0..4).filter(|node| *node != 1).any(|node| {
            self.network
                .log(node)
                .lines()
                .any(|line| line.contains("coordinator: signed") && line.contains(&payload))
        })
    }

    /// Whether any node sent the scripted peer a partial signature for `(KEY, nonce) -> payload`.
    fn partial_sent(&self, nonce: u64, payload: [u8; 32]) -> bool {
        let id = request(nonce, payload).id;
        self.partials
            .lock()
            .unwrap()
            .iter()
            .any(|(_, request)| *request == id)
    }

    fn submitted(&self, node: usize, nonce: u64, payload: [u8; 32]) -> bool {
        let payload = hex(payload);
        self.network.log(node).lines().any(|line| {
            line.contains("submitted signing authorization")
                && line.contains(&format!("nonce={nonce} "))
                && line.contains(&payload)
        })
    }

    fn rejected_by(&self, node: usize, nonce: u64, payload: [u8; 32]) -> bool {
        let payload = hex(payload);
        self.network.log(node).lines().any(|line| {
            line.contains("applied signing authorization")
                && line.contains(&format!("nonce={nonce} "))
                && line.contains(&payload)
                && line.contains("outcome=Rejected")
        })
    }
}

/// Node 3 is `blocks` (1 or 2) finalized blocks behind, one of them authorizing A: within the
/// readiness tolerance, so it is ready and submits a conflicting B it cannot see is taken. The
/// replicated state machine rejects B (ordered after A); no partial and no signature for B exist.
fn stale_conflicting_submission(blocks: u64) {
    let lagging = lagging_network();
    let network = &lagging.network;
    let (a, b) = (root(0xaa), root(0xbb));
    let (signed_a, height) = lagging.lag(100, a, blocks);

    // This is the tolerance branch: behind by `blocks`, yet ready.
    let readiness = network.readiness(3);
    assert_eq!(readiness["state"], "ready", "{readiness}");
    assert_eq!(readiness["can_submit_authorization"], true);
    assert_eq!(
        readiness["known_finalized_height"].as_u64().unwrap()
            - readiness["applied_height"].as_u64().unwrap(),
        blocks
    );
    // Asked directly, node 3 refuses both payloads: it signs nothing it has not applied.
    for payload in [a, b] {
        let asked = request(100, payload);
        assert_eq!(
            ask(network, &lagging.peer, 3, &asked),
            wire::Message::Refused {
                request: asked.id,
                reason: Refusal::NotAuthorized
            }
        );
    }

    std::thread::scope(|scope| {
        let stale = scope.spawn(|| network.sign(3, KEY, 100, b));
        // Accepted for submission (not rejected at once): node 3 has no record of A.
        network.wait_until("node 3 to submit B", || lagging.submitted(3, 100, b));
        lagging.resume_blocks();
        // Consensus orders B after A: rejected, the authorization unchanged.
        network.wait_until("B to be finalized and rejected", || {
            lagging.rejected_by(0, 100, b)
        });
        for node in [0, 2] {
            assert_eq!(
                authorization(network, node, 100),
                Some((a.to_vec(), height))
            );
        }
        lagging.release();
        // Node 3 applies A, then its own rejected command: the client learns of the conflict.
        let (status, body) = stale.join().unwrap();
        assert_eq!(status, 409, "{body}");
        assert_eq!(body["result"], "REJECTED");
        assert_eq!(body["height"], height);
    });
    assert!(lagging.rejected_by(3, 100, b));
    assert_eq!(authorization(network, 3, 100), Some((a.to_vec(), height)));
    network.wait_for_ready(&[3]);

    // After recovery node 3 recognizes the conflict at once, and A still signs identically.
    let (status, body) = network.sign(3, KEY, 100, b);
    assert_eq!(status, 409, "{body}");
    let (status, again) = network.sign(3, KEY, 100, a);
    assert_eq!(status, 200, "{again}");
    assert_eq!(again["signature"], signed_a["signature"]);
    assert!(ethereum_verify(&lagging.key, &a, &again["signature"]));

    // The byzantine signer cannot collect B either: every honest node refuses it.
    for node in [0, 2, 3] {
        let asked = request(100, b);
        assert_eq!(
            ask(network, &lagging.peer, node, &asked),
            wire::Message::Refused {
                request: asked.id,
                reason: Refusal::Conflict
            },
            "node {node}"
        );
    }
    assert!(!lagging.partial_sent(100, b), "a partial signature for B");
    assert!(!lagging.signed_anywhere(b), "a group signature for B");
}

#[test]
fn one_block_behind_conflicting_authorization_is_rejected() {
    stale_conflicting_submission(1);
}

#[test]
fn two_blocks_behind_conflicting_authorization_is_rejected() {
    stale_conflicting_submission(2);
}

/// Three blocks behind, beyond the tolerance: node 3 is not ready and refuses B before submitting
/// anything; an authorization it has applied still signs.
#[test]
fn three_blocks_behind_refuses_before_submission() {
    let lagging = lagging_network();
    let network = &lagging.network;
    let (a, b) = (root(0xaa), root(0xbb));
    let (signed_a, _) = lagging.lag(100, a, 3);

    let readiness = network.readiness(3);
    assert_eq!(readiness["state"], "syncing", "{readiness}");
    assert_eq!(readiness["reasons"], json!(["local_backlog"]));
    let (status, body) = network.sign(3, KEY, 100, b);
    assert_eq!(status, 503, "{body}");
    assert_eq!(body["result"], "NOT_READY");
    assert_eq!(body["reasons"], json!(["local_backlog"]));
    assert!(!lagging.submitted(3, 100, b), "submitted while not ready");

    // Applied before the lag: signable through node 3 by its keyholder, node 0's and node 1's.
    // Node 2 frozen, so node 3's own partial is needed: the coordinator asks its peers at once and
    // three fast peers would otherwise do without it.
    let index_3 = u64::from(index_of(network, 3));
    network.freeze(2);
    let (status, body) = network.sign(3, KEY, APPLIED_NONCE, root(0x50));
    network.thaw(2);
    assert_eq!(status, 200, "{body}");
    assert!(
        body["signers"]
            .as_array()
            .unwrap()
            .contains(&index_3.into()),
        "{body}"
    );
    assert!(ethereum_verify(
        &lagging.key,
        &root(0x50),
        &body["signature"]
    ));

    lagging.resume_blocks();
    lagging.release();
    network.wait_for_ready(&[3]);
    let (status, body) = network.sign(3, KEY, 100, b);
    assert_eq!(status, 409, "{body}");
    let (status, again) = network.sign(3, KEY, 100, a);
    assert_eq!(status, 200, "{again}");
    assert_eq!(again["signature"], signed_a["signature"]);
    assert!(!lagging.partial_sent(100, b));
    assert!(!lagging.signed_anywhere(b));
}

/// While node 3 is one or two blocks behind, A goes through node 0 and a conflicting B through
/// node 3 for the same new nonce, in a random order. Consensus authorizes exactly one, the same on
/// every node, and only that one is signed. Seed: `E2E_SEED` (printed).
#[test]
fn concurrent_conflicting_requests_while_lagging() {
    let seed = std::env::var("E2E_SEED")
        .ok()
        .and_then(|seed| seed.parse().ok())
        .unwrap_or_else(rand::random::<u64>);
    println!("concurrent lag test seed {seed} (E2E_SEED to reproduce)");
    let mut rng = StdRng::seed_from_u64(seed);
    let lagging = lagging_network();
    let network = &lagging.network;

    for round in 0..3u8 {
        let marker = 1_000 + u64::from(round) * 10;
        let nonce = marker + 1;
        let (a, b) = (root(0xa0 + round), root(0xb0 + round));
        let blocks = rng.random_range(1..=2u64);
        let a_first = rng.random_bool(0.5);
        let gap = Duration::from_millis(rng.random_range(0..300));
        println!("round {round}: {blocks} block(s) behind, A first: {a_first}, gap {gap:?}");
        lagging.lag(marker, root(0x10 + round), blocks);

        let (via_0, via_3) = std::thread::scope(|scope| {
            let through_0 = || scope.spawn(move || network.sign(0, KEY, nonce, a));
            let through_3 = || scope.spawn(move || network.sign(3, KEY, nonce, b));
            let (via_0, via_3) = if a_first {
                let via_0 = through_0();
                std::thread::sleep(gap);
                (via_0, through_3())
            } else {
                let via_3 = through_3();
                std::thread::sleep(gap);
                (through_0(), via_3)
            };
            // Each request is submitted, or answered without a submission: node 0 answers `409` at
            // once if B is already applied there; node 3 refuses B if A's block put it three
            // blocks behind.
            network.wait_until("both requests handled", || {
                (lagging.submitted(0, nonce, a) || via_0.is_finished())
                    && (lagging.submitted(3, nonce, b) || via_3.is_finished())
            });
            lagging.resume_blocks();
            wait_applied(network, &[0, 2], nonce);
            lagging.release();
            (via_0.join().unwrap(), via_3.join().unwrap())
        });

        wait_applied(network, &[0, 2, 3], nonce);
        let winner = authorization(network, 0, nonce).unwrap();
        for node in [2, 3] {
            assert_eq!(
                authorization(network, node, nonce),
                Some(winner.clone()),
                "node {node}"
            );
        }
        let submitted_b = lagging.submitted(3, nonce, b);
        let outcome = if winner.0 == a.to_vec() {
            assert_eq!(via_0.0, 200, "{}", via_0.1);
            assert!(ethereum_verify(&lagging.key, &a, &via_0.1["signature"]));
            if submitted_b {
                assert_eq!(via_3.0, 409, "{}", via_3.1);
                assert_eq!(via_3.1["result"], "REJECTED");
                "A authorized, B rejected by consensus"
            } else {
                assert_eq!(via_3.0, 503, "{}", via_3.1);
                assert_eq!(via_3.1["result"], "NOT_READY");
                assert_eq!(via_3.1["reasons"], json!(["local_backlog"]));
                "A authorized, B refused before submission (node 3 three blocks behind)"
            }
        } else {
            assert_eq!(winner.0, b.to_vec());
            assert!(submitted_b);
            assert_eq!(via_3.0, 200, "{}", via_3.1);
            assert!(ethereum_verify(&lagging.key, &b, &via_3.1["signature"]));
            assert_eq!(via_0.0, 409, "{}", via_0.1);
            assert_eq!(via_0.1["result"], "REJECTED");
            if lagging.submitted(0, nonce, a) {
                "B authorized, A rejected by consensus"
            } else {
                "B authorized and applied first, A rejected from node 0's state"
            }
        };
        println!("round {round}: {outcome}");
        let losing = if winner.0 == a.to_vec() { b } else { a };
        assert!(!lagging.partial_sent(nonce, losing));
        assert!(!lagging.signed_anywhere(losing));

        wait_caught_up(network);
        std::fs::write(&lagging.hold, b"").unwrap();
    }
}
