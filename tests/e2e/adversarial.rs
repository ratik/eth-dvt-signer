//! Audit C3/E6, D1-D6, E4/E5: slow, malformed, duplicated and replayed signing traffic, and the
//! parked-request queue, against real nodes over real authenticated p2p.

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
use blst::min_pk::Signature as EthSignature;
use commonware_codec::Encode as _;
use eth_mpc_signer::{
    dkg::{CeremonyId, parked::PER_PEER, signing::Message},
    signer::wire::{self, Refusal, Request},
};
use rand::{Rng as _, SeedableRng as _, rngs::StdRng};
use serde_json::Value;
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

fn signers(body: &Value) -> Vec<u32> {
    body["signers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|index| index.as_u64().unwrap() as u32)
        .collect()
}

/// Whether `node` sends a partial signature for request `id` within `timeout` (other messages are
/// skipped).
fn wait_partial(
    peer: &FakePeer,
    node: usize,
    id: &commonware_cryptography::sha256::Digest,
    timeout: Duration,
) -> bool {
    let end = Instant::now() + timeout;
    while Instant::now() < end {
        if let Some((from, wire::Message::Partial { request, .. })) =
            peer.recv(Duration::from_millis(50))
            && from == node
            && request == *id
        {
            return true;
        }
    }
    false
}

/// The first message from `node` about request `id` within `timeout`.
fn wait_message(
    peer: &FakePeer,
    node: usize,
    id: &commonware_cryptography::sha256::Digest,
    timeout: Duration,
) -> Option<wire::Message> {
    let end = Instant::now() + timeout;
    while Instant::now() < end {
        if let Some((from, message)) = peer.recv(Duration::from_millis(50)) {
            let about = match &message {
                wire::Message::Partial { request, .. } | wire::Message::Refused { request, .. } => {
                    request
                }
                wire::Message::Request(request) => &request.id,
            };
            if from == node && about == id {
                return Some(message);
            }
        }
    }
    None
}

/// A compressed G2 encoding of a point on the curve but outside the prime-order subgroup.
fn outside_subgroup() -> [u8; 96] {
    let mut rng = StdRng::seed_from_u64(1);
    loop {
        let mut bytes = [0u8; 96];
        rng.fill_bytes(&mut bytes);
        bytes[0] = (bytes[0] & 0x1f) | 0x80; // compressed, not infinity
        if bytes[0] & 0x1f >= 0x1a || bytes[48] >= 0x1a {
            continue; // coordinates must be below the field modulus
        }
        if let Ok(point) = EthSignature::from_bytes(&bytes)
            && point.validate(false).is_err()
        {
            return bytes;
        }
    }
}

/// C3/E6: a participant that is frozen (silent but connected), flaps, or restarts does not stop
/// the other three, and its late answers do not disturb finished requests.
#[test]
fn c3_e6_frozen_and_flapping_participant() {
    let (network, key) = network_with_key();
    let index_3 = index_of(&network, 3);

    network.freeze(3);
    for nonce in 0..5u64 {
        let start = Instant::now();
        let (status, body) = network.sign(0, KEY, nonce, root(nonce as u8));
        assert_eq!(status, 200, "{body}");
        assert!(!signers(&body).contains(&index_3));
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "{:?}",
            start.elapsed()
        );
    }
    let unsolicited = network.count(0, "unsolicited signing response");
    network.thaw(3);
    network.wait_until("late answers of node 3 to be dropped", || {
        network.count(0, "unsolicited signing response") > unsolicited
    });

    for round in 0..4u64 {
        network.freeze(3);
        let (status, body) = network.sign(1, KEY, 100 + round, root(0x10 + round as u8));
        assert_eq!(status, 200, "{body}");
        network.thaw(3);
        let (status, body) = network.sign(2, KEY, 200 + round, root(0x20 + round as u8));
        assert_eq!(status, 200, "{body}");
        assert!(ethereum_verify(
            &key,
            &root(0x20 + round as u8),
            &body["signature"]
        ));
    }
    for round in 0..2u64 {
        network.stop_node(3);
        let (status, body) = network.sign(0, KEY, 300 + round, root(0x30 + round as u8));
        assert_eq!(status, 200, "{body}");
        network.restart_node(3);
    }
    network.wait_for_ready(&[3]);
    for node in network.all() {
        network.wait_until(&format!("node {node} to apply every authorization"), || {
            network.status(node)["authorizations"] == 15
        });
    }
}

/// D1/D3: invalid encodings, an infinity point, a point outside the subgroup, truncated, oversized
/// and random messages, valid signatures of another payload or another ceremony, duplicates and
/// late or unknown responses: none counts; node 3's genuine partial does.
#[test]
fn d1_d3_malformed_and_duplicate_responses() {
    let (network, key) = network_with_key();
    network.start_dkg(0, "validator-002");
    network.wait_for_dkg("validator-002", &network.all());
    let (status, reference) = network.sign(0, KEY, 100, root(0xaa));
    assert_eq!(status, 200, "{reference}");
    wait_applied(&network, &network.all(), 100);
    let index_3 = index_of(&network, 3);

    // Node 2 is down, so node 0 needs node 3, now byzantine with its real shares of both keys.
    network.stop_node(2);
    network.stop_node(3);
    let outside = outside_subgroup();
    let mut noise = StdRng::seed_from_u64(2);
    let responder: Responder = Box::new(move |shares, from, message| {
        let wire::Message::Request(request) = message else {
            return Vec::new();
        };
        let partial = |message: &Message, share| message.partial_sign(share);
        let encode = |partial| {
            wire::Message::Partial {
                request: request.id,
                partial,
            }
            .encode()
            .to_vec()
        };
        let right = Message::Ethereum(request.payload_hash);
        let genuine = encode(partial(&right, &shares[0]));
        let with_point = |point: &[u8]| {
            let mut bytes = genuine.clone();
            let at = bytes.len() - 96;
            bytes[at..].copy_from_slice(point);
            bytes
        };
        let mut infinity = [0u8; 96];
        infinity[0] = 0xc0;
        let mut random = vec![0u8; 200];
        noise.fill_bytes(&mut random);
        [
            with_point(&[0u8; 96]),
            with_point(&infinity),
            with_point(&outside),
            genuine[..genuine.len() - 10].to_vec(),
            [genuine.clone(), vec![0; 7]].concat(),
            random,
            encode(partial(&Message::Ethereum(root(0xee)), &shares[0])),
            encode(partial(&right, &shares[1])),
            genuine.clone(),
            genuine,
            encode(partial(&Message::Ethereum(root(0xef)), &shares[0])),
        ]
        .into_iter()
        .map(|bytes| (from, bytes))
        .collect()
    });
    let peer = FakePeer::start(&network, 3, &[0, 1], responder);
    let probe = request(100, root(0xaa));
    let node_0_partial = ask(&network, &peer, 0, &probe);
    assert!(matches!(node_0_partial, wire::Message::Partial { .. }));

    let invalid = network.count(0, "invalid signing message");
    let rejected = network.count(0, "rejected partial signature");
    let ignored = network.count(0, "ignored signing response");
    // Node 1 is frozen, so the request stays open after node 3's genuine partial and the
    // duplicates that follow it are processed (and ignored) by the same request.
    network.freeze(1);
    let (status, signed) = std::thread::scope(|scope| {
        let signing = scope.spawn(|| network.sign(0, KEY, 100, root(0xaa)));
        network.wait_until("node 0 to log every rejection", || {
            network.count(0, "invalid signing message") >= invalid + 6
                && network.count(0, "rejected partial signature") >= rejected + 2
                && network.count(0, "ignored signing response") >= ignored + 2
        });
        network.thaw(1);
        signing.join().unwrap()
    });
    assert_eq!(status, 200, "{signed}");
    assert_eq!(signed["signature"], reference["signature"]);
    assert!(signers(&signed).contains(&index_3), "{signed}");
    assert!(ethereum_verify(&key, &root(0xaa), &signed["signature"]));

    // Responses for a finished request and for an unknown one are dropped.
    let unsolicited = network.count(0, "unsolicited signing response");
    peer.send(0, node_0_partial.encode().to_vec());
    let unknown = wire::Message::Refused {
        request: Request::id_of(&CeremonyId::new(KEY).unwrap(), 4242, &root(1)),
        reason: Refusal::Conflict,
    };
    peer.send(0, unknown.encode().to_vec());
    network.wait_until("node 0 to drop both", || {
        network.count(0, "unsolicited signing response") >= unsolicited + 2
    });
    assert_eq!(network.status(0)["signing_sessions"], 0);
}

/// D4: three invalid answers ban a participant for the request, even if it then sends its genuine
/// partial; honest participants still complete. A banned participant is not asked again (L-5).
#[test]
fn d4_strike_limit() {
    let (network, _) = network_with_key();
    let (status, reference) = network.sign(0, KEY, 100, root(0xaa));
    assert_eq!(status, 200, "{reference}");
    wait_applied(&network, &network.all(), 100);
    let index_3 = index_of(&network, 3);

    network.stop_node(3);
    let asked = Arc::new(AtomicUsize::new(0));
    let counter = asked.clone();
    let responder: Responder = Box::new(move |shares, from, message| {
        let wire::Message::Request(request) = message else {
            return Vec::new();
        };
        counter.fetch_add(1, Ordering::SeqCst);
        let encode = |partial| {
            wire::Message::Partial {
                request: request.id,
                partial,
            }
            .encode()
            .to_vec()
        };
        let mut out: Vec<_> = (0..3u8)
            .map(|i| {
                (
                    from,
                    encode(Message::Ethereum(root(0xe0 + i)).partial_sign(&shares[0])),
                )
            })
            .collect();
        out.push((
            from,
            encode(Message::Ethereum(request.payload_hash).partial_sign(&shares[0])),
        ));
        out
    });
    let peer = FakePeer::start(&network, 3, &[0], responder);
    assert!(matches!(
        ask(&network, &peer, 0, &request(100, root(0xaa))),
        wire::Message::Partial { .. }
    ));

    // Node 2 frozen: node 0 would need node 3, which banned itself. Node 0 asked it once: the
    // retransmissions of the next 5 seconds go to node 2 only.
    let ignored = network.count(0, "ignored signing response");
    network.freeze(2);
    let before = asked.load(Ordering::SeqCst);
    let (status, body) = network.sign(0, KEY, 100, root(0xaa));
    let during = asked.load(Ordering::SeqCst) - before;
    network.thaw(2);
    assert_eq!(status, 504, "{body}");
    assert_eq!(body["valid_partials"], 2);
    assert!(network.count(0, "ignored signing response") > ignored);
    assert_eq!(during, 1, "requests sent to the banned participant");

    let (status, signed) = network.sign(0, KEY, 100, root(0xaa));
    assert_eq!(status, 200, "{signed}");
    assert!(!signers(&signed).contains(&index_3));
    assert_eq!(signed["signature"], reference["signature"]);
}

/// D5/D6: replayed signing requests (before, during and after authorization, across coordinator and
/// full restarts) never create or change an authorization; requests and ids of one ceremony do not
/// work for another.
#[test]
fn d5_d6_replay_and_cross_ceremony() {
    let (network, key) = network_with_key();
    network.start_dkg(0, "validator-002");
    let key_2 = Value::String(network.wait_for_dkg("validator-002", &network.all()));
    network.stop_node(3);
    let silent: Responder = Box::new(|_, _, _| Vec::new());
    let peer = FakePeer::start(&network, 3, &[], silent);
    let a = request(500, root(0xaa));
    let b = request(500, root(0xbb));
    let count = |node| network.status(node)["authorizations"].clone();

    // Before.
    for _ in 0..3 {
        assert_eq!(
            ask(&network, &peer, 0, &a),
            wire::Message::Refused {
                request: a.id,
                reason: Refusal::NotAuthorized
            }
        );
    }
    assert_eq!(count(0), 0);

    // During: replays while node 1 coordinates the authorization.
    let (status, signed) = std::thread::scope(|scope| {
        let signing = scope.spawn(|| network.sign(1, KEY, 500, root(0xaa)));
        for _ in 0..20 {
            peer.send(0, wire::Message::Request(a.clone()).encode().to_vec());
            peer.send(0, wire::Message::Request(b.clone()).encode().to_vec());
            std::thread::sleep(Duration::from_millis(25));
        }
        signing.join().unwrap()
    });
    assert_eq!(status, 200, "{signed}");
    wait_applied(&network, &[0, 1, 2], 500);

    // After, after a coordinator restart, after a restart of every node.
    let check = |network: &TestNetwork| {
        assert!(matches!(
            ask(network, &peer, 0, &a),
            wire::Message::Partial { .. }
        ));
        assert_eq!(
            ask(network, &peer, 0, &b),
            wire::Message::Refused {
                request: b.id,
                reason: Refusal::Conflict
            }
        );
        for node in [0, 1, 2] {
            assert_eq!(network.status(node)["authorizations"], 1);
            let (_, body) = network.get(node, &format!("/authorizations/{KEY}/500"));
            assert_eq!(unhex(&body["payload_hash"]), root(0xaa));
        }
    };
    check(&network);
    network.restart_node(0);
    network.wait_for_ready(&[0]);
    check(&network);
    let (status, body) = network.sign(0, KEY, 500, root(0xbb));
    assert_eq!(status, 409, "{body}");
    for node in [0, 1, 2] {
        network.stop_node(node);
    }
    for node in [0, 1, 2] {
        network.restart_node(node);
    }
    network.wait_for_ready(&[0, 1, 2]);
    check(&network);

    // Another ceremony: same nonce, not authorized there; a request id of ceremony 1 relabelled
    // to ceremony 2 is inconsistent and dropped.
    let other = Request::new(CeremonyId::new("validator-002").unwrap(), 500, root(0xaa));
    assert_eq!(
        ask(&network, &peer, 0, &other),
        wire::Message::Refused {
            request: other.id,
            reason: Refusal::NotAuthorized
        }
    );
    let mut relabelled = a.clone();
    relabelled.ceremony = CeremonyId::new("validator-002").unwrap();
    peer.send(
        0,
        wire::Message::Request(relabelled.clone()).encode().to_vec(),
    );
    assert!(wait_message(&peer, 0, &relabelled.id, Duration::from_secs(2)).is_none());

    // Nonce 500 is free in ceremony 2: B can be signed there, with ceremony 2's key only.
    let (status, theirs) = network.sign(2, "validator-002", 500, root(0xbb));
    assert_eq!(status, 200, "{theirs}");
    assert!(ethereum_verify(&key_2, &root(0xbb), &theirs["signature"]));
    assert!(!ethereum_verify(&key, &root(0xbb), &theirs["signature"]));
}

/// E4/E5: one peer sends more unauthorized requests than its share of the parked queue (64 of
/// 256): it only evicts its own oldest ones (fairness between peers: `dkg::parked` unit tests).
/// Then expiry.
#[test]
fn e4_e5_parked_overflow_and_expiry() {
    let (network, _) = network_with_key();
    network.stop_node(3);
    let silent: Responder = Box::new(|_, _, _| Vec::new());
    let peer = FakePeer::start(&network, 3, &[], silent);
    ask(&network, &peer, 0, &request(9_999, root(0xaa)));
    let rss_before = network.rss_kib(0);

    for nonce in 10_000..10_300u64 {
        peer.send(
            0,
            wire::Message::Request(request(nonce, root(0xaa)))
                .encode()
                .to_vec(),
        );
    }
    network.wait_until("the peer's share of the parked queue to fill", || {
        network.status(0)["parked_requests"] == PER_PEER
    });
    let rss_full = network.rss_kib(0);

    // A request still parked is answered when its authorization arrives; the oldest ones were
    // dropped and are not; authorized requests are answered at once.
    let (status, _) = network.sign(1, KEY, 10_299, root(0xaa));
    assert_eq!(status, 200);
    assert!(wait_partial(
        &peer,
        0,
        &request(10_299, root(0xaa)).id,
        Duration::from_secs(10)
    ));
    let (status, _) = network.sign(1, KEY, 10_000, root(0xaa));
    assert_eq!(status, 200);
    assert!(!wait_partial(
        &peer,
        0,
        &request(10_000, root(0xaa)).id,
        Duration::from_secs(3)
    ));
    assert!(matches!(
        ask(&network, &peer, 0, &request(10_000, root(0xaa))),
        wire::Message::Partial { .. }
    ));

    // Parked requests expire after 16 blocks; an expired one is never answered with a partial.
    network.wait_until("parked requests to expire", || {
        network.status(0)["parked_requests"] == 0
    });
    let (status, _) = network.sign(1, KEY, 10_100, root(0xaa));
    assert_eq!(status, 200);
    assert!(!wait_partial(
        &peer,
        0,
        &request(10_100, root(0xaa)).id,
        Duration::from_secs(3)
    ));
    println!("e4: rss before {rss_before} KiB, with {PER_PEER} parked {rss_full} KiB");
}
