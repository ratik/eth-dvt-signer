//! E2E-7 to E2E-9: unauthorized signing requests, byzantine responses and a lagging signer, over
//! real authenticated p2p.

use crate::{
    KEY,
    harness::{
        TestNetwork, ethereum_verify,
        peer::{FakePeer, Responder},
        root,
    },
    signing::network_with_key,
};
use commonware_codec::Encode as _;
use commonware_cryptography::bls12381::primitives::variant::PartialSignature;
use commonware_utils::Participant;
use eth_dvt_signer::{
    dkg::{CeremonyId, signing::Message},
    signer::wire::{self, Refusal, Request},
};
use std::time::{Duration, Instant};

fn id(name: &str) -> CeremonyId {
    CeremonyId::new(name).unwrap()
}

pub fn index_of(network: &TestNetwork, id: usize) -> u32 {
    let (_, body) = network.get(id, &format!("/dkg/status/{KEY}"));
    body["participant_index"].as_u64().unwrap() as u32
}

pub fn wait_applied(network: &TestNetwork, nodes: &[usize], nonce: u64) {
    for &node in nodes {
        network.wait_until(&format!("authorization {nonce} on node {node}"), || {
            network
                .get(node, &format!("/authorizations/{KEY}/{nonce}"))
                .0
                == 200
        });
    }
}

pub fn request(nonce: u64, payload: [u8; 32]) -> Request {
    Request::new(id(KEY), nonce, payload)
}

/// Send `request` to `node` (again every second, while the connection comes up) until it answers;
/// return its answer.
pub fn ask(
    network: &TestNetwork,
    peer: &FakePeer,
    node: usize,
    request: &Request,
) -> wire::Message {
    let bytes = wire::Message::Request(request.clone()).encode().to_vec();
    // Answers to earlier requests are not answers to this one.
    while peer.recv(Duration::ZERO).is_some() {}
    let start = Instant::now();
    loop {
        peer.send(node, bytes.clone());
        let resend = Instant::now() + Duration::from_secs(1);
        while Instant::now() < resend {
            if let Some((from, message)) = peer.recv(Duration::from_millis(100)) {
                let answers = match &message {
                    wire::Message::Partial { request: id, .. }
                    | wire::Message::Refused { request: id, .. } => *id == request.id,
                    wire::Message::Request(_) => false,
                };
                if from == node && answers {
                    return message;
                }
            }
        }
        if start.elapsed() > Duration::from_secs(60) {
            network.fail(&format!("node {node} never answered {request:?}"));
        }
    }
}

/// Everything `node` sends about `request` within `window`.
pub fn answers_within(peer: &FakePeer, node: usize, request: &Request, window: Duration) -> usize {
    let end = Instant::now() + window;
    let mut count = 0;
    while Instant::now() < end {
        if let Some((from, wire::Message::Partial { request: id, .. })) =
            peer.recv(Duration::from_millis(100))
            && from == node
            && id == request.id
        {
            count += 1;
        }
    }
    count
}

/// E2E-7: a validly encoded, authenticated signing request is not an authorization.
#[test]
fn unauthorized_signing_requests_are_refused() {
    let (network, _) = network_with_key();
    let (status, body) = network.sign(0, KEY, 100, root(0xaa));
    assert_eq!(status, 200, "{body}");
    wait_applied(&network, &[0, 1, 2], 100);

    // A peer with node 3's identity (and real p2p credentials) asks the others directly.
    network.stop_node(3);
    let silent: Responder = Box::new(|_, _, _| Vec::new());
    let peer = FakePeer::start(&network, 3, &[], silent);

    for node in 0..3 {
        // Never authorized.
        let unauthorized = request(200, root(0xaa));
        assert_eq!(
            ask(&network, &peer, node, &unauthorized),
            wire::Message::Refused {
                request: unauthorized.id,
                reason: Refusal::NotAuthorized
            }
        );
        // Conflicts with the authorization of nonce 100.
        let conflicting = request(100, root(0xbb));
        assert_eq!(
            ask(&network, &peer, node, &conflicting),
            wire::Message::Refused {
                request: conflicting.id,
                reason: Refusal::Conflict
            }
        );
        // A request whose id does not match its fields gets no answer at all.
        let mut forged = request(100, root(0xaa));
        forged.payload_hash = root(0xbb);
        peer.send(
            node,
            wire::Message::Request(forged.clone()).encode().to_vec(),
        );

        // Positive control: the authorized request is signed, by the node's own share index.
        let authorized = request(100, root(0xaa));
        match ask(&network, &peer, node, &authorized) {
            wire::Message::Partial { partial, .. } => {
                assert_eq!(partial.index.get(), index_of(&network, node));
            }
            other => panic!("node {node} did not sign the authorized request: {other:?}"),
        }
        // No partial ever shows up for the refused or forged requests.
        for refused in [&unauthorized, &conflicting, &forged] {
            assert_eq!(
                answers_within(&peer, node, refused, Duration::from_secs(1)),
                0
            );
        }
    }
}

/// E2E-8: a byzantine participant floods the coordinator with bad partial signatures; only valid
/// ones count and the signature is the same as without it.
#[test]
fn byzantine_responses_never_count() {
    let (network, key) = network_with_key();
    let (status, reference) = network.sign(0, KEY, 100, root(0xaa));
    assert_eq!(status, 200, "{reference}");
    wait_applied(&network, &network.all(), 100);
    let victim = index_of(&network, 1);
    let index_3 = index_of(&network, 3);

    // Without node 2, node 0 needs node 3's partial; node 3 is now byzantine (with its real
    // share, loaded from its storage).
    network.stop_node(2);
    network.stop_node(3);
    let responder: Responder = Box::new(move |shares, from, message| {
        let wire::Message::Request(request) = message else {
            return Vec::new();
        };
        let share = &shares[0];
        let genuine = Message::Ethereum(request.payload_hash).partial_sign(share);
        let other_payload = Message::Ethereum(root(0xee)).partial_sign(share);
        let forged_index = PartialSignature {
            index: Participant::new(victim),
            value: genuine.value,
        };
        let other_ceremony = Request::id_for(
            &id("validator-002"),
            &request.authorization,
            &request.payload_hash,
        );
        let other_request = Request::id_of(&request.ceremony, 999, &request.payload_hash);
        let partial = |request, partial| {
            wire::Message::Partial { request, partial }
                .encode()
                .to_vec()
        };
        vec![
            (from, vec![0xde, 0xad, 0xbe, 0xef]),
            (from, partial(request.id, forged_index)),
            (from, partial(request.id, other_payload)),
            (from, partial(other_ceremony, genuine.clone())),
            (from, partial(other_request, genuine.clone())),
            (from, partial(request.id, genuine.clone())),
            (from, partial(request.id, genuine)),
        ]
    });
    let peer = FakePeer::start(&network, 3, &[0], responder);
    // Wait until the fake node is connected to node 0.
    let probe = request(100, root(0xaa));
    assert!(matches!(
        ask(&network, &peer, 0, &probe),
        wire::Message::Partial { .. }
    ));

    let rejected = network.count(0, "rejected partial signature");
    let (status, signed) = network.sign(0, KEY, 100, root(0xaa));
    assert_eq!(status, 200, "{signed}");
    assert_eq!(signed["signature"], reference["signature"]);
    assert!(ethereum_verify(&key, &root(0xaa), &signed["signature"]));
    let signers: Vec<u64> = signed["signers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|index| index.as_u64().unwrap())
        .collect();
    assert!(signers.contains(&(index_3 as u64)), "{signers:?}");

    // The forged index and the signature over another payload were rejected, the messages for
    // other requests were never delivered to this one, and garbage was dropped.
    network.wait_until("the coordinator's rejections in its log", || {
        network.count(0, "rejected partial signature") >= rejected + 2
    });
    assert!(network.count(0, "forged participant index") >= 1);
    assert!(network.count(0, "reason=\"invalid signature\"") >= 1);
    assert!(network.count(0, "unsolicited signing response") >= 2);
    assert!(network.count(0, "invalid signing message") >= 1);
}

/// E2E-9 / R4: a node that has not applied an authorization refuses to sign it, reports why it is
/// not ready and does not authorize, while the others go on; it signs once it catches up.
#[test]
fn lagging_signer_refuses_until_applied() {
    let (network, key) = network_with_key();
    let index_3 = index_of(&network, 3);

    // Node 3 stops applying finalized blocks (it keeps voting).
    let hold = network.dir.join("hold-3");
    network.restart_node_with(
        3,
        vec![(
            "ETH_MPC_SIGNER_HOLD_FILE".into(),
            hold.display().to_string(),
        )],
    );
    network.wait_for_ready(&[3]);
    std::fs::write(&hold, b"").unwrap();
    network.wait_until("node 3 to hold execution", || {
        network.count(3, "test hook: holding block execution") > 0
    });

    let (status, signed) = network.sign(0, KEY, 100, root(0xaa));
    assert_eq!(status, 200, "{signed}");
    let signers: Vec<u64> = signed["signers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|index| index.as_u64().unwrap())
        .collect();
    assert!(!signers.contains(&(index_3 as u64)));
    let (status, _) = network.get(3, &format!("/authorizations/{KEY}/100"));
    assert_eq!(status, 404, "node 3 has not applied the authorization");

    // It knows of finalized blocks it has not applied: it says so, and does not authorize.
    network.wait_until("node 3 to report its backlog", || {
        let readiness = network.readiness(3);
        readiness["state"] == "syncing"
            && readiness["reasons"]
                .as_array()
                .unwrap()
                .iter()
                .any(|reason| reason == "local_backlog")
            && readiness["known_finalized_height"].as_u64() > readiness["applied_height"].as_u64()
    });
    crate::rollback::assert_not_ready(&network, 3, "local_backlog");
    let (status, body) = network.sign(3, KEY, 101, root(0xbb));
    assert_eq!(status, 503, "{body}");
    assert_eq!(body["result"], "NOT_READY");
    assert_eq!(network.get(0, &format!("/authorizations/{KEY}/101")).0, 404);
    // The others are ready and keep authorizing.
    network.wait_for_ready(&[0, 1, 2]);
    let (status, other) = network.sign(1, KEY, 102, root(0xcc));
    assert_eq!(status, 200, "{other}");

    // With node 2 down, node 0 needs node 3, which refuses: not enough signers.
    network.stop_node(2);
    let (status, failed) = network.sign(0, KEY, 100, root(0xaa));
    assert_eq!(status, 504, "{failed}");
    assert_eq!(failed["result"], "SIGNING_TIMEOUT");
    assert_eq!(failed["valid_partials"], 2);
    assert_eq!(failed["refusals"][index_3.to_string()], "not_authorized");
    assert!(network.count(3, "not authorized here (yet)") > 0);

    // Node 3 catches up; the same request now succeeds with it, identically.
    std::fs::remove_file(&hold).unwrap();
    wait_applied(&network, &[3], 100);
    network.wait_for_ready(&[3]);
    let (status, again) = network.sign(0, KEY, 100, root(0xaa));
    assert_eq!(status, 200, "{again}");
    assert_eq!(again["signature"], signed["signature"]);
    assert!(ethereum_verify(&key, &root(0xaa), &again["signature"]));
}
