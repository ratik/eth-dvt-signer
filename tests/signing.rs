//! Consensus-authorized threshold signing over the simulated network: the coordinator, the
//! signing protocol and its failure cases, with Ethereum (blst) verification of every signature.

mod common;

use blst::{
    BLST_ERROR,
    min_pk::{PublicKey as EthPublicKey, Signature as EthSignature},
};
use common::{
    Cluster, Injector, RETENTION, complete_dkg, id, request, start_network, start_network_with,
    wait_for_height,
};
use commonware_codec::{DecodeExt as _, Encode as _};
use commonware_cryptography::{
    Signer as _,
    bls12381::primitives::variant::PartialSignature,
    ed25519::{PrivateKey, PublicKey},
    sha256::Digest,
};
use commonware_runtime::{Clock as _, IoBuf, Runner as _, deterministic};
use commonware_utils::ordered::Quorum as _;
use eth_dvt_signer::{
    dkg::{
        Variant,
        ceremony::Ceremony,
        signing::{self, ETHEREUM_DST, Message},
    },
    engine,
    signer::{
        coordinator::{AuthorizationKind, SignError, Signed},
        wire::{self, Refusal, Request},
    },
    types::Outcome,
};
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

const KEY: &str = "validator-001";

fn root(byte: u8) -> [u8; 32] {
    [byte; 32]
}

/// Verify like an Ethereum consensus client (blst, POP ciphersuite, subgroup checks).
fn ethereum_verify(key: &[u8], root: &[u8; 32], signature: &[u8]) -> bool {
    let Ok(key) = EthPublicKey::key_validate(key) else {
        return false;
    };
    let Ok(signature) = EthSignature::sig_validate(signature, true) else {
        return false;
    };
    signature.verify(true, root, ETHEREUM_DST, &[], &key, true) == BLST_ERROR::BLST_SUCCESS
}

async fn sign(cluster: &Cluster, via: usize, nonce: u64, byte: u8) -> Result<Signed, SignError> {
    cluster.signers[via].sign(request(KEY, nonce, byte)).await
}

/// Wait until node `node` has applied the authorization of `(KEY, nonce)`.
async fn wait_applied(
    context: &deterministic::Context,
    cluster: &Cluster,
    node: usize,
    nonce: u64,
) {
    while cluster.clients[node]
        .authorization(id(KEY), nonce)
        .await
        .unwrap()
        .authorization
        .is_none()
    {
        context.sleep(Duration::from_millis(50)).await;
    }
}

/// Partial signatures of every node for the authorized `(KEY, nonce, root)`.
async fn partials(
    context: &deterministic::Context,
    cluster: &Cluster,
    nonce: u64,
    byte: u8,
) -> Vec<PartialSignature<Variant>> {
    let mut out = Vec::new();
    for node in 0..cluster.dkg.len() {
        wait_applied(context, cluster, node, nonce).await;
        out.push(
            cluster.dkg[node]
                .partial(id(KEY), nonce, root(byte))
                .await
                .unwrap()
                .unwrap(),
        );
    }
    out
}

fn key_bytes(ceremony: &Ceremony) -> Vec<u8> {
    ceremony.public_key().unwrap().encode().to_vec()
}

#[test]
fn signs_ethereum_signing_roots() {
    deterministic::Runner::timed(Duration::from_secs(300)).start(|context| async move {
        let cluster = start_network(&context, RETENTION).await;

        // No ceremony yet.
        assert!(matches!(
            sign(&cluster, 0, 100, 0xa1).await,
            Err(SignError::UnknownCeremony)
        ));
        let ceremony = complete_dkg(&context, &cluster, KEY).await;
        let key = key_bytes(&ceremony);
        assert!(
            EthPublicKey::key_validate(&key).is_ok(),
            "valid Ethereum public key"
        );

        // New authorization, then signature.
        let signed = sign(&cluster, 0, 100, 0xa1).await.unwrap();
        assert_eq!(signed.kind, AuthorizationKind::New);
        assert_eq!(signed.signers.len(), 3);
        let signature = signed.signature.encode();
        assert_eq!(signature.len(), 96);
        assert!(ethereum_verify(&key, &root(0xa1), &signature));
        assert!(
            !ethereum_verify(&key, &root(0xa2), &signature),
            "another root"
        );

        // The identical request, through another node: no new authorization, same signature.
        let again = sign(&cluster, 2, 100, 0xa1).await.unwrap();
        assert_eq!(again.kind, AuthorizationKind::Existing);
        assert_eq!(again.authorization, signed.authorization);
        assert_eq!(again.signature, signed.signature);
        for client in &cluster.clients {
            assert_eq!(client.status().await.unwrap().authorizations, 1);
        }

        // Any 3 of the 4 partials recover the same signature (no private key involved).
        let all = partials(&context, &cluster, 100, 0xa1).await;
        let output = ceremony.output.as_ref().unwrap();
        for subset in [[0, 1, 2], [0, 1, 3], [0, 2, 3], [1, 2, 3]] {
            let recovered =
                signing::recover(output.public(), subset.iter().map(|&i| &all[i])).unwrap();
            assert_eq!(recovered, signed.signature);
        }

        // A second ceremony has another key: its signature of the same root does not verify
        // under the first key.
        let other = complete_dkg(&context, &cluster, "validator-002").await;
        let theirs = cluster.signers[1]
            .sign(request("validator-002", 100, 0xa1))
            .await
            .unwrap();
        assert!(ethereum_verify(
            &key_bytes(&other),
            &root(0xa1),
            &theirs.signature.encode()
        ));
        assert!(!ethereum_verify(
            &key,
            &root(0xa1),
            &theirs.signature.encode()
        ));
        assert_ne!(theirs.signature, signed.signature);
    });
}

#[test]
fn concurrent_identical_requests_share_one_authorization() {
    deterministic::Runner::timed(Duration::from_secs(300)).start(|context| async move {
        let cluster = start_network(&context, RETENTION).await;
        complete_dkg(&context, &cluster, KEY).await;

        let (a, b) = futures::join!(sign(&cluster, 0, 7, 0x77), sign(&cluster, 3, 7, 0x77));
        let (a, b) = (a.unwrap(), b.unwrap());
        assert_eq!(a.signature, b.signature);
        assert_eq!(a.authorization, b.authorization);
        let new = [a.kind, b.kind]
            .into_iter()
            .filter(|kind| *kind == AuthorizationKind::New)
            .count();
        assert!(new <= 1, "at most one request creates the authorization");
        for client in &cluster.clients {
            assert_eq!(client.status().await.unwrap().authorizations, 1);
        }
    });
}

#[test]
fn conflicting_requests_cannot_both_be_signed() {
    deterministic::Runner::timed(Duration::from_secs(300)).start(|context| async move {
        let cluster = start_network(&context, RETENTION).await;
        let ceremony = complete_dkg(&context, &cluster, KEY).await;

        let (a, b) = futures::join!(sign(&cluster, 0, 100, 0xaa), sign(&cluster, 3, 100, 0xbb));
        let (winner, loser, signed) = match (a, b) {
            (Ok(signed), Err(SignError::Conflict(authorization))) => {
                assert_eq!(authorization.payload_hash, root(0xaa));
                (0xaa, 0xbb, signed)
            }
            (Err(SignError::Conflict(authorization)), Ok(signed)) => {
                assert_eq!(authorization.payload_hash, root(0xbb));
                (0xbb, 0xaa, signed)
            }
            other => panic!("expected one signature and one conflict: {other:?}"),
        };
        assert!(ethereum_verify(
            &key_bytes(&ceremony),
            &root(winner),
            &signed.signature.encode()
        ));

        // No node signs the losing payload, whoever asks and however.
        for node in 0..4 {
            wait_applied(&context, &cluster, node, 100).await;
            assert_eq!(
                cluster.dkg[node]
                    .partial(id(KEY), 100, root(loser))
                    .await
                    .unwrap(),
                Err(Refusal::Conflict)
            );
            assert!(matches!(
                sign(&cluster, node, 100, loser).await,
                Err(SignError::Conflict(_))
            ));
        }
        let receipt = cluster.clients[1]
            .submit(request(KEY, 100, loser))
            .await
            .unwrap();
        assert_eq!(receipt.outcome, Outcome::Rejected);
    });
}

#[test]
fn authorization_outlives_its_coordinator() {
    deterministic::Runner::timed(Duration::from_secs(300)).start(|context| async move {
        let cluster = start_network(&context, RETENTION).await;
        complete_dkg(&context, &cluster, KEY).await;

        // A coordinator that died right after the authorization: consensus decided, nobody signed.
        let receipt = cluster.clients[0]
            .submit(request(KEY, 5, 0x55))
            .await
            .unwrap();
        assert_eq!(receipt.outcome, Outcome::Accepted);

        // Another one picks it up without a new authorization.
        let signed = sign(&cluster, 1, 5, 0x55).await.unwrap();
        assert_eq!(signed.kind, AuthorizationKind::Existing);
        assert_eq!(signed.authorization.height, receipt.height);

        // A coordinator that died holding two partials: they are simply produced again.
        let lost = partials(&context, &cluster, 5, 0x55).await;
        let retried = sign(&cluster, 2, 5, 0x55).await.unwrap();
        assert_eq!(retried.signature, signed.signature);
        assert_eq!(partials(&context, &cluster, 5, 0x55).await, lost);
    });
}

#[test]
fn signs_with_one_node_offline_and_lagging_node_catches_up() {
    deterministic::Runner::timed(Duration::from_secs(600)).start(|context| async move {
        let cluster = start_network(&context, RETENTION).await;
        let ceremony = complete_dkg(&context, &cluster, KEY).await;
        let key = key_bytes(&ceremony);
        let index_of = |node: usize| {
            ceremony
                .config
                .participants
                .index(&cluster.keys[node])
                .unwrap()
                .get()
        };

        // Node 3 is unreachable: consensus and signing go on with the other three.
        cluster.disconnect(3).await;
        let signed = sign(&cluster, 0, 1, 0x01).await.unwrap();
        assert_eq!(signed.kind, AuthorizationKind::New);
        assert!(!signed.signers.contains(&index_of(3)));
        assert!(ethereum_verify(
            &key,
            &root(0x01),
            &signed.signature.encode()
        ));

        // It has not applied the authorization, so it refuses to sign it.
        assert_eq!(
            cluster.dkg[3]
                .partial(id(KEY), 1, root(0x01))
                .await
                .unwrap(),
            Err(Refusal::NotAuthorized)
        );

        // Back online, it catches up, then signs; and it can replace another node.
        cluster.connect(3).await;
        wait_applied(&context, &cluster, 3, 1).await;
        let partial = cluster.dkg[3]
            .partial(id(KEY), 1, root(0x01))
            .await
            .unwrap()
            .unwrap();
        Message::Ethereum(root(0x01))
            .verify_partial(ceremony.output.as_ref().unwrap().public(), &partial)
            .unwrap();
        cluster.disconnect(0).await;
        let signed = sign(&cluster, 3, 2, 0x02).await.unwrap();
        assert!(signed.signers.contains(&index_of(3)));
        assert!(ethereum_verify(
            &key,
            &root(0x02),
            &signed.signature.encode()
        ));
    });
}

#[test]
fn state_and_shares_survive_a_full_restart() {
    let ((key, first), checkpoint) = deterministic::Runner::timed(Duration::from_secs(300))
        .start_and_recover(|context| async move {
            let cluster = start_network(&context, RETENTION).await;
            let ceremony = complete_dkg(&context, &cluster, KEY).await;
            let signed = sign(&cluster, 0, 1, 0x0a).await.unwrap();
            assert!(matches!(
                sign(&cluster, 1, 1, 0x0b).await,
                Err(SignError::Conflict(_))
            ));
            (key_bytes(&ceremony), signed.signature.encode().to_vec())
        });

    deterministic::Runner::from(checkpoint).start(|context| async move {
        let cluster = start_network(&context, RETENTION).await;
        let ceremony = cluster.dkg[2].ceremony(id(KEY)).await.unwrap().unwrap();
        assert_eq!(key_bytes(&ceremony), key, "group key unchanged");

        // The old authorization still signs (the same signature), the conflict is still rejected,
        // and new requests work.
        let again = sign(&cluster, 3, 1, 0x0a).await.unwrap();
        assert_eq!(again.kind, AuthorizationKind::Existing);
        assert_eq!(again.signature.encode().to_vec(), first);
        assert!(matches!(
            sign(&cluster, 2, 1, 0x0b).await,
            Err(SignError::Conflict(_))
        ));
        // New authorizations wait until the node follows consensus again (a block applied since
        // the restart).
        let restarted_at = cluster.clients[1].status().await.unwrap().height;
        wait_for_height(&context, &cluster.clients, restarted_at + 1).await;
        let new = sign(&cluster, 1, 2, 0x0c).await.unwrap();
        assert_eq!(new.kind, AuthorizationKind::New);
        assert!(ethereum_verify(&key, &root(0x0c), &new.signature.encode()));
    });
}

/// Node 3's partial over another payload, the share index it pretends to have, another request.
type Ammunition = (PartialSignature<Variant>, u32, Digest);

#[test]
fn invalid_partial_signatures_never_count() {
    deterministic::Runner::timed(Duration::from_secs(600)).start(|context| async move {
        // Node 3 answers node 0's signing requests with garbage, a forged index, a valid
        // signature over another payload, responses for other requests and duplicates, before
        // its genuine partial.
        let byzantine = PrivateKey::from_seed(3).public_key();
        let ammunition: Arc<Mutex<Option<Ammunition>>> = Arc::default();
        let cluster = start_network_with(&context, RETENTION, |node, channel| {
            if node != 0 || channel != engine::SIGNING_CHANNEL {
                return None;
            }
            let byzantine = byzantine.clone();
            let ammunition = ammunition.clone();
            let injector: Injector = Box::new(move |from: &PublicKey, message: IoBuf| {
                let Ok(wire::Message::Partial { request, partial }) =
                    wire::Message::decode(message.clone())
                else {
                    return vec![message];
                };
                let Some((other_payload, victim, other_request)) =
                    ammunition.lock().unwrap().clone()
                else {
                    return vec![message];
                };
                if *from != byzantine {
                    return vec![message];
                }
                let forged_index = PartialSignature {
                    index: commonware_utils::Participant::new(victim),
                    value: partial.value,
                };
                let encode = |message: wire::Message| IoBuf::from(message.encode());
                vec![
                    IoBuf::from(vec![1, 2, 3]),
                    encode(wire::Message::Partial {
                        request,
                        partial: forged_index,
                    }),
                    encode(wire::Message::Partial {
                        request,
                        partial: other_payload,
                    }),
                    encode(wire::Message::Partial {
                        request: other_request,
                        partial: partial.clone(),
                    }),
                    encode(wire::Message::Refused {
                        request,
                        reason: Refusal::Conflict,
                    }),
                    message.clone(),
                    message,
                ]
            });
            Some(injector)
        })
        .await;
        let ceremony = complete_dkg(&context, &cluster, KEY).await;
        let victim = ceremony
            .config
            .participants
            .index(&cluster.keys[1])
            .unwrap()
            .get();

        // A valid partial of node 3 over another (authorized) payload.
        cluster.clients[0]
            .submit(request(KEY, 2, 0xbb))
            .await
            .unwrap();
        let other = partials(&context, &cluster, 2, 0xbb).await[3].clone();
        let other_request = Request::id_of(&id("validator-002"), 1, &root(0xaa));
        ammunition
            .lock()
            .unwrap()
            .replace((other, victim, other_request));

        // Reference: the signature from nodes 0, 1, 2.
        cluster.clients[0]
            .submit(request(KEY, 1, 0xaa))
            .await
            .unwrap();
        let honest = partials(&context, &cluster, 1, 0xaa).await;
        let expected =
            signing::recover(ceremony.output.as_ref().unwrap().public(), &honest[..3]).unwrap();

        // Node 2 is out of reach, so node 0 needs node 3's partial: only the genuine one counts.
        cluster.disconnect(2).await;
        let signed = sign(&cluster, 0, 1, 0xaa).await.unwrap();
        let index_of_3 = ceremony
            .config
            .participants
            .index(&byzantine)
            .unwrap()
            .get();
        assert!(signed.signers.contains(&index_of_3));
        assert_eq!(signed.signature, expected);
        assert!(ethereum_verify(
            &key_bytes(&ceremony),
            &root(0xaa),
            &signed.signature.encode()
        ));
    });
}

#[test]
fn signing_requests_authorize_nothing() {
    deterministic::Runner::timed(Duration::from_secs(300)).start(|context| async move {
        let cluster = start_network(&context, RETENTION).await;
        complete_dkg(&context, &cluster, KEY).await;
        sign(&cluster, 0, 1, 0xaa).await.unwrap();

        // Every gate of the signer, as a network request would hit it.
        for node in 0..4 {
            let dkg = &cluster.dkg[node];
            wait_applied(&context, &cluster, node, 1).await;
            assert_eq!(
                dkg.partial(id(KEY), 2, root(0xaa)).await.unwrap(),
                Err(Refusal::NotAuthorized)
            );
            assert_eq!(
                dkg.partial(id(KEY), 1, root(0xbb)).await.unwrap(),
                Err(Refusal::Conflict)
            );
            assert_eq!(
                dkg.partial(id("nope"), 1, root(0xaa)).await.unwrap(),
                Err(Refusal::UnknownCeremony)
            );
            assert!(dkg.partial(id(KEY), 1, root(0xaa)).await.unwrap().is_ok());
        }
        // A request id that does not match its fields is rejected outright.
        let mut forged = Request::new(id(KEY), 1, root(0xaa));
        forged.payload_hash = root(0xbb);
        assert!(!forged.is_consistent());
    });
}

/// Answers of the misbehaving `nodes` to node 0's partial-signature requests: a final refusal, then
/// three partials claiming another participant's index (three strikes), never the genuine one.
fn misbehave(
    cluster_keys: Vec<PublicKey>,
    liars: Vec<usize>,
) -> impl FnMut(usize, u64) -> Option<Injector> {
    move |node, channel| {
        if node != 0 || channel != engine::SIGNING_CHANNEL {
            return None;
        }
        let liars: Vec<PublicKey> = liars.iter().map(|&i| cluster_keys[i].clone()).collect();
        let injector: Injector = Box::new(move |from: &PublicKey, message: IoBuf| {
            let Ok(wire::Message::Partial { request, partial }) =
                wire::Message::decode(message.clone())
            else {
                return vec![message];
            };
            if !liars.contains(from) {
                return vec![message];
            }
            let encode = |message: wire::Message| IoBuf::from(message.encode());
            let mut out = vec![encode(wire::Message::Refused {
                request,
                reason: Refusal::Conflict,
            })];
            for victim in 0..3u32 {
                let forged = PartialSignature {
                    index: commonware_utils::Participant::new(
                        (partial.index.get() + 1 + victim) % 4,
                    ),
                    value: partial.value,
                };
                out.push(encode(wire::Message::Partial {
                    request,
                    partial: forged,
                }));
            }
            out
        });
        Some(injector)
    }
}

/// Audit B-1: one byzantine participant answering with a final refusal *and* three invalid partials
/// must count as one lost participant, not two: signing then waits for the honest node that is
/// briefly unreachable instead of giving up.
#[test]
fn one_byzantine_participant_cannot_abort_signing() {
    deterministic::Runner::timed(Duration::from_secs(600)).start(|context| async move {
        let keys: Vec<PublicKey> = (0..4)
            .map(|i| PrivateKey::from_seed(i).public_key())
            .collect();
        let cluster = start_network_with(&context, RETENTION, misbehave(keys, vec![3])).await;
        let ceremony = complete_dkg(&context, &cluster, KEY).await;
        let receipt = cluster.clients[0]
            .submit(request(KEY, 1, 0xaa))
            .await
            .unwrap();
        assert_eq!(receipt.outcome, Outcome::Accepted);

        // Node 2 is unreachable for the first second of the signing.
        cluster.disconnect(2).await;
        let (signed, ()) = futures::join!(sign(&cluster, 0, 1, 0xaa), async {
            context.sleep(Duration::from_secs(1)).await;
            cluster.connect(2).await;
        });
        let signed = signed.expect("three honest signers are available");
        let index = |node: usize| {
            ceremony
                .config
                .participants
                .index(&cluster.keys[node])
                .unwrap()
                .get()
        };
        let mut expected = vec![index(0), index(1), index(2)];
        expected.sort();
        assert_eq!(signed.signers, expected);
        assert!(ethereum_verify(
            &key_bytes(&ceremony),
            &root(0xaa),
            &signed.signature.encode()
        ));
    });
}

/// Audit B-2: with three misbehaving participants signing is impossible, and the coordinator must
/// say so (and release its resources) rather than fail in another way.
#[test]
fn too_many_byzantine_participants_fail_cleanly() {
    deterministic::Runner::timed(Duration::from_secs(600)).start(|context| async move {
        let keys: Vec<PublicKey> = (0..4)
            .map(|i| PrivateKey::from_seed(i).public_key())
            .collect();
        let cluster = start_network_with(&context, RETENTION, misbehave(keys, vec![1, 2, 3])).await;
        complete_dkg(&context, &cluster, KEY).await;
        cluster.clients[0]
            .submit(request(KEY, 1, 0xaa))
            .await
            .unwrap();
        for node in 1..4 {
            wait_applied(&context, &cluster, node, 1).await;
        }

        let result = sign(&cluster, 0, 1, 0xaa).await;
        assert!(
            matches!(result, Err(SignError::InsufficientSigners { valid: 1, .. })),
            "{result:?}"
        );
        assert_eq!(cluster.signers[0].stats().in_flight, 0, "request released");
        assert_eq!(cluster.signers[0].stats().sessions, 0, "session released");
    });
}
