//! Distributed key generation end to end: four full nodes run ceremonies over the simulated network,
//! then use their shares for threshold BLS signatures.

mod common;

use blst::{
    BLST_ERROR,
    min_pk::{PublicKey as EthPublicKey, Signature as EthSignature},
};
use common::{
    Cluster, Injector, RETENTION, request, start_network, start_network_with, tear_newest_copy,
};
use commonware_codec::{DecodeExt as _, Encode as _};
use commonware_cryptography::{
    Signer as _,
    bls12381::{
        dkg::feldman_desmedt::{Dealer, DealerPrivMsg, Output, Player},
        primitives::{Error as BlsError, group::Scalar, variant::PartialSignature},
    },
    ed25519::{PrivateKey, PublicKey},
};
use commonware_math::algebra::Random as _;
use commonware_runtime::{Clock as _, IoBuf, Runner as _, Supervisor as _, deterministic};
use eth_mpc_signer::{
    dkg::{
        CeremonyId, DkgStatus, Faults, Unsupported, Variant,
        actor::ShareStatus,
        ceremony::{Ceremony, StartOutcome},
        secrets::Secrets,
        signing::{self, ETHEREUM_DST, Message},
        wire,
    },
    engine,
    signer::wire::Refusal,
    types::{Outcome, SignRequest},
};
use futures::future::join_all;
use rand::{SeedableRng as _, rngs::StdRng};
use std::{
    collections::BTreeSet,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

/// An Ethereum signing root (any 32 bytes: the protocol does not care what it commits to).
const ROOT: [u8; 32] = [0x56; 32];
const MESSAGE: Message = Message::Ethereum(ROOT);

fn id(name: &str) -> CeremonyId {
    CeremonyId::new(name).unwrap()
}

/// Start `name` through node `via` with the default configuration.
async fn start(cluster: &Cluster, via: usize, name: &str) -> StartOutcome {
    let dkg = &cluster.dkg[via];
    dkg.start(dkg.config(id(name)), false)
        .await
        .unwrap()
        .outcome
}

/// Wait until the given nodes see the ceremony with `status` and, once completed, have settled
/// their share. Returns each node's view.
async fn wait_for(
    context: &deterministic::Context,
    cluster: &Cluster,
    nodes: &[usize],
    name: &str,
    status: DkgStatus,
) -> Vec<Ceremony> {
    let mut views = Vec::new();
    for &node in nodes {
        loop {
            let dkg = &cluster.dkg[node];
            if let Some(ceremony) = dkg.ceremony(id(name)).await.unwrap()
                && ceremony.status == status
                && (status != DkgStatus::Completed
                    || dkg.share(id(name)).await.unwrap() != ShareStatus::Pending)
            {
                views.push(ceremony);
                break;
            }
            context.sleep(Duration::from_millis(100)).await;
        }
    }
    views
}

/// Partial signatures of `root` by the given nodes, under the authorization `(name, nonce)`.
/// Consensus decides the authorization first (through the first node); each node signs once it
/// has applied it.
async fn partials(
    context: &deterministic::Context,
    cluster: &Cluster,
    nodes: &[usize],
    name: &str,
    nonce: u64,
    root: [u8; 32],
) -> Vec<PartialSignature<Variant>> {
    let request = SignRequest {
        ceremony: id(name),
        nonce,
        payload_hash: root,
    };
    let receipt = cluster.clients[nodes[0]].submit(request).await.unwrap();
    assert!(
        matches!(
            receipt.outcome,
            Outcome::Accepted | Outcome::AlreadyAccepted
        ),
        "{receipt:?}"
    );
    let mut out = Vec::new();
    for &node in nodes {
        loop {
            match cluster.dkg[node]
                .partial(id(name), nonce, root)
                .await
                .unwrap()
            {
                Ok(partial) => {
                    out.push(partial);
                    break;
                }
                Err(Refusal::NotAuthorized) => context.sleep(Duration::from_millis(50)).await,
                Err(refusal) => panic!("node {node} refused: {refusal}"),
            }
        }
    }
    out
}

/// Recover a group signature from `partials` and check it against the group key.
fn recover_and_verify(
    output: &Output<Variant, PublicKey>,
    partials: &[&PartialSignature<Variant>],
    message: Message,
) -> Result<signing::Signature, BlsError> {
    let signature = signing::recover(output.public(), partials.iter().copied())?;
    message.verify(output.public().public(), &signature)?;
    Ok(signature)
}

/// Verify like an Ethereum consensus client: blst, minimal-pubkey-size, the POP ciphersuite DST,
/// key and signature subgroup checks.
fn ethereum_verify(key: &[u8], root: &[u8; 32], signature: &[u8]) -> BLST_ERROR {
    let key = match EthPublicKey::key_validate(key) {
        Ok(key) => key,
        Err(err) => return err,
    };
    let signature = match EthSignature::sig_validate(signature, true) {
        Ok(signature) => signature,
        Err(err) => return err,
    };
    signature.verify(true, root, ETHEREUM_DST, &[], &key, true)
}

#[test]
fn dkg_produces_a_threshold_key() {
    deterministic::Runner::timed(Duration::from_secs(300)).start(|context| async move {
        let cluster = start_network(&context, RETENTION).await;

        // Nothing can be authorized before the key exists.
        let receipt = cluster.clients[0]
            .submit(request("validator-001", 1, 0x56))
            .await
            .unwrap();
        assert_eq!(receipt.outcome, Outcome::UnknownCeremony);

        assert_eq!(
            start(&cluster, 1, "validator-001").await,
            StartOutcome::Started(0)
        );
        let views = wait_for(
            &context,
            &cluster,
            &[0, 1, 2, 3],
            "validator-001",
            DkgStatus::Completed,
        )
        .await;

        // Every node reports the same group key and public polynomial.
        let output = views[0].output.clone().unwrap();
        for view in &views {
            assert_eq!(view.output.as_ref(), Some(&output));
            assert_eq!(view.config.threshold, 3);
            assert_eq!(view.config.participants.len(), 4);
        }
        assert_eq!(output.public().required(), 3);
        assert!(output.revealed().is_empty(), "no share was revealed");

        // Every node holds a different, valid share (checked through its partial signature: the
        // shares themselves never leave the nodes).
        for dkg in &cluster.dkg {
            assert_eq!(
                dkg.share(id("validator-001")).await.unwrap(),
                ShareStatus::Stored
            );
        }
        let all = partials(&context, &cluster, &[0, 1, 2, 3], "validator-001", 1, ROOT).await;
        let indices: BTreeSet<u32> = all.iter().map(|partial| partial.index.get()).collect();
        assert_eq!(indices.len(), 4);
        let mut partial_publics = BTreeSet::new();
        for partial in &all {
            MESSAGE
                .verify_partial(output.public(), partial)
                .expect("partial signature verifies against its share's public key");
            partial_publics.insert(
                output
                    .public()
                    .partial_public(partial.index)
                    .unwrap()
                    .encode(),
            );
        }
        assert_eq!(partial_publics.len(), 4);

        // Any three participants produce the same valid group signature. Recovery only uses the
        // public partial signatures and the public polynomial: no private key is reconstructed.
        let mut signatures = BTreeSet::new();
        for combination in [[0, 1, 2], [0, 1, 3], [0, 2, 3], [1, 2, 3]] {
            let selected: Vec<_> = combination.iter().map(|&i| &all[i]).collect();
            let signature = recover_and_verify(&output, &selected, MESSAGE).unwrap();
            signatures.insert(signature.encode());
        }
        assert_eq!(signatures.len(), 1);

        // An Ethereum client accepts the group key and the group signature as they are encoded.
        let key = output.public().public().encode();
        let signature = signatures.first().unwrap();
        assert_eq!((key.len(), signature.len()), (48, 96));
        let Message::Ethereum(root) = MESSAGE else {
            unreachable!()
        };
        assert_eq!(
            ethereum_verify(&key, &root, signature),
            BLST_ERROR::BLST_SUCCESS
        );
        assert_ne!(
            ethereum_verify(&key, &[0x57; 32], signature),
            BLST_ERROR::BLST_SUCCESS
        );

        // Two participants cannot: recovery refuses, and passing one partial off as the missing
        // third participant's yields a signature that does not verify.
        assert!(matches!(
            signing::recover(output.public(), &all[..2]),
            Err(BlsError::NotEnoughPartialSignatures(3, 2))
        ));
        let forged = PartialSignature {
            index: all[2].index,
            value: all[0].value,
        };
        assert!(recover_and_verify(&output, &[&all[0], &all[1], &forged], MESSAGE).is_err());

        // An invalid partial signature is rejected.
        assert!(MESSAGE.verify_partial(output.public(), &forged).is_err());

        // A partial signature over another message cannot be substituted.
        let other = partials(&context, &cluster, &[2], "validator-001", 2, [0x57; 32]).await;
        assert!(MESSAGE.verify_partial(output.public(), &other[0]).is_err());
        assert!(recover_and_verify(&output, &[&all[0], &all[1], &other[0]], MESSAGE).is_err());

        // Nothing is signed without an authorization, or for another payload.
        assert_eq!(
            cluster.dkg[0]
                .partial(id("unknown"), 1, ROOT)
                .await
                .unwrap(),
            Err(Refusal::UnknownCeremony)
        );
        assert_eq!(
            cluster.dkg[0]
                .partial(id("validator-001"), 3, ROOT)
                .await
                .unwrap(),
            Err(Refusal::NotAuthorized)
        );
        assert_eq!(
            cluster.dkg[0]
                .partial(id("validator-001"), 1, [0x57; 32])
                .await
                .unwrap(),
            Err(Refusal::Conflict)
        );

        let again = cluster.clients[3]
            .submit(request("validator-001", 1, 0x56))
            .await
            .unwrap();
        assert_eq!(again.outcome, Outcome::AlreadyAccepted);
    });
}

#[test]
fn late_dealer_log_changes_nothing() {
    deterministic::Runner::timed(Duration::from_secs(300)).start(|context| async move {
        let cluster = start_network(&context, RETENTION).await;
        assert_eq!(start(&cluster, 0, "late").await, StartOutcome::Started(0));
        let views = wait_for(
            &context,
            &cluster,
            &[0, 1, 2, 3],
            "late",
            DkgStatus::Completed,
        )
        .await;
        let completed = views[0].clone();
        let output = completed.output.clone().unwrap();
        assert_eq!(output.dealers().len(), 3);

        // The dealer left out of the key collected every acknowledgement, but its log reaches
        // consensus only now. It is a valid log: right dealer, right ceremony, all four acks.
        let signers: Vec<PrivateKey> = (0..4).map(PrivateKey::from_seed).collect();
        let late = signers
            .iter()
            .find(|signer| output.dealers().position(&signer.public_key()).is_none())
            .unwrap();
        let info = completed.info();
        let mut rng = StdRng::seed_from_u64(7);
        let (mut dealer, commitment, dealings) = Dealer::<Variant, PrivateKey>::start::<Faults>(
            &mut rng,
            info.clone(),
            late.clone(),
            None,
        )
        .unwrap();
        for (player_key, dealing) in dealings {
            let signer = signers
                .iter()
                .find(|signer| signer.public_key() == player_key)
                .unwrap();
            let mut player =
                Player::<Variant, PrivateKey>::new(info.clone(), signer.clone()).unwrap();
            let ack = player
                .dealer_message::<Faults>(late.public_key(), commitment.clone(), dealing)
                .unwrap()
                .unwrap();
            dealer.receive_player_ack(player_key, ack).unwrap();
        }
        let log = dealer.finalize::<Faults>();
        assert!(log.clone().check(&info).is_some());

        let height = cluster.clients[1].status().await.unwrap().height;
        cluster.dkg[1].submit_log(completed.round, log).unwrap();

        // Wait until every node has finalized and executed it (it left every mempool).
        for client in &cluster.clients {
            loop {
                let status = client.status().await.unwrap();
                if status.mempool == 0 && status.height > height + 1 {
                    break;
                }
                context.sleep(Duration::from_millis(100)).await;
            }
        }

        // Same key, same commitments, same record on every node; shares unaffected.
        for dkg in &cluster.dkg {
            let view = dkg.ceremony(id("late")).await.unwrap().unwrap();
            assert_eq!(view, completed);
            assert!(
                view.output
                    .unwrap()
                    .dealers()
                    .position(&late.public_key())
                    .is_none()
            );
            assert_eq!(dkg.share(id("late")).await.unwrap(), ShareStatus::Stored);
        }
        let all = partials(&context, &cluster, &[0, 1, 2, 3], "late", 1, ROOT).await;
        for partial in &all {
            MESSAGE.verify_partial(output.public(), partial).unwrap();
        }
        recover_and_verify(&output, &[&all[3], &all[1], &all[0]], MESSAGE).unwrap();
    });
}

#[test]
fn duplicate_requests_start_one_ceremony() {
    deterministic::Runner::timed(Duration::from_secs(300)).start(|context| async move {
        let cluster = start_network(&context, RETENTION).await;

        // The same request through every node at once.
        let outcomes = join_all((0..4).map(|via| start(&cluster, via, "validator-001"))).await;
        let started = outcomes
            .iter()
            .filter(|outcome| **outcome == StartOutcome::Started(0))
            .count();
        let existing = outcomes
            .iter()
            .filter(|outcome| **outcome == StartOutcome::Exists(0))
            .count();
        assert_eq!((started, existing), (1, 3), "{outcomes:?}");

        let views = wait_for(
            &context,
            &cluster,
            &[0, 1, 2, 3],
            "validator-001",
            DkgStatus::Completed,
        )
        .await;
        let key = views[0].public_key().cloned().unwrap();

        // Repeating it later changes nothing: no new ceremony, no new randomness.
        assert_eq!(
            start(&cluster, 2, "validator-001").await,
            StartOutcome::Exists(0)
        );
        let view = cluster.dkg[3]
            .ceremony(id("validator-001"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(view.public_key(), Some(&key));

        // Only one round was used: the next ceremony is round 1.
        assert_eq!(
            start(&cluster, 0, "validator-002").await,
            StartOutcome::Started(1)
        );
    });
}

#[test]
fn conflicting_ceremony_is_rejected() {
    deterministic::Runner::timed(Duration::from_secs(300)).start(|context| async move {
        let cluster = start_network(&context, RETENTION).await;
        let dkg = &cluster.dkg[0];
        assert_eq!(
            start(&cluster, 0, "validator-001").await,
            StartOutcome::Started(0)
        );

        // Same id, different parameters: rejected by consensus, whichever node submits it.
        let mut threshold = dkg.config(id("validator-001"));
        threshold.threshold = 2;
        assert_eq!(
            cluster.dkg[1]
                .start(threshold.clone(), false)
                .await
                .unwrap()
                .outcome,
            StartOutcome::Conflict(0)
        );
        let mut version = dkg.config(id("validator-001"));
        version.version = 2;
        assert_eq!(
            cluster.dkg[2].start(version, false).await.unwrap().outcome,
            StartOutcome::Conflict(0)
        );
        let mut participants = dkg.config(id("validator-001"));
        participants.participants = participants
            .participants
            .iter()
            .take(3)
            .cloned()
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        assert_eq!(
            cluster.dkg[3]
                .start(participants, false)
                .await
                .unwrap()
                .outcome,
            StartOutcome::Conflict(0)
        );

        // The unsupported parameters are not started under a fresh id either.
        threshold.id = id("validator-002");
        assert!(matches!(
            dkg.start(threshold, false).await.unwrap().outcome,
            StartOutcome::Unsupported(Unsupported::Threshold { expected: 3, .. })
        ));
        assert!(dkg.ceremony(id("validator-002")).await.unwrap().is_none());

        // The original ceremony is unaffected.
        let views = wait_for(
            &context,
            &cluster,
            &[0, 1, 2, 3],
            "validator-001",
            DkgStatus::Completed,
        )
        .await;
        assert_eq!(views[0].config.threshold, 3);
    });
}

#[test]
fn ceremony_fails_safely_without_every_participant() {
    deterministic::Runner::timed(Duration::from_secs(1800)).start(|context| async move {
        let cluster = start_network(&context, RETENTION).await;
        common::wait_for_height(&context, &cluster.clients, 2).await;

        // Node 3 becomes unreachable. Consensus continues with 3 of 4 nodes, but the ceremony
        // cannot: every dealer needs node 3's acknowledgement, and revealing node 3's dealing
        // instead (allowed by Feldman-Desmedt) would put share material on chain.
        cluster.disconnect(3).await;
        assert_eq!(
            start(&cluster, 0, "offline").await,
            StartOutcome::Started(0)
        );
        let views = wait_for(&context, &cluster, &[0, 1, 2], "offline", DkgStatus::Failed).await;
        for (node, view) in views.iter().enumerate() {
            assert!(view.public_key().is_none());
            assert_eq!(
                cluster.dkg[node].share(id("offline")).await.unwrap(),
                ShareStatus::Pending
            );
            assert_eq!(
                cluster.dkg[node]
                    .partial(id("offline"), 1, ROOT)
                    .await
                    .unwrap(),
                Err(Refusal::NotCompleted)
            );
        }
        // A failed id stays used: retrying it does not restart it with fresh randomness.
        assert_eq!(start(&cluster, 1, "offline").await, StartOutcome::Exists(0));

        // Node 3 comes back, catches up, and a new ceremony includes everyone.
        cluster.connect(3).await;
        wait_for(&context, &cluster, &[3], "offline", DkgStatus::Failed).await;
        assert_eq!(start(&cluster, 2, "online").await, StartOutcome::Started(1));
        let views = wait_for(
            &context,
            &cluster,
            &[0, 1, 2, 3],
            "online",
            DkgStatus::Completed,
        )
        .await;
        let output = views[0].output.clone().unwrap();
        let all = partials(&context, &cluster, &[3, 0, 1], "online", 1, ROOT).await;
        recover_and_verify(&output, &all.iter().collect::<Vec<_>>(), MESSAGE).unwrap();
    });
}

#[test]
fn shares_survive_restart() {
    let (output, checkpoint) = deterministic::Runner::timed(Duration::from_secs(300))
        .start_and_recover(|context| async move {
            let cluster = start_network(&context, RETENTION).await;
            assert_eq!(
                start(&cluster, 0, "validator-001").await,
                StartOutcome::Started(0)
            );
            let views = wait_for(
                &context,
                &cluster,
                &[0, 1, 2, 3],
                "validator-001",
                DkgStatus::Completed,
            )
            .await;
            views[0].output.clone().unwrap()
        });

    // Restart every node from its storage.
    deterministic::Runner::from(checkpoint).start(|context| async move {
        let cluster = start_network(&context, RETENTION).await;
        for dkg in &cluster.dkg {
            assert_eq!(
                dkg.share(id("validator-001")).await.unwrap(),
                ShareStatus::Stored
            );
            let view = dkg.ceremony(id("validator-001")).await.unwrap().unwrap();
            assert_eq!(view.output.as_ref(), Some(&output), "public key unchanged");
        }

        // Starting it again does not regenerate anything.
        assert_eq!(
            start(&cluster, 3, "validator-001").await,
            StartOutcome::Exists(0)
        );

        // The restored shares still sign.
        let all = partials(&context, &cluster, &[0, 2, 3], "validator-001", 1, ROOT).await;
        recover_and_verify(&output, &all.iter().collect::<Vec<_>>(), MESSAGE).unwrap();
    });
}

#[test]
fn invalid_dkg_messages_cannot_break_agreement() {
    deterministic::Runner::timed(Duration::from_secs(600)).start(|context| async move {
        // Node 3 is a byzantine dealer: on top of its genuine dealings, the honest nodes receive
        // from it garbage, a dealing with a wrong share, a conflicting dealing (another commitment
        // with a matching share), duplicates, and forged acknowledgements.
        let byzantine = PrivateKey::from_seed(3);
        let ceremony: Arc<Mutex<Option<Ceremony>>> = Arc::default();
        let conflicts = Arc::new(AtomicUsize::new(0));
        let cluster = start_network_with(&context, RETENTION, |node, channel| {
            if node == 3 || channel != engine::DKG_CHANNEL {
                return None;
            }
            let me = PrivateKey::from_seed(node as u64).public_key();
            let byzantine = byzantine.clone();
            let ceremony = ceremony.clone();
            let conflicts = conflicts.clone();
            let mut rng = StdRng::seed_from_u64(node as u64);
            let injector: Injector = Box::new(move |from, message| {
                if *from != byzantine.public_key() {
                    return vec![message];
                }
                match wire::Message::decode(message.clone()) {
                    Ok(wire::Message::Dealing {
                        round,
                        commitment,
                        share,
                    }) => {
                        // Hold the dealer's messages until the test knows the ceremony (it retransmits).
                        let Some(ceremony) = ceremony.lock().unwrap().clone() else {
                            return vec![];
                        };
                        let tampered = wire::Message::Dealing {
                            round,
                            commitment: commitment.clone(),
                            share: DealerPrivMsg::new(Scalar::random(&mut rng)),
                        };
                        let (_, other, shares) = Dealer::<Variant, PrivateKey>::start::<Faults>(
                            &mut rng,
                            ceremony.info(),
                            byzantine.clone(),
                            None,
                        )
                        .unwrap();
                        let conflicting = wire::Message::Dealing {
                            round,
                            commitment: other,
                            share: shares
                                .into_iter()
                                .find(|(player, _)| *player == me)
                                .unwrap()
                                .1,
                        };
                        let genuine = wire::Message::Dealing {
                            round,
                            commitment,
                            share,
                        };
                        conflicts.fetch_add(1, Ordering::Relaxed);
                        vec![
                            IoBuf::from(vec![0xde, 0xad, 0xbe, 0xef]),
                            IoBuf::from(tampered.encode()),
                            IoBuf::from(conflicting.encode()),
                            IoBuf::from(genuine.encode()),
                            IoBuf::from(genuine.encode()),
                        ]
                    }
                    Ok(wire::Message::Ack { .. }) => {
                        let mut forged = message.as_ref().to_vec();
                        let last = forged.len() - 1;
                        forged[last] ^= 1;
                        vec![IoBuf::from(forged), message.clone(), message]
                    }
                    Err(_) => vec![message],
                }
            });
            Some(injector)
        })
        .await;

        assert_eq!(
            start(&cluster, 0, "byzantine").await,
            StartOutcome::Started(0)
        );
        let view = cluster.dkg[0]
            .ceremony(id("byzantine"))
            .await
            .unwrap()
            .unwrap();
        ceremony.lock().unwrap().replace(view);

        // Honest players acknowledged the conflicting commitment first, so node 3 never collects
        // the acknowledgements it needs: its contribution is left out, and everyone agrees.
        let views = wait_for(
            &context,
            &cluster,
            &[0, 1, 2, 3],
            "byzantine",
            DkgStatus::Completed,
        )
        .await;
        let output = views[0].output.clone().unwrap();
        for view in &views {
            assert_eq!(view.output.as_ref(), Some(&output));
        }
        assert!(
            conflicts.load(Ordering::Relaxed) >= 3,
            "every honest node got conflicting dealings"
        );
        assert!(!views[0].logs.contains_key(&byzantine.public_key()));
        assert_eq!(output.dealers().len(), 3);

        // Node 3 is still an honest player: every node holds a working share.
        for dkg in &cluster.dkg {
            assert_eq!(
                dkg.share(id("byzantine")).await.unwrap(),
                ShareStatus::Stored
            );
        }
        let all = partials(&context, &cluster, &[1, 2, 3], "byzantine", 1, ROOT).await;
        recover_and_verify(&output, &all.iter().collect::<Vec<_>>(), MESSAGE).unwrap();
    });
}

#[test]
fn interrupted_share_write_is_never_used() {
    let (output, checkpoint) = deterministic::Runner::timed(Duration::from_secs(300))
        .start_and_recover(|context| async move {
            let cluster = start_network(&context, RETENTION).await;
            assert_eq!(
                start(&cluster, 1, "validator-001").await,
                StartOutcome::Started(0)
            );
            let views = wait_for(
                &context,
                &cluster,
                &[0, 1, 2, 3],
                "validator-001",
                DkgStatus::Completed,
            )
            .await;
            views[0].output.clone().unwrap()
        });

    deterministic::Runner::from(checkpoint).start(|context| async move {
        // Node 2 crashed halfway through writing its share: the secret store falls back to its
        // previous complete state, which holds the acknowledged dealings but no share.
        tear_newest_copy(&context, "node-2-secrets").await;
        let secrets = Secrets::init(context.child("inspect"), "node-2-secrets".into(), None)
            .await
            .unwrap();
        assert!(secrets.share(0).is_none(), "the torn write held the share");
        assert!(!secrets.dealings(0).is_empty());
        drop(secrets);

        // On restart the node does not use anything partial: it derives the share again from the
        // persisted dealings and the finalized logs, checks it against the agreed polynomial, and
        // stores it before using it.
        let cluster = start_network(&context, RETENTION).await;
        assert_eq!(
            cluster.dkg[2].share(id("validator-001")).await.unwrap(),
            ShareStatus::Stored
        );
        let all = partials(&context, &cluster, &[2, 0, 3], "validator-001", 1, ROOT).await;
        MESSAGE.verify_partial(output.public(), &all[0]).unwrap();
        recover_and_verify(&output, &all.iter().collect::<Vec<_>>(), MESSAGE).unwrap();
    });
}
