//! Ethereum validator duties over the simulated network: consensus authorization with slashing
//! protection in the replicated state machine, threshold signing of the computed signing root,
//! and Ethereum (blst) verification of every signature against the validator key.

mod common;

use blst::{
    BLST_ERROR,
    min_pk::{PublicKey as EthPublicKey, Signature as EthSignature},
};
use common::{
    Cluster, RETENTION, complete_ceremony, complete_dkg, id, request, start_network,
    wait_for_height,
};
use commonware_codec::Encode as _;
use commonware_runtime::{Clock as _, Runner as _, deterministic};
use eth_mpc_signer::{
    dkg::{ceremony::Ceremony, signing::ETHEREUM_DST},
    eth::{
        duty::{Duty, DutyRequest, ForkInfo, ValidatorKey},
        types::{AttestationData, BeaconBlockHeader, Checkpoint, Root},
        web3signer::parse_request,
    },
    signer::{
        coordinator::{AuthorizationKind, SignError, Signed},
        wire::Refusal,
    },
    slashing::{
        Activation, ActivationOutcome, ActivationRefusal, ChainIdentity, Decision,
        Refusal as Slashing,
    },
    types::{Command, Outcome, SignRequest},
};
use std::{path::Path, time::Duration};

const KEY: &str = "validator-eth";

/// Every supported duty, as Lighthouse sends it (`tests/fixtures/web3signer`).
const FIXTURES: [&str; 10] = [
    "block_v2_electra.json",
    "attestation.json",
    "randao_reveal.json",
    "aggregation_slot.json",
    "aggregate_and_proof_phase0.json",
    "aggregate_and_proof_electra.json",
    "sync_committee_message.json",
    "sync_committee_selection_proof.json",
    "contribution_and_proof.json",
    "voluntary_exit.json",
];

/// The fixture `name` for validator `key`, and the signing root its client sent.
fn fixture(name: &str, key: ValidatorKey) -> (DutyRequest, Root) {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/web3signer")
        .join(name);
    let parsed = parse_request(&std::fs::read(path).unwrap()).unwrap();
    (
        DutyRequest {
            validator: key,
            fork: parsed.fork,
            duty: parsed.duty,
        },
        parsed.signing_root.unwrap(),
    )
}

/// The chain of the fixtures.
fn fork() -> ForkInfo {
    fixture("attestation.json", [0; 48]).0.fork
}

fn proposal(key: ValidatorKey, slot: u64, body: u8) -> DutyRequest {
    DutyRequest {
        validator: key,
        fork: fork(),
        duty: Duty::BlockProposal(BeaconBlockHeader {
            slot,
            proposer_index: 7,
            parent_root: [1; 32],
            state_root: [2; 32],
            body_root: [body; 32],
        }),
    }
}

/// An attestation from `source` to `target`; `vote` changes its data (and root).
fn attestation(key: ValidatorKey, source: u64, target: u64, vote: u8) -> DutyRequest {
    DutyRequest {
        validator: key,
        fork: fork(),
        duty: Duty::Attestation(AttestationData {
            slot: target * 32,
            index: 0,
            beacon_block_root: [vote; 32],
            source: Checkpoint {
                epoch: source,
                root: [3; 32],
            },
            target: Checkpoint {
                epoch: target,
                root: [vote; 32],
            },
        }),
    }
}

/// A deterministic runtime. `SIM_SEED=<n>` runs another schedule (default: commonware's seed).
fn runner(timeout: Duration) -> deterministic::Runner {
    let mut config = deterministic::Config::default().with_timeout(Some(timeout));
    if let Some(seed) = std::env::var("SIM_SEED")
        .ok()
        .and_then(|seed| seed.parse().ok())
    {
        config = config.with_seed(seed);
    }
    deterministic::Runner::new(config)
}

/// Verify like an Ethereum consensus client (blst, POP ciphersuite, subgroup checks).
fn ethereum_verify(key: &ValidatorKey, root: &Root, signed: &Signed) -> bool {
    let Ok(key) = EthPublicKey::key_validate(key) else {
        return false;
    };
    let Ok(signature) = EthSignature::sig_validate(&signed.signature.encode(), true) else {
        return false;
    };
    signature.verify(true, root, ETHEREUM_DST, &[], &key, true) == BLST_ERROR::BLST_SUCCESS
}

fn validator_key(ceremony: &Ceremony) -> ValidatorKey {
    ceremony
        .public_key()
        .unwrap()
        .encode()
        .as_ref()
        .try_into()
        .unwrap()
}

/// The chain of the fixtures.
fn chain() -> ChainIdentity {
    ChainIdentity {
        genesis_validators_root: fork().genesis_validators_root,
    }
}

/// Complete the validator ceremony `name` and return its key, once every node lists it (not
/// activated: it signs nothing yet).
async fn inactive_validator(
    context: &deterministic::Context,
    cluster: &Cluster,
    name: &str,
) -> ValidatorKey {
    let ceremony = complete_ceremony(context, cluster, name, true).await;
    let key = validator_key(&ceremony);
    for client in &cluster.clients {
        let entry = client
            .validators()
            .await
            .unwrap()
            .into_iter()
            .find(|entry| entry.key == key)
            .expect("listed once its ceremony completed");
        assert_eq!(
            (entry.ceremony, entry.round, entry.activation),
            (id(name), ceremony.round, None)
        );
    }
    key
}

/// Wait until every node has applied `key`'s activation; return it.
async fn wait_activated(
    context: &deterministic::Context,
    cluster: &Cluster,
    key: ValidatorKey,
) -> Activation {
    let mut activations = Vec::new();
    for client in &cluster.clients {
        loop {
            let entry = client
                .validators()
                .await
                .unwrap()
                .into_iter()
                .find(|entry| entry.key == key);
            if let Some(activation) = entry.and_then(|entry| entry.activation) {
                activations.push(activation);
                break;
            }
            context.sleep(Duration::from_millis(50)).await;
        }
    }
    assert!(activations.windows(2).all(|pair| pair[0] == pair[1]));
    activations[0]
}

/// A validator key `name`, activated for the fixtures' chain on every node.
async fn validator(
    context: &deterministic::Context,
    cluster: &Cluster,
    name: &str,
) -> ValidatorKey {
    let key = inactive_validator(context, cluster, name).await;
    let receipt = cluster.activate(0, key, chain()).await.unwrap();
    assert_eq!(receipt.outcome, ActivationOutcome::Activated);
    let activation = wait_activated(context, cluster, key).await;
    assert_eq!(
        activation,
        Activation {
            chain: chain(),
            height: receipt.height
        }
    );
    key
}

async fn sign(cluster: &Cluster, via: usize, request: &DutyRequest) -> Result<Signed, SignError> {
    cluster.signers[via]
        .sign_duty(request.clone(), Some(request.signing_root()), None)
        .await
}

/// Wait until node `node` has applied the authorization of `request`.
async fn wait_applied(
    context: &deterministic::Context,
    cluster: &Cluster,
    node: usize,
    request: &DutyRequest,
) {
    while cluster.clients[node]
        .check_duty(request.clone())
        .await
        .unwrap()
        .height
        .is_none()
    {
        context.sleep(Duration::from_millis(50)).await;
    }
}

/// No node produces a partial signature of `root` with the validator ceremony `name`, as a duty
/// of `validator` or as a development request (whatever its nonce).
async fn nobody_signs(cluster: &Cluster, name: &str, validator: ValidatorKey, root: Root) {
    for (node, dkg) in cluster.dkg.iter().enumerate() {
        assert_eq!(
            dkg.partial_duty(id(name), validator, root)
                .await
                .unwrap()
                .err(),
            Some(Refusal::NotAuthorized),
            "node {node} signed an unauthorized root"
        );
        for nonce in [0, 1] {
            assert_eq!(
                dkg.partial(id(name), nonce, root).await.unwrap().err(),
                Some(Refusal::WrongPurpose),
                "node {node}: a development request to a validator key (nonce {nonce})"
            );
        }
    }
}

#[test]
fn signs_every_supported_duty() {
    runner(Duration::from_secs(600)).start(|context| async move {
        let cluster = start_network(&context, RETENTION).await;
        let key = validator(&context, &cluster, KEY).await;

        for (index, name) in FIXTURES.iter().enumerate() {
            let (request, root) = fixture(name, key);
            // A voluntary exit is signed only with the approvers' authorization (P0.2).
            let endorsement = if request.duty.kind().needs_approval() {
                assert!(
                    matches!(
                        cluster.signers[index % 4]
                            .sign_duty(request.clone(), Some(root), None)
                            .await,
                        Err(SignError::NotApproved)
                    ),
                    "{name}"
                );
                let command = Command::Duty(Box::new(request.clone()));
                Some(cluster.endorse(cluster.next_nonce().await, &command))
            } else {
                None
            };
            let signed = cluster.signers[index % 4]
                .sign_duty(request.clone(), Some(root), endorsement)
                .await
                .unwrap_or_else(|err| panic!("{name}: {err}"));
            assert_eq!(signed.kind, AuthorizationKind::New, "{name}");
            assert_eq!(signed.request.payload_hash, root, "{name}");
            assert!(ethereum_verify(&key, &root, &signed), "{name}");

            // The same duty again, through another node and without `signingRoot`: the same
            // signature, no new authorization.
            let again = cluster.signers[(index + 1) % 4]
                .sign_duty(request, None, None)
                .await
                .unwrap();
            assert_eq!(again.kind, AuthorizationKind::Existing, "{name}");
            assert_eq!(again.signature, signed.signature, "{name}");
        }

        // The validator key signs nothing else: no generic authorization, no development signing.
        assert!(matches!(
            cluster.signers[0].sign(request(KEY, 1, 0xaa)).await,
            Err(SignError::ValidatorKey)
        ));
        let receipt = cluster.clients[1]
            .submit(request(KEY, 1, 0xaa))
            .await
            .unwrap();
        assert_eq!(receipt.outcome, Outcome::ValidatorKey);
        assert_eq!(receipt.authorization, None);
        nobody_signs(&cluster, KEY, key, [0xaa; 32]).await;
    });
}

#[test]
fn slashing_protection_refuses_conflicting_duties() {
    runner(Duration::from_secs(600)).start(|context| async move {
        let cluster = start_network(&context, RETENTION).await;
        let key = validator(&context, &cluster, KEY).await;

        // Proposals: one block per slot.
        let block = proposal(key, 64, 1);
        let signed = sign(&cluster, 0, &block).await.unwrap();
        assert!(ethereum_verify(&key, &block.signing_root(), &signed));
        let double = proposal(key, 64, 2);
        for via in 0..4 {
            assert!(matches!(
                sign(&cluster, via, &double).await,
                Err(SignError::Refused(Slashing::DoubleProposal { slot: 64 }))
            ));
        }
        assert!(sign(&cluster, 1, &proposal(key, 65, 2)).await.is_ok());

        // Attestations: no double vote, no surround either way.
        let vote = attestation(key, 2, 5, 1);
        sign(&cluster, 2, &vote).await.unwrap();
        let refused = [
            (
                attestation(key, 2, 5, 2),
                Slashing::DoubleVote { target: 5 },
            ),
            (
                attestation(key, 1, 6, 1),
                Slashing::SurroundsSigned {
                    source_epoch: 2,
                    target_epoch: 5,
                },
            ),
            (
                attestation(key, 3, 4, 1),
                Slashing::SurroundedBySigned {
                    source_epoch: 2,
                    target_epoch: 5,
                },
            ),
        ];
        for (index, (request, refusal)) in refused.iter().enumerate() {
            match sign(&cluster, index % 4, request).await {
                Err(SignError::Refused(found)) => assert_eq!(&found, refusal),
                other => panic!("{refusal:?}: {other:?}"),
            }
        }
        assert!(sign(&cluster, 3, &attestation(key, 5, 6, 1)).await.is_ok());

        // Refused roots are signed by nobody, however asked.
        for (request, _) in &refused {
            nobody_signs(&cluster, KEY, key, request.signing_root()).await;
        }
        nobody_signs(&cluster, KEY, key, double.signing_root()).await;
        for node in 0..4 {
            wait_applied(&context, &cluster, node, &block).await;
            assert!(
                cluster.dkg[node]
                    .partial_duty(id(KEY), key, block.signing_root())
                    .await
                    .unwrap()
                    .is_ok()
            );
        }

        // A signing root that is not the duty's is refused before anything is decided.
        let next = proposal(key, 66, 1);
        match cluster.signers[0]
            .sign_duty(next.clone(), Some([0xee; 32]), None)
            .await
        {
            Err(SignError::RootMismatch(computed)) => assert_eq!(computed, next.signing_root()),
            other => panic!("root mismatch: {other:?}"),
        }
        let check = cluster.clients[0].check_duty(next).await.unwrap();
        assert_eq!((check.decision, check.height), (Decision::Accepted, None));

        // Another chain, and a key that is not a validator.
        let mut other_chain = attestation(key, 6, 7, 1);
        other_chain.fork.genesis_validators_root = [0x42; 32];
        assert!(matches!(
            sign(&cluster, 1, &other_chain).await,
            Err(SignError::Refused(Slashing::OtherChain))
        ));
        assert!(matches!(
            sign(&cluster, 1, &proposal([0xab; 48], 64, 1)).await,
            Err(SignError::UnknownValidator)
        ));
        // A source after its target cannot be signed (nor recorded).
        assert!(matches!(
            sign(&cluster, 2, &attestation(key, 9, 8, 1)).await,
            Err(SignError::Refused(Slashing::SourceAfterTarget { .. }))
        ));
    });
}

#[test]
fn concurrent_conflicting_duties_authorize_one() {
    runner(Duration::from_secs(600)).start(|context| async move {
        let cluster = start_network(&context, RETENTION).await;
        let key = validator(&context, &cluster, KEY).await;

        let pairs = [
            (proposal(key, 10, 1), proposal(key, 10, 2)),
            (attestation(key, 1, 2, 1), attestation(key, 1, 2, 2)),
            (attestation(key, 3, 6, 1), attestation(key, 4, 5, 1)),
        ];
        for (round, (a, b)) in pairs.iter().enumerate() {
            let (x, y) = futures::join!(sign(&cluster, round % 4, a), sign(&cluster, 3, b));
            let (winner, loser, refusal) = match (x, y) {
                (Ok(signed), Err(SignError::Refused(refusal))) => ((a, signed), b, refusal),
                (Err(SignError::Refused(refusal)), Ok(signed)) => ((b, signed), a, refusal),
                other => panic!("round {round}: expected one signature and one refusal: {other:?}"),
            };
            assert!(refusal.is_slashing(), "round {round}: {refusal:?}");
            assert!(ethereum_verify(&key, &winner.0.signing_root(), &winner.1));
            for node in 0..4 {
                wait_applied(&context, &cluster, node, winner.0).await;
                let check = cluster.clients[node]
                    .check_duty(loser.clone())
                    .await
                    .unwrap();
                assert!(
                    matches!(check.decision, Decision::Refused(_)),
                    "node {node}"
                );
            }
            nobody_signs(&cluster, KEY, key, loser.signing_root()).await;
        }
    });
}

/// What a Byzantine coordinator can ask of the keyholders (a request from the network goes through
/// the same check as this node's own coordinator): the authorization-binding scenarios of
/// docs/security-review.md, against every node.
#[test]
fn byzantine_coordinators_cannot_sign_unauthorized_duties() {
    runner(Duration::from_secs(900)).start(|context| async move {
        let cluster = start_network(&context, RETENTION).await;
        let first = validator(&context, &cluster, KEY).await;
        let second = validator(&context, &cluster, "validator-other").await;
        complete_dkg(&context, &cluster, "development").await;

        let block = proposal(first, 10, 1);
        sign(&cluster, 0, &block).await.unwrap();
        let root = block.signing_root();
        let duty = |name: &'static str, validator: ValidatorKey, root: Root| {
            let cluster = &cluster;
            move |node: usize| async move {
                cluster.dkg[node]
                    .partial_duty(id(name), validator, root)
                    .await
                    .unwrap()
                    .err()
            }
        };
        let development = |name: &'static str, nonce: u64, root: Root| {
            let cluster = &cluster;
            move |node: usize| async move {
                cluster.dkg[node]
                    .partial(id(name), nonce, root)
                    .await
                    .unwrap()
                    .err()
            }
        };
        for node in 0..4 {
            wait_applied(&context, &cluster, node, &block).await;
            // The genuine reference signs.
            assert_eq!(duty(KEY, first, root)(node).await, None);
            // 1. Another validator's authorization: under its key, or its ceremony.
            assert_eq!(
                duty("validator-other", first, root)(node).await,
                Some(Refusal::NotAuthorized)
            );
            assert_eq!(
                duty("validator-other", second, root)(node).await,
                Some(Refusal::NotAuthorized)
            );
            assert_eq!(
                duty(KEY, second, root)(node).await,
                Some(Refusal::NotAuthorized)
            );
            // 2. Another ceremony with another purpose (a development key).
            assert_eq!(
                duty("development", first, root)(node).await,
                Some(Refusal::WrongPurpose)
            );
            // 5. A root that is not authorized.
            assert_eq!(
                duty(KEY, first, proposal(first, 10, 2).signing_root())(node).await,
                Some(Refusal::NotAuthorized)
            );
            // 6, 7. A development request to the validator key: never, with any nonce, even
            // for a root the validator may sign.
            for nonce in [0, 1, u64::MAX] {
                assert_eq!(
                    development(KEY, nonce, root)(node).await,
                    Some(Refusal::WrongPurpose)
                );
            }
        }

        // 6. A development authorization of the duty's root under nonce 0: it signs with the
        //    development key only.
        let receipt = cluster.clients[2]
            .submit(SignRequest {
                ceremony: id("development"),
                nonce: 0,
                payload_hash: root,
            })
            .await
            .unwrap();
        assert_eq!(receipt.outcome, Outcome::Accepted);
        for node in 0..4 {
            while development("development", 0, root)(node).await == Some(Refusal::NotAuthorized) {
                context.sleep(Duration::from_millis(50)).await;
            }
            assert_eq!(development("development", 0, root)(node).await, None);
            assert_eq!(
                duty("development", first, root)(node).await,
                Some(Refusal::WrongPurpose)
            );
            assert_eq!(
                development(KEY, 0, root)(node).await,
                Some(Refusal::WrongPurpose)
            );
        }

        // A coordinator skipping its own checks submits the conflict straight to consensus: the
        // state machine refuses it, and nobody signs it.
        let double = proposal(first, 10, 2);
        let receipt = cluster.clients[1]
            .submit_duty(double.clone(), None)
            .await
            .unwrap();
        assert_eq!(
            receipt.decision,
            Decision::Refused(Slashing::DoubleProposal { slot: 10 })
        );
        assert_eq!(receipt.signing_root, double.signing_root());
        nobody_signs(&cluster, KEY, first, double.signing_root()).await;
        nobody_signs(&cluster, "validator-other", second, double.signing_root()).await;

        // The other validator's history is its own.
        let theirs = proposal(second, 10, 2);
        let signed = sign(&cluster, 3, &theirs).await.unwrap();
        assert!(ethereum_verify(&second, &theirs.signing_root(), &signed));
        assert!(!ethereum_verify(&first, &theirs.signing_root(), &signed));
    });
}

#[test]
fn authorization_outlives_its_coordinator() {
    runner(Duration::from_secs(600)).start(|context| async move {
        let cluster = start_network(&context, RETENTION).await;
        let key = validator(&context, &cluster, KEY).await;

        // The coordinator died after consensus decided (an HTTP request that failed or timed out):
        // the authorization stands, and the conflict stays refused.
        let block = proposal(key, 20, 1);
        let receipt = cluster.clients[0]
            .submit_duty(block.clone(), None)
            .await
            .unwrap();
        assert_eq!(receipt.decision, Decision::Accepted);
        assert_eq!(receipt.authorized_at, Some(receipt.height));
        // The same duty submitted again is decided in a later block, and keeps the original
        // authorization.
        let retry = cluster.clients[3]
            .submit_duty(block.clone(), None)
            .await
            .unwrap();
        assert_eq!(retry.decision, Decision::AlreadyAccepted);
        assert!(retry.height > receipt.height);
        assert_eq!(retry.authorized_at, Some(receipt.height));
        assert!(matches!(
            sign(&cluster, 1, &proposal(key, 20, 2)).await,
            Err(SignError::Refused(Slashing::DoubleProposal { slot: 20 }))
        ));
        let signed = sign(&cluster, 2, &block).await.unwrap();
        assert_eq!(signed.kind, AuthorizationKind::Existing);
        assert_eq!(signed.authorization.height, receipt.height);
        assert!(ethereum_verify(&key, &block.signing_root(), &signed));
    });
}

#[test]
fn isolated_node_cannot_authorize_a_conflict() {
    runner(Duration::from_secs(900)).start(|context| async move {
        let cluster = start_network(&context, RETENTION).await;
        let key = validator(&context, &cluster, KEY).await;

        // Node 3 misses the authorization of the block: it does not sign it either (4. a keyholder
        // that has not applied the authorization).
        cluster.disconnect(3).await;
        let block = proposal(key, 30, 1);
        sign(&cluster, 0, &block).await.unwrap();
        assert_eq!(
            cluster.dkg[3]
                .partial_duty(id(KEY), key, block.signing_root())
                .await
                .unwrap()
                .err(),
            Some(Refusal::NotAuthorized)
        );

        // Its stale state does not know the block, so it tries consensus, which it cannot reach.
        let double = proposal(key, 30, 2);
        let check = cluster.clients[3].check_duty(double.clone()).await.unwrap();
        assert_eq!(check.decision, Decision::Accepted, "stale view");
        match sign(&cluster, 3, &double).await {
            Err(SignError::NotReady(_) | SignError::AuthorizationTimeout) => {}
            other => panic!("an isolated node signed: {other:?}"),
        }

        // Back online, it catches up; whatever it submitted is refused when ordered.
        cluster.connect(3).await;
        wait_applied(&context, &cluster, 3, &block).await;
        let height = cluster.clients[0].status().await.unwrap().height;
        wait_for_height(&context, &cluster.clients, height + 2).await;
        assert!(matches!(
            sign(&cluster, 3, &double).await,
            Err(SignError::Refused(Slashing::DoubleProposal { slot: 30 }))
        ));
        nobody_signs(&cluster, KEY, key, double.signing_root()).await;
        let again = sign(&cluster, 3, &block).await.unwrap();
        assert_eq!(again.kind, AuthorizationKind::Existing);
    });
}

#[test]
fn slashing_history_survives_a_full_restart() {
    let ((key, signature, activation), checkpoint) = runner(Duration::from_secs(600))
        .start_and_recover(|context| async move {
            let cluster = start_network(&context, RETENTION).await;
            let key = validator(&context, &cluster, KEY).await;
            let activation = wait_activated(&context, &cluster, key).await;
            let signed = sign(&cluster, 0, &proposal(key, 40, 1)).await.unwrap();
            sign(&cluster, 1, &attestation(key, 2, 5, 1)).await.unwrap();
            (key, signed.signature, activation)
        });

    deterministic::Runner::from(checkpoint).start(|context| async move {
        let cluster = start_network(&context, RETENTION).await;
        // The activation is read back as it was, and still cannot change.
        for client in &cluster.clients {
            let entry = client.validators().await.unwrap()[0].clone();
            assert_eq!((entry.key, entry.activation), (key, Some(activation)));
        }
        let receipt = cluster
            .activate(
                2,
                key,
                ChainIdentity {
                    genesis_validators_root: [0x42; 32],
                },
            )
            .await
            .unwrap();
        assert_eq!(
            receipt.outcome,
            ActivationOutcome::Refused(ActivationRefusal::OtherChain {
                genesis_validators_root: chain().genesis_validators_root
            })
        );

        // The history decides as before the restart.
        let again = sign(&cluster, 3, &proposal(key, 40, 1)).await.unwrap();
        assert_eq!(again.kind, AuthorizationKind::Existing);
        assert_eq!(again.signature, signature);
        assert!(matches!(
            sign(&cluster, 2, &proposal(key, 40, 2)).await,
            Err(SignError::Refused(Slashing::DoubleProposal { slot: 40 }))
        ));
        assert!(matches!(
            sign(&cluster, 1, &attestation(key, 1, 6, 1)).await,
            Err(SignError::Refused(Slashing::SurroundsSigned { .. }))
        ));

        // New duties once the node follows consensus again.
        let restarted_at = cluster.clients[0].status().await.unwrap().height;
        wait_for_height(&context, &cluster.clients, restarted_at + 1).await;
        let vote = attestation(key, 5, 6, 1);
        let signed = sign(&cluster, 0, &vote).await.unwrap();
        assert_eq!(signed.kind, AuthorizationKind::New);
        assert!(ethereum_verify(&key, &vote.signing_root(), &signed));
    });
}

/// `request` for the chain `chain`.
fn on_chain(mut request: DutyRequest, chain: ChainIdentity) -> DutyRequest {
    request.fork.genesis_validators_root = chain.genesis_validators_root;
    request
}

/// Activation is explicit, decided by consensus, and immutable: nothing is signed before it, two
/// conflicting activations sent at once through different nodes end in one decision, and only the
/// activated chain is signed for afterwards.
#[test]
fn activation_is_explicit_decided_by_consensus_and_immutable() {
    runner(Duration::from_secs(600)).start(|context| async move {
        let cluster = start_network(&context, RETENTION).await;
        let key = inactive_validator(&context, &cluster, KEY).await;

        // Not activated: refused through any coordinator and straight from consensus, nothing
        // recorded, nothing signed.
        let block = proposal(key, 64, 1);
        for via in 0..4 {
            assert!(matches!(
                sign(&cluster, via, &block).await,
                Err(SignError::Refused(Slashing::NotActivated))
            ));
        }
        let receipt = cluster.clients[1]
            .submit_duty(block.clone(), None)
            .await
            .unwrap();
        assert_eq!(receipt.decision, Decision::Refused(Slashing::NotActivated));
        nobody_signs(&cluster, KEY, key, block.signing_root()).await;

        // Two activations for different chains at once, through different nodes.
        let other = ChainIdentity {
            genesis_validators_root: [0x42; 32],
        };
        // Approved with consecutive nonces: both apply, in nonce order.
        let nonce = cluster.next_nonce().await;
        let approved = |nonce, chain| {
            Some(cluster.endorse(
                nonce,
                &Command::ActivateValidator {
                    validator: key,
                    chain,
                },
            ))
        };
        let (a, b) = futures::join!(
            cluster.clients[0].activate_validator(key, chain(), approved(nonce, chain())),
            cluster.clients[3].activate_validator(key, other, approved(nonce + 1, other))
        );
        let (a, b) = (a.unwrap(), b.unwrap());
        let (winner, loser) = match (a.outcome, b.outcome) {
            (
                ActivationOutcome::Activated,
                ActivationOutcome::Refused(ActivationRefusal::OtherChain {
                    genesis_validators_root,
                }),
            ) => {
                assert_eq!(genesis_validators_root, chain().genesis_validators_root);
                (chain(), other)
            }
            (
                ActivationOutcome::Refused(ActivationRefusal::OtherChain {
                    genesis_validators_root,
                }),
                ActivationOutcome::Activated,
            ) => {
                assert_eq!(genesis_validators_root, other.genesis_validators_root);
                (other, chain())
            }
            outcomes => panic!("expected one activation and one refusal: {outcomes:?}"),
        };
        let activation = wait_activated(&context, &cluster, key).await;
        assert_eq!(activation.chain, winner);

        // The activated chain signs; the other is refused, and was never recorded.
        let signed = sign(&cluster, 2, &on_chain(block.clone(), winner))
            .await
            .unwrap();
        assert!(ethereum_verify(
            &key,
            &on_chain(block.clone(), winner).signing_root(),
            &signed
        ));
        assert!(matches!(
            sign(&cluster, 1, &on_chain(proposal(key, 65, 1), loser)).await,
            Err(SignError::Refused(Slashing::OtherChain))
        ));

        // Immutable: the other chain is refused, the same one changes nothing.
        let again = cluster.activate(2, key, loser).await.unwrap();
        assert_eq!(
            again.outcome,
            ActivationOutcome::Refused(ActivationRefusal::OtherChain {
                genesis_validators_root: winner.genesis_validators_root
            })
        );
        let same = cluster.activate(1, key, winner).await.unwrap();
        assert_eq!(
            same.outcome,
            ActivationOutcome::AlreadyActivated(activation)
        );
        assert_eq!(wait_activated(&context, &cluster, key).await, activation);
    });
}

/// A node that has not applied the activation refuses every duty of the key, and a duty for
/// another chain that it submits anyway is refused when consensus orders it.
#[test]
fn stale_node_cannot_authorize_another_chain() {
    runner(Duration::from_secs(900)).start(|context| async move {
        let cluster = start_network(&context, RETENTION).await;
        let key = inactive_validator(&context, &cluster, KEY).await;

        cluster.disconnect(3).await;
        let receipt = cluster.activate(0, key, chain()).await.unwrap();
        assert_eq!(receipt.outcome, ActivationOutcome::Activated);

        let other = on_chain(
            proposal(key, 64, 1),
            ChainIdentity {
                genesis_validators_root: [0x42; 32],
            },
        );
        assert!(matches!(
            sign(&cluster, 3, &other).await,
            Err(SignError::Refused(Slashing::NotActivated))
        ));
        // Submitted straight from the stale node, decided once ordered, with the activation.
        let (receipt, ()) =
            futures::join!(cluster.clients[3].submit_duty(other.clone(), None), async {
                context.sleep(Duration::from_secs(2)).await;
                cluster.connect(3).await;
            });
        assert_eq!(
            receipt.unwrap().decision,
            Decision::Refused(Slashing::OtherChain)
        );
        wait_activated(&context, &cluster, key).await;
        nobody_signs(&cluster, KEY, key, other.signing_root()).await;

        // Caught up, it signs for the activated chain.
        let block = proposal(key, 64, 1);
        let signed = sign(&cluster, 3, &block).await.unwrap();
        assert!(ethereum_verify(&key, &block.signing_root(), &signed));
    });
}

/// A batch activation through consensus: refused as a whole for an unknown key (nothing
/// activated, its nonce used), then two keys activated in one block, on every node, and they
/// sign; repeated, it changes nothing.
#[test]
fn a_batch_activation_activates_every_key_or_none() {
    use eth_mpc_signer::{slashing::BatchActivationOutcome, types::BatchActivation};
    runner(Duration::from_secs(900)).start(|context| async move {
        let cluster = start_network(&context, RETENTION).await;
        let first = inactive_validator(&context, &cluster, "batch-a").await;
        let second = inactive_validator(&context, &cluster, "batch-b").await;
        let submit = |validators: Vec<ValidatorKey>| {
            let cluster = &cluster;
            async move {
                let batch = BatchActivation {
                    chain: chain(),
                    validators: validators.into_iter().map(|key| (key, None)).collect(),
                };
                let nonce = cluster.next_nonce().await;
                let endorsement =
                    cluster.endorse(nonce, &Command::ActivateValidators(Box::new(batch.clone())));
                let receipt = cluster.clients[1]
                    .activate_batch(batch, Some(endorsement))
                    .await
                    .unwrap();
                (nonce, receipt)
            }
        };

        let unknown = [0x55; 48];
        let (nonce, refused) = submit(vec![first, unknown, second]).await;
        assert_eq!(
            refused.outcome,
            BatchActivationOutcome::Refused {
                key: unknown,
                refusal: ActivationRefusal::UnknownValidator
            }
        );
        let validators = cluster.clients[0].validators().await.unwrap();
        assert!(validators.iter().all(|entry| entry.activation.is_none()));
        assert_eq!(cluster.next_nonce().await, nonce + 1);

        let (_, receipt) = submit(vec![first, second]).await;
        assert_eq!(
            receipt.outcome,
            BatchActivationOutcome::Activated {
                activated: 2,
                already: 0
            }
        );
        for key in [first, second] {
            let activation = wait_activated(&context, &cluster, key).await;
            assert_eq!(
                activation,
                Activation {
                    chain: chain(),
                    height: receipt.height
                }
            );
            let block = proposal(key, 64, 1);
            let signed = sign(&cluster, 2, &block).await.unwrap();
            assert!(ethereum_verify(&key, &block.signing_root(), &signed));
        }

        let (_, again) = submit(vec![second, first]).await;
        assert_eq!(
            again.outcome,
            BatchActivationOutcome::Activated {
                activated: 0,
                already: 2
            }
        );
    });
}
