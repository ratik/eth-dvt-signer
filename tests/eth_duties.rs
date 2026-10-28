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
    executor::ValidatorEntry,
    signer::{
        coordinator::{AuthorizationKind, SignError, Signed},
        wire::Refusal,
    },
    slashing::{Decision, Refusal as Slashing},
    types::Outcome,
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

/// Complete the validator ceremony `name` and return its key, once every node lists it.
async fn validator(
    context: &deterministic::Context,
    cluster: &Cluster,
    name: &str,
) -> ValidatorKey {
    let ceremony = complete_ceremony(context, cluster, name, true).await;
    let key = validator_key(&ceremony);
    for client in &cluster.clients {
        let entry = ValidatorEntry {
            key,
            ceremony: id(name),
            round: ceremony.round,
        };
        assert!(client.validators().await.unwrap().contains(&entry));
    }
    key
}

async fn sign(cluster: &Cluster, via: usize, request: &DutyRequest) -> Result<Signed, SignError> {
    cluster.signers[via]
        .sign_duty(request.clone(), Some(request.signing_root()))
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

/// No node produces a partial signature of `root` for the validator ceremony `name`.
async fn nobody_signs(cluster: &Cluster, name: &str, root: Root) {
    for (node, dkg) in cluster.dkg.iter().enumerate() {
        for nonce in [0, 1] {
            assert_eq!(
                dkg.partial(id(name), nonce, root).await.unwrap(),
                Err(Refusal::NotAuthorized),
                "node {node} signed an unauthorized root (nonce {nonce})"
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
            let signed = cluster.signers[index % 4]
                .sign_duty(request.clone(), Some(root))
                .await
                .unwrap_or_else(|err| panic!("{name}: {err}"));
            assert_eq!(signed.kind, AuthorizationKind::New, "{name}");
            assert_eq!(signed.request.payload_hash, root, "{name}");
            assert!(ethereum_verify(&key, &root, &signed), "{name}");

            // The same duty again, through another node and without `signingRoot`: the same
            // signature, no new authorization.
            let again = cluster.signers[(index + 1) % 4]
                .sign_duty(request, None)
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
        nobody_signs(&cluster, KEY, [0xaa; 32]).await;
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
            nobody_signs(&cluster, KEY, request.signing_root()).await;
        }
        nobody_signs(&cluster, KEY, double.signing_root()).await;
        for node in 0..4 {
            wait_applied(&context, &cluster, node, &block).await;
            assert!(
                cluster.dkg[node]
                    .partial(id(KEY), 0, block.signing_root())
                    .await
                    .unwrap()
                    .is_ok()
            );
        }

        // A signing root that is not the duty's is refused before anything is decided.
        let next = proposal(key, 66, 1);
        match cluster.signers[0]
            .sign_duty(next.clone(), Some([0xee; 32]))
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
            nobody_signs(&cluster, KEY, loser.signing_root()).await;
        }
    });
}

#[test]
fn byzantine_coordinators_cannot_sign_unauthorized_duties() {
    runner(Duration::from_secs(900)).start(|context| async move {
        let cluster = start_network(&context, RETENTION).await;
        let first = validator(&context, &cluster, KEY).await;
        let second = validator(&context, &cluster, "validator-other").await;
        complete_dkg(&context, &cluster, "development").await;

        let block = proposal(first, 10, 1);
        sign(&cluster, 0, &block).await.unwrap();

        // A coordinator skipping its own checks submits the conflict straight to consensus: the
        // state machine refuses it.
        let double = proposal(first, 10, 2);
        let receipt = cluster.clients[1]
            .submit_duty(double.clone())
            .await
            .unwrap();
        assert_eq!(
            receipt.decision,
            Decision::Refused(Slashing::DoubleProposal { slot: 10 })
        );
        assert_eq!(receipt.signing_root, double.signing_root());
        nobody_signs(&cluster, KEY, double.signing_root()).await;

        // An authorization is for one root and one validator: the other validator's ceremony
        // does not sign it, and a development authorization of a duty's root signs nothing with
        // a validator key.
        nobody_signs(&cluster, "validator-other", block.signing_root()).await;
        let development = cluster.clients[2]
            .submit(eth_mpc_signer::types::SignRequest {
                ceremony: id("development"),
                nonce: 1,
                payload_hash: double.signing_root(),
            })
            .await
            .unwrap();
        assert_eq!(development.outcome, Outcome::Accepted);
        nobody_signs(&cluster, KEY, double.signing_root()).await;
        nobody_signs(&cluster, "validator-other", double.signing_root()).await;

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
        let receipt = cluster.clients[0].submit_duty(block.clone()).await.unwrap();
        assert_eq!(receipt.decision, Decision::Accepted);
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

        // Node 3 misses the authorization of the block.
        cluster.disconnect(3).await;
        let block = proposal(key, 30, 1);
        sign(&cluster, 0, &block).await.unwrap();

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
        nobody_signs(&cluster, KEY, double.signing_root()).await;
        let again = sign(&cluster, 3, &block).await.unwrap();
        assert_eq!(again.kind, AuthorizationKind::Existing);
    });
}

#[test]
fn slashing_history_survives_a_full_restart() {
    let ((key, signature), checkpoint) =
        runner(Duration::from_secs(600)).start_and_recover(|context| async move {
            let cluster = start_network(&context, RETENTION).await;
            let key = validator(&context, &cluster, KEY).await;
            let signed = sign(&cluster, 0, &proposal(key, 40, 1)).await.unwrap();
            sign(&cluster, 1, &attestation(key, 2, 5, 1)).await.unwrap();
            (key, signed.signature)
        });

    deterministic::Runner::from(checkpoint).start(|context| async move {
        let cluster = start_network(&context, RETENTION).await;
        for client in &cluster.clients {
            assert_eq!(client.validators().await.unwrap()[0].key, key);
        }

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
