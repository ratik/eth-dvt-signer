//! Unit tests of `crate::storage`: a child module of it (`#[path]` in `src/storage.rs`),
//! so private items are in scope.

use super::*;
use crate::{
    dkg::{
        CeremonyConfig,
        ceremony::tests::{committee, deal, signers},
    },
    types::SignRequest,
};
use commonware_cryptography::{Hasher as _, Sha256};
use commonware_runtime::{Runner as _, Supervisor as _, deterministic};
use commonware_storage::metadata::Config;

fn tx(command: Command) -> Transaction {
    Transaction { id: 0, command }
}

fn sign(nonce: u64, byte: u8) -> Transaction {
    tx(Command::Sign(SignRequest {
        ceremony: CeremonyId::new("c").unwrap(),
        nonce,
        payload_hash: [byte; 32],
    }))
}

#[test]
fn survives_restart() {
    deterministic::Runner::default().start(|mut context| async move {
        let signers = signers();
        let committee = committee(&signers);
        let config = CeremonyConfig::new(CeremonyId::new("c").unwrap(), committee.clone());
        let mut store = Store::init(context.child("first"), "node", committee.clone())
            .await
            .unwrap();
        let block = Sha256::hash(&[b"block"]);

        // Height 1: signing before the ceremony exists, then start it.
        let applied = store
            .apply_block(
                1,
                &block,
                &[sign(1, 1), tx(Command::StartCeremony(config))],
                &mut context,
            )
            .await
            .unwrap();
        assert_eq!(
            applied.effects[0],
            Effect::Sign(Outcome::UnknownCeremony, None)
        );
        let started = applied.changed[0].clone();

        // Height 2: complete it with every dealer log, then authorize in height 3.
        let (_, logs) = deal(&mut context, &started, &signers, &[]);
        let logs: Vec<_> = logs
            .into_iter()
            .map(|log| {
                tx(Command::DealerLog {
                    round: 0,
                    log: Box::new(log),
                })
            })
            .collect();
        store
            .apply_block(2, &block, &logs, &mut context)
            .await
            .unwrap();
        let applied = store
            .apply_block(
                3,
                &block,
                &[sign(1, 1), sign(1, 2), sign(2, 2)],
                &mut context,
            )
            .await
            .unwrap();
        let first = Authorization {
            payload_hash: [1; 32],
            height: 3,
        };
        assert_eq!(
            applied.effects,
            vec![
                Effect::Sign(Outcome::Accepted, Some(first)),
                Effect::Sign(Outcome::Rejected, Some(first)),
                Effect::Sign(
                    Outcome::Accepted,
                    Some(Authorization {
                        payload_hash: [2; 32],
                        height: 3
                    })
                ),
            ]
        );
        assert_eq!(applied.authorized.len(), 2);
        let committed = store.authorizations();
        let ceremonies: Vec<_> = store.ceremonies().iter().cloned().collect();
        drop(store);

        let store = Store::init(context.child("second"), "node", committee)
            .await
            .unwrap();
        assert_eq!(store.height(), 3);
        assert_eq!(store.authorizations(), committed);
        assert_eq!(
            store.ceremonies().iter().cloned().collect::<Vec<_>>(),
            ceremonies
        );
        let (_, authorization) = store.authorization(&CeremonyId::new("c").unwrap(), 1);
        assert_eq!(authorization, Some(first));
    });
}

#[test]
fn refuses_format_1_state() {
    deterministic::Runner::default().start(|context| async move {
        // Any data in the format 1 partition.
        let mut legacy = Metadata::<_, FixedBytes<1>, Vec<u8>>::init(
            context.child("legacy"),
            Config {
                partition: "node-registry".into(),
                codec_config: ((0..).into(), ()),
            },
        )
        .await
        .unwrap();
        legacy.put(FixedBytes::new([0]), vec![1]);
        legacy.sync().await.unwrap();

        let committee = committee(&signers());
        assert!(matches!(
            Store::init(context.child("store"), "node", committee).await,
            Err(Error::Legacy(partition)) if partition == "node-registry"
        ));
    });
}
mod validator {
    use super::*;
    use crate::{
        eth::{
            duty::{Duty, DutyRequest, Fork, ForkInfo},
            types::{AttestationData, BeaconBlockHeader, Checkpoint},
        },
        slashing::{ActivationRefusal, Refusal},
    };
    use commonware_cryptography::ed25519::PrivateKey;
    use commonware_runtime::{Blob as _, Storage as _};

    fn fork(genesis: u8) -> ForkInfo {
        ForkInfo {
            fork: Fork {
                previous_version: [0, 0, 0, 1],
                current_version: [0, 0, 0, 2],
                epoch: 0,
            },
            genesis_validators_root: [genesis; 32],
        }
    }

    fn duty(key: ValidatorKey, duty: Duty) -> DutyRequest {
        DutyRequest {
            validator: key,
            fork: fork(9),
            duty,
        }
    }

    fn chain(genesis: u8) -> ChainIdentity {
        ChainIdentity {
            genesis_validators_root: [genesis; 32],
        }
    }

    /// Activate `key` for the chain of [fork] (`genesis`).
    fn activate(key: ValidatorKey, genesis: u8) -> Transaction {
        tx(Command::ActivateValidator {
            validator: key,
            chain: chain(genesis),
        })
    }

    fn authorized(key: ValidatorKey, request: &DutyRequest) -> DutyAuthorization {
        DutyAuthorization {
            validator: key,
            round: 0,
            signing_root: request.signing_root(),
        }
    }

    fn propose(key: ValidatorKey, slot: u64, body: u8) -> DutyRequest {
        duty(
            key,
            Duty::BlockProposal(BeaconBlockHeader {
                slot,
                proposer_index: 5,
                parent_root: [1; 32],
                state_root: [2; 32],
                body_root: [body; 32],
            }),
        )
    }

    fn attestation(key: ValidatorKey, source: u64, target: u64) -> DutyRequest {
        duty(
            key,
            Duty::Attestation(AttestationData {
                slot: target * 32,
                index: 0,
                beacon_block_root: [4; 32],
                source: Checkpoint {
                    epoch: source,
                    root: [3; 32],
                },
                target: Checkpoint {
                    epoch: target,
                    root: [4; 32],
                },
            }),
        )
    }

    fn submit(request: &DutyRequest) -> Transaction {
        tx(Command::Duty(Box::new(request.clone())))
    }

    fn id(id: &str) -> CeremonyId {
        CeremonyId::new(id).unwrap()
    }

    /// Start the validator ceremony `v` (round 0) at height 1 and complete it at height 2.
    /// Returns its key.
    async fn complete_validator<E: Context + CryptoRng>(
        context: &mut E,
        store: &mut Store<E>,
        signers: &[PrivateKey],
    ) -> ValidatorKey {
        let block = Sha256::hash(&[b"block"]);
        let config = CeremonyConfig::new(id("v"), committee(signers));
        let applied = store
            .apply_block(
                1,
                &block,
                &[tx(Command::StartValidatorCeremony(config))],
                context,
            )
            .await
            .unwrap();
        assert_eq!(
            applied.effects,
            vec![Effect::Start(StartOutcome::Started(0))]
        );
        let (_, logs) = deal(context, &applied.changed[0], signers, &[]);
        let logs: Vec<_> = logs
            .into_iter()
            .map(|log| {
                tx(Command::DealerLog {
                    round: 0,
                    log: Box::new(log),
                })
            })
            .collect();
        let applied = store.apply_block(2, &block, &logs, context).await.unwrap();
        assert_eq!(applied.changed[0].status, DkgStatus::Completed);
        group_key(&applied.changed[0]).unwrap()
    }

    #[test]
    fn duties_and_their_history_survive_restart() {
        deterministic::Runner::default().start(|mut context| async move {
            let signers = signers();
            let committee = committee(&signers);
            let mut store = Store::init(context.child("first"), "node", committee.clone())
                .await
                .unwrap();
            let block = Sha256::hash(&[b"block"]);

            // A duty for a key that is not (yet) a validator.
            let unknown = propose([0xaa; 48], 1, 1);
            let applied = store
                .apply_block(1, &block, &[submit(&unknown)], &mut context)
                .await
                .unwrap();
            assert_eq!(
                applied.effects,
                vec![Effect::Duty(
                    Decision::Refused(Refusal::UnknownValidator),
                    unknown.signing_root()
                )]
            );
            assert!(applied.duties.is_empty());
            drop(store);

            let mut store = Store::init(context.child("second"), "other", committee.clone())
                .await
                .unwrap();
            let key = complete_validator(&mut context, &mut store, &signers).await;
            // Registered when its ceremony completed: round 0, no history, not activated.
            let (validator_id, validator) = store.protection().validator_of(&key).unwrap();
            assert_eq!(
                (
                    validator_id,
                    validator.round,
                    validator.activation,
                    validator.records
                ),
                (0, 0, None, 0)
            );

            let proposal = propose(key, 10, 1);
            let conflicting = propose(key, 10, 2);
            let vote = attestation(key, 1, 2);
            let mut other_chain = attestation(key, 2, 3);
            other_chain.fork = fork(8);
            let activation = Activation {
                chain: chain(9),
                height: 3,
            };
            let applied = store
                .apply_block(
                    3,
                    &block,
                    &[
                        // Purposes are separate: the validator key does not sign generic
                        // payloads, and neither id can be restarted with the other purpose.
                        tx(Command::Sign(SignRequest {
                            ceremony: id("v"),
                            nonce: 1,
                            payload_hash: proposal.signing_root(),
                        })),
                        tx(Command::StartCeremony(CeremonyConfig::new(
                            id("v"),
                            committee.clone(),
                        ))),
                        // Nothing is signed before the activation, which is set once.
                        submit(&proposal),
                        activate(key, 9),
                        activate(key, 8),
                        activate(key, 9),
                        submit(&proposal),
                        submit(&conflicting),
                        submit(&vote),
                        submit(&proposal),
                        submit(&other_chain),
                    ],
                    &mut context,
                )
                .await
                .unwrap();
            assert_eq!(
                applied.effects,
                vec![
                    Effect::Sign(Outcome::ValidatorKey, None),
                    Effect::Start(StartOutcome::Conflict(0)),
                    Effect::Duty(
                        Decision::Refused(Refusal::NotActivated),
                        proposal.signing_root()
                    ),
                    Effect::Activate(ActivationOutcome::Activated),
                    Effect::Activate(ActivationOutcome::Refused(ActivationRefusal::OtherChain {
                        genesis_validators_root: [9; 32]
                    })),
                    Effect::Activate(ActivationOutcome::AlreadyActivated(activation)),
                    Effect::Duty(Decision::Accepted, proposal.signing_root()),
                    Effect::Duty(
                        Decision::Refused(Refusal::DoubleProposal { slot: 10 }),
                        conflicting.signing_root()
                    ),
                    Effect::Duty(Decision::Accepted, vote.signing_root()),
                    Effect::Duty(Decision::AlreadyAccepted, proposal.signing_root()),
                    Effect::Duty(
                        Decision::Refused(Refusal::OtherChain),
                        other_chain.signing_root()
                    ),
                ]
            );
            assert!(applied.authorized.is_empty(), "no generic authorization");
            // The keyholder learns exactly the authorized roots, refused ones never.
            assert_eq!(
                applied.duties,
                vec![
                    authorized(key, &proposal),
                    authorized(key, &vote),
                    authorized(key, &proposal)
                ]
            );
            assert_eq!(
                store.protection().authorized_duties(),
                vec![authorized(key, &proposal), authorized(key, &vote)]
            );
            let protection = store.protection().clone();
            drop(store);

            // After a restart the same history decides the same way.
            let mut store = Store::init(context.child("third"), "other", committee.clone())
                .await
                .unwrap();
            assert_eq!(store.protection(), &protection);
            assert_eq!(
                store.protection().validator(0).unwrap().activation,
                Some(activation)
            );
            assert_eq!(store.protection().authorized_at(&proposal), Some(3));
            let surrounding = attestation(key, 0, 3);
            let applied = store
                .apply_block(
                    4,
                    &block,
                    &[
                        submit(&conflicting),
                        submit(&proposal),
                        submit(&surrounding),
                        tx(Command::StartValidatorCeremony(CeremonyConfig::new(
                            id("v"),
                            committee.clone(),
                        ))),
                        activate(key, 8),
                    ],
                    &mut context,
                )
                .await
                .unwrap();
            assert_eq!(
                applied.effects,
                vec![
                    Effect::Duty(
                        Decision::Refused(Refusal::DoubleProposal { slot: 10 }),
                        conflicting.signing_root()
                    ),
                    Effect::Duty(Decision::AlreadyAccepted, proposal.signing_root()),
                    Effect::Duty(
                        Decision::Refused(Refusal::SurroundsSigned {
                            source_epoch: 1,
                            target_epoch: 2
                        }),
                        surrounding.signing_root()
                    ),
                    // Restarting the validator ceremony neither resets nor replaces it, and
                    // the restart did not make the activation changeable.
                    Effect::Start(StartOutcome::Exists(0)),
                    Effect::Activate(ActivationOutcome::Refused(ActivationRefusal::OtherChain {
                        genesis_validators_root: [9; 32]
                    })),
                ]
            );
            assert_eq!(store.protection().validator(0).unwrap().records, 2);
            // A retry in a later block keeps the original authorization: no new record, the
            // height of the block that decided it.
            assert_eq!(store.protection().authorized_at(&proposal), Some(3));
            assert_eq!(applied.duties, vec![authorized(key, &proposal)]);
        });
    }

    /// A validator stored by the version before activations is read as not activated, its
    /// chain kept only to check the activation.
    #[test]
    fn legacy_validator_records_are_not_activated() {
        let mut legacy = vec![3u8];
        legacy.extend_from_slice(&[7; 48]);
        legacy.extend_from_slice(&5u64.to_be_bytes());
        legacy.push(1);
        legacy.extend_from_slice(&[9; 32]);
        legacy.extend_from_slice(&2u64.to_be_bytes());
        let Value::Validator(validator) = Value::read(&mut legacy.as_slice()).unwrap() else {
            panic!("a validator");
        };
        assert_eq!(
            validator,
            Validator {
                key: [7; 48],
                round: 5,
                activation: None,
                legacy_chain: Some([9; 32]),
                records: 2,
            }
        );
        // Written back in the current layout, it reads the same.
        let encoded = Value::Validator(validator.clone()).encode();
        assert_eq!(encoded[0], 7);
        assert_eq!(
            Value::read(&mut encoded.as_ref()).unwrap(),
            Value::Validator(validator)
        );
    }

    /// A torn write of the newest copy (a crash while applying a block of duties) leaves the
    /// state of the block before; applying the block again gives the same records and the same
    /// decisions, with nothing signed in between.
    #[test]
    fn a_torn_duty_block_is_applied_again_identically() {
        deterministic::Runner::default().start(|mut context| async move {
            let signers = signers();
            let committee = committee(&signers);
            let mut store = Store::init(context.child("first"), "torn", committee.clone())
                .await
                .unwrap();
            let key = complete_validator(&mut context, &mut store, &signers).await;
            let block = Sha256::hash(&[b"block"]);
            let duties = [
                activate(key, 9),
                submit(&propose(key, 10, 1)),
                submit(&propose(key, 10, 2)),
                submit(&attestation(key, 1, 2)),
            ];
            let first = store
                .apply_block(3, &block, &duties, &mut context)
                .await
                .unwrap();
            let protection = store.protection().clone();
            drop(store);

            // Truncate the newest copy, as a crash halfway through writing it would.
            let partition = "torn-state";
            let mut newest = (0, "left");
            for name in ["left", "right"] {
                let (blob, len) = context.open(partition, name.as_bytes()).await.unwrap();
                if len >= 8 {
                    let version = blob.read_at(0, 8, Default::default()).await.unwrap();
                    let version =
                        u64::from_be_bytes(version.coalesce().as_ref().try_into().unwrap());
                    if version >= newest.0 {
                        newest = (version, name);
                    }
                }
            }
            let (blob, len) = context.open(partition, newest.1.as_bytes()).await.unwrap();
            blob.resize(len / 2).await.unwrap();
            blob.sync().await.unwrap();

            let mut store = Store::init(context.child("second"), "torn", committee)
                .await
                .unwrap();
            assert_eq!(store.height(), 2, "the block before");
            assert!(store.protection().authorized_duties().is_empty());
            assert_eq!(store.protection().validator(0).unwrap().activation, None);
            let again = store
                .apply_block(3, &block, &duties, &mut context)
                .await
                .unwrap();
            assert_eq!(again.effects, first.effects);
            assert_eq!(again.duties, first.duties);
            assert_eq!(store.protection(), &protection);
        });
    }

    /// Cost of applying a block with one new attestation while the state holds N slashing
    /// records, on disk (tokio runtime): every block rewrites the whole state partition.
    #[test]
    #[ignore = "benchmark: cargo test --release --lib apply_cost -- --ignored --nocapture"]
    fn apply_cost_with_history() {
        let dir =
            std::env::temp_dir().join(format!("eth-mpc-signer-apply-bench-{}", std::process::id()));
        let runner = commonware_runtime::tokio::Runner::new(
            commonware_runtime::tokio::Config::new().with_storage_directory(&dir),
        );
        let partition = dir.join("bench-state");
        runner.start(|mut context| async move {
            let signers = signers();
            let mut store = Store::init(context.child("store"), "bench", committee(&signers))
                .await
                .unwrap();
            let key = complete_validator(&mut context, &mut store, &signers).await;
            let block = Sha256::hash(&[b"block"]);
            store
                .apply_block(3, &block, &[activate(key, 9)], &mut context)
                .await
                .unwrap();
            let (mut height, mut epoch) = (4, 0u64);
            println!("\napplying a block with one new attestation, on disk");
            println!(
                "  {:>8} {:>12} {:>12}",
                "records", "ms/block", "state bytes"
            );
            for records in [0u64, 1_000, 10_000, 50_000, 100_000] {
                while epoch < records {
                    let batch: Vec<_> = (epoch + 1..=(epoch + 1_000).min(records))
                        .map(|target| submit(&attestation(key, target - 1, target)))
                        .collect();
                    epoch += batch.len() as u64;
                    store
                        .apply_block(height, &block, &batch, &mut context)
                        .await
                        .unwrap();
                    height += 1;
                }
                let blocks = 20;
                let start = std::time::Instant::now();
                for _ in 0..blocks {
                    epoch += 1;
                    let duty = submit(&attestation(key, epoch - 1, epoch));
                    store
                        .apply_block(height, &block, &[duty], &mut context)
                        .await
                        .unwrap();
                    height += 1;
                }
                let ms = start.elapsed().as_secs_f64() * 1000.0 / f64::from(blocks);
                let bytes: u64 = std::fs::read_dir(&partition)
                    .map(|entries| {
                        entries
                            .filter_map(|entry| entry.ok()?.metadata().ok())
                            .map(|metadata| metadata.len())
                            .max()
                            .unwrap_or(0)
                    })
                    .unwrap_or(0);
                println!("  {:>8} {ms:>12.2} {bytes:>12}", epoch);
            }
        });
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// What tampering with the stored history of a validator does to the next start.
    #[test]
    fn altered_history_fails_closed() {
        type Tamper = fn(&mut Metadata<deterministic::Context, Key, Value>, ValidatorKey);
        let cases: [(&str, Tamper); 9] = [
            ("proposal removed", |metadata, _| {
                metadata.remove(&key(PROPOSAL_PREFIX, 0, 10));
            }),
            ("attestation removed", |metadata, _| {
                metadata.remove(&key(ATTESTATION_PREFIX, 0, 2));
            }),
            ("validator removed", |metadata, _| {
                metadata.remove(&key(VALIDATOR_PREFIX, 0, 0));
            }),
            ("validator purpose removed", |metadata, _| {
                metadata.remove(&key(VALIDATOR_ROUND_PREFIX, 0, 0));
            }),
            ("records of an unknown validator", |metadata, _| {
                let _ = metadata.put(
                    key(PROPOSAL_PREFIX, 1, 10),
                    Value::Signed(Signed {
                        signing_root: [0; 32],
                        height: 3,
                    }),
                );
            }),
            ("validator key replaced", |metadata, key| {
                let Some(Value::Validator(validator)) =
                    metadata.get(&super::key(VALIDATOR_PREFIX, 0, 0)).cloned()
                else {
                    panic!("validator record")
                };
                let mut other = key;
                other[47] ^= 1;
                let _ = metadata.put(
                    super::key(VALIDATOR_PREFIX, 0, 0),
                    Value::Validator(Validator {
                        key: other,
                        ..validator
                    }),
                );
            }),
            ("a record of the wrong type", |metadata, _| {
                let _ = metadata.put(key(ATTESTATION_PREFIX, 0, 2), Value::Number(1));
            }),
            ("activation removed", |metadata, _| {
                let Some(Value::Validator(validator)) =
                    metadata.get(&key(VALIDATOR_PREFIX, 0, 0)).cloned()
                else {
                    panic!("validator record")
                };
                let _ = metadata.put(
                    key(VALIDATOR_PREFIX, 0, 0),
                    Value::Validator(Validator {
                        activation: None,
                        ..validator
                    }),
                );
            }),
            ("attestation that surrounds another", |metadata, _| {
                let Some(Value::Validator(validator)) =
                    metadata.get(&key(VALIDATOR_PREFIX, 0, 0)).cloned()
                else {
                    panic!("validator record")
                };
                let _ = metadata.put(
                    key(ATTESTATION_PREFIX, 0, 9),
                    Value::Attested(Attested {
                        source: 0,
                        signing_root: [0; 32],
                        height: 3,
                    }),
                );
                let _ = metadata.put(
                    key(VALIDATOR_PREFIX, 0, 0),
                    Value::Validator(Validator {
                        records: validator.records + 1,
                        ..validator
                    }),
                );
            }),
        ];
        deterministic::Runner::default().start(|mut context| async move {
            let signers = signers();
            let committee = committee(&signers);
            let block = Sha256::hash(&[b"block"]);
            for (case, tamper) in cases {
                let prefix = case.replace(' ', "-");
                let mut store = Store::init(context.child("store"), &prefix, committee.clone())
                    .await
                    .unwrap();
                let key = complete_validator(&mut context, &mut store, &signers).await;
                store
                    .apply_block(
                        3,
                        &block,
                        &[
                            activate(key, 9),
                            submit(&propose(key, 10, 1)),
                            submit(&attestation(key, 1, 2)),
                        ],
                        &mut context,
                    )
                    .await
                    .unwrap();
                drop(store);

                let mut metadata = Metadata::<_, Key, Value>::init(
                    context.child("tamper"),
                    Config {
                        partition: format!("{prefix}-state"),
                        codec_config: (),
                    },
                )
                .await
                .unwrap();
                tamper(&mut metadata, key);
                metadata.sync().await.unwrap();

                match Store::init(context.child("restart"), &prefix, committee.clone()).await {
                    Err(Error::Slashing(reason)) => println!("{case}: {reason}"),
                    Err(Error::Corrupt(entry)) => println!("{case}: corrupt {entry}"),
                    Err(other) => panic!("{case}: unexpected error {other}"),
                    Ok(_) => panic!("{case}: a store with altered history started"),
                }
            }
        });
    }
}
