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

mod administration {
    use super::*;
    use crate::{
        admin::{AdminRecord, Administration, Approvers},
        slashing::ChainIdentity,
        types::Authorized,
    };
    use commonware_cryptography::{Signer as _, ed25519::PrivateKey};

    pub(super) fn administration(committee: &Set<PublicKey>) -> Administration {
        let approvers = (100..103)
            .map(|seed| PrivateKey::from_seed(seed).public_key())
            .collect();
        Administration::new(Approvers::new(2, approvers).unwrap(), committee)
    }

    fn activation(byte: u8) -> Command {
        Command::ActivateValidator {
            validator: [byte; 48],
            chain: ChainIdentity {
                genesis_validators_root: [1; 32],
            },
        }
    }

    /// `command` approved by the approvers of `seeds` with `nonce`.
    pub(super) fn approved(
        admin: &Administration,
        nonce: u64,
        command: Command,
        seeds: &[u64],
    ) -> Transaction {
        let mut approvals: Vec<_> = seeds
            .iter()
            .map(|seed| {
                admin
                    .approve(&PrivateKey::from_seed(*seed), nonce, &command)
                    .unwrap()
            })
            .collect();
        approvals.sort_by_key(|approval| approval.approver);
        tx(Command::Admin(Box::new(Authorized {
            nonce,
            command,
            approvals,
        })))
    }

    /// P0 test 16: the administrative nonce is committed with its block and restored on restart,
    /// with the approver set it was applied under. A bare protected command from history applies
    /// as before and uses no nonce.
    #[test]
    fn the_nonce_survives_restart() {
        deterministic::Runner::default().start(|mut context| async move {
            let committee = committee(&signers());
            let admin = administration(&committee);
            let mut store = Store::init(context.child("first"), "node", committee.clone())
                .await
                .unwrap();
            store.administer(Some(admin.clone()));
            assert_eq!(store.admin(), AdminRecord::default());
            let block = Sha256::hash(&[b"block"]);
            let applied = store
                .apply_block(
                    1,
                    &block,
                    &[
                        approved(&admin, 1, activation(1), &[100, 101]),
                        tx(activation(2)),
                        approved(&admin, 2, activation(3), &[101, 102]),
                    ],
                    &mut context,
                )
                .await
                .unwrap();
            // Unknown keys: refused, as without approvals; the nonces are used all the same.
            assert_eq!(applied.effects.len(), 3);
            let record = AdminRecord {
                nonce: 2,
                approvers: admin.approvers().digest(),
                ..AdminRecord::default()
            };
            assert_eq!(store.admin(), record);
            drop(store);

            let mut store = Store::init(context.child("second"), "node", committee)
                .await
                .unwrap();
            assert_eq!(store.admin(), record);
            store.administer(Some(admin.clone()));
            store
                .apply_block(
                    2,
                    &block,
                    &[approved(&admin, 3, activation(4), &[100, 102])],
                    &mut context,
                )
                .await
                .unwrap();
            assert_eq!(store.admin().nonce, 3);
        });
    }

    /// A finalized protected command this node cannot admit stops it rather than diverge.
    fn refused(transaction: impl FnOnce(&Administration) -> Transaction, configured: bool) {
        deterministic::Runner::default().start(|mut context| async move {
            let committee = committee(&signers());
            let admin = administration(&committee);
            let mut store = Store::init(context.child("store"), "node", committee)
                .await
                .unwrap();
            store.administer(configured.then(|| admin.clone()));
            let block = Sha256::hash(&[b"block"]);
            let _ = store
                .apply_block(1, &block, &[transaction(&admin)], &mut context)
                .await;
        });
    }

    #[test]
    #[should_panic(expected = "administrative nonce 2, the next is 1")]
    fn a_skipped_nonce_stops_the_node() {
        refused(|admin| approved(admin, 2, activation(1), &[100, 101]), true);
    }

    #[test]
    #[should_panic(expected = "does not verify here")]
    fn too_few_approvals_stop_the_node() {
        refused(|admin| approved(admin, 1, activation(1), &[100]), true);
    }

    #[test]
    #[should_panic(expected = "has no approver set")]
    fn a_node_without_approvers_stops() {
        refused(
            |admin| approved(admin, 1, activation(1), &[100, 101]),
            false,
        );
    }
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
            types::{
                AttestationData, BeaconBlockHeader, Checkpoint, DepositMessage, VoluntaryExit,
            },
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
            kind: request.duty.kind(),
            period: request.duty.protection().period(),
            terms: request.duty.terms(),
            source: match &request.duty {
                Duty::Attestation(data) => Some(data.source.epoch),
                _ => None,
            },
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

    /// P0.2 tests 1 to 4, 12 and 21 (storage): an exit or a deposit authorized bare (history
    /// written before approvals existed) is recorded but never handed to the keyholder; one
    /// authorized with approvals is, also after a restart. Approved later, the bare one is too.
    #[test]
    fn an_exit_or_a_deposit_is_signed_only_once_approved() {
        deterministic::Runner::default().start(|mut context| async move {
            let signers = signers();
            let committee = committee(&signers);
            let admin = super::administration::administration(&committee);
            let mut store = Store::init(context.child("first"), "node", committee.clone())
                .await
                .unwrap();
            store.administer(Some(admin.clone()));
            let key = complete_validator(&mut context, &mut store, &signers).await;
            let block = Sha256::hash(&[b"block"]);
            let exit = |epoch| {
                duty(
                    key,
                    Duty::VoluntaryExit(VoluntaryExit {
                        epoch,
                        validator_index: 7,
                    }),
                )
            };
            let deposit = DutyRequest {
                validator: key,
                fork: ForkInfo {
                    fork: Fork {
                        previous_version: [0, 0, 0, 1],
                        current_version: [0, 0, 0, 1],
                        epoch: 0,
                    },
                    genesis_validators_root: [0; 32],
                },
                duty: Duty::Deposit(DepositMessage {
                    pubkey: key,
                    withdrawal_credentials: [1; 32],
                    amount: 32_000_000_000,
                }),
            };
            let approved = |nonce, request: &DutyRequest| {
                super::administration::approved(
                    &admin,
                    nonce,
                    Command::Duty(Box::new(request.clone())),
                    &[100, 101],
                )
            };
            let (legacy, exit) = (exit(10), exit(11));
            let applied = store
                .apply_block(
                    3,
                    &block,
                    &[
                        activate(key, 9),
                        submit(&legacy),
                        approved(1, &exit),
                        approved(2, &deposit),
                    ],
                    &mut context,
                )
                .await
                .unwrap();
            assert_eq!(
                applied.effects[1..],
                [
                    Effect::Duty(Decision::Accepted, legacy.signing_root()),
                    Effect::Duty(Decision::Accepted, exit.signing_root()),
                    Effect::Duty(Decision::Accepted, deposit.signing_root()),
                ]
            );
            // The keyholder learns the approved ones only; the bare one is recorded (it counts
            // against the epoch's roots) and never signed.
            let signable = vec![authorized(key, &exit), authorized(key, &deposit)];
            assert_eq!(applied.duties, signable);
            assert_eq!(store.protection().authorized_duties(), signable);
            assert_eq!(store.protection().authorized_at(&legacy), Some(3));
            assert!(!store.protection().is_approved(&legacy));
            assert!(store.protection().is_approved(&exit));
            assert_eq!(
                store
                    .protection()
                    .approval(0, &deposit.signing_root())
                    .map(|approved| approved.nonce),
                Some(2)
            );
            assert_eq!(store.admin().nonce, 2);
            let protection = store.protection().clone();
            drop(store);

            // Restarted: the same approvals, so the same signable roots.
            let mut store = Store::init(context.child("second"), "node", committee.clone())
                .await
                .unwrap();
            store.administer(Some(admin.clone()));
            assert_eq!(store.protection(), &protection);
            assert_eq!(store.protection().authorized_duties(), signable);

            // A bare repeat of the approved exit is a retry; the bare one approved later becomes
            // signable (the same root, no new record).
            let applied = store
                .apply_block(
                    4,
                    &block,
                    &[submit(&exit), approved(3, &legacy)],
                    &mut context,
                )
                .await
                .unwrap();
            assert_eq!(
                applied.effects,
                [
                    Effect::Duty(Decision::AlreadyAccepted, exit.signing_root()),
                    Effect::Duty(Decision::AlreadyAccepted, legacy.signing_root()),
                ]
            );
            assert_eq!(
                applied.duties,
                vec![authorized(key, &exit), authorized(key, &legacy)]
            );
            assert_eq!(store.protection().validator(0).unwrap().records, 3);
            assert_eq!(
                store
                    .protection()
                    .approval(0, &legacy.signing_root())
                    .map(|approved| approved.nonce),
                Some(3)
            );
            drop(store);
            let store = Store::init(context.child("third"), "node", committee)
                .await
                .unwrap();
            assert_eq!(store.protection().authorized_duties().len(), 3);
        });
    }

    /// Builder registrations (`eth::registration`): none without a policy; a policy applies from
    /// the next transaction, in block order, so a registration after a policy change in the same
    /// block is decided by the new policy and one before it by the old; a retry of an authorized
    /// registration the policy in force no longer allows is refused; nothing limits distinct
    /// registrations (a validator client signs one at each restart); a registration for another
    /// key is refused. The policy and the registrations, with their terms for the keyholder,
    /// survive a restart; a registration record that is not one of its validator's records stops
    /// the node.
    #[test]
    fn registrations_follow_the_policy_in_force() {
        use crate::eth::{
            duty::DutyKind,
            registration::{Policy, Terms},
            types::ValidatorRegistration,
        };
        deterministic::Runner::default().start(|mut context| async move {
            let signers = signers();
            let committee = committee(&signers);
            let admin = super::administration::administration(&committee);
            let mut store = Store::init(context.child("first"), "node", committee.clone())
                .await
                .unwrap();
            store.administer(Some(admin.clone()));
            let key = complete_validator(&mut context, &mut store, &signers).await;
            let block = Sha256::hash(&[b"block"]);
            let genesis = ForkInfo {
                fork: Fork {
                    previous_version: [0, 0, 0, 1],
                    current_version: [0, 0, 0, 1],
                    epoch: 0,
                },
                genesis_validators_root: [0; 32],
            };
            let registration = |fee_recipient: u8, timestamp: u64| DutyRequest {
                validator: key,
                fork: genesis,
                duty: Duty::ValidatorRegistration(ValidatorRegistration {
                    fee_recipient: [fee_recipient; 20],
                    gas_limit: 30_000_000,
                    timestamp,
                    pubkey: key,
                }),
            };
            let policy = |fee_recipients: &[u8]| {
                Policy::new(
                    fee_recipients.iter().map(|byte| [*byte; 20]).collect(),
                    30_000_000,
                    60_000_000,
                    30,
                    3600,
                )
                .unwrap()
            };
            let set = |nonce, policy: Policy| {
                super::administration::approved(
                    &admin,
                    nonce,
                    Command::SetRegistrationPolicy(Box::new(policy)),
                    &[100, 101],
                )
            };
            let refused = |request: &DutyRequest| {
                Effect::Duty(
                    Decision::Refused(Refusal::RegistrationPolicy),
                    request.signing_root(),
                )
            };
            let accepted =
                |request: &DutyRequest| Effect::Duty(Decision::Accepted, request.signing_root());

            // No policy: refused. Then a policy of A (1): B (2) after it is refused, A accepted.
            let (a1, b1) = (registration(1, 100), registration(2, 100));
            let applied = store
                .apply_block(
                    3,
                    &block,
                    &[
                        activate(key, 9),
                        submit(&a1),
                        set(1, policy(&[1])),
                        submit(&b1),
                        submit(&a1),
                    ],
                    &mut context,
                )
                .await
                .unwrap();
            assert_eq!(
                applied.effects[1..],
                [
                    refused(&a1),
                    Effect::RegistrationPolicy(policy(&[1]).digest()),
                    refused(&b1),
                    accepted(&a1),
                ]
            );
            assert_eq!(applied.registration_policy, Some(policy(&[1])));
            assert_eq!(applied.duties, vec![authorized(key, &a1)]);
            assert_eq!(
                applied.duties[0].terms,
                Some(Terms {
                    fee_recipient: [1; 20],
                    gas_limit: Some(30_000_000)
                })
            );
            assert_eq!(store.registration_policy(), Some(&policy(&[1])));

            // A before a change to B's policy: decided by A's, accepted. After it: the retry of A
            // is refused, B accepted.
            let (a2, b2) = (registration(1, 200), registration(2, 200));
            let applied = store
                .apply_block(
                    4,
                    &block,
                    &[submit(&a2), set(2, policy(&[2])), submit(&a1), submit(&b2)],
                    &mut context,
                )
                .await
                .unwrap();
            assert_eq!(
                applied.effects,
                [
                    accepted(&a2),
                    Effect::RegistrationPolicy(policy(&[2]).digest()),
                    refused(&a1),
                    accepted(&b2),
                ]
            );
            assert_eq!(
                applied.duties,
                vec![authorized(key, &a2), authorized(key, &b2)]
            );

            // Twenty distinct registrations of B (twenty restarts of a validator client): all
            // accepted; a retry of one is idempotent; one for another key is refused.
            let many: Vec<DutyRequest> =
                (0..20).map(|index| registration(2, 300 + index)).collect();
            let mut other = registration(2, 400);
            other.duty = Duty::ValidatorRegistration(ValidatorRegistration {
                fee_recipient: [2; 20],
                gas_limit: 30_000_000,
                timestamp: 400,
                pubkey: [9; 48],
            });
            let mut transactions: Vec<Transaction> = many.iter().map(submit).collect();
            transactions.push(submit(&many[3]));
            transactions.push(submit(&other));
            let applied = store
                .apply_block(5, &block, &transactions, &mut context)
                .await
                .unwrap();
            assert!(
                applied.effects[..20]
                    .iter()
                    .zip(&many)
                    .all(|(effect, request)| *effect == accepted(request))
            );
            assert_eq!(
                applied.effects[20..],
                [
                    Effect::Duty(Decision::AlreadyAccepted, many[3].signing_root()),
                    Effect::Duty(
                        Decision::Refused(Refusal::RegistrationForAnotherKey),
                        other.signing_root()
                    ),
                ]
            );
            assert_eq!(store.protection().validator(0).unwrap().records, 23);
            assert_eq!(store.protection().authorized_at(&a1), Some(3));
            assert!(store.protection().export(0).blocks.is_empty());
            let protection = store.protection().clone();
            drop(store);

            // Restarted: the same policy and registrations, terms included.
            let store = Store::init(context.child("second"), "node", committee.clone())
                .await
                .unwrap();
            assert_eq!(store.protection(), &protection);
            assert_eq!(store.registration_policy(), Some(&policy(&[2])));
            let registrations: Vec<_> = store
                .protection()
                .authorized_duties()
                .into_iter()
                .filter(|duty| duty.kind == DutyKind::ValidatorRegistration)
                .collect();
            assert_eq!(registrations.len(), 23);
            assert!(registrations.iter().all(|duty| duty.terms.is_some()));
            drop(store);

            // A registration under a sequence number no record of its validator has: refused.
            let mut metadata = Metadata::<_, Key, Value>::init(
                context.child("tamper"),
                Config {
                    partition: "node-state".into(),
                    codec_config: (),
                },
            )
            .await
            .unwrap();
            let (root, registered) = protection
                .registrations_of(0)
                .next()
                .map(|(root, registered)| (*root, *registered))
                .unwrap();
            metadata.put(
                crate::storage::key(REGISTRATION_PREFIX, 0, 99),
                Value::Registration(
                    root,
                    Registered {
                        sequence: 99,
                        ..registered
                    },
                ),
            );
            metadata.sync().await.unwrap();
            assert!(matches!(
                Store::init(context.child("third"), "node", committee)
                    .await
                    .map(|_| ()),
                Err(Error::Slashing(_))
            ));
        });
    }

    /// Gloas envelopes and proposer preferences follow the registration policy in force at
    /// their transaction, as registrations do; an envelope needs the validator's own block; the
    /// terms a keyholder checks survive a restart.
    #[test]
    fn gloas_duties_follow_the_policy_in_force() {
        use crate::eth::{
            duty::DutyKind,
            gloas::{BUILDER_INDEX_SELF_BUILD, EnvelopeSummary, ProposerPreferences},
            registration::Policy,
        };
        use tree_hash::TreeHash as _;
        deterministic::Runner::default().start(|mut context| async move {
            let signers = signers();
            let committee = committee(&signers);
            let admin = super::administration::administration(&committee);
            let mut store = Store::init(context.child("first"), "node", committee.clone())
                .await
                .unwrap();
            store.administer(Some(admin.clone()));
            let key = complete_validator(&mut context, &mut store, &signers).await;
            let block = Sha256::hash(&[b"block"]);
            let policy = |fee_recipients: &[u8]| {
                Policy::new(
                    fee_recipients.iter().map(|byte| [*byte; 20]).collect(),
                    30_000_000,
                    60_000_000,
                    30,
                    3600,
                )
                .unwrap()
            };
            let set = |nonce, policy: Policy| {
                super::administration::approved(
                    &admin,
                    nonce,
                    Command::SetRegistrationPolicy(Box::new(policy)),
                    &[100, 101],
                )
            };
            let proposal = propose(key, 64, 1);
            let Duty::BlockProposal(header) = &proposal.duty else {
                unreachable!()
            };
            let envelope = |fee: u8, block_root: [u8; 32]| {
                duty(
                    key,
                    Duty::ExecutionPayloadEnvelope(Box::new(EnvelopeSummary {
                        parent_hash: [1; 32],
                        fee_recipient: [fee; 20],
                        state_root: [2; 32],
                        receipts_root: [3; 32],
                        logs_bloom_root: [4; 32],
                        prev_randao: [5; 32],
                        block_number: 1,
                        gas_limit: 60_000_000,
                        gas_used: 0,
                        timestamp: 1,
                        extra_data_root: [6; 32],
                        base_fee_per_gas: [7; 32],
                        block_hash: [8; 32],
                        transactions_root: [9; 32],
                        withdrawals_root: [10; 32],
                        blob_gas_used: 0,
                        excess_blob_gas: 0,
                        block_access_list_root: [11; 32],
                        slot_number: 64,
                        execution_requests_root: [12; 32],
                        builder_index: BUILDER_INDEX_SELF_BUILD,
                        beacon_block_root: block_root,
                        parent_beacon_block_root: [13; 32],
                    })),
                )
            };
            let preferences = |fee: u8, gas: u64| {
                duty(
                    key,
                    Duty::ProposerPreferences(ProposerPreferences {
                        dependent_root: [fee; 32],
                        proposal_slot: 96,
                        validator_index: 5,
                        fee_recipient: [fee; 20],
                        target_gas_limit: gas,
                    }),
                )
            };
            let refused = |request: &DutyRequest, refusal| {
                Effect::Duty(Decision::Refused(refusal), request.signing_root())
            };
            let accepted =
                |request: &DutyRequest| Effect::Duty(Decision::Accepted, request.signing_root());
            let own = header.tree_hash_root().0;
            let (envelope_a, envelope_b) = (envelope(1, own), envelope(2, own));
            let foreign = envelope(1, [0xee; 32]);
            let (preferences_a, preferences_high) =
                (preferences(1, 60_000_000), preferences(1, 90_000_000));

            // No policy: the envelope is refused. A policy of A: B's envelope refused, A's
            // accepted only for the own block; preferences within the range only.
            let applied = store
                .apply_block(
                    3,
                    &block,
                    &[
                        activate(key, 9),
                        submit(&proposal),
                        submit(&envelope_a),
                        set(1, policy(&[1])),
                        submit(&envelope_b),
                        submit(&foreign),
                        submit(&envelope_a),
                        submit(&preferences_high),
                        submit(&preferences_a),
                    ],
                    &mut context,
                )
                .await
                .unwrap();
            assert_eq!(
                applied.effects[1..],
                [
                    accepted(&proposal),
                    refused(&envelope_a, Refusal::RegistrationPolicy),
                    Effect::RegistrationPolicy(policy(&[1]).digest()),
                    refused(&envelope_b, Refusal::RegistrationPolicy),
                    refused(&foreign, Refusal::EnvelopeWithoutOwnBlock { slot: 64 }),
                    accepted(&envelope_a),
                    refused(&preferences_high, Refusal::RegistrationPolicy),
                    accepted(&preferences_a),
                ]
            );
            assert_eq!(
                applied.duties,
                vec![
                    authorized(key, &proposal),
                    authorized(key, &envelope_a),
                    authorized(key, &preferences_a)
                ]
            );
            // After a change to B's policy, the retry of A's envelope is refused.
            let applied = store
                .apply_block(
                    4,
                    &block,
                    &[set(2, policy(&[2])), submit(&envelope_a)],
                    &mut context,
                )
                .await
                .unwrap();
            assert_eq!(
                applied.effects[1..],
                [refused(&envelope_a, Refusal::RegistrationPolicy)]
            );
            let protection = store.protection().clone();
            drop(store);

            // Restarted: the terms a keyholder checks are back.
            let store = Store::init(context.child("second"), "node", committee)
                .await
                .unwrap();
            assert_eq!(store.protection(), &protection);
            let gloas: Vec<_> = store
                .protection()
                .authorized_duties()
                .into_iter()
                .filter(|duty| duty.kind.is_gloas())
                .collect();
            assert_eq!(
                gloas,
                vec![
                    authorized(key, &envelope_a),
                    authorized(key, &preferences_a)
                ]
            );
            assert!(gloas.iter().all(|duty| duty.terms.is_some()));
            assert_eq!(
                gloas
                    .iter()
                    .map(|duty| duty.kind)
                    .collect::<Vec<DutyKind>>(),
                [
                    DutyKind::ExecutionPayloadEnvelope,
                    DutyKind::ProposerPreferences
                ]
            );
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
        let Value::Validator(validator) =
            Value::read(&mut commonware_codec::Copying(legacy.as_slice())).unwrap()
        else {
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
            Value::read(&mut commonware_codec::Copying(encoded.as_ref())).unwrap(),
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
            drop(blob);

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
        let cases: [(&str, Tamper); 10] = [
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
            // P0.2: an approval makes a root signable; one of a root never authorized is forged.
            ("approval of an unauthorized exit", |metadata, _| {
                let _ = metadata.put(
                    key(APPROVAL_PREFIX, 0, 1),
                    Value::Approval(
                        [0xee; 32],
                        crate::slashing::Approved {
                            kind: DutyKind::VoluntaryExit,
                            period: 10,
                            nonce: 0,
                        },
                    ),
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

    /// Imported keys: registration, acknowledged shares, history and the activation barriers,
    /// through blocks and a restart.
    pub(super) mod imported {
        use super::*;
        use crate::{
            dkg::{
                PROTOCOL_VERSION,
                ceremony::{ImportOutcome, ReadyAck, ReadyIgnored},
            },
            import::{
                dealer,
                manifest::{MANIFEST_VERSION, Manifest, Member},
            },
            slashing::{
                Acknowledgment, HistoryImport, HistoryOutcome, HistoryRefusal, HistorySummary,
                ImportedAttestation, ImportedBlock,
            },
        };
        use commonware_cryptography::bls12381::primitives::group::{Private, Scalar};
        use rand::{SeedableRng as _, rngs::StdRng};

        /// A manifest for the key `seed`, split among `committee`.
        pub(crate) fn manifest(ceremony: &str, committee: &Set<PublicKey>, seed: u64) -> Manifest {
            let secret = Private::new(Scalar::from_u64(seed + 1000));
            let split =
                dealer::split(&secret, committee, &mut StdRng::seed_from_u64(seed)).unwrap();
            Manifest {
                version: MANIFEST_VERSION,
                ceremony: id(ceremony),
                import_id: [seed as u8; 16],
                validator: split.sharing.public().encode().as_ref().try_into().unwrap(),
                protocol_version: PROTOCOL_VERSION,
                threshold: 3,
                members: committee
                    .iter()
                    .enumerate()
                    .map(|(index, identity)| Member {
                        identity: identity.clone(),
                        share_key: [index as u8 + 1; 32],
                    })
                    .collect(),
                commitments: split.commitments,
            }
        }

        fn register(manifest: &Manifest) -> Transaction {
            tx(Command::RegisterImportedKey(Box::new(manifest.clone())))
        }

        pub(crate) fn history(
            key: ValidatorKey,
            genesis: u8,
            slot: u64,
            source: u64,
            target: u64,
        ) -> Transaction {
            tx(Command::ImportSlashingProtection(Box::new(HistoryImport {
                chain: chain(genesis),
                digest: [7; 32],
                validators: vec![(
                    key,
                    HistorySummary {
                        block: Some(ImportedBlock {
                            slot,
                            signing_root: None,
                        }),
                        attestation: Some(ImportedAttestation {
                            source,
                            target,
                            signing_root: None,
                        }),
                    },
                )],
            })))
        }

        pub(crate) fn activate_imported(
            key: ValidatorKey,
            genesis: u8,
            acknowledgment: Acknowledgment,
        ) -> Transaction {
            tx(Command::ActivateImportedValidator {
                validator: key,
                chain: chain(genesis),
                acknowledgment,
            })
        }

        pub(crate) const ACKNOWLEDGED: Acknowledgment = Acknowledgment {
            previous_signer_stopped: true,
            no_other_active_signer: true,
            history_exported_after_stop: true,
            automatic_restart_disabled: true,
        };

        /// P0.1 tests 18, 19, 25, 27 and 28 at the state machine: a history import from before
        /// approvals existed still applies (bare, no nonce); an approved one applies as the
        /// import itself, across a consensus epoch, and uses one nonce; one the state machine
        /// refuses changes no floor (it still uses its nonce: voters cannot know an outcome
        /// before applying it); a restart keeps floors and nonce.
        #[test]
        fn an_approved_import_applies_once_across_an_epoch() {
            use crate::{
                admin::AdminRecord,
                storage::tests::administration::{administration, approved},
                types::{Command, Reconfiguration},
            };
            use commonware_cryptography::Signer as _;
            deterministic::Runner::default().start(|mut context| async move {
                let signers = signers();
                let committee = committee(&signers);
                let admin = administration(&committee);
                let block = Sha256::hash(&[b"block"]);
                let manifest = manifest("imported", &committee, 1);
                let key = manifest.validator;
                let mut store = Store::init(context.child("first"), "node", committee.clone())
                    .await
                    .unwrap();
                store.administer(Some(admin.clone()));
                let floors = |store: &Store<_>| {
                    let protection = store.protection();
                    let (id, _) = protection.validator_of(&key).unwrap();
                    protection.imported(id).unwrap().floors
                };
                let import =
                    |slot, source, target| match history(key, 9, slot, source, target).command {
                        command @ Command::ImportSlashingProtection(_) => command,
                        _ => unreachable!(),
                    };
                let reconfigure = Command::Reconfigure(Box::new(Reconfiguration {
                    epoch: 1,
                    remove: committee.iter().next().unwrap().clone(),
                    add: PrivateKey::from_seed(77).public_key(),
                }));
                let mut effects = Vec::new();
                for (height, transactions) in [
                    // Legacy history: bare, as before approvals existed.
                    (1, vec![register(&manifest)]),
                    (2, vec![history(key, 9, 100, 10, 11)]),
                    // The end of consensus epoch 0, approved.
                    (3, vec![approved(&admin, 1, reconfigure, &[100, 101])]),
                    // In epoch 1: an approved import, then one for another chain.
                    (
                        4,
                        vec![approved(&admin, 2, import(120, 12, 13), &[101, 102])],
                    ),
                    (
                        5,
                        vec![approved(
                            &admin,
                            3,
                            match history(key, 8, 130, 13, 14).command {
                                command @ Command::ImportSlashingProtection(_) => command,
                                _ => unreachable!(),
                            },
                            &[100, 102],
                        )],
                    ),
                ] {
                    let applied = store
                        .apply_block(height, &block, &transactions, &mut context)
                        .await
                        .unwrap();
                    effects.push(applied.effects.into_iter().next().unwrap());
                    if height == 2 {
                        assert_eq!(store.admin(), AdminRecord::default());
                    }
                }
                assert_eq!(effects[1], Effect::History(HistoryOutcome::Imported));
                assert_eq!(effects[3], Effect::History(HistoryOutcome::Imported));
                assert!(matches!(
                    effects[4],
                    Effect::History(HistoryOutcome::Refused(HistoryRefusal::OtherChain { .. }))
                ));
                assert_eq!(store.epochs().current().epoch, 1);
                assert_eq!(store.admin().nonce, 3);
                let imported = floors(&store);
                assert_eq!(imported.block, Some(120));
                drop(store);

                let store = Store::init(context.child("second"), "node", committee)
                    .await
                    .unwrap();
                assert_eq!(store.admin().nonce, 3);
                assert_eq!(floors(&store), imported);
            });
        }

        /// Register an imported key at height 1, its history at 2, 3 acknowledgements at 3, and
        /// activate it at 4 (for the chain of [fork]). Returns its key.
        pub(super) async fn activated<E: Context + CryptoRng>(
            context: &mut E,
            store: &mut Store<E>,
            signers: &[PrivateKey],
        ) -> ValidatorKey {
            let block = Sha256::hash(&[b"block"]);
            let manifest = manifest("imported", &committee(signers), 1);
            let key = manifest.validator;
            for (height, transactions) in [
                (1, vec![register(&manifest)]),
                (2, vec![history(key, 9, 100, 10, 11)]),
                (
                    3,
                    signers[..3]
                        .iter()
                        .map(|signer| {
                            tx(Command::ShareReady(Box::new(ReadyAck::sign(
                                signer,
                                0,
                                manifest.digest(),
                            ))))
                        })
                        .collect(),
                ),
                (4, vec![activate_imported(key, 9, ACKNOWLEDGED)]),
            ] {
                store
                    .apply_block(height, &block, &transactions, context)
                    .await
                    .unwrap();
            }
            key
        }

        /// Write the fuzz seeds of what only this module builds (`cargo test --lib
        /// write_fuzz_seeds -- --ignored`): every value of two state partitions (a DKG validator
        /// and an imported one, each with duties), their epoch records, the import manifest, and
        /// the transactions that built them (`crate::fuzzing`).
        #[test]
        #[ignore]
        fn write_fuzz_seeds() {
            use commonware_codec::Encode as _;
            use commonware_cryptography::Signer as _;
            fn seed(target: &str, name: &str, bytes: &[u8]) {
                let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("fuzz/corpus")
                    .join(target);
                std::fs::create_dir_all(&dir).unwrap();
                std::fs::write(dir.join(format!("seed-{name}")), bytes).unwrap();
            }
            deterministic::Runner::default().start(|mut context| async move {
                let signers = signers();
                let committee = committee(&signers);
                let block = Sha256::hash(&[b"block"]);
                let mut dkg = Store::init(context.child("dkg"), "dkg", committee.clone())
                    .await
                    .unwrap();
                let key = super::complete_validator(&mut context, &mut dkg, &signers).await;
                let duties = |key| {
                    vec![
                        activate(key, 9),
                        submit(&propose(key, 10, 1)),
                        submit(&attestation(key, 1, 2)),
                        submit(&attestation(key, 2, 3)),
                    ]
                };
                dkg.apply_block(3, &block, &duties(key), &mut context)
                    .await
                    .unwrap();
                let mut imported =
                    Store::init(context.child("imported"), "imported", committee.clone())
                        .await
                        .unwrap();
                let imported_key = activated(&mut context, &mut imported, &signers).await;
                let transactions = duties(imported_key)[1..].to_vec();
                imported
                    .apply_block(5, &block, &transactions, &mut context)
                    .await
                    .unwrap();
                drop((dkg, imported));

                for prefix in ["dkg", "imported"] {
                    let metadata = Metadata::<_, Key, Value>::init(
                        context.child("read"),
                        Config {
                            partition: format!("{prefix}-state"),
                            codec_config: (),
                        },
                    )
                    .await
                    .unwrap();
                    for (index, key) in metadata.keys().enumerate() {
                        let mut bytes = vec![0u8];
                        bytes.extend_from_slice(&metadata.get(key).unwrap().encode());
                        seed("state_value", &format!("{prefix}-{index}"), &bytes);
                    }
                }
                // A later epoch (epoch 0 is never stored).
                let record = crate::epochs::EpochRecord {
                    epoch: 1,
                    change: Some((
                        committee.iter().next().unwrap().clone(),
                        signers[0].public_key(),
                    )),
                    committee: committee.clone(),
                    boundary: 5,
                    boundary_digest: block,
                };
                let mut bytes = vec![1u8];
                bytes.extend_from_slice(&record.encode());
                seed("state_value", "epoch-1", &bytes);
                let manifest = manifest("imported", &committee, 1);
                seed("manifest", "imported", &manifest.encode());
                for (index, transaction) in [
                    register(&manifest),
                    history(manifest.validator, 9, 100, 10, 11),
                    activate_imported(manifest.validator, 9, ACKNOWLEDGED),
                    tx(Command::ShareReady(Box::new(ReadyAck::sign(
                        &signers[0],
                        0,
                        manifest.digest(),
                    )))),
                ]
                .iter()
                .enumerate()
                {
                    seed(
                        "transaction",
                        &format!("import-{index}"),
                        &transaction.encode(),
                    );
                }
            });
        }

        #[test]
        fn imported_keys_activate_only_after_history_shares_and_acknowledgement() {
            deterministic::Runner::default().start(|mut context| async move {
                let signers = signers();
                let committee = committee(&signers);
                let block = Sha256::hash(&[b"block"]);
                let mut store = Store::init(context.child("first"), "node", committee.clone())
                    .await
                    .unwrap();
                let manifest = manifest("imported", &committee, 1);
                let key = manifest.validator;

                // Registration: once; the same manifest is idempotent; another manifest under the
                // id, the key under another id, or an invalid manifest are refused.
                let mut conflicting = manifest.clone();
                conflicting.import_id = [9; 16];
                let mut other_id = manifest.clone();
                other_id.ceremony = id("imported-again");
                let mut invalid = super::imported::manifest("invalid", &committee, 2);
                invalid.threshold = 2;
                let applied = store
                    .apply_block(
                        1,
                        &block,
                        &[
                            register(&manifest),
                            register(&manifest),
                            register(&conflicting),
                            register(&other_id),
                            register(&invalid),
                        ],
                        &mut context,
                    )
                    .await
                    .unwrap();
                assert_eq!(
                    applied.effects[0],
                    Effect::Register(ImportOutcome::Registered(0))
                );
                assert_eq!(
                    applied.effects[1],
                    Effect::Register(ImportOutcome::Exists(0))
                );
                assert_eq!(
                    applied.effects[2],
                    Effect::Register(ImportOutcome::Conflict(0))
                );
                assert_eq!(
                    applied.effects[3],
                    Effect::Register(ImportOutcome::KeyExists(0))
                );
                assert!(matches!(
                    applied.effects[4],
                    Effect::Register(ImportOutcome::Invalid(_))
                ));
                assert_eq!(applied.designated, vec![0]);
                let (id0, validator) = store.protection().validator_of(&key).unwrap();
                assert_eq!((id0, validator.activation), (0, None));

                // Registered, nothing else: no duty, no plain activation, no imported activation.
                let applied = store
                    .apply_block(
                        2,
                        &block,
                        &[
                            submit(&propose(key, 200, 1)),
                            activate(key, 9),
                            activate_imported(key, 9, ACKNOWLEDGED),
                        ],
                        &mut context,
                    )
                    .await
                    .unwrap();
                assert_eq!(
                    applied.effects[0],
                    Effect::Duty(
                        Decision::Refused(Refusal::NotActivated),
                        propose(key, 200, 1).signing_root()
                    )
                );
                assert_eq!(
                    applied.effects[1],
                    Effect::Activate(ActivationOutcome::Refused(ActivationRefusal::ImportedKey))
                );
                assert_eq!(
                    applied.effects[2],
                    Effect::Activate(ActivationOutcome::Refused(
                        ActivationRefusal::NoImportedHistory
                    ))
                );

                // History for chain 9; then another chain is refused for history and activation.
                let applied = store
                    .apply_block(
                        3,
                        &block,
                        &[
                            history(key, 9, 100, 10, 11),
                            history(key, 8, 100, 10, 11),
                            activate_imported(key, 8, ACKNOWLEDGED),
                        ],
                        &mut context,
                    )
                    .await
                    .unwrap();
                assert_eq!(
                    applied.effects[0],
                    Effect::History(HistoryOutcome::Imported)
                );
                assert!(matches!(
                    applied.effects[1],
                    Effect::History(HistoryOutcome::Refused(HistoryRefusal::OtherChain { .. }))
                ));
                assert!(matches!(
                    applied.effects[2],
                    Effect::Activate(ActivationOutcome::Refused(
                        ActivationRefusal::HistoryForAnotherChain { .. }
                    ))
                ));

                // Shares: two acknowledgements are not enough; bad ones are ignored.
                let digest = manifest.digest();
                let mut forged = ReadyAck::sign(&signers[3], 0, digest);
                forged.round = 0;
                forged.signature = ReadyAck::sign(&signers[2], 0, digest).signature;
                let outsider = <PrivateKey as commonware_cryptography::Signer>::from_seed(99);
                let applied = store
                    .apply_block(
                        4,
                        &block,
                        &[
                            tx(Command::ShareReady(Box::new(ReadyAck::sign(
                                &signers[0],
                                0,
                                digest,
                            )))),
                            tx(Command::ShareReady(Box::new(ReadyAck::sign(
                                &signers[1],
                                0,
                                digest,
                            )))),
                            tx(Command::ShareReady(Box::new(ReadyAck::sign(
                                &signers[1],
                                0,
                                digest,
                            )))),
                            tx(Command::ShareReady(Box::new(forged))),
                            tx(Command::ShareReady(Box::new(ReadyAck::sign(
                                &signers[2],
                                0,
                                [0; 32].into(),
                            )))),
                            tx(Command::ShareReady(Box::new(ReadyAck::sign(
                                &outsider, 0, digest,
                            )))),
                            activate_imported(key, 9, ACKNOWLEDGED),
                        ],
                        &mut context,
                    )
                    .await
                    .unwrap();
                assert!(matches!(applied.effects[0], Effect::Ready(Ok(_))));
                assert_eq!(
                    applied.effects[1], applied.effects[2],
                    "a repeated acknowledgement"
                );
                assert_eq!(
                    applied.effects[3],
                    Effect::Ready(Err(ReadyIgnored::BadSignature))
                );
                assert_eq!(
                    applied.effects[4],
                    Effect::Ready(Err(ReadyIgnored::Manifest))
                );
                assert_eq!(
                    applied.effects[5],
                    Effect::Ready(Err(ReadyIgnored::NotParticipant))
                );
                assert_eq!(
                    applied.effects[6],
                    Effect::Activate(ActivationOutcome::Refused(
                        ActivationRefusal::SharesNotReady {
                            ready: 2,
                            required: 3
                        }
                    ))
                );

                // A third share; then an incomplete acknowledgement, then the complete one.
                let incomplete = Acknowledgment {
                    automatic_restart_disabled: false,
                    ..ACKNOWLEDGED
                };
                let applied = store
                    .apply_block(
                        5,
                        &block,
                        &[
                            tx(Command::ShareReady(Box::new(ReadyAck::sign(
                                &signers[2],
                                0,
                                digest,
                            )))),
                            activate_imported(key, 9, incomplete),
                            activate_imported(key, 9, ACKNOWLEDGED),
                            activate_imported(key, 9, ACKNOWLEDGED),
                            activate(key, 9),
                        ],
                        &mut context,
                    )
                    .await
                    .unwrap();
                assert_eq!(
                    applied.effects[1],
                    Effect::Activate(ActivationOutcome::Refused(
                        ActivationRefusal::NotAcknowledged
                    ))
                );
                assert_eq!(
                    applied.effects[2],
                    Effect::Activate(ActivationOutcome::Activated)
                );
                assert!(matches!(
                    applied.effects[3],
                    Effect::Activate(ActivationOutcome::AlreadyActivated(_))
                ));
                assert!(matches!(
                    applied.effects[4],
                    Effect::Activate(ActivationOutcome::AlreadyActivated(_))
                ));

                // Duties: the same slashing protection as any validator, plus the imported floors.
                let cases = [
                    (
                        propose(key, 100, 1),
                        Decision::Refused(Refusal::BlockAtOrBelowImported {
                            slot: 100,
                            floor: 100,
                        }),
                    ),
                    (propose(key, 101, 1), Decision::Accepted),
                    (
                        propose(key, 101, 2),
                        Decision::Refused(Refusal::DoubleProposal { slot: 101 }),
                    ),
                    (
                        attestation(key, 9, 12),
                        Decision::Refused(Refusal::SourceBelowImported {
                            source_epoch: 9,
                            floor: 10,
                        }),
                    ),
                    (
                        attestation(key, 10, 11),
                        Decision::Refused(Refusal::TargetAtOrBelowImported {
                            target_epoch: 11,
                            floor: 11,
                        }),
                    ),
                    (attestation(key, 10, 12), Decision::Accepted),
                ];
                let transactions: Vec<_> =
                    cases.iter().map(|(request, _)| submit(request)).collect();
                let applied = store
                    .apply_block(6, &block, &transactions, &mut context)
                    .await
                    .unwrap();
                for ((request, expected), effect) in cases.iter().zip(&applied.effects) {
                    assert_eq!(*effect, Effect::Duty(*expected, request.signing_root()));
                }
                // A registration of the same key never resets anything, and the active key takes
                // no history.
                let applied = store
                    .apply_block(
                        7,
                        &block,
                        &[
                            register(&manifest),
                            register(&other_id),
                            history(key, 9, 50, 1, 2),
                        ],
                        &mut context,
                    )
                    .await
                    .unwrap();
                assert_eq!(
                    applied.effects[0],
                    Effect::Register(ImportOutcome::Exists(0))
                );
                assert_eq!(
                    applied.effects[1],
                    Effect::Register(ImportOutcome::KeyExists(0))
                );
                assert_eq!(
                    applied.effects[2],
                    Effect::History(HistoryOutcome::Refused(HistoryRefusal::Activated { key }))
                );
                let before = (
                    store.protection().clone(),
                    store.ceremonies().iter().cloned().collect::<Vec<_>>(),
                );
                drop(store);

                // Restart: the same state, the same decisions.
                let mut store = Store::init(context.child("second"), "node", committee.clone())
                    .await
                    .unwrap();
                assert_eq!(store.protection(), &before.0);
                assert_eq!(
                    store.ceremonies().iter().cloned().collect::<Vec<_>>(),
                    before.1
                );
                assert_eq!(
                    store
                        .ceremonies()
                        .by_round(0)
                        .unwrap()
                        .imported()
                        .unwrap()
                        .ready
                        .len(),
                    3
                );
                let applied = store
                    .apply_block(
                        8,
                        &block,
                        &[
                            submit(&propose(key, 101, 3)),
                            submit(&propose(key, 60, 3)),
                            submit(&propose(key, 101, 1)),
                        ],
                        &mut context,
                    )
                    .await
                    .unwrap();
                assert_eq!(
                    applied.effects[0],
                    Effect::Duty(
                        Decision::Refused(Refusal::DoubleProposal { slot: 101 }),
                        propose(key, 101, 3).signing_root()
                    )
                );
                assert_eq!(
                    applied.effects[1],
                    Effect::Duty(
                        Decision::Refused(Refusal::BlockAtOrBelowImported {
                            slot: 60,
                            floor: 100
                        }),
                        propose(key, 60, 3).signing_root()
                    )
                );
                assert_eq!(
                    applied.effects[2],
                    Effect::Duty(
                        Decision::AlreadyAccepted,
                        propose(key, 101, 1).signing_root()
                    )
                );
            });
        }

        /// Once an imported key is activated, no command changes its import state (floors, chain,
        /// imports, acknowledgement), whatever it is: a history (far in the future, older, the
        /// same, another chain), a registration of the same key, another share acknowledgement,
        /// an activation, a ceremony start under its id, a dealer log for its round, a duty, or a
        /// development signing request. The same after a restart.
        #[test]
        fn an_activated_imported_key_keeps_its_floors_whatever_the_command() {
            deterministic::Runner::default().start(|mut context| async move {
                let signers = signers();
                let committee = committee(&signers);
                let block = Sha256::hash(&[b"block"]);
                let mut store = Store::init(context.child("first"), "node", committee.clone())
                    .await
                    .unwrap();
                let key = activated(&mut context, &mut store, &signers).await;
                let (validator, _) = store.protection().validator_of(&key).unwrap();
                let imported = *store.protection().imported(validator).unwrap();
                assert_eq!(
                    imported.floors,
                    Floors {
                        block: Some(100),
                        attestation: Some((10, 11))
                    }
                );
                let manifest = manifest("imported", &committee, 1);
                let mut other_id = manifest.clone();
                other_id.ceremony = id("imported-again");
                // A development ceremony, for a well-formed dealer log addressed to the imported
                // key's round.
                let applied = store
                    .apply_block(
                        5,
                        &block,
                        &[tx(Command::StartCeremony(CeremonyConfig::new(
                            id("other"),
                            committee.clone(),
                        )))],
                        &mut context,
                    )
                    .await
                    .unwrap();
                let (_, logs) = deal(&mut context, &applied.changed[0], &signers, &[]);

                let far = 1 << 40;
                let transactions = vec![
                    history(key, 9, far, far, far),
                    history(key, 9, 50, 1, 2),
                    history(key, 9, 100, 10, 11),
                    history(key, 8, far, far, far),
                    register(&manifest),
                    register(&other_id),
                    tx(Command::ShareReady(Box::new(ReadyAck::sign(
                        &signers[3],
                        0,
                        manifest.digest(),
                    )))),
                    activate_imported(key, 9, ACKNOWLEDGED),
                    activate_imported(key, 8, ACKNOWLEDGED),
                    activate(key, 9),
                    activate(key, 8),
                    tx(Command::StartValidatorCeremony(CeremonyConfig::new(
                        id("imported"),
                        committee.clone(),
                    ))),
                    tx(Command::StartCeremony(CeremonyConfig::new(
                        id("imported"),
                        committee.clone(),
                    ))),
                    tx(Command::DealerLog {
                        round: 0,
                        log: Box::new(logs[0].clone()),
                    }),
                    tx(Command::Sign(SignRequest {
                        ceremony: id("imported"),
                        nonce: 1,
                        payload_hash: [1; 32],
                    })),
                    submit(&propose(key, 101, 1)),
                    submit(&attestation(key, 11, 12)),
                ];
                let applied = store
                    .apply_block(6, &block, &transactions, &mut context)
                    .await
                    .unwrap();
                let effects = &applied.effects;
                for effect in &effects[..4] {
                    assert_eq!(
                        *effect,
                        Effect::History(HistoryOutcome::Refused(HistoryRefusal::Activated { key }))
                    );
                }
                assert_eq!(effects[4], Effect::Register(ImportOutcome::Exists(0)));
                assert_eq!(effects[5], Effect::Register(ImportOutcome::KeyExists(0)));
                assert!(matches!(effects[6], Effect::Ready(Ok(_))));
                assert!(matches!(
                    effects[7],
                    Effect::Activate(ActivationOutcome::AlreadyActivated(_))
                ));
                assert!(matches!(
                    effects[8],
                    Effect::Activate(ActivationOutcome::Refused(
                        ActivationRefusal::OtherChain { .. }
                    ))
                ));
                assert!(matches!(
                    effects[9],
                    Effect::Activate(ActivationOutcome::AlreadyActivated(_))
                ));
                assert!(matches!(
                    effects[10],
                    Effect::Activate(ActivationOutcome::Refused(_))
                ));
                for effect in &effects[11..13] {
                    assert!(
                        !matches!(effect, Effect::Start(StartOutcome::Started(_))),
                        "{effect:?}"
                    );
                }
                assert!(matches!(effects[13], Effect::Log(Err(_))));
                assert_eq!(effects[14], Effect::Sign(Outcome::ValidatorKey, None));
                assert_eq!(
                    effects[15],
                    Effect::Duty(Decision::Accepted, propose(key, 101, 1).signing_root())
                );
                assert_eq!(
                    effects[16],
                    Effect::Duty(Decision::Accepted, attestation(key, 11, 12).signing_root())
                );
                assert_eq!(*store.protection().imported(validator).unwrap(), imported);
                drop(store);

                // Restart: the same import state; a block the far-future history would have
                // refused is signed.
                let mut store = Store::init(context.child("second"), "node", committee.clone())
                    .await
                    .unwrap();
                assert_eq!(*store.protection().imported(validator).unwrap(), imported);
                let applied = store
                    .apply_block(7, &block, &[submit(&propose(key, 200, 1))], &mut context)
                    .await
                    .unwrap();
                assert_eq!(
                    applied.effects[0],
                    Effect::Duty(Decision::Accepted, propose(key, 200, 1).signing_root())
                );
            });
        }

        /// Imported keys' state tampered with on disk: the next start refuses.
        #[test]
        fn altered_import_state_fails_closed() {
            type Tamper = fn(&mut Metadata<deterministic::Context, Key, Value>);
            let cases: [(&str, Tamper); 4] = [
                ("import state removed", |metadata| {
                    metadata.remove(&key(IMPORTED_PREFIX, 0, 0));
                }),
                ("acknowledgement removed", |metadata| {
                    let Some(Value::ImportedValidator(imported)) =
                        metadata.get(&key(IMPORTED_PREFIX, 0, 0)).cloned()
                    else {
                        panic!("import state")
                    };
                    let _ = metadata.put(
                        key(IMPORTED_PREFIX, 0, 0),
                        Value::ImportedValidator(ImportedValidator {
                            acknowledged: None,
                            ..imported
                        }),
                    );
                }),
                ("history removed", |metadata| {
                    let Some(Value::ImportedValidator(imported)) =
                        metadata.get(&key(IMPORTED_PREFIX, 0, 0)).cloned()
                    else {
                        panic!("import state")
                    };
                    let _ = metadata.put(
                        key(IMPORTED_PREFIX, 0, 0),
                        Value::ImportedValidator(ImportedValidator {
                            chain: None,
                            ..imported
                        }),
                    );
                }),
                ("imported ceremony replaced by a DKG one", |metadata| {
                    let Some(Value::ImportedCeremony(ceremony)) =
                        metadata.get(&key(CEREMONY_PREFIX, 0, 0)).cloned()
                    else {
                        panic!("imported ceremony")
                    };
                    // Same id and round, no key: the validator no longer matches a ceremony key.
                    let _ = metadata.put(
                        key(CEREMONY_PREFIX, 0, 0),
                        Value::Ceremony(Box::new(Ceremony {
                            origin: crate::dkg::ceremony::Origin::Dkg,
                            status: DkgStatus::Failed,
                            ..*ceremony
                        })),
                    );
                }),
            ];
            deterministic::Runner::default().start(|mut context| async move {
                let signers = signers();
                let committee = committee(&signers);
                for (case, tamper) in cases {
                    let prefix = case.replace(' ', "-");
                    let mut store = Store::init(context.child("store"), &prefix, committee.clone())
                        .await
                        .unwrap();
                    activated(&mut context, &mut store, &signers).await;
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
                    tamper(&mut metadata);
                    metadata.sync().await.unwrap();
                    match Store::init(context.child("restart"), &prefix, committee.clone()).await {
                        Err(Error::Slashing(reason)) => println!("{case}: {reason}"),
                        Err(other) => panic!("{case}: unexpected error {other}"),
                        Ok(_) => panic!("{case}: a store with altered import state started"),
                    }
                }
            });
        }
    }

    mod reshare {
        use super::*;
        use crate::{
            dkg::{
                Faults,
                ceremony::{
                    AbortOutcome, GenerationOutcome, GenerationRefusal, ReadyAck, ReshareOutcome,
                    tests::reshare::deal_reshare,
                },
            },
            import::dealer,
            slashing::Floors,
        };
        use commonware_cryptography::Signer as _;
        use commonware_cryptography::bls12381::primitives::group::{Private, Scalar, Share};
        use commonware_parallel::Sequential;
        use commonware_utils::ordered::Quorum as _;
        use rand::{SeedableRng as _, rngs::StdRng};

        fn start(key: ValidatorKey, name: &str) -> Transaction {
            tx(Command::StartResharing {
                validator: key,
                ceremony: id(name),
                membership: None,
            })
        }

        fn activate_generation(key: ValidatorKey, round: u64) -> Transaction {
            tx(Command::ActivateGeneration {
                validator: key,
                round,
            })
        }

        fn abort(key: ValidatorKey, round: u64) -> Transaction {
            tx(Command::AbortResharing {
                validator: key,
                round,
            })
        }

        fn ready(signer: &PrivateKey, ceremony: &Ceremony) -> Transaction {
            tx(Command::ShareReady(Box::new(ReadyAck::sign(
                signer,
                ceremony.round,
                ceremony.session,
            ))))
        }

        /// An activated DKG validator key (round 0, heights 1 to 3) and every node's share of it,
        /// by node.
        async fn active_dkg_validator<E: Context + CryptoRng>(
            context: &mut E,
            store: &mut Store<E>,
            signers: &[PrivateKey],
        ) -> (ValidatorKey, Vec<Share>) {
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
            let (players, logs) = deal(context, &applied.changed[0], signers, &[]);
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
            let ceremony = applied.changed[0].clone();
            let key = group_key(&ceremony).unwrap();
            let shares = players
                .into_iter()
                .map(|player| {
                    player
                        .finalize::<Faults>(context, ceremony.logs(), &Sequential)
                        .unwrap()
                        .1
                })
                .collect();
            store
                .apply_block(3, &block, &[activate(key, 9)], context)
                .await
                .unwrap();
            (key, shares)
        }

        /// Complete the reshare `round` at `height` with every dealer's log (each dealing its
        /// `shares`, by node). Returns the completed ceremony.
        async fn complete<E: Context + CryptoRng>(
            context: &mut E,
            store: &mut Store<E>,
            signers: &[PrivateKey],
            round: u64,
            shares: &[Share],
            height: u64,
        ) -> Ceremony {
            let block = Sha256::hash(&[b"block"]);
            let started = store.ceremonies().by_round(round).unwrap().clone();
            let (_, logs) = deal_reshare(context, &started, signers, shares, &[]);
            let logs: Vec<_> = logs
                .into_iter()
                .map(|log| {
                    tx(Command::DealerLog {
                        round,
                        log: Box::new(log),
                    })
                })
                .collect();
            let applied = store
                .apply_block(height, &block, &logs, context)
                .await
                .unwrap();
            let ceremony = applied
                .changed
                .iter()
                .find(|ceremony| ceremony.round == round)
                .unwrap()
                .clone();
            assert_eq!(ceremony.status, DkgStatus::Completed);
            ceremony
        }

        /// A DKG validator key is reshared through consensus: one reshare at a time, activated
        /// only once completed and every new share acknowledged, then the key signs with the new
        /// generation and keeps its whole history (the same refusals before and after), its
        /// activation and its identity. Aborts, the generation states and a restart.
        #[test]
        fn a_reshared_key_keeps_its_history_and_activates_only_when_ready() {
            deterministic::Runner::default().start(|mut context| async move {
                let signers = signers();
                let committee = committee(&signers);
                let block = Sha256::hash(&[b"block"]);
                let mut store = Store::init(context.child("first"), "node", committee.clone())
                    .await
                    .unwrap();
                let (key, shares0) = active_dkg_validator(&mut context, &mut store, &signers).await;
                let (validator_id, before) = store.protection().validator_of(&key).unwrap();
                let activation = before.activation;

                // Generation 0 signs.
                let signed = [
                    propose(key, 10, 1),
                    attestation(key, 1, 2),
                    attestation(key, 2, 5),
                ];
                let applied = store
                    .apply_block(
                        4,
                        &block,
                        &signed.iter().map(submit).collect::<Vec<_>>(),
                        &mut context,
                    )
                    .await
                    .unwrap();
                for effect in &applied.effects {
                    assert!(
                        matches!(effect, Effect::Duty(Decision::Accepted, _)),
                        "{effect:?}"
                    );
                }

                // Start: once; the same again is idempotent; another is pending; unknown key.
                let applied = store
                    .apply_block(
                        5,
                        &block,
                        &[
                            start(key, "v-g1"),
                            start(key, "v-g1"),
                            start(key, "v-g1b"),
                            start([0xaa; 48], "v-other"),
                            activate_generation(key, 1),
                        ],
                        &mut context,
                    )
                    .await
                    .unwrap();
                assert_eq!(
                    applied.effects,
                    vec![
                        Effect::Reshare(ReshareOutcome::Started(1)),
                        Effect::Reshare(ReshareOutcome::Exists(1)),
                        Effect::Reshare(ReshareOutcome::Pending(1)),
                        Effect::Reshare(ReshareOutcome::UnknownValidator),
                        Effect::Generation(GenerationOutcome::Refused(
                            GenerationRefusal::NotCompleted
                        )),
                    ]
                );
                assert_eq!(applied.designated, vec![1]);

                // Generation 0 keeps signing while the reshare runs.
                let applied = store
                    .apply_block(6, &block, &[submit(&propose(key, 11, 1))], &mut context)
                    .await
                    .unwrap();
                assert_eq!(applied.duties[0].round, 0);

                let g1 = complete(&mut context, &mut store, &signers, 1, &shares0, 7).await;
                assert_eq!(
                    g1.public_key(),
                    store.ceremonies().by_round(0).unwrap().public_key()
                );
                assert_eq!(store.protection().validator_of(&key).unwrap().1.round, 0);

                // Activation: every new share must be acknowledged.
                let applied = store
                    .apply_block(
                        8,
                        &block,
                        &[
                            activate_generation(key, 1),
                            ready(&signers[0], &g1),
                            ready(&signers[1], &g1),
                            ready(&signers[2], &g1),
                            activate_generation(key, 1),
                        ],
                        &mut context,
                    )
                    .await
                    .unwrap();
                assert_eq!(
                    applied.effects[0],
                    Effect::Generation(GenerationOutcome::Refused(GenerationRefusal::NotReady {
                        ready: 0,
                        required: 4
                    }))
                );
                assert_eq!(
                    applied.effects[4],
                    Effect::Generation(GenerationOutcome::Refused(GenerationRefusal::NotReady {
                        ready: 3,
                        required: 4
                    }))
                );
                let applied = store
                    .apply_block(
                        9,
                        &block,
                        &[
                            ready(&signers[3], &g1),
                            activate_generation(key, 1),
                            activate_generation(key, 1),
                            abort(key, 1),
                        ],
                        &mut context,
                    )
                    .await
                    .unwrap();
                assert_eq!(
                    applied.effects[1..],
                    [
                        Effect::Generation(GenerationOutcome::Activated { from: 0 }),
                        Effect::Generation(GenerationOutcome::AlreadyActive),
                        Effect::Abort(AbortOutcome::Refused(GenerationRefusal::Active)),
                    ]
                );
                assert_eq!(applied.generations, vec![(key, 1)]);
                let (id_after, after) = store.protection().validator_of(&key).unwrap();
                assert_eq!(
                    (id_after, after.round, after.activation),
                    (validator_id, 1, activation)
                );

                // The same history: conflicts refused exactly as before, repeats idempotent, new
                // duties authorized for generation 1.
                let cases = [
                    (
                        propose(key, 10, 2),
                        Decision::Refused(Refusal::DoubleProposal { slot: 10 }),
                    ),
                    (propose(key, 10, 1), Decision::AlreadyAccepted),
                    (
                        {
                            let mut request = attestation(key, 1, 2);
                            if let Duty::Attestation(data) = &mut request.duty {
                                data.beacon_block_root = [9; 32];
                            }
                            request
                        },
                        Decision::Refused(Refusal::DoubleVote { target: 2 }),
                    ),
                    (
                        attestation(key, 0, 6),
                        Decision::Refused(Refusal::SurroundsSigned {
                            source_epoch: 2,
                            target_epoch: 5,
                        }),
                    ),
                    (
                        attestation(key, 3, 4),
                        Decision::Refused(Refusal::SurroundedBySigned {
                            source_epoch: 2,
                            target_epoch: 5,
                        }),
                    ),
                    (propose(key, 12, 1), Decision::Accepted),
                ];
                let applied = store
                    .apply_block(
                        10,
                        &block,
                        &cases
                            .iter()
                            .map(|(request, _)| submit(request))
                            .collect::<Vec<_>>(),
                        &mut context,
                    )
                    .await
                    .unwrap();
                for ((request, expected), effect) in cases.iter().zip(&applied.effects) {
                    assert_eq!(*effect, Effect::Duty(*expected, request.signing_root()));
                }
                assert!(applied.duties.iter().all(|duty| duty.round == 1));

                // A second reshare, from generation 1, aborted; activation of it refused; a third.
                let applied = store
                    .apply_block(
                        11,
                        &block,
                        &[
                            start(key, "v-g2"),
                            abort(key, 2),
                            abort(key, 2),
                            activate_generation(key, 2),
                            start(key, "v-g3"),
                            abort(key, 0),
                        ],
                        &mut context,
                    )
                    .await
                    .unwrap();
                assert_eq!(
                    applied.effects,
                    vec![
                        Effect::Reshare(ReshareOutcome::Started(2)),
                        Effect::Abort(AbortOutcome::Aborted),
                        Effect::Abort(AbortOutcome::AlreadyAborted),
                        Effect::Generation(GenerationOutcome::Refused(GenerationRefusal::Aborted)),
                        Effect::Reshare(ReshareOutcome::Started(3)),
                        Effect::Abort(AbortOutcome::Refused(GenerationRefusal::NotReshare)),
                    ]
                );
                let before = (
                    store.protection().clone(),
                    store.ceremonies().iter().cloned().collect::<Vec<_>>(),
                );
                drop(store);

                // Restart: a retired generation (0), the active one (1), an aborted reshare (2), one
                // in progress (3): the same state, verified.
                let store = Store::init(context.child("second"), "node", committee.clone())
                    .await
                    .unwrap();
                assert_eq!(store.protection(), &before.0);
                assert_eq!(
                    store.ceremonies().iter().cloned().collect::<Vec<_>>(),
                    before.1
                );
                assert_eq!(store.protection().validator_of(&key).unwrap().1.round, 1);
            });
        }

        /// R2 through consensus: the key of A, B, C, D is reshared by A, B, C to A, B, C, E. D's
        /// acknowledgement does not count (it holds no share of the new generation), E's is
        /// required; the key activates the new generation with its whole history and activation;
        /// a start naming the retired generation is stale; the state restarts verified, with the
        /// reshare's dealers.
        #[test]
        fn a_replaced_keyholder_holds_the_new_generation_through_consensus() {
            use crate::dkg::ceremony::{ReadyIgnored, tests::reshare::replace};
            deterministic::Runner::default().start(|mut context| async move {
                let signers = signers();
                let committee = committee(&signers);
                let block = Sha256::hash(&[b"block"]);
                let mut store = Store::init(context.child("first"), "node", committee.clone())
                    .await
                    .unwrap();
                let (key, shares0) = active_dkg_validator(&mut context, &mut store, &signers).await;
                let (validator_id, before) = store.protection().validator_of(&key).unwrap();
                let activation = before.activation;
                store
                    .apply_block(
                        4,
                        &block,
                        &[
                            submit(&propose(key, 10, 1)),
                            submit(&attestation(key, 2, 5)),
                        ],
                        &mut context,
                    )
                    .await
                    .unwrap();

                let membership = replace::membership(&signers, 0);
                let start = |name: &str, membership: &crate::dkg::ceremony::Membership| {
                    tx(Command::StartResharing {
                        validator: key,
                        ceremony: id(name),
                        membership: Some(Box::new(membership.clone())),
                    })
                };
                let applied = store
                    .apply_block(
                        5,
                        &block,
                        &[start("v-r2", &membership), start("v-r2", &membership)],
                        &mut context,
                    )
                    .await
                    .unwrap();
                assert_eq!(
                    applied.effects,
                    vec![
                        Effect::Reshare(ReshareOutcome::Started(1)),
                        Effect::Reshare(ReshareOutcome::Exists(1)),
                    ]
                );
                let started = store.ceremonies().by_round(1).unwrap().clone();
                let players = replace::new_keyholders(&signers);
                let dealers: Vec<(PrivateKey, Share)> = (0..3)
                    .map(|node| (signers[node].clone(), shares0[node].clone()))
                    .collect();
                let (_, logs) =
                    replace::deal_replacement(&mut context, &started, &dealers, &players);
                let logs: Vec<_> = logs
                    .into_iter()
                    .map(|log| {
                        tx(Command::DealerLog {
                            round: 1,
                            log: Box::new(log),
                        })
                    })
                    .collect();
                let applied = store
                    .apply_block(6, &block, &logs, &mut context)
                    .await
                    .unwrap();
                let g1 = applied
                    .changed
                    .iter()
                    .find(|ceremony| ceremony.round == 1)
                    .unwrap()
                    .clone();
                assert_eq!(g1.status, DkgStatus::Completed);
                assert_eq!(
                    g1.public_key(),
                    store.ceremonies().by_round(0).unwrap().public_key()
                );

                // D's acknowledgement is ignored; A, B and C are not enough.
                let applied = store
                    .apply_block(
                        7,
                        &block,
                        &[
                            ready(&signers[3], &g1),
                            ready(&signers[0], &g1),
                            ready(&signers[1], &g1),
                            ready(&signers[2], &g1),
                            activate_generation(key, 1),
                        ],
                        &mut context,
                    )
                    .await
                    .unwrap();
                assert_eq!(
                    applied.effects[0],
                    Effect::Ready(Err(ReadyIgnored::NotParticipant))
                );
                assert_eq!(
                    applied.effects[4],
                    Effect::Generation(GenerationOutcome::Refused(GenerationRefusal::NotReady {
                        ready: 3,
                        required: 4
                    }))
                );
                let applied = store
                    .apply_block(
                        8,
                        &block,
                        &[
                            ready(&replace::replacement(), &g1),
                            activate_generation(key, 1),
                        ],
                        &mut context,
                    )
                    .await
                    .unwrap();
                assert_eq!(
                    applied.effects[1],
                    Effect::Generation(GenerationOutcome::Activated { from: 0 })
                );
                let (id_after, after) = store.protection().validator_of(&key).unwrap();
                assert_eq!(
                    (id_after, after.round, after.activation),
                    (validator_id, 1, activation)
                );

                // The same history; a start naming the retired generation is stale.
                let applied = store
                    .apply_block(
                        9,
                        &block,
                        &[
                            submit(&propose(key, 10, 2)),
                            submit(&attestation(key, 1, 6)),
                            start("v-r2b", &membership),
                        ],
                        &mut context,
                    )
                    .await
                    .unwrap();
                assert!(matches!(
                    applied.effects[0],
                    Effect::Duty(Decision::Refused(Refusal::DoubleProposal { slot: 10 }), _)
                ));
                assert!(matches!(
                    applied.effects[1],
                    Effect::Duty(Decision::Refused(Refusal::SurroundsSigned { .. }), _)
                ));
                assert_eq!(
                    applied.effects[2],
                    Effect::Reshare(ReshareOutcome::Stale { from: 0, active: 1 })
                );

                let before = store.ceremonies().iter().cloned().collect::<Vec<_>>();
                drop(store);
                let store = Store::init(context.child("second"), "node", committee.clone())
                    .await
                    .unwrap();
                assert_eq!(
                    store.ceremonies().iter().cloned().collect::<Vec<_>>(),
                    before
                );
                assert_eq!(
                    store.ceremonies().by_round(1).unwrap().dealers(),
                    &membership.dealers
                );
                assert_eq!(store.protection().validator_of(&key).unwrap().1.round, 1);
            });
        }

        /// An imported key is reshared through the same protocol; its imported floors, chain and
        /// import state stay, and imports stay refused.
        #[test]
        fn an_imported_key_reshares_and_keeps_its_floors() {
            deterministic::Runner::default().start(|mut context| async move {
                let signers = signers();
                let committee = committee(&signers);
                let block = Sha256::hash(&[b"block"]);
                let mut store = Store::init(context.child("first"), "node", committee.clone())
                    .await
                    .unwrap();
                let key = super::imported::activated(&mut context, &mut store, &signers).await;
                let (validator_id, _) = store.protection().validator_of(&key).unwrap();
                let imported = *store.protection().imported(validator_id).unwrap();
                // The split behind the manifest (seed 1), shares by node.
                let split = dealer::split(
                    &Private::new(Scalar::from_u64(1001)),
                    &committee,
                    &mut StdRng::seed_from_u64(1),
                )
                .unwrap();
                let shares: Vec<Share> = signers
                    .iter()
                    .map(|signer| {
                        let index = committee.index(&signer.public_key()).unwrap();
                        split
                            .shares
                            .iter()
                            .find(|share| share.index == index)
                            .unwrap()
                            .clone()
                    })
                    .collect();

                let applied = store
                    .apply_block(5, &block, &[start(key, "imported-g1")], &mut context)
                    .await
                    .unwrap();
                assert_eq!(
                    applied.effects,
                    vec![Effect::Reshare(ReshareOutcome::Started(1))]
                );
                let g1 = complete(&mut context, &mut store, &signers, 1, &shares, 6).await;
                let mut transactions: Vec<_> =
                    signers.iter().map(|signer| ready(signer, &g1)).collect();
                transactions.push(activate_generation(key, 1));
                let applied = store
                    .apply_block(7, &block, &transactions, &mut context)
                    .await
                    .unwrap();
                assert_eq!(
                    applied.effects[4],
                    Effect::Generation(GenerationOutcome::Activated { from: 0 })
                );

                // Same import state (floors, chain, import round 0), refusals by the floors, no
                // import accepted.
                assert_eq!(
                    *store.protection().imported(validator_id).unwrap(),
                    imported
                );
                assert_eq!(
                    imported.floors,
                    Floors {
                        block: Some(100),
                        attestation: Some((10, 11))
                    }
                );
                let applied = store
                    .apply_block(
                        8,
                        &block,
                        &[
                            submit(&propose(key, 100, 1)),
                            submit(&attestation(key, 10, 11)),
                            submit(&propose(key, 101, 1)),
                            super::imported::history(key, 9, 50, 1, 2),
                        ],
                        &mut context,
                    )
                    .await
                    .unwrap();
                assert!(matches!(
                    applied.effects[0],
                    Effect::Duty(Decision::Refused(Refusal::BlockAtOrBelowImported { .. }), _)
                ));
                assert!(matches!(
                    applied.effects[1],
                    Effect::Duty(
                        Decision::Refused(Refusal::TargetAtOrBelowImported { .. }),
                        _
                    )
                ));
                assert!(matches!(
                    applied.effects[2],
                    Effect::Duty(Decision::Accepted, _)
                ));
                assert!(matches!(
                    applied.effects[3],
                    Effect::History(HistoryOutcome::Refused(
                        crate::slashing::HistoryRefusal::Activated { .. }
                    ))
                ));
                assert_eq!(applied.duties[0].round, 1);
                drop(store);
                let store = Store::init(context.child("second"), "node", committee)
                    .await
                    .unwrap();
                assert_eq!(
                    *store.protection().imported(validator_id).unwrap(),
                    imported
                );
                assert_eq!(store.protection().validator_of(&key).unwrap().1.round, 1);
            });
        }
    }
}

fn epoch_key(seed: u64) -> PublicKey {
    use commonware_cryptography::Signer as _;
    commonware_cryptography::ed25519::PrivateKey::from_seed(seed).public_key()
}

fn epoch_committee(seeds: [u64; 4]) -> Set<PublicKey> {
    use commonware_utils::TryCollect as _;
    seeds.map(epoch_key).into_iter().try_collect().unwrap()
}

fn reconfigure(epoch: u64, remove: u64, add: u64) -> Transaction {
    tx(Command::Reconfigure(Box::new(
        crate::types::Reconfiguration {
            epoch,
            remove: epoch_key(remove),
            add: epoch_key(add),
        },
    )))
}

/// A reconfiguration is committed with its block as the next consensus epoch, which the state
/// restores on restart; the original committee must lead to it.
#[test]
fn a_reconfiguration_commits_the_next_epoch() {
    deterministic::Runner::default().start(|mut context| async move {
        let committee = epoch_committee([0, 1, 2, 3]);
        let mut store = Store::init(context.child("first"), "node", committee.clone())
            .await
            .unwrap();
        assert_eq!(store.epochs().current().epoch, 0);
        store
            .apply_block(1, &Sha256::hash(&[b"one"]), &[sign(1, 1)], &mut context)
            .await
            .unwrap();
        let boundary = Sha256::hash(&[b"two"]);
        let applied = store
            .apply_block(2, &boundary, &[reconfigure(1, 3, 4)], &mut context)
            .await
            .unwrap();
        let record = applied.reconfigured.clone().unwrap();
        assert_eq!(
            applied.effects,
            vec![Effect::Reconfigure(Box::new(record.clone()))]
        );
        assert_eq!(
            (record.epoch, record.boundary, record.boundary_digest),
            (1, 2, boundary)
        );
        assert_eq!(record.committee, epoch_committee([0, 1, 2, 4]));
        assert_eq!(store.epochs().current(), &record);
        drop(store);

        let store = Store::init(context.child("second"), "node", committee.clone())
            .await
            .unwrap();
        assert_eq!(store.height(), 2);
        assert_eq!(store.epochs().current(), &record);
        assert_eq!(store.epochs().get(0).unwrap().committee, committee);
        drop(store);

        // Another original committee (a wrong --participants) does not lead to epoch 1.
        let refused = Store::init(
            context.child("third"),
            "node",
            epoch_committee([0, 1, 2, 5]),
        )
        .await;
        assert!(matches!(refused, Err(Error::Epochs(_))));
    });
}

/// The committee finalizes only a reconfiguration that follows the rules (`application`): one
/// that does not means this node's state is not the committee's, and it stops.
#[test]
#[should_panic(expected = "invalid reconfiguration")]
fn a_finalized_invalid_reconfiguration_stops_the_node() {
    deterministic::Runner::default().start(|mut context| async move {
        let mut store = Store::init(
            context.child("store"),
            "node",
            epoch_committee([0, 1, 2, 3]),
        )
        .await
        .unwrap();
        let _ = store
            .apply_block(
                1,
                &Sha256::hash(&[b"one"]),
                &[reconfigure(2, 3, 4)],
                &mut context,
            )
            .await;
    });
}

#[test]
#[should_panic(expected = "with other transactions")]
fn a_finalized_reconfiguration_with_company_stops_the_node() {
    deterministic::Runner::default().start(|mut context| async move {
        let mut store = Store::init(
            context.child("store"),
            "node",
            epoch_committee([0, 1, 2, 3]),
        )
        .await
        .unwrap();
        let _ = store
            .apply_block(
                1,
                &Sha256::hash(&[b"one"]),
                &[sign(1, 1), reconfigure(1, 3, 4)],
                &mut context,
            )
            .await;
    });
}

#[path = "storage_model.rs"]
mod model;
