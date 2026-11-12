//! A model test of the replicated state (`storage`, `slashing`), and hostile storage: a child
//! module of `storage::tests`.
//!
//! Every seed starts from two DKG validator keys and an imported key (with a random EIP-3076
//! history), activated for [CHAIN], then applies random blocks of validator duties: proposals,
//! attestations (double and surround votes in both directions are frequent), bounded duties, PTC
//! votes; of an unknown key and for another chain too. After every block:
//!
//! 1. each decision matches an independent, deliberately simple model of the rules
//!    ([Reference]: full lists, no ordered-neighbour shortcut), up to the refusal's details;
//! 2. a replica applying the same blocks, closed and reopened at random heights, decides the same
//!    and passes `Protection::verify`;
//!
//! and at the end nothing slashable was ever accepted, checked pairwise over everything accepted.
//!
//! Hostile storage: after a seed's history, single random edits of the state partition (an entry
//! removed, a value mutated, another entry's value copied over it, an entry duplicated under a
//! neighbouring key). Every removed or duplicated record stops the store at start (a removed
//! metadata entry may change nothing). A record whose content is rewritten consistently (an
//! attestation's source lowered, within the order of its neighbours) can start, and then accept
//! what the intact store refused: one node's state is not authenticated, and consensus tolerates
//! one such node (audit L-30). The test counts those, and fails on any other path to them.
//!
//! `MODEL_SEEDS=<n>` and `HOSTILE_SEEDS=<n>` run more seeds; `MODEL_SEED=<k>` runs one.
//! Builder registrations, envelopes, exits and deposits (policy and approval bound) are covered by
//! the example tests of `storage::tests::validator`.

use super::validator::imported::{ACKNOWLEDGED, activate_imported, history, manifest};
use super::*;
use crate::{
    dkg::{CeremonyId, ceremony::ReadyAck},
    eth::{
        duty::{
            Duty, DutyKind, DutyRequest, Fork, ForkInfo, MAX_ROOTS_PER_PERIOD, MAX_SLOT_MESSAGES,
        },
        gloas::PayloadAttestationData,
        types::{AttestationData, BeaconBlockHeader, Checkpoint, SyncAggregatorSelectionData},
    },
    slashing::{ChainIdentity, Decision, Refusal},
};
use commonware_codec::DecodeExt as _;
use commonware_storage::metadata::Metadata;
use rand::{RngExt as _, SeedableRng as _, rngs::StdRng};
use std::{collections::BTreeMap, mem::discriminant};

/// The chain every key is activated for, and another one.
const CHAIN: u8 = 9;
const OTHER_CHAIN: u8 = 8;
/// Blocks of random duties per seed.
const BLOCKS: usize = 24;
/// The height of the imported key's history (the seed's), between the genesis blocks.
const HISTORY_HEIGHT: u64 = 4;
/// The first height of random duties.
const FIRST: u64 = 8;

fn seeds(variable: &str, default: u64) -> std::ops::Range<u64> {
    if let Some(seed) = std::env::var("MODEL_SEED")
        .ok()
        .and_then(|seed| seed.parse().ok())
    {
        return seed..seed + 1;
    }
    0..std::env::var(variable)
        .ok()
        .and_then(|seeds| seeds.parse().ok())
        .unwrap_or(default)
}

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

fn chain(genesis: u8) -> ChainIdentity {
    ChainIdentity {
        genesis_validators_root: [genesis; 32],
    }
}

/// The blocks every seed starts from, but the imported key's history ([HISTORY_HEIGHT]).
struct Genesis {
    blocks: Vec<(u64, Vec<Transaction>)>,
    /// The DKG keys and the imported key.
    keys: Vec<ValidatorKey>,
    imported: ValidatorKey,
}

/// The store of partition prefix `name`, opened.
async fn open(context: &deterministic::Context, name: &str) -> Store<deterministic::Context> {
    Store::init(context.child("model"), name, committee(&signers()))
        .await
        .unwrap()
}

/// Apply `transactions` at `height`, and keep them in `blocks`.
async fn apply(
    store: &mut Store<deterministic::Context>,
    context: &mut deterministic::Context,
    blocks: &mut Vec<(u64, Vec<Transaction>)>,
    height: u64,
    transactions: Vec<Transaction>,
) -> Applied {
    let applied = store
        .apply_block(height, &Sha256::hash(&[b"block"]), &transactions, context)
        .await
        .unwrap();
    blocks.push((height, transactions));
    applied
}

/// Two validator ceremonies (heights 1 and 2), an imported key registered (3), acknowledged (5)
/// and activated (6), and the DKG keys activated (7); checked once on a store of its own.
async fn genesis(context: &mut deterministic::Context) -> Genesis {
    let signers = signers();
    let committee = committee(&signers);
    let block = Sha256::hash(&[b"block"]);
    let mut store = open(context, "genesis").await;
    let mut blocks = Vec::new();
    let start = ["m1", "m2"]
        .into_iter()
        .map(|id| {
            tx(Command::StartValidatorCeremony(CeremonyConfig::new(
                CeremonyId::new(id).unwrap(),
                committee.clone(),
            )))
        })
        .collect();
    let started = apply(&mut store, context, &mut blocks, 1, start)
        .await
        .changed;
    let mut logs = Vec::new();
    for ceremony in &started {
        let (_, dealt) = deal(context, ceremony, &signers, &[]);
        logs.extend(dealt.into_iter().map(|log| {
            tx(Command::DealerLog {
                round: ceremony.round,
                log: Box::new(log),
            })
        }));
    }
    let completed = apply(&mut store, context, &mut blocks, 2, logs)
        .await
        .changed;
    let keys: Vec<ValidatorKey> = completed
        .iter()
        .map(|ceremony| group_key(ceremony).unwrap())
        .collect();
    assert_eq!(keys.len(), 2);

    let manifest = manifest("imported", &committee, 1);
    let imported = manifest.validator;
    apply(
        &mut store,
        context,
        &mut blocks,
        3,
        vec![tx(Command::RegisterImportedKey(Box::new(manifest.clone())))],
    )
    .await;
    let (_, registered) = store.protection().validator_of(&imported).unwrap();
    let round = registered.round;
    store
        .apply_block(
            HISTORY_HEIGHT,
            &block,
            &[history(imported, CHAIN, 3, 1, 2)],
            context,
        )
        .await
        .unwrap();
    let acknowledgements = signers[..3]
        .iter()
        .map(|signer| {
            tx(Command::ShareReady(Box::new(ReadyAck::sign(
                signer,
                round,
                manifest.digest(),
            ))))
        })
        .collect();
    apply(&mut store, context, &mut blocks, 5, acknowledgements).await;
    apply(
        &mut store,
        context,
        &mut blocks,
        6,
        vec![activate_imported(imported, CHAIN, ACKNOWLEDGED)],
    )
    .await;
    let activations = keys
        .iter()
        .map(|key| {
            tx(Command::ActivateValidator {
                validator: *key,
                chain: chain(CHAIN),
            })
        })
        .collect();
    apply(&mut store, context, &mut blocks, 7, activations).await;
    for key in keys.iter().chain([&imported]) {
        let (_, validator) = store.protection().validator_of(key).unwrap();
        assert!(
            validator.activation.is_some(),
            "genesis activates every key"
        );
    }
    let mut all = keys;
    all.push(imported);
    Genesis {
        blocks,
        keys: all,
        imported,
    }
}

/// An imported history's floors: the latest block slot, and the attestation's source and target.
#[derive(Clone, Copy, Debug)]
struct Floors {
    block: u64,
    source: u64,
    target: u64,
}

/// A random duty of one of `keys` (or of an unknown key), mostly for [CHAIN].
fn random_duty(rng: &mut StdRng, keys: &[ValidatorKey]) -> DutyRequest {
    let validator = if rng.random_ratio(1, 30) {
        [0x77; 48]
    } else {
        keys[rng.random_range(0..keys.len())]
    };
    let genesis = if rng.random_ratio(1, 30) {
        OTHER_CHAIN
    } else {
        CHAIN
    };
    let duty = match rng.random_range(0..12) {
        0..=3 => Duty::BlockProposal(BeaconBlockHeader {
            slot: rng.random_range(0..16),
            proposer_index: 5,
            parent_root: [1; 32],
            state_root: [2; 32],
            body_root: [rng.random_range(0..3u8); 32],
        }),
        4..=7 => {
            let target = rng.random_range(0..12u64);
            // Sometimes after the target (never signable).
            let source = rng.random_range(target.saturating_sub(5)..=target + 1);
            Duty::Attestation(AttestationData {
                slot: target * 32,
                index: 0,
                beacon_block_root: [rng.random_range(0..3u8); 32],
                source: Checkpoint {
                    epoch: source,
                    root: [3; 32],
                },
                target: Checkpoint {
                    epoch: target,
                    root: [4; 32],
                },
            })
        }
        8 => Duty::RandaoReveal {
            epoch: rng.random_range(0..4),
        },
        // Few slots, many roots: the per-period limit is reached.
        9 => Duty::SyncCommitteeMessage {
            beacon_block_root: [rng.random_range(0..12u8); 32],
            slot: rng.random_range(0..3),
        },
        10 => {
            if rng.random_bool(0.5) {
                Duty::AggregationSlot {
                    slot: rng.random_range(0..4),
                }
            } else {
                Duty::SyncSelectionProof(SyncAggregatorSelectionData {
                    slot: rng.random_range(0..4),
                    subcommittee_index: rng.random_range(0..12),
                })
            }
        }
        _ => Duty::PayloadAttestation(PayloadAttestationData {
            beacon_block_root: [rng.random_range(0..2u8); 32],
            slot: rng.random_range(0..6),
            payload_present: rng.random_bool(0.5),
            blob_data_available: true,
        }),
    };
    DutyRequest {
        validator,
        fork: fork(genesis),
        duty,
    }
}

/// One validator in [Reference]: what it signed, in full.
#[derive(Clone, Debug, Default)]
struct Signed {
    floors: Option<Floors>,
    blocks: BTreeMap<u64, Root>,
    /// Target to source and root.
    attestations: BTreeMap<u64, (u64, Root)>,
    bounded: BTreeMap<(DutyKind, u64), Vec<Root>>,
}

/// The rules, written again from EIP-3076 and the module docs of `slashing`, without its data
/// structures or shortcuts. Refusals carry placeholder details: only their kind is compared.
#[derive(Clone, Debug, Default)]
struct Reference {
    validators: BTreeMap<ValidatorKey, Signed>,
}

impl Reference {
    fn new(keys: &[ValidatorKey], imported: ValidatorKey, floors: Floors) -> Self {
        let mut validators: BTreeMap<_, Signed> =
            keys.iter().map(|key| (*key, Signed::default())).collect();
        validators.get_mut(&imported).unwrap().floors = Some(floors);
        Self { validators }
    }

    fn decide(&mut self, request: &DutyRequest) -> Decision {
        use Decision::{Accepted, AlreadyAccepted, Refused};
        let Some(signed) = self.validators.get_mut(&request.validator) else {
            return Refused(Refusal::UnknownValidator);
        };
        if let Duty::Attestation(data) = &request.duty
            && data.source.epoch > data.target.epoch
        {
            return Refused(Refusal::SourceAfterTarget {
                source_epoch: 0,
                target_epoch: 0,
            });
        }
        if request.fork.genesis_validators_root != [CHAIN; 32] {
            return Refused(Refusal::OtherChain);
        }
        let root = request.signing_root();
        match &request.duty {
            Duty::BlockProposal(header) => {
                let slot = header.slot;
                match signed.blocks.get(&slot) {
                    Some(signed_root) if *signed_root == root => AlreadyAccepted,
                    _ if signed.floors.is_some_and(|floors| slot <= floors.block) => {
                        Refused(Refusal::BlockAtOrBelowImported { slot: 0, floor: 0 })
                    }
                    Some(_) => Refused(Refusal::DoubleProposal { slot: 0 }),
                    None => {
                        signed.blocks.insert(slot, root);
                        Accepted
                    }
                }
            }
            Duty::Attestation(data) => {
                let (source, target) = (data.source.epoch, data.target.epoch);
                if signed
                    .attestations
                    .get(&target)
                    .is_some_and(|(_, signed_root)| *signed_root == root)
                {
                    return AlreadyAccepted;
                }
                if let Some(floors) = signed.floors {
                    if source < floors.source {
                        return Refused(Refusal::SourceBelowImported {
                            source_epoch: 0,
                            floor: 0,
                        });
                    }
                    if target <= floors.target {
                        return Refused(Refusal::TargetAtOrBelowImported {
                            target_epoch: 0,
                            floor: 0,
                        });
                    }
                }
                if signed.attestations.contains_key(&target) {
                    return Refused(Refusal::DoubleVote { target: 0 });
                }
                // Every signed attestation, not only the nearest ones.
                if signed
                    .attestations
                    .iter()
                    .any(|(&other_target, &(other_source, _))| {
                        other_target < target && other_source > source
                    })
                {
                    return Refused(Refusal::SurroundsSigned {
                        source_epoch: 0,
                        target_epoch: 0,
                    });
                }
                if signed
                    .attestations
                    .iter()
                    .any(|(&other_target, &(other_source, _))| {
                        other_target > target && other_source < source
                    })
                {
                    return Refused(Refusal::SurroundedBySigned {
                        source_epoch: 0,
                        target_epoch: 0,
                    });
                }
                signed.attestations.insert(target, (source, root));
                Accepted
            }
            duty => {
                let (kind, period, limit) = match duty {
                    Duty::RandaoReveal { epoch } => {
                        (DutyKind::RandaoReveal, *epoch, MAX_ROOTS_PER_PERIOD)
                    }
                    Duty::SyncCommitteeMessage { slot, .. } => {
                        (DutyKind::SyncCommitteeMessage, *slot, MAX_ROOTS_PER_PERIOD)
                    }
                    Duty::AggregationSlot { slot } => {
                        (DutyKind::AggregationSlot, *slot, MAX_ROOTS_PER_PERIOD)
                    }
                    Duty::SyncSelectionProof(data) => (
                        DutyKind::SyncSelectionProof,
                        data.slot,
                        MAX_ROOTS_PER_PERIOD,
                    ),
                    Duty::PayloadAttestation(data) => {
                        (DutyKind::PayloadAttestation, data.slot, MAX_SLOT_MESSAGES)
                    }
                    other => panic!("the generator makes no {other:?}"),
                };
                let roots = signed.bounded.entry((kind, period)).or_default();
                if roots.contains(&root) {
                    AlreadyAccepted
                } else if roots.len() >= limit {
                    Refused(Refusal::TooManyRoots {
                        kind,
                        period: 0,
                        max: 0,
                    })
                } else {
                    roots.push(root);
                    Accepted
                }
            }
        }
    }
}

/// The same decision, up to a refusal's details.
fn same(ours: &Decision, reference: &Decision) -> bool {
    match (ours, reference) {
        (Decision::Accepted, Decision::Accepted)
        | (Decision::AlreadyAccepted, Decision::AlreadyAccepted) => true,
        (Decision::Refused(ours), Decision::Refused(reference)) => {
            discriminant(ours) == discriminant(reference)
        }
        _ => false,
    }
}

/// Nothing slashable among `accepted`, pairwise: no two blocks of one slot, no double vote, no
/// surround; and no period with more roots than its kind allows.
fn nothing_slashable(accepted: &[DutyRequest]) -> Result<(), String> {
    let mut blocks = BTreeMap::<(ValidatorKey, u64), Root>::new();
    let mut attestations = BTreeMap::<ValidatorKey, Vec<(u64, u64, Root)>>::new();
    let mut bounded = BTreeMap::<(ValidatorKey, DutyKind, u64), Vec<Root>>::new();
    for request in accepted {
        let root = request.signing_root();
        match &request.duty {
            Duty::BlockProposal(header) => {
                if let Some(other) = blocks.insert((request.validator, header.slot), root)
                    && other != root
                {
                    return Err(format!("two blocks of slot {}", header.slot));
                }
            }
            Duty::Attestation(data) => {
                let (source, target) = (data.source.epoch, data.target.epoch);
                for &(other_source, other_target, other_root) in
                    attestations.entry(request.validator).or_default().iter()
                {
                    if other_target == target && other_root != root {
                        return Err(format!("a double vote for target {target}"));
                    }
                    if (other_source < source && target < other_target)
                        || (source < other_source && other_target < target)
                    {
                        return Err(format!(
                            "({source}, {target}) and ({other_source}, {other_target}) surround"
                        ));
                    }
                }
                attestations
                    .entry(request.validator)
                    .or_default()
                    .push((source, target, root));
            }
            duty => {
                let kind = duty.kind();
                let roots = bounded
                    .entry((request.validator, kind, duty.protection().period()))
                    .or_default();
                if !roots.contains(&root) {
                    roots.push(root);
                }
                let limit = match kind {
                    DutyKind::PayloadAttestation => MAX_SLOT_MESSAGES,
                    _ => MAX_ROOTS_PER_PERIOD,
                };
                if roots.len() > limit {
                    return Err(format!("{} roots of {kind:?} in one period", roots.len()));
                }
            }
        }
    }
    Ok(())
}

/// A seed's history on a store with partition prefix `prefix`: the genesis blocks with the seed's
/// imported history, then [BLOCKS] random blocks, each checked against [Reference]. With
/// `replica`, a second store applies the same blocks and is reopened at random heights.
struct History {
    store: Store<deterministic::Context>,
    accepted: Vec<DutyRequest>,
    rng: StdRng,
}

async fn run(
    context: &mut deterministic::Context,
    genesis: &Genesis,
    seed: u64,
    prefix: &str,
    replica: bool,
) -> Result<History, String> {
    let block = Sha256::hash(&[b"block"]);
    let mut rng = StdRng::seed_from_u64(seed);
    let floors = Floors {
        block: rng.random_range(0..6),
        target: rng.random_range(0..5),
        source: 0,
    };
    let floors = Floors {
        source: rng.random_range(0..=floors.target),
        ..floors
    };
    let mut blocks = genesis.blocks.clone();
    blocks.push((
        HISTORY_HEIGHT,
        vec![history(
            genesis.imported,
            CHAIN,
            floors.block,
            floors.source,
            floors.target,
        )],
    ));
    blocks.sort_by_key(|(height, _)| *height);

    let replica_name = format!("{prefix}-replica");
    let mut store = open(context, prefix).await;
    let mut copy = if replica {
        Some(open(context, &replica_name).await)
    } else {
        None
    };
    for (height, transactions) in &blocks {
        store
            .apply_block(*height, &block, transactions, context)
            .await
            .unwrap();
        if let Some(copy) = &mut copy {
            copy.apply_block(*height, &block, transactions, context)
                .await
                .unwrap();
        }
    }

    let mut reference = Reference::new(&genesis.keys, genesis.imported, floors);
    let mut accepted = Vec::new();
    for height in FIRST..FIRST + BLOCKS as u64 {
        let requests: Vec<DutyRequest> = (0..rng.random_range(1..=8))
            .map(|_| random_duty(&mut rng, &genesis.keys))
            .collect();
        let transactions: Vec<Transaction> = requests
            .iter()
            .map(|request| tx(Command::Duty(Box::new(request.clone()))))
            .collect();
        let applied = store
            .apply_block(height, &block, &transactions, context)
            .await
            .unwrap();
        for (request, effect) in requests.iter().zip(&applied.effects) {
            let Effect::Duty(decision, root) = effect else {
                return Err(format!("height {height}: not a duty's effect: {effect:?}"));
            };
            if *root != request.signing_root() {
                return Err(format!("height {height}: another root for {request:?}"));
            }
            let expected = reference.decide(request);
            if !same(decision, &expected) {
                return Err(format!(
                    "height {height}: {decision:?}, the reference {expected:?}, for {:?} of {}",
                    request.duty,
                    hex::encode(&request.validator[..4]),
                ));
            }
            if *decision == Decision::Accepted {
                accepted.push(request.clone());
            }
        }
        if let Some(replica) = &mut copy {
            let again = replica
                .apply_block(height, &block, &transactions, context)
                .await
                .unwrap();
            if again.effects != applied.effects {
                return Err(format!("height {height}: the replica decided otherwise"));
            }
        }
        if copy.is_some() && rng.random_ratio(1, 5) {
            // Closed first: a blob is open once at a time.
            copy = None;
            copy.insert(open(context, &replica_name).await)
                .protection()
                .verify()
                .map_err(|err| format!("height {height}: the reopened replica: {err}"))?;
        }
    }
    nothing_slashable(&accepted)?;
    if let Some(replica) = copy {
        let duties = |store: &Store<_>| {
            let mut duties = store.protection().authorized_duties();
            duties.sort_by_key(|duty| {
                (
                    duty.validator,
                    duty.kind as u8,
                    duty.period,
                    duty.signing_root,
                )
            });
            duties
        };
        if duties(&store) != duties(&replica) {
            return Err("the replica holds other authorizations".into());
        }
    }
    Ok(History {
        store,
        accepted,
        rng,
    })
}

#[test]
fn the_state_follows_a_reference_model_and_replicas_agree() {
    deterministic::Runner::default().start(|mut context| async move {
        let genesis = genesis(&mut context).await;
        let mut failures = Vec::new();
        let (mut decided, mut accepted) = (0, 0);
        for seed in seeds("MODEL_SEEDS", 200) {
            match run(&mut context, &genesis, seed, &format!("model-{seed}"), true).await {
                Ok(history) => {
                    accepted += history.accepted.len();
                    decided += 1;
                }
                Err(err) => failures.push(format!("seed {seed}: {err}")),
            }
        }
        println!("{decided} seeds, {accepted} duties accepted");
        assert!(failures.is_empty(), "{failures:#?}");
    });
}

/// Duties to ask a store: every accepted one again, conflicting ones (another block of its slot,
/// another vote for its target, votes surrounding it and surrounded by it), and fresh random ones.
fn probes(history: &mut History, keys: &[ValidatorKey]) -> Vec<DutyRequest> {
    let mut probes = Vec::new();
    for request in &history.accepted {
        probes.push(request.clone());
        let mut conflict = request.clone();
        match &mut conflict.duty {
            Duty::BlockProposal(header) => header.body_root = [0xee; 32],
            Duty::Attestation(data) => {
                data.beacon_block_root = [0xee; 32];
                let mut surrounding = request.clone();
                let mut surrounded = request.clone();
                if let (Duty::Attestation(outer), Duty::Attestation(inner)) =
                    (&mut surrounding.duty, &mut surrounded.duty)
                {
                    outer.source.epoch = outer.source.epoch.saturating_sub(1);
                    outer.target.epoch += 1;
                    outer.slot = outer.target.epoch * 32;
                    inner.source.epoch += 1;
                    inner.target.epoch =
                        inner.target.epoch.saturating_sub(1).max(inner.source.epoch);
                    inner.slot = inner.target.epoch * 32;
                }
                probes.push(surrounding);
                probes.push(surrounded);
            }
            Duty::SyncCommitteeMessage {
                beacon_block_root, ..
            } => *beacon_block_root = [0xee; 32],
            Duty::PayloadAttestation(data) => data.payload_present = !data.payload_present,
            _ => {}
        }
        probes.push(conflict);
    }
    for _ in 0..20 {
        probes.push(random_duty(&mut history.rng, keys));
    }
    probes
}

/// The kinds of single edits a hostile medium makes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Edit {
    Remove,
    Mutate,
    CopyOther,
    Duplicate,
}

#[test]
fn hostile_storage_stops_the_store_or_is_a_tolerated_rewrite() {
    deterministic::Runner::default().start(|mut context| async move {
        let genesis = genesis(&mut context).await;
        let committee = committee(&signers());
        // Per edit and record prefix: refused at start, loaded deciding the same, loaded deciding
        // otherwise but refusing what was refused, loaded accepting what was refused.
        let mut outcomes = BTreeMap::<(String, u8), [u32; 4]>::new();
        let mut failures = Vec::new();
        for seed in seeds("HOSTILE_SEEDS", 60) {
            let prefix = format!("hostile-{seed}");
            let mut history = run(&mut context, &genesis, seed, &prefix, false)
                .await
                .unwrap();
            let probes = probes(&mut history, &genesis.keys);
            let intact: Vec<Decision> = probes
                .iter()
                .map(|probe| history.store.protection().check(probe).1)
                .collect();
            let History { store, mut rng, .. } = history;
            drop(store);
            let config = || Config {
                partition: format!("{prefix}-state"),
                codec_config: (),
            };
            for _ in 0..20 {
                let mut metadata = Metadata::<_, Key, Value>::init(context.child("edit"), config())
                    .await
                    .unwrap();
                let keys: Vec<Key> = metadata.keys().cloned().collect();
                let target = keys[rng.random_range(0..keys.len())].clone();
                let original = metadata.get(&target).cloned().unwrap();
                let edit = [Edit::Remove, Edit::Mutate, Edit::CopyOther, Edit::Duplicate]
                    [rng.random_range(0..4)];
                // The key to restore afterwards, and its value before (none: remove it).
                let undo: (Key, Option<Value>) = match edit {
                    Edit::Remove => {
                        metadata.remove(&target);
                        (target.clone(), Some(original.clone()))
                    }
                    Edit::Mutate => {
                        let mut bytes = original.encode().to_vec();
                        for _ in 0..rng.random_range(1..=3) {
                            let index = rng.random_range(0..bytes.len());
                            bytes[index] ^= 1 << rng.random_range(0..8);
                        }
                        match Value::decode(commonware_codec::Copying(bytes.as_slice())) {
                            Ok(mutated) if mutated != original => {
                                metadata.put(target.clone(), mutated);
                                (target.clone(), Some(original.clone()))
                            }
                            _ => continue,
                        }
                    }
                    Edit::CopyOther => {
                        let other = &keys[rng.random_range(0..keys.len())];
                        let value = metadata.get(other).cloned().unwrap();
                        if value == original {
                            continue;
                        }
                        metadata.put(target.clone(), value);
                        (target.clone(), Some(original.clone()))
                    }
                    Edit::Duplicate => {
                        let (prefix, a, b) = parse(&target);
                        let neighbour = key(prefix, a, b.wrapping_add(1));
                        if metadata.get(&neighbour).is_some() {
                            continue;
                        }
                        metadata.put(neighbour.clone(), original.clone());
                        (neighbour, None)
                    }
                };
                let metadata = metadata.sync().await.unwrap();
                drop(metadata);

                let outcome = match Store::init(
                    context.child("hostile"),
                    &prefix,
                    committee.clone(),
                )
                .await
                {
                    Err(_) => 0,
                    Ok(store)
                        if matches!(edit, Edit::Remove | Edit::Duplicate)
                            && parse(&target).0 != META_PREFIX =>
                    {
                        drop(store);
                        failures.push(format!(
                            "seed {seed}: the store started with {edit:?} of {:?}",
                            parse(&target)
                        ));
                        4
                    }
                    Ok(store) => {
                        let now: Vec<Decision> = probes
                            .iter()
                            .map(|probe| store.protection().check(probe).1)
                            .collect();
                        let mut outcome = if now == intact { 1 } else { 2 };
                        if edit == Edit::Remove && now != intact {
                            failures.push(format!(
                                "seed {seed}: a removed metadata entry {:?} changed decisions",
                                parse(&target)
                            ));
                        }
                        for (before, after) in intact.iter().zip(&now) {
                            if matches!(before, Decision::Refused(refusal) if refusal.is_slashing())
                                && !matches!(after, Decision::Refused(_))
                            {
                                outcome = 3;
                            }
                        }
                        outcome
                    }
                };
                if outcome < 4 {
                    outcomes
                        .entry((format!("{edit:?}"), parse(&target).0))
                        .or_insert([0; 4])[outcome] += 1;
                }
                if outcome == 3 && !matches!(edit, Edit::Mutate | Edit::CopyOther) {
                    failures.push(format!(
                        "seed {seed}: {edit:?} of {:?} accepted what was refused",
                        parse(&target)
                    ));
                }

                let mut metadata = Metadata::<_, Key, Value>::init(context.child("undo"), config())
                    .await
                    .unwrap();
                match undo {
                    (key, Some(value)) => {
                        metadata.put(key, value);
                    }
                    (key, None) => {
                        metadata.remove(&key);
                    }
                }
                drop(metadata.sync().await.unwrap());
            }
            // Every edit undone: the store starts and decides as before.
            let store = Store::init(context.child("restored"), &prefix, committee.clone())
                .await
                .unwrap();
            let now: Vec<Decision> = probes
                .iter()
                .map(|probe| store.protection().check(probe).1)
                .collect();
            assert_eq!(
                now, intact,
                "seed {seed}: the undone edits changed the store"
            );
        }
        println!("edit, record prefix: refused, same, otherwise, accepting what was refused");
        for ((edit, prefix), counts) in &outcomes {
            println!("{edit} {prefix}: {counts:?}");
        }
        let rewritten: u32 = outcomes.values().map(|counts| counts[3]).sum();
        println!(
            "{rewritten} consistent rewrites of a record accepted what was refused (audit L-30)"
        );
        assert!(failures.is_empty(), "{failures:#?}");
    });
}
