//! Web3Signer signing requests produced by Lighthouse v8.3.2's own code: its types, its
//! `Web3SignerObject` (the duty object of the request), `SignableMessage::signing_root` and
//! `SigningContext::domain_hash`. The private `SigningRequest` envelope is
//! `{type, fork_info, signingRoot, #[serde(flatten)] object}` with `ForkInfo {fork,
//! genesis_validators_root}`; it is rebuilt here from those public parts in the same order.
//!
//! The signing contexts are the ones `validator_store::signing_context` builds: the domain epoch of
//! each duty, `ChainSpec::fork_at_epoch(epoch)` (mainnet), and the Capella fork for exits from
//! Deneb on (EIP-7044).
//!
//! Usage: `lh-fixtures <repository fixtures dir> <output dir>`.

use serde_json::{Value, json};
use signing_method::{SignableMessage, SigningContext, Web3SignerObject};
use std::path::Path;
use types::{
    AbstractExecPayload, AggregateAndProof, AggregateAndProofBase, AggregateAndProofElectra,
    AttestationData, BeaconBlock, BeaconBlockAltair, BeaconBlockBellatrix, BeaconBlockCapella,
    BeaconBlockDeneb, BeaconBlockElectra, BeaconBlockFulu, BlindedPayload, ChainSpec, Checkpoint,
    ContributionAndProof, Domain, EmptyBlock, Epoch, EthSpec, Fork, ForkName, FullPayload, Hash256,
    MainnetEthSpec, Slot, SyncAggregatorSelectionData, VoluntaryExit,
};

type E = MainnetEthSpec;

fn genesis_validators_root() -> Hash256 {
    // The genesis validators root of Web3Signer's examples (the other fixtures).
    serde_json::from_value(json!(
        "0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673"
    ))
    .unwrap()
}

fn hash(byte: u8) -> Hash256 {
    Hash256::repeat_byte(byte)
}

/// `validator_store::signing_context`.
fn context(spec: &ChainSpec, domain: Domain, epoch: Epoch) -> SigningContext {
    let fork = if domain == Domain::VoluntaryExit && spec.fork_name_at_epoch(epoch).deneb_enabled()
    {
        Fork {
            previous_version: spec.capella_fork_version,
            current_version: spec.capella_fork_version,
            epoch,
        }
    } else {
        spec.fork_at_epoch(epoch)
    };
    SigningContext {
        domain,
        epoch,
        fork,
        genesis_validators_root: genesis_validators_root(),
    }
}

/// `SigningMethod::get_signature` up to the HTTP request: the root, then the request body.
fn request<Payload: AbstractExecPayload<E>>(
    spec: &ChainSpec,
    message: SignableMessage<'_, E, Payload>,
    object: Web3SignerObject<'_, E, Payload>,
    context: SigningContext,
) -> Value {
    let signing_root = message.signing_root(context.domain_hash(spec));
    let mut body = serde_json::Map::new();
    body.insert(
        "type".into(),
        serde_json::to_value(object.message_type()).unwrap(),
    );
    body.insert(
        "fork_info".into(),
        json!({
            "fork": serde_json::to_value(context.fork).unwrap(),
            "genesis_validators_root": serde_json::to_value(context.genesis_validators_root).unwrap(),
        }),
    );
    body.insert(
        "signingRoot".into(),
        serde_json::to_value(signing_root).unwrap(),
    );
    let Value::Object(fields) = serde_json::to_value(&object).unwrap() else {
        panic!("the object serializes as a map");
    };
    body.extend(fields);
    Value::Object(body)
}

fn write(out: &Path, name: &str, value: &Value) {
    let path = out.join(format!("{name}.json"));
    std::fs::write(&path, serde_json::to_string(value).unwrap() + "\n").unwrap();
    println!("{name}: {}", value["signingRoot"]);
}

fn fixture(dir: &Path, name: &str, field: &str) -> Value {
    let value: Value =
        serde_json::from_str(&std::fs::read_to_string(dir.join(name)).unwrap()).unwrap();
    value[field].clone()
}

/// A block of fork `fork`, at a slot inside it.
fn block<Block: EmptyBlock>(
    spec: &ChainSpec,
    fork: ForkName,
    index: u64,
    set: impl FnOnce(&mut Block, Slot),
) -> (Block, Epoch) {
    let epoch = spec.fork_epoch(fork).unwrap() + 1;
    let slot = epoch.start_slot(E::slots_per_epoch()) + index;
    let mut block = Block::empty(spec);
    set(&mut block, slot);
    (block, epoch)
}

macro_rules! header_fields {
    ($block:ident, $slot:ident, $index:expr) => {
        $block.slot = $slot;
        $block.proposer_index = 1000 + $index;
        $block.parent_root = hash($index as u8);
        $block.state_root = hash(0x10 + $index as u8);
    };
}

macro_rules! blocks {
    ($spec:ident, $out:ident, $($fork:ident, $variant:ident, $name:literal, $index:expr);*) => {$(
        let (full, epoch) = block::<$variant<E, FullPayload<E>>>(&$spec, ForkName::$fork, $index, |b, slot| {
            header_fields!(b, slot, $index);
        });
        let blinded = BeaconBlock::<E, BlindedPayload<E>>::$fork(full.clone_as_blinded());
        let full = BeaconBlock::<E, FullPayload<E>>::$fork(full);
        let ctx = || context(&$spec, Domain::BeaconProposer, epoch);
        let full_request = request(
            &$spec,
            SignableMessage::BeaconBlock(&full),
            Web3SignerObject::beacon_block(&full).unwrap(),
            ctx(),
        );
        let blinded_request = request(
            &$spec,
            SignableMessage::BeaconBlock(&blinded),
            Web3SignerObject::beacon_block(&blinded).unwrap(),
            ctx(),
        );
        assert_eq!(full_request, blinded_request, "{}: blinded and full requests", $name);
        write(&$out, concat!("block_v2_", $name), &full_request);
    )*};
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let fixtures = Path::new(&args[1]);
    let out = Path::new(&args[2]);
    std::fs::create_dir_all(out).unwrap();
    let spec = ChainSpec::mainnet();
    let slots = E::slots_per_epoch();

    // Blocks: Altair sends the whole block; Bellatrix to Fulu the header, the same for a
    // blinded block (checked).
    let (altair, epoch) =
        block::<BeaconBlockAltair<E, FullPayload<E>>>(&spec, ForkName::Altair, 1, |b, slot| {
            header_fields!(b, slot, 1u64);
        });
    let altair = BeaconBlock::<E, FullPayload<E>>::Altair(altair);
    write(
        out,
        "block_v2_altair_full_block",
        &request(
            &spec,
            SignableMessage::BeaconBlock(&altair),
            Web3SignerObject::beacon_block(&altair).unwrap(),
            context(&spec, Domain::BeaconProposer, epoch),
        ),
    );
    blocks!(spec, out,
        Bellatrix, BeaconBlockBellatrix, "bellatrix", 2u64;
        Capella, BeaconBlockCapella, "capella", 3u64;
        Deneb, BeaconBlockDeneb, "deneb", 4u64;
        Electra, BeaconBlockElectra, "electra", 5u64;
        Fulu, BeaconBlockFulu, "fulu", 6u64
    );

    // The other duties, in Fulu (the phase 0 aggregate in Deneb).
    let fulu = spec.fork_epoch(ForkName::Fulu).unwrap() + 10;
    let deneb = spec.fork_epoch(ForkName::Deneb).unwrap() + 10;
    let slot = fulu.start_slot(slots) + 3;

    let attestation = AttestationData {
        slot,
        index: 0,
        beacon_block_root: hash(0xb1),
        source: Checkpoint {
            epoch: fulu - 1,
            root: hash(0xb2),
        },
        target: Checkpoint {
            epoch: fulu,
            root: hash(0xb3),
        },
    };
    write(
        out,
        "attestation",
        &request::<FullPayload<E>>(
            &spec,
            SignableMessage::AttestationData(&attestation),
            Web3SignerObject::Attestation(&attestation),
            context(&spec, Domain::BeaconAttester, attestation.target.epoch),
        ),
    );
    write(
        out,
        "randao_reveal",
        &request::<FullPayload<E>>(
            &spec,
            SignableMessage::RandaoReveal(fulu),
            Web3SignerObject::RandaoReveal { epoch: fulu },
            context(&spec, Domain::Randao, fulu),
        ),
    );
    write(
        out,
        "aggregation_slot",
        &request::<FullPayload<E>>(
            &spec,
            SignableMessage::SelectionProof(slot),
            Web3SignerObject::AggregationSlot { slot },
            context(&spec, Domain::SelectionProof, slot.epoch(slots)),
        ),
    );

    // Aggregates: the data of the repository fixtures, read by Lighthouse's serde, moved into the
    // fork; the domain epoch is the target epoch, as Lighthouse signs it.
    let mut phase0: AggregateAndProofBase<E> = serde_json::from_value(fixture(
        fixtures,
        "aggregate_and_proof_phase0.json",
        "aggregate_and_proof",
    ))
    .unwrap();
    phase0.aggregate.data.slot = deneb.start_slot(slots) + 2;
    phase0.aggregate.data.source.epoch = deneb - 1;
    phase0.aggregate.data.target.epoch = deneb;
    let phase0 = AggregateAndProof::Base(phase0);
    write(
        out,
        "aggregate_and_proof_phase0",
        &request::<FullPayload<E>>(
            &spec,
            SignableMessage::SignedAggregateAndProof(phase0.to_ref()),
            Web3SignerObject::AggregateAndProof(phase0.to_ref()),
            context(&spec, Domain::AggregateAndProof, deneb),
        ),
    );
    let mut electra: AggregateAndProofElectra<E> = serde_json::from_value(fixture(
        fixtures,
        "aggregate_and_proof_electra.json",
        "aggregate_and_proof",
    ))
    .unwrap();
    electra.aggregate.data.slot = slot;
    electra.aggregate.data.source.epoch = fulu - 1;
    electra.aggregate.data.target.epoch = fulu;
    let electra = AggregateAndProof::Electra(electra);
    write(
        out,
        "aggregate_and_proof_electra",
        &request::<FullPayload<E>>(
            &spec,
            SignableMessage::SignedAggregateAndProof(electra.to_ref()),
            Web3SignerObject::AggregateAndProof(electra.to_ref()),
            context(&spec, Domain::AggregateAndProof, fulu),
        ),
    );

    write(
        out,
        "sync_committee_message",
        &request::<FullPayload<E>>(
            &spec,
            SignableMessage::SyncCommitteeSignature {
                beacon_block_root: hash(0xc1),
                slot,
            },
            Web3SignerObject::SyncCommitteeMessage {
                beacon_block_root: hash(0xc1),
                slot,
            },
            context(&spec, Domain::SyncCommittee, slot.epoch(slots)),
        ),
    );
    let selection = SyncAggregatorSelectionData {
        slot,
        subcommittee_index: 2,
    };
    write(
        out,
        "sync_committee_selection_proof",
        &request::<FullPayload<E>>(
            &spec,
            SignableMessage::SyncSelectionProof(&selection),
            Web3SignerObject::SyncAggregatorSelectionData(&selection),
            context(
                &spec,
                Domain::SyncCommitteeSelectionProof,
                slot.epoch(slots),
            ),
        ),
    );
    let mut contribution: ContributionAndProof<E> = serde_json::from_value(fixture(
        fixtures,
        "contribution_and_proof.json",
        "contribution_and_proof",
    ))
    .unwrap();
    contribution.contribution.slot = slot;
    write(
        out,
        "contribution_and_proof",
        &request::<FullPayload<E>>(
            &spec,
            SignableMessage::SignedContributionAndProof(&contribution),
            Web3SignerObject::ContributionAndProof(&contribution),
            context(&spec, Domain::ContributionAndProof, slot.epoch(slots)),
        ),
    );
    let exit = VoluntaryExit {
        epoch: fulu,
        validator_index: 7,
    };
    write(
        out,
        "voluntary_exit",
        &request::<FullPayload<E>>(
            &spec,
            SignableMessage::VoluntaryExit(&exit),
            Web3SignerObject::VoluntaryExit(&exit),
            context(&spec, Domain::VoluntaryExit, exit.epoch),
        ),
    );
}
