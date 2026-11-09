//! Gloas roots against consensus-specs v1.7.0-beta.4 ssz_static vectors
//! (`tests/fixtures/gloas`, converted by `extract.py`): the progressive merkleization, every
//! container a validator signs, and the envelope summary.

use super::*;
use crate::eth::types::{AggregateAndProofElectra, AttestationElectra};
use serde::de::DeserializeOwned;
use serde_json::Value;
use ssz::{Decode as _, Encode as _};

/// The cases of one fixture: each value parsed as `T`, with its expected root.
fn cases<T: DeserializeOwned>(fixture: &str) -> Vec<(String, T, Root)> {
    let file: Value = serde_json::from_str(fixture).expect("fixture JSON");
    file["cases"]
        .as_array()
        .expect("cases")
        .iter()
        .map(|case| {
            let name = case["case"].as_str().expect("case name").to_string();
            let value = serde_json::from_value(case["value"].clone())
                .unwrap_or_else(|error| panic!("{name}: {error}"));
            let root = hex::decode(
                case["root"]
                    .as_str()
                    .expect("root")
                    .trim_start_matches("0x"),
            )
            .expect("hex root")
            .try_into()
            .expect("32 bytes");
            (name, value, root)
        })
        .collect()
}

#[test]
fn payload_attestation_data_roots() {
    let cases = cases::<PayloadAttestationData>(include_str!(
        "../../fixtures/gloas/PayloadAttestationData.json"
    ));
    assert_eq!(cases.len(), 5);
    for (name, data, root) in cases {
        assert_eq!(data.tree_hash_root().0, root, "{name}");
        let encoded = data.as_ssz_bytes();
        assert_eq!(
            PayloadAttestationData::from_ssz_bytes(&encoded).unwrap(),
            data
        );
    }
}

#[test]
fn proposer_preferences_roots() {
    let cases = cases::<ProposerPreferences>(include_str!(
        "../../fixtures/gloas/ProposerPreferences.json"
    ));
    assert_eq!(cases.len(), 5);
    for (name, preferences, root) in cases {
        assert_eq!(preferences.tree_hash_root().0, root, "{name}");
    }
}

#[test]
fn attestation_roots_are_progressive() {
    let cases = cases::<AttestationElectra>(include_str!("../../fixtures/gloas/Attestation.json"));
    assert_eq!(cases.len(), 5);
    for (name, attestation, root) in cases {
        assert_eq!(attestation_root(&attestation), root, "{name}");
        // Electra's root of the same fields differs: the form must follow the fork.
        assert_ne!(attestation.tree_hash_root().0, root, "{name}");
    }
}

#[test]
fn aggregate_and_proof_roots() {
    let cases = cases::<AggregateAndProofElectra>(include_str!(
        "../../fixtures/gloas/AggregateAndProof.json"
    ));
    assert_eq!(cases.len(), 5);
    for (name, aggregate, root) in cases {
        assert_eq!(aggregate_and_proof_root(&aggregate), root, "{name}");
    }
}

#[test]
fn execution_requests_roots() {
    let cases =
        cases::<ExecutionRequests>(include_str!("../../fixtures/gloas/ExecutionRequests.json"));
    assert_eq!(cases.len(), 5);
    for (name, requests, root) in cases {
        assert_eq!(requests.root(), root, "{name}");
    }
}

#[test]
fn execution_payload_roots() {
    let cases =
        cases::<ExecutionPayload>(include_str!("../../fixtures/gloas/ExecutionPayload.json"));
    assert_eq!(cases.len(), 3);
    for (name, payload, root) in cases {
        let envelope = ExecutionPayloadEnvelope {
            payload,
            execution_requests: ExecutionRequests {
                deposits: vec![],
                withdrawals: vec![],
                consolidations: vec![],
                builder_deposits: vec![],
                builder_exits: vec![],
            },
            builder_index: 0,
            beacon_block_root: [0; 32],
            parent_beacon_block_root: [0; 32],
        };
        assert_eq!(envelope.summary().unwrap().payload_root(), root, "{name}");
    }
}

#[test]
fn execution_payload_envelope_roots_through_the_summary() {
    let cases = cases::<ExecutionPayloadEnvelope>(include_str!(
        "../../fixtures/gloas/ExecutionPayloadEnvelope.json"
    ));
    assert_eq!(cases.len(), 3);
    for (name, envelope, root) in cases {
        let summary = envelope.summary().unwrap();
        assert_eq!(summary.root(), root, "{name}");
        // Consensus carries the summary: it decodes to itself, with the same root.
        let decoded = EnvelopeSummary::from_ssz_bytes(&summary.as_ssz_bytes()).unwrap();
        assert_eq!(decoded, summary);
        assert_eq!(decoded.root(), root, "{name}");
        // The JSON form round-trips (what the API parses is what a client sent).
        let json = serde_json::to_value(&envelope).unwrap();
        assert_eq!(
            serde_json::from_value::<ExecutionPayloadEnvelope>(json).unwrap(),
            envelope
        );
    }
}

#[test]
fn an_envelope_summary_is_small_enough_for_consensus() {
    let (_, envelope, _) = cases::<ExecutionPayloadEnvelope>(include_str!(
        "../../fixtures/gloas/ExecutionPayloadEnvelope.json"
    ))
    .remove(0);
    let summary = envelope.summary().unwrap();
    // An address, 14 roots (the uint256 base fee among them) and 8 integers.
    assert_eq!(summary.as_ssz_bytes().len(), 20 + 32 * 14 + 8 * 8);
    assert!(summary.as_ssz_bytes().len() < crate::eth::duty::MAX_DUTY_BYTES);
}

#[test]
fn extra_data_beyond_its_limit_is_refused() {
    let (_, mut envelope, _) = cases::<ExecutionPayloadEnvelope>(include_str!(
        "../../fixtures/gloas/ExecutionPayloadEnvelope.json"
    ))
    .remove(0);
    envelope.payload.extra_data = vec![0; 33];
    assert_eq!(envelope.summary(), Err(ExtraDataTooLong(33)));
}

#[test]
fn uint256_decimal_strings() {
    for text in [
        "0",
        "1",
        "255",
        "256",
        "1000000000",
        "33641352223709482988637980108924389704801639107354634827638743682802872463053",
        "115792089237316195423570985008687907853269984665640564039457584007913129639935",
    ] {
        let value = parse_u256(text).unwrap_or_else(|| panic!("{text}"));
        assert_eq!(format_u256(&value), text);
    }
    assert_eq!(parse_u256("256").unwrap()[..2], [0, 1]);
    // 2^256 overflows; signs, spaces, hex and the empty string are not decimal integers.
    for text in [
        "115792089237316195423570985008687907853269984665640564039457584007913129639936",
        "",
        "-1",
        " 1",
        "0x10",
        "1e3",
    ] {
        assert_eq!(parse_u256(text), None, "{text:?}");
    }
}

#[test]
fn progressive_trees_follow_the_specification_shape() {
    use crate::eth::progressive::{merkleize_progressive, short_bytes_root};
    let chunk = |byte: u8| [byte; 32];
    let hash = |left: &Root, right: &Root| -> Root {
        use sha2::{Digest, Sha256};
        Sha256::new()
            .chain_update(left)
            .chain_update(right)
            .finalize()
            .into()
    };
    let zero = [0u8; 32];
    assert_eq!(merkleize_progressive(&[]), zero);
    // One chunk: hash(c0, zero).
    assert_eq!(merkleize_progressive(&[chunk(1)]), hash(&chunk(1), &zero));
    // Two chunks: hash(c0, hash(merkleize([c1], 4), zero)).
    let four = |a: Root, b: Root, c: Root, d: Root| hash(&hash(&a, &b), &hash(&c, &d));
    assert_eq!(
        merkleize_progressive(&[chunk(1), chunk(2)]),
        hash(&chunk(1), &hash(&four(chunk(2), zero, zero, zero), &zero))
    );
    // Five chunks fill the 1 and 4 subtrees exactly.
    assert_eq!(
        merkleize_progressive(&[chunk(1), chunk(2), chunk(3), chunk(4), chunk(5)]),
        hash(
            &chunk(1),
            &hash(&four(chunk(2), chunk(3), chunk(4), chunk(5)), &zero)
        )
    );
    assert_eq!(short_bytes_root(&[7; 20])[..20], [7; 20]);
}

/// The Gloas duties as consensus carries them: tags 12 (a Gloas aggregate) to 15, each decoding
/// to itself with the same signing root.
#[test]
fn gloas_duties_round_trip_in_consensus() {
    use crate::eth::duty::{AggregateAndProof, Duty, DutyKind, Fork, ForkInfo};
    use commonware_codec::{DecodeExt as _, Encode as _};
    let (_, aggregate, _) = cases::<AggregateAndProofElectra>(include_str!(
        "../../fixtures/gloas/AggregateAndProof.json"
    ))
    .remove(0);
    let (_, ptc, _) = cases::<PayloadAttestationData>(include_str!(
        "../../fixtures/gloas/PayloadAttestationData.json"
    ))
    .remove(0);
    let (_, preferences, _) = cases::<ProposerPreferences>(include_str!(
        "../../fixtures/gloas/ProposerPreferences.json"
    ))
    .remove(0);
    let (_, envelope, _) = cases::<ExecutionPayloadEnvelope>(include_str!(
        "../../fixtures/gloas/ExecutionPayloadEnvelope.json"
    ))
    .remove(0);
    let fork = ForkInfo {
        fork: Fork {
            previous_version: [0, 0, 0, 7],
            current_version: [0, 0, 0, 8],
            epoch: 0,
        },
        genesis_validators_root: [3; 32],
    };
    for (tag, kind, duty) in [
        (
            12,
            DutyKind::AggregateAndProof,
            Duty::AggregateAndProof(AggregateAndProof::Gloas(Box::new(aggregate.clone()))),
        ),
        (
            13,
            DutyKind::PayloadAttestation,
            Duty::PayloadAttestation(ptc),
        ),
        (
            14,
            DutyKind::ExecutionPayloadEnvelope,
            Duty::ExecutionPayloadEnvelope(Box::new(envelope.summary().unwrap())),
        ),
        (
            15,
            DutyKind::ProposerPreferences,
            Duty::ProposerPreferences(preferences),
        ),
    ] {
        let encoded = duty.encode();
        assert_eq!(encoded[0], tag);
        let decoded = Duty::decode(encoded).unwrap();
        assert_eq!(decoded, duty);
        assert_eq!(decoded.kind(), kind);
        assert_eq!(decoded.signing_root(&fork), duty.signing_root(&fork));
    }
    // The Gloas and Electra forms of one aggregate are distinct duties with distinct roots.
    let electra = Duty::AggregateAndProof(AggregateAndProof::Electra(Box::new(aggregate.clone())));
    let gloas = Duty::AggregateAndProof(AggregateAndProof::Gloas(Box::new(aggregate)));
    assert_ne!(electra.signing_root(&fork), gloas.signing_root(&fork));
}
