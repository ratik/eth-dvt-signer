//! Parsing of Web3Signer signing requests (`eth::web3signer`), on fixtures shaped as Lighthouse
//! v8.3.2 sends them (`tests/fixtures/web3signer/README.md`).

use eth_mpc_signer::eth::{
    duty::{AggregateAndProof, Duty, DutyKind, format_root},
    web3signer::{ParseError, parse_identifier, parse_request},
};
use serde_json::{Value, json};
use std::path::Path;

fn fixture(name: &str) -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/web3signer")
        .join(name);
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn parse(value: &Value) -> Result<eth_mpc_signer::eth::web3signer::Request, ParseError> {
    parse_request(value.to_string().as_bytes())
}

#[test]
fn lighthouse_requests_parse_and_reproduce_their_signing_roots() {
    let cases = [
        ("block_v2_electra.json", DutyKind::BlockProposal),
        ("attestation.json", DutyKind::Attestation),
        ("randao_reveal.json", DutyKind::RandaoReveal),
        ("aggregation_slot.json", DutyKind::AggregationSlot),
        (
            "aggregate_and_proof_phase0.json",
            DutyKind::AggregateAndProof,
        ),
        (
            "aggregate_and_proof_electra.json",
            DutyKind::AggregateAndProof,
        ),
        (
            "sync_committee_message.json",
            DutyKind::SyncCommitteeMessage,
        ),
        (
            "sync_committee_selection_proof.json",
            DutyKind::SyncSelectionProof,
        ),
        (
            "contribution_and_proof.json",
            DutyKind::ContributionAndProof,
        ),
        ("voluntary_exit.json", DutyKind::VoluntaryExit),
    ];
    for (name, kind) in cases {
        let value = fixture(name);
        let request = parse(&value).unwrap_or_else(|err| panic!("{name}: {err}"));
        assert_eq!(request.duty.kind(), kind, "{name}");
        let expected = value["signingRoot"].as_str().unwrap();
        assert_eq!(
            format_root(&request.signing_root.unwrap()),
            expected,
            "{name}"
        );
        assert_eq!(
            format_root(&request.duty.signing_root(&request.fork)),
            expected,
            "{name}: computed root"
        );
    }
}

#[test]
fn the_attestation_shape_selects_the_aggregate_fork() {
    // Lighthouse sends `AGGREGATE_AND_PROOF` for every fork: `committee_bits` means Electra.
    let phase0 = parse(&fixture("aggregate_and_proof_phase0.json")).unwrap();
    assert!(matches!(
        phase0.duty,
        Duty::AggregateAndProof(AggregateAndProof::Phase0(_))
    ));
    let electra = parse(&fixture("aggregate_and_proof_electra.json")).unwrap();
    assert!(matches!(
        electra.duty,
        Duty::AggregateAndProof(AggregateAndProof::Electra(_))
    ));
    // The same objects under `AGGREGATE_AND_PROOF_V2`, versioned.
    for (name, version, expected) in [
        ("aggregate_and_proof_phase0.json", "DENEB", &phase0),
        ("aggregate_and_proof_electra.json", "FULU", &electra),
    ] {
        let mut value = fixture(name);
        let data = value["aggregate_and_proof"].take();
        value["type"] = json!("AGGREGATE_AND_PROOF_V2");
        value["aggregate_and_proof"] = json!({ "version": version, "data": data });
        assert_eq!(&parse(&value).unwrap(), expected, "{version}");
    }
    // A version whose shape does not match the data is refused.
    let mut value = fixture("aggregate_and_proof_electra.json");
    let data = value["aggregate_and_proof"].take();
    value["type"] = json!("AGGREGATE_AND_PROOF_V2");
    value["aggregate_and_proof"] = json!({ "version": "DENEB", "data": data });
    assert!(matches!(parse(&value), Err(ParseError::Invalid(_))));
}

#[test]
fn unsupported_requests_are_refused() {
    let unsupported = |value: Value| {
        assert!(
            matches!(parse(&value), Err(ParseError::Unsupported(_))),
            "{value}: {:?}",
            parse(&value)
        );
    };
    for version in ["PHASE0", "ALTAIR", "GLOAS", "HEZE", "FUTURE"] {
        let mut value = fixture("block_v2_electra.json");
        value["beacon_block"]["version"] = json!(version);
        unsupported(value);
    }
    // A whole block instead of its header.
    let mut value = fixture("block_v2_electra.json");
    value["beacon_block"]["block"] = json!({ "slot": "0" });
    unsupported(value);
    for kind in [
        "BLOCK",
        "VALIDATOR_REGISTRATION",
        "DEPOSIT",
        "SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF_V9",
        "EXECUTION_PAYLOAD_ENVELOPE",
        "PAYLOAD_ATTESTATION_MESSAGE",
    ] {
        let mut value = fixture("randao_reveal.json");
        value["type"] = json!(kind);
        unsupported(value);
    }
    let mut value = fixture("aggregate_and_proof_phase0.json");
    let data = value["aggregate_and_proof"].take();
    value["type"] = json!("AGGREGATE_AND_PROOF_V2");
    value["aggregate_and_proof"] = json!({ "version": "GLOAS", "data": data });
    unsupported(value);
}

#[test]
fn malformed_requests_are_refused() {
    let invalid = |value: Value, what: &str| {
        assert!(
            matches!(parse(&value), Err(ParseError::Invalid(_))),
            "{what}: {:?}",
            parse(&value)
        );
    };
    let mut value = fixture("attestation.json");
    value.as_object_mut().unwrap().remove("fork_info");
    invalid(value, "missing fork_info");

    let mut value = fixture("attestation.json");
    value["fork_info"]["fork"]["current_version"] = json!("0x000001");
    invalid(value, "3-byte fork version");

    let mut value = fixture("attestation.json");
    value["fork_info"]["genesis_validators_root"] = json!("04700007");
    invalid(value, "root without 0x");

    let mut value = fixture("attestation.json");
    value["attestation"]["slot"] = json!("-1");
    invalid(value, "negative slot");

    let mut value = fixture("attestation.json");
    value["attestation"]["slot"] = json!("18446744073709551616");
    invalid(value, "slot above u64");

    let mut value = fixture("attestation.json");
    value["attestation"]["extra"] = json!("1");
    invalid(value, "unknown attestation field");

    let mut value = fixture("attestation.json");
    value["type"] = json!("BLOCK_V2");
    invalid(value, "object of another type");

    let mut value = fixture("attestation.json");
    value["signingRoot"] = json!("0x1234");
    invalid(value, "short signing root");

    // Minimal-preset sizes (Web3Signer's own contribution example): mainnet only.
    let mut value = fixture("contribution_and_proof.json");
    value["contribution_and_proof"]["contribution"]["aggregation_bits"] = json!("0x24");
    invalid(value, "Bitvector[8] aggregation bits");

    invalid(json!("not an object"), "not an object");
    assert!(matches!(
        parse_request(b"{not json"),
        Err(ParseError::Invalid(_))
    ));

    // Boundary values are accepted as they are.
    let mut value = fixture("attestation.json");
    value["attestation"]["slot"] = json!("18446744073709551615");
    value["attestation"]["target"]["epoch"] = json!("18446744073709551615");
    assert!(parse(&value).is_ok());
}

#[test]
fn field_name_variants_of_web3signer_examples_are_accepted() {
    // Some Web3Signer examples use camelCase fork fields; integers may come unquoted.
    let mut value = fixture("aggregation_slot.json");
    value["fork_info"] = json!({
        "fork": { "previousVersion": "0x00000001", "currentVersion": "0x00000001", "epoch": 1 },
        "genesis_validators_root": "0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673",
    });
    let request = parse(&value).unwrap();
    assert_eq!(
        format_root(&request.duty.signing_root(&request.fork)),
        value["signingRoot"].as_str().unwrap()
    );
    // No signingRoot: accepted, nothing to compare.
    let mut value = fixture("randao_reveal.json");
    value.as_object_mut().unwrap().remove("signingRoot");
    assert_eq!(parse(&value).unwrap().signing_root, None);
}

#[test]
fn identifiers_are_48_byte_hex_keys() {
    let key = format!("0x{}", "ab".repeat(48));
    assert_eq!(parse_identifier(&key).unwrap(), [0xab; 48]);
    for bad in [
        "",
        "0x",
        &"ab".repeat(48),
        &format!("0x{}", "ab".repeat(47)),
        "0xzz",
    ] {
        assert!(parse_identifier(bad).is_err(), "{bad}");
    }
}

#[test]
fn block_headers_of_every_supported_fork_reproduce_their_roots() {
    // Lighthouse v8.3.2 (`Web3SignerObject::beacon_block`) sends `block_header` from Bellatrix on,
    // with `fork_at_epoch(block epoch)` as the fork. Roots from `ssz_roots.py`, which shares no
    // code with the signer.
    for (fork, current_version) in [
        ("bellatrix", [2, 0, 0, 0]),
        ("capella", [3, 0, 0, 0]),
        ("deneb", [4, 0, 0, 0]),
        ("electra", [5, 0, 0, 0]),
        ("fulu", [6, 0, 0, 0]),
    ] {
        let value = fixture(&format!("block_v2_mainnet_{fork}.json"));
        let request = parse(&value).unwrap_or_else(|err| panic!("{fork}: {err}"));
        assert_eq!(request.duty.kind(), DutyKind::BlockProposal, "{fork}");
        // The block is in its fork: the domain uses the current version.
        assert_eq!(
            request.fork.version_at(request.duty.epoch()),
            current_version,
            "{fork}"
        );
        let expected = value["signingRoot"].as_str().unwrap();
        assert_eq!(
            format_root(&request.duty.signing_root(&request.fork)),
            expected,
            "{fork}"
        );
    }
}

fn lighthouse(name: &str) -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/lighthouse")
        .join(name);
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

/// Requests produced by Lighthouse v8.3.2's own code (`tests/fixtures/lighthouse/README.md`): the
/// parser accepts each supported one, and the signing root it computes is the one Lighthouse
/// computed.
#[test]
fn lighthouse_produced_requests_reproduce_lighthouse_roots() {
    let cases = [
        ("block_v2_bellatrix.json", DutyKind::BlockProposal),
        ("block_v2_capella.json", DutyKind::BlockProposal),
        ("block_v2_deneb.json", DutyKind::BlockProposal),
        ("block_v2_electra.json", DutyKind::BlockProposal),
        ("block_v2_fulu.json", DutyKind::BlockProposal),
        ("attestation.json", DutyKind::Attestation),
        ("randao_reveal.json", DutyKind::RandaoReveal),
        ("aggregation_slot.json", DutyKind::AggregationSlot),
        (
            "aggregate_and_proof_phase0.json",
            DutyKind::AggregateAndProof,
        ),
        (
            "aggregate_and_proof_electra.json",
            DutyKind::AggregateAndProof,
        ),
        (
            "sync_committee_message.json",
            DutyKind::SyncCommitteeMessage,
        ),
        (
            "sync_committee_selection_proof.json",
            DutyKind::SyncSelectionProof,
        ),
        (
            "contribution_and_proof.json",
            DutyKind::ContributionAndProof,
        ),
        ("voluntary_exit.json", DutyKind::VoluntaryExit),
    ];
    for (name, kind) in cases {
        let value = lighthouse(name);
        let request = parse(&value).unwrap_or_else(|err| panic!("{name}: {err}"));
        assert_eq!(request.duty.kind(), kind, "{name}");
        assert_eq!(
            format_root(&request.duty.signing_root(&request.fork)),
            value["signingRoot"].as_str().unwrap(),
            "{name}: Lighthouse's root"
        );
    }
    // Lighthouse sends an Altair block whole: refused, not misread.
    assert!(matches!(
        parse(&lighthouse("block_v2_altair_full_block.json")),
        Err(ParseError::Unsupported(_))
    ));
}
