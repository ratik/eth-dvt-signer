//! Conformance with the Ethereum remote-signing API specification
//! (`ethereum/remote-signing-api` v1.4.0, vendored in `tests/vectors/remote-signing-api`).
//!
//! Every request example of `POST /api/v1/eth2/sign/{identifier}` goes through the request parser
//! the node and the gateway share (`eth::web3signer`). Each example has an expected outcome below:
//! signed, with the example's `signingRoot` reproduced (or the reason it is not), or refused, with
//! the reason. An example the table does not name, or a name the specification no longer has,
//! fails the test, so a new version of the specification cannot pass unread. The report is
//! `docs/remote-signing-api.md`.

use eth_dvt_signer::eth::{
    duty::{Duty, DutyKind, Fork, ForkInfo, format_root},
    web3signer::{ParseError, parse_request},
};
use serde_json::Value;
use std::{collections::BTreeMap, path::Path};

const SPEC: &str = "tests/vectors/remote-signing-api/v1.4.0";

fn spec(file: &str) -> serde_yaml::Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(SPEC).join(file);
    serde_yaml::from_str(&std::fs::read_to_string(&path).unwrap())
        .unwrap_or_else(|err| panic!("{}: {err}", path.display()))
}

fn sign_operation() -> serde_yaml::Value {
    spec("signing/paths/sign.yaml")["post"].clone()
}

/// The request examples of the signing endpoint, by name, as JSON.
fn examples() -> BTreeMap<String, Value> {
    let examples = &sign_operation()["requestBody"]["content"]["application/json"]["examples"];
    examples
        .as_mapping()
        .expect("the signing endpoint has request examples")
        .iter()
        .map(|(name, example)| {
            let name = name.as_str().unwrap().to_owned();
            let value = serde_json::to_value(&example["value"]).unwrap();
            (name, value)
        })
        .collect()
}

/// What happened to the example's `signingRoot`.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Root {
    /// The computed root is the example's.
    Reproduced,
    /// The example carries no `signingRoot` (it is optional).
    Absent,
    /// The computed root is not the example's but this one, which `ssz_roots.py` (an SSZ
    /// implementation that shares no code with the signer) computes too; the reason is in the
    /// report.
    Differs(String),
}

/// The root of the Electra and Fulu `AGGREGATE_AND_PROOF_V2` examples (mainnet preset), as this
/// signer and `tests/fixtures/web3signer/ssz_roots.py` both compute it. The specification gives
/// `0x2475..c9e0`, which neither preset reproduces.
const ELECTRA_AGGREGATE_ROOT: &str =
    "0x1180bcb41bda522b3420274c6e4931c37ecf4eef99a57e4d04fc81e82b2ced40";

#[derive(Clone, Debug, PartialEq, Eq)]
enum Outcome {
    Signed(DutyKind, Root),
    /// `400`: a request type, fork or form this signer does not sign.
    Unsupported,
    /// `400`: the example does not parse as a mainnet-preset request.
    Invalid,
}

use Outcome::*;

/// The expected outcome of every example of the specification, by its name there. Why each
/// refusal and each differing root is right: `docs/remote-signing-api.md`.
fn expected() -> BTreeMap<&'static str, Outcome> {
    use DutyKind as K;
    use Root::*;
    BTreeMap::from([
        ("BLOCK_V2 (GLOAS)", Signed(K::BlockProposal, Reproduced)),
        ("BLOCK_V2 (FULU)", Signed(K::BlockProposal, Reproduced)),
        ("BLOCK_V2 (ELECTRA)", Signed(K::BlockProposal, Reproduced)),
        ("BLOCK_V2 (DENEB)", Signed(K::BlockProposal, Reproduced)),
        ("BLOCK_V2 (CAPELLA)", Signed(K::BlockProposal, Reproduced)),
        ("BLOCK_V2 (BELLATRIX)", Signed(K::BlockProposal, Reproduced)),
        ("BLOCK_V2 (ALTAIR)", Unsupported),
        ("BLOCK_V2 (PHASE 0)", Unsupported),
        ("BLOCK (DEPRECATED)", Unsupported),
        ("ATTESTATION", Signed(K::Attestation, Reproduced)),
        ("AGGREGATION_SLOT", Signed(K::AggregationSlot, Reproduced)),
        (
            "AGGREGATE_AND_PROOF_V2 (GLOAS)",
            Signed(K::AggregateAndProof, Reproduced),
        ),
        (
            "AGGREGATE_AND_PROOF_V2 (FULU)",
            Signed(K::AggregateAndProof, Differs(ELECTRA_AGGREGATE_ROOT.into())),
        ),
        (
            "AGGREGATE_AND_PROOF_V2 (ELECTRA)",
            Signed(K::AggregateAndProof, Differs(ELECTRA_AGGREGATE_ROOT.into())),
        ),
        (
            "AGGREGATE_AND_PROOF_V2 (DENEB)",
            Signed(K::AggregateAndProof, Reproduced),
        ),
        (
            "AGGREGATE_AND_PROOF_V2 (CAPELLA)",
            Signed(K::AggregateAndProof, Reproduced),
        ),
        (
            "AGGREGATE_AND_PROOF_V2 (BELLATRIX)",
            Signed(K::AggregateAndProof, Reproduced),
        ),
        (
            "AGGREGATE_AND_PROOF_V2 (ALTAIR)",
            Signed(K::AggregateAndProof, Reproduced),
        ),
        (
            "AGGREGATE_AND_PROOF_V2 (PHASE 0)",
            Signed(K::AggregateAndProof, Reproduced),
        ),
        (
            "AGGREGATE_AND_PROOF (DEPRECATED)",
            Signed(K::AggregateAndProof, Reproduced),
        ),
        ("RANDAO_REVEAL", Signed(K::RandaoReveal, Reproduced)),
        ("VOLUNTARY_EXIT", Signed(K::VoluntaryExit, Reproduced)),
        (
            "SYNC_COMMITTEE_MESSAGE",
            Signed(K::SyncCommitteeMessage, Reproduced),
        ),
        (
            "SYNC_COMMITTEE_SELECTION_PROOF",
            Signed(K::SyncSelectionProof, Reproduced),
        ),
        ("SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF", Invalid),
        (
            "VALIDATOR_REGISTRATION",
            Signed(K::ValidatorRegistration, Reproduced),
        ),
        ("DEPOSIT", Signed(K::Deposit, Reproduced)),
        ("EXECUTION_PAYLOAD_BID (GLOAS)", Unsupported),
        ("EXECUTION_PAYLOAD_ENVELOPE (GLOAS)", Invalid),
        (
            "PAYLOAD_ATTESTATION_MESSAGE (GLOAS)",
            Signed(K::PayloadAttestation, Absent),
        ),
        (
            "PROPOSER_PREFERENCES (GLOAS)",
            Signed(K::ProposerPreferences, Absent),
        ),
        ("BUILDER_REQUEST_AUTH (GLOAS)", Unsupported),
    ])
}

/// The fork a registration is rooted in: it carries none, and the node takes its network's
/// genesis fork version with a zero root (`Network::fork_info`). The examples' network has
/// genesis fork version `0x00000001`.
fn examples_genesis() -> ForkInfo {
    ForkInfo {
        fork: Fork {
            previous_version: [0, 0, 0, 1],
            current_version: [0, 0, 0, 1],
            epoch: 0,
        },
        genesis_validators_root: [0; 32],
    }
}

fn outcome(example: &Value) -> (Outcome, String) {
    let request = match parse_request(example.to_string().as_bytes()) {
        Ok(request) => request,
        Err(ParseError::Unsupported(reason)) => return (Unsupported, reason),
        Err(ParseError::Invalid(reason)) => return (Invalid, reason),
    };
    let fork = match &request.duty {
        Duty::ValidatorRegistration(_) => examples_genesis(),
        _ => request.fork,
    };
    let computed = format_root(&request.duty.signing_root(&fork));
    let root = match example.get("signingRoot").and_then(Value::as_str) {
        None => Root::Absent,
        Some(root) if root == computed => Root::Reproduced,
        Some(_) => Root::Differs(computed.clone()),
    };
    (Signed(request.duty.kind(), root), computed)
}

#[test]
fn every_request_example_of_the_specification_has_its_expected_outcome() {
    let examples = examples();
    let expected = expected();
    let mut failures = Vec::new();
    for (name, example) in &examples {
        let (actual, detail) = outcome(example);
        match expected.get(name.as_str()) {
            None => failures.push(format!(
                "{name}: not in the table, outcome {actual:?} ({detail})"
            )),
            Some(expected) if *expected != actual => failures.push(format!(
                "{name}: expected {expected:?}, got {actual:?} ({detail}; example root {})",
                example["signingRoot"]
            )),
            Some(_) => println!("{name}: {actual:?}"),
        }
    }
    for name in expected.keys() {
        if !examples.contains_key(*name) {
            failures.push(format!("{name}: no longer an example of the specification"));
        }
    }
    assert!(failures.is_empty(), "\n{}", failures.join("\n"));
}

/// The two examples refused as invalid are each one field away from a mainnet request, and with
/// that field fixed they are signed: the contribution example is written for the minimal preset
/// (a 1-byte `Bitvector[8]`; mainnet's is 16 bytes), and the envelope example's `logs_bloom` is
/// 262 bytes (a `ByteVector[256]`).
#[test]
fn the_invalid_examples_are_signed_once_their_one_defect_is_fixed() {
    let examples = examples();

    let mut contribution = examples["SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF"].clone();
    let bits = &mut contribution["contribution_and_proof"]["contribution"]["aggregation_bits"];
    assert_eq!(bits.as_str(), Some("0x24"));
    // The same first byte: both bitvectors fit one chunk, so the root is unchanged.
    *bits = Value::from(format!("0x24{}", "00".repeat(15)));
    assert_eq!(
        outcome(&contribution).0,
        Signed(DutyKind::ContributionAndProof, Root::Reproduced)
    );

    let mut envelope = examples["EXECUTION_PAYLOAD_ENVELOPE (GLOAS)"].clone();
    let bloom = &mut envelope["execution_payload_envelope"]["data"]["payload"]["logs_bloom"];
    assert_eq!(bloom.as_str().map(str::len), Some(2 + 2 * 262));
    *bloom = Value::from(format!("0x{}", "00".repeat(256)));
    assert_eq!(
        outcome(&envelope).0,
        Signed(DutyKind::ExecutionPayloadEnvelope, Root::Absent)
    );
}

/// Every request type of the specification's discriminator is either signed or refused by name,
/// and no type the parser signs is missing from the specification.
#[test]
fn every_request_type_of_the_specification_is_handled() {
    let schema = &sign_operation()["requestBody"]["content"]["application/json"]["schema"];
    let types: Vec<String> = schema["discriminator"]["mapping"]
        .as_mapping()
        .unwrap()
        .keys()
        .map(|key| key.as_str().unwrap().to_owned())
        .collect();
    let refused = ["BLOCK", "EXECUTION_PAYLOAD_BID", "BUILDER_REQUEST_AUTH"];
    let signed = [
        "AGGREGATION_SLOT",
        "AGGREGATE_AND_PROOF",
        "AGGREGATE_AND_PROOF_V2",
        "ATTESTATION",
        "BLOCK_V2",
        "DEPOSIT",
        "RANDAO_REVEAL",
        "VOLUNTARY_EXIT",
        "SYNC_COMMITTEE_MESSAGE",
        "SYNC_COMMITTEE_SELECTION_PROOF",
        "SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF",
        "VALIDATOR_REGISTRATION",
        "EXECUTION_PAYLOAD_ENVELOPE",
        "PAYLOAD_ATTESTATION_MESSAGE",
        "PROPOSER_PREFERENCES",
    ];
    let mut known: Vec<&str> = signed.iter().chain(&refused).copied().collect();
    known.sort_unstable();
    let mut types: Vec<&str> = types.iter().map(String::as_str).collect();
    types.sort_unstable();
    assert_eq!(types, known);

    // A refused type is refused by name, with its reason, not as an unknown type.
    for kind in refused {
        let body = serde_json::json!({ "type": kind });
        match parse_request(body.to_string().as_bytes()) {
            Err(ParseError::Unsupported(reason)) => {
                assert!(reason.starts_with(kind), "{kind}: {reason}")
            }
            other => panic!("{kind}: {other:?}"),
        }
    }
}

/// The endpoints and status codes the specification defines. Codes beyond them are this
/// signer's extensions (`docs/remote-signing-api.md`, "Status codes").
#[test]
fn the_specification_defines_two_endpoints_and_five_status_codes() {
    let root = spec("remote-signing-oapi.yaml");
    assert_eq!(root["info"]["version"].as_str(), Some("v1.4.0"));
    let mut paths: Vec<&str> = root["paths"]
        .as_mapping()
        .unwrap()
        .keys()
        .map(|key| key.as_str().unwrap())
        .collect();
    paths.sort_unstable();
    assert_eq!(
        paths,
        ["/api/v1/eth2/publicKeys", "/api/v1/eth2/sign/{identifier}"]
    );
    let operation = sign_operation();
    let mut codes: Vec<&str> = operation["responses"]
        .as_mapping()
        .unwrap()
        .keys()
        .map(|key| key.as_str().unwrap())
        .collect();
    codes.sort_unstable();
    assert_eq!(codes, ["200", "400", "404", "412", "500"]);
}
