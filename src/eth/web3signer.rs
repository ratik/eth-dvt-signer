//! Requests of the Web3Signer Ethereum signing API
//! (`POST /api/v1/eth2/sign/{identifier}`, Consensys Web3Signer `openapi-specs/eth2`), as validator
//! clients send them (Lighthouse v8.3: snake_case objects, quoted integers, `signingRoot` always
//! present, `AGGREGATE_AND_PROOF` for every fork with the Electra attestation shape from Electra on,
//! the Gloas types of remote-signing-api v1.4.0 as `{"version": "GLOAS", "data": ...}`).
//!
//! Parsing only: the duty object is checked to have exactly the specification's shape, and the
//! client's `signingRoot` is kept to be compared with the one computed from the duty. Nothing here
//! decides whether a duty may be signed.

use super::{
    duty::{AggregateAndProof, Duty, DutyRequest, Fork, ForkInfo, ValidatorKey},
    gloas::{ExecutionPayloadEnvelope, PayloadAttestationData, ProposerPreferences},
    network::Network,
    types::{
        AggregateAndProofElectra, AggregateAndProofPhase0, AttestationData, BeaconBlockHeader,
        ContributionAndProof, DepositMessage, Root, SyncAggregatorSelectionData,
        ValidatorRegistration, Version, VoluntaryExit, hex_bytes,
    },
};
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::Value;

/// Block versions signed from their header (`BLOCK_V2` with `block_header`): every fork from
/// Bellatrix to Gloas. Phase 0 and Altair blocks come whole and are not supported.
pub const BLOCK_HEADER_VERSIONS: [&str; 6] =
    ["BELLATRIX", "CAPELLA", "DENEB", "ELECTRA", "FULU", "GLOAS"];

/// `AGGREGATE_AND_PROOF_V2` versions with the phase 0 attestation shape.
const PHASE0_AGGREGATE_VERSIONS: [&str; 5] = ["PHASE0", "ALTAIR", "BELLATRIX", "CAPELLA", "DENEB"];
/// `AGGREGATE_AND_PROOF_V2` versions with the Electra attestation shape.
const ELECTRA_AGGREGATE_VERSIONS: [&str; 2] = ["ELECTRA", "FULU"];
/// The version of the Gloas objects (`{"version": "GLOAS", "data": ...}`) and of a Gloas
/// `AGGREGATE_AND_PROOF_V2` (Electra's shape, rooted progressively).
const GLOAS: &str = "GLOAS";

/// Why a request cannot be signed as sent (HTTP 400).
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
    #[error("invalid request: {0}")]
    Invalid(String),
    #[error("unsupported: {0}")]
    Unsupported(String),
}

/// Why a signing request does not name a duty to sign.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RequestError {
    #[error(transparent)]
    Parse(#[from] ParseError),
    #[error("the registration's pubkey is not the validator key of the path")]
    RegistrationKey,
    /// A registration carries no fork: only a pinned network gives its domain.
    #[error("no Ethereum network is pinned")]
    NoNetwork,
}

/// The duty `POST /api/v1/eth2/sign/{identifier}` with `body` asks the network to sign, under
/// `network` (the pinned chain, if any), and the client's signing root. The node's API and the
/// gateway (`mpc-gateway`) read a request the same way:
/// - a builder registration carries no fork: its domain is the network's genesis fork version
///   with a zero root (`Network::fork_info`), and its key must be the path's;
/// - an aggregate is rooted in its epoch's form (progressive from Gloas on), which the request
///   does not tell: the pinned schedule does (`Network::resolve`).
pub fn duty_request(
    identifier: &str,
    body: &[u8],
    network: Option<&Network>,
) -> Result<(DutyRequest, Option<Root>), RequestError> {
    let validator = parse_identifier(identifier)?;
    let request = parse_request(body)?;
    let mut fork = request.fork;
    if let Some(registration) = request.duty.registration() {
        if registration.pubkey != validator {
            return Err(RequestError::RegistrationKey);
        }
        fork = network
            .ok_or(RequestError::NoNetwork)?
            .fork_info(&request.duty);
    }
    let duty = match network {
        Some(network) => network.resolve(request.duty),
        None => request.duty,
    };
    Ok((
        DutyRequest {
            validator,
            fork,
            duty,
        },
        request.signing_root,
    ))
}

/// Whether `signature` (96 bytes, compressed G2) is the validator key's signature of `root`
/// (BLS12-381 min-pk, the Ethereum ciphersuite).
pub fn verify_signature(key: &ValidatorKey, root: &Root, signature: &[u8]) -> bool {
    use crate::dkg::{GroupKey, signing};
    use commonware_codec::DecodeExt as _;
    let (Ok(key), Ok(signature)) = (
        GroupKey::decode(commonware_codec::Copying(key.as_slice())),
        signing::Signature::decode(commonware_codec::Copying(signature)),
    ) else {
        return false;
    };
    signing::Message::Ethereum(*root)
        .verify(&key, &signature)
        .is_ok()
}

/// A parsed signing request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub fork: ForkInfo,
    pub duty: Duty,
    /// The client's signing root (`signingRoot`), to compare with the computed one.
    pub signing_root: Option<Root>,
}

/// `0x`-prefixed hex of a 48-byte compressed BLS public key.
pub fn parse_identifier(identifier: &str) -> Result<ValidatorKey, ParseError> {
    let digits = identifier
        .strip_prefix("0x")
        .ok_or_else(|| ParseError::Invalid("public key must start with 0x".into()))?;
    hex::decode(digits)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| ParseError::Invalid("public key must be 48 bytes of hex".into()))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Epoch {
    #[serde(with = "serde_utils::quoted_u64")]
    epoch: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Slot {
    #[serde(with = "serde_utils::quoted_u64")]
    slot: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SyncCommitteeMessage {
    #[serde(with = "hex_bytes")]
    beacon_block_root: Root,
    #[serde(with = "serde_utils::quoted_u64")]
    slot: u64,
}

/// `deposit` of a `DEPOSIT` request: the deposit message and the genesis fork version.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DepositRequest {
    #[serde(with = "hex_bytes")]
    pubkey: [u8; 48],
    #[serde(with = "hex_bytes")]
    withdrawal_credentials: Root,
    #[serde(with = "serde_utils::quoted_u64")]
    amount: u64,
    #[serde(with = "hex_bytes")]
    genesis_fork_version: Version,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BeaconBlockRequest {
    version: String,
    block_header: Option<BeaconBlockHeader>,
    block: Option<Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Versioned {
    version: String,
    data: Value,
}

#[derive(Deserialize)]
struct Envelope {
    #[serde(rename = "type")]
    kind: String,
    #[serde(alias = "forkInfo")]
    fork_info: Option<ForkInfo>,
    #[serde(rename = "signingRoot", alias = "signing_root", default)]
    signing_root: Option<String>,
}

fn field<T: DeserializeOwned>(body: &Value, name: &str) -> Result<T, ParseError> {
    let value = body
        .get(name)
        .ok_or_else(|| ParseError::Invalid(format!("missing `{name}`")))?;
    // Deserialized from the borrowed value: an envelope's payload is not copied.
    T::deserialize(value).map_err(|err| ParseError::Invalid(format!("`{name}`: {err}")))
}

/// A Gloas object (`{"version": "GLOAS", "data": ...}`) of request type `kind`.
fn gloas<T: DeserializeOwned>(body: &Value, kind: &str, name: &str) -> Result<T, ParseError> {
    let value = body
        .get(name)
        .ok_or_else(|| ParseError::Invalid(format!("missing `{name}`")))?;
    match value.get("version").and_then(Value::as_str) {
        Some(GLOAS) => {}
        Some(version) => {
            return Err(ParseError::Unsupported(format!("{kind} version {version}")));
        }
        None => return Err(ParseError::Invalid(format!("`{name}`: missing `version`"))),
    }
    if let Some(object) = value.as_object()
        && let Some(other) = object
            .keys()
            .find(|key| *key != "version" && *key != "data")
    {
        return Err(ParseError::Invalid(format!(
            "`{name}`: unknown field `{other}`"
        )));
    }
    let data = value
        .get("data")
        .ok_or_else(|| ParseError::Invalid(format!("`{name}`: missing `data`")))?;
    T::deserialize(data).map_err(|err| ParseError::Invalid(format!("`{name}.data`: {err}")))
}

fn object<T: DeserializeOwned>(value: Value, name: &str) -> Result<T, ParseError> {
    serde_json::from_value(value).map_err(|err| ParseError::Invalid(format!("`{name}`: {err}")))
}

fn root(text: &str) -> Result<Root, ParseError> {
    text.strip_prefix("0x")
        .and_then(|digits| hex::decode(digits).ok())
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| ParseError::Invalid("`signingRoot` must be 32 bytes of 0x-hex".into()))
}

/// Parse a request body.
pub fn parse_request(body: &[u8]) -> Result<Request, ParseError> {
    let body: Value =
        serde_json::from_slice(body).map_err(|err| ParseError::Invalid(err.to_string()))?;
    let envelope =
        Envelope::deserialize(&body).map_err(|err| ParseError::Invalid(err.to_string()))?;
    let duty = match envelope.kind.as_str() {
        "BLOCK_V2" => {
            let block: BeaconBlockRequest = field(&body, "beacon_block")?;
            if !BLOCK_HEADER_VERSIONS.contains(&block.version.as_str()) {
                return Err(ParseError::Unsupported(format!(
                    "BLOCK_V2 version {} (supported: {})",
                    block.version,
                    BLOCK_HEADER_VERSIONS.join(", ")
                )));
            }
            if block.block.is_some() {
                return Err(ParseError::Unsupported(
                    "full blocks: send the block header (`block_header`)".into(),
                ));
            }
            Duty::BlockProposal(
                block
                    .block_header
                    .ok_or_else(|| ParseError::Invalid("missing `block_header`".into()))?,
            )
        }
        "ATTESTATION" => Duty::Attestation(field::<AttestationData>(&body, "attestation")?),
        "RANDAO_REVEAL" => Duty::RandaoReveal {
            epoch: field::<Epoch>(&body, "randao_reveal")?.epoch,
        },
        "AGGREGATION_SLOT" => Duty::AggregationSlot {
            slot: field::<Slot>(&body, "aggregation_slot")?.slot,
        },
        // Deprecated by Web3Signer but what Lighthouse sends for every fork: the attestation
        // shape tells the fork (Electra added `committee_bits`).
        "AGGREGATE_AND_PROOF" => {
            let value: Value = field(&body, "aggregate_and_proof")?;
            let electra = value
                .get("aggregate")
                .and_then(|aggregate| aggregate.get("committee_bits"))
                .is_some();
            Duty::AggregateAndProof(if electra {
                AggregateAndProof::Electra(Box::new(object::<AggregateAndProofElectra>(
                    value,
                    "aggregate_and_proof",
                )?))
            } else {
                AggregateAndProof::Phase0(Box::new(object::<AggregateAndProofPhase0>(
                    value,
                    "aggregate_and_proof",
                )?))
            })
        }
        "AGGREGATE_AND_PROOF_V2" => {
            let versioned: Versioned = field(&body, "aggregate_and_proof")?;
            let version = versioned.version.as_str();
            Duty::AggregateAndProof(if PHASE0_AGGREGATE_VERSIONS.contains(&version) {
                AggregateAndProof::Phase0(Box::new(object(
                    versioned.data,
                    "aggregate_and_proof.data",
                )?))
            } else if ELECTRA_AGGREGATE_VERSIONS.contains(&version) {
                AggregateAndProof::Electra(Box::new(object(
                    versioned.data,
                    "aggregate_and_proof.data",
                )?))
            } else if version == GLOAS {
                AggregateAndProof::Gloas(Box::new(object(
                    versioned.data,
                    "aggregate_and_proof.data",
                )?))
            } else {
                return Err(ParseError::Unsupported(format!(
                    "AGGREGATE_AND_PROOF_V2 version {version}"
                )));
            })
        }
        "SYNC_COMMITTEE_MESSAGE" => {
            let message: SyncCommitteeMessage = field(&body, "sync_committee_message")?;
            Duty::SyncCommitteeMessage {
                beacon_block_root: message.beacon_block_root,
                slot: message.slot,
            }
        }
        "SYNC_COMMITTEE_SELECTION_PROOF" => {
            Duty::SyncSelectionProof(field::<SyncAggregatorSelectionData>(
                &body,
                "sync_aggregator_selection_data",
            )?)
        }
        "SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF" => {
            Duty::ContributionAndProof(Box::new(field::<ContributionAndProof>(
                &body,
                "contribution_and_proof",
            )?))
        }
        "VOLUNTARY_EXIT" => Duty::VoluntaryExit(field::<VoluntaryExit>(&body, "voluntary_exit")?),
        // Fork-agnostic (`compute_domain(DOMAIN_DEPOSIT)`): the genesis fork version comes with
        // the deposit, there is no `fork_info`.
        "DEPOSIT" => {
            if envelope.fork_info.is_some() {
                return Err(ParseError::Invalid(
                    "DEPOSIT takes `deposit.genesis_fork_version`, not `fork_info`".into(),
                ));
            }
            let deposit: DepositRequest = field(&body, "deposit")?;
            let signing_root = envelope.signing_root.as_deref().map(root).transpose()?;
            return Ok(Request {
                fork: ForkInfo {
                    fork: Fork {
                        previous_version: deposit.genesis_fork_version,
                        current_version: deposit.genesis_fork_version,
                        epoch: 0,
                    },
                    genesis_validators_root: [0; 32],
                },
                duty: Duty::Deposit(DepositMessage {
                    pubkey: deposit.pubkey,
                    withdrawal_credentials: deposit.withdrawal_credentials,
                    amount: deposit.amount,
                }),
                signing_root,
            });
        }
        // Fork-agnostic (`compute_domain(DOMAIN_APPLICATION_BUILDER)`), sent without `fork_info`
        // (Web3Signer's API; Lighthouse omits it). The domain needs the network's genesis fork
        // version, which the request does not carry: the API puts the network's form in place of
        // this zero one (`Network::fork_info`), and the fork check refuses any other.
        "VALIDATOR_REGISTRATION" => {
            if envelope.fork_info.is_some() {
                return Err(ParseError::Invalid(
                    "VALIDATOR_REGISTRATION takes no `fork_info`".into(),
                ));
            }
            let registration: ValidatorRegistration = field(&body, "validator_registration")?;
            let signing_root = envelope.signing_root.as_deref().map(root).transpose()?;
            return Ok(Request {
                fork: ForkInfo {
                    fork: Fork {
                        previous_version: [0; 4],
                        current_version: [0; 4],
                        epoch: 0,
                    },
                    genesis_validators_root: [0; 32],
                },
                duty: Duty::ValidatorRegistration(registration),
                signing_root,
            });
        }
        "PAYLOAD_ATTESTATION_MESSAGE" => Duty::PayloadAttestation(gloas::<PayloadAttestationData>(
            &body,
            "PAYLOAD_ATTESTATION_MESSAGE",
            "payload_attestation_message",
        )?),
        // The whole payload, hashed here into the summary consensus carries (`eth::gloas`).
        "EXECUTION_PAYLOAD_ENVELOPE" => {
            let envelope = gloas::<ExecutionPayloadEnvelope>(
                &body,
                "EXECUTION_PAYLOAD_ENVELOPE",
                "execution_payload_envelope",
            )?;
            Duty::ExecutionPayloadEnvelope(Box::new(
                envelope
                    .summary()
                    .map_err(|err| ParseError::Invalid(err.to_string()))?,
            ))
        }
        "PROPOSER_PREFERENCES" => Duty::ProposerPreferences(gloas::<ProposerPreferences>(
            &body,
            "PROPOSER_PREFERENCES",
            "proposer_preferences",
        )?),
        "EXECUTION_PAYLOAD_BID" => {
            return Err(ParseError::Unsupported(
                "EXECUTION_PAYLOAD_BID: a builder's message, never a validator's (a self-built \
                 bid carries no signature)"
                    .into(),
            ));
        }
        "BLOCK" => {
            return Err(ParseError::Unsupported(
                "BLOCK (deprecated): use BLOCK_V2 with a block header".into(),
            ));
        }
        other => {
            return Err(ParseError::Unsupported(format!(
                "signing request type {other} (see docs/ethereum-signing.md)"
            )));
        }
    };
    let fork = envelope
        .fork_info
        .ok_or_else(|| ParseError::Invalid("missing `fork_info`".into()))?;
    let signing_root = envelope.signing_root.as_deref().map(root).transpose()?;
    Ok(Request {
        fork,
        duty,
        signing_root,
    })
}
