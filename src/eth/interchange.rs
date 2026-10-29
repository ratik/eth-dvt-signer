//! EIP-3076 slashing-protection interchange, format version 5.
//!
//! - [parse]: the JSON document, strictly (decimal strings, `0x` hex, no unknown fields), then the
//!   history of every validator against Ethereum's slashing conditions. Entries of one public key
//!   are merged; exact duplicates are kept once. A history slashable with respect to itself is
//!   refused whole: two different blocks for one slot (a missing signing root matching nothing), two
//!   different attestations for one target, an attestation with its source after its target, or two
//!   attestations surrounding each other. The interchange test suite allows refusing such files,
//!   and silently importing part of a slashable history would hide that the key was misused.
//! - [Interchange::summary]: what enters consensus, EIP-3076's minimal form (the latest block and
//!   the latest attestation of each validator; see `slashing`).
//! - [Interchange::digest]: SHA-256 of a canonical encoding, independent of the JSON's formatting.
//! - [export]: an interchange from the network's records (`slashing::Protection::export`).

use crate::{
    eth::{duty::ValidatorKey, types::Root},
    import::{hex0x, unhex_array},
    slashing::{
        ChainIdentity, Exported, HistoryImport, HistorySummary, ImportedAttestation, ImportedBlock,
    },
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;

/// The only interchange format version.
pub const FORMAT_VERSION: &str = "5";

/// Domain of [Interchange::digest].
const DIGEST_NAMESPACE: &[u8] = b"_ETH_MPC_SIGNER_EIP3076_INTERCHANGE";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InterchangeJson {
    pub metadata: MetadataJson,
    pub data: Vec<ValidatorJson>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetadataJson {
    pub interchange_format_version: String,
    pub genesis_validators_root: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidatorJson {
    pub pubkey: String,
    pub signed_blocks: Vec<BlockJson>,
    pub signed_attestations: Vec<AttestationJson>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlockJson {
    pub slot: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing_root: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttestationJson {
    pub source_epoch: String,
    pub target_epoch: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing_root: Option<String>,
}

/// One validator's signed messages, as the interchange states them.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct History {
    /// By slot.
    pub blocks: BTreeMap<u64, Option<Root>>,
    /// By target: `(source, signing root)`.
    pub attestations: BTreeMap<u64, (u64, Option<Root>)>,
}

/// A parsed, validated interchange.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Interchange {
    pub chain: ChainIdentity,
    pub validators: BTreeMap<ValidatorKey, History>,
}

/// Why an interchange is refused.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("malformed interchange JSON: {0}")]
    Json(String),
    #[error("unsupported interchange_format_version {0:?} (supported: {FORMAT_VERSION:?})")]
    Version(String),
    #[error("invalid {0}")]
    Field(String),
    /// The history of `pubkey` is slashable with respect to itself.
    #[error("the history of {pubkey} is slashable with respect to itself: {reason}")]
    Slashable { pubkey: String, reason: String },
}

fn number(text: &str, field: &str) -> Result<u64, Error> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(Error::Field(format!("{field} {text:?} (a decimal string)")));
    }
    text.parse()
        .map_err(|_| Error::Field(format!("{field} {text:?} (out of range)")))
}

fn hex_field<const N: usize>(text: &str, field: &str) -> Result<[u8; N], Error> {
    if !text.starts_with("0x") {
        return Err(Error::Field(format!("{field} {text:?} (0x-prefixed hex)")));
    }
    unhex_array::<N>(text)
        .ok_or_else(|| Error::Field(format!("{field} {text:?} ({N} bytes of hex)")))
}

/// Parse and validate an interchange document.
pub fn parse(bytes: &[u8]) -> Result<Interchange, Error> {
    let json: InterchangeJson =
        serde_json::from_slice(bytes).map_err(|err| Error::Json(err.to_string()))?;
    from_json(&json)
}

pub fn from_json(json: &InterchangeJson) -> Result<Interchange, Error> {
    if json.metadata.interchange_format_version != FORMAT_VERSION {
        return Err(Error::Version(
            json.metadata.interchange_format_version.clone(),
        ));
    }
    let chain = ChainIdentity {
        genesis_validators_root: hex_field::<32>(
            &json.metadata.genesis_validators_root,
            "genesis_validators_root",
        )?,
    };
    let mut validators: BTreeMap<ValidatorKey, History> = BTreeMap::new();
    for entry in &json.data {
        let key = hex_field::<48>(&entry.pubkey, "pubkey")?;
        let slashable = |reason: String| Error::Slashable {
            pubkey: entry.pubkey.clone(),
            reason,
        };
        let history = validators.entry(key).or_default();
        for block in &entry.signed_blocks {
            let slot = number(&block.slot, "slot")?;
            let root = block
                .signing_root
                .as_deref()
                .map(|root| hex_field::<32>(root, "signing_root"))
                .transpose()?;
            match history.blocks.get(&slot) {
                // The same block again (or the same unknown block): one record.
                Some(existing) if *existing == root => {}
                Some(_) => {
                    return Err(slashable(format!(
                        "two different blocks for slot {slot} (a missing signing root matches \
                         nothing)"
                    )));
                }
                None => {
                    history.blocks.insert(slot, root);
                }
            }
        }
        for attestation in &entry.signed_attestations {
            let source = number(&attestation.source_epoch, "source_epoch")?;
            let target = number(&attestation.target_epoch, "target_epoch")?;
            let root = attestation
                .signing_root
                .as_deref()
                .map(|root| hex_field::<32>(root, "signing_root"))
                .transpose()?;
            if source > target {
                return Err(slashable(format!(
                    "attestation with source {source} after target {target}"
                )));
            }
            match history.attestations.get(&target) {
                Some(existing) if *existing == (source, root) => {}
                Some(_) => {
                    return Err(slashable(format!(
                        "two different attestations for target {target} (double vote)"
                    )));
                }
                None => {
                    history.attestations.insert(target, (source, root));
                }
            }
        }
    }
    // Surround votes: with one attestation per target, a history has none iff sources never
    // decrease as targets increase (for t1 < t2, s2 < s1 is exactly "the second surrounds the
    // first").
    for (key, history) in &validators {
        let mut previous: Option<(u64, u64)> = None;
        for (&target, &(source, _)) in &history.attestations {
            if let Some((previous_target, previous_source)) = previous
                && source < previous_source
            {
                return Err(Error::Slashable {
                    pubkey: hex0x(key),
                    reason: format!(
                        "attestation {source}->{target} surrounds \
                         {previous_source}->{previous_target}"
                    ),
                });
            }
            previous = Some((target, source));
        }
    }
    Ok(Interchange { chain, validators })
}

impl History {
    /// EIP-3076's minimal form: the latest block, and the attestation with the greatest target
    /// (in a history without surround votes, also the greatest source).
    pub fn summary(&self) -> HistorySummary {
        HistorySummary {
            block: self
                .blocks
                .iter()
                .next_back()
                .map(|(&slot, &signing_root)| ImportedBlock { slot, signing_root }),
            attestation: self.attestations.iter().next_back().map(
                |(&target, &(source, signing_root))| ImportedAttestation {
                    source,
                    target,
                    signing_root,
                },
            ),
        }
    }
}

impl Interchange {
    /// SHA-256 of the canonical encoding: chain, then each validator (by key) with its blocks (by
    /// slot) and attestations (by target), every number big endian, every root with a presence
    /// byte.
    pub fn digest(&self) -> Root {
        let mut hasher = Sha256::new();
        hasher.update(DIGEST_NAMESPACE);
        hasher.update(self.chain.genesis_validators_root);
        let root = |hasher: &mut Sha256, root: &Option<Root>| match root {
            Some(root) => {
                hasher.update([1]);
                hasher.update(root);
            }
            None => hasher.update([0]),
        };
        hasher.update((self.validators.len() as u64).to_be_bytes());
        for (key, history) in &self.validators {
            hasher.update(key);
            hasher.update((history.blocks.len() as u64).to_be_bytes());
            for (slot, signing_root) in &history.blocks {
                hasher.update(slot.to_be_bytes());
                root(&mut hasher, signing_root);
            }
            hasher.update((history.attestations.len() as u64).to_be_bytes());
            for (target, (source, signing_root)) in &history.attestations {
                hasher.update(source.to_be_bytes());
                hasher.update(target.to_be_bytes());
                root(&mut hasher, signing_root);
            }
        }
        hasher.finalize().into()
    }

    /// The import that enters consensus, for the validators `selected` (all when `None`).
    pub fn import(&self, selected: Option<&[ValidatorKey]>) -> Result<HistoryImport, Error> {
        let validators = match selected {
            None => self
                .validators
                .iter()
                .map(|(key, history)| (*key, history.summary()))
                .collect(),
            Some(keys) => keys
                .iter()
                .map(|key| {
                    self.validators
                        .get(key)
                        .map(|history| (*key, history.summary()))
                        .ok_or_else(|| {
                            Error::Field(format!("{} is not in the interchange", hex0x(key)))
                        })
                })
                .collect::<Result<_, _>>()?,
        };
        Ok(HistoryImport {
            chain: self.chain,
            digest: self.digest(),
            validators,
        })
    }
}

/// An interchange document of `validators` for `chain`.
pub fn export(chain: &ChainIdentity, validators: &[(ValidatorKey, Exported)]) -> InterchangeJson {
    InterchangeJson {
        metadata: MetadataJson {
            interchange_format_version: FORMAT_VERSION.into(),
            genesis_validators_root: hex0x(&chain.genesis_validators_root),
        },
        data: validators
            .iter()
            .map(|(key, exported)| ValidatorJson {
                pubkey: hex0x(key),
                signed_blocks: exported
                    .blocks
                    .iter()
                    .map(|(slot, root)| BlockJson {
                        slot: slot.to_string(),
                        signing_root: root.as_ref().map(|root| hex0x(root)),
                    })
                    .collect(),
                signed_attestations: exported
                    .attestations
                    .iter()
                    .map(|(source, target, root)| AttestationJson {
                        source_epoch: source.to_string(),
                        target_epoch: target.to_string(),
                        signing_root: root.as_ref().map(|root| hex0x(root)),
                    })
                    .collect(),
            })
            .collect(),
    }
}

#[cfg(test)]
#[path = "../../tests/unit/eth/interchange.rs"]
mod tests;
