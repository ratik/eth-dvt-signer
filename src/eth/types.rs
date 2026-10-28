//! Ethereum consensus containers that validators sign, as the consensus specifications define
//! them (v1.6.1, mainnet preset), with their SSZ encoding and `hash_tree_root` from sigp's
//! `ethereum_ssz` and `tree_hash` (the implementation Lighthouse uses) and the JSON shape of the
//! Web3Signer API (snake_case fields, quoted integers, `0x`-hex bytes).

use serde::{Deserialize, Serialize};
use ssz::{BitList, BitVector};
use ssz_derive::{Decode, Encode};
use tree_hash_derive::TreeHash;
use typenum::{U64, U128, U2048, U131072};

/// `Root`: a 32-byte hash.
pub type Root = [u8; 32];
/// `Version`: a 4-byte fork version.
pub type Version = [u8; 4];
/// `BLSSignature`: a 96-byte compressed G2 point (signed objects may contain signatures).
pub type Signature = [u8; 96];

/// `MAX_VALIDATORS_PER_COMMITTEE` * `MAX_COMMITTEES_PER_SLOT` (Electra aggregation bits).
type ElectraAggregationBits = U131072;

/// `0x`-prefixed hex of fixed-size byte arrays.
pub mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer, de::Error};

    pub fn serialize<S: Serializer, const N: usize>(
        bytes: &[u8; N],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&format!("0x{}", hex::encode(bytes)))
    }

    pub fn deserialize<'de, D: Deserializer<'de>, const N: usize>(
        deserializer: D,
    ) -> Result<[u8; N], D::Error> {
        let text = String::deserialize(deserializer)?;
        let digits = text
            .strip_prefix("0x")
            .ok_or_else(|| D::Error::custom("hex bytes must start with 0x"))?;
        let bytes = hex::decode(digits).map_err(D::Error::custom)?;
        bytes.try_into().map_err(|bytes: Vec<u8>| {
            D::Error::custom(format!("expected {N} bytes, got {}", bytes.len()))
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, TreeHash)]
#[serde(deny_unknown_fields)]
pub struct Checkpoint {
    #[serde(with = "serde_utils::quoted_u64")]
    pub epoch: u64,
    #[serde(with = "hex_bytes")]
    pub root: Root,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, TreeHash)]
#[serde(deny_unknown_fields)]
pub struct AttestationData {
    #[serde(with = "serde_utils::quoted_u64")]
    pub slot: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub index: u64,
    #[serde(with = "hex_bytes")]
    pub beacon_block_root: Root,
    pub source: Checkpoint,
    pub target: Checkpoint,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, TreeHash)]
#[serde(deny_unknown_fields)]
pub struct BeaconBlockHeader {
    #[serde(with = "serde_utils::quoted_u64")]
    pub slot: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub proposer_index: u64,
    #[serde(with = "hex_bytes")]
    pub parent_root: Root,
    #[serde(with = "hex_bytes")]
    pub state_root: Root,
    #[serde(with = "hex_bytes")]
    pub body_root: Root,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, TreeHash)]
#[serde(deny_unknown_fields)]
pub struct VoluntaryExit {
    #[serde(with = "serde_utils::quoted_u64")]
    pub epoch: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub validator_index: u64,
}

/// `Attestation` up to Deneb.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, TreeHash)]
#[serde(deny_unknown_fields)]
pub struct AttestationPhase0 {
    pub aggregation_bits: BitList<U2048>,
    pub data: AttestationData,
    #[serde(with = "hex_bytes")]
    pub signature: Signature,
}

/// `Attestation` from Electra (EIP-7549).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, TreeHash)]
#[serde(deny_unknown_fields)]
pub struct AttestationElectra {
    pub aggregation_bits: BitList<ElectraAggregationBits>,
    pub data: AttestationData,
    #[serde(with = "hex_bytes")]
    pub signature: Signature,
    pub committee_bits: BitVector<U64>,
}

/// `AggregateAndProof` up to Deneb.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, TreeHash)]
#[serde(deny_unknown_fields)]
pub struct AggregateAndProofPhase0 {
    #[serde(with = "serde_utils::quoted_u64")]
    pub aggregator_index: u64,
    pub aggregate: AttestationPhase0,
    #[serde(with = "hex_bytes")]
    pub selection_proof: Signature,
}

/// `AggregateAndProof` from Electra.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, TreeHash)]
#[serde(deny_unknown_fields)]
pub struct AggregateAndProofElectra {
    #[serde(with = "serde_utils::quoted_u64")]
    pub aggregator_index: u64,
    pub aggregate: AttestationElectra,
    #[serde(with = "hex_bytes")]
    pub selection_proof: Signature,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, TreeHash)]
#[serde(deny_unknown_fields)]
pub struct SyncAggregatorSelectionData {
    #[serde(with = "serde_utils::quoted_u64")]
    pub slot: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub subcommittee_index: u64,
}

/// `SyncCommitteeContribution` (`SYNC_COMMITTEE_SIZE / SYNC_COMMITTEE_SUBNET_COUNT` = 128 bits).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, TreeHash)]
#[serde(deny_unknown_fields)]
pub struct SyncCommitteeContribution {
    #[serde(with = "serde_utils::quoted_u64")]
    pub slot: u64,
    #[serde(with = "hex_bytes")]
    pub beacon_block_root: Root,
    #[serde(with = "serde_utils::quoted_u64")]
    pub subcommittee_index: u64,
    pub aggregation_bits: BitVector<U128>,
    #[serde(with = "hex_bytes")]
    pub signature: Signature,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, TreeHash)]
#[serde(deny_unknown_fields)]
pub struct ContributionAndProof {
    #[serde(with = "serde_utils::quoted_u64")]
    pub aggregator_index: u64,
    pub contribution: SyncCommitteeContribution,
    #[serde(with = "hex_bytes")]
    pub selection_proof: Signature,
}

/// `ForkData`: what `compute_fork_data_root` hashes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TreeHash)]
#[serde(deny_unknown_fields)]
pub struct ForkData {
    #[serde(with = "hex_bytes")]
    pub current_version: Version,
    #[serde(with = "hex_bytes")]
    pub genesis_validators_root: Root,
}

/// `SigningData`: what `compute_signing_root` hashes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TreeHash)]
#[serde(deny_unknown_fields)]
pub struct SigningData {
    #[serde(with = "hex_bytes")]
    pub object_root: Root,
    #[serde(with = "hex_bytes")]
    pub domain: Root,
}
