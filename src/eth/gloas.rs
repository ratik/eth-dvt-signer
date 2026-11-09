//! Gloas (EIP-7732, consensus-specs v1.7.0-beta.4) containers a validator signs, in the JSON
//! shape of the Web3Signer API (remote-signing-api v1.4.0, as Lighthouse v8.3 sends it), with
//! their `hash_tree_root`.
//!
//! | Message | Signed object | Domain |
//! | --- | --- | --- |
//! | PTC vote | `PayloadAttestationData` | `DOMAIN_PTC_ATTESTER`, epoch of its slot |
//! | Payload of a self-built block | `ExecutionPayloadEnvelope` | `DOMAIN_BEACON_BUILDER`, epoch of the payload's slot |
//! | Proposer preferences | `ProposerPreferences` | `DOMAIN_PROPOSER_PREFERENCES`, the fork version of the proposal's epoch |
//! | Aggregate | `AggregateAndProof` (Electra's fields; `Attestation` is a progressive container from Gloas on) | unchanged |
//!
//! An envelope carries the whole execution payload (transactions included, megabytes). The API
//! node hashes it into an [`EnvelopeSummary`]: the fields a rule reads as values, every other
//! leaf as its root. Only the summary enters consensus, and it has the envelope's root, so
//! every node signs exactly the envelope the client sent.

use super::{
    progressive,
    types::{Address, AggregateAndProofElectra, AttestationElectra, Root, Signature, hex_bytes},
};
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use tree_hash::TreeHash as _;
use tree_hash_derive::TreeHash;

/// `BUILDER_INDEX_SELF_BUILD`: the builder index of a payload the proposer built itself.
pub const BUILDER_INDEX_SELF_BUILD: u64 = u64::MAX;

/// `MAX_EXTRA_DATA_BYTES` (`ExtraData` is a `ByteList[32]`).
pub const MAX_EXTRA_DATA_BYTES: usize = 32;

/// `PayloadAttestationData`: a PTC (payload timeliness committee) vote.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, TreeHash)]
#[serde(deny_unknown_fields)]
pub struct PayloadAttestationData {
    #[serde(with = "hex_bytes")]
    pub beacon_block_root: Root,
    #[serde(with = "serde_utils::quoted_u64")]
    pub slot: u64,
    pub payload_present: bool,
    pub blob_data_available: bool,
}

/// `ProposerPreferences` (Gloas `p2p-interface.md`): the fee recipient and gas limit a proposer
/// accepts trustless builder bids for, for one of its proposal slots.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, TreeHash)]
#[serde(deny_unknown_fields)]
pub struct ProposerPreferences {
    #[serde(with = "hex_bytes")]
    pub dependent_root: Root,
    #[serde(with = "serde_utils::quoted_u64")]
    pub proposal_slot: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub validator_index: u64,
    #[serde(with = "hex_bytes")]
    pub fee_recipient: Address,
    #[serde(with = "serde_utils::quoted_u64")]
    pub target_gas_limit: u64,
}

/// The root of an `Attestation` from Gloas on: Electra's fields in a progressive container,
/// `aggregation_bits` a progressive bit list.
pub fn attestation_root(attestation: &AttestationElectra) -> Root {
    progressive::container_root(&[
        progressive::bit_list_root(&attestation.aggregation_bits.iter().collect::<Vec<_>>()),
        attestation.data.tree_hash_root().0,
        attestation.signature.tree_hash_root().0,
        attestation.committee_bits.tree_hash_root().0,
    ])
}

/// The root of an `AggregateAndProof` from Gloas on: a plain container of Electra's fields,
/// whose attestation roots as [`attestation_root`].
pub fn aggregate_and_proof_root(aggregate: &AggregateAndProofElectra) -> Root {
    progressive::plain_container_root(&[
        progressive::u64_root(aggregate.aggregator_index),
        attestation_root(&aggregate.aggregate),
        aggregate.selection_proof.tree_hash_root().0,
    ])
}

/// `0x`-hex of bytes of any length.
pub mod hex_vec {
    use serde::{Deserialize, Deserializer, Serializer, de::Error};

    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&format!("0x{}", hex::encode(bytes)))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(deserializer)?;
        let digits = text
            .strip_prefix("0x")
            .ok_or_else(|| D::Error::custom("hex bytes must start with 0x"))?;
        hex::decode(digits).map_err(D::Error::custom)
    }
}

/// A list of `0x`-hex byte strings (transactions).
mod hex_vec_list {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    #[derive(Serialize, Deserialize)]
    struct Item(#[serde(with = "super::hex_vec")] Vec<u8>);

    pub fn serialize<S: Serializer>(items: &[Vec<u8>], serializer: S) -> Result<S::Ok, S::Error> {
        items
            .iter()
            .map(|item| Item(item.clone()))
            .collect::<Vec<_>>()
            .serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<Vec<u8>>, D::Error> {
        Ok(Vec::<Item>::deserialize(deserializer)?
            .into_iter()
            .map(|Item(bytes)| bytes)
            .collect())
    }
}

/// A `uint256` as a decimal string (`base_fee_per_gas`), held as its 32-byte little-endian
/// encoding (its SSZ encoding and its root).
mod decimal_u256 {
    use serde::{Deserialize, Deserializer, Serializer, de::Error};

    pub fn parse(text: &str) -> Option<[u8; 32]> {
        if text.is_empty() || text.len() > 78 || !text.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        let mut value = [0u8; 32];
        for digit in text.bytes() {
            // value = value * 10 + digit, little-endian, refusing an overflow.
            let mut carry = u32::from(digit - b'0');
            for byte in &mut value {
                let product = u32::from(*byte) * 10 + carry;
                *byte = product as u8;
                carry = product >> 8;
            }
            if carry != 0 {
                return None;
            }
        }
        Some(value)
    }

    pub fn format(value: &[u8; 32]) -> String {
        let mut digits = Vec::new();
        let mut rest = *value;
        while rest.iter().any(|byte| *byte != 0) {
            // rest /= 10, from the most significant byte down.
            let mut remainder = 0u32;
            for byte in rest.iter_mut().rev() {
                let current = (remainder << 8) | u32::from(*byte);
                *byte = (current / 10) as u8;
                remainder = current % 10;
            }
            digits.push(b'0' + remainder as u8);
        }
        if digits.is_empty() {
            digits.push(b'0');
        }
        digits.reverse();
        String::from_utf8(digits).expect("ASCII digits")
    }

    pub fn serialize<S: Serializer>(value: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&format(value))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 32], D::Error> {
        let text = String::deserialize(deserializer)?;
        parse(&text).ok_or_else(|| D::Error::custom(format!("not a uint256: {text}")))
    }
}

pub use decimal_u256::{format as format_u256, parse as parse_u256};

/// `Withdrawal` (Capella).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TreeHash)]
#[serde(deny_unknown_fields)]
pub struct Withdrawal {
    #[serde(with = "serde_utils::quoted_u64")]
    pub index: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub validator_index: u64,
    #[serde(with = "hex_bytes")]
    pub address: Address,
    #[serde(with = "serde_utils::quoted_u64")]
    pub amount: u64,
}

/// `DepositRequest` (Electra).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TreeHash)]
#[serde(deny_unknown_fields)]
pub struct DepositRequest {
    #[serde(with = "hex_bytes")]
    pub pubkey: [u8; 48],
    #[serde(with = "hex_bytes")]
    pub withdrawal_credentials: Root,
    #[serde(with = "serde_utils::quoted_u64")]
    pub amount: u64,
    #[serde(with = "hex_bytes")]
    pub signature: Signature,
    #[serde(with = "serde_utils::quoted_u64")]
    pub index: u64,
}

/// `WithdrawalRequest` (Electra).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TreeHash)]
#[serde(deny_unknown_fields)]
pub struct WithdrawalRequest {
    #[serde(with = "hex_bytes")]
    pub source_address: Address,
    #[serde(with = "hex_bytes")]
    pub validator_pubkey: [u8; 48],
    #[serde(with = "serde_utils::quoted_u64")]
    pub amount: u64,
}

/// `ConsolidationRequest` (Electra).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TreeHash)]
#[serde(deny_unknown_fields)]
pub struct ConsolidationRequest {
    #[serde(with = "hex_bytes")]
    pub source_address: Address,
    #[serde(with = "hex_bytes")]
    pub source_pubkey: [u8; 48],
    #[serde(with = "hex_bytes")]
    pub target_pubkey: [u8; 48],
}

/// `BuilderDepositRequest` (Gloas, EIP-8282).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TreeHash)]
#[serde(deny_unknown_fields)]
pub struct BuilderDepositRequest {
    #[serde(with = "hex_bytes")]
    pub pubkey: [u8; 48],
    #[serde(with = "hex_bytes")]
    pub withdrawal_credentials: Root,
    #[serde(with = "serde_utils::quoted_u64")]
    pub amount: u64,
    #[serde(with = "hex_bytes")]
    pub signature: Signature,
}

/// `BuilderExitRequest` (Gloas, EIP-8282).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TreeHash)]
#[serde(deny_unknown_fields)]
pub struct BuilderExitRequest {
    #[serde(with = "hex_bytes")]
    pub source_address: Address,
    #[serde(with = "hex_bytes")]
    pub pubkey: [u8; 48],
}

fn roots<T: tree_hash::TreeHash>(items: &[T]) -> Vec<Root> {
    items.iter().map(|item| item.tree_hash_root().0).collect()
}

/// `ExecutionRequests` (Gloas: a progressive container of progressive lists).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionRequests {
    pub deposits: Vec<DepositRequest>,
    pub withdrawals: Vec<WithdrawalRequest>,
    pub consolidations: Vec<ConsolidationRequest>,
    pub builder_deposits: Vec<BuilderDepositRequest>,
    pub builder_exits: Vec<BuilderExitRequest>,
}

impl ExecutionRequests {
    pub fn root(&self) -> Root {
        progressive::container_root(&[
            progressive::list_root(&roots(&self.deposits)),
            progressive::list_root(&roots(&self.withdrawals)),
            progressive::list_root(&roots(&self.consolidations)),
            progressive::list_root(&roots(&self.builder_deposits)),
            progressive::list_root(&roots(&self.builder_exits)),
        ])
    }
}

/// `ExecutionPayload` (Gloas: a progressive container of 19 fields).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionPayload {
    #[serde(with = "hex_bytes")]
    pub parent_hash: Root,
    #[serde(with = "hex_bytes")]
    pub fee_recipient: Address,
    #[serde(with = "hex_bytes")]
    pub state_root: Root,
    #[serde(with = "hex_bytes")]
    pub receipts_root: Root,
    #[serde(with = "hex_bytes")]
    pub logs_bloom: [u8; 256],
    #[serde(with = "hex_bytes")]
    pub prev_randao: Root,
    #[serde(with = "serde_utils::quoted_u64")]
    pub block_number: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub gas_limit: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub gas_used: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub timestamp: u64,
    #[serde(with = "hex_vec")]
    pub extra_data: Vec<u8>,
    #[serde(with = "decimal_u256")]
    pub base_fee_per_gas: [u8; 32],
    #[serde(with = "hex_bytes")]
    pub block_hash: Root,
    #[serde(with = "hex_vec_list")]
    pub transactions: Vec<Vec<u8>>,
    pub withdrawals: Vec<Withdrawal>,
    #[serde(with = "serde_utils::quoted_u64")]
    pub blob_gas_used: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub excess_blob_gas: u64,
    #[serde(with = "hex_vec")]
    pub block_access_list: Vec<u8>,
    #[serde(with = "serde_utils::quoted_u64")]
    pub slot_number: u64,
}

/// `ExecutionPayloadEnvelope` (Gloas: a progressive container of 5 fields).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionPayloadEnvelope {
    pub payload: ExecutionPayload,
    pub execution_requests: ExecutionRequests,
    #[serde(with = "serde_utils::quoted_u64")]
    pub builder_index: u64,
    #[serde(with = "hex_bytes")]
    pub beacon_block_root: Root,
    #[serde(with = "hex_bytes")]
    pub parent_beacon_block_root: Root,
}

/// Why a payload cannot be hashed as the specification types it.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("extra_data has {0} bytes, more than {MAX_EXTRA_DATA_BYTES}")]
pub struct ExtraDataTooLong(pub usize);

impl ExecutionPayloadEnvelope {
    /// The envelope's summary: what consensus carries and every node signs.
    pub fn summary(&self) -> Result<EnvelopeSummary, ExtraDataTooLong> {
        let payload = &self.payload;
        if payload.extra_data.len() > MAX_EXTRA_DATA_BYTES {
            return Err(ExtraDataTooLong(payload.extra_data.len()));
        }
        let transactions: Vec<Root> = payload
            .transactions
            .iter()
            .map(|transaction| progressive::bytes_root(transaction))
            .collect();
        Ok(EnvelopeSummary {
            parent_hash: payload.parent_hash,
            fee_recipient: payload.fee_recipient,
            state_root: payload.state_root,
            receipts_root: payload.receipts_root,
            logs_bloom_root: progressive::byte_vector_root(&payload.logs_bloom),
            prev_randao: payload.prev_randao,
            block_number: payload.block_number,
            gas_limit: payload.gas_limit,
            gas_used: payload.gas_used,
            timestamp: payload.timestamp,
            extra_data_root: progressive::byte_list_root(&payload.extra_data, MAX_EXTRA_DATA_BYTES),
            base_fee_per_gas: payload.base_fee_per_gas,
            block_hash: payload.block_hash,
            transactions_root: progressive::list_root(&transactions),
            withdrawals_root: progressive::list_root(&roots(&payload.withdrawals)),
            blob_gas_used: payload.blob_gas_used,
            excess_blob_gas: payload.excess_blob_gas,
            block_access_list_root: progressive::bytes_root(&payload.block_access_list),
            slot_number: payload.slot_number,
            execution_requests_root: self.execution_requests.root(),
            builder_index: self.builder_index,
            beacon_block_root: self.beacon_block_root,
            parent_beacon_block_root: self.parent_beacon_block_root,
        })
    }
}

/// An `ExecutionPayloadEnvelope` as consensus carries it: the payload's fixed fields and the
/// roots of its variable ones (and of `logs_bloom`), then the envelope's own fields with the
/// root of its execution requests. [`Self::root`] is the envelope's `hash_tree_root`.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct EnvelopeSummary {
    pub parent_hash: Root,
    pub fee_recipient: Address,
    pub state_root: Root,
    pub receipts_root: Root,
    pub logs_bloom_root: Root,
    pub prev_randao: Root,
    pub block_number: u64,
    pub gas_limit: u64,
    pub gas_used: u64,
    pub timestamp: u64,
    pub extra_data_root: Root,
    /// `uint256`, little-endian.
    pub base_fee_per_gas: [u8; 32],
    pub block_hash: Root,
    pub transactions_root: Root,
    pub withdrawals_root: Root,
    pub blob_gas_used: u64,
    pub excess_blob_gas: u64,
    pub block_access_list_root: Root,
    pub slot_number: u64,
    pub execution_requests_root: Root,
    pub builder_index: u64,
    pub beacon_block_root: Root,
    pub parent_beacon_block_root: Root,
}

impl EnvelopeSummary {
    /// The payload's `hash_tree_root`.
    pub fn payload_root(&self) -> Root {
        progressive::container_root(&[
            self.parent_hash,
            progressive::short_bytes_root(&self.fee_recipient),
            self.state_root,
            self.receipts_root,
            self.logs_bloom_root,
            self.prev_randao,
            progressive::u64_root(self.block_number),
            progressive::u64_root(self.gas_limit),
            progressive::u64_root(self.gas_used),
            progressive::u64_root(self.timestamp),
            self.extra_data_root,
            self.base_fee_per_gas,
            self.block_hash,
            self.transactions_root,
            self.withdrawals_root,
            progressive::u64_root(self.blob_gas_used),
            progressive::u64_root(self.excess_blob_gas),
            self.block_access_list_root,
            progressive::u64_root(self.slot_number),
        ])
    }

    /// The envelope's `hash_tree_root`.
    pub fn root(&self) -> Root {
        progressive::container_root(&[
            self.payload_root(),
            self.execution_requests_root,
            progressive::u64_root(self.builder_index),
            self.beacon_block_root,
            self.parent_beacon_block_root,
        ])
    }

    /// Whether the proposer built the payload itself (the only envelope a validator signs).
    pub const fn self_built(&self) -> bool {
        self.builder_index == BUILDER_INDEX_SELF_BUILD
    }
}

#[cfg(test)]
#[path = "../../tests/unit/eth/gloas.rs"]
mod tests;
