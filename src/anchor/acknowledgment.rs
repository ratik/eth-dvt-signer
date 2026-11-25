//! The approvers' acknowledgment of a rollback (docs/anchor.md): when the newer state the anchor
//! shows is lost for good, the approvers sign, offline, that the cluster continues in a new anchor
//! generation from the state it has, keeping the anchored marks as floors (so nothing signed
//! before can be signed again differently).
//!
//! It is written to the anchor, create-only, as `<cluster>/acknowledgments/<generation>-<hash>`
//! (a faulty writer cannot take the place of a valid one), by every node started with it
//! (`--anchor-acknowledgment`). Nodes read the highest generation whose acknowledgment carries
//! enough valid approvals, and compare only the records of that generation.
//!
//! The document is exchanged like a protected command (`mpc-admin sign`, `show`): its fields, a
//! description and the exact message, both derived again before signing and before use.

use super::record::Marks;
use crate::admin::{ApprovalJson, Approvers, format_key};
use crate::import::unhex;
use commonware_codec::{DecodeExt as _, Encode as _, Write as _};
use commonware_cryptography::{
    Hasher as _, Sha256, Signer as _, Verifier as _,
    ed25519::{PrivateKey, PublicKey, Signature},
    sha256::Digest,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Domain separation of acknowledgments from every other Ed25519 signature (approvers' commands
/// included).
pub const NAMESPACE: &[u8] = b"_ETH_MPC_SIGNER_ANCHOR_ACKNOWLEDGMENT";

/// The document's `kind`, which tells it from a protected command's.
pub const KIND: &str = "anchor-acknowledgment";

const VERSION: &[u8] = b"eth-mpc-signer/anchor-acknowledgment/v1";

/// What the approvers acknowledge.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Acknowledgment {
    pub cluster: Digest,
    /// The generation the cluster continues in: the previous one plus one.
    pub generation: u64,
    /// The previous generation's gate height and the block the records named there: the state
    /// given up (informational).
    pub height: u64,
    pub digest: Digest,
    /// The previous generation's anchored marks: floors in the new one.
    pub marks: Marks,
}

impl Acknowledgment {
    /// The exact bytes each approver signs.
    pub fn message(&self) -> Vec<u8> {
        let mut message = VERSION.to_vec();
        message.extend_from_slice(self.cluster.as_ref());
        self.generation.write(&mut message);
        self.height.write(&mut message);
        message.extend_from_slice(self.digest.as_ref());
        self.marks.write(&mut message);
        message
    }

    /// What it does, for the approvers.
    pub fn describe(&self) -> String {
        let mark = |value: Option<u64>| value.map_or_else(|| "none".to_string(), |v| v.to_string());
        format!(
            "acknowledge a rollback: the cluster continues in anchor generation {}, giving up the \
             state at height {} (block 0x{}); no block at or below slot {}, no attestation with a \
             target at or below epoch {} or a source below epoch {}",
            self.generation,
            self.height,
            hex::encode(self.digest),
            mark(self.marks.block_slot),
            mark(self.marks.target),
            mark(self.marks.source),
        )
    }
}

/// The acknowledgment as approvers exchange and sign it.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AcknowledgmentDocument {
    /// [`KIND`].
    pub kind: String,
    /// The cluster (`GET /admin`), `0x`-hex.
    pub cluster_id: String,
    pub generation: u64,
    pub height: u64,
    /// `0x`-hex.
    pub digest: String,
    pub marks: Marks,
    pub description: String,
    /// The exact bytes each approver signs, `0x`-hex.
    pub message: String,
    pub approvals: Vec<ApprovalJson>,
}

fn digest(value: &str, what: &str) -> Result<Digest, String> {
    unhex(value)
        .and_then(|bytes| Digest::decode(commonware_codec::Copying(bytes.as_slice())).ok())
        .ok_or_else(|| format!("{what} {value} is not 32 bytes of 0x-hex"))
}

impl AcknowledgmentDocument {
    /// `acknowledgment`, unsigned.
    pub fn draft(acknowledgment: &Acknowledgment) -> Self {
        Self {
            kind: KIND.to_string(),
            cluster_id: format!("0x{}", hex::encode(acknowledgment.cluster)),
            generation: acknowledgment.generation,
            height: acknowledgment.height,
            digest: format!("0x{}", hex::encode(acknowledgment.digest)),
            marks: acknowledgment.marks,
            description: acknowledgment.describe(),
            message: format!("0x{}", hex::encode(acknowledgment.message())),
            approvals: Vec::new(),
        }
    }

    pub fn from_json(text: &str) -> Result<Self, String> {
        serde_json::from_str(text).map_err(|err| format!("acknowledgment: {err}"))
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("serializable")
    }

    /// The acknowledgment, rebuilt from the fields, after checking that the description and the
    /// message are the ones they derive (a document edited after drafting is refused).
    pub fn acknowledgment(&self) -> Result<Acknowledgment, String> {
        if self.kind != KIND {
            return Err(format!("kind {} is not {KIND}", self.kind));
        }
        if self.generation == 0 {
            return Err("generation 0 is the anchor's first: nothing to acknowledge".into());
        }
        let acknowledgment = Acknowledgment {
            cluster: digest(&self.cluster_id, "cluster_id")?,
            generation: self.generation,
            height: self.height,
            digest: digest(&self.digest, "digest")?,
            marks: self.marks,
        };
        if self.description != acknowledgment.describe() {
            return Err(
                "the description is not the acknowledgment's: the document was edited".into(),
            );
        }
        if self.message != format!("0x{}", hex::encode(acknowledgment.message())) {
            return Err("the message is not the acknowledgment's: the document was edited".into());
        }
        Ok(acknowledgment)
    }

    /// Add `key`'s approval (replacing an earlier one by the same key).
    pub fn sign(&mut self, key: &PrivateKey) -> Result<(), String> {
        let message = self.acknowledgment()?.message();
        let approver = format_key(&key.public_key());
        self.approvals
            .retain(|approval| approval.approver != approver);
        self.approvals.push(ApprovalJson {
            approver,
            signature: format!("0x{}", hex::encode(key.sign(NAMESPACE, &message).encode())),
        });
        self.approvals.sort_by(|a, b| a.approver.cmp(&b.approver));
        Ok(())
    }

    /// Add `other`'s approvals: the same acknowledgment, signed separately.
    pub fn merge(&mut self, other: &Self) -> Result<(), String> {
        let unsigned = |document: &Self| Self {
            approvals: Vec::new(),
            ..document.clone()
        };
        if unsigned(self) != unsigned(other) {
            return Err("the documents are not the same acknowledgment".into());
        }
        for approval in &other.approvals {
            match self
                .approvals
                .iter()
                .find(|known| known.approver == approval.approver)
            {
                Some(known) if known.signature != approval.signature => {
                    return Err(format!("{} signed twice, differently", approval.approver));
                }
                Some(_) => {}
                None => self.approvals.push(approval.clone()),
            }
        }
        self.approvals.sort_by(|a, b| a.approver.cmp(&b.approver));
        Ok(())
    }

    /// Each approval checked against `approvers`: `Ok` for a valid one.
    pub fn check(&self, approvers: &Approvers) -> Result<Vec<Result<(), String>>, String> {
        let message = self.acknowledgment()?.message();
        Ok(self
            .approvals
            .iter()
            .map(|approval| {
                let key = unhex(&approval.approver)
                    .and_then(|bytes| {
                        PublicKey::decode(commonware_codec::Copying(bytes.as_slice())).ok()
                    })
                    .ok_or("not an Ed25519 public key")?;
                if approvers.index(&key).is_none() {
                    return Err("not in the approver set".to_string());
                }
                let signature = unhex(&approval.signature)
                    .and_then(|bytes| {
                        Signature::decode(commonware_codec::Copying(bytes.as_slice())).ok()
                    })
                    .ok_or("not an Ed25519 signature")?;
                if key.verify(NAMESPACE, &message, &signature) {
                    Ok(())
                } else {
                    Err("the signature does not verify".into())
                }
            })
            .collect())
    }

    /// The acknowledgment, if it is of `cluster` and at least the threshold of distinct
    /// approvers of `approvers` signed it.
    pub fn verify(
        &self,
        approvers: &Approvers,
        cluster: &Digest,
    ) -> Result<Acknowledgment, String> {
        let acknowledgment = self.acknowledgment()?;
        if acknowledgment.cluster != *cluster {
            return Err("an acknowledgment of another cluster".into());
        }
        let valid: BTreeSet<&str> = self
            .approvals
            .iter()
            .zip(self.check(approvers)?)
            .filter(|(_, check)| check.is_ok())
            .map(|(approval, _)| approval.approver.as_str())
            .collect();
        if valid.len() < usize::from(approvers.threshold()) {
            return Err(format!(
                "{} valid approvals, {} required",
                valid.len(),
                approvers.threshold()
            ));
        }
        Ok(acknowledgment)
    }

    /// Its file name under `acknowledgments/`: the generation, then the SHA-256 of the
    /// acknowledged message (another document of the same generation cannot take its place).
    pub fn name(&self) -> Result<String, String> {
        let acknowledgment = self.acknowledgment()?;
        Ok(format!(
            "{:020}-{}",
            acknowledgment.generation,
            hex::encode(Sha256::hash(&[acknowledgment.message().as_slice()]))
        ))
    }
}
