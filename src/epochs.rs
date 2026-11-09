//! Consensus epochs (R3): which committee votes, and on which heights.
//!
//! Epoch 0's committee is the one given on the command line (`--participants`). A later epoch
//! replaces exactly one member: the current committee finalizes a block T carrying a
//! `Reconfigure` command, no honest node votes for or builds a child of such a block
//! (`application`), and every node commits the next epoch's record together with T, exits, and
//! restarts in the new epoch, derived from its own state. The new epoch's consensus starts from T
//! (its genesis), on channels of its own (`engine::consensus_channels`), with its own journal.
//!
//! A process runs one epoch for its whole life: a block is applied only by a process running
//! that block's epoch (a node exits right after the last block of its epoch). So the committee
//! every component checks against (ceremonies, partial-signature requests, the coordinator's
//! role) is a constant of the process, the current epoch's.
//!
//! Marshal verifies every height's finalization with the committee of that height's epoch:
//! [Schemes] (the [Provider]) and [Heights] (the [Epocher]) cover every epoch up to the current
//! one. This node signs only in the current epoch, and only as a member.

use crate::{
    application::Scheme,
    types::{Block, Command},
};
use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error as CodecError, Read, ReadExt as _, Write};
use commonware_consensus::types::{Epoch, EpochInfo, Epocher, Height};
use commonware_cryptography::{
    Digest as _, Digestible as _, Signer as _,
    certificate::{Provider, Scoped},
    ed25519::{PrivateKey, PublicKey},
    sha256::Digest,
};
use commonware_utils::{TryCollect as _, ordered::Set};
use std::sync::Arc;

/// The reconfiguration a block carries with its approvals (`admin`), if any:
/// `(epoch, removed, added)`. A bare one, without approvals, is no reconfiguration: honest voters
/// refuse a block carrying one, and it ends no epoch.
pub fn reconfiguration(block: &Block) -> Option<(u64, &PublicKey, &PublicKey)> {
    block
        .transactions
        .iter()
        .find_map(|transaction| match &transaction.command {
            Command::Admin(authorized) => match &authorized.command {
                Command::Reconfigure(change) => Some((change.epoch, &change.remove, &change.add)),
                _ => None,
            },
            _ => None,
        })
}

/// Whether `block` is the last of its epoch: it carries an approved reconfiguration, so no block
/// may follow it in the epoch. Decided by the block's content alone, so every honest node refuses
/// its children, whatever it has applied. Only a block honest voters notarized can be a parent,
/// and they notarize one only if its reconfiguration's approvals and nonce check (`admin`).
pub fn is_terminal(block: &Block) -> bool {
    reconfiguration(block).is_some()
}

/// One consensus epoch: its committee and where it starts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpochRecord {
    pub epoch: u64,
    /// The voters.
    pub committee: Set<PublicKey>,
    /// The member this epoch removed and the one it added (none for epoch 0).
    pub change: Option<(PublicKey, PublicKey)>,
    /// Height of the previous epoch's last block (the one carrying the `Reconfigure`): this
    /// epoch's consensus genesis. 0, the genesis block, for epoch 0.
    pub boundary: u64,
    /// Digest of that block.
    pub boundary_digest: Digest,
}

impl EpochRecord {
    /// Epoch 0: `committee`, from the genesis block.
    pub fn genesis(committee: Set<PublicKey>) -> Self {
        Self {
            epoch: 0,
            committee,
            change: None,
            boundary: 0,
            boundary_digest: Block::genesis().digest(),
        }
    }
}

// Only later epochs are stored (epoch 0 is the command line's committee): `change` is always set.
impl Write for EpochRecord {
    fn write(&self, buf: &mut impl BufMut) {
        let (removed, added) = self.change.as_ref().expect("only later epochs are stored");
        self.epoch.write(buf);
        removed.write(buf);
        added.write(buf);
        self.committee.write(buf);
        self.boundary.write(buf);
        self.boundary_digest.write(buf);
    }
}

impl Read for EpochRecord {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let range = (1..=crate::dkg::MAX_PARTICIPANTS.get() as usize).into();
        let epoch = u64::read(buf)?;
        let removed = PublicKey::read(buf)?;
        let added = PublicKey::read(buf)?;
        Ok(Self {
            epoch,
            change: Some((removed, added)),
            committee: Set::read_cfg(buf, &(range, ()))?,
            boundary: u64::read(buf)?,
            boundary_digest: Digest::read(buf)?,
        })
    }
}

impl EncodeSize for EpochRecord {
    fn encode_size(&self) -> usize {
        let (removed, added) = self.change.as_ref().expect("only later epochs are stored");
        self.epoch.encode_size()
            + removed.encode_size()
            + added.encode_size()
            + self.committee.encode_size()
            + self.boundary.encode_size()
            + self.boundary_digest.encode_size()
    }
}

/// Why a reconfiguration is refused.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Refusal {
    #[error("names epoch {named}, but the next epoch is {next}")]
    Epoch { named: u64, next: u64 },
    #[error("the key to remove is not a member of the committee")]
    NotMember,
    #[error("the key to add is already a member of the committee")]
    AlreadyMember,
    #[error("the key to add is not a configured follower")]
    NotCandidate,
    #[error("a block carrying a reconfiguration must carry nothing else")]
    NotAlone,
}

/// Every epoch up to the current one, in order.
#[derive(Clone, Debug)]
pub struct Epochs(Vec<EpochRecord>);

impl Epochs {
    /// Epoch 0 only, with `committee`.
    pub fn new(committee: Set<PublicKey>) -> Self {
        Self(vec![EpochRecord::genesis(committee)])
    }

    /// Epoch 0 with `genesis` (the command line's committee) and the stored later epochs, which
    /// must follow from it one by one.
    pub fn restore(genesis: Set<PublicKey>, mut stored: Vec<EpochRecord>) -> Result<Self, String> {
        stored.sort_by_key(|record| record.epoch);
        let mut epochs = Self::new(genesis);
        for record in stored {
            let previous = epochs.current();
            let (removed, added) = record
                .change
                .clone()
                .ok_or(format!("epoch {} names no change", record.epoch))?;
            let follows = record.boundary > previous.boundary
                && epochs
                    .next(
                        record.epoch,
                        &removed,
                        &added,
                        record.boundary,
                        record.boundary_digest,
                    )
                    .is_ok_and(|expected| expected == record);
            if !follows {
                return Err(format!(
                    "epoch {} does not follow from epoch {} (is --participants this node's \
                     original committee?)",
                    record.epoch, previous.epoch
                ));
            }
            epochs.0.push(record);
        }
        Ok(epochs)
    }

    /// The epoch this process runs.
    pub fn current(&self) -> &EpochRecord {
        self.0.last().expect("epoch 0 always exists")
    }

    pub fn get(&self, epoch: u64) -> Option<&EpochRecord> {
        self.0.get(usize::try_from(epoch).ok()?)
    }

    pub fn iter(&self) -> impl Iterator<Item = &EpochRecord> {
        self.0.iter()
    }

    /// The epoch that follows the current one if `removed` is replaced by `added` in the block
    /// `boundary` (`digest`), or why it cannot. `epoch` is the epoch the command names.
    pub fn next(
        &self,
        epoch: u64,
        removed: &PublicKey,
        added: &PublicKey,
        boundary: u64,
        digest: Digest,
    ) -> Result<EpochRecord, Refusal> {
        let current = self.current();
        let next = current.epoch + 1;
        if epoch != next {
            return Err(Refusal::Epoch { named: epoch, next });
        }
        if current.committee.position(removed).is_none() {
            return Err(Refusal::NotMember);
        }
        if current.committee.position(added).is_some() {
            return Err(Refusal::AlreadyMember);
        }
        let committee = current
            .committee
            .iter()
            .filter(|member| *member != removed)
            .chain(std::iter::once(added))
            .cloned()
            .try_collect()
            .expect("one member replaced by a new key");
        Ok(EpochRecord {
            epoch,
            committee,
            change: Some((removed.clone(), added.clone())),
            boundary,
            boundary_digest: digest,
        })
    }

    /// Check a reconfiguration against the current epoch, and with `candidates`, that it adds one
    /// of them (a configured follower).
    pub fn check(
        &self,
        epoch: u64,
        removed: &PublicKey,
        added: &PublicKey,
        candidates: Option<&Set<PublicKey>>,
    ) -> Result<(), Refusal> {
        // The boundary is not checked: any block may carry it.
        self.next(epoch, removed, added, 0, Digest::EMPTY)?;
        match candidates {
            Some(candidates) if candidates.position(added).is_none() => Err(Refusal::NotCandidate),
            _ => Ok(()),
        }
    }

    /// Check a block's reconfiguration, if it carries one (see [Epochs::check]): alone in its
    /// block.
    pub fn check_block(
        &self,
        block: &Block,
        candidates: Option<&Set<PublicKey>>,
    ) -> Result<(), Refusal> {
        let Some((epoch, removed, added)) = reconfiguration(block) else {
            return Ok(());
        };
        if block.transactions.len() != 1 {
            return Err(Refusal::NotAlone);
        }
        self.check(epoch, removed, added, candidates)
    }

    /// Whether `parent` is the current epoch's last block: a block of this epoch carrying a
    /// reconfiguration, which no block may follow. The block that ended the previous epoch is this
    /// epoch's genesis, which blocks do follow.
    pub fn ends_current(&self, parent: &Block) -> bool {
        parent.height.get() > self.current().boundary && is_terminal(parent)
    }

    /// Append the epoch that follows the current one.
    pub fn push(&mut self, record: EpochRecord) {
        assert_eq!(
            record.epoch,
            self.current().epoch + 1,
            "epochs are consecutive"
        );
        self.0.push(record);
    }
}

/// The consensus scheme of every epoch up to the current one, for marshal: this node can sign
/// only in the current epoch, and only as one of its members.
#[derive(Clone)]
pub struct Schemes(Arc<Vec<Arc<Scheme>>>);

impl Schemes {
    pub fn new(namespace: &[u8], epochs: &Epochs, signer: &PrivateKey) -> Self {
        let current = epochs.current().epoch;
        let me = signer.public_key();
        let schemes = epochs
            .iter()
            .map(|record| {
                let committee = record.committee.clone();
                Arc::new(
                    if record.epoch == current && committee.position(&me).is_some() {
                        Scheme::signer(namespace, committee, signer.clone())
                            .expect("signer is a member")
                    } else {
                        Scheme::verifier(namespace, committee)
                    },
                )
            })
            .collect();
        Self(Arc::new(schemes))
    }

    /// The current epoch's scheme (for simplex).
    pub fn current(&self) -> Scheme {
        self.0
            .last()
            .expect("epoch 0 always exists")
            .as_ref()
            .clone()
    }
}

impl Provider for Schemes {
    type Scope = Epoch;
    type Scheme = Scheme;

    // Every known epoch has a full scheme (the current one can sign only if this node is a
    // member): marshal needs an epoch's participants to check its notarizations too.
    fn scoped(&self, epoch: Epoch) -> Option<Scoped<Scheme>> {
        let index = usize::try_from(epoch.get()).ok()?;
        self.0.get(index).cloned().map(Scoped::scheme)
    }
}

/// The heights of every epoch up to the current one. The current epoch has no end (the next
/// epoch's start is only known once its `Reconfigure` is finalized), unless `close` ends it
/// (`--close-epoch-at`).
#[derive(Clone, Debug)]
pub struct Heights(Arc<Vec<(u64, u64)>>);

impl Heights {
    pub fn new(epochs: &Epochs, close: Option<u64>) -> Self {
        let records: Vec<&EpochRecord> = epochs.iter().collect();
        let bounds = records
            .iter()
            .enumerate()
            .map(|(index, record)| {
                // Epoch 0 also holds the genesis block (height 0), as `FixedEpocher` does.
                let first = if index == 0 { 0 } else { record.boundary + 1 };
                let last = match records.get(index + 1) {
                    Some(next) => next.boundary,
                    None => close.unwrap_or(u64::MAX - 1),
                };
                (first, last)
            })
            .collect();
        Self(Arc::new(bounds))
    }

    fn bounds(&self, epoch: Epoch) -> Option<(u64, u64)> {
        self.0.get(usize::try_from(epoch.get()).ok()?).copied()
    }
}

impl Epocher for Heights {
    fn containing(&self, height: Height) -> Option<EpochInfo> {
        let (epoch, (first, last)) = self
            .0
            .iter()
            .enumerate()
            .find(|(_, (first, last))| (*first..=*last).contains(&height.get()))?;
        Some(EpochInfo::new(
            Epoch::new(epoch as u64),
            height,
            Height::new(*first),
            Height::new(*last),
        ))
    }

    fn first(&self, epoch: Epoch) -> Option<Height> {
        self.bounds(epoch).map(|(first, _)| Height::new(first))
    }

    fn last(&self, epoch: Epoch) -> Option<Height> {
        self.bounds(epoch).map(|(_, last)| Height::new(last))
    }
}

#[cfg(test)]
#[path = "../tests/unit/epochs.rs"]
mod tests;
