//! Replicated ceremony state, changed only by finalized blocks.
//!
//! Only public data lives here: configurations, dealer logs (a dealer's commitment plus every
//! player's signed acknowledgement) and the resulting public polynomial. Feldman-Desmedt lets a
//! dealer publish ("reveal") the private dealing of a player that did not acknowledge it; such
//! logs are refused, so no share material ever enters a block. The price is liveness: every player
//! must acknowledge a dealer for its log to count (see [Ceremonies::record]).

use super::{
    CeremonyConfig, CeremonyId, DEADLINE_BLOCKS, DkgStatus, Faults, GroupKey, MAX_ACTIVE,
    MAX_PARTICIPANTS, NAMESPACE, Unsupported, Variant,
};
use bytes::{Buf, BufMut};
use commonware_codec::{
    Encode as _, EncodeSize, Error as CodecError, Read, ReadExt as _, Write, varint::UInt,
};
use commonware_cryptography::{
    Hasher as _, Sha256,
    bls12381::{
        dkg::feldman_desmedt::{
            DealerLog, DealerLogSummary, Failure, Info, Logs, Output, Reveal, SignedDealerLog,
            observe,
        },
        primitives::sharing::{Mode, ModeVersion},
    },
    ed25519::{self, PrivateKey, PublicKey},
    sha256::Digest,
};
use commonware_parallel::Sequential;
use commonware_utils::{
    ordered::{Quorum as _, Set},
    union,
};
use rand_core::CryptoRng;
use std::collections::{BTreeMap, BTreeSet};
use tracing::warn;

/// A dealer log as submitted to consensus: signed by its dealer for one ceremony.
pub type SignedLog = SignedDealerLog<Variant, PrivateKey>;

/// One ceremony as every node sees it.
#[derive(Clone, Debug, PartialEq)]
pub struct Ceremony {
    pub config: CeremonyConfig,
    /// DKG round: ceremonies are numbered sequentially, failed ones included.
    pub round: u64,
    /// Height of the block that started the ceremony.
    pub started: u64,
    /// Digest of the configuration, round and starting block. It is part of the DKG namespace, so
    /// every signature of the ceremony (acks, logs) is bound to it and to this chain.
    pub session: Digest,
    pub status: DkgStatus,
    /// Accepted dealer logs. Once completed: exactly the logs that produced the key.
    pub logs: BTreeMap<PublicKey, DealerLog<Variant, PublicKey>>,
    /// Public result (group key and public polynomial), once completed.
    pub output: Option<Output<Variant, PublicKey>>,
}

impl Ceremony {
    fn new(config: CeremonyConfig, round: u64, started: u64, block: &Digest) -> Self {
        let mut hasher = Sha256::default();
        hasher.update(NAMESPACE);
        hasher.update(&config.encode());
        hasher.update(&round.to_be_bytes());
        hasher.update(block.as_ref());
        Self {
            config,
            round,
            started,
            session: hasher.finalize().1,
            status: DkgStatus::InProgress,
            logs: BTreeMap::new(),
            output: None,
        }
    }

    /// Feldman-Desmedt round information shared by every dealer, player and observer.
    pub fn info(&self) -> Info<Variant, PublicKey> {
        Info::new::<Faults>(
            &union(NAMESPACE, self.session.as_ref()),
            self.round,
            None,
            Mode::NonZeroCounter,
            Reveal::V1,
            self.config.participants.clone(),
            self.config.participants.clone(),
        )
        .expect("a non-empty committee forms a valid round")
    }

    pub fn public_key(&self) -> Option<&GroupKey> {
        self.output.as_ref().map(|output| output.public().public())
    }

    /// Fresh [Logs] holding the accepted logs.
    pub fn logs(&self) -> Logs<Variant, PublicKey, Faults> {
        let mut logs = Logs::new(self.info());
        for (dealer, log) in &self.logs {
            logs.record(dealer.clone(), log.clone());
        }
        logs
    }
}

/// Result of a `StartCeremony` command.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StartOutcome {
    /// A new ceremony was created with this round.
    Started(u64),
    /// The same configuration was already started (idempotent).
    Exists(u64),
    /// The id is taken by a ceremony with a different configuration.
    Conflict(u64),
    /// The configuration cannot be run.
    Unsupported(Unsupported),
}

/// Why a dealer log was not recorded.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Ignored {
    #[error("unknown ceremony")]
    UnknownCeremony,
    #[error("ceremony is not in progress")]
    Closed,
    #[error("signature does not match this ceremony")]
    BadSignature,
    #[error("dealer is not a participant")]
    NotParticipant,
    #[error("dealer already has a log")]
    Duplicate,
    #[error("log reveals private dealings")]
    Reveals,
}

/// Every ceremony, by round. Deterministic: same blocks, same state on every node.
pub struct Ceremonies {
    committee: Set<PublicKey>,
    ceremonies: BTreeMap<u64, Ceremony>,
    ids: BTreeMap<CeremonyId, u64>,
    /// Rounds changed since the last [Ceremonies::take_changed].
    changed: BTreeSet<u64>,
}

impl Ceremonies {
    pub fn new(committee: Set<PublicKey>) -> Self {
        Self {
            committee,
            ceremonies: BTreeMap::new(),
            ids: BTreeMap::new(),
            changed: BTreeSet::new(),
        }
    }

    /// Re-insert a ceremony loaded from storage.
    pub fn restore(&mut self, ceremony: Ceremony) {
        self.ids.insert(ceremony.config.id.clone(), ceremony.round);
        self.ceremonies.insert(ceremony.round, ceremony);
    }

    pub fn get(&self, id: &CeremonyId) -> Option<&Ceremony> {
        self.ids.get(id).map(|round| &self.ceremonies[round])
    }

    pub fn iter(&self) -> impl Iterator<Item = &Ceremony> {
        self.ceremonies.values()
    }

    /// Ceremonies changed since the previous call.
    pub fn take_changed(&mut self) -> Vec<Ceremony> {
        std::mem::take(&mut self.changed)
            .into_iter()
            .map(|round| self.ceremonies[&round].clone())
            .collect()
    }

    /// Start `config` in the block at `height`. An id is never reused, whatever its outcome.
    pub fn start(&mut self, config: CeremonyConfig, height: u64, block: &Digest) -> StartOutcome {
        if let Some(&round) = self.ids.get(&config.id) {
            return if self.ceremonies[&round].config == config {
                StartOutcome::Exists(round)
            } else {
                StartOutcome::Conflict(round)
            };
        }
        if let Err(reason) = config.check(&self.committee) {
            return StartOutcome::Unsupported(reason);
        }
        let active = self
            .ceremonies
            .values()
            .filter(|ceremony| ceremony.status == DkgStatus::InProgress)
            .count();
        if active >= MAX_ACTIVE {
            return StartOutcome::Unsupported(Unsupported::TooManyActive);
        }

        let round = self.ceremonies.len() as u64;
        self.ids.insert(config.id.clone(), round);
        self.ceremonies
            .insert(round, Ceremony::new(config, round, height, block));
        self.changed.insert(round);
        StartOutcome::Started(round)
    }

    /// Record a dealer log for the ceremony `round`. The first valid log of each dealer wins.
    ///
    /// A log is only accepted if it is signed by a participant for this very ceremony and every
    /// player acknowledged the dealing (no reveals). The acknowledgement signatures and the
    /// commitment are verified later, by [observe], before any log is used.
    pub fn record(&mut self, round: u64, log: SignedLog) -> Result<PublicKey, Ignored> {
        let ceremony = self
            .ceremonies
            .get_mut(&round)
            .ok_or(Ignored::UnknownCeremony)?;
        if ceremony.status != DkgStatus::InProgress {
            return Err(Ignored::Closed);
        }
        let (dealer, log) = log.check(&ceremony.info()).ok_or(Ignored::BadSignature)?;
        if ceremony.config.participants.position(&dealer).is_none() {
            return Err(Ignored::NotParticipant);
        }
        if ceremony.logs.contains_key(&dealer) {
            return Err(Ignored::Duplicate);
        }
        match log.summary() {
            DealerLogSummary::Ok { reveals, .. } if reveals.is_empty() => {}
            _ => return Err(Ignored::Reveals),
        }
        ceremony.logs.insert(dealer.clone(), log);
        self.changed.insert(round);
        Ok(dealer)
    }

    /// End of the block at `height`: complete ceremonies that have enough valid logs and fail
    /// those past their deadline.
    pub fn advance(&mut self, height: u64, rng: &mut impl CryptoRng) {
        for (round, ceremony) in &mut self.ceremonies {
            if ceremony.status != DkgStatus::InProgress {
                continue;
            }
            let required = ceremony.config.participants.quorum::<Faults>() as usize;
            if ceremony.logs.len() >= required {
                match observe::<Variant, PublicKey, Faults, ed25519::Batch>(
                    rng,
                    ceremony.logs(),
                    &Sequential,
                ) {
                    Ok(output) => {
                        // Players must finalize with exactly the logs that produced the key.
                        ceremony
                            .logs
                            .retain(|dealer, _| output.dealers().position(dealer).is_some());
                        ceremony.output = Some(output);
                        ceremony.status = DkgStatus::Completed;
                        self.changed.insert(*round);
                        continue;
                    }
                    Err(Failure::InsufficientLogs { faults, .. }) => {
                        for (dealer, reason) in faults.iter_pairs() {
                            warn!(round, ?dealer, %reason, "dropping invalid dealer log");
                            ceremony.logs.remove(dealer);
                        }
                        self.changed.insert(*round);
                    }
                }
            }
            if height >= ceremony.started + DEADLINE_BLOCKS {
                ceremony.status = DkgStatus::Failed;
                self.changed.insert(*round);
            }
        }
    }
}

fn write_status(status: DkgStatus, buf: &mut impl BufMut) {
    (status as u8).write(buf);
}

fn read_status(buf: &mut impl Buf) -> Result<DkgStatus, CodecError> {
    match u8::read(buf)? {
        0 => Ok(DkgStatus::NotStarted),
        1 => Ok(DkgStatus::InProgress),
        2 => Ok(DkgStatus::Completed),
        3 => Ok(DkgStatus::Failed),
        tag => Err(CodecError::InvalidEnum(tag)),
    }
}

impl Write for Ceremony {
    fn write(&self, buf: &mut impl BufMut) {
        self.config.write(buf);
        UInt(self.round).write(buf);
        UInt(self.started).write(buf);
        self.session.write(buf);
        write_status(self.status, buf);
        UInt(self.logs.len() as u32).write(buf);
        for (dealer, log) in &self.logs {
            dealer.write(buf);
            log.write(buf);
        }
        self.output.is_some().write(buf);
        if let Some(output) = &self.output {
            output.write(buf);
        }
    }
}

impl Read for Ceremony {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let config = CeremonyConfig::read(buf)?;
        let round = UInt::read(buf)?.into();
        let started = UInt::read(buf)?.into();
        let session = Digest::read(buf)?;
        let status = read_status(buf)?;
        let count: u32 = UInt::read(buf)?.into();
        if count > MAX_PARTICIPANTS.get() {
            return Err(CodecError::Invalid("Ceremony", "too many logs"));
        }
        let mut logs = BTreeMap::new();
        for _ in 0..count {
            let dealer = PublicKey::read(buf)?;
            let log = DealerLog::read_cfg(buf, &MAX_PARTICIPANTS)?;
            logs.insert(dealer, log);
        }
        let output = if bool::read(buf)? {
            Some(Output::read_cfg(
                buf,
                &(MAX_PARTICIPANTS, ModeVersion::v0()),
            )?)
        } else {
            None
        };
        Ok(Self {
            config,
            round,
            started,
            session,
            status,
            logs,
            output,
        })
    }
}

impl EncodeSize for Ceremony {
    fn encode_size(&self) -> usize {
        self.config.encode_size()
            + UInt(self.round).encode_size()
            + UInt(self.started).encode_size()
            + self.session.encode_size()
            + 1
            + UInt(self.logs.len() as u32).encode_size()
            + self
                .logs
                .iter()
                .map(|(dealer, log)| dealer.encode_size() + log.encode_size())
                .sum::<usize>()
            + 1
            + self.output.as_ref().map_or(0, EncodeSize::encode_size)
    }
}

#[cfg(test)]
#[path = "../../tests/unit/dkg/ceremony.rs"]
pub(crate) mod tests;
