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
pub(crate) mod tests {
    use super::*;
    use crate::dkg::{
        secrets::KeyShare,
        signing::{self, Message},
    };
    use commonware_codec::DecodeExt as _;
    use commonware_cryptography::{
        Signer as _,
        bls12381::dkg::feldman_desmedt::{Dealer, Player},
    };
    use commonware_runtime::{Runner as _, deterministic};
    use commonware_utils::TryCollect as _;

    pub(crate) fn signers() -> Vec<PrivateKey> {
        (0..4).map(PrivateKey::from_seed).collect()
    }

    pub(crate) fn committee(signers: &[PrivateKey]) -> Set<PublicKey> {
        signers
            .iter()
            .map(|signer| signer.public_key())
            .try_collect()
            .unwrap()
    }

    fn config(id: &str, signers: &[PrivateKey]) -> CeremonyConfig {
        CeremonyConfig::new(CeremonyId::new(id).unwrap(), committee(signers))
    }

    /// Run every dealer of `ceremony` in memory. `skip_ack` players do not acknowledge `dealer`.
    pub(crate) fn deal(
        rng: &mut impl CryptoRng,
        ceremony: &Ceremony,
        signers: &[PrivateKey],
        skip_ack: &[(usize, usize)],
    ) -> (Vec<Player<Variant, PrivateKey>>, Vec<SignedLog>) {
        let info = ceremony.info();
        let mut players: Vec<_> = signers
            .iter()
            .map(|signer| Player::new(info.clone(), signer.clone()).unwrap())
            .collect();
        let mut logs = Vec::new();
        for (d, signer) in signers.iter().enumerate() {
            let (mut dealer, commitment, dealings) =
                Dealer::start::<Faults>(&mut *rng, info.clone(), signer.clone(), None).unwrap();
            for (player_key, dealing) in dealings {
                let p = signers
                    .iter()
                    .position(|signer| signer.public_key() == player_key)
                    .unwrap();
                let ack = players[p]
                    .dealer_message::<Faults>(signer.public_key(), commitment.clone(), dealing)
                    .unwrap()
                    .unwrap();
                if !skip_ack.contains(&(d, p)) {
                    dealer.receive_player_ack(player_key, ack).unwrap();
                }
            }
            logs.push(dealer.finalize::<Faults>());
        }
        (players, logs)
    }

    #[test]
    fn start_is_idempotent_and_rejects_conflicts() {
        let signers = signers();
        let mut ceremonies = Ceremonies::new(committee(&signers));
        let block = Sha256::hash(&[b"block"]);
        let first = config("validator-001", &signers);

        assert_eq!(
            ceremonies.start(first.clone(), 1, &block),
            StartOutcome::Started(0)
        );
        assert_eq!(
            ceremonies.start(first.clone(), 2, &block),
            StartOutcome::Exists(0)
        );

        let mut conflicting = first.clone();
        conflicting.threshold = 2;
        assert_eq!(
            ceremonies.start(conflicting.clone(), 3, &block),
            StartOutcome::Conflict(0)
        );

        // The same unsupported configuration under a fresh id is rejected, not started.
        conflicting.id = CeremonyId::new("validator-002").unwrap();
        assert!(matches!(
            ceremonies.start(conflicting, 3, &block),
            StartOutcome::Unsupported(Unsupported::Threshold { .. })
        ));
        assert_eq!(
            ceremonies.start(config("validator-002", &signers), 4, &block),
            StartOutcome::Started(1)
        );
        assert_eq!(ceremonies.iter().count(), 2);

        // Bounded number of concurrent ceremonies.
        for i in 3..=MAX_ACTIVE {
            ceremonies.start(config(&format!("v-{i}"), &signers), 5, &block);
        }
        assert_eq!(
            ceremonies.start(config("one-too-many", &signers), 5, &block),
            StartOutcome::Unsupported(Unsupported::TooManyActive)
        );
    }

    #[test]
    fn completes_and_players_agree() {
        deterministic::Runner::default().start(|mut context| async move {
            let signers = signers();
            let mut ceremonies = Ceremonies::new(committee(&signers));
            ceremonies.start(
                config("validator-001", &signers),
                1,
                &Sha256::hash(&[b"b1"]),
            );
            let ceremony = ceremonies
                .get(&CeremonyId::new("validator-001").unwrap())
                .unwrap()
                .clone();
            let (players, logs) = deal(&mut context, &ceremony, &signers, &[]);

            // Two logs are not enough.
            for log in logs.iter().take(2) {
                ceremonies.record(0, log.clone()).unwrap();
            }
            ceremonies.advance(2, &mut context);
            assert_eq!(
                ceremonies.iter().next().unwrap().status,
                DkgStatus::InProgress
            );

            for log in logs.into_iter().skip(2) {
                ceremonies.record(0, log).unwrap();
            }
            ceremonies.advance(3, &mut context);
            let ceremony = ceremonies.iter().next().unwrap().clone();
            assert_eq!(ceremony.status, DkgStatus::Completed);
            assert_eq!(ceremony.logs.len(), 3, "exactly the selected logs are kept");
            let output = ceremony.output.clone().unwrap();

            // Every player derives a different share of the same key.
            let mut partials = Vec::new();
            for (player, signer) in players.into_iter().zip(&signers) {
                let (local, share) = player
                    .finalize::<Faults, ed25519::Batch>(&mut context, ceremony.logs(), &Sequential)
                    .unwrap();
                assert_eq!(local, output);
                let key_share = KeyShare::new(&ceremony, share);
                key_share.verify(&signer.public_key(), &ceremony).unwrap();
                partials.push(Message::Ethereum([7; 32]).partial_sign(&key_share.share));
            }
            let signature = signing::recover(output.public(), &partials[1..]).unwrap();
            Message::Ethereum([7; 32])
                .verify(output.public().public(), &signature)
                .unwrap();

            // The record survives a codec round trip (it is persisted by every node).
            assert_eq!(Ceremony::decode(ceremony.encode()).unwrap(), ceremony);
        });
    }

    #[test]
    fn late_log_changes_nothing() {
        deterministic::Runner::default().start(|mut context| async move {
            let signers = signers();
            let mut ceremonies = Ceremonies::new(committee(&signers));
            ceremonies.start(config("late", &signers), 1, &Sha256::hash(&[b"b"]));
            let ceremony = ceremonies.iter().next().unwrap().clone();
            let (players, logs) = deal(&mut context, &ceremony, &signers, &[]);

            for log in &logs[..3] {
                ceremonies.record(0, log.clone()).unwrap();
            }
            ceremonies.advance(2, &mut context);
            ceremonies.take_changed();
            let completed = ceremonies.iter().next().unwrap().clone();
            assert_eq!(completed.status, DkgStatus::Completed);
            let late_dealer = signers[3].public_key();
            assert!(!completed.logs.contains_key(&late_dealer));

            // The fourth log is perfectly valid, but arrives after finalization.
            assert_eq!(ceremonies.record(0, logs[3].clone()), Err(Ignored::Closed));
            ceremonies.advance(3, &mut context);
            assert!(ceremonies.take_changed().is_empty(), "nothing to persist");
            let after = ceremonies.iter().next().unwrap();
            assert_eq!(after, &completed);
            let output = after.output.as_ref().unwrap();
            assert_eq!(output.dealers().len(), 3);
            assert!(output.dealers().position(&late_dealer).is_none());

            // The late dealer, as a player, still derives a share of the same key.
            for player in players {
                let (local, _) = player
                    .finalize::<Faults, ed25519::Batch>(&mut context, after.logs(), &Sequential)
                    .unwrap();
                assert_eq!(&local, output);
            }
        });
    }

    #[test]
    fn extra_log_in_the_completing_block_is_not_used() {
        deterministic::Runner::default().start(|mut context| async move {
            let signers = signers();
            let mut ceremonies = Ceremonies::new(committee(&signers));
            ceremonies.start(config("four", &signers), 1, &Sha256::hash(&[b"b"]));
            let ceremony = ceremonies.iter().next().unwrap().clone();
            let (_, logs) = deal(&mut context, &ceremony, &signers, &[]);

            // All four logs land in the same block.
            for log in &logs {
                ceremonies.record(0, log.clone()).unwrap();
            }
            ceremonies.advance(2, &mut context);
            let completed = ceremonies.iter().next().unwrap().clone();
            assert_eq!(completed.logs.len(), 3);

            // Exactly three commitments are used (the first three dealers in key order), and the
            // result is the one those three alone produce.
            let mut by_key: Vec<_> = ceremony.config.participants.iter().cloned().collect();
            by_key.truncate(3);
            assert_eq!(completed.logs.keys().cloned().collect::<Vec<_>>(), by_key);
            let mut alone = Ceremonies::new(committee(&signers));
            alone.start(config("four", &signers), 1, &Sha256::hash(&[b"b"]));
            for (log, signer) in logs.iter().zip(&signers) {
                if by_key.contains(&signer.public_key()) {
                    alone.record(0, log.clone()).unwrap();
                }
            }
            alone.advance(2, &mut context);
            assert_eq!(alone.iter().next().unwrap().output, completed.output);
        });
    }

    #[test]
    fn rejects_invalid_logs() {
        deterministic::Runner::default().start(|mut context| async move {
            let signers = signers();
            let mut ceremonies = Ceremonies::new(committee(&signers));
            ceremonies.start(config("a", &signers), 1, &Sha256::hash(&[b"b1"]));
            ceremonies.start(config("b", &signers), 1, &Sha256::hash(&[b"b1"]));
            let a = ceremonies
                .get(&CeremonyId::new("a").unwrap())
                .unwrap()
                .clone();
            let b = ceremonies
                .get(&CeremonyId::new("b").unwrap())
                .unwrap()
                .clone();

            // Player 3 never acknowledges dealer 0: dealer 0's log would reveal player 3's dealing.
            let (_, logs_a) = deal(&mut context, &a, &signers, &[(0, 3)]);
            let (_, logs_b) = deal(&mut context, &b, &signers, &[]);

            assert_eq!(
                ceremonies.record(9, logs_a[1].clone()),
                Err(Ignored::UnknownCeremony)
            );
            assert_eq!(
                ceremonies.record(0, logs_a[0].clone()),
                Err(Ignored::Reveals)
            );
            // A valid log of ceremony b does not verify for ceremony a.
            assert_eq!(
                ceremonies.record(0, logs_b[1].clone()),
                Err(Ignored::BadSignature)
            );
            ceremonies.record(0, logs_a[1].clone()).unwrap();
            // Same dealer again: the first log wins, even if the second differs.
            assert_eq!(
                ceremonies.record(0, logs_a[1].clone()),
                Err(Ignored::Duplicate)
            );
            let (_, other) = deal(&mut context, &a, &signers, &[]);
            assert_eq!(
                ceremonies.record(0, other[1].clone()),
                Err(Ignored::Duplicate)
            );
        });
    }

    #[test]
    fn fails_after_deadline() {
        deterministic::Runner::default().start(|mut context| async move {
            let signers = signers();
            let mut ceremonies = Ceremonies::new(committee(&signers));
            ceremonies.start(config("late", &signers), 10, &Sha256::hash(&[b"b"]));
            let ceremony = ceremonies.iter().next().unwrap().clone();
            let (_, logs) = deal(&mut context, &ceremony, &signers, &[]);

            ceremonies.advance(10 + DEADLINE_BLOCKS - 1, &mut context);
            assert_eq!(
                ceremonies.iter().next().unwrap().status,
                DkgStatus::InProgress
            );
            ceremonies.advance(10 + DEADLINE_BLOCKS, &mut context);
            assert_eq!(ceremonies.iter().next().unwrap().status, DkgStatus::Failed);

            // Late logs cannot revive it.
            assert_eq!(ceremonies.record(0, logs[0].clone()), Err(Ignored::Closed));
        });
    }
}
