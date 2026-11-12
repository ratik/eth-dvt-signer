//! A keyholder's side of the anchor (docs/anchor.md): its own chain of records, what it must write
//! before giving a partial, the anchored marks and the confirmation gate it signs under, and the
//! replies it holds while a record is being written.
//!
//! The logic is synchronous; the keyholder actor runs [`write_noting`] in a task of its own and
//! posts the outcome back to its mailbox.
//!
//! **A write whose outcome was lost** (no answer within [WRITE_TIMEOUT], a lost reply) may still
//! have landed. The keeper keeps the record it sent ([Job::attempt]) and reads its head back before
//! the next write. If its next place holds that very record, the record is its own and counts as
//! written. Any other record there, or beyond it, is another process's: a clone, as before.

use super::{
    record::{Marks, Record, SignedRecord},
    rules::View,
    store::{AnchorError, AnchorStore},
};
use crate::eth::duty::DutyKind;
use commonware_cryptography::{
    Signer as _,
    ed25519::{PrivateKey, PublicKey},
    sha256::Digest,
};
use std::{
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

/// How long a keyholder waits for a record write before it gives the partials anyway, under the
/// restart floor alone (degraded).
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(2);

/// How often a degraded keyholder tries the anchor again.
pub const RETRY: Duration = Duration::from_secs(30);

/// What a duty needs its keyholder's record to cover before the keyholder gives a partial: a
/// block's slot; an attestation's source and target. Nothing for the other kinds (not slashable:
/// the restart floor bounds PTC votes and envelopes).
pub fn needed(kind: DutyKind, period: u64, source: Option<u64>) -> Option<Marks> {
    match kind {
        DutyKind::BlockProposal => Some(Marks {
            block_slot: Some(period),
            ..Marks::default()
        }),
        DutyKind::Attestation => Some(Marks {
            source,
            target: Some(period),
            ..Marks::default()
        }),
        _ => None,
    }
}

/// Why the anchored marks or the gate refuse a new duty.
pub fn anchored_refusal(
    anchored: &Marks,
    kind: DutyKind,
    period: u64,
    source: Option<u64>,
) -> Option<String> {
    match kind {
        DutyKind::BlockProposal => anchored
            .block_slot
            .filter(|mark| period <= *mark)
            .map(|mark| format!("block slot {period} at or below the anchored slot {mark}")),
        DutyKind::Attestation => {
            if let Some(mark) = anchored.target.filter(|mark| period <= *mark) {
                return Some(format!(
                    "attestation target {period} at or below the anchored target {mark}"
                ));
            }
            match (source, anchored.source) {
                (Some(source), Some(mark)) if source < mark => Some(format!(
                    "attestation source {source} below the anchored source {mark} (a surround \
                     vote of a signed attestation)"
                )),
                _ => None,
            }
        }
        _ => None,
    }
}

/// What the keyholder must do with a partial it computed.
#[derive(Debug, PartialEq, Eq)]
// Returned once per partial and consumed at once: its size does not matter.
#[allow(clippy::large_enum_variant)]
pub enum Step {
    /// Give it now.
    Give,
    /// Hold it until a record covering it is written; write `record` first if given (no write is
    /// in flight).
    Hold(Option<Job>),
}

/// A record to write: the marks it raises to, and where the keyholder's chain stands. When
/// `refresh` is set the keyholder does not know its latest record (the anchor was unreachable at
/// start): the task reads it first.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Job {
    pub marks: Marks,
    pub height: u64,
    pub digest: Digest,
    pub head: Option<SignedRecord>,
    pub refresh: bool,
    /// A record an earlier write sent without learning whether it landed: found at its place,
    /// it is this node's own, not a clone's.
    pub attempt: Option<SignedRecord>,
}

/// A keyholder's anchor state.
pub struct Keeper<R> {
    store: Arc<AnchorStore>,
    key: PrivateKey,
    cluster: Digest,
    generation: u64,
    /// Its latest record, if it knows it (`head_known`).
    head: Option<SignedRecord>,
    head_known: bool,
    /// The record of a write whose outcome was lost ([Job::attempt]).
    attempt: Option<SignedRecord>,
    /// The marks of the record being written, if one is.
    writing: Option<Marks>,
    /// Replies held for a record covering their marks.
    held: Vec<(Marks, R)>,
    /// The anchored marks read at start: no new duty at or below them.
    anchored: Marks,
    /// Whether this node's chain holds what the records name (the gate).
    confirmed: bool,
    /// The anchor could not be read or written: partials are given under the restart floor
    /// alone, and `unanchored` collects what was signed meanwhile.
    degraded: bool,
    unanchored: Marks,
    last_attempt: Option<SystemTime>,
    /// The latest block applied here.
    height: u64,
    digest: Digest,
}

impl<R> Keeper<R> {
    /// A keyholder's anchor after the reading at start: `view` and `head` (its own latest record)
    /// if the anchor answered, `None` if not (degraded: the restart floor alone, the gate open).
    pub fn new(
        store: Arc<AnchorStore>,
        key: PrivateKey,
        cluster: Digest,
        reading: Option<(View, Option<SignedRecord>, bool)>,
        height: u64,
        digest: Digest,
    ) -> Self {
        let (generation, anchored, confirmed, head, head_known, degraded) = match reading {
            Some((view, head, confirmed)) => (
                view.generation(),
                view.marks(),
                confirmed,
                head,
                true,
                false,
            ),
            None => (0, Marks::default(), true, None, false, true),
        };
        Self {
            store,
            key,
            cluster,
            generation,
            head,
            head_known,
            attempt: None,
            writing: None,
            held: Vec::new(),
            anchored,
            confirmed,
            degraded,
            unanchored: Marks::default(),
            last_attempt: None,
            height,
            digest,
        }
    }

    pub fn store(&self) -> Arc<AnchorStore> {
        self.store.clone()
    }

    pub fn key(&self) -> PrivateKey {
        self.key.clone()
    }

    pub const fn cluster(&self) -> Digest {
        self.cluster
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub const fn anchored(&self) -> Marks {
        self.anchored
    }

    pub const fn confirmed(&self) -> bool {
        self.confirmed
    }

    pub const fn degraded(&self) -> bool {
        self.degraded
    }

    pub fn head(&self) -> Option<&SignedRecord> {
        self.head.as_ref()
    }

    pub fn public_key(&self) -> PublicKey {
        self.key.public_key()
    }

    /// The executor confirmed this node's chain against the records.
    pub fn confirm(&mut self) {
        self.confirmed = true;
    }

    /// A block was applied here.
    pub fn applied(&mut self, height: u64, digest: Digest) {
        self.height = height;
        self.digest = digest;
    }

    /// Why the gate or the anchored marks refuse a new duty, if they do.
    pub fn refusal(&self, kind: DutyKind, period: u64, source: Option<u64>) -> Option<String> {
        if !self.confirmed {
            return Some(
                "this node's chain does not hold what the anchor's records name yet".to_string(),
            );
        }
        anchored_refusal(&self.anchored, kind, period, source)
    }

    /// Why the gate refuses any other new partial (a development signature), if it does.
    pub fn gate_refusal(&self) -> Option<String> {
        (!self.confirmed).then(|| {
            "this node's chain does not hold what the anchor's records name yet".to_string()
        })
    }

    fn job(&self, marks: Marks) -> Job {
        Job {
            marks,
            height: self.height,
            digest: self.digest,
            head: self.head.clone(),
            refresh: !self.head_known,
            attempt: self.attempt.clone(),
        }
    }

    fn head_marks(&self) -> Marks {
        self.head
            .as_ref()
            .map(|head| head.record.marks)
            .unwrap_or_default()
    }

    /// What to do with a computed partial that needs `needed` covered (`None`: nothing).
    pub fn step(&mut self, needed: Option<Marks>, reply: R) -> (Step, Option<R>) {
        let Some(needed) = needed else {
            return (Step::Give, Some(reply));
        };
        if self.head_marks().covers(&needed) {
            return (Step::Give, Some(reply));
        }
        if self.degraded {
            self.unanchored = self.unanchored.max(needed);
            return (Step::Give, Some(reply));
        }
        self.held.push((needed, reply));
        if self.writing.is_some() {
            return (Step::Hold(None), None);
        }
        let marks = self.held_marks();
        self.writing = Some(marks);
        (Step::Hold(Some(self.job(marks))), None)
    }

    fn held_marks(&self) -> Marks {
        self.held
            .iter()
            .fold(self.head_marks(), |marks, (needed, _)| marks.max(*needed))
    }

    /// `record` was written: the replies it covers, and the next record to write for those it
    /// does not.
    pub fn written(&mut self, record: SignedRecord) -> (Vec<R>, Option<Job>) {
        self.head = Some(record);
        self.head_known = true;
        self.attempt = None;
        self.writing = None;
        self.degraded = false;
        self.unanchored = Marks::default();
        let marks = self.head_marks();
        let (given, still): (Vec<_>, Vec<_>) = std::mem::take(&mut self.held)
            .into_iter()
            .partition(|(needed, _)| marks.covers(needed));
        self.held = still;
        let next = (!self.held.is_empty()).then(|| {
            let marks = self.held_marks();
            self.writing = Some(marks);
            self.job(marks)
        });
        (given.into_iter().map(|(_, reply)| reply).collect(), next)
    }

    /// A write sent `attempted` (if it got that far) without learning whether it landed: its
    /// head is read again before the next write, which takes `attempted` as its own if found.
    fn lost(&mut self, attempted: Option<SignedRecord>) {
        if attempted.is_some() {
            self.attempt = attempted;
            self.head_known = false;
        }
    }

    /// The write failed or timed out, after sending `attempted` if it got that far: the
    /// keyholder is degraded, and gives every held reply.
    pub fn failed(&mut self, now: SystemTime, attempted: Option<SignedRecord>) -> Vec<R> {
        self.lost(attempted);
        self.writing = None;
        self.degraded = true;
        self.last_attempt = Some(now);
        let held = std::mem::take(&mut self.held);
        for (needed, _) in &held {
            self.unanchored = self.unanchored.max(*needed);
        }
        held.into_iter().map(|(_, reply)| reply).collect()
    }

    /// A record to write now without holding anything: a heartbeat every `interval` while the
    /// height moves, or, while degraded, a catch-up record (with what was signed meanwhile) every
    /// [`RETRY`].
    pub fn due(&mut self, now: SystemTime, interval: Duration) -> Option<Job> {
        if self.writing.is_some() {
            return None;
        }
        let since = |at: Option<SystemTime>| {
            at.and_then(|at| now.duration_since(at).ok())
                .unwrap_or(Duration::MAX)
        };
        let due = if self.degraded {
            since(self.last_attempt) >= RETRY
        } else {
            let last = self
                .head
                .as_ref()
                .map(|head| UNIX_EPOCH + Duration::from_millis(head.record.written_at));
            // A new generation (an acknowledged rollback) needs a record of its own at once.
            let moved = self.head.as_ref().is_none_or(|head| {
                head.record.height < self.height || head.record.generation != self.generation
            });
            moved && since(last) >= interval && since(self.last_attempt) >= interval.min(RETRY)
        };
        if !due {
            return None;
        }
        self.last_attempt = Some(now);
        let marks = self.head_marks().max(self.unanchored);
        self.writing = Some(marks);
        Some(self.job(marks))
    }

    /// A due write failed (nothing was held for it), after sending `attempted` if it got that
    /// far.
    pub fn due_failed(&mut self, now: SystemTime, attempted: Option<SignedRecord>) {
        self.lost(attempted);
        self.writing = None;
        self.degraded = true;
        self.last_attempt = Some(now);
    }
}

/// The record `job` asks for, after `head` (read first if `job.refresh`).
pub async fn write(
    store: &AnchorStore,
    key: &PrivateKey,
    cluster: Digest,
    generation: u64,
    job: Job,
    now: SystemTime,
) -> Result<SignedRecord, AnchorError> {
    write_noting(store, key, cluster, generation, job, now, &Mutex::new(None)).await
}

/// [write], noting in `attempted` each record it sends before it sends it: if the write ends
/// without an outcome (a timeout drops it), the caller still knows what may have landed.
pub async fn write_noting(
    store: &AnchorStore,
    key: &PrivateKey,
    cluster: Digest,
    generation: u64,
    job: Job,
    now: SystemTime,
    attempted: &Mutex<Option<SignedRecord>>,
) -> Result<SignedRecord, AnchorError> {
    let node = key.public_key();
    let mut head = if job.refresh {
        store.latest(&node).await?
    } else {
        job.head.clone()
    };
    if let Some(attempt) = &job.attempt {
        head = after_attempt(store, head, attempt)?;
    }
    let record = |head: &Option<SignedRecord>| {
        SignedRecord::sign(
            key,
            Record {
                cluster,
                node: node.clone(),
                generation,
                sequence: head.as_ref().map_or(0, |head| head.record.sequence + 1),
                previous: head
                    .as_ref()
                    .map_or_else(|| Digest::from([0; 32]), SignedRecord::hash),
                height: job.height,
                digest: job.digest,
                marks: head
                    .as_ref()
                    .map_or(job.marks, |head| head.record.marks.max(job.marks)),
                written_at: now
                    .duration_since(UNIX_EPOCH)
                    .map_or(0, |since| since.as_millis() as u64),
            },
        )
    };
    let note = |record: &SignedRecord| {
        *attempted
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(record.clone());
    };
    let first = record(&head);
    note(&first);
    match store.put(&first).await {
        Ok(()) => Ok(first),
        Err(AnchorError::Exists { path }) => {
            // The earlier attempt at this very place, landed after the head was read back: this
            // node's own record. Write after it, once.
            let Some(attempt) = job
                .attempt
                .as_ref()
                .filter(|attempt| attempt.record.sequence == first.record.sequence)
            else {
                return Err(AnchorError::Exists { path });
            };
            if store.get(&node, attempt.record.sequence).await?.as_ref() != Some(attempt) {
                return Err(AnchorError::Exists { path });
            }
            let next = record(&Some(attempt.clone()));
            note(&next);
            store.put(&next).await?;
            Ok(next)
        }
        Err(err) => Err(err),
    }
}

/// The head to write after, read back as `latest`, given the `attempt` of a write whose outcome
/// was lost: below its place, it did not land (yet); at its place, it must be that very record;
/// beyond it, another process wrote.
fn after_attempt(
    store: &AnchorStore,
    latest: Option<SignedRecord>,
    attempt: &SignedRecord,
) -> Result<Option<SignedRecord>, AnchorError> {
    let sequence = attempt.record.sequence;
    match &latest {
        Some(latest)
            if latest.record.sequence > sequence
                || (latest.record.sequence == sequence && latest != attempt) =>
        {
            Err(AnchorError::Exists {
                path: store.place(&attempt.record.node, latest.record.sequence),
            })
        }
        _ => Ok(latest),
    }
}
