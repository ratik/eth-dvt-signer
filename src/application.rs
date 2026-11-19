//! Block production for consensus.
//!
//! [Application] is wrapped by marshal's `Inline` adapter, which handles block dissemination,
//! parent/height checks and ordered delivery of finalized blocks. The application itself only:
//!
//! - builds a block from the local mempool when this node leads a view (`propose`),
//! - accepts any well-formed block (`verify`; size limits are enforced by the codec), except
//!   around the end of a consensus epoch (below),
//! - forwards finalized blocks to the executor, and records the finalized tip (`report`).
//!
//! A duty or a slashing-protection import beyond this node's time horizon (`eth::horizon`) is
//! neither proposed nor voted for: the horizon is checked against this node's clock, where it
//! decides what enters consensus, never when a block is applied.
//!
//! A protected command (`admin`) is neither proposed nor voted for without a threshold of
//! approvals and exactly the next administrative nonce: the executor's committed nonce plus the
//! protected commands of the ancestors it has not applied yet. A bare protected command (one
//! without approvals) is refused in a new block; one from the history before approvals existed is
//! still applied (`storage`).
//!
//! A builder registration (`eth::registration`) is neither proposed nor voted for unless the
//! registration policy in force at it allows it (the policy at the parent, as the executor's
//! committed one and the policy changes of the ancestors it has not applied, then each change in
//! the block, in order: the same order the state machine applies them in) and its timestamp is
//! within the policy's window by this node's clock. A leader puts at most
//! [MAX_REGISTRATIONS_PER_BLOCK] registrations in a block, after every other transaction; a voter
//! refuses a block with more.
//!
//! A block carrying a reconfiguration is the last of its consensus epoch (`epochs`, R3): this node
//! neither builds nor votes for a child of one, and a block carrying one must carry nothing else
//! and follow the current epoch's rules, adding a configured follower. The check reads the parent
//! block only, never the applied state: a notarization takes the votes of more honest nodes than
//! there can be faulty ones, so no child of such a block is ever notarized, however far behind the
//! voters' executors are, and every node stops at the same block.

use crate::{
    admin::Administration,
    epochs::Epochs,
    eth::{
        horizon::Horizon,
        registration::{self, MAX_PENDING_REGISTRATIONS, MAX_REGISTRATIONS_PER_BLOCK, Policy},
    },
    executor::Message,
    hooks,
    types::{Block, Command, MAX_BLOCK_BYTES, MAX_TRANSACTIONS_PER_BLOCK, Transaction},
};
use commonware_actor::Feedback;
use commonware_codec::EncodeSize as _;
use commonware_consensus::{
    Heightable as _, Reporter,
    marshal::{Update, ancestry::Ancestry},
    simplex::types::Context,
};
use commonware_cryptography::{Digested, Digestible as _, ed25519::PublicKey, sha256::Digest};
use commonware_runtime::{Clock, Metrics, Spawner};
use commonware_utils::channel::mpsc;
use commonware_utils::ordered::Set;
use futures::StreamExt as _;
use rand_core::Rng;
use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime},
};
use tracing::{debug, warn};

/// Consensus signing scheme.
pub type Scheme = commonware_consensus::simplex::scheme::ed25519::Scheme;

/// How long a leader waits for transactions before proposing an empty block.
///
/// Requests are gossiped to every node, so the leader proposes as soon as one arrives; this only
/// bounds how often empty blocks are produced while idle. It must stay below
/// `engine::LEADER_TIMEOUT`, leaving time to build and broadcast the proposal.
pub const MAX_IDLE: Duration = Duration::from_millis(1500);
const IDLE_POLL: Duration = Duration::from_millis(10);

/// Transactions waiting to be included in a block, in arrival order.
#[derive(Clone, Default)]
pub struct Mempool(Arc<Mutex<Pending>>);

#[derive(Default)]
struct Pending {
    queue: VecDeque<(Digest, Transaction)>,
    known: HashSet<Digest>,
    /// Builder registrations in `queue`.
    registrations: usize,
    /// The peer that gossiped each pending transaction (this node's own have none).
    origins: HashMap<Digest, PublicKey>,
    /// Transactions and bytes pending per gossiping peer.
    per_peer: HashMap<PublicKey, (usize, usize)>,
}

/// Most transactions one peer's gossip keeps pending: a faulty peer can delay the others by about
/// one block, never fill the queue.
pub const MAX_PENDING_PER_PEER: usize = MAX_TRANSACTIONS_PER_BLOCK;

/// Most bytes one peer's gossip keeps pending: two blocks' worth.
pub const MAX_PENDING_BYTES_PER_PEER: usize = 2 * MAX_BLOCK_BYTES;

impl Pending {
    fn recount(&mut self) {
        self.registrations = self
            .queue
            .iter()
            .filter(|(_, transaction)| transaction.command.is_registration())
            .count();
        let Pending {
            queue,
            known,
            origins,
            per_peer,
            ..
        } = self;
        origins.retain(|digest, _| known.contains(digest));
        per_peer.clear();
        for (digest, transaction) in queue.iter() {
            if let Some(peer) = origins.get(digest) {
                let (count, bytes) = per_peer.entry(peer.clone()).or_default();
                *count += 1;
                *bytes += transaction.encode_size();
            }
        }
    }
}

impl Mempool {
    /// Returns true if the transaction was added: it was not already pending, and if it is a
    /// builder registration, fewer than [MAX_PENDING_REGISTRATIONS] are.
    pub fn insert(&self, transaction: Transaction) -> bool {
        self.insert_from(None, transaction)
    }

    /// [Mempool::insert] for a transaction `peer` gossiped: also refused once that peer has
    /// [MAX_PENDING_PER_PEER] transactions or [MAX_PENDING_BYTES_PER_PEER] bytes pending.
    pub fn insert_from(&self, peer: Option<PublicKey>, transaction: Transaction) -> bool {
        let digest = transaction.digest();
        let registration = transaction.command.is_registration();
        let size = transaction.encode_size();
        let mut pending = self.0.lock().unwrap();
        if registration && pending.registrations >= MAX_PENDING_REGISTRATIONS {
            return false;
        }
        if let Some(peer) = &peer {
            let (count, bytes) = pending.per_peer.get(peer).copied().unwrap_or_default();
            if count >= MAX_PENDING_PER_PEER || bytes + size > MAX_PENDING_BYTES_PER_PEER {
                return false;
            }
        }
        if !pending.known.insert(digest) {
            return false;
        }
        if let Some(peer) = peer {
            let (count, bytes) = pending.per_peer.entry(peer.clone()).or_default();
            *count += 1;
            *bytes += size;
            pending.origins.insert(digest, peer);
        }
        pending.queue.push_back((digest, transaction));
        pending.registrations += usize::from(registration);
        true
    }

    pub fn remove_all(&self, transactions: &[Transaction]) {
        let mut pending = self.0.lock().unwrap();
        let mut removed = false;
        for transaction in transactions {
            removed |= pending.known.remove(&transaction.digest());
        }
        if removed {
            let Pending { queue, known, .. } = &mut *pending;
            queue.retain(|(digest, _)| known.contains(digest));
            pending.recount();
        }
    }

    /// Keep only the pending transactions `keep` accepts.
    pub fn retain(&self, keep: impl Fn(&Transaction) -> bool) {
        let mut pending = self.0.lock().unwrap();
        let Pending { queue, known, .. } = &mut *pending;
        queue.retain(|(digest, transaction)| {
            let kept = keep(transaction);
            if !kept {
                known.remove(digest);
            }
            kept
        });
        pending.recount();
    }

    pub fn len(&self) -> usize {
        self.0.lock().unwrap().queue.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Builder registrations pending.
    pub fn registrations(&self) -> usize {
        self.0.lock().unwrap().registrations
    }

    /// Oldest pending transactions not contained in `exclude`, within the block size limits:
    /// every other kind first, then at most [MAX_REGISTRATIONS_PER_BLOCK] builder registrations
    /// in what is left, so registrations never take an attestation's or a proposal's place.
    fn select(&self, exclude: &HashSet<Digest>) -> Vec<Transaction> {
        let pending = self.0.lock().unwrap();
        let mut bytes = 0;
        let mut fits = |transaction: &Transaction| {
            bytes += transaction.encode_size();
            bytes <= MAX_BLOCK_BYTES
        };
        let candidates = || {
            pending
                .queue
                .iter()
                .filter(|(digest, _)| !exclude.contains(digest))
                .map(|(_, transaction)| transaction)
        };
        let mut selected: Vec<Transaction> = candidates()
            .filter(|transaction| !transaction.command.is_registration())
            .take(MAX_TRANSACTIONS_PER_BLOCK)
            .take_while(|transaction| fits(transaction))
            .cloned()
            .collect();
        let room = MAX_TRANSACTIONS_PER_BLOCK
            .saturating_sub(selected.len())
            .min(MAX_REGISTRATIONS_PER_BLOCK);
        selected.extend(
            candidates()
                .filter(|transaction| transaction.command.is_registration())
                .take(room)
                .take_while(|transaction| fits(transaction))
                .cloned(),
        );
        selected
    }
}

/// Most not yet applied ancestors a voter reads to learn the administrative nonce a block's
/// protected commands must continue from: a voter further behind refuses the block (it is not
/// needed for the quorum while the others are caught up).
const MAX_UNAPPLIED: usize = 1024;

/// The executor's last applied height, administrative nonce and builder registration policy,
/// read together.
#[derive(Clone, Default)]
pub struct Committed(Arc<Mutex<CommittedState>>);

#[derive(Clone, Default)]
struct CommittedState {
    height: u64,
    nonce: u64,
    policy: Option<Arc<Policy>>,
}

impl Committed {
    pub fn new(height: u64, nonce: u64) -> Self {
        Self(Arc::new(Mutex::new(CommittedState {
            height,
            nonce,
            policy: None,
        })))
    }

    pub fn set(&self, height: u64, nonce: u64, policy: Option<Policy>) {
        let mut state = self.0.lock().unwrap();
        // Keep the shared copy while the policy is unchanged.
        let policy = match (policy, state.policy.take()) {
            (Some(policy), Some(current)) if *current == policy => Some(current),
            (policy, _) => policy.map(Arc::new),
        };
        *state = CommittedState {
            height,
            nonce,
            policy,
        };
    }

    /// `(height, nonce)`.
    pub fn get(&self) -> (u64, u64) {
        let state = self.0.lock().unwrap();
        (state.height, state.nonce)
    }

    /// `(height, nonce, policy)`.
    fn snapshot(&self) -> (u64, u64, Option<Arc<Policy>>) {
        let state = self.0.lock().unwrap();
        (state.height, state.nonce, state.policy.clone())
    }
}

/// The last registration policy `block` sets, if it sets one.
fn last_policy(block: &Block) -> Option<Arc<Policy>> {
    block
        .transactions
        .iter()
        .rev()
        .find_map(|transaction| transaction.command.registration_policy())
        .map(|policy| Arc::new(policy.clone()))
}

fn registration_count(block: &Block) -> usize {
    block
        .transactions
        .iter()
        .filter(|transaction| transaction.command.is_registration())
        .count()
}

/// The duties of `block` the fee-recipient policy binds (registrations, Gloas preferences and
/// envelopes): with none, and no protected command, a voter needs neither policy nor nonce.
fn policy_bound_count(block: &Block) -> usize {
    block
        .transactions
        .iter()
        .filter(|transaction| {
            matches!(&transaction.command, Command::Duty(request) if request.duty.terms().is_some())
        })
        .count()
}

/// The duties of `transactions` the fee-recipient policy binds that `policy` (the policy in
/// force before the first) and each policy change among them, in order, refuse at `now` with
/// `leeway` (a registration's window; `registration::check_duty`): `(index, why)`.
fn refused_by_policy(
    transactions: &[Transaction],
    mut policy: Option<Arc<Policy>>,
    now: SystemTime,
    leeway: Duration,
) -> Vec<(usize, registration::Refusal)> {
    let mut refused = Vec::new();
    for (index, transaction) in transactions.iter().enumerate() {
        if let Some(change) = transaction.command.registration_policy() {
            policy = Some(Arc::new(change.clone()));
            continue;
        }
        if let Command::Duty(request) = &transaction.command
            && let Err(refusal) =
                registration::check_duty(policy.as_deref(), &request.duty, now, leeway)
        {
            refused.push((index, refusal));
        }
    }
    refused
}

/// The administrative nonce of a protected command (`None` for any other).
fn admin_nonce(transaction: &Transaction) -> Option<u64> {
    match &transaction.command {
        Command::Admin(authorized) => Some(authorized.nonce),
        _ => None,
    }
}

fn admin_count(block: &Block) -> u64 {
    block
        .transactions
        .iter()
        .filter(|transaction| admin_nonce(transaction).is_some())
        .count() as u64
}

/// What this node checks a block against, beyond the codec: the end of its consensus epoch, the
/// time horizon of duties and the approvals of protected commands.
#[derive(Clone)]
pub struct Rules {
    /// The consensus epochs, up to the one this node runs.
    pub epochs: Arc<Epochs>,
    /// Keys a reconfiguration may add: the configured followers.
    pub candidates: Set<PublicKey>,
    /// Height of a block carrying a reconfiguration this node saw as a proposal's parent (0:
    /// none): the epoch's last block, finalized or not yet.
    pub terminal: Arc<AtomicU64>,
    /// This node's time horizon.
    pub horizon: Horizon,
    /// The approver set (`--approvers`); without, no protected command is proposed or voted for.
    pub admin: Option<Administration>,
    /// The executor's applied height and administrative nonce.
    pub committed: Committed,
}

impl Rules {
    /// Whether `transaction` may enter a new block, the nonce aside: not a bare protected
    /// command, and if approved, approved here; a ceremony it starts has an id of its kind
    /// (`Command::ceremony_id_rule`: reserved ids are the protected commands', and only theirs).
    fn authorized(&self, transaction: &Transaction) -> Result<(), String> {
        match &transaction.command {
            command if command.is_protected() => {
                Err("a protected command without approvals".into())
            }
            Command::Admin(authorized) => {
                authorized.command.ceremony_id_rule()?;
                match &self.admin {
                    None => Err("a protected command, and this node has no approver set".into()),
                    Some(admin) => admin
                        .verify(authorized)
                        .map_err(|reason| format!("a protected command: {reason}")),
                }
            }
            command => command.ceremony_id_rule(),
        }
    }
}

#[derive(Clone)]
pub struct Application {
    mempool: Mempool,
    /// Highest finalized height marshal knows of (it may not have every block below it yet).
    tip: Arc<AtomicU64>,
    executor: mpsc::UnboundedSender<Message>,
    rules: Rules,
}

impl Application {
    pub const fn new(
        mempool: Mempool,
        tip: Arc<AtomicU64>,
        executor: mpsc::UnboundedSender<Message>,
        rules: Rules,
    ) -> Self {
        Self {
            mempool,
            tip,
            executor,
            rules,
        }
    }

    /// Whether `parent` ends this node's epoch (`Epochs::ends_current`), with a reconfiguration
    /// approved here: then no block follows it. Honest voters notarize no block whose
    /// reconfiguration is not approved, so this only holds for one that is; checking it here too
    /// keeps a block with forged approvals from stopping this node's proposals and votes.
    fn ends_epoch(&self, parent: &Block) -> bool {
        if !self.rules.epochs.ends_current(parent) {
            return false;
        }
        let approved = parent.transactions.iter().all(|transaction| {
            !matches!(transaction.command, Command::Admin(_))
                || self.rules.authorized(transaction).is_ok()
        });
        if !approved {
            warn!(
                height = parent.height.get(),
                "a parent carries a reconfiguration without valid approvals: not the epoch's end"
            );
            return false;
        }
        self.rules
            .terminal
            .fetch_max(parent.height.get(), Ordering::AcqRel);
        true
    }

    /// `selected` without the duties whose `fork_info` is not this node's network's (P0.3) and
    /// the transactions beyond this node's horizon at `now`, which are dropped from the mempool:
    /// such a duty never becomes one to propose (validator clients do not send them), and voters
    /// would refuse the block.
    fn admissible(&self, selected: Vec<Transaction>, now: SystemTime) -> Vec<Transaction> {
        let (selected, wrong): (Vec<_>, Vec<_>) = selected.into_iter().partition(|transaction| {
            match self.rules.horizon.command_fork(&transaction.command) {
                Ok(()) => true,
                Err(wrong) => {
                    warn!(id = transaction.id, %wrong, "dropping a duty of another fork schedule");
                    false
                }
            }
        });
        self.mempool.remove_all(&wrong);
        if hooks::no_horizon() {
            return selected;
        }
        let (admitted, beyond): (Vec<_>, Vec<_>) =
            selected.into_iter().partition(|transaction| {
                match self
                    .rules
                    .horizon
                    .command(&transaction.command, now, Horizon::ADMISSION)
                {
                    Ok(()) => true,
                    Err(beyond) => {
                        warn!(id = transaction.id, %beyond, "dropping a transaction beyond the horizon");
                        false
                    }
                }
            });
        self.mempool.remove_all(&beyond);
        admitted
    }

    /// What a child of `parent` continues from: the next administrative nonce (the executor's
    /// committed one plus the protected commands of the ancestors it has not applied) and the
    /// registration policy in force (the last one those ancestors set, else the committed one),
    /// read from `ancestry` (which yields `parent`'s ancestors after `parent`). `None` if unknown
    /// here: `parent` is below the applied height, or too many ancestors are not applied.
    async fn unapplied(
        &self,
        parent: &Arc<Block>,
        ancestry: &mut impl Ancestry<Block>,
    ) -> Option<(u64, Option<Arc<Policy>>)> {
        let (executed, nonce, committed) = self.rules.committed.snapshot();
        if parent.height.get() < executed {
            return None;
        }
        let mut pending = 0;
        let mut unapplied = 0;
        let mut policy = None;
        let mut ancestor = Some(parent.clone());
        loop {
            let block = ancestor?;
            if block.height.get() <= executed {
                return Some((nonce + pending + 1, policy.or(committed)));
            }
            unapplied += 1;
            if unapplied > MAX_UNAPPLIED {
                return None;
            }
            pending += admin_count(&block);
            if policy.is_none() {
                policy = last_policy(&block);
            }
            ancestor = ancestry.next().await.map(|block| block.inner_shared());
        }
    }

    /// `transactions` with the builder registrations moved after every other transaction, at
    /// most [MAX_REGISTRATIONS_PER_BLOCK] of them, and without the duties the policy in force at
    /// them (from `policy`, the one at the parent) or a registration's window at `now` refuses:
    /// registrations, Gloas preferences and envelopes (dropped from the mempool: validator
    /// clients sign again). A reconfiguration goes alone.
    fn with_registrations(
        &self,
        transactions: Vec<Transaction>,
        registrations: Vec<Transaction>,
        policy: Option<Arc<Policy>>,
        now: SystemTime,
    ) -> Vec<Transaction> {
        let reconfigures = transactions.iter().any(|transaction| {
            matches!(&transaction.command, Command::Admin(authorized) if matches!(authorized.command, Command::Reconfigure(_)))
        });
        let mut block = transactions;
        if !reconfigures {
            block.extend(registrations.into_iter().take(MAX_REGISTRATIONS_PER_BLOCK));
        }
        // Registrations, and Gloas preferences and envelopes among the others, as voters check
        // them: the policy in force at each.
        let refused = refused_by_policy(&block, policy, now, Horizon::ADMISSION);
        if refused.is_empty() {
            return block;
        }
        let mut dropped = Vec::new();
        for (index, refusal) in refused.iter().rev() {
            let transaction = block.remove(*index);
            warn!(id = transaction.id, %refusal, "dropping a duty the registration policy refuses");
            dropped.push(transaction);
        }
        self.mempool.remove_all(&dropped);
        block
    }

    /// `selected` with its protected commands checked (`Rules::authorized`): those without valid
    /// approvals, and approved ones whose nonce is used, are dropped from the mempool; approved
    /// ones go in nonce order from `next` while consecutive, the others wait (`None`: the nonce is
    /// unknown, none goes). A reconfiguration goes alone: in a block of its own when its nonce is
    /// the next, else it waits for the block after the commands before it. One that breaks the
    /// epoch's rules is dropped.
    fn administered(&self, selected: Vec<Transaction>, next: Option<u64>) -> Vec<Transaction> {
        let mut dropped = Vec::new();
        let mut approved = Vec::new();
        let mut others = Vec::new();
        for transaction in selected {
            if let Err(reason) = self.rules.authorized(&transaction) {
                warn!(id = transaction.id, %reason, "dropping a transaction");
                dropped.push(transaction);
                continue;
            }
            match (admin_nonce(&transaction), next) {
                (None, _) => others.push(transaction),
                (Some(nonce), Some(next)) if nonce < next => {
                    warn!(
                        id = transaction.id,
                        nonce, next, "dropping a protected command whose nonce is used"
                    );
                    dropped.push(transaction);
                }
                (Some(_), Some(_)) => approved.push(transaction),
                (Some(_), None) => {}
            }
        }
        approved.sort_by_key(admin_nonce);
        let first = next.unwrap_or_default();
        for (next, transaction) in (first..).zip(approved) {
            if admin_nonce(&transaction) != Some(next) {
                // A gap, or a second command with the same nonce: it waits (and is dropped once
                // its nonce is used).
                break;
            }
            let Command::Admin(authorized) = &transaction.command else {
                unreachable!("approved");
            };
            if let Command::Reconfigure(change) = &authorized.command {
                if next != first {
                    break;
                }
                match self.rules.epochs.check(
                    change.epoch,
                    &change.remove,
                    &change.add,
                    Some(&self.rules.candidates),
                ) {
                    Ok(()) => {
                        self.mempool.remove_all(&dropped);
                        return vec![transaction];
                    }
                    Err(refusal) => {
                        warn!(id = transaction.id, %refusal, "dropping a reconfiguration");
                        dropped.push(transaction);
                        break;
                    }
                }
            }
            others.push(transaction);
        }
        self.mempool.remove_all(&dropped);
        others
    }
}

impl<E> commonware_consensus::Application<E> for Application
where
    E: Rng + Spawner + Metrics + Clock,
{
    type SigningScheme = Scheme;
    type Context = Context<Digest, PublicKey>;
    type Block = Block;
    type Input = ();

    async fn propose(
        &mut self,
        (context, consensus): (E, Self::Context),
        mut ancestry: impl Ancestry<Self::Block>,
        _: (),
    ) -> Option<Digested<Self::Block>> {
        let parent = ancestry.next().await?.inner_shared();
        // The epoch ended with the parent: skip the view (a test hook builds on it anyway, as a
        // faulty leader would).
        if self.ends_epoch(&parent) && !hooks::propose_past_terminal() {
            debug!(
                height = parent.height.get(),
                "the epoch ended with the parent: not proposing"
            );
            return None;
        }

        // Give clients a moment to submit something instead of spinning out empty blocks.
        let deadline = context.current() + MAX_IDLE;
        while self.mempool.is_empty() && context.current() < deadline {
            context.sleep(IDLE_POLL).await;
        }

        // Skip transactions already carried by notarized-but-not-yet-executed ancestors, and
        // count their protected commands: the next administrative nonce follows them.
        let (executed, nonce, committed) = self.rules.committed.snapshot();
        let mut in_flight = HashSet::new();
        let mut pending = 0;
        let mut policy = None;
        let mut ancestor = Some(parent.clone());
        while let Some(block) = ancestor.filter(|block| block.height().get() > executed) {
            in_flight.extend(block.transactions.iter().map(Transaction::digest));
            pending += admin_count(&block);
            if policy.is_none() {
                policy = last_policy(&block);
            }
            ancestor = ancestry.next().await.map(|block| block.inner_shared());
        }
        let next = (parent.height().get() >= executed).then_some(nonce + pending + 1);
        let policy = policy.or(committed);
        while hooks::empty_blocks_paused() && self.mempool.select(&in_flight).is_empty() {
            context.sleep(IDLE_POLL).await;
        }

        // No trusted time: no time-bound transaction (`clock::now_or_refuse`).
        let now = crate::clock::now_or_refuse(context.current());
        let (registrations, selected): (Vec<_>, Vec<_>) = self
            .admissible(self.mempool.select(&in_flight), now)
            .into_iter()
            .partition(|transaction| transaction.command.is_registration());
        let mut transactions = self.with_registrations(
            self.administered(selected, next),
            registrations,
            policy,
            now,
        );
        // A faulty leader's own transactions (test hook; none in a deployment).
        transactions.extend(hooks::injected());
        let block = Block::new(
            parent.digest(),
            parent.height().next(),
            consensus.round.view().get(),
            transactions,
        );
        debug!(
            height = block.height.get(),
            view = block.view,
            transactions = block.transactions.len(),
            "proposing a block"
        );
        let digest = block.digest();
        Some(Digested::precomputed(block, digest))
    }

    async fn verify(
        &mut self,
        (context, _): (E, Self::Context),
        mut ancestry: impl Ancestry<Self::Block>,
    ) -> bool {
        // Inline already checked parent linkage and height, and the codec bounds the block size.
        // Any sequence of well-formed transactions is a valid input for the state machine, except
        // after the epoch's last block, for a reconfiguration that breaks the rules, for a duty
        // whose `fork_info` is not this network's, for a duty or an import beyond this node's
        // horizon, and for a protected command without valid approvals or with any nonce but the
        // next ones.
        let (Some(block), Some(parent)) = (ancestry.next().await, ancestry.next().await) else {
            return false;
        };
        let (block, parent) = (block.inner_shared(), parent.inner_shared());
        // No trusted time: a block with a time-bound transaction gets no vote.
        let now = crate::clock::now_or_refuse(context.current());
        for transaction in &block.transactions {
            // A duty under a domain this network's fork schedule does not give it (P0.3).
            if let Err(wrong) = self.rules.horizon.command_fork(&transaction.command) {
                warn!(
                    height = block.height.get(),
                    id = transaction.id,
                    %wrong,
                    "refusing a block with a duty of another fork schedule"
                );
                return false;
            }
            if let Err(beyond) =
                self.rules
                    .horizon
                    .command(&transaction.command, now, Horizon::VOTE)
            {
                warn!(
                    height = block.height.get(),
                    id = transaction.id,
                    %beyond,
                    "refusing a block with a transaction beyond the horizon"
                );
                return false;
            }
        }
        if self.ends_epoch(&parent) {
            warn!(
                height = block.height.get(),
                parent = parent.height.get(),
                "refusing a block after the epoch's last block"
            );
            return false;
        }
        for transaction in &block.transactions {
            if let Err(reason) = self.rules.authorized(transaction) {
                warn!(
                    height = block.height.get(),
                    id = transaction.id,
                    %reason,
                    "refusing a block with an unauthorized command"
                );
                return false;
            }
        }
        if let Err(refusal) = self
            .rules
            .epochs
            .check_block(&block, Some(&self.rules.candidates))
        {
            warn!(height = block.height.get(), %refusal, "refusing a reconfiguration");
            return false;
        }
        let registrations = registration_count(&block);
        if registrations > MAX_REGISTRATIONS_PER_BLOCK {
            warn!(
                height = block.height.get(),
                registrations,
                limit = MAX_REGISTRATIONS_PER_BLOCK,
                "refusing a block with too many builder registrations"
            );
            return false;
        }
        if admin_count(&block) == 0 && policy_bound_count(&block) == 0 {
            return true;
        }
        let Some((next, policy)) = self.unapplied(&parent, &mut ancestry).await else {
            warn!(
                height = block.height.get(),
                "refusing a block with protected commands or builder registrations: the \
                 administrative nonce or registration policy they follow is unknown here"
            );
            return false;
        };
        if let Some((index, refusal)) =
            refused_by_policy(&block.transactions, policy, now, Horizon::VOTE)
                .into_iter()
                .next()
        {
            warn!(
                height = block.height.get(),
                id = block.transactions[index].id,
                %refusal,
                "refusing a block with a duty the registration policy in force refuses"
            );
            return false;
        }
        if admin_count(&block) > 0 {
            let nonces: Vec<u64> = block.transactions.iter().filter_map(admin_nonce).collect();
            if nonces
                .iter()
                .zip(next..)
                .any(|(nonce, expected)| *nonce != expected)
            {
                warn!(
                    height = block.height.get(),
                    ?nonces,
                    next,
                    "refusing a block with protected commands out of nonce order (replayed or \
                     stale)"
                );
                return false;
            }
        }
        true
    }
}

impl Reporter for Application {
    type Activity = Update<Block>;

    fn report(&mut self, update: Self::Activity) -> Feedback {
        match update {
            Update::Block(block, ack) => {
                // If the executor is gone the node is shutting down; dropping `ack` stops marshal.
                let _ = self.executor.send(Message::Finalized {
                    block: block.inner_shared(),
                    ack,
                });
            }
            // Knowledge only (not durable yet): what the executor has not applied is a backlog.
            Update::Tip(_, height, _) => {
                self.tip.fetch_max(height.get(), Ordering::Release);
            }
        }
        Feedback::Ok
    }
}

#[cfg(test)]
#[path = "../tests/unit/application.rs"]
mod tests;
