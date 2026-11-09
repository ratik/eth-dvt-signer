//! The executor's side of the anchor (docs/anchor.md): as blocks are applied, compare this node's
//! chain with the records read at start, confirm it, or decide that the network was rolled back.

use super::rules::View;
use commonware_cryptography::sha256::Digest;
use std::collections::BTreeMap;

/// Blocks a node applies after its start before it judges the network's finalized tip against
/// the anchor (rule c): enough for a lagging node to learn the network's tip from consensus.
pub const TIP_GRACE_BLOCKS: u64 = 32;

/// What the records say about this node's chain so far.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Not decided yet: the node signs nothing new.
    Pending,
    /// The chain holds what the records name: the node signs.
    Confirmed,
    /// The chain is not the one that was signed under: stop.
    RolledBack(String),
}

/// The records read at start, and this node's chain at their heights.
#[derive(Clone, Debug)]
pub struct Watch {
    view: View,
    /// This node's block digest at each record height it has applied (and kept).
    observed: BTreeMap<u64, Digest>,
    confirmed: bool,
    /// Blocks applied since start.
    applied: u64,
}

impl Watch {
    /// `view`, with this node's digests at the record heights it had applied at start.
    pub fn new(view: View, observed: BTreeMap<u64, Digest>) -> Self {
        Self {
            view,
            observed,
            confirmed: false,
            applied: 0,
        }
    }

    /// The record heights whose block this node must observe.
    pub fn heights(&self) -> Vec<u64> {
        self.view
            .records()
            .iter()
            .map(|record| record.record.height)
            .collect()
    }

    pub fn view(&self) -> &View {
        &self.view
    }

    /// The verdict before anything is applied (at start).
    pub fn start(&mut self) -> Verdict {
        self.judge(None)
    }

    /// A block was applied: `height`, `digest`, with `tip` the network's finalized tip as this
    /// node knows it (marshal's).
    pub fn applied(&mut self, height: u64, digest: Digest, tip: u64) -> Verdict {
        self.applied += 1;
        if self.heights().contains(&height) {
            self.observed.insert(height, digest);
        }
        self.judge(Some(tip))
    }

    fn judge(&mut self, tip: Option<u64>) -> Verdict {
        let digest_at = |height: u64| self.observed.get(&height).copied();
        if self.view.contradicted(digest_at) {
            let nodes = self.view.contradictions(digest_at).len();
            return Verdict::RolledBack(format!(
                "the anchor's records of {nodes} nodes name other blocks at heights this node \
                 applied"
            ));
        }
        if self.confirmed {
            return Verdict::Confirmed;
        }
        if self.view.confirmed(digest_at) {
            self.confirmed = true;
            return Verdict::Confirmed;
        }
        if let (Some(tip), Some(gate)) = (tip, self.view.gate_height())
            && self.applied >= TIP_GRACE_BLOCKS
            && tip < gate
        {
            return Verdict::RolledBack(format!(
                "the network finalizes at height {tip}, below the height {gate} the anchor's \
                 records show was finalized"
            ));
        }
        Verdict::Pending
    }
}
