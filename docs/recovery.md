# Recovery and readiness

This page describes what a node checks when it starts, what it claims about itself while it runs,
which recovery procedures are supported, and what cannot be detected. Each claim names the
mechanism that enforces it. Passing tests are evidence, not proof ([§9](#9-tests)).

## 1. What a node can know about itself

| Condition | Known? | How |
| --------- | ------ | --- |
| Local storage opened | Yes | `Store::init`, `Secrets::init` and marshal's archives open, or the node exits |
| State consistent with marshal's progress | Yes, at startup | marshal returns its durable processed height (`Floor`) from `init`; the node compares it before any actor starts |
| Slashing history internally consistent and matching the ceremonies | Yes, at startup | `Store::verify`: per-validator record counts, known validators, keys equal to their ceremony's group key ([slashing-protection.md](slashing-protection.md)) |
| Slashing history complete with respect to the network | **No** | a consistently older history (a rollback) looks like a node that missed blocks; the node replays them. Without the WORM anchor, a rollback of every node is not detected (§7) |
| Key shares consistent with the state | Yes, at startup | every stored share must belong to a completed ceremony of the state; loaded shares are verified against the ceremony's public polynomial |
| All locally known finalized blocks applied | Yes | marshal reports its finalized tip (`Update::Tip`); the node compares it with the executor's height |
| Caught up with the network | **No** | a node only knows what its peers told it. Nothing claims this |
| Able to sign an applied authorization | Yes | the DKG actor answers only after it loads its shares, and signs only an authorization committed in its state |
| Its consensus journal is complete | **No** (partly) | a missing journal is detected. An older journal is not: an old but internally consistent snapshot looks like a node that was offline |

## 2. Startup checks (fail closed)

`engine::open` and `Opened::start` open the durable stores and check them against each other before
any actor runs (`engine::check_recovery`, `engine::check_boundary`). On failure the node logs
`refusing to start` with the reason and exits with status 1 (77 when the anchor shows a rollback,
§7). Nothing is reset or deleted: no file is removed and no key share is regenerated.

**Evidence of damaged copies.** Opening a commonware metadata store truncates a copy that fails its
integrity check (it recovers from the other copy). This happens before the checks can run. So,
before it opens anything, the node reads every copy of the state, the secret store, marshal's
progress and the archives' metadata. It checks each copy (an 8-byte version, the entries, a
big-endian CRC32 of both), and saves each copy that fails to the `registry-diagnostics` partition,
synced (`engine::preserve_damaged_copies`).

- A saved copy is named by its content. It is written once and never rewritten; a partial one,
  from a crash while saving, is written again. The node never reads it.
- Nothing writes old bytes back into the working stores. They recover as commonware recovers them.
- A start interrupted after saving leaves the working copy untouched. Repeated starts never
  duplicate the evidence (`lifecycle::r5_damaged_copy_is_saved_before_opening`).
- Opening the stores otherwise changes them as any start does: the archive metadata is rewritten
  and torn journal tails are repaired.

| Check | Refuses when | Why |
| ----- | ------------ | --- |
| Replicated state opens | both copies corrupted, an unknown format, or the legacy format 1 | the state cannot be trusted or read |
| State not behind marshal | state height < marshal's processed height | marshal resumes after the last block it saw acknowledged, and the executor acknowledges a block only after the state commit. So the state can be one block ahead (a crash before the acknowledgement; the block is replayed and skipped), never behind. Behind means applied blocks were lost; running would skip them silently (BUG-2) |
| Share has its ceremony | a stored share's round has no completed ceremony in the state | a share is stored only after its ceremony's completion is durably applied. Otherwise the state (and its authorization history) was lost or rolled back while the share stayed |
| Slashing history consistent | a record of an unknown validator; a validator whose record count differs from its stored records; a validator ceremony without its validator, or the reverse; a key that is not its ceremony's; records without an activation (or a chain pinned by an earlier version); attestations that surround each other; an entry of an unknown kind | the history of a validator key must be complete before the key signs again: a lost proposal or attestation would let a conflicting one through ([slashing-protection.md](slashing-protection.md#startup-checks-fail-closed)) |
| Consensus journal present | the current epoch's journal partition is empty while the node has finalized history in that epoch (state or marshal height above the epoch's start) | the node may have voted in views it no longer remembers; voting again could equivocate. Only the operator can override it (`--allow-missing-consensus-journal`, §6). A node at the very start of an epoch has no journal of it yet ([reconfiguration.md](reconfiguration.md)) |
| Consensus epochs follow from the committee | the state's epoch records do not follow, one by one, from `--participants` | the command line names another original committee than the one this state's epochs come from |
| Epoch boundary matches the history | in an epoch after the first: the stored block at the epoch's start differs from the recorded one, or a finalization of an earlier epoch is stored above it | the previous epoch would have finalized past its last block; marshal could hand such a block to the executor as this epoch's |
| Closing height reachable | `--close-epoch-at` at or below the state's height | the node would never reach that height, so it would never stop |
| Approver set unchanged | the state applied a protected command under an approver set, and the node is started with another set or without `--approvers` | it would refuse, or accept, protected commands differently from the network. Restore the network's approver file ([administration.md](administration.md)) |
| Ethereum network unchanged | the state applied a protected command for an Ethereum network, and the node is started for another one | the same: every node needs the network's `--eth-network`, or the same `--eth-genesis-*` values |
| Anchor (with `--anchor`) | the anchor's records show this node's network was rolled back (exit status 77); an acknowledgment of a rollback does not verify or cannot be written | §7, [anchor.md](anchor.md) |

The executor keeps the run-time check of BUG-2: a finalized block delivered at a height other than
the next one stops the node.

## 3. Consensus restart: the durable floor

Consensus starts from `simplex::Floor::Finalized`, the finalization of the last block marshal
durably processed in the node's epoch. Without one, it starts from the epoch's genesis. The voter
skips every journal entry at or below that view and never votes there again. Marshal's processed
height only moves forward, as the floor requires. So a node whose journal was lost, or replaced by
an older one, cannot repeat a vote at or below its last processed finalization.

What the floor guarantees, and why:

- **It is a durable finalization.** Marshal syncs its processed height only after the executor
  acknowledged the block, and the executor acknowledges only after the state commit. The
  finalization certificate of a processed block is stored (and synced) before the block is
  delivered. A crash after the state commit and before the acknowledgement leaves the floor below
  the state, never above it (`crash::a4_*`).
- **It is valid for this committee.** Simplex verifies the certificate against the configured
  scheme (participants and namespace) when the engine is built, and refuses to start otherwise.
- **It comes after the startup checks.** Consensus is the last component started.
- **The voter never goes below it.** The voter enters `floor_view + 1` and never moves to a lower
  view. It cannot vote at or below the floor (`rollback::journal_only_rollback_resumes_above_floor`
  shows a node with an old journal resuming at `floor_view + 1`, not at the old journal's view).

What the floor does not cover:

- votes cast after that finalization (the views in flight when the node stopped). A journal older
  than those votes forgets them, and the node may vote again differently: an equivocation that
  peers may detect;
- anything at all when marshal's progress was rolled back together with the journal (a restore of
  the whole directory). The floor is rolled back too (`rollback::a1_full_restore_*` asserts it).

Those are §6's unsupported cases. The floor detects no rollback. It only bounds what a node with a
lost or older journal can repeat.

`/status` reports the floor (`readiness.consensus.floor_height`, `floor_view`) and the consensus
epoch (`readiness.consensus.epoch`). In an epoch after the first, the floor is the epoch's genesis
(the block that ended the previous epoch) until the node processed a finalization of its own
epoch. A finalization of another epoch is never a floor (simplex refuses one).

A node stops on its own only in these cases. Any other exit is a failure.

| Exit status | When | What to do |
| --- | --- | --- |
| **75** | Its consensus epoch ended with the block it just committed | Restart it: it runs the next epoch ([reconfiguration.md](reconfiguration.md)) |
| **76** | The epoch was closed with `--close-epoch-at` by a block without a reconfiguration | Restart it without the flag: the same epoch continues |
| **77** | The anchor's records show its network was rolled back | Do not restart it in a loop (§7) |

## 4. Readiness is not a safety mechanism

Readiness only decides whether this node accepts new work. No signature depends on it:

1. **A partial signature needs a durably applied authorization.** `dkg::actor::partial` signs only
   an authorization committed in this node's state for exactly the requested payload: a
   `storage::Committed` value for a development key, the validator's duty records for a duty. Only
   the store creates those, from state read from disk or just synced. A node behind the network has
   fewer authorizations, never different ones. It refuses what it has not applied
   (`not_authorized`, the request is parked). It never signs a payload it has not applied.
2. **Consensus decides authorizations; the first finalized one wins.** `state::apply` is
   deterministic. The first finalized command for a `(ceremony, nonce)` creates the authorization.
   A later command with another payload is `Rejected` and changes nothing, on every node, because
   every node applies the same finalized sequence. For a validator duty, slashing protection
   refuses the conflicting one in the same way (`412`).
3. **A coordinator signs only what the state machine returned.** It collects partials only after it
   finds the authorization applied locally, or after its own command was applied with outcome
   `Accepted` (or `AlreadyAccepted`, same payload). `Rejected` ends the request with `409`.
4. **A group signature needs three partials**, from three distinct keyholders that each checked
   (1). A Byzantine keyholder contributes at most one.

So a stale node may *submit* a conflicting command (its local read finds nothing). But the command
can only be finalized after the authorization it conflicts with, and is rejected there. The node
learns the outcome when it applies that block. On the development `POST /sign`, its client gets
`409 REJECTED`, or `AUTHORIZATION_TIMEOUT` if the node does not catch up in time (a retry then gets
`409`). The node never treats the local absence of an authorization as proof that a nonce is
unused.

The readiness tolerance (two blocks) is a liveness choice only. With a tolerance of zero, a node
would refuse new authorizations at random right after every block. With any tolerance, (1) to (4)
hold. `lag::*` tests one, two and three blocks of lag, with a Byzantine signer in place of node 1
and conflicting requests racing through a current node and a lagging node. The conflicting
request B is submitted and rejected at one and two blocks, and refused before submission at three.
No partial or group signature for the losing payload ever exists.

## 5. Readiness

`readiness::Readiness::evaluate` is a pure function of what the node observes:

- `applied`: the height of the last block applied to the replicated state;
- `known_finalized`: the highest finalized height marshal knows of (blocks may still be missing);
- `last_applied`: when this process last applied a new block (`None` if none since it started);
- the number of completed ceremonies without a usable share.

With an anchor, the keyholder's anchor state adds two reasons (`Readiness::with_anchor`).

| Reason | Condition | State | Blocks new authorizations |
| ------ | --------- | ----- | ------------------------- |
| `no_block_since_start` | `last_applied` is `None` | `syncing` | yes |
| `local_backlog` | `known_finalized > applied + 2`. Marshal reports a finalized tip a moment before it delivers the block, and may finalize the next one meanwhile, so up to two blocks are normally on their way | `syncing` | yes |
| `no_recent_finalization` | `now - last_applied > STALL` (10 s, five leader timeouts; an idle network finalizes a block every ~1.6 s) | `degraded` | yes |
| `share_unavailable` | a completed ceremony has no usable share here | `degraded` | no |
| `anchor_behind` | this node's chain does not hold yet what the anchor's records name | `syncing` | yes |
| `anchor_unavailable` | the anchor did not answer; the node signs under the restart floor alone | `degraded` | no |

`ready` means no reason applies. `syncing` wins over `degraded`. The readiness body has two
predicates:

- `can_sign_authorized`: always `true` on a running node (its storage passed §2, and its shares are
  loaded, since the actor answered). Each partial is still decided by `dkg::actor::partial`: share
  present and verified, authorization committed here, payload equal to the committed one.
- `can_submit_authorization`: no reason that blocks new authorizations applies.

Whether a node votes is decided at startup (§2, §3) and never changes at run time
(`readiness.consensus.voting`).

Where readiness applies:

- A signing request for an authorization already applied here goes straight to signature
  collection, whatever the readiness. The authorization is finalized and durable, and the keyholder
  of every participant checks it again.
- A signing request that needs a new authorization is refused with `503` and the blocking `reasons`
  unless `can_submit_authorization` holds (`signer::coordinator`); the development `POST /sign`
  names it `NOT_READY`. A node that does not follow consensus would submit a command whose outcome
  it cannot see.
- `GET /ready` returns the readiness with `200` when `ready`, and `503` otherwise. `GET /status`
  includes it.

What readiness does not claim:

- that the node has the network's latest block: `known_finalized_height` is what this node knows;
- more than it observed: `ready` is evidence at most `STALL` old. A node cut off from every peer
  reports `no_recent_finalization` only once `STALL` has passed;
- that nothing older is missing after a restart: the first new block proves that consensus
  progressed with this node. Marshal backfills missing blocks, and they appear as `local_backlog`
  once their finalization is known.

## 6. Recovery scenarios

### Supported

| Scenario | Behavior | Enforced by |
| -------- | -------- | ----------- |
| Normal restart | Replays its journal above the floor, re-delivers unacknowledged blocks, `syncing` until it applies a new block, then `ready` | §2, §3, the executor's at-least-once handling |
| Restart with intact durable state after a crash (at any point) | The same. A block applied but not acknowledged is skipped on re-delivery. A torn unacknowledged write falls back to the older state copy, and the block is applied again | executor height check, metadata copies |
| Application state restored from an older backup, **current consensus journal kept** | Marshal must be restored with it (otherwise `MissingBlocks` stops the node). The node replays the finalized blocks it lacks. It refuses to sign what it has not applied (`not_authorized`, parked), never signs a conflicting payload (its authorizations are a prefix of the finalized history), and becomes `ready` after the replay | §2, keyholder gate, consensus ordering |
| Node behind the retained history | Restored from a healthy node's partitions (procedure below). It then behaves as above | `recovery::lagging_node_restored_from_peer_copy` |
| A follower (a non-voting keyholder, R2) restarted, or joining for the first time | It catches up like a voter, by backfill from the committee; its secret store is its own. Joining after the voters pruned their history needs a copy of a healthy node's state and marshal partitions (procedure below), which it cannot verify (no state root; audit L-20) | `follower::fol_3_*`, `replace::r2_e2e_3_*`, `replace::r2_e2e_restart_e_*` |
| Consensus journal lost | Refuses to start. With `--allow-missing-consensus-journal`, start it only after the other nodes have finalized more than 10 views (what peers keep) beyond anything this node can have voted in. It starts above its floor, and the votes it forgot are in views its peers no longer consider | §2, §3 |

**Restoring a node behind the retained history.** A node that was offline for longer than
`--retain-blocks` cannot backfill the missing blocks from its peers. Restore it from a healthy
node:

1. Stop the lagging node and a healthy one. With one node already down, consensus pauses until the
   healthy node is back.
2. In the lagging node's `<data-dir>/node-<id>`, replace every partition with the healthy node's
   copy, **except** its own secret store (`registry-secrets`, `registry-secrets-pending`), its consensus journals
   (`registry-consensus`, `registry-consensus-<e>`) and its `vault` directory.
3. Restart both.

Never take the secret store or a consensus journal from another node, and never take a consensus
journal from an old backup. Another node's key share makes this node's partials invalid. Another or
an older journal makes it vote twice in a view, and its peers then block it for an hour (audit
L-7).

A node with a sealed vault (`--vault gcp-tdx`) refuses `--allow-missing-consensus-journal`
([tee.md](tee.md)).

### Not supported (no automatic recovery)

| Scenario | Why | What happens |
| -------- | --- | ------------ |
| Restoring an old consensus journal | the node forgets votes cast after the backup; it can repeat votes above its floor differently (an equivocation, a Byzantine fault) | not detectable when the rest of the directory is consistent with it; peers that see an equivocation block the node at the p2p layer for an hour (audit L-7) |
| Replacing a node's directory with another node's | another node's key share (partials rejected) and votes (equivocation for that identity) | not detected by this node |
| Restoring several nodes from stale snapshots | two or more nodes without their votes exceed `f = 1` | consensus no longer guarantees safety |
| Whole-network rollback | §7 | without an anchor: conflicting signatures of the development `/sign`, and a crafted surround vote (L-1); the restart floor refuses double proposals and double votes. With an anchor: every node stops with exit status 77 |

### Scenario summary

| Scenario | Safe to sign? | Safe to vote? | Recovery behavior |
| -------- | ------------- | ------------- | ----------------- |
| Normal restart | Yes (keyholder gate over committed state; §2) | Yes (intact journal replayed above the floor; §3) | `syncing` until a new block is applied, then `ready` |
| Application rollback, journal intact | Yes (a stale prefix: refuses what it has not applied, never signs a conflict; §2 requires state and marshal together) | Yes (its own votes are known from the journal) | Replays missing blocks, then `ready` |
| Full node rollback | Its partials: yes, the same gate over a prefix of the finalized history. A group signature for a conflicting payload: no, while the other three keep the history | **Not guaranteed**: votes forgotten after the snapshot can be repeated differently; tolerated as one Byzantine node | Not detected locally; converges, or peers block it; `ready` only while it applies blocks, `degraded` within `STALL` if cut off |
| Rolled back to before a validator's activation (consensus journal kept) | Yes: the key signs nothing for it until the activation is replayed, then only for the activated chain, which it cannot change | Yes | Replays the activation from the finalized chain (E2E-ETH-8) |
| One offline peer | Yes | Yes | The restarting node is `ready` once consensus finalizes again with its votes. With a second node away, every node reports `no_recent_finalization`, new authorizations get `503 NOT_READY`, and applied ones fail in bounded time |
| Two nodes restarted together | Yes | Yes | Nothing is finalized while both are down. Once they are back, if they missed the certificate of the view the other two entered, consensus waits for the other two's next nullify retry (`timeout_retry`, 3 s), which carries it: 6.3 to 9.7 s measured after the restart in that case (audit L-14). Validator duties due meanwhile can be missed. Restart one node at a time, and wait until it is `ready` |
| Corrupted storage | The node does not run once the damage is detected (§2); a torn copy not yet acknowledged is replayed | Does not run | Exit status 1, storage left as it is |
| Whole-network rollback | Without an anchor: **no** for the development `/sign` and for crafted surround votes (L-1); the restart floor refuses blocks and attestations of slots and epochs before the restart. With an anchor: nothing new is signed before the nodes stop | **No** | Without an anchor: undetectable, unsupported. With one: every node exits with status 77; restore newer state, or the approvers acknowledge the rollback (§7) |
| Every node restarted at once (storage intact) | Yes; the restart floor refuses new duties of the current epoch (attestations) and slot (blocks) | Yes | Signs again from the next slot (blocks) and epoch (attestations) |

## 7. Whole-network rollback (L-1)

Suppose every node is restored to storage from before `(ceremony, nonce)` was authorized for
payload A. The network then authorizes and signs a conflicting payload B for the same nonce.
`rollback::a2_whole_network_rollback` reproduces this and fails. It stays `#[ignore]` so that the
ordinary suite stays green, and must not be changed to pass.

Why the node cannot detect it:

- Everything that records the authorization was rolled back on every node: the replicated state,
  the block archives, the consensus journals and marshal's progress. What remains is a consistent
  older history, identical to a network that never saw the authorization.
- Consensus safety assumes at most `f = 1` faulty node. A rollback of every node is a fault of all
  of them.
- A local monotonic counter (an epoch, a high-water mark, a "last signed" record) in the same
  directory is rolled back with it. In another directory of the same machine, the same operator
  action or backup system rolls it back. It helps only if the rollback cannot reach it.

What detects it is monotonic state that the rollback cannot reach. This repository implements one:
the WORM anchor ([anchor.md](anchor.md), `--anchor`). Its records live on S3, GCS or a directory
outside the nodes' storage and backups, and a keyholder writes them before it signs past them.
Other designs (a hardware counter, TEE sealing, another chain, more independent nodes) are not
implemented.

The same holds for Ethereum slashing protection, which is part of the replicated state
([slashing-protection.md](slashing-protection.md)). The state alone protects against every fault
above except this one. An Ethereum validator is slashed for two conflicting signatures, whatever
this system believes, and a rollback of every node forgets what was signed.
`eth2::e2e_eth_l1_whole_network_rollback_signs_a_double_proposal` reproduces a double proposal
with the keyholders' restart floor switched off (ignored, failing).

**The restart floor** narrows the problem without any record
([slashing-protection.md](slashing-protection.md#the-restart-floor)). Every keyholder process
refuses a new block, attestation, PTC vote or envelope of a slot (for an attestation: an epoch) it
may have signed for before it started. It knows this from its clock and the time horizon it
already keeps. After a whole-network rollback, every process has restarted, and any two quorums
share a keyholder. So no double proposal or double vote is signed (`floor::floor_1`). The floor
does not detect the rollback. It does not refuse a surround vote that a client crafts; that needs
slashing history outside the nodes' rollback domain, which is the WORM anchor. No local counter
was added.

**With the WORM anchor** ([anchor.md](anchor.md)), each keyholder writes a record before it signs
past its previous one. The record names its applied block and the highest block slot and
attestation source and target it may sign.

- After a whole-network rollback, no node signs before its chain holds what the records name.
  Every node stops with **exit status 77** once the network finalizes below them (`anchor::an_2`).
- Do not restart such nodes in a loop. Restore every node from newer state if any exists; the
  nodes are confirmed at start.
- If no newer state exists, the approvers acknowledge the rollback (`mpc-admin anchor
  acknowledge`, then `mpc-admin sign`; nodes started with `--anchor-acknowledgment`). The nodes
  continue in a new anchor generation under the anchored marks, so nothing signed before can be
  signed again differently (`anchor::an_6`).
- A single node rolled back alone is not stopped: it catches up from its peers (`anchor::an_3`).

**Restarting nodes with the floor.** Restart one node at a time where you can: the other three
keyholders sign, and nothing is missed. When every node restarts at once (an R3 reconfiguration, a
simultaneous upgrade, a power loss), the validators lose the current epoch's attestations whose
slots were still ahead, and a proposal only in the slot or two of the restart. From the next epoch
on, everything signs. A node logs its floor at start (`restart floor`) and each refusal (`not
signing a duty at or below this process's restart floor`). No flag switches the floor off; only a
test hook does.

## 8. Other limits addressed here

- **L-3 (coalescing per node).** Identical requests on one node share one task: an optimization.
  Coordinators on different nodes may each aggregate the same authorized payload. That is correct:
  consensus alone decides what is authorized.
- **L-4 (parked-request fairness).** Requests parked until their authorization is applied are
  capped at 64 per peer and 256 in total (`dkg::parked`), so a flooding peer evicts only its own
  oldest requests. They are released when answered (the authorization applied, or refused as
  conflicting), and expire after 16 applied blocks. A disconnect does not release them; expiry
  does.
- **L-5 (banned participants).** A participant is banned for a request after three invalid
  answers. It gets no more retransmissions for that request, and its later answers are ignored. The
  request state is released when the request ends (`signer::coordinator::collect`).
- **HTTP exposure.** The plain HTTP API binds to `127.0.0.1` only, with no option to change it, and
  has no authentication. The optional mTLS listener (`--https-listen`) serves the same API to
  clients with a certificate from `--client-ca`. The Web3Signer API signs only duties that pass
  slashing protection. The development API, which signs any root it is given, exists only in
  `dev-api` builds and is not for a network.

## 9. Tests

| Scenario | Tests |
| -------- | ----- |
| Readiness rules, parking policy | `readiness::tests`, `dkg::parked::tests` (unit, deterministic) |
| Normal restart | `readiness::r1_normal_restart_becomes_ready` |
| Application rollback, journal intact | `rollback::a1_single_node_rollback`, `rollback::a2_two_node_rollback`, `recovery::lagging_node_restored_from_peer_copy` |
| Full node rollback | `rollback::a1_full_restore_never_signs_conflict` (records whether the node was blocked) |
| Lagging node | `failures::lagging_signer_refuses_until_applied` |
| Corrupted or inconsistent storage | `lifecycle::f4_*`, `lifecycle::r5_missing_consensus_journal_fails_closed`, `lifecycle::r5_share_without_state_fails_closed` |
| Recovery with an offline peer | `readiness::r6_recovery_with_one_offline_peer` |
| L-4, L-5 | `adversarial::e4_e5_parked_overflow_and_expiry`, `adversarial::d4_strike_limit` |
| Readiness tolerance against conflicting authorizations | `lag::one_block_behind_*`, `lag::two_blocks_behind_*`, `lag::three_blocks_behind_*`, `lag::concurrent_conflicting_requests_while_lagging` |
| Durable floor | `rollback::journal_only_rollback_resumes_above_floor`, `crash::a3_*`, `crash::a4_*`, `rollback::a1_full_restore_*` |
| Evidence of damaged copies | `lifecycle::r5_damaged_copy_is_saved_before_opening`; every F4/R5 refusal test checks it through the helper `lifecycle::assert_fails_closed` |
| Slashing history: persistence, fail-closed startup on altered history | `storage::tests::validator::*` (unit) |
| Slashing history across crashes, restarts, a lagging node and a single-node rollback | `eth2::e2e_eth_3_*`, `eth2::e2e_eth_4_*`, `eth2::e2e_eth_5_*`, `eth2::e2e_eth_6_*`, `eth2::e2e_eth_7_*`, `tests/eth_duties.rs`, `storage::tests::validator::a_torn_duty_block_is_applied_again_identically` |
| Chain identity across restarts and recovery | `slashing_history_survives_a_full_restart`, `stale_node_cannot_authorize_another_chain`, `eth2::e2e_eth_8_*`, `storage::tests::validator::altered_history_fails_closed` (activation removed) |
| L-1 | `rollback::a2_whole_network_rollback`, `eth2::e2e_eth_l1_whole_network_rollback_signs_a_double_proposal` (ignored, failing: no floor, no anchor); `floor::floor_1` to `floor_3`; `anchor::an_1` to `an_6` |
