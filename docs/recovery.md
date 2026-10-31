# Recovery and readiness

What a node checks when it starts, what it claims about itself while it runs, which recovery
procedures are supported, and what cannot be detected. Every claim names the mechanism that
enforces it. Passing tests are evidence, not proof (tests are listed in the last section).

## 1. What a node can know about itself

| Condition | Known? | How |
| --------- | ------ | --- |
| Local storage opened | Yes | `Store::init`, `Secrets::init` and marshal's archives open, or the node exits |
| State consistent with marshal's progress | Yes, at startup | marshal returns its durable processed height (`Floor`) from `init`; compared before any actor starts |
| Slashing history internally consistent and matching the ceremonies | Yes, at startup | `Store::verify`: per-validator record counts, known validators, keys equal to their ceremony's group key ([slashing-protection.md](slashing-protection.md)) |
| Slashing history complete with respect to the network | **No** | a history consistently older (a rollback) looks like a node that missed blocks; it replays them, and a rollback of every node is undetected (§7) |
| Key shares consistent with the state | Yes, at startup | every stored share must belong to a completed ceremony of the state; loaded shares are verified against the ceremony's public polynomial |
| All locally known finalized blocks applied | Yes | marshal reports its finalized tip (`Update::Tip`); compared with the executor's height |
| Caught up with the network | **No** | a node only knows what its peers told it. Nothing claims this |
| Able to sign an applied authorization | Yes | the DKG actor answers only after loading its shares, and signs only a `Committed` authorization |
| Its consensus journal is complete | **No** (partly) | a missing journal is detected; an older journal is not (an old but internally consistent snapshot looks like a node that was offline) |

## 2. Startup checks (fail closed)

`engine::open` and `Opened::start` open the durable stores first and check them against each
other before any actor runs (`engine::check_recovery`, `engine::check_boundary`). On failure the node logs `refusing to start` with the
reason and exits with status 1. Nothing is reset or deleted, no file is removed and no key share is
regenerated.

Evidence: opening a commonware metadata store truncates a copy that fails its integrity check
(it recovers from the other copy), and that happens before the checks can run. So, before
opening anything, the node reads every copy of the state, the secret store, marshal's progress and
the archives' metadata, and saves each copy that fails the same check (an 8-byte version, the
entries, a big-endian CRC32 of both) to the `registry-diagnostics` partition, synced
(`engine::preserve_damaged_copies`). A saved copy is named by its content: written once, never
rewritten (a partial one, from a crash while saving, is written again), never read by the node.
The working stores are then left to commonware's normal recovery; nothing writes old bytes back
into them. A start interrupted after saving leaves the working copy untouched; repeated starts
never duplicate the evidence (`lifecycle::r5_damaged_copy_is_saved_before_opening`). Opening the
stores otherwise changes them as any start does: archive metadata rewritten, torn journal tails
repaired.

| Check | Refuses when | Why |
| ----- | ------------ | --- |
| Replicated state opens | both copies corrupted, unknown format, legacy format 1 | the state cannot be trusted or read |
| State not behind marshal | state height < marshal's processed height | marshal resumes after the last block it saw acknowledged, and the executor acknowledges only after the state commit: the state can be ahead by one block (crash before the acknowledgement, replayed and skipped), never behind. Behind means applied blocks were lost; running would skip them silently (BUG-2) |
| Share has its ceremony | a stored share's round has no completed ceremony in the state | a share is stored only after its ceremony's completion is durably applied; otherwise the state (and its authorization history) was lost or rolled back while the share stayed |
| Slashing history consistent | a record of an unknown validator, a validator whose record count differs from its stored records, a validator ceremony without its validator (or the reverse), a key that is not its ceremony's, records without an activation (or a chain pinned by the previous version), attestations that surround each other, an entry of an unknown kind | the history of a validator key must be complete before it signs again: a lost proposal or attestation would let a conflicting one through ([slashing-protection.md](slashing-protection.md#startup-checks-fail-closed)) |
| Consensus journal present | the current epoch's journal partition is empty while the node has finalized history in that epoch (state or marshal height above the epoch's start) | the node may have voted in views it no longer remembers; voting again could equivocate. Overridable by the operator only (`--allow-missing-consensus-journal`, see §6). A node at the very start of an epoch has no journal of it yet ([reconfiguration.md](reconfiguration.md)) |
| Consensus epochs follow from the committee | the state's epoch records do not follow, one by one, from `--participants` | the command line names another original committee than the one this state's epochs come from |
| Epoch boundary matches the history | in an epoch after the first: the stored block at the epoch's start differs from the recorded one, or a finalization of an earlier epoch is stored above it | the previous epoch would have finalized past its last block; marshal could hand such a block to the executor as this epoch's |
| Closing height reachable | `--close-epoch-at` at or below the state's height | the node would never reach it, so never stop |

The executor keeps the run-time check of BUG-2: a finalized block delivered at a height other than
the next one stops the node.

## 3. Consensus restart: the durable floor

Consensus starts from `simplex::Floor::Finalized`, the finalization of the last block marshal
durably processed (before, it always started from genesis). The voter skips every journal entry at
or below that view and never votes there again. Marshal's processed height only moves forward,
which the floor requires, and genesis, used before, is the lowest possible floor: a normal restart
behaves as before, and a node whose journal was lost or replaced by an older one cannot repeat a
vote at or below its last processed finalization.

What the floor guarantees, and why:

- It is a durable finalization: marshal's processed height is synced only after the executor
  acknowledged the block, which it does after the state commit; the finalization certificate of a
  processed block is stored (and synced) before the block is delivered. A crash after the state
  commit and before the acknowledgement leaves the floor one block below the state
  (`crash::a4_*` asserts it), never above it.
- It is valid for this committee: simplex verifies the certificate against the configured scheme
  (participants and namespace) when the engine is built, and refuses to start otherwise.
- It comes after the startup checks: consensus is the last component started.
- The voter enters `floor_view + 1` and never moves to a lower view; journal entries at or below
  the floor are skipped. It cannot vote at or below the floor
  (`rollback::journal_only_rollback_resumes_above_floor` shows a node with an old journal resuming
  at `floor_view + 1`, not at the old journal's view).

What the floor does not cover: votes cast after that finalization (the views in flight when the
node stopped: a journal older than those votes forgets them, and the node may vote again
differently, an equivocation peers may detect), and anything at all when marshal's progress was
rolled back together with the journal (a whole-directory restore: the floor is rolled back too,
`rollback::a1_full_restore_*` asserts it). Those are §6's unsupported cases. The floor detects no
rollback; it only bounds what a node with a lost or older journal can repeat.

`/status` reports the floor (`readiness.consensus.floor_height`, `floor_view`) and the consensus
epoch (`readiness.consensus.epoch`). In an epoch after the first, the floor is the epoch's genesis
(the block that ended the previous epoch) until the node processed a finalization of its own
epoch: a finalization of another epoch is never a floor (simplex refuses one).

A node stops on its own only at the end of its consensus epoch, after committing the block that
ended it: status **75** (restart it: it runs the next epoch) or, closed with `--close-epoch-at`
without a reconfiguration, **76** (restart it without the flag). Any other exit is a failure, as
before ([reconfiguration.md](reconfiguration.md)).

## 4. Readiness is not a safety mechanism

Readiness only decides whether this node accepts new work. No signature depends on it:

1. **A partial signature needs a durably applied authorization.** `dkg::actor::partial` signs only
   a `storage::Committed` value for exactly the requested payload; only the store creates those,
   from state read from disk or just synced. A node behind the network has fewer authorizations,
   never different ones: it refuses (`not_authorized`, the request is parked), it never signs a
   payload it has not applied.
2. **Authorizations are decided by consensus, first finalized wins.** `state::apply` is
   deterministic: the first finalized command for a `(ceremony, nonce)` creates the authorization;
   a later command with another payload is `Rejected` and changes nothing, on every node, because
   every node applies the same finalized sequence.
3. **A coordinator signs only what the state machine returned.** It collects partials only after
   finding the authorization applied locally, or after its own command was applied with outcome
   `Accepted` (or `AlreadyAccepted`, same payload); `Rejected` ends the request with `409`.
4. **A group signature needs three partials**, from three distinct keyholders that each checked
   (1); a byzantine keyholder contributes at most one.

So a stale node may *submit* a conflicting command (its local read finds nothing), but the command
can only be finalized after the authorization it conflicts with, and is rejected there. The node
learns the outcome when it applies that block: its client gets `409 REJECTED`, or
`AUTHORIZATION_TIMEOUT` if it does not catch up in time (retrying then gets `409`). Local absence
of an authorization is never treated as proof that a nonce is unused.

The readiness tolerance (two blocks) is a liveness choice only. With a tolerance of zero, a node
would refuse new authorizations at random right after every block; with any tolerance, (1)-(4)
hold. `lag::*` exercises one, two and three blocks of lag with a byzantine signer in place of
node 1 and conflicting requests racing through a current and a lagging node: B is submitted and
rejected at one and two blocks, refused before submission at three, and no partial or group
signature for the losing payload ever exists.

## 5. Readiness

`readiness::Readiness::evaluate` is a pure function of what the node observes:

- `applied`: height of the last block applied to the replicated state;
- `known_finalized`: the highest finalized height marshal knows of (blocks may still be missing);
- `last_applied`: when this process last applied a new block (`None` if none since it started);
- the number of completed ceremonies without a usable share.

| Reason | Condition | State |
| ------ | --------- | ----- |
| `no_block_since_start` | `last_applied` is `None` | `syncing` |
| `local_backlog` | `known_finalized > applied + 2` (marshal reports a finalized tip a moment before delivering its block, and may finalize the next one meanwhile: up to two blocks are normally on their way) | `syncing` |
| `no_recent_finalization` | `now - last_applied > STALL` (10 s, five leader timeouts; an idle network finalizes a block every ~1.6 s) | `degraded` |
| `share_unavailable` | a completed ceremony has no usable share here | `degraded` |

`ready` means no reason applies. `syncing` wins over `degraded`.

Predicates:

```text
can_sign_authorized       = true for every running node
                            (storage passed §2, shares loaded: the actor answered)
                            each partial is still decided by dkg::actor::partial:
                            share present and verified, (ceremony, nonce) Committed here,
                            payload equal to the committed one
can_submit_authorization  = no reason among no_block_since_start, local_backlog,
                            no_recent_finalization
can_participate_in_consensus
                          = decided at startup (§2, §3); never changed at run time
```

Where they apply:

- `POST /sign` for an authorization already applied here goes straight to signature collection,
  whatever the readiness: the authorization is finalized and durable, and the keyholder of every
  participant checks it again.
- `POST /sign` that needs a new authorization is refused with `503 NOT_READY` and the blocking
  `reasons` unless `can_submit_authorization` holds (`signer::coordinator::sign`). A node that does
  not follow consensus would submit a command whose outcome it cannot see.
- `GET /ready` returns the readiness with `200` when `ready`, `503` otherwise; `GET /status`
  includes it.

What readiness does not claim:

- not that the node has the network's latest block: `known_finalized_height` is what this node
  knows;
- `ready` is evidence at most `STALL` old: a node cut off from every peer reports
  `no_recent_finalization` only once `STALL` has passed;
- after a restart, the first new block proves that consensus progressed with this node, not that
  nothing older is missing; missing blocks are backfilled by marshal and appear as
  `local_backlog` once their finalization is known.

## 6. Recovery scenarios

### Supported

| Scenario | Behavior | Enforced by |
| -------- | -------- | ----------- |
| Normal restart | Replays its journal above the floor, re-delivers unacknowledged blocks, `syncing` until it applies a new block, then `ready` | §2, §3, executor at-least-once handling |
| Restart with intact durable state after a crash (any point) | Same; a block applied but not acknowledged is skipped on re-delivery; a torn unacknowledged write falls back to the older state copy and the block is re-applied | executor height check, metadata copies |
| Application state restored from an older backup, **current consensus journal kept** | Marshal must be restored with it (otherwise `MissingBlocks` stops the node). The node replays the finalized blocks it lacks, refuses to sign what it has not applied (`not_authorized`, parked), never signs a conflicting payload (its authorizations are a prefix of the finalized history), and becomes `ready` after replay | §2, keyholder gate, consensus ordering |
| Node behind the retained history, restored from a healthy node's partitions (its own `registry-secrets` and `registry-consensus` kept) | As above, from the healthy node's (stopped) copy | README, Storage; `recovery::lagging_node_restored_from_peer_copy` |
| A follower (a non-voting keyholder, R2) restarted, or joining for the first time | It catches up like a voter, by backfill from the committee; its secret store is its own. Joining after the voters pruned their history needs a copy of a healthy node's state and marshal partitions (as in the row above), which it cannot verify (no state root; audit L-20) | `follower::fol_3_*`, `replace::r2_e2e_3_*`, `replace::r2_e2e_restart_e_*` |
| Consensus journal lost | Refuses to start. With `--allow-missing-consensus-journal`, after the other nodes have finalized more than 10 views (what peers keep) beyond anything this node can have voted in: it starts above its floor, and votes it forgot are in views its peers no longer consider | §2, §3 |

### Not supported (no automatic recovery)

| Scenario | Why | What happens |
| -------- | --- | ------------ |
| Restoring an old consensus journal | the node forgets votes cast after the backup; votes above its floor can be repeated differently (an equivocation, a Byzantine fault) | not detectable when the rest of the directory is consistent with it; peers that see an equivocation block the node at the P2P layer for an hour (audit L-7) |
| Replacing a node's directory with another node's | another node's key share (partials rejected) and votes (equivocation for that identity) | not detected by this node |
| Restoring several nodes from stale snapshots | two or more nodes without their votes exceed `f = 1` | safety no longer guaranteed by consensus |
| Whole-network rollback | §7 | conflicting signatures (L-1) |

### Scenario summary

| Scenario | Safe to sign? | Safe to vote? | Recovery behavior |
| -------- | ------------- | ------------- | ----------------- |
| Normal restart | Yes (keyholder gate over committed state; §2) | Yes (intact journal replayed above the floor; §3) | `syncing` until a new block is applied, then `ready` |
| Application rollback, journal intact | Yes (stale prefix: refuses unapplied, never conflicting; §2 requires state and marshal together) | Yes (own votes known from the journal) | Replays missing blocks, then `ready` |
| Full node rollback | Its partials: yes, same gate over a prefix of the finalized history. Group signature for a conflicting payload: no, while the other three keep the history | **Not guaranteed**: forgotten votes after the snapshot can be repeated differently; tolerated as one Byzantine node | Not detected locally; converges or is blocked by peers; `ready` only while it applies blocks, `degraded` within `STALL` if cut off |
| Rolled back to before a validator's activation (consensus journal kept) | Yes: the key signs nothing for it until the activation is replayed, then only for the activated chain, which cannot be changed through it | Yes | Replays the activation from the finalized chain (E2E-ETH-8) |
| One offline peer | Yes | Yes | The restarting node is `ready` once consensus finalizes again with its votes; with a second node away, every node reports `no_recent_finalization`, new authorizations get `503 NOT_READY`, applied ones fail in bounded time |
| Two nodes restarted together | Yes | Yes | Nothing is finalized while both are down. Once they are back, if they missed the certificate of the view the other two entered, consensus waits for the other two's next nullify retry (`timeout_retry`, 3 s), which carries it: 6.3 to 9.7 s measured after the restart in that case (audit L-14). Validator duties due meanwhile can be missed. Restart one node at a time, and wait for it to be `ready` |
| Corrupted storage | The node does not run when the damage is detected (§2); a torn copy not yet acknowledged is replayed | Does not run | Exit status 1, storage left as is |
| Whole-network rollback | **No** (L-1) | **No** | Undetectable, unsupported |

## 7. Whole-network rollback (L-1)

If every node is restored to storage from before `(ceremony, nonce)` was authorized for payload A,
the network authorizes and signs a conflicting payload B for the same nonce:
`rollback::a2_whole_network_rollback` reproduces it and fails; it stays `#[ignore]` so the ordinary
suite stays green, and must not be changed to pass.

Why it cannot be detected here:

- Everything that records the authorization (replicated state, block archives, consensus journals,
  marshal progress) was rolled back on every node. What remains is a consistent older history,
  identical to a network that never saw the authorization.
- Consensus safety assumes at most `f = 1` faulty node; a rollback of every node is a fault of all
  of them.
- A local monotonic counter (an epoch, a high-water mark, a "last signed" record) stored in the same
  directory is rolled back with it. Stored in another directory of the same machine, it is rolled
  back by the same operator action or backup system. It helps only if the rollback cannot reach it.

What would detect it, all outside this task:

- monotonic state that the rollback cannot reach: a hardware monotonic counter or TEE sealing, an
  external append-only log or anchor (another chain, a transparency log) consulted before signing;
- or peers that are not rolled back: more nodes than the faulty threshold kept independent.

The same holds for Ethereum slashing protection, which is now part of the replicated state
([slashing-protection.md](slashing-protection.md)). It protects against every fault above
except this one. An Ethereum validator is slashed for two conflicting signatures, whatever this
system believes, and a rollback of every node forgets what was signed:
`eth2::e2e_eth_l1_whole_network_rollback_signs_a_double_proposal` reproduces a double proposal
(ignored, failing). Protection against it needs slashing history outside the nodes' rollback
domain. An anchor is designed in [slashing-protection.md](slashing-protection.md#proposal-an-independent-durable-anchor),
not implemented. No local counter was added in its place.

## 8. Other limits addressed here

- **L-3 (coalescing per node).** Identical requests on one node share one task: an optimization.
  Coordinators on different nodes may each aggregate the same authorized payload; that is
  correct, consensus alone decides what is authorized.
- **L-4 (parked-request fairness).** Requests parked until their authorization is applied are
  capped at 64 per peer and 256 in total (`dkg::parked`): a flooding peer evicts only its own
  oldest requests. They are released when answered (authorization applied, or refused as
  conflicting) and expire after 16 applied blocks. A disconnect does not release them; expiry does.
- **L-5 (banned participants).** A participant banned for a request (three invalid answers) is no
  longer sent retransmissions for it, and its later answers are ignored; the request state is
  released when the request ends (`signer::coordinator::collect`).
- **HTTP exposure.** The API binds to `127.0.0.1` only, with no option to change it. It has no
  authentication. The Web3Signer API signs only duties that pass slashing protection. The
  development API, which signs any root it is given, exists only in `dev-api` builds. Neither is
  for a network.

## 9. Tests

| Scenario | Tests |
| -------- | ----- |
| Readiness rules, parking policy | `readiness::tests`, `dkg::parked::tests` (unit, deterministic) |
| R1 normal restart | `readiness::r1_normal_restart_becomes_ready` |
| R2 application rollback, journal intact | `rollback::a1_single_node_rollback`, `rollback::a2_two_node_rollback`, `recovery::lagging_node_restored_from_peer_copy` |
| R3 full node rollback | `rollback::a1_full_restore_never_signs_conflict` (records whether the node was blocked) |
| R4 lagging node | `failures::lagging_signer_refuses_until_applied` |
| R5 corrupted or inconsistent storage | `lifecycle::f4_*`, `lifecycle::r5_missing_consensus_journal_fails_closed`, `lifecycle::r5_share_without_state_fails_closed` |
| R6 recovery with an offline peer | `readiness::r6_recovery_with_one_offline_peer` |
| L-4, L-5 | `adversarial::e4_e5_parked_overflow_and_expiry`, `adversarial::d4_strike_limit` |
| Readiness tolerance vs. conflicting authorizations | `lag::one_block_behind_*`, `lag::two_blocks_behind_*`, `lag::three_blocks_behind_*`, `lag::concurrent_conflicting_requests_while_lagging` |
| Durable floor | `rollback::journal_only_rollback_resumes_above_floor`, `crash::a3_*`, `crash::a4_*`, `rollback::a1_full_restore_*` |
| Evidence of damaged copies | `lifecycle::r5_damaged_copy_is_saved_before_opening`, `lifecycle::assert_fails_closed` (every R5/F4 refusal) |
| Slashing history: persistence, fail-closed startup on altered history | `storage::tests::validator::*` (unit) |
| Slashing history across crashes, restarts, a lagging node and a single-node rollback | `eth2::e2e_eth_3_*`, `eth2::e2e_eth_4_*`, `eth2::e2e_eth_5_*`, `eth2::e2e_eth_6_*`, `eth2::e2e_eth_7_*`, `tests/eth_duties.rs`, `storage::tests::validator::a_torn_duty_block_is_applied_again_identically` |
| Chain identity across restarts and recovery | `slashing_history_survives_a_full_restart`, `stale_node_cannot_authorize_another_chain`, `eth2::e2e_eth_8_*`, `storage::tests::validator::altered_history_fails_closed` (activation removed) |
| L-1 | `rollback::a2_whole_network_rollback`, `eth2::e2e_eth_l1_whole_network_rollback_signs_a_double_proposal` (ignored, fail) |
