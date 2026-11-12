# Replacing a consensus voter (R3)

D, one of the four consensus voters, is permanently lost. R2
([resharing.md](resharing.md#r2-replacing-a-lost-keyholder)) gave D's key share to E, a
follower. R3 gives E D's vote:

| | Before (epoch 0) | After (epoch 1) |
| --- | --- | --- |
| Consensus voters (quorum 3 of 4) | A, B, C, D (D offline) | A, B, C, E |
| Keyholders of the active generation | A, B, C, E (after R2) | A, B, C, E |
| Validator key, its generation, slashing records | | unchanged |
| Fault tolerance | none: A, B and C must all be up | one voter may fail |

R3 is a maintenance operation, not an online reconfiguration. The current committee finalizes one
block that ends its epoch. Every node stops after that block. Once restarted, it runs the next
epoch. Commonware is used as it is.

Terms: a **voter** is a member of the consensus **committee**. A **follower** is a node outside the
committee (`--followers`): it applies finalized blocks and does not vote. A **keyholder** holds a
share of a validator key's active generation ([resharing.md](resharing.md)). An **approver** signs
protected operations offline ([administration.md](administration.md)).

## Epochs

A consensus epoch is a fixed committee and the heights it finalizes (`src/epochs.rs`).

- **Epoch 0** is the committee given on the command line: `--participants`, nodes
  `0..participants`.
- **A later epoch** replaces exactly one member. Its committee is the previous one with one voter
  removed and one configured follower (`--followers`) added. The size and threshold stay the same.
- **The boundary.** The block that carries the `Reconfigure` command ends its epoch. That block is
  the next epoch's consensus genesis (`simplex::Floor::Genesis`). The next epoch's heights start
  right above it.
- **Records.** Each later epoch is a record in the replicated state: its number, its committee, the
  member removed, the member added, and the boundary block's height and digest. The record is
  committed in the same atomic write as the boundary block. At startup the records must follow one
  by one from the command line's committee. Otherwise the node refuses to start (a wrong
  `--participants`).
- **One epoch per process.** A node reads its epoch from its state at startup and runs that epoch
  until it exits. Every committee check uses that epoch's committee: ceremonies, partial-signature
  requests, the coordinator, the signing API and the p2p primary peers. A block is always applied
  by a process that runs the block's epoch, so the committee is a constant of the process.

What each epoch has of its own, and what marshal checks:

| | Epoch 0 | Epoch `e` ≥ 1 |
| --- | --- | --- |
| Simplex engine | `Epoch::zero()` | `Epoch::new(e)`; votes and certificates name their epoch |
| Floor | the genesis block, then the last finalization this node processed | the boundary block (`Genesis`), then this epoch's last processed finalization |
| Journal | `<prefix>-consensus` | `<prefix>-consensus-<e>` (simplex replays a journal without filtering by epoch) |
| p2p channels (votes, certificates, resolver) | 0, 1, 2 | `8 + 3(e − 1)` + 0, 1, 2 |
| Finalizations below the boundary | verified with epoch 0's committee | each height with its own epoch's committee (`Schemes`, `Heights`) |

A node also registers the consensus channels of the epoch before its own and the epoch after it,
and drops what arrives on them. Commonware's p2p drops the connection on a message from an
unregistered channel, and blocks the sender of another epoch's vote on a node's own channels for an
hour. Either would cut a lagging node off from the peers it must catch up from.

## The end of an epoch

`Reconfigure { epoch, remove, add }` is a protected operation: it needs a threshold of the
approvers' offline signatures and the next administrative nonce ([administration.md](administration.md)).

1. **Submitted** with `POST /consensus/reconfigure` (or `mpc-admin replace-node`). Each node checks
   it against its own epoch before it proposes or votes:
   - `epoch` is the next one;
   - `remove` is a member and `add` is not;
   - `add` is a configured follower;
   - it is the only transaction of its block.

   A leader drops an invalid one from its mempool. Voters refuse a block that carries one.
2. **Finalized** in a block T by the current committee.
3. **The guard.** No honest node builds or votes for a child of T. `Application::propose` returns
   nothing on such a parent. `Application::verify` refuses a block whose parent carries an approved
   `Reconfigure`; it reads the parent, which marshal hands to `verify` with the block.
   - The check depends only on the parent's bytes, never on what the node has applied. So it does
     not matter that some voters' executors lag.
   - A notarization takes 3 of 4 votes, at least 2 of them from honest nodes, and each honest
     notarize vote follows a successful `verify`. So no child of T is ever notarized, and nothing
     above T can be built.
   - T is the last block finalized in its epoch, the same for every node.
4. **Committed and stopped.** Each node applies T and commits the next epoch's record with it. The
   executor applies nothing more, and the process exits with status **75**. Its supervisor restarts
   it (Docker restart policy, systemd, the test harness). `mpc-admin` never restarts anything.
5. **Restarted** in the new epoch, from T.
   - A voter of the new epoch votes and coordinates signing.
   - A node that is not a voter (D, if it returns) follows the epoch without voting.
   - E's signing API answered `403` while E was a follower. It now signs.

Answers of `POST /consensus/reconfigure`: `202` once submitted (every node stops after the block,
so none can answer with the outcome), `400` refused by the rules above, `403` without valid
approvals, `409` the epoch already ended or the nonce is used, `503` the node has no approver set.

Without the guard, the end of the epoch would race the next view. Voting runs ahead of block
application, so A, B and C would usually finalize a child of T before they applied T and stopped.
A returning D and two lagging voters could do the same. The epoch-0 chain would then go on above the
block the new epoch starts from, and a node's archive could hand such a block to its executor in
the new epoch. The guard rules this out with no lag parameter.

### Closing an epoch (`--close-epoch-at`)

Commonware finalizes T in its own view when every voter that notarized T also certifies it in
time. With D offline, A, B and C must all send a finalize vote. If one of them timed out after it
notarized T, it nullifies the view and never finalizes T. T then stays notarized but not
finalized. No later block may build on T either (the guard), so epoch 0 stalls for good. This is
safe, but not live.

To recover, restart every voter of the epoch with `--close-epoch-at <height of T>`:

- Their `Epocher` ends the epoch at that height. Marshal re-proposes the block at that height in
  later views until it is finalized (commonware's epoch-boundary re-proposal).
- The nodes then apply T and exit with status 75 as usual.
- The flag only restricts what a node builds and votes for. A wrong height stalls; it never forks.
- If a block without a `Reconfigure` is finalized at that height (possible only if T's view was
  also nullified, so T was skipped), each node stops there with status **76**. Restart it without
  the flag: the same epoch continues.

`mpc-admin resume` reports a last block that stays unfinalized for longer than `--stall` seconds
(default 30), and prints the restart command. A node refuses to start with a closing height at or
below its state's height. A node with a sealed vault (`--vault gcp-tdx`) refuses the flag
([tee.md](tee.md)).

### A node left behind

A node that was down when its epoch ended (or that comes back with old data, like D) restarts in
the old epoch. Its own consensus engine cannot tell it about the end, since no peer runs that epoch
any more.

- `POST /consensus/sync {"height": T}` asks its peers for T's finalization (`202`). `mpc-admin
  resume` does this; it finds T on a node that switched.
- The node verifies the finalization with the old committee, and marshal fetches the missing blocks
  below it.
- The node applies them up to T, exits with status 75, and restarts in the new epoch.

A finalization that does not verify is refused, so the request cannot be abused.

## Procedure

1. Every node runs with the same `--participants`, `--followers` and `--approvers`. E runs as a
   follower, has applied the finalized history, and holds a share of every active validator key
   (R2). Each node has a supervisor that restarts it when it exits.
2. Draft the reconfiguration, have the approvers sign it offline, and submit it:
   ```sh
   mpc-admin --nodes 127.0.0.1:8080,127.0.0.1:8081,127.0.0.1:8082,127.0.0.1:8083,127.0.0.1:8084 replace-node --old 3 --new 4 --output replace.json
   mpc-admin sign --command replace.json --key approver-1.key --output replace-1.json   # each approver, offline
   mpc-admin --nodes ... replace-node --command replace-1.json --command replace-2.json
   ```
   `--old` and `--new` take a node index (development keys) or a `0x` consensus identity. Both runs
   check that every answering node runs the same epoch, and that the change follows the rules. They
   warn if:
   - D still answers;
   - E is behind, or holds no share of an active key;
   - a node does not answer.

   The first run drafts the reconfiguration for the next epoch and the network's next
   administrative nonce. The second run submits it with its approvals through a voter that stays.
   It follows each node through its stop and restart, and waits until the new epoch finalizes a
   block (`--wait`, 600 s by default).
3. If the switch does not complete, run `mpc-admin resume`. It is idempotent and submits no
   command.
4. Keep D off, or let it come back as a follower of the new epoch (step 3 brings it there).

Signing pauses from T's finalization until the new epoch's first finalization: the restarts plus
a view or two. Requests in flight at the stop get an error. A repeated request returns the same
authorization and signature, but Lighthouse does not repeat a failed signing request.

- **Devnet run J** (`20261107T082254Z`): the switch took about 5 s, and 7 requests failed:
  selection proofs, a sync committee message and a contribution. No attestation or block request
  failed ([ethereum-devnet.md](ethereum-devnet.md#approved-deposit-and-pinned-fork-schedule-run-j)).
- **The keyholders' restart floor** ([slashing-protection.md](slashing-protection.md#the-restart-floor))
  adds a cost. Every node restarts at once, so every keyholder refuses new duties of the slot and
  epoch it may have signed for before its restart. A switch therefore also costs the current
  epoch's attestations whose slots are still ahead, and a proposal in the slot or two of the
  restart. From the next epoch on, everything signs.
- **Devnet run N** (`20261109T142310Z`) measured it: the switch in slot 386 (epoch 12) cost both
  validators their epoch-12 attestations (slots 390 and 403). The floor refused nothing else
  ([ethereum-devnet.md](ethereum-devnet.md#restart-floor-run-n)).

## Signing and slashing protection

- **One authorization history.** Epoch 0 finalizes the heights up to T, and epoch 1 the heights
  above it. Slashing protection is one replicated state, applied in height order. A duty cannot be
  authorized independently in both epochs.
- **Nothing to migrate.** Committed authorizations, slashing records, validator activations and
  share generations stay as they are. The new epoch's record is the only new state.
- **Partial-signature requests** are answered only for committee members of the keyholder's own
  epoch. In epoch 1, every keyholder refuses D. A keyholder still in epoch 0 answers only for
  authorizations committed in its own state, all at or below T.
- **E coordinates** after its restart, with the generation R2 gave it.

## Security properties and limitations

- **Byzantine model.** At most one faulty voter per committee. A faulty leader that builds on T is
  refused (R3-8). A faulty D cannot reach a quorum in either epoch.
- **Who may reconfigure.** Only the approvers: a threshold of their offline signatures over the
  exact change, with the network's next administrative nonce ([administration.md](administration.md)).
  Every honest voter checks them before it votes.
  - A bare `Reconfigure`, without approvals, ends nothing. Honest voters refuse its block, and the
    guard recognizes only an approved one whose approvals verify on that node.
  - A reconfiguration whose nonce is used or skipped is never voted for. So a stale or replayed one
    cannot freeze an epoch (test `admin_2`).
  - Only a configured follower can be added. An unknown key never becomes a voter, even with
    approvals.
  - A threshold of compromised approvers can still remove an honest voter (L-22). There is no time
    lock or governance.
- **Stalled last block** (L-21): an operator must do the closing restart above.
- **Restored backups** (L-23): a node restored from a copy taken before the switch replays epoch 0
  harmlessly, since no epoch-0 quorum is left. But at its restart in epoch 1 it has no epoch-1
  journal, although the real node may have voted in epoch 1. The missing-journal check cannot see
  this, because the node has no epoch-1 history yet. Never restore a consensus journal (L-7).
- **Retention.** A node behind by more than the retained history (`--retain-blocks`) cannot fetch
  the block that ended its epoch, as for any lagging node.
- **Same configuration everywhere.** Every node must run a binary that knows the `Reconfigure`
  command and the epoch channels, with the same approver file (`--approvers`).

## Tests

| What | Tests |
| --- | --- |
| Epoch rules, records, restore from the command line's committee, heights per epoch, signing only in the current epoch as a member, the block rules | `src/epochs.rs` (`tests/unit/epochs.rs`) |
| The command's encoding (tag 14) | `types::tests::reconfigure_encoding` |
| The record committed with its block and restored; a wrong original committee refused; a finalized invalid reconfiguration, or one with other transactions, stops the node | `storage::tests::a_reconfiguration_commits_the_next_epoch`, `a_finalized_invalid_reconfiguration_stops_the_node`, `a_finalized_reconfiguration_with_company_stops_the_node` |
| Real processes: R3-1 replacement with `mpc-admin`; R3-2/R3-3 E votes and signs without C, the same key and history; R3-4 D returns; R3-5 a node left in epoch 0 catches up; R3-6 crashes around the switch; R3-7 refusals; R3-8 a faulty leader past the end; R3-9 closing an epoch | `tests/e2e/reconfigure.rs` |
| A live Lighthouse validator: the switch (8 s from the first stop to epoch 1's first block), A, B, E signing without C, D back and caught up, no duty missed | [ethereum-devnet.md](ethereum-devnet.md#replacing-a-lost-consensus-voter-run-h) (run H) |
