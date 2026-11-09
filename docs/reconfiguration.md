# Replacing a consensus voter (R3)

D, one of the four consensus voters, is permanently lost. R2 ([resharing.md](resharing.md#r2-replacing-a-lost-keyholder)) gave its key share to E, a follower; R3 gives E its vote:

| | Before (epoch 0) | After (epoch 1) |
| --- | --- | --- |
| Consensus voters (quorum 3 of 4) | A, B, C, D (D offline) | A, B, C, E |
| Keyholders of the active generation | A, B, C, E (after R2) | A, B, C, E |
| Validator key, its generation, slashing records | | unchanged |
| Fault tolerance | none: A, B and C must all be up | one voter may fail |

R3 is a maintenance operation, not online reconfiguration: the current committee finalizes one block that ends its epoch, every node stops after that block, and restarted, runs the next epoch. Commonware is used as it is; nothing in it changed.

## Epochs

A consensus epoch is a fixed committee and the heights it finalizes (`src/epochs.rs`).

- **Epoch 0** is the committee given on the command line (`--participants`, nodes `0..participants`).
- **A later epoch** replaces exactly one member: its committee is the previous one with one voter removed and one configured follower (`--followers`) added, the same size and threshold.
- **The boundary.** An epoch starts after the block that ended the previous one (a block carrying a `Reconfigure` command): that block is the new epoch's consensus genesis (`simplex::Floor::Genesis`), and the new epoch's heights start right above it.
- **Records.** Every later epoch is a record in the replicated state, committed in the same atomic write as the block that ended the previous epoch: its number, committee, the member removed and the one added, and the boundary block's height and digest. On startup the records must follow, one by one, from the command line's committee; otherwise the node refuses to start (a wrong `--participants`).
- **One epoch per process.** A node reads its epoch from its state when it opens it, and runs that epoch until it exits. Every committee check (ceremonies, partial-signature requests, the coordinator, the signing API, the p2p primary peers) uses that epoch's committee. A block is always applied by a process running that block's epoch, so the committee is a constant of the process.

What each epoch has of its own, and what marshal checks:

| | Epoch 0 | Epoch `e` ≥ 1 |
| --- | --- | --- |
| Simplex engine | `Epoch::zero()` | `Epoch::new(e)`; votes and certificates name their epoch |
| Floor | genesis block, then the last finalization this node processed | the boundary block (`Genesis`), then this epoch's last processed finalization |
| Journal | `<prefix>-consensus` | `<prefix>-consensus-<e>` (simplex replays a journal without filtering by epoch) |
| p2p channels (votes, certificates, resolver) | 0, 1, 2 | `8 + 3(e − 1)` + 0, 1, 2 |
| Finalizations below the boundary | verified with epoch 0's committee | each height with its own epoch's committee (`Schemes`, `Heights`) |

A node also registers the consensus channels of the epochs before and after its own and drops what arrives on them. A message on an unregistered channel makes commonware's p2p drop the connection, and a vote of another epoch on a node's own channels gets its sender blocked for an hour. Either would cut a lagging node off from the peers it must catch up from.

## The end of an epoch

`Reconfigure { epoch, remove, add }`:

1. **Submitted** with `POST /consensus/reconfigure` (or `mpc-admin replace-node`). Each node checks it against its own epoch before proposing or voting:
   - `epoch` is the next one;
   - `remove` is a member and `add` is not;
   - `add` is a configured follower;
   - it is the only transaction of its block.

   A leader drops an invalid one from its mempool; voters refuse a block carrying one.
2. **Finalized** in a block T by the current committee.
3. **The guard.** No honest node builds or votes for a child of T: `Application::propose` returns nothing on such a parent, and `Application::verify` refuses a block whose parent carries a `Reconfigure` (it reads the parent, which marshal hands to `verify` with the block).
   - The check depends on the parent's bytes only, never on what the node has applied, so voters whose executors lag do not matter.
   - A notarization takes 3 of 4 votes, at least 2 from honest nodes, and each honest notarize vote follows a successful `verify`. So no child of T is ever notarized, and nothing above T can be built.
   - T is the last block finalized in its epoch, the same for every node.
4. **Committed and stopped.** Each node applies T: the next epoch's record is committed with it, the executor applies nothing more, and the process exits with status **75**. Its supervisor restarts it (Docker restart policy, systemd, the test harness); `mpc-admin` never restarts anything.
5. **Restarted** in the new epoch, from T.
   - A voter of it votes and coordinates signing.
   - A node that is no voter (D, should it return) follows it without voting.
   - E's signing API, `403` while it followed, now signs.

Without the guard, the end of the epoch would race the next view: voting runs ahead of block application, so A, B and C would usually finalize a child of T before they had applied T and stopped. A returning D plus two lagging voters could do the same. The epoch-0 chain would go on above the block the new epoch starts from, and a node's archive could hand such a block to its executor in the new epoch. The guard rules this out with no lag parameter.

### Closing an epoch (`--close-epoch-at`)

Commonware finalizes T in its own view when every voter that notarized it also certifies it in time. With D offline, A, B and C must all send a finalize vote. If one of them timed out after notarizing T (it then nullifies the view and never finalizes it), T stays notarized but unfinalized. No later block may build on it either (the guard), so epoch 0 stalls for good. This is safe, not live.

The recovery is to restart every voter of the epoch with `--close-epoch-at <height of T>`:

- Their `Epocher` ends the epoch at that height, and marshal re-proposes the block at it in later views until it is finalized (commonware's epoch-boundary re-proposal).
- The nodes then apply T and exit with status 75 as usual.
- The flag only restricts what a node builds and votes for. A wrong height stalls; it never forks.
- If a block without a `Reconfigure` is finalized at that height (possible only if T's view was also nullified, so T was skipped), each node stops there with status **76** and is restarted without the flag: the same epoch continues.

`mpc-admin resume` reports a last block unfinalized for longer than `--stall` seconds and prints the command. A node refuses to start with a closing height at or below its state's.

### A node left behind

A node that was down when its epoch ended (or comes back with old data, like D) restarts in the old epoch. It cannot learn the end from its own consensus engine, since no peer runs that epoch any more.

- `POST /consensus/sync {"height": T}` (or `mpc-admin resume`, which finds T on a node that switched) asks its peers for T's finalization.
- The finalization is verified with the old committee, and marshal fetches the missing blocks below it.
- The node applies them up to T, exits with status 75, and restarts in the new epoch.

A finalization that does not verify is refused, so the request cannot be abused.

## Procedure

1. Every node runs this version with the same `--participants` and `--followers`. E runs as a follower, has applied the finalized history, and holds a share of every active validator key (R2). Each node has a supervisor that restarts it when it exits.
2. The reconfiguration is a protected operation ([administration.md](administration.md)): the approvers sign it offline.
   ```sh
   mpc-admin --nodes 127.0.0.1:8080,127.0.0.1:8081,127.0.0.1:8082,127.0.0.1:8083,127.0.0.1:8084 replace-node --old 3 --new 4 --output replace.json
   mpc-admin sign --command replace.json --key alice.key --output replace-alice.json   # each approver, offline
   mpc-admin --nodes ... replace-node --command replace-alice.json --command replace-bob.json
   ```
   Both runs check that every answering node runs the same epoch and that the change follows the rules. They warn if:
   - D still answers;
   - E is behind or holds no share of an active key;
   - a node does not answer.

   The first run drafts the reconfiguration (the next epoch, the network's next administrative nonce). The second submits it with its approvals through a voter, follows each node through its stop and restart, and waits until the new epoch finalizes a block.
3. If it does not complete: `mpc-admin resume` (idempotent; it never submits anything).
4. Keep D off, or let it come back as a follower of the new epoch (step 3 brings it there).

Signing pauses from T's finalization until the new epoch's first finalization: the restarts plus a view or two. Requests in flight at the stop get an error. A repeated request returns the same authorization and signature, but Lighthouse does not repeat a failed signing request. In devnet run J (`20261107T082254Z`) the switch took about 5 s and 7 requests failed: selection proofs, a sync committee message and a contribution. No attestation or block request failed ([ethereum-devnet.md](ethereum-devnet.md#approved-deposit-and-pinned-fork-schedule-run-j)). Since the keyholders' restart floor ([slashing-protection.md](slashing-protection.md#the-restart-floor)), a switch also costs the current epoch's attestations whose slots are still ahead, and a proposal in the slot or two of the restart: every node restarts at once, so every keyholder refuses new duties of the slot and epoch it may have signed for before. From the next epoch on everything signs. Devnet run N (`20261109T142310Z`) measured it: the switch in slot 386 (epoch 12) cost both validators their epoch-12 attestations (slots 390 and 403); nothing else the floor refused failed ([ethereum-devnet.md](ethereum-devnet.md#restart-floor-run-n)).

## Signing and slashing protection

- **One authorization history.** Epoch 0 finalizes heights up to T and epoch 1 heights above it; slashing protection is one replicated state applied in height order. A duty cannot be authorized independently in both epochs.
- **Nothing to migrate.** Committed authorizations, slashing records, validator activations and key share generations are untouched. The record of the new epoch is the only new state.
- **Partial-signature requests** are answered only for committee members of the keyholder's own epoch. D is refused by every keyholder in epoch 1. A keyholder still in epoch 0 answers only for authorizations committed in its own state, all at or below T.
- **E coordinates** after its restart, with the generation R2 gave it.

## Security properties and limitations

- **Byzantine model.** At most one faulty voter per committee. A faulty leader that builds on T is refused (R3-8); a faulty D cannot reach a quorum in either epoch.
- **Who may reconfigure.** Only the approvers: a threshold of their offline signatures over the exact change, with the network's next administrative nonce ([administration.md](administration.md)). Every honest voter checks them before voting.
  - A bare `Reconfigure` (as before this version) ends nothing: honest voters refuse its block, and the terminal guard recognizes only an approved one, with approvals that verify on that node.
  - A reconfiguration whose nonce is used or skipped is never voted for, so a stale or replayed one cannot freeze an epoch (test `admin_2`).
  - Only a configured follower can be added, so an unknown key never becomes a voter, even with approvals.
  - Compromised approvers (a threshold of them) can still remove an honest voter (L-22). There is no time lock or governance.
- **Stalled last block** (L-21): needs the closing restart above, by an operator.
- **Restored backups** (L-23): a node restored from a copy taken before the switch replays epoch 0 harmlessly (no epoch-0 quorum is left). But at its restart in epoch 1 it has no epoch-1 journal, although the real node may have voted in epoch 1. The missing-journal check cannot see this, because the node has no epoch-1 history yet. As before, never restore a consensus journal (L-7).
- **Retention.** A node behind by more than the retained history (`--retain-blocks`) cannot fetch the block that ended its epoch, as for any lagging node.
- **Upgrade first.** Every node must run this version before the first reconfiguration (new command, new channels), with the same approver file (`--approvers`). Before one exists, the state is unchanged and an older binary still reads it.

## Tests

| What | Tests |
| --- | --- |
| Epoch rules, records, restore from the command line's committee, heights per epoch, signing only in the current epoch as a member, the block rules | `src/epochs.rs` (`tests/unit/epochs.rs`) |
| The command's encoding (tag 14) | `types::tests::reconfigure_encoding` |
| The record committed with its block and restored; a wrong original committee refused; a finalized invalid reconfiguration, or one with other transactions, stops the node | `storage::tests::a_reconfiguration_commits_the_next_epoch`, `a_finalized_invalid_reconfiguration_stops_the_node`, `a_finalized_reconfiguration_with_company_stops_the_node` |
| Real processes: R3-1 replacement with `mpc-admin`, R3-2/R3-3 E votes and signs without C, same key and history, R3-4 D returns, R3-5 a node left in epoch 0 catches up, R3-6 crashes around the switch, R3-7 refusals, R3-8 a faulty leader past the end, R3-9 closing an epoch | `tests/e2e/reconfigure.rs` |
| A live Lighthouse validator: the switch (8 s from the first stop to epoch 1's first block), A, B, E signing without C, D back and caught up, no duty missed | [ethereum-devnet.md](ethereum-devnet.md#replacing-a-lost-consensus-voter-run-h) (run H) |
