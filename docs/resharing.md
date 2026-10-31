# Resharing: new share generations of a validator key

Two operations produce a new share generation of a validator key, with the same protocol:

- **R1** refreshes the shares within the committee (A, B, C, D deal to A, B, C, D).
- **R2** replaces a permanently lost keyholder (A, B, C deal to A, B, C, E): [below](#r2-replacing-a-lost-keyholder).

R1 rotates the secret shares of an existing validator key inside the fixed 3-of-4 committee:

- The key's four shares are replaced by four new, independently random ones.
- Nobody reconstructs the private key.
- The public key and the Ethereum validator identity stay the same: no new deposit.
- The slashing-protection history, activation and imported floors are untouched.
- The consensus committee is unchanged.

Both DKG keys and imported keys are reshared by the same protocol.

**Prototype.** The node API has no authentication and binds to `127.0.0.1`.

**What R1 does not change.** These limitations are unchanged and unresolved:

| Limitation | Status |
| --- | --- |
| L-1, rollback of every node | A rollback loses the reshare like any other state. |
| L-15, another signer with the original key | Resharing an imported key does not destroy the keystore it came from. |
| L-16, a leader timeout after a node failure | Consensus is unchanged. |
| L-17, poisoning an import before activation | Unchanged. |

Resharing does not revoke a compromised share by itself ([below](#old-shares)). Neither R1 nor R2 changes the consensus committee ([R2](#r2-replacing-a-lost-keyholder)).

## Cryptography

The network uses commonware's Feldman-Desmedt **reshare** mode, the construction of Desmedt97 ("Redistributing secret shares to new access structures"). It is already part of the pinned `commonware-cryptography` 2026.9.0 and runs on the same dealer, player and dealer-log pipeline as the DKG. No cryptography is implemented here.

**The old sharing.** Let `f(x) = s + a₁x + a₂x²` be the sharing of the active generation. Keyholder `j` holds `s_j = f(j)` (evaluation points `x = i + 1`), and its public verification share is `s_j·G₁`.

**Dealing.** Each dealer `j` (a keyholder of the active generation) deals a fresh random polynomial `g_j(x) = s_j + c_{j,1}x + c_{j,2}x²`. It publishes Feldman commitments `C_{j,k} = c_{j,k}·G₁`, with `C_{j,0}` its public share, and sends `g_j(i)` privately to each player `i` over the encrypted DKG p2p channel. Each player checks its value against the commitments and acknowledges it with a signature.

**Binding to the old key.** A dealing whose constant commitment `C_{j,0}` is not exactly dealer `j`'s public share of the previous generation is refused (`MismatchedReshareCommitment`). A dealer therefore cannot change the key, whatever it deals.

**Selection.** A dealer's log (its commitments and every player's acknowledgement, nothing private) goes through consensus. At the end of a block, consensus selects the first valid quorum of logs: a set `S` of at least 3 dealers.

**New shares.** Each player `i` derives its new share `s'_i = Σ_{j∈S} λ_j g_j(i)`, where `λ_j` are the Lagrange coefficients at 0 for `S` over the old evaluation points. The new polynomial is `f'(x) = Σ λ_j g_j(x)`, so `f'(0) = Σ λ_j s_j = f(0) = s`. Its public commitments are `Σ λ_j C_j`, whose constant term is `s·G₁`: the same public key. Commonware asserts this when it completes the round.

**Relation to a zero-constant refresh.** `f'(x) − f(x)` is a polynomial with a zero constant term. It is uniformly random as soon as one selected dealer is honest. So this is the zero-constant refresh `f' = f + Σ r_j`, written as a redistribution. The redistribution form was chosen for three reasons:

- it is implemented, with its checks, in the pinned library, so no new cryptography is written here;
- the new players never need their own old shares, which is what replacing a keyholder (R2) needs;
- the round is bound to the previous generation's public output, which enters its transcript.

**Verification rules**, each applied deterministically:

1. **Player.** A player acknowledges a dealing only if its private value matches the dealer's commitments, the constant commitment is the dealer's previous public share, and it is the dealer's first dealing (a second, different one is not acknowledged).
2. **Log.** A dealer log counts only if:
   - it is signed for this round and session (a replayed log of another round fails);
   - its dealer is one of the round's dealers (keyholders of the generation refreshed);
   - every player acknowledged its dealing: no reveals, as for the DKG, so no share material ever enters a block.
3. **Selection.** Consensus selects the logs (`observe`), checking the acknowledgement signatures and the commitments; invalid logs are dropped.
4. **Share use.** A player uses its new share only after verifying it against the selected logs' interpolated commitments, and persists it before announcing it.

**Security assumptions:**

- At least one selected dealer provides unpredictable randomness. Of the at least 3 selected dealers, at most one is Byzantine.
- Dealings, acknowledgements and logs are authenticated: ed25519 signatures and authenticated p2p.
- Private dealings are confidential: encrypted p2p, persisted only in each node's secret store.
- Invalid dealings are detected: the player checks, the constant-commitment check, and `observe`.
- The private key is never reconstructed: no node computes `Σ λ_j s_j`; each player interpolates only its own share.
- **Share erasure is operational, not cryptographic.** A node erases its retired share from its secret store, writing both of the store's copies. What the file system, a snapshot or a backup kept is out of reach.

### Old shares

A reshare does **not** revoke the old generation.

- **Old shares still sign.** The old shares are still a valid sharing of the same key: any 3 of them still produce valid signatures for it. Refreshing protects against an attacker who collects fewer than 3 shares of one generation, but only if the old shares are really erased.
- **Compromise carries over.** A share compromised before the reshare stays dangerous if 2 other old shares can also be obtained, for example from backups.
- **The original keystore stays.** Resharing an imported key does not touch its original keystore (L-15).
- **No mixing.** Shares of different generations never combine. Each collection verifies every partial signature against one generation's verification shares, and a partial signature from an old share fails against the new ones. Interpolating a mix gives an invalid signature (`a_reshare_keeps_the_key_and_refreshes_every_share`).

## Share generations

A **share generation** of a validator key is the ceremony that holds it: its round, configuration, session, commitments and its keyholders' share indices (the sorted order of its players, `x = i + 1`; the committee for DKG keys and R1, A, B, C, E after R2). The validator's `round` (`slashing::Validator`) names the **active** generation, the only one that signs.

Validator entry and status fields:

| Field | Meaning |
| --- | --- |
| Generation number (`generation` in `GET /validators`) | Activations so far; 0 for the key's first generation. |
| Generation id (`generation_id`) | SHA-256 of a namespace, the key, the round, the session (configuration, round, starting block) and the public sharing; it never repeats. |
| `ceremony_id` | The active generation's ceremony. |

A reshare's state follows from the replicated state; nothing extra is stored:

| State | Condition |
| --- | --- |
| `in_progress` | Dealing; consensus has fewer than 3 valid logs. |
| `awaiting_shares` | Completed; not every keyholder acknowledged its new share. |
| `ready` | Completed; all 4 acknowledged. |
| `active` | The validator's round. |
| `retired` | Completed, and the validator moved to a later round: its shares are erased on every node. |
| `aborted` | Aborted, or not completed within 32 blocks of its start. |

## Lifecycle

```
ACTIVE(g) ── POST /validators/reshare ──> StartResharing ──consensus──> reshare r InProgress
   │  dealers deal their share of g (p2p); players acknowledge; logs through consensus
   │  first valid quorum of logs ──> r Completed: same key, new commitments
   │  each keyholder: derive s'_i, verify, persist, then ShareReady (signed) ──consensus──>
   │  all 4 acknowledged ──> READY(r)
   │  POST /validators/reshare/activate ──> ActivateGeneration ──consensus──> ACTIVE(r)
   │  keyholders erase their share of g after applying that block
   └─ POST /validators/reshare/abort (or 32 blocks without completion) ──> r aborted, g stays
```

| Command | Decided against the committed state | Refused when |
| --- | --- | --- |
| `StartResharing {validator, ceremony, membership}` | The key is an activated validator; no other reshare of it is in progress or awaiting activation; the active generation has a public output (an imported key's registered sharing serves as one). With a membership (R2), [its rules](#membership) | `unknown_validator`, not activated, pending (`409`, one at a time), id taken (`409`), stale or invalid membership; the same id, key and membership again is idempotent |
| `DealerLog` | As for a DKG | Not signed for this round, dealer not one of the round's dealers, reveals, closed |
| `ShareReady {round, session, participant, signature}` | A signed statement by a keyholder that it derived, verified and persisted its new share; counted only once the reshare is completed | Before completion, wrong session, not a participant, bad signature: ignored |
| `ActivateGeneration {validator, round}` | The round is a reshare of this key, completed, refreshing the active generation, with all 4 acknowledged | `not_reshare`, `not_completed`, `aborted`, `stale` (it refreshes a generation that is no longer active), `not_ready`; repeating it is idempotent |
| `AbortResharing {validator, round}` | The round is a reshare of this key that is not, and never was, active | `not_reshare`, `active`; repeating it is idempotent |

A completed reshare cannot be replayed as a new generation. It activates only while the key's active generation is the one it refreshed, and rounds never repeat. Nothing in a reshare touches the slashing records, the activation, or the import state ([slashing-protection.md](slashing-protection.md)).

```bash
curl -s localhost:8080/validators/reshare -H 'content-type: application/json' \
  -d '{"public_key": "0x..", "ceremony_id": "validator-eth-g1"}'
curl -s localhost:8080/validators/reshare/validator-eth-g1     # status, ready_shares, verification_shares
curl -s localhost:8080/validators/reshare/activate -H 'content-type: application/json' \
  -d '{"public_key": "0x..", "ceremony_id": "validator-eth-g1"}'
```

## Activation and signing continuity

A committed activation is one finalized block. Each node applies it at its own time, so the signing path never assumes that all nodes switched together:

- **Requests are generation-bound.** A coordinator reads the validator's active generation from its own committed state and asks for partial signatures under that ceremony. The request id binds the ceremony, and every partial is verified against that generation's verification shares.
- **A keyholder signs a duty only with the generation it has committed as active.** A request for an older generation is refused for good (`stale_generation`). A request for a newer one, not yet applied there, is parked until the node applies the activation, then answered.
- **One retry.** If a collection fails and the validator's active generation changed meanwhile, the coordinator asks once more with the new one.
- **Authorizations are unaffected.** The slashing records belong to the key, so a duty authorized under `g` is signed under `g + 1` if it is retried after the activation.

| Situation | What happens |
| --- | --- |
| Duties while the reshare is prepared | Signed by generation `g` as usual: no pause. |
| A request in flight when the activation is applied | Keyholders that applied it refuse `g` (`stale_generation`); the coordinator retries with `g + 1`. Those that did not yet still sign `g`, and a collection succeeds with whichever 3 answer for one generation. |
| A node lagging behind the activation | Its requests for `g + 1` are parked; it answers once it applies the block. Its coordinator still uses `g` until then, and the others refuse it, so its requests fail or are retried. |
| A node that persisted its new share and crashed before acknowledging | It loads the share on restart and acknowledges then. Activation waits for it (or for an abort). |
| A node restarting right after the activation | It reads the active generation from its committed state, erases the retired share, and signs with `g + 1`. |
| Coordinator retries across the boundary | The same authorization; the request names the generation; never mixed. |
| A node that has not observed the activation | It still signs `g` for coordinators that ask `g`. It never signs `g + 1` before applying the activation. |

The node does not pause signing explicitly. On the devnet, the imported key signed with its old generation while the new one was prepared and with the new one from its next duty; no duty was missed and no request failed ([ethereum-devnet.md](ethereum-devnet.md#resharing-run-f)).

## Crash recovery

The persistence order makes every step restartable:

1. The dealer seed is persisted before anything is sent, so a restart deals the same dealing again rather than a conflicting one.
2. Every received dealing is persisted before it is acknowledged (`Player::resume`).
3. The new share is derived, verified and persisted (synced) before the `ShareReady` acknowledgement is submitted.
4. Acknowledgements and the activation are consensus commands, applied atomically with the validator's round.
5. A keyholder learns about an activation only after the block is durable.

On restart, a node:

- rebuilds each validator's active generation from its committed state;
- resumes a reshare in progress (same seed, persisted dealings);
- loads or derives its new share, and acknowledges it if consensus does not have the acknowledgement yet;
- erases the shares of retired generations.

It never treats a retired generation as a missing share (it stays ready), and never signs with a generation that is not active in its state.

| Crash point (`test-hooks`) | Tested by |
| --- | --- |
| Before dealing (`reshare-before-dealing`) | `e2e_rsh_crash_before_dealing` |
| After the dealer randomness is persisted (`reshare-after-seed`) | `e2e_rsh_crash_after_seed`, E2E-RSH-2 |
| After sending its dealings (`reshare-after-dealings-sent`) | `e2e_rsh_crash_after_dealings_sent` |
| After the first dealing received (`reshare-after-first-dealing`) | `e2e_rsh_crash_after_first_dealing` |
| After all dealings received (`reshare-after-all-dealings`) | `e2e_rsh_crash_after_all_dealings` |
| After persisting the new share (`reshare-after-share-stored`) | `e2e_rsh_crash_after_share_stored`, E2E-RSH-4 |
| After the acknowledgement (`reshare-after-ready`) | `e2e_rsh_crash_after_ready` |
| Right before applying the activation (`before-apply-activation`) | `e2e_rsh_crash_before_activation`, E2E-RSH-3 |
| Right after applying it (`after-apply-activation`) | `e2e_rsh_crash_after_activation`, E2E-RSH-3 |
| At its first partial signature with the new generation (`new-generation-partial`) | `e2e_rsh_crash_at_first_new_partial` |

In each case the node restarts, the reshare completes and activates, and every node signs with the new generation. A conflicting duty stays refused, and an old duty repeated gives the same signature.

A reshare that cannot complete is aborted explicitly or fails at its deadline. The active generation and its shares are never touched before an activation.

## Storage

**Replicated state.**
- A reshare is a ceremony entry (value tag 11): its DKG fields plus the key, the generation it refreshes, that generation's public output, the acknowledged shares and its dealers. Tag 10, R1's encoding without dealers (they were the previous generation's keyholders), is still read and never written.
- `StartResharing` keeps R1's encoding (command tag 10) without a membership; with one it is tag 13. An R1 history replays unchanged.
- An activation rewrites only the validator entry's `round`.
- Slashing records, the activation and the import state are not written.
- The startup checks accept a validator whose ceremony is an active, retired or pending generation of its key, and an imported key's import state at its original round. They still refuse inconsistent states.

**Secret store.**
- The new share is stored under the new round, written once.
- The retired round's seed, dealings and share are erased with two writes (`Secrets::erase`), and the same happens for an aborted reshare.

Older binaries cannot read a state with reshares (an unknown value tag): they refuse to start, and nothing is misread. `PROTOCOL_VERSION` is unchanged; mixed-version clusters are unsupported: an R1 binary cannot decode a block with an R2 start.

## Liveness and Byzantine behavior

**Every player and every selected dealer is needed.** A dealing counts only if every player acknowledged it (no reveals), and activation waits for every new share to be acknowledged. With one of them offline, a reshare cannot complete: it is aborted or fails at its deadline, and the active generation keeps signing. For R1 that means all four nodes; for R2, A, B, C (dealers and players) and E.

**R1 does not restore fault tolerance after losing a node.** It needs that node. R2 does without it, and restores the redundancy of the key's shares, not of consensus ([below](#what-r2-restores-and-what-it-does-not)).

| Behavior | Effect | Test |
| --- | --- | --- |
| An invalid or malformed dealing | Refused by players and never acknowledged; with that dealer's dealing missing, the other dealers' logs still complete the round if every player acknowledged them | `a_dealing_that_would_change_the_key_is_refused`, E2E-RSH-4 |
| Conflicting dealings from one dealer | Only the first is acknowledged; no log can collect acknowledgements for two commitments | `a_conflicting_dealing_is_not_acknowledged` |
| A dealer that deals nothing | The other 3 suffice | `three_dealers_suffice` |
| A dealing or log for another validator, generation or round | Not signed for this round's session, or its constant commitment mismatches: refused | `reshare_rules_and_replays` |
| A replayed log | Refused: wrong session, or closed | `reshare_rules_and_replays` |
| A player that never acknowledges | The reshare cannot complete: aborted, the active generation stays | E2E-RSH-4 |
| A keyholder acknowledging readiness without a share | Consensus checks the signature and cannot see a share, so a false acknowledgement counts. The generation then activates with 3 working new shares, which sign. Availability is reduced (as by a Byzantine node that refuses to sign); safety is not | E2E-RSH-4 |
| A node restarting with stale generation metadata | Its committed state is authoritative: it reads the active generation from it and refuses older ones | E2E-RSH-3, crash tests |
| Repeated or concurrent starts and activations | Idempotent (same id and key), or refused (another pending reshare, a stale or completed one) | `a_reshared_key_keeps_its_history_and_activates_only_when_ready` |
| A signing request during the activation | Bound to one generation; refused or parked, retried once | E2E-RSH-3, `e2e_rsh_crash_at_first_new_partial` |

## R2: replacing a lost keyholder

D, one of the four nodes, is permanently lost. E replaces it as a keyholder; the consensus committee is deliberately not reconfigured:

| | Before | After |
| --- | --- | --- |
| Consensus voters (committee, quorum 3 of 4) | A, B, C, D | A, B, C, D, unchanged (D offline) |
| Keyholders of the active generation (threshold 3 of 4) | A, B, C, D | A, B, C, E |
| Validator public key | `K` | `K`, the same bytes |
| Slashing history, activation, imported floors | | unchanged |

D stays offline throughout. A, B and C deal their shares of the active generation; A, B, C and E receive fresh shares of the new one. E then signs where C's or D's share would: A, B and E produce valid signatures without C.

### What R2 restores and what it does not

- **Restored: the key's redundancy.** Before R2, only A, B and C hold usable shares: losing one more of them loses the key. After R2, four keyholders hold shares of the new generation, and any three sign.
- **Not restored: consensus availability.** The committee is still A, B, C, D, and finalization needs 3 of its 4 votes. With D offline, **every one of A, B and C must be up**: losing another voter stops finalization, so no duty is authorized and nothing is signed until it is back. E does not vote and cannot replace a voter. Replacing D in consensus is R3, a reconfiguration of the committee by consensus epochs ([reconfiguration.md](reconfiguration.md)).
- **Not restored: latency.** D is still a leader every fourth view, and each of its turns costs the leader timeout (2 s, L-16) before the next leader proposes. Duties whose authorization falls in such a view wait about 2 s longer, as they did since D was lost.

### Consensus voters and MPC keyholders

The two roles are separate:

- **Voters** are the committee (`--participants`, nodes `0..participants`). They vote, lead, and run signing coordinators (the Web3Signer API).
- **Keyholders** are the players of a key's active generation. They answer partial-signature requests for duties committed in their own replicated state. A keyholder need not be a voter.
- **Coordinators** are committee members: a keyholder answers signing requests only from committee members (`dkg::actor`), and a follower runs no coordinator. Whether it signs is decided, as for every keyholder, by the duty's committed authorization and its active generation, never by who asks.

### Follower nodes

E runs the same binary as a **follower**: a node outside the committee, started with `--followers 1` (node `participants + j`). Every node of the network uses the same `--participants` and `--followers`. Verified against the pinned commonware 2026.9.0 sources:

| Need | How (commonware) |
| --- | --- |
| Connectivity without joining the committee | p2p `lookup` tracks the committee as **primary** peers and followers as **secondary** peers (`AddressableTrackedPeers`). Secondary peers are accepted when they dial in and receive `Recipients::All` traffic on their connections; nobody dials them. E dials the voters. |
| Every channel registered | A message on an unregistered channel makes `lookup` drop the connection, so E runs the full engine and registers every channel. |
| Finalized blocks, verified against A, B, C, D | E's simplex engine uses `ed25519::Scheme::verifier(committee)`: it verifies votes and certificates but cannot sign. `sign` returns nothing without a key, simplex skips voting when `me()` is `None`, and the round-robin leaders are committee members only. Voters broadcast votes and certificates with `Recipients::All`, so E receives them. |
| Blocks and backfill | Blocks are broadcast to all peers (`Recipients::All`) and cached from primary peers. Resolvers fetch from primary peers only and serve any connected peer, so E backfills from A, B, C. |
| Applying blocks | Marshal (with the verifier scheme) delivers finalized blocks to E's executor, which applies them to E's own replicated state: the same state machine as the voters'. |
| Restart | E's journals and archives recover as a voter's do; it resumes above its durable finalized floor and catches up by backfill. |
| Submitting transactions | E gossips its transactions (`ShareReady`) to the voters' mempools. It never proposes, so it gossips each one again every 4 applied blocks until a block contains it. |

E's HTTP API serves status, readiness (`consensus.voting: false`), ceremonies and validators, but no signing: the Web3Signer and development signing endpoints answer `403`.

**Bootstrap.** Blocks carry no state root, so E builds its state by applying the finalized history from genesis, fetched from the voters. That works while the voters still keep the whole history (`--retain-blocks`, 100 000 blocks by default). Beyond it, E's state and marshal partitions are restored from a stopped healthy node's copy, as for a node behind the retained history ([recovery.md](recovery.md)). E's secret store is its own and is never copied: E has no share of anything before the replacement.

### Membership

`POST /validators/reshare` with an explicit membership:

```json
{
  "public_key": "0x<validator key>",
  "ceremony_id": "validator-eth-r2",
  "from_round": 0,
  "dealers": ["0x<A>", "0x<B>", "0x<C>"],
  "players": ["0x<A>", "0x<B>", "0x<C>", "0x<E>"]
}
```

The identities are consensus identities (`GET /identity` of each node). Consensus checks the membership deterministically, from committed state only:

| Rule | Refusal |
| --- | --- |
| `from_round` is the key's active generation (a delayed command never applies to a later one) | `stale` (`409`) |
| Every dealer is a keyholder of that generation | `dealer_not_keyholder` (`400`) |
| At least that generation's threshold of dealers (3) | `too_few_dealers` (`400`) |
| Exactly as many players as the committee has members (4), each once; the threshold stays the committee's (3) | `player_count` (`400`); a repeated or malformed identity is refused by the API |
| The same id again: the same key, generation, dealers and players | otherwise `conflict` (`409`) |

Players need not be committee members, and consensus membership is never derived from them. The cryptography is commonware's, unchanged: `Info::new(previous, dealers = {A, B, C}, players = {A, B, C, E})` requires dealers among the previous players and at least its quorum; the round needs `max(quorum(dealers), quorum(previous)) = 3` valid logs, so all three dealers must deal; the new polynomial has degree `quorum(players) − 1 = 2`; the public key is asserted unchanged. The round's dealers and players enter its transcript, so its dealings, acknowledgements and logs cannot be replayed into another round. D is neither a dealer nor a player: commonware refuses its dealing, and players refuse its messages.

### Local approval of new keyholders

The admin API is unauthenticated (a prototype limitation). Without a further check, one request could hand a key's shares to identities an attacker controls. Each dealer therefore deals to **new** keyholders only if its operator approved that exact recipient set for that key, in a local file (`--approved-reshares <file>`):

```text
# <validator public key> <identity>,<identity>,<identity>,<identity>
0xb84e...10ef 0x5925...428c,0x478b...5266,0xedd0...7033,0x1c0c...f880
```

- The file is read when the node joins the ceremony, before its dealer seed is created: an approval must be in place before the reshare starts (or the node restarted).
- Without a matching line, the node deals nothing: no seed, no commitment, no private dealing. It still verifies and acknowledges dealings as a player (that reveals nothing of its own share). A malformed file approves nothing.
- R1 (players are the generation's keyholders) needs no approval.
- The approval is local configuration, not replicated state: consensus accepts any well-formed membership, and nodes may disagree about approvals without diverging. An unapproved reshare stays `in_progress` without a single dealer log and is aborted (or fails at its deadline).

A reshare completes only with at least the threshold of dealers (3), so a recipient set that fewer than three operators approved never receives a usable sharing. Each approving dealer does give each recipient one evaluation of its dealing polynomial, so approve only identities you operate. This is a prototype safeguard, not an authorization system: there are no operator signatures, no governance and no authenticated admin API.

### Lifecycle and activation

The R1 lifecycle, unchanged: `ACTIVE(g)` → `StartResharing` (with membership) → dealing by A, B, C to A, B, C, E → completed → each new keyholder derives, verifies and persists its share, then submits `ShareReady` → `READY` once all four acknowledged → `ActivateGeneration` → `ACTIVE(g + 1)`.

- E takes part as a player only (it holds no share of `g`). It receives the dealings over the DKG channel, verifies them, persists them before acknowledging, derives and persists its share, then gossips its acknowledgement.
- D's acknowledgement does not count: it is not a player of `g + 1`.
- Activation requires the completed reshare, all four new keyholders' acknowledgements and the committed command; an aborted or stale reshare never activates, and a generation is never partly activated.
- After activation, A, B, C and E serve `g + 1`. Requests naming `g` are refused for good (`stale_generation`), in-flight ones retried once, as in R1. A, B and C erase their shares of `g`. D's copy of its old share stays on D (see the limitations).

### Signing routing

The coordinator already sends partial-signature requests to the active generation's players (`ceremony.config.participants` of the active generation) and verifies each partial against that generation's verification shares: after the replacement it asks A, B, C and E, with E's index in the new generation. A committee member that is not a keyholder of the active generation (D, were it back) would coordinate with three of the four keyholders' partials; no test exercises it, since the coordinators here are A, B and C. The rest is unchanged: the validator, the signing root, the committed authorization, the active generation and slashing protection are checked by every keyholder against its own state; E signs only duties its own executor applied, and parks requests it has not applied yet (by about 0.1 s, its follower lag).

### Persistence and recovery

- A node needs a share of a generation only if it is one of its players. E has none of `g`; D has none of `g + 1`; neither is reported as a missing share.
- The R1 order holds for E: received dealings persisted before acknowledged, the share persisted before `ShareReady`, the activation applied atomically, the keyholder told after the block is durable.
- E restarted before receiving its share, after persisting it, after its acknowledgement, and while applying the activation: in each case it resumes, the replacement completes and activates, and E signs (`tests/e2e/replace.rs`, `r2_e2e_restart_e_*`). E restarted after the activation loads its share and signs (R2-E2E-3).

### Replacement procedure

1. All nodes run with `--participants 4 --followers 1`, voters with `--approved-reshares <file>` (a rolling restart if they were not: each restart pauses finalization while D is offline).
2. Start E (node 4). Wait until `GET /ready` on E is `200` (it applied the finalized history) and `GET /validators` on E lists the key.
3. On A, B and C, append the approval line for the key and A, B, C, E (identities from `GET /identity`).
4. `POST /validators/reshare` with the membership above, on a voter. Wait until `GET /validators/reshare/<id>` is `ready` on A, B, C and E.
5. `POST /validators/reshare/activate` on a voter. Wait until `GET /validators` on every keyholder shows the new `ceremony_id`.
6. Keep D off. Never restart it with its old data: its old share is useless only as long as the old shares of A, B and C are really erased.

### Security properties and limitations

- The public key and the slashing history are unchanged; no new deposit.
- The new generation's shares are fresh: D's old share does not combine with them, and a partial signature from any old share fails against the new verification shares.
- **Resharing does not revoke copied shares.** D's old share (lost or stolen with D), and any backup of an old share of A, B or C, remain shares of `g`. Three shares of `g` still sign as the key. R2 protects against an attacker who holds D's share only if the old shares of A, B and C are erased and no backups of them exist (erasure is operational, L-15).
- **Consensus: no fault tolerance left while D is offline.** See [above](#what-r2-restores-and-what-it-does-not).
- **Unauthenticated admin API.** Anyone with access to a node's loopback API can start or abort reshares; the local approval only limits who receives shares.
- **The approval is a prototype safeguard**, local and unauthenticated, not an authorization system (no operator signatures or governance).
- **Follower bootstrap needs the retained history** or a restored state copy, whose correctness E cannot check (no state root).
- L-1, L-15, L-16, L-17 and every other documented limitation are unchanged ([audit.md](audit.md)).

### Tests

| What | Tests |
| --- | --- |
| A follower joins without voting, applies the same state, restarts and catches up, submits a transaction (its first gossip dropped), cannot vote, propose or count toward a quorum | `tests/e2e/follower.rs`, FOL-1 to FOL-5 |
| R2-CRYPTO-1 to 5 and 8 over 8 seeds: dealers A, B, C, players A, B, C, E; all three dealers required; D neither a dealer nor a player; the key byte for byte unchanged; any 3 new shares sign, 2 cannot, A, B, E without C; old and new partials never combine | `dkg::ceremony::tests::reshare::replace::replacing_a_lost_keyholder_keeps_the_key` |
| Membership rules: dealers outside the generation, too few dealers, wrong player counts, a stale generation, idempotent and conflicting starts; D's log and an R1 log refused; the codec, R1's encoding still read | `replace::replacement_membership_rules`, `types::tests::reshare_start_encodings` |
| R2-CRYPTO-6: a dealing of another share, a value meant for another player, a DKG dealing: refused by E | `replace::invalid_replacement_dealings_are_refused` |
| R2-CRYPTO-7: no approval, no dealing (the file's rules) | `dkg::approval::tests::*`, R2-E2E-4 |
| The lifecycle through consensus: D's acknowledgement ignored, E's required, the same history and refusals after activation, a stale start, a restart | `storage::tests::validator::reshare::a_replaced_keyholder_holds_the_new_generation_through_consensus` |
| Real processes: R2-E2E-1 (loss of D, replacement, the same key), R2-E2E-2 (A, B, E sign with C's partials off; A and B alone cannot), R2-E2E-3 (E restarts), R2-E2E-4 (invalid, stale, unapproved, replayed), R2-E2E-5 (aborted replacement, the old generation with A, B, C), R2-E2E-6 (slashing protection of a DKG key and an imported key's floors), E restarted at four points | `tests/e2e/replace.rs` |
| A live Lighthouse validator: D lost, E joins, the key reshared to A, B, C, E, E's share signing with C's switched off | [ethereum-devnet.md](ethereum-devnet.md#replacing-a-lost-keyholder-run-g) |

## Performance

Measured on the devnet (run F, [ethereum-devnet.md](ethereum-devnet.md#resharing-run-f)), with
4 nodes on one host and 4 s slots:

| | DKG key | Imported key |
| --- | --- | --- |
| Ceremony: start to every new share acknowledged | 1.5 s | 1.7 s |
| Ready to activation decided | 0.2 s | 0.2 s |
| Activation to every node signing with the new generation | 0.1 s | under 0.1 s |
| Consensus transactions | 10: start, 4 dealer logs, 4 acknowledgements, activation | 10 |
| Lighthouse requests failed, coordinator retries | 0, 0 | 0, 0 |

Per reshare, the p2p messages are by design: 12 private dealings (each of 4 dealers to 3 others)
and 12 acknowledgements, plus retransmissions until acknowledged. No permanent round is added to
signing: a duty still takes one consensus decision (or none for a repeat) and one partial-signature
collection. The only change is a generation lookup, and a single retry when the generation changes
during a request.

End-to-end latency through the proxy was unchanged: p50 / p95 279 / 524 ms before and
282 / 520 ms after (n ≈ 1 300 each). With one keyholder offline after the reshare, signing
continued with 3 keyholders. The only slow requests were the leader-timeout delays of L-16 right
after the node stopped, unrelated to resharing.

### R2 on the devnet (run G)

Measured with a live Lighthouse validator ([ethereum-devnet.md](ethereum-devnet.md#replacing-a-lost-keyholder-run-g)), 4 voters and the follower on one host, 4 s slots:

| | |
| --- | --- |
| E catching up from genesis (1 475 blocks) | 15.6 s |
| Ceremony: start to every new share acknowledged | 1.7 s |
| Ready to activation decided | 0.2 s |
| Activation to every keyholder switched | under 0.1 s |
| Consensus transactions | 9: start, 3 dealer logs, 4 acknowledgements, activation |
| End-to-end latency p50 / p95 | 220 / 392 ms with A, B, C, D; 284 / 402 ms with D lost; 233 / 513 ms after the replacement; 268 / 579 ms with A, B, E (C's partials off) |
| Lighthouse requests failed or retried | 0 |
| Missed attestations or proposals | none (epochs 11 to 22; 16 of 16 proposals canonical) |
| With C's partials off | all 17 signatures combined A's, B's and E's shares |

E's partial adds no round: a keyholder answers once it applied the duty's block, and E applies it about 0.1 s after the voters (E2E logs). D's leader turns still cost the leader timeout when a duty falls in one (none did in run G).

## Tests

| What | Tests |
| --- | --- |
| Over 12 seeds and two successive reshares: the key unchanged; every share and verification share changed; new commitments verify the new shares; any 3 new shares sign as the key, 2 cannot; an old share does not verify against, or combine with, the new ones; generation ids differ | `dkg::ceremony::tests::reshare::a_reshare_keeps_the_key_and_refreshes_every_share` |
| Dealings that would change the key; conflicting dealings; 3 dealers suffice; start rules, replays, acknowledgements, aborts, the codec; an imported key | `dkg::ceremony::tests::reshare::*` |
| The lifecycle through consensus: one at a time, activation only when completed and every share acknowledged, the same history and refusals before and after (double proposal, double vote, both surround directions), aborts, a restart with retired, active, aborted and in-progress generations | `storage::tests::validator::reshare::a_reshared_key_keeps_its_history_and_activates_only_when_ready` |
| An imported key: floors, chain and import state kept, imports still refused | `storage::tests::validator::reshare::an_imported_key_reshares_and_keeps_its_floors` |
| Real processes: E2E-RSH-1 (refresh and activation, the same key and signatures, other shares, history, one keyholder offline), RSH-2 (failure before activation, resume, abort), RSH-3 (crashes around activation), RSH-4 (invalid participants), RSH-5 (an imported key, still signing as the original key), and 10 crash points | `tests/e2e/reshare.rs` |
| A live Lighthouse validator reshared on the devnet | [ethereum-devnet.md](ethereum-devnet.md#resharing-run-f) |
