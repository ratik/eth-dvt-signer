# Resharing: new share generations of a validator key

A reshare gives a validator key a new **share generation**: new secret shares of the same key.
Two operations use the same protocol:

| Operation | Dealers | Players |
| --- | --- | --- |
| **R1**: refresh the shares within the committee | A, B, C, D | A, B, C, D |
| **R2**: replace a permanently lost keyholder ([below](#r2-replacing-a-lost-keyholder)) | A, B, C | A, B, C, E |

A reshare:

- replaces the key's four shares with four new, independently random ones;
- never reconstructs the private key;
- keeps the public key, so the Ethereum validator identity stays the same and needs no new deposit;
- keeps the slashing-protection history, the activation and the imported floors;
- does not change the consensus committee. R3 does that ([reconfiguration.md](reconfiguration.md)).

DKG keys and imported keys are reshared by the same protocol.

| Term | Meaning |
| --- | --- |
| node | One process of the network, with a consensus identity (`GET /identity`). |
| committee, voter | The nodes that vote in consensus (in epoch 0, `--participants`). Each one is a voter. |
| follower | A node outside the committee (`--followers`). It applies finalized blocks and does not vote. |
| ceremony | One DKG, import or reshare of a key, numbered by its `round`. |
| generation | The ceremony whose shares sign for a key. The **active** generation is the only one that signs. |
| keyholder | A node that holds a share of a key's active generation. |
| dealer | A keyholder of the active generation that deals its share in a reshare. |
| player | A node that receives a share of the new generation. |
| approver | The holder of an offline key that signs protected operations ([administration.md](administration.md)). |

Resharing leaves these limitations as they are ([audit.md](audit.md)):

| Limitation | Effect of a reshare |
| --- | --- |
| L-1, rollback of every node | A rollback loses the reshare like any other state. |
| L-15, another signer with the original key | Resharing an imported key does not destroy the keystore it came from. |
| L-16, a leader timeout after a node failure | None: consensus is unchanged. |
| L-17, poisoning an import before activation | None: a reshare does not touch the import state. |

A reshare does not revoke a compromised share ([Old shares](#old-shares)).

## Cryptography

The network uses the **reshare** mode of commonware's Feldman-Desmedt DKG, the construction of
Desmedt97 ("Redistributing secret shares to new access structures"). It is part of the pinned
`commonware-cryptography` 2026.10.0 and runs on the same dealer, player and dealer-log pipeline as
the DKG. This repository implements no cryptography of its own.

**The old sharing.** Let `f(x) = s + a₁x + a₂x²` be the sharing of the active generation.
Keyholder `j` holds `s_j = f(j)` (evaluation points `x = i + 1`). Its public verification share is
`s_j·G₁`.

**Dealing.** Each dealer `j` deals a fresh random polynomial `g_j(x) = s_j + c_{j,1}x + c_{j,2}x²`.
It publishes the Feldman commitments `C_{j,k} = c_{j,k}·G₁`, where `C_{j,0}` is its public share.
It sends `g_j(i)` privately to each player `i` over the encrypted DKG p2p channel. Each player
checks its value against the commitments and signs an acknowledgement.

**Binding to the old key.** A dealing whose constant commitment `C_{j,0}` is not dealer `j`'s
public share of the previous generation is refused (`MismatchedReshareCommitment`). So a dealer
cannot change the key, whatever it deals.

**Selection.** A dealer's log goes through consensus. It holds the commitments and every player's
acknowledgement, nothing private. At the end of a block, consensus selects the first valid quorum
of logs: a set `S` of at least 3 dealers.

**New shares.** Each player `i` derives its new share `s'_i = Σ_{j∈S} λ_j g_j(i)`, where `λ_j` are
the Lagrange coefficients at 0 for `S` over the old evaluation points. The new polynomial is
`f'(x) = Σ λ_j g_j(x)`, so `f'(0) = Σ λ_j s_j = f(0) = s`. Its public commitments are `Σ λ_j C_j`.
Their constant term is `s·G₁`: the same public key. Commonware asserts this when it completes the
round.

**Relation to a zero-constant refresh.** `f'(x) − f(x)` has a zero constant term. It is uniformly
random if one selected dealer is honest. So the reshare is the zero-constant refresh
`f' = f + Σ r_j`, written as a redistribution. The redistribution form was chosen because:

- the pinned library implements it, with its checks, so no new cryptography is written here;
- the players never need their own old shares, which R2 needs (E has none);
- the round is bound to the previous generation's public output, which enters its transcript.

**Verification rules.** Every node applies them deterministically:

1. **Player.** A player acknowledges a dealing only if:
   - its private value matches the dealer's commitments;
   - the constant commitment is the dealer's previous public share;
   - it is the dealer's first dealing. A second, different dealing gets no acknowledgement.
2. **Log.** A dealer log counts only if:
   - it is signed for this round and session (a log replayed from another round fails);
   - its dealer is one of the round's dealers (keyholders of the generation refreshed);
   - every player acknowledged its dealing. There are no reveals, as for the DKG, so no share
     material ever enters a block.
3. **Selection.** Consensus selects the logs (`observe`). It checks the acknowledgement signatures
   and the commitments, and drops invalid logs.
4. **Share use.** A player verifies its new share against the interpolated commitments of the
   selected logs. It persists the share before it announces it, and uses it only after that.

**Security assumptions:**

- At least one selected dealer gives unpredictable randomness. Of the at least 3 selected dealers,
  at most one is Byzantine.
- Dealings, acknowledgements and logs are authenticated: ed25519 signatures and authenticated p2p.
- Private dealings stay confidential: encrypted p2p, and persisted only in each node's secret store.
- Invalid dealings are detected: by the player's checks, the constant-commitment check and
  `observe`.
- No node reconstructs the private key: no node computes `Σ λ_j s_j`, and each player interpolates
  only its own share.
- **Share erasure is operational, not cryptographic.** A node erases its retired share from its
  secret store and writes both copies of the store. A copy that the file system, a snapshot or a
  backup kept is out of reach.

### Old shares

A reshare does **not** revoke the old generation:

- **Old shares still sign.** The old shares stay a valid sharing of the same key: any 3 of them
  still sign for it. A refresh protects against an attacker who collects fewer than 3 shares of
  one generation, but only if the old shares are really erased.
- **A compromise carries over.** A share stolen before the reshare stays dangerous if the attacker
  can also get 2 other old shares, for example from backups.
- **The original keystore stays.** Resharing an imported key does not touch its original keystore
  (L-15).
- **Generations never mix.** Each collection verifies every partial signature against the
  verification shares of one generation. A partial signature from an old share fails against the
  new ones. Interpolating a mix gives an invalid signature
  (`a_reshare_keeps_the_key_and_refreshes_every_share`).

## Share generations

A share generation of a validator key is the ceremony that holds its shares: its round,
configuration, session, commitments and the share indices of its keyholders. A keyholder's share
index is its position in the sorted set of the ceremony's players (evaluation point `x = i + 1`).
The players are the committee for DKG keys and R1, and A, B, C, E after R2. The validator's
`round` (`slashing::Validator`) names the active generation.

| Field | Where | Meaning |
| --- | --- | --- |
| `generation` | `GET /validators` | Generations activated since the key's first; 0 for a key never reshared. |
| `ceremony_id` | `GET /validators` | The active generation's ceremony. |
| `generation_id` | `GET /dkg/status/{ceremony_id}`, `GET /validators/reshare/{ceremony_id}` | SHA-256 of a namespace, the key, the round, the session (configuration, round, starting block) and the public sharing. It never repeats. |

The state of a reshare (`status` in `GET /validators/reshare/{ceremony_id}`) follows from the
replicated state. Nothing extra is stored.

| State | Condition |
| --- | --- |
| `in_progress` | Dealing: consensus has fewer than 3 valid logs. |
| `awaiting_shares` | Completed; not every player acknowledged its new share. |
| `ready` | Completed; all 4 players acknowledged. |
| `active` | The validator's round. |
| `retired` | Completed, and the validator moved to a later round. Every keyholder erases its share. |
| `aborted` | Aborted, or not completed within 32 blocks of its start. |

## Lifecycle

```
ACTIVE(g) ── POST /validators/reshare ──> StartResharing ──consensus──> reshare r in_progress
   │  dealers deal their share of g (p2p); players acknowledge; logs through consensus
   │  first valid quorum of logs ──> r completed: same key, new commitments
   │  each player: derive s'_i, verify, persist, then ShareReady (signed) ──consensus──>
   │  all 4 acknowledged ──> r ready
   │  POST /validators/reshare/activate ──> ActivateGeneration ──consensus──> ACTIVE(r)
   │  keyholders erase their share of g after applying that block
   └─ POST /validators/reshare/abort (or 32 blocks without completion) ──> r aborted, g stays
```

Consensus decides each command against the committed state:

| Command | Applied when | Refused or ignored when |
| --- | --- | --- |
| `StartResharing {validator, ceremony, membership}` | The key is an activated validator. No other reshare of it is in progress or awaiting activation. The active generation has a public output (an imported key's registered sharing serves as one). With a membership (R2), [its rules](#membership) hold. | See the HTTP answers below. The same id, key and membership again is idempotent. |
| `DealerLog` | As for a DKG. | Not signed for this round, dealer not one of the round's dealers, a second log of the same dealer, reveals, round closed. |
| `ShareReady {round, session, participant, signature}` | A keyholder's signed statement that it derived, verified and persisted its new share. It counts only once the reshare is completed. | Ignored: before completion, wrong session, not a player, bad signature. |
| `ActivateGeneration {validator, round}` | The round is a completed reshare of this key, it refreshes the active generation, and all 4 players acknowledged. | `not_reshare`, `not_completed`, `aborted`, `stale` (it refreshes a generation that is no longer active), `not_ready`. Repeating it is idempotent. |
| `AbortResharing {validator, round}` | The round is a reshare of this key that is not, and never was, active. | `not_reshare`, `active`. Repeating it is idempotent. |

HTTP answers of `POST /validators/reshare`:

| Status | When |
| --- | --- |
| `200` | Started, or already started with the same id, key and membership. The body is the reshare's state. |
| `400` | A malformed request. `from_round`, `dealers` and `players` not given together. An identity listed twice. An authorization on an R1 request. A membership refused (`dealer_not_keyholder`, `too_few_dealers`, `player_count`). An unsupported configuration, for example 4 ceremonies already in progress. |
| `403` | An R2 request without valid approvals. |
| `404` | An unknown validator key. |
| `409` | The key is not activated. Another reshare of the key is in progress or awaiting activation. The ceremony id is taken. `from_round` is not the active generation. The active generation has no public output. The administrative nonce is used. |
| `503` | No approver set on the node (R2), or the node cannot submit. |
| `504` | The start was not finalized in time (it may still be). |

`POST /validators/reshare/activate` and `/abort` answer `200` with the reshare's state, `404` if
the id is not a reshare of this key, and `409` with the `refusal` for a refused command.

```bash
curl -s localhost:8080/validators/reshare -H 'content-type: application/json' \
  -d '{"public_key": "0x..", "ceremony_id": "validator-eth-g1"}'
curl -s localhost:8080/validators/reshare/validator-eth-g1     # status, ready_shares, verification_shares
curl -s localhost:8080/validators/reshare/activate -H 'content-type: application/json' \
  -d '{"public_key": "0x..", "ceremony_id": "validator-eth-g1"}'
```

A completed reshare cannot be replayed as a new generation. It activates only while the key's
active generation is the one it refreshed, and rounds never repeat.

## Activation and signing continuity

A committed activation is one finalized block. Each node applies it at its own time, so the
signing path never assumes that all nodes switched together:

- **Requests are bound to a generation.** A coordinator reads the validator's active generation
  from its own committed state and asks for partial signatures under that ceremony. The request id
  binds the ceremony. Every partial is verified against that generation's verification shares.
- **A keyholder signs a duty only with the generation it committed as active.** It refuses a
  request for an older generation for good (`stale_generation`). It parks a request for a newer
  generation it has not applied yet, and answers it once it applies the activation.
- **One retry.** If a collection fails and the validator's active generation changed meanwhile,
  the coordinator asks once more with the new generation.
- **Authorizations do not change.** The slashing records belong to the key. A duty authorized
  under `g` is signed under `g + 1` if it is retried after the activation.

| Situation | What happens |
| --- | --- |
| Duties while the reshare is prepared | Generation `g` signs them as usual: no pause. |
| A request in flight when the activation is applied | Keyholders that applied it refuse `g` (`stale_generation`), and the coordinator retries with `g + 1`. Keyholders that did not apply it yet still sign `g`. A collection succeeds with any 3 answers for one generation. |
| A node lagging behind the activation | It parks requests for `g + 1` and answers once it applies the block. Its coordinator still uses `g` until then; the others refuse it, so its requests fail or are retried. |
| A node that persisted its new share and crashed before it acknowledged | It loads the share on restart and acknowledges then. Activation waits for it (or for an abort). |
| A node restarting right after the activation | It reads the active generation from its committed state, erases the retired share, and signs with `g + 1`. |
| Coordinator retries across the boundary | The same authorization. The request names the generation, so generations never mix. |
| A node that has not observed the activation | It still signs `g` for coordinators that ask for `g`. It never signs `g + 1` before it applies the activation. |

The node does not pause signing on purpose. On the devnet, the imported key signed with its old
generation while the new one was prepared, and with the new one from its next duty. No duty was
missed and no request failed ([ethereum-devnet.md](ethereum-devnet.md#resharing-run-f)).

## Crash recovery

The persistence order makes every step restartable:

1. The dealer persists its seed before it sends anything. A restart deals the same dealing again,
   not a conflicting one.
2. A player persists every dealing it receives before it acknowledges it (`Player::resume`).
3. A player derives, verifies and persists (syncs) its new share before it submits the `ShareReady`
   acknowledgement.
4. Acknowledgements and the activation are consensus commands, applied atomically with the
   validator's round.
5. A keyholder learns about an activation only after the block is durable.

On restart, a node:

- rebuilds each validator's active generation from its committed state;
- resumes a reshare in progress (same seed, persisted dealings);
- loads or derives its new share, and acknowledges it if consensus does not have the
  acknowledgement yet;
- erases the shares of retired generations.

It never reports a retired generation as a missing share (it stays ready). It never signs with a
generation that is not active in its state.

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

In each case the node restarts, the reshare completes and activates, and every node signs with the
new generation. A conflicting duty stays refused, and an old duty repeated gives the same
signature.

A reshare that cannot complete is aborted, or fails at its deadline. Nothing touches the active
generation or its shares before an activation.

## Storage

**Replicated state.**

- A reshare is a ceremony entry (value tag 11): its DKG fields, the key, the generation it
  refreshes, that generation's public output, the acknowledged shares and its dealers. Tag 10 is
  R1's older encoding without dealers (they were the previous generation's keyholders). It is still
  read and never written.
- `StartResharing` without a membership uses command tag 10, R1's encoding. With a membership it
  uses tag 13. An R1 history replays unchanged.
- An activation rewrites only the validator entry's `round`.
- A reshare writes no slashing record, activation or import state
  ([slashing-protection.md](slashing-protection.md)).
- The startup checks accept a validator whose ceremony is an active, retired or pending generation
  of its key, and an imported key's import state at its original round. They still refuse
  inconsistent states.

**Secret store.**

- The new share is stored under the new round, written once.
- The seed, dealings and share of a retired round are erased with two writes (`Secrets::erase`).
  The same happens for an aborted reshare.

A binary that does not know a value or command tag refuses to start, or cannot decode the block:
nothing is misread. `PROTOCOL_VERSION` stays 1. Mixed-version clusters are not supported: for
example, an R1-only binary cannot decode a block with an R2 start.

## Liveness and Byzantine behavior

**Every player and every selected dealer is needed.** A dealing counts only if every player
acknowledged it (no reveals). Activation waits until every new share is acknowledged. With one of
them offline, a reshare cannot complete: it is aborted or fails at its deadline, and the active
generation keeps signing. R1 needs all four nodes. R2 needs A, B, C (dealers and players) and E.

**R1 does not restore fault tolerance after the loss of a node.** It needs that node. R2 does not
need it, and restores the redundancy of the key's shares, not of consensus
([below](#what-r2-restores-and-what-it-does-not)).

| Behavior | Effect | Test |
| --- | --- | --- |
| An invalid or malformed dealing | Players refuse it and never acknowledge it. The other dealers' logs still complete the round if every player acknowledged them | `a_dealing_that_would_change_the_key_is_refused`, E2E-RSH-4 |
| Conflicting dealings from one dealer | Only the first is acknowledged; no log can collect acknowledgements for two commitments | `a_conflicting_dealing_is_not_acknowledged` |
| A dealer that deals nothing | The other 3 suffice | `three_dealers_suffice` |
| A dealing or log for another validator, generation or round | Refused: not signed for this round's session, or its constant commitment does not match | `reshare_rules_and_replays` |
| A replayed log | Refused: wrong session, or round closed | `reshare_rules_and_replays` |
| A player that never acknowledges | The reshare cannot complete: it is aborted, and the active generation stays | E2E-RSH-4 |
| A keyholder that acknowledges without a share | Consensus checks the signature and cannot see a share, so a false acknowledgement counts. The generation then activates with 3 working new shares, which sign. Availability drops (as with a Byzantine node that refuses to sign); safety does not | E2E-RSH-4 |
| A node restarting with stale generation metadata | Its committed state decides: it reads the active generation from it and refuses older ones | E2E-RSH-3, crash tests |
| Repeated or concurrent starts and activations | Idempotent (same id and key), or refused (another pending reshare, a stale or completed one) | `a_reshared_key_keeps_its_history_and_activates_only_when_ready` |
| A signing request during the activation | Bound to one generation; refused or parked, retried once | E2E-RSH-3, `e2e_rsh_crash_at_first_new_partial` |

## R2: replacing a lost keyholder

D, one of the four nodes, is permanently lost. E replaces it as a keyholder. The consensus
committee is deliberately not reconfigured:

| | Before | After |
| --- | --- | --- |
| Consensus voters (committee, quorum 3 of 4) | A, B, C, D | A, B, C, D, unchanged (D offline) |
| Keyholders of the active generation (threshold 3 of 4) | A, B, C, D | A, B, C, E |
| Validator public key | `K` | `K`, the same bytes |
| Slashing history, activation, imported floors | | unchanged |

D stays offline throughout. A, B and C deal their shares of the active generation. A, B, C and E
receive fresh shares of the new one. E then signs where C's or D's share would: A, B and E produce
valid signatures without C.

### What R2 restores and what it does not

- **Restored: the key's redundancy.** Before R2, only A, B and C hold usable shares: one more loss
  loses the key. After R2, four keyholders hold shares of the new generation, and any three sign.
- **Not restored: consensus availability.** The committee is still A, B, C, D, and finalization
  needs 3 of its 4 votes. With D offline, **every one of A, B and C must be up**. If one more voter
  is lost, finalization stops: no duty is authorized and nothing is signed until it is back. E does
  not vote and cannot replace a voter. R3 replaces D in consensus with a reconfiguration of the
  committee by consensus epochs ([reconfiguration.md](reconfiguration.md)).
- **Not restored: latency.** D is still the leader of every fourth view. Each of its turns costs
  the leader timeout (2 s, L-16) before the next leader proposes. A duty whose authorization falls
  in such a view waits about 2 s longer, as it has since D was lost.

### Consensus voters and MPC keyholders

The two roles are separate:

- **Voters** are the committee (`--participants`, nodes `0..participants`). They vote, lead, and
  run the signing coordinators (the Web3Signer API).
- **Keyholders** are the players of a key's active generation. They answer partial-signature
  requests for duties committed in their own replicated state. A keyholder need not be a voter.
- **Coordinators** are committee members. A keyholder answers signing requests only from
  committee members (`dkg::actor`), and a follower runs no coordinator. As for every keyholder,
  the duty's committed authorization and the active generation decide whether a follower signs,
  never who asks.

### Follower nodes

E runs the same binary as a **follower**, started with `--followers 1` (node `participants + j`).
Every node of the network uses the same `--participants` and `--followers`. The table below was
checked against the pinned commonware 2026.9.0 sources:

| Need | How (commonware) |
| --- | --- |
| Connectivity without joining the committee | p2p `lookup` tracks the committee as **primary** peers and followers as **secondary** peers (`AddressableTrackedPeers`). Secondary peers are accepted when they dial in, and receive `Recipients::All` traffic on their connections; nobody dials them. E dials the voters. |
| Every channel registered | A message on an unregistered channel makes `lookup` drop the connection. So E runs the full engine and registers every channel. |
| Finalized blocks, verified against A, B, C, D | E's simplex engine uses `ed25519::Scheme::verifier(committee)`: it verifies votes and certificates but cannot sign. `sign` returns nothing without a key, simplex skips voting when `me()` is `None`, and the round-robin leaders are committee members only. Voters broadcast votes and certificates with `Recipients::All`, so E receives them. |
| Blocks and backfill | Blocks are broadcast to all peers (`Recipients::All`) and cached from primary peers. Resolvers fetch from primary peers only and serve any connected peer, so E backfills from A, B, C. |
| Applying blocks | Marshal (with the verifier scheme) delivers finalized blocks to E's executor. It applies them to E's own replicated state, with the same state machine as the voters'. |
| Restart | E's journals and archives recover as a voter's do. It resumes above its durable finalized floor and catches up by backfill. |
| Submitting transactions | E gossips its transactions (`ShareReady`) to the voters' mempools. It never proposes, so it gossips each one again every 4 applied blocks until a block contains it. |

E's HTTP API serves status, readiness (`consensus.voting: false`), ceremonies and validators, but
no signing: the Web3Signer and development signing endpoints answer `403`.

**Bootstrap.** Blocks carry no state root. So E builds its state by applying the finalized history
from genesis, fetched from the voters. This works while the voters still keep the whole history
(`--retain-blocks`, 100 000 blocks by default). Beyond it, restore E's state and marshal partitions
from a stopped healthy node's copy, as for a node behind the retained history
([recovery.md](recovery.md)). E's secret store is its own and is never copied: E has no share of
anything before the replacement.

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

The identities are consensus identities (`GET /identity` of each node). Consensus checks the
membership deterministically, from committed state only:

| Rule | Refusal |
| --- | --- |
| `from_round` is the key's active generation, so a delayed command never applies to a later one | `stale` (`409`) |
| Every dealer is a keyholder of that generation | `dealer_not_keyholder` (`400`) |
| At least that generation's threshold of dealers (3) | `too_few_dealers` (`400`) |
| Exactly as many players as the committee has members (4), each once; the threshold stays the committee's (3) | `player_count` (`400`). The API refuses a repeated or malformed identity |
| The same id again: the same key, generation, dealers and players | otherwise `conflict` (`409`) |

Players need not be committee members, and consensus membership is never derived from them. The
cryptography is commonware's, unchanged:

- `Info::new(previous, dealers = {A, B, C}, players = {A, B, C, E})` requires the dealers to be
  previous players, and at least its quorum of them.
- The round needs `max(quorum(dealers), quorum(previous)) = 3` valid logs, so all three dealers
  must deal.
- The new polynomial has degree `quorum(players) − 1 = 2`.
- The public key is asserted unchanged.

The round's dealers and players enter its transcript, so its dealings, acknowledgements and logs
cannot be replayed into another round. D is neither a dealer nor a player: commonware refuses its
dealing, and players refuse its messages.

### Local approval of new keyholders

A reshare to new keyholders hands a key's shares to other identities. Two gates protect it. An R1
refresh within the committee needs neither.

1. **The approvers (replicated).** A reshare to new keyholders is a protected operation
   ([administration.md](administration.md)). Honest leaders and voters accept the `StartResharing`
   command with a membership only with a threshold of the approvers' offline signatures over that
   exact membership, and with the next administrative nonce. Without them, the API refuses it
   (`403`).
2. **Each dealer's operator (local).** A dealer deals to new keyholders only if its operator
   approved that exact recipient set for that key, in a local file (`--approved-reshares <file>`):

   ```text
   # <validator public key> <identity>,<identity>,<identity>,<identity>
   0xb84e...10ef 0x5925...428c,0x478b...5266,0xedd0...7033,0x1c0c...f880
   ```

The rules of the approval file:

- The node reads the file when it joins the reshare, before it creates its dealer seed. So the
  approval must be in place before the reshare starts (or the node must be restarted).
- Without a matching line, the node deals nothing: no seed, no commitment, no private dealing. It
  still verifies and acknowledges dealings as a player, which reveals nothing of its own share. A
  malformed file approves nothing.
- R1 (the players are the generation's keyholders) needs no approval.
- The approval is local configuration, not replicated state. Consensus accepts any well-formed
  membership, and nodes may disagree about approvals without diverging. An unapproved reshare stays
  `in_progress` without a single dealer log, and is aborted or fails at its deadline.

A reshare completes only with at least the threshold of dealers (3). So a recipient set that fewer
than three operators approved never receives a usable sharing. Each approving dealer does give each
recipient one evaluation of its dealing polynomial: approve only identities you operate.

### Lifecycle and activation

The R1 lifecycle applies unchanged: `ACTIVE(g)` → `StartResharing` (with a membership) → A, B, C
deal to A, B, C, E → completed → each new keyholder derives, verifies and persists its share, then
submits `ShareReady` → `ready` once all four acknowledged → `ActivateGeneration` → `ACTIVE(g + 1)`.

- E takes part as a player only (it holds no share of `g`). It receives the dealings over the DKG
  channel, verifies them, and persists them before it acknowledges them. It derives and persists
  its share, then gossips its acknowledgement.
- D's acknowledgement does not count: D is not a player of `g + 1`.
- Activation requires the completed reshare, the acknowledgements of all four new keyholders and
  the committed command. An aborted or stale reshare never activates, and a generation is never
  partly activated.
- After activation, A, B, C and E serve `g + 1`. They refuse requests that name `g` for good
  (`stale_generation`), and requests in flight are retried once, as in R1. A, B and C erase their
  shares of `g`. D's copy of its old share stays on D ([limitations](#security-properties-and-limitations)).

### Signing routing

The coordinator sends partial-signature requests to the players of the active generation
(`ceremony.config.participants`). It verifies each partial against that generation's verification
shares. After the replacement it asks A, B, C and E, with E's index in the new generation.

A committee member that is not a keyholder of the active generation (D, if it came back) would
coordinate with the partials of three of the four keyholders. No test exercises this, since the
coordinators here are A, B and C.

Everything else is unchanged. Every keyholder checks the validator, the signing root, the
committed authorization, the active generation and slashing protection against its own state. E
signs only duties its own executor applied. It parks requests it has not applied yet, by about
0.1 s, its follower lag.

### Persistence and recovery

- A node needs a share of a generation only if it is one of its players. E has none of `g`, and D
  has none of `g + 1`. Neither is reported as a missing share.
- The R1 order holds for E: received dealings persisted before they are acknowledged, the share
  persisted before `ShareReady`, the activation applied atomically, the keyholder told after the
  block is durable.
- E was restarted before it received its share, after it persisted it, after its acknowledgement,
  and while it applied the activation. In each case it resumes, the replacement completes and
  activates, and E signs (`tests/e2e/replace.rs`, `r2_e2e_restart_e_*`). E restarted after the
  activation loads its share and signs (R2-E2E-3).

### Replacement procedure

1. All nodes run with `--participants 4 --followers 1` and the same `--approvers` file. The voters
   also run with `--approved-reshares <file>`. If they did not, do a rolling restart: each restart
   pauses finalization while D is offline.
2. Start E (node 4). Wait until `GET /ready` on E answers `200` (it applied the finalized history)
   and `GET /validators` on E lists the key.
3. On A, B and C, append the approval line for the key and A, B, C, E (identities from
   `GET /identity`).
4. Draft the reshare with the membership above:
   `mpc-admin draft reshare --request '{"public_key", "ceremony_id", "from_round", "dealers", "players"}'`.
   The approvers sign it offline (`mpc-admin sign`). Submit it with `mpc-admin submit`, which posts
   `POST /validators/reshare` with its `authorization`. Wait until `GET /validators/reshare/<id>`
   is `ready` on A, B, C and E.
5. Send `POST /validators/reshare/activate` to a voter. Wait until `GET /validators` on every
   keyholder shows the new `ceremony_id`.
6. Keep D off. Never restart it with its old data: its old share is useless only while the old
   shares of A, B and C are really erased.

### Security properties and limitations

- The public key and the slashing history stay the same; no new deposit.
- The new generation's shares are fresh. D's old share does not combine with them, and a partial
  signature from any old share fails against the new verification shares.
- **Resharing does not revoke copied shares.** D's old share (lost or stolen with D) and any backup
  of an old share of A, B or C remain shares of `g`. Three shares of `g` still sign as the key. R2
  protects against an attacker who holds D's share only if the old shares of A, B and C are erased
  and no backups of them exist (erasure is operational, L-18).
- **Consensus has no fault tolerance left while D is offline.** See
  [above](#what-r2-restores-and-what-it-does-not).
- **Approved by signatures.** A reshare to new keyholders needs the approvers' signatures (checked
  by every honest voter) and each dealer's local approval. Anyone who can reach a node's API can
  still start an R1 refresh or abort a reshare (L-6): denial of service, not a change of
  keyholders. The plain HTTP API listens on `127.0.0.1` only; the optional mTLS listener
  (`--https-listen`) accepts any client with a certificate from `--client-ca`.
- **Follower bootstrap needs the retained history** or a restored state copy, which E cannot check
  (no state root).
- L-1, L-15, L-16, L-17 and every other documented limitation are unchanged ([audit.md](audit.md)).

### Tests

| What | Tests |
| --- | --- |
| A follower joins without voting, applies the same state, restarts and catches up, submits a transaction (its first gossip dropped), and cannot vote, propose or count toward a quorum | `tests/e2e/follower.rs`, FOL-1 to FOL-5 |
| R2-CRYPTO-1 to 5 and 8, over 8 seeds: dealers A, B, C, players A, B, C, E; all three dealers required; D neither a dealer nor a player; the key unchanged byte for byte; any 3 new shares sign, 2 cannot, A, B, E sign without C; old and new partials never combine | `dkg::ceremony::tests::reshare::replace::replacing_a_lost_keyholder_keeps_the_key` |
| Membership rules: dealers outside the generation, too few dealers, wrong player counts, a stale generation, idempotent and conflicting starts; D's log and an R1 log refused; the codec, with R1's encoding still read | `replace::replacement_membership_rules`, `types::tests::reshare_start_encodings` |
| R2-CRYPTO-6: E refuses a dealing of another share, a value meant for another player, and a DKG dealing | `replace::invalid_replacement_dealings_are_refused` |
| R2-CRYPTO-7: no approval, no dealing (the file's rules) | `dkg::approval::tests::*`, R2-E2E-4 |
| The lifecycle through consensus: D's acknowledgement ignored, E's required, the same history and refusals after activation, a stale start, a restart | `storage::tests::validator::reshare::a_replaced_keyholder_holds_the_new_generation_through_consensus` |
| Real processes: R2-E2E-1 (loss of D, replacement, the same key), R2-E2E-2 (A, B, E sign with C's partials off; A and B alone cannot), R2-E2E-3 (E restarts), R2-E2E-4 (invalid, stale, unapproved, replayed), R2-E2E-5 (aborted replacement, the old generation signs with A, B, C), R2-E2E-6 (slashing protection of a DKG key and an imported key's floors), E restarted at four points | `tests/e2e/replace.rs` |
| A live Lighthouse validator: D lost, E joins, the key reshared to A, B, C, E, E's share signing with C's switched off | [ethereum-devnet.md](ethereum-devnet.md#replacing-a-lost-keyholder-run-g) |

## Performance

Measured on the devnet (run F, [ethereum-devnet.md](ethereum-devnet.md#resharing-run-f)), with 4
nodes on one host and 4 s slots:

| | DKG key | Imported key |
| --- | --- | --- |
| Ceremony: start to every new share acknowledged | 1.5 s | 1.7 s |
| Ready to activation decided | 0.2 s | 0.2 s |
| Activation to every node signing with the new generation | 0.1 s | under 0.1 s |
| Consensus transactions | 10: start, 4 dealer logs, 4 acknowledgements, activation | 10 |
| Lighthouse requests failed, coordinator retries | 0, 0 | 0, 0 |

By design, one reshare sends 12 private dealings over p2p (each of 4 dealers to 3 others) and 12
acknowledgements, plus retransmissions until acknowledged. Signing gets no permanent extra round:
a duty still takes one consensus decision (or none for a repeat) and one partial-signature
collection. The only additions are a generation lookup, and a single retry when the generation
changes during a request.

End-to-end latency through the proxy did not change: p50 / p95 279 / 524 ms before and
282 / 520 ms after (n ≈ 1 300 each). With one keyholder offline after the reshare, 3 keyholders
kept signing. The only slow requests were the leader-timeout delays of L-16 right after the node
stopped, unrelated to resharing.

### R2 on the devnet (run G)

Measured with a live Lighthouse validator
([ethereum-devnet.md](ethereum-devnet.md#replacing-a-lost-keyholder-run-g)), 4 voters and the
follower on one host, 4 s slots:

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

E's partial adds no round: a keyholder answers once it applied the duty's block, and E applies it
about 0.1 s after the voters (E2E logs). D's leader turns still cost the leader timeout when a duty
falls in one (none did in run G).

## Tests

| What | Tests |
| --- | --- |
| Over 12 seeds and two successive reshares: the key unchanged; every share and verification share changed; the new commitments verify the new shares; any 3 new shares sign as the key, 2 cannot; an old share does not verify against, or combine with, the new ones; the generation ids differ | `dkg::ceremony::tests::reshare::a_reshare_keeps_the_key_and_refreshes_every_share` |
| Dealings that would change the key; conflicting dealings; 3 dealers suffice; start rules, replays, acknowledgements, aborts, the codec; an imported key | `dkg::ceremony::tests::reshare::*` |
| The lifecycle through consensus: one at a time; activation only when completed and every share acknowledged; the same history and refusals before and after (double proposal, double vote, both surround directions); aborts; a restart with retired, active, aborted and in-progress generations | `storage::tests::validator::reshare::a_reshared_key_keeps_its_history_and_activates_only_when_ready` |
| An imported key: floors, chain and import state kept, imports still refused | `storage::tests::validator::reshare::an_imported_key_reshares_and_keeps_its_floors` |
| Real processes: E2E-RSH-1 (refresh and activation, the same key and signatures, other shares, history, one keyholder offline), RSH-2 (failure before activation, resume, abort), RSH-3 (crashes around activation), RSH-4 (invalid participants), RSH-5 (an imported key, still signing as the original key), and 10 crash points | `tests/e2e/reshare.rs` |
| A live Lighthouse validator reshared on the devnet | [ethereum-devnet.md](ethereum-devnet.md#resharing-run-f) |
