# Resharing: new share generations of a validator key

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

Resharing does not revoke a compromised share by itself ([below](#old-shares)). It is not a change of committee ([R2](#r2-replacing-a-keyholder)).

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
   - its dealer is a keyholder of the generation refreshed;
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

A **share generation** of a validator key is the ceremony that holds it: its round, configuration, session, commitments and the participants' share indices (sorted committee order, `x = i + 1`). The validator's `round` (`slashing::Validator`) names the **active** generation, the only one that signs.

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
| `StartResharing {validator, ceremony}` | The key is an activated validator; no other reshare of it is in progress or awaiting activation; the active generation has a public output (an imported key's registered sharing serves as one) | `unknown_validator`, not activated, pending (`409`, one at a time), id taken (`409`); the same id and key again is idempotent |
| `DealerLog` | As for a DKG | Not signed for this round, dealer not a keyholder of `g`, reveals, closed |
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
- A reshare is a ceremony entry (value tag 10): its DKG fields plus the key, the generation it refreshes, that generation's public output and the acknowledged shares.
- An activation rewrites only the validator entry's `round`.
- Slashing records, the activation and the import state are not written.
- The startup checks accept a validator whose ceremony is an active, retired or pending generation of its key, and an imported key's import state at its original round. They still refuse inconsistent states.

**Secret store.**
- The new share is stored under the new round, written once.
- The retired round's seed, dealings and share are erased with two writes (`Secrets::erase`), and the same happens for an aborted reshare.

Older binaries cannot read a state with reshares (an unknown value tag): they refuse to start, and nothing is misread. `PROTOCOL_VERSION` is unchanged; mixed-version clusters are unsupported.

## Liveness and Byzantine behavior

**All four keyholders are needed.** A dealing counts only if every player acknowledged it (no reveals), and activation waits for every new share to be acknowledged. With one node offline, a reshare cannot complete: it is aborted or fails at its deadline, and the active generation keeps signing with 3 nodes.

**Resharing does not restore fault tolerance after losing a node.** Its share cannot be rebuilt without that node; that is what R2 is for.

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

## R2: replacing a keyholder

R1 keeps old keyholders = new keyholders = the consensus committee. Replacing D with E (A, B, C, D → A, B, C, E) needs the following. The cryptography already supports it (`Info::new(previous, dealers, players)`, dealers taken from the previous output's players), and this format keeps dealers, players, share indices and consensus identities apart.

1. A ceremony configuration with separate players. Today `CeremonyConfig::check` requires the participants to be the committee. Dealers would be ≥ 3 of {A, B, C, D}, players {A, B, C, E}, and share indices follow the new player set.
2. Keyholder membership separate from consensus. E must reach the DKG and signing p2p channels, whose peer set is the consensus committee today, possibly without voting.
3. Coordinators route partial-signature requests to the active generation's players, not to the committee.
4. Readiness, the startup checks and the acknowledgements per generation's player set.
5. D's share retired and erased: as with L-15, that D erased it is the operator's statement.

A committee change of consensus itself (dynamic membership) is separate again.

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

## Tests

| What | Tests |
| --- | --- |
| Over 12 seeds and two successive reshares: the key unchanged; every share and verification share changed; new commitments verify the new shares; any 3 new shares sign as the key, 2 cannot; an old share does not verify against, or combine with, the new ones; generation ids differ | `dkg::ceremony::tests::reshare::a_reshare_keeps_the_key_and_refreshes_every_share` |
| Dealings that would change the key; conflicting dealings; 3 dealers suffice; start rules, replays, acknowledgements, aborts, the codec; an imported key | `dkg::ceremony::tests::reshare::*` |
| The lifecycle through consensus: one at a time, activation only when completed and every share acknowledged, the same history and refusals before and after (double proposal, double vote, both surround directions), aborts, a restart with retired, active, aborted and in-progress generations | `storage::tests::validator::reshare::a_reshared_key_keeps_its_history_and_activates_only_when_ready` |
| An imported key: floors, chain and import state kept, imports still refused | `storage::tests::validator::reshare::an_imported_key_reshares_and_keeps_its_floors` |
| Real processes: E2E-RSH-1 (refresh and activation, the same key and signatures, other shares, history, one keyholder offline), RSH-2 (failure before activation, resume, abort), RSH-3 (crashes around activation), RSH-4 (invalid participants), RSH-5 (an imported key, still signing as the original key), and 10 crash points | `tests/e2e/reshare.rs` |
| A live Lighthouse validator reshared on the devnet | [ethereum-devnet.md](ethereum-devnet.md#resharing-run-f) |
