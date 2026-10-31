# Adversarial audit of the signing path

Scope: authorization safety, durable recovery, crash consistency, concurrency, partial-signature
collection, Byzantine participants, timeouts and limits, process lifecycle. Method: read the code
paths below, then reproduce every claim with a test (deterministic simulation where possible, real
processes otherwise). Passing tests are evidence, not a proof.

## 1. Trust boundaries

| Event | Where | Code |
| ----- | ----- | ---- |
| Authorization visible (in memory) | executor, inside `Store::apply_block` (holds `&mut` until `sync`) | `src/storage.rs` |
| Authorization durable | `Metadata::sync` returns | `src/storage.rs` |
| Signer learns an authorization | `Committed` values, sent after the sync, before any client answer; or read from disk at start | `src/executor.rs`, `src/dkg/actor.rs` |
| Duty decided, signing root computed | `Protection::authorize` inside `Store::apply_block`, from the typed duty of the finalized command; record and authorization in the block's one sync | `src/slashing.rs`, `src/storage.rs` |
| Signer learns a duty authorization | `(ceremony round, root)` sent after the sync, before any client answer (`AuthorizedDuties`); or `Protection::authorized_roots` read from disk at start | `src/executor.rs`, `src/engine.rs`, `src/dkg/actor.rs` |
| Partial signature generated | `dkg::actor::partial` only: local coordinator, peer request, or parked request released by `Authorized` | `src/dkg/actor.rs` |
| Signature returned | coordinator `sign`, after recovery and verification | `src/signer/coordinator.rs` |
| State restored from disk | `Store::init` (state), `Secrets::init` (shares), marshal (re-delivery from its processed height), simplex journal | |
| Messages served before catch-up | HTTP and p2p are up immediately; signing requests are refused (`not_authorized`) or parked | `src/rpc.rs`, `src/dkg/actor.rs` |
| Coordinator retries | re-sends requests to silent participants every 500 ms until the deadline; clients may repeat requests | `src/signer/coordinator.rs` |
| Allocations | in-flight counter (max 256, drop guard), response sessions (drop guard), parked queue (256, 16 blocks) | |

## 2. Findings

| ID | Severity | Finding | Reproducer | Status |
| -- | -------- | ------- | ---------- | ------ |
| BUG-1 | High: Byzantine liveness | A participant answering with a final refusal **and** three invalid partials was counted twice in the coordinator's give-up check. One Byzantine node could make signing fail (`INSUFFICIENT_SIGNERS`) while three honest signers were available. | `tests/signing.rs::one_byzantine_participant_cannot_abort_signing` (deterministic) | Fixed: count distinct participants, saturating arithmetic |
| BUG-2 | Critical: replicated-state divergence | The executor skipped already-applied heights but never checked that a delivered block is the next one. If the state partition is behind marshal's processed height (newest copy torn or damaged after the block was acknowledged, partition deleted or restored alone), the node silently skipped finalized blocks. Observed: block 8 `Accepted` on node 0, `UnknownCeremony` on the damaged node 3. A skipped authorization lets that node accept a conflicting payload locally. | `tests/e2e/lifecycle.rs::f4_corrupted_state_fails_closed` (damage pinned after the acknowledgement with the hold hook), `f4_lost_state_fails_closed` | Fixed: the executor refuses a non-consecutive height; the node stops. A copy torn *before* the acknowledgement is legitimately re-delivered and repaired: `f4_torn_unacknowledged_write_is_replayed` |
| BUG-3 | Medium: operability | A node stopping on a fatal error (for example the check above) exited with status 0, invisible to a supervisor. | `f4_lost_state_fails_closed` | Fixed: exit status 1 whenever a node stops |
| BUG-4 | Medium: availability under concurrency | Identical concurrent requests on one node each ran a full task: their own command, their own requests to every participant, and every participant's answers fanned out to every session (N sessions, ~3N^2 messages through 64-slot buffers). On a loaded machine, 256 identical requests produced 43 and then 1 signature, the rest timed out. | `concurrency::e3_in_flight_limit` (first version) in full-suite runs | Fixed: identical requests in flight on a node share one task and its result (at most 1024 waiters, then `503`). 120 identical requests: slowest 1.1 s before, 0.26 s after |
| BUG-5 | Low: reporting | A validator duty retried through a coordinator that had not applied the original block yet was submitted again and decided `AlreadyAccepted` in a later block. The coordinator then reported that later block as the authorization's height. The signature and the slashing record were unchanged, but the authorization's reported identity was not the original one. Found by running the duty simulations under other seeds. | `SIM_SEED=9` and `16` of `tests/eth_duties.rs::authorization_outlives_its_coordinator`; now also deterministic in that test | Fixed: the duty receipt carries the height of the block that authorized the root (`authorized_at`) |
| H-1 | Hardening | The in-flight counter was decremented by the task body; a task ending abnormally would leak one slot of the 256. No reachable path found. | none | Drop guard |
| H-2 | Hardening (recovery) | BUG-2's check ran only when the next finalized block arrived: a node whose state was behind marshal served and signed (a stale prefix, never a conflict) until then. Nothing else related the durable stores to each other at startup. | `lifecycle::f4_*`, `lifecycle::r5_*` | Startup checks before any actor runs: state not behind marshal's processed height, every key share has its completed ceremony, consensus journal present when there is history (operator override). See [recovery.md](recovery.md) |
| H-3 | Hardening (consensus) | Consensus always started from the genesis floor, so a node whose journal was lost or older could repeat votes in views already finalized. | `readiness::r1_*` (floor reported), `lifecycle::r5_missing_consensus_journal_fails_closed` | Simplex starts from `Floor::Finalized` at marshal's durable processed finalization: never votes again at or below it |
| H-4 | Hardening (evidence) | A node refusing to start erased the evidence: commonware's metadata store truncates a copy that fails its checksum as soon as it is opened. A first fix kept the bytes in memory and wrote them back if the start was refused; review found it not crash-safe (the evidence existed only in memory between the truncation and the write-back) and it wrote known-bad bytes into live storage. | `lifecycle::r5_damaged_copy_is_saved_before_opening`, `lifecycle::f4_corrupted_state_fails_closed` | Before opening any store, every copy failing the integrity check is saved, synced, to `registry-diagnostics` (named by content, written once); working stores follow commonware's normal recovery |
| H-5 | Hardening (authorization binding) | The signing request did not name the kind of authorization. A keyholder signed a validator round's duty root whatever the request's nonce, and purpose separation at the keyholder rested on the state machine never creating development authorizations for validator rounds. No signature outside an authorization was possible. | `tests/eth_duties.rs::byzantine_coordinators_cannot_sign_unauthorized_duties`, E2E-ETH-9 | Typed `AuthorizationRef` (development nonce, or duty of a validator key) bound into the request id (protocol 2). The keyholder checks purpose, the key's current round and `(key, root)` among the key's records. The coordinator checks the ceremony's group key is the validator key. See [security-review.md](security-review.md#signing-authorization-binding) |
| H-6 | Hardening (chain identity) | A validator's chain was pinned by its first authorized duty: a wrong first request bound it to the wrong chain for good. | `activation_is_explicit_decided_by_consensus_and_immutable`, `stale_node_cannot_authorize_another_chain`, E2E-ETH-1, E2E-ETH-8 | Explicit, immutable activation decided by consensus. Earlier data is read as not activated and must be activated explicitly for its recorded chain |
| H-7 | Hardening (performance) | The surround check scanned the validator's whole attestation history: 341 µs per new attestation with 100 000 attestations. | `eth_bench` | O(log n) with the same rules, from the ordering of a surround-free history, verified at startup and against the full scan by randomized differential tests ([slashing-protection.md](slashing-protection.md#attestation-checks)) |
| T-1 | Test harness | Port blocks were probed then released: two test processes could get the same ports. | `lifecycle::f2_port_blocks_never_overlap` | Lock files per block, shared by all test processes |
| T-2 | Test harness | The scripted peer registered only the signing channel. commonware-p2p drops a connection on a message for an unregistered channel, so the real nodes' consensus traffic kept disconnecting it and one-shot messages were lost. | `adversarial::e4_e5_parked_overflow_and_expiry` | It registers and drains every channel |
| T-3 | Test harness | Restarted nodes were queried before their HTTP server was up. | crash and rollback tests | Restart waits for HTTP |
| T-4 | Test harness | Reserved ports reached 59 400, inside the ephemeral ranges (macOS 49152+, Linux 32768+): an outgoing connection could take a reserved port, and a node failed with `AddrInUse`. | full-suite run 2 (`b1`) | Port blocks between 10 240 and 32 000 |
| T-5 | Test harness | The whole suite started every network at once (~130 node processes): 5 s signing deadlines were missed for load reasons alone. | full-suite runs 1-3 (`a6`, `a2_two_node`) | At most 4 networks at once per test process (`E2E_MAX_NETWORKS`) |
| T-6 | Test logic | Rollback tests restored the whole data directory, consensus journal included, and expected the restored node to rejoin. In 3 of about 14 runs the node was blocked by its peers for equivocating (L-7), and the test failed on liveness (A1 stall, A1 `SIGNING_TIMEOUT` with 1 partial, A2 `SIGNING_TIMEOUT` with 2). A retry first added to A2 for this was based on a wrong hypothesis (links still coming up) and was removed. | `target/audit-logs/` (rerun 1, rerun 3, `a1-x-2-1`): `nullify after finalize peer=<restored node>` on the blocking nodes | A1 and A2 roll back all but the consensus journal and assert that nobody was blocked; `a1_full_restore_never_signs_conflict` covers the full restore with assertions valid in both outcomes |
| T-8 | Test harness | The E2E harness runs `target/debug/eth-mpc-signer`, a path shared by every feature set. A `cargo test` with default features (no `dev-api`), run during or between E2E runs, replaces it. Cargo copies the binary to that path only when it relinks, so a later `test-hooks` build that is up to date does not restore it, and every development API call answered `404`. Observed while validating the Web3Signer work: 20 and then 47 failures (`target/audit-logs/eth-e2e-invalid-binary-*.txt`). | `target/audit-logs/eth-e2e-invalid-binary-*.txt` | The harness now fails at once with an explanation when `/sign` is not served. Validation runs never overlap cargo builds with other features; `touch src/main.rs` forces the relink |
| T-9 | Test logic | E2E-ETH-8 asked the rolled-back node to sign a known duty as soon as it had replayed the activation. It had not replayed the later block holding that duty's record yet, so the duty was a new authorization to it, which it correctly refused while catching up (`503 local_backlog`). Failed once in the first hardening run. | `target/audit-logs/failures/hardening-e2e-run1*` | The test waits until the node has caught up; no assertion relaxed |
| T-7 | Test logic | Timing assumptions in the first versions: F4 damaged state at an unpinned moment (a crash before the acknowledgement is a legitimate replay), A5/A6 crash hooks on participants the coordinator did not need, D1 duplicates sent after the session had completed, scripted-peer replies read from earlier requests. | full-suite runs | Pinned with hooks (hold, freeze of a third node, `ask` drains old events); no assertion was relaxed |
| T-10 | Test environment (exposure) | The first devnet check started Kurtosis 1.22.2's engine directly on the shared test host. The engine publishes its API, which creates containers, on `0.0.0.0`, with no option to change it, and Docker's published ports bypass a host firewall. | observed on the test host; no request reached it in our logs | Stopped after about 20 s and its 4 volumes removed; nothing else on the host was touched. The integration now runs inside one Docker-in-Docker container, alone on its network, with no published port, its inner daemon on its Unix socket only (`integration/ethereum/scripts/env.sh`). `dockerd --ip=127.0.0.1` was tried first: Kurtosis then fails, it needs host port bindings |
| T-11 | Integration harness | First integration runs, each failing in the harness, never in the signer. Fulu needs a supernode (`kurtosis run` refused). Signer containers could not write log files created by the root driver (run 1: `environment`, node 0 not ready in 180 s). The real `cast` error was hidden by Docker's pull progress (run A: `deposit`). A retried deposit transaction was refused (`transaction indexing is in progress`, then `replacement transaction underpriced`). Foundry's `--json` receipt is an envelope. Alpine has no `/etc/machine-id` | on the test host, `$IT_HOME/failed/` and `$IT_HOME/runs/` (Kurtosis and run logs; the `cast` errors were seen in interactive output only) | Supernode; files owned by the host user; images pulled first, errors keep stdout and stderr; the deposit is sent once and its receipt polled; the envelope is unwrapped; a machine id is created. No assertion was relaxed |
| H-8 | Hardening (liveness beyond `f = 1`) | Two nodes that missed the certificate of the view the other two had entered (restarted or rolled back together) stayed in the previous view, and the other two could not reach a quorum alone. Simplex sends that certificate only with a view's nullify retries, not with its first nullify, so consensus waited for the intact nodes' next retry: `timeout_retry`, 10 s. Found on Linux: `rollback::a2_two_node_rollback` failed 3 of 10 runs and in 1 of 3 full suites (`504`, authorization timeout 10 s). Debug logs show the split (nodes 0 and 1 in view 12, nodes 2 and 3 nullifying view 11) and the release 160 ms after the retry that carried view 11's notarization. | `a2_two_node_rollback` with `E2E_RUST_LOG=...,commonware_consensus=debug` (test host, `validation/repro-a2-1402`, `validation/debug-a2-1405`) | `timeout_retry` 3 s, checked first in commonware-consensus 2026.9.0 (the retry broadcasts `get_best_certificate()` to every peer; it re-signs the same nullify; the skip timeout, 11 s, must stay above it). The test's authorization timeout is 15 s: it checks eventual recovery beyond `f = 1`; its safety assertions are unchanged. The stall itself remains (L-14) |
| T-12 | Test logic | `concurrency::e3_in_flight_limit` lifted its pause as soon as 256 requests were in flight, before the other 44 were refused: a request sent late found a slot freed by a completed one (`(257, 43)` instead of `(256, 44)`, one of three full suites on Linux). The limit was never exceeded. | test host, `validation/20261028T135047Z/e2e-3.txt` | The pause is lifted once all 44 are refused; the assertion stays `(256, 44)` |

## 3. Remaining issues and unsupported scenarios

| ID | Issue | Impact | Evidence |
| -- | ----- | ------ | -------- |
| L-1 | **Rollback of a quorum (here: every node) to older storage is undetected.** Nothing remembers the authorization, so a conflicting payload is authorized and signed: two valid signatures for one `(ceremony, nonce)`. The same holds for Ethereum slashing history: a double proposal is signed. Detecting it needs state outside the nodes (a monotonic counter or an external anchor). A counter in the same, rollbackable storage does not help. See [recovery.md](recovery.md) §7, and the anchor design (not implemented) in [slashing-protection.md](slashing-protection.md). | Safety, unsupported scenario. **Unresolved**; applies to imported keys unchanged | `rollback::a2_whole_network_rollback` and `eth2::e2e_eth_l1_whole_network_rollback_signs_a_double_proposal`: both **fail**, kept `#[ignore]` |
| L-2 | **Addressed.** A lagging or rolled-back node reports why it is not ready (`/status`, `/ready`: `no_block_since_start`, `local_backlog`, `no_recent_finalization`, `share_unavailable`) and refuses new authorizations (`503 NOT_READY`) instead of timing out. Reads (`/authorizations`) are still its local view: readiness says how current it is, never that it has the network's latest block. | Availability only | `rollback::a1_*`, `failures::lagging_signer_refuses_until_applied`, `readiness::*` |
| L-3 | Identical requests coalesce per node only: the same request sent at once to all four nodes runs one task on each (at most four commands, four collections). Documented as an optimization: consensus alone decides what is authorized; several coordinators may aggregate the same payload. | Load, bounded by the node count | `concurrency::b1_identical_requests` (at most one command per node) |
| L-4 | **Fixed.** The parked queue was shared: one peer could evict other peers' parked requests. Now at most 64 per peer and 256 in total; a flooding peer evicts only its own. A disconnect does not release parked requests (expiry after 16 blocks does). | Latency only | `dkg::parked::tests`, `adversarial::e4_e5_parked_overflow_and_expiry` |
| L-5 | **Fixed.** A participant banned for a request still received its retransmissions. Now it is not asked again for that request (exactly one request in D4, where there were about ten). | Wasted messages | `adversarial::d4_strike_limit` |
| L-6 | No client authentication or rate limiting: any HTTP client can create authorizations and slashing records (consensus and storage cost). It can also use up a validator's slot or epoch with a duty for the wrong block or fork version, which is a liveness loss for that duty. The API binds to loopback only, with no option to expose it. The raw signing API exists only in `dev-api` builds. | Availability | design, `tests/production_api.rs` |
| L-11 | Slashing history is never pruned. It grows by ~66 bytes per authorized duty, and every block rewrites the state partition (a block with one duty: 4.1 ms on disk with no history, 10.5 ms with 50 000 records). The surround check scans the validator's attestations with a lower target (normally all of them: 341 µs with 100 000). Pruning needs EIP-3076 low watermarks (refuse at or below the pruned range). | Performance over a validator's lifetime | design; measured in §6 |
| L-12 | The validator client's `fork_info` is trusted for the fork versions (the domain). The chain is no longer taken from the first duty (**addressed**, H-6): it is the explicit activation. A fork version that is wrong for the activated chain gives a signature that is invalid on chain but uses the slot or epoch. Only the mainnet preset is supported. | Liveness of a duty | [ethereum-signing.md](ethereum-signing.md) |
| L-13 | **Deposit signing is first come, once per key.** On a node started with `--enable-deposit-signing`, any client of its API obtains the key's one deposit signature, with withdrawal credentials of its choice, if nobody did before. A wrong first request (amount, credentials, genesis fork version) uses that signature for good: any other deposit message for the key is refused (`too_many_roots`). The first deposit on chain sets the credentials; later deposits to the key are top-ups to them. | Onboarding of a key; the funds of later deposits if the credentials are not the operator's | E2E-ETH-10, `slashing::tests::a_validator_signs_one_deposit_message_of_its_own_key`; mitigations: the flag is off by default and the API is loopback-only. Check the deposit's credentials on chain before funding more |
| L-14 | **Two nodes restarted together can stall signing for seconds, enough to miss Ethereum duties.** When both missed the certificate of the view the others are in (H-8), consensus waits for the intact nodes' leader timeout (2 s), then one or more nullify retries (3 s each), then a view change. Measured on Linux, 25 runs of `a2_two_node_rollback`: longest stall after the restart p50 3.0 s, p90 8.2 s, max 9.7 s; with a split (at least 9 of 25), 6.3 to 9.7 s. With 10 s retries: up to 13.3 s, and 2 of 6 runs still stalled when the test gave up. On mainnet an attestation is due 4 s into a 12 s slot: an authorization stalled past that misses it or arrives late, and a block proposal due then is lost. Two simultaneous failures exceed `f = 1`, so no bound is guaranteed. Not implemented: a faster way for lagging peers to get the certificate (answering a nullify for an older view with that view's certificate, or advancing from marshal's finalizations). | Liveness of duties | §6, `a2_two_node_rollback` (prints the recovery time). Operational rule: restart one node at a time, and wait for it to be `ready` |
| L-15 | **An imported key can have a second signer outside the network.** Key import is a trusted-dealer split of an existing keystore ([key-import.md](key-import.md)): the keystore, its backups and the dealer machine held the full secret, and whether the previous signer is stopped is the operator's acknowledgment, recorded by consensus but not verified. A second signer is slashable whatever the network does. An incomplete EIP-3076 history (exported before the stop, or from the wrong signer) protects only what it contains. | Slashing of an imported key, through operator error | **Unresolved**, operational: [key-import.md](key-import.md#assumptions); the floors refuse everything at or below the imported history (E2E-IMP-1, the devnet migration) |
| L-16 | **One keyholder stopping can delay duties by a leader timeout (2 s).** A duty whose authorization falls into a view the stopped node leads waits for the 2 s leader timeout before the view is skipped. In devnet run E, node 2's stop delayed the authorizations of two consecutive slots by 1.9 to 2.1 s: 2 sync committee messages (slots 1090 and 1091) and 8 selection proofs. No later request took more than 0.66 s, which fits consensus skipping the stopped leader's views (not confirmed in consensus internals). With 4 s slots a sync committee message is due 1.33 s into the slot, so the two were late; with mainnet's 12 s slots (due at 4 s) they would not be. Whether they were included in sync aggregates was not checked. Consensus and signing are unchanged in this milestone. | Latency; missed duties on short slots | Run E (`20261028T203033Z`): `logs/proxy.jsonl`, node 0's `authorization_ms` 2095 and 1922 ([ethereum-devnet.md](ethereum-devnet.md#migration-run-e)) |
| L-17 | **An imported key's history import cannot be undone.** Floors only rise, by design, and no command lowers them. Before the activation, an interchange with a far-future slot or epoch stops the key from signing for good, and the key cannot be registered again. Any client of a node's API can submit one (no authentication, L-6), and so can a Byzantine node, bypassing the API's full-history check (consensus checks the summary). It never weakens protection, and the operator sees the floors (`GET /keys/import/{id}`) before activating. **Narrowed:** after the activation, the state machine refuses every import (`activated`), and no other command writes the floors. | Liveness of an imported key (permanent), before its activation | `eth::interchange::tests::no_history_is_imported_once_the_key_is_activated`, `storage::tests::validator::imported::an_activated_imported_key_keeps_its_floors_whatever_the_command`, E2E-IMP-1 |
| L-18 | **Resharing needs every dealer and player, and trusts their readiness acknowledgements.** A dealing counts only if every player acknowledged it (no reveals), and a generation activates only once every new share is acknowledged: with one of them offline, a reshare cannot complete (it is aborted or fails at its deadline; the active generation keeps signing). An R1 refresh therefore needs all four nodes; an R2 replacement needs the three remaining keyholders and the new one, not the lost node. An acknowledgement is a keyholder's signed claim that it stored its share: a false one lets a generation activate with three working shares. Old shares stay a valid sharing of the same key until erased; erasure is best effort, and a reshare revokes no copied or backed-up share (the lost node's included). | Liveness of resharing; availability after a false acknowledgement; no revocation of old shares | [resharing.md](resharing.md#liveness-and-byzantine-behavior); E2E-RSH-4, R2-E2E-5 |
| L-19 | **Replacing a lost keyholder (R2) does not restore consensus fault tolerance.** The committee is not reconfigured: with D lost, finalization needs every one of A, B, C, and losing another voter stops authorizations and signing until it is back. D's leader turns keep costing the 2 s leader timeout (L-16). E, a follower, can neither vote nor stand in for a voter. R3 replaces D as a voter ([reconfiguration.md](reconfiguration.md)); until then this holds. | Availability after a node loss | [resharing.md](resharing.md#what-r2-restores-and-what-it-does-not); FOL-5 (a follower does not count toward a quorum) |
| L-20 | **R2's recipient approval is local and unauthenticated; a follower cannot verify a restored state.** A dealer deals to new keyholders only if its operator listed the exact key and recipient set in a local file (`--approved-reshares`), so one API request cannot hand shares to arbitrary identities. It is a prototype safeguard: the admin API that starts and aborts reshares has no authentication (L-6), there are no operator signatures, and an operator who approves gives each recipient one evaluation of its dealing polynomial. A follower that joins after the voters pruned their history must be given a copy of another node's state, which it cannot check (blocks carry no state root). | Who receives a key's shares rests on operators' files; follower bootstrap trust | `dkg::approval::tests`, R2-E2E-4; [resharing.md](resharing.md#follower-nodes) |
| L-21 | **A last block of an epoch that is notarized but never finalized stalls the epoch (R3).** With D offline, A, B and C must all send their finalize vote for the block carrying the reconfiguration; one that timed out after notarizing it never does, and no block may follow it (the guard). The network then finalizes nothing until an operator restarts the voters with `--close-epoch-at <its height>`, which makes commonware re-propose it until it is finalized. Safety holds throughout; a wrong height only stalls. Not reproduced in the tests (it needs a stall of at least 3 s exactly at that block); the closing mode itself is. | Availability during a reconfiguration | [reconfiguration.md](reconfiguration.md#closing-an-epoch---close-epoch-at); R3-9 |
| L-22 | **Reconfiguration is not authorized beyond its validity rules (R3).** The admin API is unauthenticated (L-6), and a faulty voter as leader can propose a reconfiguration of its own. Only a configured follower can be added, so an unknown key never becomes a voter, but an honest voter can be replaced by a configured follower. No governance, no operator approval of the new committee. | Availability (an honest voter evicted); safety holds with at most one faulty member per committee | `epochs::tests`, R3-7 |
| L-23 | **A node restored from a backup taken before a reconfiguration can equivocate in the new epoch (R3).** It replays the old epoch harmlessly (no quorum of it is left), then starts the new epoch with no journal, although the real node may already have voted in it; with no history of the new epoch yet, the missing-journal check cannot tell. The same class as L-7: never restore a consensus journal. | A Byzantine fault, tolerated within `f = 1` | [reconfiguration.md](reconfiguration.md#security-properties-and-limitations) |
| L-7 | **Restoring a node's consensus journal from older bytes (for example a whole data-directory backup) makes it forget its own votes.** It can then vote twice in one view (observed: `nullify` after its own `finalize`). Honest peers detect this and block it at the P2P layer for `block_duration` (1 hour), on every channel, signing included. Safety holds: consensus tolerates one equivocator, and the node still signs only what it has committed. Liveness: the node cannot catch up, coordinate or contribute partials for up to an hour; the other three continue with no spare capacity. Whether it happens depends on timing: 4 of about 32 full restores during the audit, mostly under load (it needs the node to time out a view before it fetches the certificates). Operational rule: never restore `registry-consensus` from a backup. Mitigated since (H-3): consensus resumes above the last finalization marshal durably processed, so a lost or older journal cannot repeat votes at or below it; a missing journal stops the node (H-2). Not covered: votes after that finalization, and a whole-directory restore (marshal rolled back too), which stays undetectable. | Availability of the restored node; a Byzantine fault, tolerated only within `f = 1` | `rollback::a1_full_restore_never_signs_conflict` (both outcomes), logs in `target/audit-logs/` |
| L-8 | A test process killed with SIGKILL leaves its temporary directory (and a stale port lock, reclaimed by the next run). Its nodes do exit. | Disk, tests only | `lifecycle::f1_nodes_die_with_their_test_process` |
| L-9 | A node uses ~320 MB resident at rest (a 160 MB page cache). 256 requests in flight add ~20 MB; 256 parked requests ~0.5 MB. | Sizing | `concurrency::e3_in_flight_limit` |
| L-10 | A leader that has not applied the last finalized block yet still holds that block's transactions in its mempool, so it skips the idle wait and proposes an empty block at once (the in-flight check keeps the transactions out of it). After busy blocks this adds empty blocks, and a lagging leader produces them back to back. Found while building the lag tests. | Efficiency only: more empty blocks, faster use of the block-counted retention window | `lag::*` (why the tests pause empty blocks instead of timing a freeze) |

## 4. Fault model

| Scenario | Safety | Liveness | Basis |
| -------- | ------ | -------- | ----- |
| One node offline | Preserved | Yes (3 signers, consensus with 3 of 4) | E2E-4, `c3_e6_*`, `a5_c1_*`, simulations |
| One Byzantine signer | Preserved: 1 share < 3, partials verified against the sender's own index | Yes with 3 honest online (after BUG-1) | `d1_d3_*`, `d4_*`, `one_byzantine_participant_cannot_abort_signing` |
| Two Byzantine signers | Threshold: 2 shares cannot sign. Consensus: `f = 2 > 1`, no guarantee; a consensus fork could commit conflicting authorizations that honest signers then sign. **Not guaranteed.** | Not guaranteed | analysis |
| One node's storage rolled back, consensus journal kept | Preserved: it re-learns the finalized history, refuses while stale, never signs B | After catch-up | `a1_single_node_rollback` |
| One node behind the retained history, restored from a healthy node's partitions (own key share and consensus journal kept) | Preserved | Yes: it signs with its own share and keeps up | `recovery::lagging_node_restored_from_peer_copy` |
| One node's whole data directory rolled back (journal included) | Preserved: never signs B, the intact nodes sign A | Not guaranteed for that node: may equivocate and be blocked for 1 hour (L-7) | `a1_full_restore_never_signs_conflict` |
| Two nodes rolled back, consensus journals kept | Preserved in the tested case (two intact nodes online keep the finalized history; the rolled-back ones converge). **Not guaranteed in general**: two stale validators exceed `f`. | Not guaranteed; in the tested case, after a stall of up to 9.7 s measured (L-14) | `a2_two_node_rollback` |
| Two nodes restarted together (storage intact) | Preserved | Eventually. Stalled while both are down; then possibly up to the intact nodes' next nullify retries (6.3 to 9.7 s measured after the restart when they missed a certificate), enough to miss duties (L-14) | `a2_two_node_rollback` recovery measurements (§6) |
| Quorum or whole network rolled back | **Violated** (L-1) | n/a | `a2_whole_network_rollback` (failing) |
| State partition corrupted, deleted or restored alone | Fail closed (after BUG-2) | Node down until repaired | `f4_*` |
| Coordinator crash | Preserved: the authorization is durable, partials are recomputed | Yes, retry on any node | `c2_*`, E2E-5, `b4_cancellation` |
| Participant crash before or after its partial | Preserved | Yes with 3 others | `a5_c1_*`, `a6_*` |
| Consensus unavailable | Preserved: no new authorizations; the submitted command is not cancelled | Existing authorizations still sign with 3 signers | `e1_*` |
| Stale participant | Preserved: refuses until the authorization is durably applied | After catch-up | `a1_*`, E2E-9, `a3_*`, `a4_*` |
| Malicious HTTP client | Authorization consistency preserved (decided by the state machine) | Not guaranteed: 256 requests in flight per node, then `503` | `b1`-`b4`, `e3_*` |
| Conflicting validator duties, concurrent, through different nodes | Preserved: one authorized, the other refused (`412`) on every node | Yes | E2E-ETH-2, `tests/eth_duties.rs` |
| Coordinator submitting a conflicting duty directly, or asking for partials of an unauthorized root | Preserved: refused by the state machine; partials refused (`not_authorized`) | Yes | `byzantine_coordinators_cannot_sign_unauthorized_duties` |
| Crash around a duty's application, coordinator crash with 2 partials, client hang-up after authorization | Preserved: record and authorization together; retries sign the same root, the conflict stays refused | Yes | E2E-ETH-4, E2E-ETH-5 |
| Lagging or rolled-back node asked for a conflicting duty | Preserved: it refuses, or submits it to consensus, which refuses it | After catch-up | E2E-ETH-6, E2E-ETH-7, `isolated_node_cannot_authorize_a_conflict` |
| Slashing history altered on disk (record lost or added, key replaced, activation lost, attestations surrounding each other) | Fail closed at startup | Node down until repaired | `storage::tests::validator::altered_history_fails_closed` |
| A validator that is not activated, or a duty for another chain | Preserved: refused by every node and by consensus, nothing recorded | n/a | `activation_is_explicit_decided_by_consensus_and_immutable` |
| Conflicting activations, concurrent, through different nodes | Preserved: consensus applies the first; the other is refused everywhere, before and after restarts | Yes | same, `slashing_history_survives_a_full_restart` |
| Stale or rolled-back node and the chain identity | Preserved: it refuses until it has the activation; a duty it submits for another chain is refused when ordered | After catch-up | `stale_node_cannot_authorize_another_chain`, E2E-ETH-8 |
| Byzantine coordinator using another reference (key, ceremony, purpose, nonce) | Preserved: refused by every keyholder | Yes | `byzantine_coordinators_cannot_sign_unauthorized_duties`, E2E-ETH-9 |
| A real validator client (Lighthouse) with one keyholder offline | Preserved | Yes: no attestation or proposal missed | devnet runs B, C and D (§6) |
| A real validator client whose coordinator is stopped, behind a failover proxy | Preserved | Yes: the proxy fails over, no duty missed | devnet runs B, C and D |
| A real validator client whose coordinator crashes after consensus authorized its duty (`authorized` crash point) | Preserved: the retry on another node returns the signature of the same authorization, accepted once | Yes | devnet runs B, C and D |

The guarantees come from different places, which must not be confused:

- **Cryptographic threshold**: any 3 of 4 shares sign, 2 cannot. A share signs only what its node has
  committed.
- **Consensus BFT**: simplex with `n = 4` tolerates `f = 1` Byzantine validator. Authorization safety
  rests on it.
- **Crash tolerance**: atomic commits, replay from marshal, the height-continuity check (BUG-2).
- **Rollback resistance**: only what honest peers' finalized history provides. A rolled-back
  minority re-syncs (and stays connected if its consensus journal was kept, L-7); a rolled-back
  quorum is undetected (L-1).
- **Slashing protection**: the replicated state machine decides each validator duty by the
  specification's rules over the validator's whole history. The decision is committed with the
  authorization and checked by every keyholder. Its durability is that of the replicated state:
  it survives crashes, restarts and a minority rollback, and not a quorum rollback (L-1). The
  development API (`dev-api` builds only) has none: its nonces are caller-chosen.

## 5. Coverage matrix

| Invariant | Tests | Result | Evidence |
| --------- | ----- | ------ | -------- |
| Durable authorization before signing | `a3_*`, `a4_*`, E2E-9, `a1_*`, simulations | Pass | Crashed or held nodes are never among the signers; refusal reason `not_authorized`; after restart the authorization is restored and signed |
| No conflicting authorization | `b2_*`, E2E-3, `a1_*`, `a2_two_node_*`, `d5_d6_*`, `f4_*`, simulations | Pass | One `200` out of 100; `409` everywhere after restart; identical state on all nodes |
| Safe single-node rollback | `a1_single_node_rollback` | Pass | Stale node refuses A and B; converges to A; B `409`; A signs identically; nobody blocked |
| Safe full-directory rollback | `a1_full_restore_never_signs_conflict` | Pass (safety); liveness of the restored node not guaranteed (L-7) | B never signed by any node; the intact nodes sign A; the restored node converges unless blocked |
| Two-node rollback | `a2_two_node_rollback` | Pass (tested case only) | B never signed; rolled-back nodes converge; consensus live; nobody blocked |
| Quorum rollback | `a2_whole_network_rollback` | **Fail** (known, L-1) | Conflicting signature for nonce 100 |
| Safe crash recovery | `a3`-`a6`, `c2`, E2E-5, E2E-6, `f4_*` | Pass (after BUG-2, BUG-3) | Crash hooks; exit status; restored authorization; damaged acknowledged state stops the node; a torn unacknowledged write is replayed to the same state |
| Byzantine response rejection | `d1_d3_*`, `d4_*`, `d5_d6_*`, E2E-8, simulations | Pass (after BUG-1) | Rejections in logs; result equals the honest signature; banned sender ignored |
| Bounded resource usage | `e3_*`, `e4_e5_*`, `b1`-`b4` | Pass (after BUG-4) | 256 distinct requests in flight + 44 `503`; identical ones share a task; parked capped at 256 and expired; counters back to 0; RSS |
| Signing with one offline node | E2E-4, `c3_e6_*`, `a5_c1_*`, `e2_*` | Pass | `200` with 3 signers; bounded `504` with 2 |
| Process lifecycle | `f1_*`, `f2_*`, repeated suite runs | Pass | No orphans after SIGKILL of the runner; no overlapping ports |
| No conflicting slashable duties | `slashing::tests`, `tests/eth_duties.rs`, E2E-ETH-2 to 7 | Pass | Exactly one of two concurrent conflicting duties signed; `412` on every node afterwards; no partial for a refused root |
| Duty record durable with its authorization | `storage::tests::validator`, E2E-ETH-3, E2E-ETH-4 | Pass | Same decisions after restart; crash before or after the sync never loses the record of a signed duty |
| Slashing history fails closed | `altered_history_fails_closed` | Pass | 7 alterations, each refused at startup |
| Validator keys sign only duties | `storage::tests::validator`, E2E-ETH-1, `tests/production_api.rs` | Pass | `ValidatorKey` outcome, `403`, no `/sign` in default builds |
| Explicit, immutable activation | `slashing::tests`, `storage::tests::validator`, `tests/eth_duties.rs`, E2E-ETH-1, E2E-ETH-8 | Pass | Nothing signed before activation; one decision for concurrent activations; the other chain refused before and after restarts and recovery |
| Authorization binding | `byzantine_coordinators_cannot_sign_unauthorized_duties`, E2E-ETH-9 | Pass | Every scenario of the binding audit refused by every keyholder, in simulation and over real p2p |
| Logarithmic attestation checks equal to the full scan | `logarithmic_checks_match_the_exhaustive_reference`, `long_histories_match_the_exhaustive_reference` | Pass | 1.5 million decisions over 5 000 seeds |
| Quorum rollback of slashing history | `e2e_eth_l1_whole_network_rollback_signs_a_double_proposal` | **Fail** (known, L-1) | Double proposal signed |
| Real validator duties on a beacon chain | devnet runs B, C and D (`integration/ethereum/scripts/run.sh`) | Pass | A DKG key, activated by a deposit the MPC network signed. Lighthouse v8.3.2 signs only through the Web3Signer API, with no keystore. Attestations have a correct target and head in the beacon state, and blocks are canonical and finalized (§6) |
| One deposit message per validator key | E2E-ETH-10, `slashing::tests` | Pass | Identical retry: same signature. Other credentials: `too_many_roots`. Another key's message: `deposit_for_another_key` |

Not covered precisely:

- B4's "before submission" case: there is no hook before the command is submitted, so the test hangs
  up immediately and whichever stage the server reached is exercised.
- A6: an aborting process may lose a message it had queued; the test accepts either outcome and
  requires a correct signature.
- Rollback of three nodes with one intact node is not tested.
- L-7's blocked outcome is not forced: `a1_full_restore_never_signs_conflict` takes whichever
  outcome the timing gives and prints it.
- The deterministic simulations run with one seed.

## 6. Final runs

Logs of every run below, and the directories of every failure seen during the audit (node logs and
storage, named by test and cause), were kept in a local `target/audit-logs/`, which has since been
deleted. From the devnet integration on, every run is on the test host, in containers, and its
logs stay under `$IT_HOME` there (`~/eth-mpc-it`).

| Check | Result |
| ----- | ------ |
| `cargo fmt --check` | clean |
| `cargo clippy --all-targets --all-features -- -D warnings` | clean |
| `cargo test` (unit, simulations) | 43 passed, 0 failed |
| Rollback tests, 6 rounds (`rollback-loop-*.txt`) | 18 of 18 passed; the full restore was never blocked |
| `a1_full_restore_never_signs_conflict`, 12 runs, 6 at once (`full-restore-load-*.txt`) | 12 of 12 passed; node 3 was blocked for equivocation in 1 (by node 2), so both outcomes were exercised |
| `cargo test --features test-hooks --test e2e`, 3 runs (`e2e-final-{1,2,3}.txt`) | 35 passed, 0 failed, 4 ignored (benchmark, two helper processes, L-1 reproducer) in each run; 128-133 s; no node process or temporary directory left after any run |
| `rollback::a2_whole_network_rollback` (ignored, L-1) | **Fails**: a second, conflicting signature for nonce 100 (`target/audit-logs/a2_whole_network_rollback/`) |
| Latency benchmark, release (`bench-final.txt`), against the run before the audit fixes | No regression beyond run-to-run variation. New authorization p50 411 ms (393), p99 742 (678): the difference is consensus time (`authorization_ms` p50 369 vs 353), while the signing path is unchanged (`collect_ms` p50 8.5 vs 9). Already authorized p50 6.7 ms (6.7). One node offline p99 2345 ms (2331) |

### Recovery hardening (after H-2 to H-4, L-2, L-4, L-5)

| Check | Result |
| ----- | ------ |
| `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings` | clean |
| `cargo test` (unit, simulations) | 55 passed, 0 failed (12 new unit tests: readiness rules, parking policy) |
| `cargo test --features test-hooks --test e2e`, 3 runs (`hardening-e2e-{1,2,3}.txt`) | 40 passed, 0 failed, 4 ignored in each run; 140-150 s; no node process left; no temporary directory left by a passing run |
| Recovery and rollback tests, 5 rounds (`hardening-recovery-*.txt`) | 16 of 16 passed in each round; the full-restore node was never blocked |
| Latency benchmark, release (`hardening-bench.txt`) | No regression: new authorization p50 337 ms (411 before), p99 639 (742); already authorized p50 6.6 ms (6.7); one node offline p99 2252 ms (2345). The gate on new authorizations adds one local status query |

Failures met while writing these tests, kept in `target/audit-logs/failures/hardening-dev/`: the
preservation check revealed H-4; a first readiness rule counted the block marshal is about to
deliver as a backlog and refused authorizations at random right after each block (now a tolerance
of two blocks, unit-tested); tests that asked a node still catching up to authorize now wait for it
to be ready.

### Readiness and recovery review

| Check | Result |
| ----- | ------ |
| `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings` | clean |
| `cargo test` (unit, simulations) | 55 passed, 0 failed |
| `lag::*`, 5 runs (`review-lag-*.txt`) | 4 of 4 passed each run. Concurrent rounds (15): A authorized and B rejected by consensus 6, B authorized and A rejected by consensus 4, B applied first and A rejected from node 0's state 3, B refused before submission (three blocks behind) 2. Never a partial or group signature for the losing payload |
| Recovery set (rollback, readiness, R5/F4, crash, lagging, recovery), 3 runs (`review-recovery-*.txt`) | 23 of 23 passed each run |
| `cargo test --features test-hooks --test e2e`, 4 runs (`review-e2e-*.txt`) | 46 of 46 in runs 1, 3 and 4. Run 2: 45 of 46, `adversarial::d1_d3_*` failed at setup: node 0 could not bind its HTTP port (`AddrInUse` on 21924, free afterwards, outside the ephemeral range; cause not identified; kept in `failures/review-dev/e2e-run2-d1_d3-http-addr-in-use`) |

Test bugs met while writing these tests (no assertion relaxed; directories in
`failures/review-dev/`): a hold-log check raced marshal's tip report; freezing a node to stop
consensus at a block boundary was racy (L-10), replaced by pausing empty blocks; the concurrent test
re-armed the hold before node 3 had applied the previous round, and waited for submissions that
correctly never happened (B refused when beyond the tolerance, A answered from state when B was
already applied).

### Ethereum signing and slashing protection

| Check | Result |
| ----- | ------ |
| `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, `cargo clippy --all-targets -- -D warnings` | clean |
| `cargo test` (unit, simulations, vectors, parsing, default-build API; `eth-cargo-test.txt`) | 85 passed, 0 failed (lib 44, dkg 8, eth_duties 7, eth_vectors 4, eth_web3signer 6, network 5, production_api 1, signing 10) |
| `tests/eth_duties.rs` with `SIM_SEED` 1 to 20 (`eth-duties-seeds.txt`) | 20 of 20 (140 test runs) |
| `cargo test --features test-hooks --test e2e`, 3 runs (`eth-e2e-{1,2,3}.txt`) | 53 passed, 0 failed, 6 ignored (2 benchmarks, 2 helper processes, 2 L-1 reproducers) in each run; 183-200 s; no node process or temporary directory left |
| `eth2::` E2E, 5 more rounds (`eth-slashing-e2e-*.txt`) | 35 of 35. The lagging node answered `412` (it submitted the conflict, consensus refused it) in 4 rounds and `503` (not ready) in 1 |
| `eth2::e2e_eth_l1_whole_network_rollback_signs_a_double_proposal` (ignored, L-1) | **Fails**: a double proposal is signed (`eth-l1-whole-network-rollback/`) |
| Latency, release (`eth-bench-latency.txt`) | Web3Signer new attestation p50 349 ms, p99 633; new proposal p50 373, p99 623; repeated duty p50 6.7 ms. The development API in the same run: new p50 384, p99 586; existing p50 6.7; one node offline p99 2247. Earlier baseline: 337 / 639 / 6.6 / 2252. No regression beyond run-to-run variation |
| Micro-benchmarks, release (`eth-bench-micro.txt`, `eth-bench-apply.txt`) | Signing root 0.5-6 µs; parse and root 4-17 µs. Slashing decision for a new attestation 2 µs (no history) to 341 µs (100 000 attestations). Apply with one duty 4.1 ms (no history) to 10.5 ms (50 000 records, 3.3 MB) |

Two first E2E runs are invalid and kept as `eth-e2e-invalid-binary-*.txt` (T-8). A default-feature
build, run during them, replaced the test binary, and every development-API call returned `404`.
They were stopped and repeated with no concurrent builds.

### Security and compatibility hardening (activation, authorization binding, attestation checks)

| Check | Result |
| ----- | ------ |
| `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, `cargo clippy --all-targets -- -D warnings` | clean |
| `cargo test` (`hardening-cargo-test.txt`) | 94 passed, 0 failed, 2 ignored (benchmarks): lib 50, dkg 8, eth_duties 9, eth_vectors 4, eth_web3signer 7, network 5, production_api 1, signing 10 |
| `tests/eth_duties.rs` with `SIM_SEED` 1 to 20 (`hardening-duties-seeds.txt`) | 20 of 20 (180 test runs), after BUG-5; seeds 9 and 16 had found it |
| Logarithmic attestation checks against the full scan, `SLASHING_SEEDS=5000` (`hardening-differential.txt`) | 1 500 000 decisions agree: accepted 91 723, retries 156 413, double votes 453 419, surrounding 360 939, surrounded 376 645, invalid 60 861 |
| `cargo test --features test-hooks --test e2e`, 3 runs (`hardening-e2e-{1,2,3}.txt`) | Run 2: 55 of 55. Runs 1 and 3: 54 of 55, each failing one test that predates this work, under full-suite load: `concurrency::e3_in_flight_limit` (20 of the 256 in-flight requests refused `NOT_READY` by the readiness gate: node 0, just restarted, fell more than 2 blocks behind under the burst) and `lag::concurrent_conflicting_requests_while_lagging` (setup race: it asserts node 3's applied height before node 3 applied the preceding empty blocks). Both passed 3 of 3 run alone (`hardening-flaky-repeats.txt`); evidence in `failures/hardening-e2e-run1-e3*` and `failures/hardening-e2e-run3-lag*`. Every `eth2::` test passed in every run. 6 ignored each run (2 benchmarks, 2 helper processes, 2 L-1 reproducers); 201-204 s; no node process or temporary directory left |
| `eth2::` E2E, 5 more rounds (`hardening-eth2-e2e-*.txt`) | 45 of 45; the lagging node answered `412` in all 5 |
| `eth2::e2e_eth_l1_whole_network_rollback_signs_a_double_proposal` (ignored, L-1) | **Fails**: a double proposal is signed (`hardening-l1-whole-network-rollback/`) |
| Latency, release (`hardening-bench-latency.txt`) | Web3Signer new attestation p50 352 ms, p99 603 (349, 633 before); new proposal p50 351, p99 590 (373, 623); repeated duty p50 6.8 ms (6.7). Development API: new p50 368, p99 617 (384, 586); existing p50 6.7 (6.7); one node offline p99 2146 (2247). No regression beyond run-to-run variation |
| Micro-benchmarks, release (`hardening-bench-micro.txt`, `hardening-bench-apply.txt`) | New attestation decision 2.1 / 2.2 / 2.2 µs with 1 000 / 10 000 / 100 000 attestations (4.0 / 21.7 / 341 before). Apply with one duty 4.5 / 5.8 / 10.9 / 19.5 ms with 1 000 / 10 000 / 50 000 / 100 000 records (unchanged: the state rewrite) |

Lighthouse compatibility, checked afterwards with Lighthouse v8.3.2's own code. The generator is
`tests/fixtures/lighthouse/generator` (tag `v8.3.2`, commit `a376defa`).

- **Requests.** 14 requests, one per supported duty and a block per fork from Bellatrix to Fulu;
  each block's blinded request equals the full block's.
- **Parsing and roots.** Each one is parsed with the root Lighthouse computed
  (`eth_web3signer::lighthouse_produced_requests_reproduce_lighthouse_roots`).
- **End to end.** E2E-ETH-1 signs each one, and every signature verifies with blst.
- **Altair.** Lighthouse's Altair full-block request is refused.
- **Independent roots.** `ssz_roots.py` reproduces all 14 roots.
- **Hand-written fixtures.** They match Lighthouse's output field for field.

A first E2E run of this work failed in E2E-ETH-8 (T-9, test logic). It was fixed, and the three runs
above were started from scratch.

### Deposit signing, the devnet integration, and validation on Linux

These checks run on the Linux test host (x86_64, 12 cores, 62 GB), in containers. The repository
checks use `env.sh validate`, in `rust:1.99.1-bookworm`. Logs are under `~/eth-mpc-it/validation/`
on that host. The first local checks, on macOS, matched (cargo test 97 passed, E2E 56 of 56 three
times), but their logs went with the deleted `target/`.

| Check | Result |
| ----- | ------ |
| First validation, `timeout_retry` 10 s (`20261028T135047Z`) | fmt, clippy (all features, default) clean; `cargo test` 97 passed (lib 51, dkg 8, eth_duties 9, eth_vectors 4, eth_web3signer 9, network 5, production_api 1, signing 10). E2E 56 of 56 in run 1; 55 of 56 in run 2 (`a2_two_node_rollback`, H-8) and run 3 (`e3_in_flight_limit`, T-12). L-1 reproducer fails: a double proposal is signed |
| `a2_two_node_rollback` alone, 10 runs, 10 s (`repro-a2-1402`) | 7 passed, 3 failed (`504`) |
| The same with consensus debug logs, 6 runs (`debug-a2-1405`) | 4 passed, 2 failed. Longest stall after the restart: p50 3.8 s, max 13.3 s; the failed runs were still stalled when the test gave up |
| E2E without `a2`, e3 fixed, 3 runs (`e3fix-1407`) | 55 of 55 in each |
| `a2` alone, 25 runs, `timeout_retry` 3 s, authorization timeout 15 s (`a2-retry3-1417`, every directory kept) | 25 of 25. Longest stall after the restart p50 3.0 s, p90 8.2 s, max 9.7 s: 16 runs within 3.9 s (no split), 6 at 6.3 to 6.5 s (one retry), 3 at 8.2 to 9.7 s. New authorization signed 0.6 to 13.4 s after the restart (p50 4.1 s); its request 0.2 to 6.1 s |
| `e3_in_flight_limit` alone, 10 runs | 10 of 10 |
| Second validation (`20261028T142418Z`) | fmt, clippy clean; `cargo test` 97 passed; E2E 56 of 56 in each of 3 runs (173-175 s); L-1 reproducer fails as expected |

The stall is measured from node 0's log: the longest gap between finalizations after the restart
of the second rolled-back node. The analysis script and the kept directories are on the test host.

Devnet runs, details in [ethereum-devnet.md](ethereum-devnet.md#results). Runs B and C used the
10 s retry, run D the 3 s retry and the final scripts. Logs are on the test host, in
`~/eth-mpc-it/runs/`.

| Run | Result |
| --- | ------ |
| Early runs (failed in the harness, T-11) | Run 1: `environment`, signer logs not writable. Run A: `deposit`, the `cast` error hidden by pull progress. The deposit was then debugged by hand |
| B (`20261028T113358Z`) | Every scenario and check passed. 86 Lighthouse requests, all signed; 10 of 10 observed epochs attested with the correct target and head; 12 of 12 observed proposals canonical. In-flight crash after a new authorization |
| C (`20261028T124404Z`) | Every scenario and check passed. 102 requests, all signed; 10 of 10; 9 of 9 canonical. The in-flight crash hit an existing authorization (so the scenario now re-arms). The whole-period check failed: the beacon node had pruned old states (so a recorder was added) |
| D (`20261028T143415Z`) | Every scenario and check passed. 91 requests, all signed. Whole active period, epochs 11 to 26: 16 of 16 correct target and head, 15 of 15 proposals canonical; 18 of 18 signed blocks canonical. In-flight crash after a new authorization, on the first attempt |

Latency over every Lighthouse request: p50 234 / 249 / 262 ms, p95 427 / 468 / 451, max 501 / 586 /
595 (runs B / C / D). The attestation deadline here is 1.33 s.

### Key import and EIP-3076

On the same Linux test host, in containers ([key-import.md](key-import.md)).

| Check | Result |
| ----- | ------ |
| First validation with key import (`20261028T200912Z`) | fmt clean; clippy with all features failed (`&PathBuf` in `tests/e2e/import.rs`); default clippy clean; `cargo test` passed; E2E 57 of 58: E2E-ETH-1 compared the validator listing without its new `origin` field (the test now expects `"origin": "dkg"`); L-1 reproducer fails as expected |
| Second validation (`20261028T202014Z`) | fmt, clippy (all features, default) clean; `cargo test` 113 passed (lib 61, dkg 8, eth_duties 9, eth_vectors 4, eth_web3signer 9, key_import 6, network 5, production_api 1, signing 10), including the 38 EIP-3076 interchange test files; E2E 58 of 58 in each of 3 runs (177-182 s), with E2E-IMP-1 and E2E-IMP-2; L-1 reproducer fails: a double proposal is signed |
| EIP-3076 review, the reference-model test (`20261029T092052Z`) | fmt, clippy clean; `cargo test` 114 passed, with `imports_and_exports_are_at_least_as_strict_as_the_specification` (300 seeds); E2E 58 of 58; L-1 reproducer fails as expected. The same test with 100 000 seeds (release build) passed in 11 s. Two deliberate bugs in a copy of `slashing.rs` (a floor refusing `slot < floor`; an export without its floor records) each made it fail |
| No import after activation (`20261029T094238Z`) | The state machine refuses `ImportSlashingProtection` for an activated key (`activated`). fmt, clippy clean; `cargo test` 116 passed, with `no_history_is_imported_once_the_key_is_activated` and `an_activated_imported_key_keeps_its_floors_whatever_the_command` (every command kind against an activated key, then a restart); E2E 58 of 58, E2E-IMP-1 refusing a far-future import after activation through the API; L-1 reproducer fails as expected. Without the new check, both new unit tests fail |
| Void round (`20261029T091808Z`) | Not a result. The mutation check had left a stale debug build: the copy restored with `rsync -a` kept an mtime older than the build, so cargo reused it, and the two export tests failed against the mutated export. Its E2E step also failed because the next round, started too early, replaced the shared debug binary (T-8). Rounds must not overlap, and a restored file must be newer than the build |
| Devnet run E (`20261028T203033Z`) | Every scenario and check passed, the migration included: genesis validator 30 moved from Lighthouse's local keystore to the network with its public key unchanged, 5.9 s from the stop to signing through the network; no attestation missed before, during or after; the three imported-floor refusals; 2 010 Lighthouse requests (1 885 of them the migrated key's, with sync committee duties), all signed ([ethereum-devnet.md](ethereum-devnet.md#migration-run-e)) |

### Resharing (R1)

On the same Linux test host, in containers ([resharing.md](resharing.md)).

| Check | Result |
| ----- | ------ |
| Found while building it | A block activating a generation also re-marks the old ceremony as changed, and the step that registers a completed DKG validator ceremony's key then moved the validator back to its old round within the same block. Caught by `a_reshared_key_keeps_its_history_and_activates_only_when_ready`; registration now happens only when a ceremony gives its key a validator or a newer round |
| First validation (`20261029T105157Z`) | fmt clean; clippy failed (`result_large_err` on two new API helpers, then fixed); `cargo test` passed; E2E 73 of 73 with the 15 resharing tests (E2E-RSH-1 to RSH-5, 10 crash points); L-1 reproducer fails as expected |
| Devnet run F (`20261029T105830Z`) | Every scenario and check passed, migration included; both MPC keys reshared live (ceremonies 1.5 and 1.7 s, every node switched within 0.1 s of the activation), no failed request, no missed attestation, proposals canonical, latency unchanged; one keyholder offline with the new generation; 3 320 Lighthouse requests, all signed ([ethereum-devnet.md](ethereum-devnet.md#resharing-run-f)) |
| Validation (`20261029T124004Z`) | fmt, clippy clean; `cargo test` passed; E2E 72 of 73 in each of 3 runs, each failure a race in the new tests, not in the protocol: RSH-4 (twice) used node 3 as coordinator right after its restart, before it caught up (`503 local_backlog`); RSH-5 installed a share on a node that had not applied the registration yet (`404`). Fixed: a stable node coordinates while another is frozen, and installation waits for the registration on each node. L-1 reproducer fails as expected |
| Final validation (`20261029T125309Z`) | fmt, clippy (all features, default) clean; `cargo test` 124 passed (lib 72); E2E 73 of 73 in each of 3 runs (233-244 s); L-1 reproducer fails: a double proposal is signed |

### Replacing a lost keyholder (R2)

On the same Linux test host, in containers ([resharing.md](resharing.md#r2-replacing-a-lost-keyholder)).

| Check | Result |
| ----- | ------ |
| Follower feasibility, pinned commonware 2026.9.0 sources | No blocker: secondary peers (`AddressableTrackedPeers`) are accepted inbound and receive `Recipients::All`; simplex with `ed25519::Scheme::verifier` skips voting (`me()` is `None`, `sign` returns nothing) and never leads; resolvers serve any connected peer and fetch from primary peers; a peer sending on an unregistered channel is disconnected (so a follower registers every channel). FOL-1 to FOL-5 passed on their first run |
| Found while building it | The DKG actor indexed its own dealing by `pending[&me]`, which would panic for a dealer that is not a player; the `reshare-after-all-dealings` crash point compared the dealings held with the player count (never reached with 3 dealers and 4 players). Both fixed. The API accepted an empty dealer or player list, which encodes but does not decode (a set holds 1 to 64): a leader proposing it would make its blocks undecodable for its peers. The API now refuses such a list (`reshare_start_encodings`, R2-E2E-4) |
| First validation (`20261030T145808Z`) | fmt, clippy (all features, default) clean; `cargo test` passed (lib 79, with the R2 unit tests); E2E 88 of 88, then 87 of 88 twice: `lag::concurrent_conflicting_requests_while_lagging` once, `crash::a4_crash_after_applying_before_signer_learns` once, neither failing before in 25 runs each; L-1 reproducer fails as expected |
| The two failures | **lag (a test race, fixed):** with a random seed, the losing request of a round can be rejected by consensus in a later block than the winner; the test re-armed node 3's hold before that block was applied, and node 3 then held it: one block more behind than the next round asserts (node 3's log: hold re-armed at 15:18:59.09, block 17 held). Reproduced once in 12 isolated runs. The test now waits until no transaction is pending anywhere before re-arming: 10 of 10. **a4 (not reproduced):** after node 1's restart, node 0's collection with node 2 frozen timed out with 2 partials; node 1 logged no signing request at all (a request that does not reach a restarted node under load). 12 of 12 in isolation, unchanged by R2 (the p2p peer set is the same primary set for a network without followers); recorded as a timing flake under the suite's load, which R2's 5-node networks increased |
| Devnet run G (`20261030T152504Z`, `run-r2`) | Exit 0. D stopped for good; E caught up in 15.6 s; the DKG key reshared by A, B, C to A, B, C, E (ceremony 1.7 s, 9 consensus transactions, activation 0.2 s later), the key unchanged; with C's partials off for an epoch, all 17 signatures combined A, B and E; epochs 11 to 22 attested, 16 of 16 proposals canonical, no Lighthouse request failed or retried; security checks 7 of 7 with D offline ([ethereum-devnet.md](ethereum-devnet.md#replacing-a-lost-keyholder-run-g)). The run's `report.md` lacks the R2 section (a scenario-name collision in `it.py`, fixed after the run); `report-r2.md` was computed from the run's records |
| Final validation (`20261031T071553Z`) | With the lag test fix and the API's empty-set refusal. fmt, clippy (all features, default) clean; `cargo test` 132 passed (lib 80); E2E 88 of 88 in each of 3 runs (315-319 s), FOL-1 to FOL-5 and the 10 R2 tests included; L-1 reproducer fails: a double proposal is signed |

### Replacing a lost consensus voter (R3)

On the same Linux test host, in containers ([reconfiguration.md](reconfiguration.md)).

| Check | Result |
| ----- | ------ |
| Research, pinned commonware 2026.9.0 sources | Simplex runs one committee per engine and has no notion of application commands; Inline re-proposes a block only at a static `Epocher` boundary; marshal checks a finalization's epoch only when the resolver delivers it (archived blocks are dispatched without that check); a notarized view not covered by a nullification must stay in the chain (forced inclusion). Hence: a stateless guard on the parent block (no lag parameter), a stop after the block that ends the epoch, per-epoch journals and channels, and the closing restart for a last block that is notarized but never finalized (L-21) |
| Phase 1 gate (`20261031T100132Z`) | Epoch-aware startup with no reconfiguration yet (the engine opens the state first, per-epoch Provider, Epocher, journal and channels): fmt, clippy (all features, default) clean; `cargo test` passed (lib 86); E2E 88 of 88; L-1 reproducer fails as expected. No behavior change |
| Found while building it | The guard first refused every child of a block carrying a reconfiguration, including in the next epoch, whose genesis that block is: epoch 1 never finalized (all eight R3 tests stalled right after a correct switch). It now applies only to a block of the current epoch (`Epochs::ends_current`, `only_a_block_of_the_current_epoch_ends_it`). Clippy flagged the new command and effect as large enum variants: boxed |
| Final validation (`20261031T103436Z`) | fmt, clippy (all features, default) clean; `cargo test` passed (lib 92); E2E 96 of 96 in each of 3 runs (370-381 s), R3-1 to R3-9 included; L-1 reproducer fails: a double proposal is signed |
| Devnet run H (`20261031T105527Z`, `run-r3`) | After R2 on the same run: the block ending epoch 0 at height 2 046, every voter stopped within 1.4 s, epoch 1's first block 8.1 s after the first stop; A, B, E signed without C (shares {0, 1, 3}, 17 signatures); D came back in epoch 0 and followed epoch 1 after `mpc-admin resume`; epochs 11 to 33 all attested, 24 of 24 proposals canonical, 0 Lighthouse requests failed or retried; security checks 7 of 7 ([ethereum-devnet.md](ethereum-devnet.md#replacing-a-lost-consensus-voter-run-h)) |
| Not done | Forcing a last block that is notarized but never finalized (it needs a voter to time out after notarizing it, which no hook reaches without changing commonware's certification); the closing restart that recovers from it is tested directly (R3-9) |

## 7. Reproducing

```bash
cargo test                                                   # unit + simulations
cargo test --features test-hooks --test e2e                  # real processes
cargo test --features test-hooks --test e2e rollback::a2_whole -- --ignored   # L-1, fails
cargo test --features test-hooks --test e2e eth2::e2e_eth_l1 -- --ignored     # L-1 for duties, fails
cargo test --features test-hooks --test e2e eth2::                            # Web3Signer E2E
SIM_SEED=7 cargo test --test eth_duties                                       # another schedule
SLASHING_SEEDS=5000 cargo test --release --lib logarithmic_checks             # differential test
cargo test --release --test eth_bench -- --ignored --nocapture                # roots, slashing checks
cargo test --release --lib apply_cost -- --ignored --nocapture                # apply cost vs history
python3 -I tests/fixtures/web3signer/ssz_roots.py tests/fixtures/web3signer/*.json   # independent roots
cargo test --features test-hooks --test e2e lag:: -- --nocapture      # E2E_SEED=<seed> to replay
cargo test --release --features test-hooks --test e2e latency -- --ignored --nocapture
E2E_KEEP=1 cargo test --features test-hooks --test e2e <name>               # keep logs
```

The deterministic simulations use commonware's default seed; failures of real-process tests keep
their directory (node logs) and print its path.
