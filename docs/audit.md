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
| H-1 | Hardening | The in-flight counter was decremented by the task body; a task ending abnormally would leak one slot of the 256. No reachable path found. | none | Drop guard |
| H-2 | Hardening (recovery) | BUG-2's check ran only when the next finalized block arrived: a node whose state was behind marshal served and signed (a stale prefix, never a conflict) until then. Nothing else related the durable stores to each other at startup. | `lifecycle::f4_*`, `lifecycle::r5_*` | Startup checks before any actor runs: state not behind marshal's processed height, every key share has its completed ceremony, consensus journal present when there is history (operator override). See [recovery.md](recovery.md) |
| H-3 | Hardening (consensus) | Consensus always started from the genesis floor, so a node whose journal was lost or older could repeat votes in views already finalized. | `readiness::r1_*` (floor reported), `lifecycle::r5_missing_consensus_journal_fails_closed` | Simplex starts from `Floor::Finalized` at marshal's durable processed finalization: never votes again at or below it |
| H-4 | Hardening (evidence) | A node refusing to start erased the evidence: commonware's metadata store truncates a copy that fails its checksum as soon as it is opened. | `lifecycle::f4_corrupted_state_fails_closed` (the damaged copy is compared before and after) | Raw bytes of the state, secret store and marshal progress are kept until the checks pass and put back if the node refuses to start |
| T-1 | Test harness | Port blocks were probed then released: two test processes could get the same ports. | `lifecycle::f2_port_blocks_never_overlap` | Lock files per block, shared by all test processes |
| T-2 | Test harness | The scripted peer registered only the signing channel. commonware-p2p drops a connection on a message for an unregistered channel, so the real nodes' consensus traffic kept disconnecting it and one-shot messages were lost. | `adversarial::e4_e5_parked_overflow_and_expiry` | It registers and drains every channel |
| T-3 | Test harness | Restarted nodes were queried before their HTTP server was up. | crash and rollback tests | Restart waits for HTTP |
| T-4 | Test harness | Reserved ports reached 59 400, inside the ephemeral ranges (macOS 49152+, Linux 32768+): an outgoing connection could take a reserved port, and a node failed with `AddrInUse`. | full-suite run 2 (`b1`) | Port blocks between 10 240 and 32 000 |
| T-5 | Test harness | The whole suite started every network at once (~130 node processes): 5 s signing deadlines were missed for load reasons alone. | full-suite runs 1-3 (`a6`, `a2_two_node`) | At most 4 networks at once per test process (`E2E_MAX_NETWORKS`) |
| T-6 | Test logic | Rollback tests restored the whole data directory, consensus journal included, and expected the restored node to rejoin. In 3 of about 14 runs the node was blocked by its peers for equivocating (L-7), and the test failed on liveness (A1 stall, A1 `SIGNING_TIMEOUT` with 1 partial, A2 `SIGNING_TIMEOUT` with 2). A retry first added to A2 for this was based on a wrong hypothesis (links still coming up) and was removed. | `target/audit-logs/` (rerun 1, rerun 3, `a1-x-2-1`): `nullify after finalize peer=<restored node>` on the blocking nodes | A1 and A2 roll back all but the consensus journal and assert that nobody was blocked; `a1_full_restore_never_signs_conflict` covers the full restore with assertions valid in both outcomes |
| T-7 | Test logic | Timing assumptions in the first versions: F4 damaged state at an unpinned moment (a crash before the acknowledgement is a legitimate replay), A5/A6 crash hooks on participants the coordinator did not need, D1 duplicates sent after the session had completed, scripted-peer replies read from earlier requests. | full-suite runs | Pinned with hooks (hold, freeze of a third node, `ask` drains old events); no assertion was relaxed |

## 3. Remaining issues and unsupported scenarios

| ID | Issue | Impact | Evidence |
| -- | ----- | ------ | -------- |
| L-1 | **Rollback of a quorum (here: every node) to older storage is undetected.** Nothing remembers the authorization, so a conflicting payload is authorized and signed: two valid signatures for one `(ceremony, nonce)`. Needs state outside the nodes (monotonic counters, external anchoring) to detect; a counter in the same, rollbackable storage does not help. Why, and what Ethereum slashing protection needs: [recovery.md](recovery.md), §6. | Safety, unsupported scenario | `rollback::a2_whole_network_rollback`: **fails**, kept `#[ignore]` |
| L-2 | **Addressed.** A lagging or rolled-back node reports why it is not ready (`/status`, `/ready`: `no_block_since_start`, `local_backlog`, `no_recent_finalization`, `share_unavailable`) and refuses new authorizations (`503 NOT_READY`) instead of timing out. Reads (`/authorizations`) are still its local view: readiness says how current it is, never that it has the network's latest block. | Availability only | `rollback::a1_*`, `failures::lagging_signer_refuses_until_applied`, `readiness::*` |
| L-3 | Identical requests coalesce per node only: the same request sent at once to all four nodes runs one task on each (at most four commands, four collections). Documented as an optimization: consensus alone decides what is authorized; several coordinators may aggregate the same payload. | Load, bounded by the node count | `concurrency::b1_identical_requests` (at most one command per node) |
| L-4 | **Fixed.** The parked queue was shared: one peer could evict other peers' parked requests. Now at most 64 per peer and 256 in total; a flooding peer evicts only its own. A disconnect does not release parked requests (expiry after 16 blocks does). | Latency only | `dkg::parked::tests`, `adversarial::e4_e5_parked_overflow_and_expiry` |
| L-5 | **Fixed.** A participant banned for a request still received its retransmissions. Now it is not asked again for that request (exactly one request in D4, where there were about ten). | Wasted messages | `adversarial::d4_strike_limit` |
| L-6 | No client authentication or rate limiting: any HTTP client can create authorizations (consensus and storage cost). The API binds to loopback only, with no option to expose it; it is documented as a development and test API. | Availability | design |
| L-7 | **Restoring a node's consensus journal from older bytes (for example a whole data-directory backup) makes it forget its own votes.** It can then vote twice in one view (observed: `nullify` after its own `finalize`). Honest peers detect this and block it at the P2P layer for `block_duration` (1 hour), on every channel, signing included. Safety holds: consensus tolerates one equivocator, and the node still signs only what it has committed. Liveness: the node cannot catch up, coordinate or contribute partials for up to an hour; the other three continue with no spare capacity. Whether it happens depends on timing: 4 of about 32 full restores during the audit, mostly under load (it needs the node to time out a view before it fetches the certificates). Operational rule: never restore `registry-consensus` from a backup. Mitigated since (H-3): consensus resumes above the last finalization marshal durably processed, so a lost or older journal cannot repeat votes at or below it; a missing journal stops the node (H-2). Not covered: votes after that finalization, and a whole-directory restore (marshal rolled back too), which stays undetectable. | Availability of the restored node; a Byzantine fault, tolerated only within `f = 1` | `rollback::a1_full_restore_never_signs_conflict` (both outcomes), logs in `target/audit-logs/` |
| L-8 | A test process killed with SIGKILL leaves its temporary directory (and a stale port lock, reclaimed by the next run). Its nodes do exit. | Disk, tests only | `lifecycle::f1_nodes_die_with_their_test_process` |
| L-9 | A node uses ~320 MB resident at rest (a 160 MB page cache). 256 requests in flight add ~20 MB; 256 parked requests ~0.5 MB. | Sizing | `concurrency::e3_in_flight_limit` |

## 4. Fault model

| Scenario | Safety | Liveness | Basis |
| -------- | ------ | -------- | ----- |
| One node offline | Preserved | Yes (3 signers, consensus with 3 of 4) | E2E-4, `c3_e6_*`, `a5_c1_*`, simulations |
| One Byzantine signer | Preserved: 1 share < 3, partials verified against the sender's own index | Yes with 3 honest online (after BUG-1) | `d1_d3_*`, `d4_*`, `one_byzantine_participant_cannot_abort_signing` |
| Two Byzantine signers | Threshold: 2 shares cannot sign. Consensus: `f = 2 > 1`, no guarantee; a consensus fork could commit conflicting authorizations that honest signers then sign. **Not guaranteed.** | Not guaranteed | analysis |
| One node's storage rolled back, consensus journal kept | Preserved: it re-learns the finalized history, refuses while stale, never signs B | After catch-up | `a1_single_node_rollback` |
| One node behind the retained history, restored from a healthy node's partitions (own key share and consensus journal kept) | Preserved | Yes: it signs with its own share and keeps up | `recovery::lagging_node_restored_from_peer_copy` |
| One node's whole data directory rolled back (journal included) | Preserved: never signs B, the intact nodes sign A | Not guaranteed for that node: may equivocate and be blocked for 1 hour (L-7) | `a1_full_restore_never_signs_conflict` |
| Two nodes rolled back, consensus journals kept | Preserved in the tested case (two intact nodes online keep the finalized history; the rolled-back ones converge). **Not guaranteed in general**: two stale validators exceed `f`. | Not guaranteed | `a2_two_node_rollback` |
| Quorum or whole network rolled back | **Violated** (L-1) | n/a | `a2_whole_network_rollback` (failing) |
| State partition corrupted, deleted or restored alone | Fail closed (after BUG-2) | Node down until repaired | `f4_*` |
| Coordinator crash | Preserved: the authorization is durable, partials are recomputed | Yes, retry on any node | `c2_*`, E2E-5, `b4_cancellation` |
| Participant crash before or after its partial | Preserved | Yes with 3 others | `a5_c1_*`, `a6_*` |
| Consensus unavailable | Preserved: no new authorizations; the submitted command is not cancelled | Existing authorizations still sign with 3 signers | `e1_*` |
| Stale participant | Preserved: refuses until the authorization is durably applied | After catch-up | `a1_*`, E2E-9, `a3_*`, `a4_*` |
| Malicious HTTP client | Authorization consistency preserved (decided by the state machine) | Not guaranteed: 256 requests in flight per node, then `503` | `b1`-`b4`, `e3_*` |

The guarantees come from different places, which must not be confused:

- **Cryptographic threshold**: any 3 of 4 shares sign, 2 cannot. A share signs only what its node has
  committed.
- **Consensus BFT**: simplex with `n = 4` tolerates `f = 1` Byzantine validator. Authorization safety
  rests on it.
- **Crash tolerance**: atomic commits, replay from marshal, the height-continuity check (BUG-2).
- **Rollback resistance**: only what honest peers' finalized history provides. A rolled-back
  minority re-syncs (and stays connected if its consensus journal was kept, L-7); a rolled-back
  quorum is undetected (L-1).
- **Slashing protection**: none. Nonces are caller-chosen; two nonces may authorize conflicting
  Ethereum messages.

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
storage, named by test and cause), are in `target/audit-logs/`.

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

## 7. Reproducing

```bash
cargo test                                                   # unit + simulations
cargo test --features test-hooks --test e2e                  # real processes
cargo test --features test-hooks --test e2e rollback::a2_whole -- --ignored   # L-1, fails
cargo test --release --features test-hooks --test e2e latency -- --ignored --nocapture
E2E_KEEP=1 cargo test --features test-hooks --test e2e <name>               # keep logs
```

The deterministic simulations use commonware's default seed; failures of real-process tests keep
their directory (node logs) and print its path.
