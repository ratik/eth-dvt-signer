# Security review: signing path

Scope: consensus-backed authorization, Ethereum validator duties and their slashing protection,
the signing protocol, the coordinator and the keyholder, as implemented in this repository. The adversarial test campaign, its findings (and fixes) and the
fault-model table are in [audit.md](audit.md).

## Assumptions

- Consensus (simplex): at most `f = 1` of 4 nodes Byzantine; finalized blocks are never reverted;
  the network is eventually synchronous for liveness.
- Threshold 3 of 4: any 3 shares sign, 2 cannot. A Byzantine node holds one share.
- p2p (commonware `lookup`): authenticated and encrypted; only the 4 configured keys can connect.
- Storage: `Metadata` commits are atomic and durable once `sync` returns; a node's data directory
  is not readable by others (mode `0700`, no encryption at rest).
- Clients are not authenticated: anyone reaching the HTTP port can have duties authorized and
  signed, within slashing protection (and, in `dev-api` builds, any payload under a development
  key).
- The validator client's `fork_info` is taken as sent: a wrong fork version or chain gives a
  signature that is invalid on the real chain but still uses the slot or epoch.

## Findings

| Question | Answer | Status |
| -------- | ------ | ------ |
| Authorization races: can a node sign after seeing an authorization but before it is durable? | No. Partials come only from `dkg::actor::partial`, which needs a `storage::Committed` value. Only the store creates those, from disk or after `sync` returns. The executor hands them over after the sync and before answering any client, so a coordinator's own request queues behind them. Remote requests that arrive first are refused (`not_authorized`) and parked. | Implemented, tested (unit, `tests/signing.rs`, E2E-9) |
| State rollback (crash): can a node restart from older state and sign a conflicting payload? | No. A crash leaves the old or the new state, never a mix. A node signs an authorization only after its commit completed, so anything it signed is on its disk. A lost commit was never signed from. On restart the node re-applies the finalized chain (its own archive, then peers), which yields the same authorization. | Implemented, tested (E2E-5, E2E-6, restart tests) |
| State rollback (malicious, whole storage snapshot) | One node restored from an old snapshot (all but its consensus journal) re-learns the same finalized history from its peers; it refuses while stale (tested, `a1_single_node_rollback`). With its consensus journal restored too, it may vote twice in a view and its peers block it for an hour; it still never signs a conflicting payload (`a1_full_restore_never_signs_conflict`, audit L-7). Two rolled-back nodes converged in the tested case (`a2_two_node_*`) but are beyond `f`, so nothing is guaranteed. Rolling back every node produces a second, conflicting signature for one nonce (`a2_whole_network_rollback`, failing): finality assumes honest nodes keep their storage. | Single node: tested. Quorum: unsupported (audit L-1) |
| Coordinator equivocation: partials for two payloads under one nonce? | No. Each participant checks its own committed authorization and signs the stored payload, whatever the request says. Consensus never commits two payloads for one `(ceremony, nonce)`, and a malicious coordinator holds one share. | Implemented, tested (`tests/signing.rs`, E2E-3, E2E-7) |
| Participant spoofing | The share index of a partial must equal the authenticated sender's index in the ceremony, and the partial must verify against that index's public share. A forged index is rejected and counts against the sender. | Implemented, tested (`tests/signing.rs`, E2E-8) |
| Cross-ceremony replay | The request id binds the ceremony, and partials verify against that ceremony's public polynomial, so another ceremony's partials fail. | Implemented, tested |
| Cross-request replay | Responses are routed by request id (version, ceremony, nonce, payload), so a response for another request never reaches this one. A partial binds only the payload (the Ethereum root). Two authorized nonces with the same root give the same signature, which is harmless. | By design, documented |
| Stale nodes | A lagging node refuses everything it has not applied. Signing an applied finalized authorization while still catching up is safe, because finalized authorizations never change. It reports why it is not ready and refuses to submit new authorizations (`NOT_READY`); readiness never claims the node has the network's latest block ([recovery.md](recovery.md)). | Implemented, tested (E2E-9, `tests/signing.rs`) |
| State partition behind the finalized history (torn newest copy, deleted or restored alone) | The node refuses to start when its state is behind marshal's processed height, and at run time the executor refuses a block that is not the next height (exit status 1 either way), instead of silently skipping blocks and diverging. A key share without its ceremony in the state, or a missing consensus journal, also stops it at startup. Copies failing their integrity check are saved to `registry-diagnostics` before the stores are opened. | Fixed in the audit (BUG-2, H-2, H-4), tested (`f4_*`, `r5_*`) |
| Byzantine participant vs. liveness | With 3 honest online signers, one Byzantine participant cannot stop signing. Its invalid responses cost it 3 strikes per request, it counts once however it fails (BUG-1, fixed), and it cannot spoof or ban others. With only 3 online including the Byzantine one, signing may fail; safety holds. | Implemented, tested (E2E-8, `tests/signing.rs`) |
| Resource exhaustion | Bounded: duties of at most 32 KiB in a command, 8 distinct roots per validator, non-slashable duty type and period; 256 requests in flight per coordinator (`503`), 64 buffered responses per request, 3 strikes per participant, 256 parked requests, at most 64 per peer (dropped after 16 blocks), no retransmission to a participant banned for the request, 1 MB p2p messages and per-peer quotas, HTTP timeout. Not bounded: HTTP clients can create authorizations and slashing records without limit (consensus and storage cost; no auth or rate limit), and slashing history is never pruned. The keyholder mailbox is limited only by the p2p quota. Authorizations are kept forever. | Partly mitigated, documented |
| Validator key signing an arbitrary root | No. The client sends a typed duty. Every node computes its signing root from the finalized command (`DutyRequest::signing_root`), never from a client's or coordinator's root, and the keyholder signs a root only if `(ceremony round, root)` is a committed duty authorization of that key. A client `signingRoot` that differs is refused before anything is decided. | Implemented, tested (`tests/eth_duties.rs`, E2E-ETH-1) |
| Byzantine coordinator pairing harmless duty fields with a conflicting root | Not possible: there is no root field in the command. The root is a function of the duty and `fork_info`, recomputed by every node. | By construction |
| Conflicting slashable duties (double proposal, double or surround vote), concurrently through different nodes | Consensus orders the commands. The state machine authorizes the first and refuses the second (`412`) on every node, over the validator's whole history. A command submitted directly by a node skipping its coordinator checks is decided the same way. | Implemented, tested (`slashing::tests`, `tests/eth_duties.rs`, E2E-ETH-2) |
| Slashing record and authorization out of step | Not possible: both are written in the one atomic commit of their block. The keyholder learns of a duty only after that commit; at startup it is seeded from the committed state. | Implemented, tested (crash points, E2E-ETH-4) |
| Validator key through the development API, or a development key through the Web3Signer API | No. The purpose is fixed by consensus when the ceremony starts. A `Sign` command on a validator ceremony is refused by the state machine (`ValidatorKey`). A development key is not a validator (`404`). The development API is not compiled into default builds. | Implemented, tested (`storage::tests::validator`, E2E-ETH-1, `tests/production_api.rs`) |
| Cross-validator and cross-purpose replay | A duty authorization is scoped to the key's ceremony round: another validator's ceremony, or a development authorization of the same bytes, does not sign it. | Implemented, tested (`tests/eth_duties.rs`) |
| Chain confusion | A validator's first authorized duty pins its genesis validators root. Duties for another chain are refused. The domain also separates chains. | Implemented, tested |
| Slashing history lost or altered on disk | Startup refuses missing or extra records (per-validator counts), unknown validators, keys that do not match their ceremony, and corrupt entries. A consistent rewrite of the history of 2 or more nodes, or a rollback of every node, is not detected: a double proposal is reproduced (`e2e_eth_l1_*`, ignored). | Partial: see [slashing-protection.md](slashing-protection.md) |
| Signing-domain separation | Ethereum signatures use the POP ciphersuite DST over the raw root. The internal domain uses another DST, and nothing exposed signs in it. DKG transcripts are signed with the ed25519 node keys. | Implemented, tested (unit, blst) |

## Not provided

- Slashing protection that survives a rollback of every node (an anchor is proposed in
  [slashing-protection.md](slashing-protection.md), not implemented), EIP-3076 import and export.
- Slashing protection for the development API (`dev-api` builds; nonces are caller-chosen).
- Client authentication, authorization policy, rate limiting.
- Encryption of shares at rest, HSM or TEE isolation.
- Protection against more than `f` Byzantine or rolled-back nodes.
