# Security review: signing path

Scope: consensus-backed authorization, the signing protocol, the coordinator and the keyholder,
as implemented in this repository. The adversarial test campaign, its findings (and fixes) and the
fault-model table are in [audit.md](audit.md).

## Assumptions

- Consensus (simplex): at most `f = 1` of 4 nodes Byzantine; finalized blocks are never reverted;
  the network is eventually synchronous for liveness.
- Threshold 3 of 4: any 3 shares sign, 2 cannot. A Byzantine node holds one share.
- p2p (commonware `lookup`): authenticated and encrypted; only the 4 configured keys can connect.
- Storage: `Metadata` commits are atomic and durable once `sync` returns; a node's data directory
  is not readable by others (mode `0700`, no encryption at rest).
- Clients are not authenticated: anyone reaching the HTTP port can authorize and sign.

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
| State partition behind the finalized history (torn newest copy, deleted or restored alone) | The node refuses to start when its state is behind marshal's processed height, and at run time the executor refuses a block that is not the next height (exit status 1 either way), instead of silently skipping blocks and diverging. A key share without its ceremony in the state, or a missing consensus journal, also stops it at startup. The damaged storage is left as found. | Fixed in the audit (BUG-2, H-2, H-4), tested (`f4_*`, `r5_*`) |
| Byzantine participant vs. liveness | With 3 honest online signers, one Byzantine participant cannot stop signing. Its invalid responses cost it 3 strikes per request, it counts once however it fails (BUG-1, fixed), and it cannot spoof or ban others. With only 3 online including the Byzantine one, signing may fail; safety holds. | Implemented, tested (E2E-8, `tests/signing.rs`) |
| Resource exhaustion | Bounded: 256 requests in flight per coordinator (`503`), 64 buffered responses per request, 3 strikes per participant, 256 parked requests, at most 64 per peer (dropped after 16 blocks), no retransmission to a participant banned for the request, 1 MB p2p messages and per-peer quotas, HTTP timeout. Not bounded: HTTP clients can create authorizations without limit (consensus and storage cost; no auth or rate limit). The keyholder mailbox is limited only by the p2p quota. Authorizations are kept forever. | Partly mitigated, documented |
| Signing-domain separation | Ethereum signatures use the POP ciphersuite DST over the raw root. The internal domain uses another DST, and nothing exposed signs in it. DKG transcripts are signed with the ed25519 node keys. | Implemented, tested (unit, blst) |

## Not provided

- Ethereum slashing protection (nonces are caller-chosen; see `docs/architecture.md`).
- Client authentication, authorization policy, rate limiting.
- Encryption of shares at rest, HSM or TEE isolation.
- Protection against more than `f` Byzantine or rolled-back nodes.
