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
| Chain confusion | A validator key signs nothing until an explicit activation for one chain (genesis validators root), decided by consensus, stored with the key, immutable. Duties for another chain are refused, and the domain also separates chains. A wrong first duty can no longer pin the wrong chain. Data of the previous version (chain pinned by the first duty) is read as not activated, and must be activated explicitly for the same chain. | Implemented, tested (`slashing::tests`, `tests/eth_duties.rs`, E2E-ETH-1, E2E-ETH-8) |
| Slashing history lost or altered on disk | Startup refuses missing or extra records (per-validator counts), unknown validators, keys that do not match their ceremony, and corrupt entries. A consistent rewrite of the history of 2 or more nodes, or a rollback of every node, is not detected: a double proposal is reproduced (`e2e_eth_l1_*`, ignored). | Partial: see [slashing-protection.md](slashing-protection.md) |
| Deposit signing (validator onboarding) | A `DEPOSIT` request is accepted only by a node started with `--enable-deposit-signing` (off by default). The state machine requires an activated key and a message for that key, and signs one deposit message per key, ever: whoever reaches such a node's API first chooses the withdrawal credentials of the key's first deposit, and nobody can replace them through the signer afterwards. The domain is the specification's (genesis fork version, no genesis validators root). | Implemented, tested (`slashing::tests`, E2E-ETH-10, the devnet deposit) |
| Integration environment exposure | Kurtosis 1.22.2's engine publishes its container-creating API on `0.0.0.0` with no option to change it, and Docker's published ports bypass a host firewall. The devnet integration therefore runs inside one Docker-in-Docker container, alone on its own network and publishing nothing; the signer's HTTP API stays loopback-only. Found on the test server, where the engine was started directly once, for about 20 seconds, then stopped. | Mitigated in `integration/ethereum/scripts/env.sh` ([ethereum-devnet.md](ethereum-devnet.md)) |
| Signing-domain separation | Ethereum signatures use the POP ciphersuite DST over the raw root. The internal domain uses another DST, and nothing exposed signs in it. DKG transcripts are signed with the ed25519 node keys. | Implemented, tested (unit, blst) |

## Signing authorization binding

The signing transport is shared by validator duties and development requests, so whether a
partial signature can only be produced for the authorization it claims was audited end to end. The
partial and group signatures cover the 32-byte signing root alone, as Ethereum requires, so
nothing else can be bound cryptographically into them. The binding is structural: who signs, with
which share, and under which committed authorization.

| Property | How it is bound |
| -------- | --------------- |
| Validator public key | Wire request `AuthorizationRef::Duty {validator}` (in the request id). The keyholder requires `(key, root)` among the key's records. The coordinator checks the ceremony's group key is the key. |
| Active ceremony id and round | The keyholder resolves the ceremony id to its round and requires it to be the round holding the key, and the ceremony to be a validator key's. |
| Ethereum chain identity | The state machine refuses roots for another chain than the activated one. The domain of the root contains the genesis validators root. |
| Duty type | The domain of the root (domain type) and the object; slashing rules per type. |
| Signing root | Computed by every node from the typed duty; compared, never taken from the client. |
| Durable authorization | The slashing record itself (one entry), committed with its block; the keyholder's set is derived from the records. |

Adversarial coordinator scenarios (a request from the network goes through the same check as the
node's own coordinator; tests: `tests/eth_duties.rs::byzantine_coordinators_cannot_sign_unauthorized_duties`,
`isolated_node_cannot_authorize_a_conflict`, E2E-ETH-9 over real p2p):

| Scenario | Before (protocol 1) | Now (protocol 2) |
| -------- | ------------------- | ---------------- |
| 1. Reuse another validator's authorization | Rejected by an explicit check: duty roots were scoped to the ceremony round | Rejected by explicit checks: the validator key in the request must be held by that round, and the root must be among that key's records (`not_authorized`) |
| 2. Reuse another ceremony's authorization | Rejected (round scope) | Rejected: round and key checks; a development ceremony refuses any duty request (`wrong_purpose`) |
| 3. Reuse one from a previous ceremony round of the validator | Impossible by construction (no resharing; a new ceremony has a new key), but an old round's in-memory roots were not invalidated if a key's round changed | Rejected by an explicit check: the key's current round only; still unreachable (no resharing) |
| 4. Ask a keyholder that has not applied the authorization | Rejected (`not_authorized`, request parked until applied) | Same |
| 5. Ask for an unauthorized root | Rejected | Rejected |
| 6. Use `nonce = 0` to mix development and duty authorizations | **Possible, harmless:** the duty check ignored the nonce, so a "development" request with any nonce for an authorized duty root got a partial; purpose separation rested on the state machine never creating development authorizations for validator rounds | Rejected by an explicit check: the request names its kind; a development request to a validator ceremony is `wrong_purpose`, whatever the nonce and root |
| 7. Use a development ceremony to sign with a validator key | Impossible by construction (each ceremony has its own key and shares); `Sign` on a validator ceremony refused by the state machine | Same, plus `wrong_purpose` at the keyholder |
| 8. Reuse a root after the validator's active ceremony changed | Unreachable (no resharing); after a restart only the current round was rebuilt, before it the old round kept its roots | Rejected by an explicit check (current round only); unreachable |

None of the "before" cases could produce a signature that was not already authorized for that
validator key. The change makes every binding an explicit check at the keyholder instead of a
consequence of invariants elsewhere. The protocol version is bound into every request id: nodes
of different versions do not sign for each other.

## Key import

An existing key is split by a trusted dealer ([key-import.md](key-import.md)). What the network
checks, and what it cannot:

| Question | Answer | Status |
| -------- | ------ | ------ |
| Does the split give the original key? | The manifest's constant commitment must be the validator key (checked by the dealer, at registration by consensus, and by each node opening its share); each share must match the commitments. Any 3 shares give exactly the original key's signatures; 2 give nothing. | Implemented, tested (`tests/key_import.rs`, E2E-IMP-1 against blst with the original secret) |
| Can a node install another node's share, a share of another split, or a modified one? | No. An envelope is HPKE-sealed to one node's X25519 key, with the manifest digest, ceremony, index, identity and recipient key in HPKE's `info` and the AEAD's associated data; the node checks each before decrypting, and the decrypted share against the registered commitments. | Implemented, tested (`envelopes_open_only_for_their_node_manifest_and_ceremony`, E2E-IMP-1) |
| Can a coordinator or one node claim that shares were installed? | No. Each keyholder acknowledges its own share with an ed25519 signature under its consensus key (own namespace, round, manifest digest); consensus counts only valid acknowledgments of committee members. Activation needs the threshold. | Implemented, tested (E2E-IMP-1, `storage::tests::validator::imported`) |
| Can an imported key sign before its history is imported, or for another chain? | No. Only `ActivateImportedValidator` activates it, decided by consensus once the history is imported for that chain, 3 shares are acknowledged and the acknowledgment is complete; `ActivateValidator` refuses it. Every duty is then checked against the activated chain. | Implemented, tested |
| Can the history be reset or weakened? | No command removes a key or its records. A key is registered once (another registration is refused, whatever the ceremony id). Imports merge floors by maximum: an older or repeated interchange changes nothing. A startup check refuses import state that is inconsistent with the ceremony or the activation. | Implemented, tested (`interchange::tests`, `storage::tests::validator::imported::altered_import_state_fails_closed`) |
| Is there a separate signing path for imported keys? | No. The coordinator and keyholders use the ceremony's `Sharing`, whatever its origin; the authorization, binding and slashing checks are the same, plus the floors. | By design |
| Secrets in files and logs | No plaintext share in any file; shares and share-encryption keys never logged; passwords only from the terminal or a file; output files `0600` in a new `0700` directory, never overwritten; the node refuses a share-encryption key readable by others. Zeroization is best effort (`Zeroizing` buffers; library and OS copies are not controlled). | Implemented, tested (`keytool_splits_a_keystore_into_four_encrypted_shares`) |
| Can a client weaken or block an imported key's history? | Weaken: no, an import only raises floors. Once the key is activated, the state machine refuses every import, and no other command writes its floors. Block: before the activation, yes, for good: an interchange with a far-future slot or epoch stops the key, and no command lowers floors; any API client can submit one (no authentication). | Implemented, tested (`no_history_is_imported_once_the_key_is_activated`, `an_activated_imported_key_keeps_its_floors_whatever_the_command`, E2E-IMP-1); the pre-activation window is documented (audit L-17) |
| Does an export keep its protection in another signer? | Against a reference implementation of EIP-3076's conditions, yes (randomized test); Lighthouse's import, read in its source, is stricter. No other client has imported one, and an export taken while the network signs can be stale. | Modeled, not tested ([slashing-protection.md](slashing-protection.md#compared-with-eip-3076)) |
| Two signers for one key | **Not detectable.** The original keystore still exists; whether the previous signer is stopped is the operator's statement (the acknowledgment), recorded but not verified. A duplicate signer is slashable whatever this network does. | Operational ([key-import.md](key-import.md#assumptions)) |

## Not provided

- Slashing protection that survives a rollback of every node (an anchor is proposed in
  [slashing-protection.md](slashing-protection.md), not implemented). It applies to imported keys
  unchanged (L-1).
- Detection of a second signer of an imported key outside the network.
- Slashing protection for the development API (`dev-api` builds; nonces are caller-chosen).
- Client authentication, authorization policy, rate limiting.
- Encryption of shares at rest, HSM or TEE isolation.
- Protection against more than `f` Byzantine or rolled-back nodes.
