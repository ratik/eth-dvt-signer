# Security review: signing path

Scope: consensus-backed authorization, Ethereum validator duties and their slashing protection, the
signing protocol, the coordinator and the keyholder, as this repository implements them. The
adversarial test campaign, its findings and fixes, and the fault-model table are in
[audit.md](audit.md).

## Assumptions

- **Consensus** (simplex): at most `f = 1` of the 4 voters is Byzantine. Finalized blocks are never
  reverted. The network is eventually synchronous; liveness needs it.
- **Threshold** 3 of 4: any 3 shares sign, 2 cannot. A Byzantine node holds one share.
- **p2p** (commonware `lookup`): authenticated and encrypted. Only the keys of the configured nodes
  (the committee and the configured followers) can connect.
- **Storage**: a `Metadata` commit is atomic, and durable once `sync` returns. A node's data
  directory has mode `0700`. The state is not encrypted at rest. With a sealed vault
  (`--vault gcp-tdx`) the secrets are.
- **Clients**: the API does not authenticate clients. Anyone who reaches a node's loopback HTTP
  API, or holds a certificate of the operator's CA for its mTLS API, can have duties authorized and
  signed, within slashing protection and the time horizon. In `dev-api` builds they can also sign
  any payload under a development key. Protected operations need the approvers' offline signatures
  instead ([administration.md](administration.md)): activation, imported-key registration, reshare
  to new keyholders, reconfiguration, EIP-3076 history import, voluntary exits, deposits and the
  registration policy.
- **Clocks**: each node's system clock is within about 2 s of the true time, except on at most one
  voter. The clock bounds which duties enter consensus (the time horizon). It never changes what a
  block does to the state ([ethereum-signing.md](ethereum-signing.md#time-horizon)).
- **Approvers**: fewer than the threshold of approver keys are compromised, and approvers read what
  they sign.
- **Ethereum network**: every node runs with the same network flags (`--eth-network`, or the same
  `--eth-genesis-*` and `--eth-fork-schedule` values). A duty's `fork_info` must follow the pinned
  fork schedule (P0.3). The network's identity is part of the cluster id that approvals sign, and
  the replicated state records it with the protected commands. A node started for another network
  refuses to start.

## Findings

| Question | Answer | Status |
| -------- | ------ | ------ |
| Authorization races: can a node sign after it sees an authorization but before the authorization is durable? | No. Only the keyholder (`dkg::actor::partial`) makes partials, and only for an authorization in its committed state: a `storage::Committed` value, or a duty authorization of a committed block. The store creates these only from disk, or after `sync` returns. The executor hands them to the keyholder after the sync and before it answers any client, so the node's own coordinator queues behind them. A remote request that arrives first is refused (`not_authorized`) and parked. | Implemented, tested (unit, `tests/signing.rs`, E2E-9) |
| State rollback after a crash: can a node restart from older state and sign a conflicting payload? | No. A crash leaves the old state or the new one, never a mix. A node signs an authorization only after its commit completes, so anything it signed is on its disk. A lost commit was never signed from. On restart the node applies the finalized chain again (its own archive, then its peers), which gives the same authorizations. | Implemented, tested (E2E-5, E2E-6, restart tests) |
| State rollback by an attacker (a whole storage snapshot restored) | See [Storage rollback by an attacker](#storage-rollback-by-an-attacker). | One node: tested. A quorum: detected with the anchor (tested, `anchor::an_1` to `an_6`; limits in audit L-29). Without the anchor, not detected (audit L-1); the restart floor still refuses double proposals and double votes. |
| Coordinator equivocation: partials for two payloads under one nonce? | No. Each participant checks its own committed authorization and signs the stored payload, whatever the request says. Consensus never commits two payloads for one `(ceremony, nonce)`. A malicious coordinator holds one share. | Implemented, tested (`tests/signing.rs`, E2E-3, E2E-7) |
| Participant spoofing | A partial's share index must equal the authenticated sender's index in the ceremony. The partial must verify against that index's public share. A forged index is rejected and counts as a strike against the sender. | Implemented, tested (`tests/signing.rs`, E2E-8) |
| Cross-ceremony replay | The request id binds the ceremony. Partials verify against that ceremony's public polynomial, so another ceremony's partials fail. | Implemented, tested |
| Cross-request replay | Responses are routed by request id: a hash of the protocol version, the ceremony, the authorization reference (a nonce, or a validator key) and the payload. A response for another request never reaches this one. A partial binds only the payload (the Ethereum root), so two authorizations of the same root give the same signature. This is harmless. | By design, documented |
| Stale nodes | A lagging node refuses everything it has not applied. It may sign an applied finalized authorization while it catches up, because finalized authorizations never change. It reports why it is not ready and does not submit new authorizations (`NOT_READY`). Readiness never claims that the node has the network's latest block ([recovery.md](recovery.md)). | Implemented, tested (E2E-9, `tests/signing.rs`) |
| State partition behind the finalized history (newest copy torn, deleted, or restored alone) | The node refuses to start when its state is behind marshal's processed height. At run time the executor refuses a block that is not the next height. Either way the node exits with status 1, instead of skipping blocks and diverging. A key share without its ceremony in the state, or a missing consensus journal, also stops it at start. Copies that fail their integrity check are saved to `registry-diagnostics` before the stores open. | Fixed in the audit (BUG-2, H-2, H-4), tested (`f4_*`, `r5_*`) |
| A Byzantine participant against liveness | With 3 honest signers online, one Byzantine participant cannot stop signing. After 3 invalid responses to a request, the coordinator ignores it for that request. It counts once, however it fails (BUG-1, fixed). It cannot spoof or ban others. With only 3 online, the Byzantine one included, signing may fail; safety holds. | Implemented, tested (E2E-8, `tests/signing.rs`) |
| Resource exhaustion | Bounded: see [Resource limits](#resource-limits). Not bounded: HTTP clients can create authorizations and slashing records without limit (consensus and storage cost; no client authentication or rate limit). Authorizations and slashing history are kept forever. Only the p2p quota limits the keyholder's mailbox. | Partly mitigated, documented |
| A validator key signing an arbitrary root | No. The client sends a typed duty. Every node computes the signing root from the finalized command (`DutyRequest::signing_root`), never from a client's or a coordinator's root. A keyholder signs a root only if `(key, root)` is among the key's committed duty authorizations and the request names the key's active ceremony round. A client `signingRoot` that differs is refused before anything is decided. | Implemented, tested (`tests/eth_duties.rs`, E2E-ETH-1) |
| A Byzantine coordinator pairs harmless duty fields with a conflicting root | Not possible. The command has no root field. The root is a function of the duty and `fork_info`, and every node computes it again. | By construction |
| Conflicting slashable duties (double proposal, double vote, surround vote) sent at once through different nodes | Consensus orders the commands. On every node the state machine authorizes the first and refuses the second (`412`), over the validator's whole history. A command that a node submits directly, without its coordinator's checks, is decided the same way. | Implemented, tested (`slashing::tests`, `tests/eth_duties.rs`, E2E-ETH-2) |
| Slashing record and authorization out of step | Not possible. Both are written in the one atomic commit of their block. The keyholder learns of a duty only after that commit. At start, the committed state seeds it. | Implemented, tested (crash points, E2E-ETH-4) |
| A validator key through the development API, or a development key through the Web3Signer API | No. Consensus fixes the purpose when the ceremony starts. The state machine refuses a `Sign` command on a validator ceremony (`ValidatorKey`). A development key is not a validator (`404`). Default builds do not compile the development API. | Implemented, tested (`storage::tests::validator`, E2E-ETH-1, `tests/production_api.rs`) |
| Cross-validator and cross-purpose replay | A duty authorization belongs to one validator key, and a keyholder signs it only in that key's active ceremony round. Another validator's ceremony, or a development authorization of the same bytes, does not sign it. | Implemented, tested (`tests/eth_duties.rs`) |
| Chain confusion | A validator key signs nothing until an explicit activation for one chain (its genesis validators root). Consensus decides the activation. It is stored with the key and never changes. Duties for another chain are refused, and the signing domain also separates chains. A wrong first duty cannot pin the wrong chain. State of the previous version (chain pinned by the first duty) reads as not activated; the key must be activated explicitly, for the same chain. | Implemented, tested (`slashing::tests`, `tests/eth_duties.rs`, E2E-ETH-1, E2E-ETH-8) |
| Slashing history lost or altered on disk | Startup refuses missing or extra records (counts per validator), unknown validators, keys that do not match their ceremony, and corrupt entries. Randomized single edits confirm this. One gap: a record whose content is rewritten consistently (an attestation's source lowered) starts, and can then accept a surround vote it refused. That is one node, which consensus tolerates (L-30, `storage::tests::model::hostile_storage_*`). Without the anchor, a consistent rewrite of the history of 2 or more nodes, or a rollback of every node, is not detected: without the restart floor, a double proposal is reproduced (`e2e_eth_l1_*`, ignored). With the anchor, a rollback of every node is detected ([anchor.md](anchor.md)). | Partial: see [slashing-protection.md](slashing-protection.md) |
| Malformed input from peers, API clients, the anchor or the disk: a crash, unbounded memory, or one value decoded from two byte strings? | Every decoder and parser that such input reaches is a fuzz target, built with AddressSanitizer and debug assertions: peers (transactions, blocks, signing and DKG messages), API clients (Web3Signer requests, EIP-3076 imports, signed commands), the anchor (records, acknowledgments), the disk (state values, epoch records, secrets, manifests) and operator tools (peers files, attestation statements and tokens). The properties: no panic, no allocation above 2 GB, no input over 10 s, one encoding per value for network messages, and an exact round trip for stored values. `cargo test` replays every input found (`tests/unit/fuzzing.rs`). | Fuzzed ([audit.md](audit.md), "Fuzzing, a model test and hostile storage"); each validation runs every target for 30 s (`fuzz-smoke`) |
| Deposit signing (validator onboarding) | A node accepts a `DEPOSIT` request only when started with `--enable-deposit-signing` (off by default). It signs only with the approvers' authorization over the exact withdrawal credentials, amount and genesis fork version (P0.2), which every voter checks. The state machine requires an activated key and a message for that key, and signs one deposit message per key, ever. The domain is the specification's: the pinned genesis fork version, and no genesis validators root. | Implemented, tested (`slashing::tests`, E2E-ETH-10, `exits::p02_1`, the devnet deposit) |
| A voluntary exit or deposit by one faulty node (L-26) | Not possible since P0.2. Both are protected commands: approvals over the exact duty, its fork context and signing root, with the next nonce. Honest leaders and voters refuse them bare or forged. A keyholder signs such a root only if the state records it as approved, so a faulty coordinator gets no partial for an unapproved one, or for a bare one from old history. Once approved, a root signs again without approvals (retries, restarts, epochs). Before P0.2, one faulty node could exit any validator. | Fixed (P0.2), tested (`exits::p02_1`, `tests/unit/storage.rs`, `tests/unit/admin.rs`) |
| Signing under a domain the client chooses (`fork_info`, L-12) | Not possible since P0.3. The API, honest leaders and every honest voter refuse a duty whose `fork_info` is not a fork of the pinned schedule, or names another version at the duty's domain epoch (exits after Deneb: Capella's; deposits: the genesis version, no root). Nothing is corrected. A keyholder signs only the authorized root, which encodes the checked domain. | Fixed (P0.3), tested (`tests/unit/eth/network.rs` with Lighthouse's requests, `forks::p03_1`) |
| A builder registration that diverts MEV payments (`VALIDATOR_REGISTRATION`) | Not outside the approved policy. A registration is signed only if the registration policy in force allows its fee recipient and gas limit, and its timestamp is within the policy's window. The policy is a protected command, applied in block order. The API, honest leaders, every honest voter, the block application and every keyholder check it, a retry included. A faulty leader's block with a refused registration, or with more than 16, is not notarized. A faulty coordinator gets no partial for an unauthorized registration, or for one the policy no longer allows. Within the policy, an API client chooses among its fee recipients (audit L-27). Before Gloas, the fee recipient of a locally built block is not covered. | Implemented, tested (`registrations::reg_1`, `reg_2`, `tests/unit/storage.rs`, `tests/unit/eth/registration.rs`) |
| Gloas: a payload or a PTC vote that is not the validator's (`EXECUTION_PAYLOAD_ENVELOPE`, `PAYLOAD_ATTESTATION_MESSAGE`, `PROPOSER_PREFERENCES`) | An envelope is signed only for a self-built payload of the block that the validator's authorized history holds for that slot, once per slot, and only if the registration policy allows the payload's fee recipient. From Gloas on, this covers the fee recipient of a locally built block. One PTC vote per slot. Preferences only under the policy. The block binding and the one-per-slot rules are rules of the replicated state. The policy is checked where registrations are checked (API, leader, voters, block application, keyholders, a retry included). A faulty leader's envelope without its block, or a second vote, is applied as a refusal. A faulty coordinator gets no partial. None of these is slashable in Gloas; the rules keep two quorums of shares from signing two different payloads or votes for one slot. Lighthouse does not retry a refused envelope or vote (audit L-28). | Implemented, tested (`gloas::gl_1` to `gl_5`, `tests/unit/slashing.rs`, `tests/unit/storage.rs`, `tests/unit/eth/gloas.rs`) |
| Integration environment exposure | Kurtosis 1.22.2's engine publishes its container-creating API on `0.0.0.0`, with no option to change it, and Docker's published ports bypass a host firewall. So the devnet runs inside one Docker-in-Docker container, alone on its own network, and publishes nothing. The signer's HTTP API stays on loopback. Found on the test server, where the engine was once started directly, for about 20 seconds, then stopped. | Mitigated in `integration/ethereum/scripts/env.sh` ([ethereum-devnet.md](ethereum-devnet.md)) |
| A far-future duty that poisons the history (a surrounding attestation, a full period, far-future import floors) | Not while at most one voter is faulty or has a wrong clock. The API, honest leaders and every honest voter refuse a duty or import whose slot or epochs have not started by their own clock (2 s leeway, 4 s for voters; non-slashable duties: at most two epochs ahead). A keyholder also refuses an early partial. The state machine never reads a clock, so clock disagreement costs votes, never divergence. | Implemented (P0), tested (`tests/unit/eth/horizon.rs`, `horizon_1` to `horizon_3`, `e2e_imp_1`) |
| Unauthorized administration (activation, imported-key registration, reshare to new keyholders, reconfiguration, EIP-3076 history import, exits, deposits, the registration policy) through the unauthenticated API, a faulty leader or gossip | Not possible. Each needs a threshold of approvers' Ed25519 signatures over the cluster id, the exact command and the next administrative nonce. An import's approvals bind every floor it sets and, through the interchange digest, every record. They lift no slashing-protection or horizon check. Every honest voter checks the approvals, and the exact nonce, before it votes. A bare, forged, replayed, stale or skipped-nonce command is never notarized, and only an approved reconfiguration ends an epoch. Block application checks again and stops the node on a mismatch. | Implemented (P0; imports P0.1), tested (`tests/unit/admin.rs`, `tests/unit/storage.rs`, `admin_1`, `admin_2`, E2E-IMP-1, R3-1, R3-7, R2-E2E-4) |
| Signing-domain separation | Ethereum signatures use the POP ciphersuite DST over the raw root. The internal domain uses another DST, and nothing exposed signs in it. DKG transcripts are signed with the nodes' Ed25519 keys. | Implemented, tested (unit, blst) |

### Storage rollback by an attacker

- One node restored from an old snapshot (all but its consensus journal) learns the same finalized
  history again from its peers. It refuses to sign while stale (`a1_single_node_rollback`).
- If its consensus journal is restored too, it may vote twice in a view, and its peers block it for
  an hour. It still never signs a conflicting payload (`a1_full_restore_never_signs_conflict`,
  audit L-7).
- Two rolled-back nodes converged in the tested case (`a2_two_node_rollback`). Two is beyond `f`,
  so nothing is guaranteed.
- A rollback of every node gives a second, conflicting signature for one nonce of the development
  `/sign` (`a2_whole_network_rollback`, ignored as a known limitation). Finality assumes that
  honest nodes keep their storage.
- For Ethereum duties, every keyholder's restart floor refuses a new block, attestation, PTC vote
  or envelope of a slot or epoch it may have signed for before it started. So no double proposal
  or double vote is signed after a whole-network rollback (`floor::floor_1`). Without the anchor,
  a surround vote that a client crafts is not refused.
- With the WORM anchor (`--anchor`, [anchor.md](anchor.md)), no node signs until its chain holds
  what the anchor's records name, and surround votes under the anchored marks are refused. After a
  whole-network rollback every node stops with exit status 77 (`anchor::an_2`). One node rolled
  back alone catches up (`anchor::an_3`).

### Resource limits

| What | Limit | Above the limit |
| --- | --- | --- |
| Signing request body (a Gloas envelope carries its whole payload) | 32 MiB | `413` |
| EIP-3076 import body | 64 MiB | `413` |
| Other request bodies | 2 MiB (axum's default) | `413` |
| A duty in a command (an envelope enters as its 532-byte summary) | 32 KiB | refused |
| Distinct roots per validator, non-slashable duty type and period | 8 | refused |
| Builder registrations | none per period; 16 per block; 1024 waiting per node; the policy's timestamp window | `503` when the queue is full |
| Signing requests in flight per coordinator | 256 | `503` |
| Buffered responses per signing request | 64 | dropped |
| Invalid responses per participant and request | 3 | the participant is ignored for that request and gets no retransmission |
| Parked requests at a keyholder | 256 in total, 64 per peer, 16 blocks each | dropped |
| p2p message | 1 MiB, with per-peer quotas | |
| Time to sign a Web3Signer request | 60 s | `504` |

## Signing authorization binding

Validator duties and development requests share the signing transport. So the audit checked, end
to end, that a partial signature can only be produced for the authorization it claims. The partial
and group signatures cover the 32-byte signing root alone, as Ethereum requires, so nothing else
can be bound into them cryptographically. The binding is structural: who signs, with which share,
and under which committed authorization.

| Property | How it is bound |
| -------- | --------------- |
| Validator public key | The wire request names it (`AuthorizationRef::Duty {validator}`, part of the request id). The keyholder requires `(key, root)` among the key's records. The coordinator checks that the ceremony's group key is the key. |
| Active ceremony id and round | The keyholder resolves the ceremony id to its round. It requires that round to be the one that holds the key, and the ceremony to be a validator key's. |
| Ethereum chain identity | The state machine refuses roots for a chain other than the activated one. The root's domain contains the genesis validators root. |
| Duty type | The root's domain (domain type) and the object; slashing rules per type. |
| Signing root | Every node computes it from the typed duty. It is compared with the client's, never taken from it. |
| Durable authorization | The slashing record itself (one entry), committed with its block. The keyholder derives its set from the records. |

Adversarial coordinator scenarios. A request from the network goes through the same check as the
node's own coordinator. Tests: `tests/eth_duties.rs::byzantine_coordinators_cannot_sign_unauthorized_duties`,
`isolated_node_cannot_authorize_a_conflict`, and E2E-ETH-9 over real p2p.

| Scenario | Before (protocol 1) | Now (protocol 2) |
| -------- | ------------------- | ---------------- |
| 1. Reuse another validator's authorization | Rejected by an explicit check: duty roots were scoped to the ceremony round | Rejected by explicit checks: the round must hold the validator key the request names, and the root must be among that key's records (`not_authorized`) |
| 2. Reuse another ceremony's authorization | Rejected (round scope) | Rejected: round and key checks. A development ceremony refuses any duty request (`wrong_purpose`) |
| 3. Reuse one from a previous ceremony round of the validator | Impossible by construction (no resharing; a new ceremony has a new key). But an old round's roots in memory were not invalidated if a key's round changed | Rejected by an explicit check: the key's current round only. Reachable since resharing (R1, R2): a request for a retired generation is refused (`stale_generation`; E2E-RSH-3, crash tests, R2-E2E-4) |
| 4. Ask a keyholder that has not applied the authorization | Rejected (`not_authorized`; the request is parked until applied) | Same |
| 5. Ask for an unauthorized root | Rejected | Rejected |
| 6. Use `nonce = 0` to mix development and duty authorizations | **Possible, harmless.** The duty check ignored the nonce, so a "development" request with any nonce for an authorized duty root got a partial. Purpose separation rested on the state machine never creating development authorizations for validator rounds | Rejected by an explicit check: the request names its kind. A development request to a validator ceremony is `wrong_purpose`, whatever the nonce and root |
| 7. Use a development ceremony to sign with a validator key | Impossible by construction (each ceremony has its own key and shares). The state machine refused `Sign` on a validator ceremony | Same, plus `wrong_purpose` at the keyholder |
| 8. Reuse a root after the validator's active ceremony changed | Unreachable (no resharing). After a restart only the current round was rebuilt; before a restart the old round kept its roots | Rejected by an explicit check (current round only). Now reachable through resharing, and its tests exercise it. A key's records belong to the key, so a root authorized before a reshare is signed with the new generation |

None of the "before" cases could produce a signature that was not already authorized for that
validator key. The change makes every binding an explicit check at the keyholder, instead of a
consequence of invariants elsewhere. Every request id binds the protocol version, so nodes of
different versions do not sign for each other.

## Key import

A trusted dealer splits an existing key ([key-import.md](key-import.md)). What the network checks,
and what it cannot:

| Question | Answer | Status |
| -------- | ------ | ------ |
| Does the split give the original key? | The manifest's constant commitment must be the validator key. The dealer checks it, consensus checks it at registration, and each node checks it when it opens its share. Each share must match the commitments. Any 3 shares give exactly the original key's signatures; 2 give nothing. | Implemented, tested (`tests/key_import.rs`, E2E-IMP-1 against blst with the original secret) |
| Can a node install another node's share, a share of another split, or a modified share? | No. An envelope is HPKE-sealed to one node's X25519 key. HPKE's `info` and the AEAD's associated data hold the manifest digest, the ceremony, the index, the identity and the recipient key. The node checks each before it decrypts, and checks the decrypted share against the registered commitments. | Implemented, tested (`envelopes_open_only_for_their_node_manifest_and_ceremony`, E2E-IMP-1) |
| Can a coordinator or one node claim that shares were installed? | No. Each keyholder acknowledges its own share with an Ed25519 signature under its consensus key (own namespace, round, manifest digest). Consensus counts only valid acknowledgments of committee members. Activation needs the threshold. | Implemented, tested (E2E-IMP-1, `storage::tests::validator::imported`) |
| Can an imported key sign before its history is imported, or for another chain? | No. Only `ActivateImportedValidator` activates it. Consensus decides it once the history is imported for that chain, 3 shares are acknowledged, and the operator's acknowledgment is complete. `ActivateValidator` refuses an imported key. Every duty is then checked against the activated chain. | Implemented, tested |
| Can the history be reset or weakened? | No. No command removes a key or its records. A key is registered once; another registration is refused, whatever the ceremony id. Imports merge floors by maximum, so an older or repeated interchange changes nothing. A startup check refuses import state that is inconsistent with the ceremony or the activation. | Implemented, tested (`interchange::tests`, `storage::tests::validator::imported::altered_import_state_fails_closed`) |
| Is there a separate signing path for imported keys? | No. The coordinator and keyholders use the ceremony's `Sharing`, whatever its origin. The authorization, binding and slashing checks are the same, plus the floors. | By design |
| Keys at rest and their release (sealed vault, [tee.md](tee.md)) | With `--vault gcp-tdx`, the vault makes and seals the identity, share-encryption and TLS keys (XChaCha20-Poly1305, with associated data that names the item). It also seals every value of `registry-secrets` and `registry-secrets-pending`. The data key exists on disk only wrapped by a Cloud KMS key. KMS releases it only to a TDX VM with debug disabled, the allowed RTMR1/RTMR2, and the key's own VM (by instance ID: the node's disk on another VM is refused). The KMS key and the identity provider must be the VM's own project's. A value that does not open, a plain value in a sealed store or the reverse, or a refused release stops the node. Shares are encrypted only to keys whose attestation verifies (`mpc-keytool split --attestation-policy`). `mpc-admin attest` checks fresh evidence, and that the TLS key that answered is the attested one. Limits: KMS/IAM admins, physical attacks, configuration not in the key release (L-31). | Implemented, tested against a fake of Google's services (`vault::tests`, `dkg::secrets::tests`, `attestation::verify::tests`, `tls::tests`, TEE-1 to TEE-6); on a real Confidential VM: `integration/tee` |
| The validator client's endpoint (`mpc-gateway`, [gateway.md](gateway.md)) | The gateway serves the Web3Signer signing API alone, on loopback or over mTLS with its own client CA. It reaches the nodes with the operator's certificate. It checks every signature against the validator key and the signing root it computes under its pinned chain, so it never passes on a coordinator's wrong signature. On a failure it asks the next node; it also hedges after a delay. Repeats are `AlreadyAccepted`.
A refusal is not one node's to give either: it is passed on only once two nodes agree on its
status, and a node the others contradict is marked faulty (BUG-7). It uses a sealed node only while its attestation verifies (image, project, the node's configuration), over connections pinned to the attested TLS key. It holds no key and no slashing state. It is trusted like the validator client: it can withhold duties, but cannot obtain a signature the network refuses. | Implemented, tested (`gateway::tests`, GW-1 to GW-4, every devnet run) |
| Secrets in files and logs | The key-import files hold no plaintext share: each share is HPKE-sealed to its node. A node stores its share in `registry-secrets`, unencrypted with a plain vault and sealed with a sealed vault. Shares and share-encryption keys are never logged. Passwords come only from the terminal or a file. Output files are `0600` in a new `0700` directory and are never overwritten. The node refuses a share-encryption key that others can read. Zeroization is best effort (`Zeroizing` buffers; library and OS copies are not controlled). | Implemented, tested (`keytool_splits_a_keystore_into_four_encrypted_shares`) |
| Can a client weaken or block an imported key's history? | Weaken: no. An import only raises floors. Once the key is activated, the state machine refuses every import, and no other command writes its floors. Block: not an API client. An import needs the approvers' signatures over exactly its history (P0.1). An approved import with high floors stops the key until real duties pass them, and no command lowers floors. The time horizon refuses floors whose slot or epochs have not started (P0), so a far-future interchange cannot stop the key for good. | Implemented, tested (`no_history_is_imported_once_the_key_is_activated`, `an_activated_imported_key_keeps_its_floors_whatever_the_command`, E2E-IMP-1); the pre-activation window is documented (audit L-17) |
| Does an export keep its protection in another signer? | Against a reference implementation of EIP-3076's conditions, yes (randomized test). Lighthouse's import, read in its source, is stricter. No other client has imported one, and an export taken while the network signs can be stale. | Modeled, not tested ([slashing-protection.md](slashing-protection.md#compared-with-eip-3076)) |
| Two signers for one key | **Not detectable.** The original keystore still exists. Whether the previous signer is stopped is the operator's statement (the acknowledgment), recorded but not verified. A duplicate signer is slashable whatever this network does. | Operational ([key-import.md](key-import.md#assumptions)) |

## Resharing

A validator key's shares are refreshed among its keyholders (R1), or a lost keyholder's share is
moved to a new keyholder, a non-voting follower (R2) ([resharing.md](resharing.md)).

| Question | Answer | Status |
| -------- | ------ | ------ |
| Can a reshare change the key? | No. Commonware refuses a dealing whose constant commitment is not its dealer's previous public share, and the interpolated result must keep the previous public key. The new generation's public key equals the old one byte for byte. | Implemented (commonware), tested (12 seeds, two reshares each; E2E-RSH-1, RSH-5) |
| Is the private key reconstructed? | No. Each player interpolates only its own share from the selected dealings. Nobody holds a quorum of shares. | By construction |
| Can generations be mixed? | No. A signing request names its generation. Each partial is verified against that generation's verification shares. An old share's partial fails against the new ones, and an interpolation of mixed partials does not verify. | Implemented, tested |
| Can a node sign with an uncommitted or stale generation? | No. A keyholder signs a duty only with the generation that its committed state has active. An older one is refused (`stale_generation`). A newer one is parked until the keyholder applies its activation. | Implemented, tested (E2E-RSH-3, 10 crash points) |
| Can a failed or Byzantine reshare disturb the active generation? | No. The active generation and its shares stay untouched until a committed activation. Activation requires a completed round and every new share acknowledged. An aborted or failed reshare's material is erased. | Implemented, tested (E2E-RSH-2, RSH-4) |
| Is the history preserved? | Yes. Only the validator's round changes; records, activation and import state stay. | Implemented, tested |
| Does it revoke old shares? | No. Old shares remain a valid sharing of the same key. Erasing them is best effort and operational. | Documented |
| A keyholder acknowledges readiness without a share | It is counted (consensus checks only its signature), and the new generation then works with 3 shares. Availability, not safety. | Documented, E2E-RSH-4 |
| Liveness | Every dealer and player is needed (no reveals). R1 needs all four nodes; R2 needs the three remaining keyholders and the new one. | Documented (audit L-18) |
| R2: can a single API request hand a key's shares to other identities? | No. A reshare to new keyholders is a protected command: it needs a threshold of approvers' signatures (P0). Also, no dealer deals to new keyholders without its operator's local approval of that exact key and recipient set (`--approved-reshares`), and a reshare needs at least 3 dealers. An R1, which is not protected, deals only to the keyholders it refreshes, so it cannot hand shares to anyone else, D after an R2 included (H-10). The approved reshare's ceremony id is reserved, so nobody can take it first (H-11). | Implemented, tested (`dkg::approval::tests`, R2-E2E-4, `a_refresh_after_a_replacement_deals_to_the_keyholders_not_the_committee`); audit L-20 |
| R2: can the lost node, or an old share, take part? | No. The lost node is neither a dealer nor a player of the new round. Commonware refuses its dealing, its acknowledgement does not count, and old-generation partials do not verify against the new shares. Its old share is still a share of the old generation (not revoked). | Implemented, tested (`replace::*`, R2-E2E-4); audit L-18 |
| R2: can the follower vote, lead or sign on its own? | No. Its consensus scheme cannot sign, and leaders are committee members. It serves no signing API, and it signs only duties that its own replicated state authorized. | Implemented, tested (FOL-5, R2-E2E-1, R2-E2E-2) |
| R2: is consensus fault tolerance restored? | No. The committee does not change: with one node lost, every one of the other three must be up. | Documented (audit L-19) |

## Not provided

- Slashing protection that survives a rollback of every node, without an anchor. The restart floor
  refuses double proposals and double votes, but not a crafted surround vote, and nothing detects
  the rollback. The WORM anchor ([anchor.md](anchor.md)) covers both, within its limits: degraded
  signing while it is unreachable, a detection lag of one record, one faulty writer, and a bucket
  whose WORM configuration the nodes cannot check (L-1, L-29). It applies to imported keys
  unchanged.
- Detection of a second signer of an imported key outside the network.
- Revocation of old key shares by resharing (erasure is operational), and an R1 refresh with a node
  offline (R2 replaces the node instead).
- Online consensus reconfiguration. Replacing a voter (R3) stops and restarts every node, and
  replaces one member per epoch. The approvers sign it (P0), but there is no governance or time
  lock (L-21 to L-23, L-25).
- A trusted time source. The time horizon trusts each node's system clock, with at most one wrong
  (L-24).
- Rotation or revocation of approver keys, and HSM support for them (L-25).
- Slashing protection for the development API (`dev-api` builds; the caller chooses nonces).
- Rate limiting and client roles. Protected operations need the approvers' offline signatures.
  Every other operation is open to any client of the loopback API, and to any certificate of the
  operator's CA on the mTLS API that `--revoked-client-certs` does not list (L-6).
- HSM isolation; TEEs other than a GCP Confidential VM on Intel TDX; encryption of the state other
  than the secrets (L-31).
- Protection against more than `f` Byzantine or rolled-back nodes.
