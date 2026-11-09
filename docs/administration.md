# Administration: operations signed by approvers (P0)

Some commands change who or what the network trusts. Such a **protected operation** takes
effect only with the Ed25519 signatures of a threshold of **approvers**. Approvers are the
operators' keys and stay offline. No node holds an approver key, and the HTTP API never receives
one: a node only checks approvers' signatures. Consensus accepting a block is not enough. Every
honest voter checks the approvals and the nonce before it votes, so a faulty leader cannot bring
in a protected command, signed or not, and neither can any client of the unauthenticated API.

Code: `src/admin.rs` (approver set, signed message, document), `src/types.rs` (`Command::Admin`,
tag 15), `src/application.rs` (voters and leaders), `src/storage.rs` (`admit`, the nonce),
`src/rpc.rs` (`authorization`, `GET /admin`), `src/bin/mpc-admin.rs` (the CLI).

## Protected operations

| Operation (`mpc-admin draft <operation>`) | Endpoint | Command | Why it is protected |
| --- | --- | --- | --- |
| `activate` | `POST /validators/activate` | `ActivateValidator`, or `ActivateImportedValidator` with an `acknowledgment` | Binds a key to a chain for good; a wrong chain bricks the key. For an imported key, it is the operator's statement that the previous signer is stopped. |
| `register-import` | `POST /keys/import` | `RegisterImportedKey` | Fixes the imported key's public sharing; fake commitments would block that key's import for good. |
| `reshare` with `from_round`, `dealers`, `players` (R2) | `POST /validators/reshare` | `StartResharing` with a membership | Hands key shares to new keyholders. |
| `reconfigure` (R3) | `POST /consensus/reconfigure` | `Reconfigure` | Changes the consensus voters. |
| `import-history` (P0.1) | `POST /slashing-protection/import` (not a dry run) | `ImportSlashingProtection` | Raises an imported key's slashing-protection floors for good; floors chosen by an attacker would refuse the key's real duties. |
| `sign-exit` (P0.2) | `POST /api/v1/eth2/sign/{key}` (`VOLUNTARY_EXIT`) | `Duty` of a voluntary exit | An exit cannot be undone: the validator leaves for good. |
| `sign-deposit` (P0.2) | `POST /api/v1/eth2/sign/{key}` (`DEPOSIT`) | `Duty` of a deposit | A key signs one deposit message, ever; the first deposit on chain sets its withdrawal credentials for good. |
| `set-registration-policy` | `POST /eth/registration-policy` | `SetRegistrationPolicy` | Decides which fee recipients builder registrations may name: where relays pay for the validators' builder blocks. |

Not protected, and still open to any client of the API (bound to loopback): starting a DKG
ceremony, a refresh within the committee (R1, `POST /validators/reshare` without a membership),
activating or aborting a reshare (`/validators/reshare/activate`, `/abort`), a dry run of a
history import, and signing every other duty. They change no trusted identity and no slashing
history except through signing itself. Misused, they deny service; they cannot make the network
sign a slashable message, an exit or a deposit, or give a share to a new party.

### Voluntary exits and deposits (P0.2)

Before P0.2 an exit and a deposit were ordinary duties: any client of a node's API, and any single
faulty node (by gossiping the duty or putting it into its own block), could get the network to
sign one, because honest voters authorized any well-formed duty and honest keyholders then signed
it. Now:

- **The approvals sign exactly the duty.** The signed payload is the `Duty` command's canonical
  encoding: the validator's public key, the whole `fork_info` (both versions, the fork epoch, the
  genesis validators root) and the duty's type and SSZ object: an exit's epoch and validator
  index, a deposit's public key, withdrawal credentials and amount. The signing root is computed
  from these bytes, so an approval of one signing root never authorizes another; the cluster id
  binds the cluster and, since P0.3, the Ethereum network. `mpc-admin show` prints the signing
  root, the domain and every field (for an exit, the validator index and exit epoch; for a
  deposit, the withdrawal credentials and amount) in capitals.
- **Consensus enforces it.** An exit or a deposit is a protected command
  (`DutyKind::needs_approval`): bare, honest leaders drop it and honest voters refuse a block
  carrying it; approved, voters check the approvals and the exact next nonce, as for every
  protected command. Approvals never lift a rule: slashing protection (a key's one deposit
  message, eight exit roots per epoch), the chain and the fork schedule still apply.
- **Keyholders enforce it.** The replicated state records which exit and deposit roots were
  authorized with approvals (`(validator, nonce) → (root, kind, period)`). A keyholder learns only
  approved ones (`Protection::duties_of`), so a coordinator that names an authorization without
  approval gets `not_authorized`. An exit or a deposit authorized bare in finalized history (before
  P0.2) stays recorded, counts against its period, and is never signed again unless approved
  later (the same root, approved: it becomes signable).
- **Retries.** A root approved once is signed again without approvals, through any node, after
  restarts and epoch changes, with the same signature; a new nonce is never needed for a retry.
- **The nonce.** As for P0.1, an approved exit or deposit that is finalized and then refused by
  the state machine (for example a second deposit message, or a key not yet activated) uses its
  nonce; every refusal before submission (API, coordinator) uses none.
- **`--enable-deposit-signing`** stays a node-local switch of the API (a node without it answers
  `400` to every deposit request). It is not a consensus rule; the approvals are. A node started
  without it still votes for an approved deposit.
- **The validator index** of an exit is not checked against the beacon chain (the network has no
  beacon state): an exit approved with another validator's index gives a signature that is invalid
  on chain. Approvers read the index from `show`.

```sh
mpc-admin --nodes ... draft sign-exit --validator 0x<key> --epoch 420000 --validator-index 123 \
    --output exit.json     # fork_info from the nodes' network: Capella's version after Deneb
mpc-admin show --command exit.json
mpc-admin sign --command exit.json --key approver.key --output exit-1.json
mpc-admin --nodes ... submit --command exit-1.json --command exit-2.json --output signed-exit.json
# signed-exit.json is a SignedVoluntaryExit; nothing is broadcast. To publish it:
#   curl -X POST -H 'Content-Type: application/json' --data @signed-exit.json \
#     http://<beacon>/eth/v1/beacon/pool/voluntary_exits
mpc-admin --nodes ... draft sign-deposit --validator 0x<key> --withdrawal-credentials 0x01.. \
    --amount 32000000000 --output deposit.json   # the credentials are never inferred
```

`submit --output` writes the deposit data (with `deposit_message_root` and `deposit_data_root`)
for a deposit. The Web3Signer endpoint takes the approvals as `authorization` beside the usual
request; without them it answers `403` for a root not approved yet.

### Builder registration policy

A builder registration (`VALIDATOR_REGISTRATION`) names the fee recipient relays pay for the
validator's builder blocks. Validator clients sign one at every restart, so the approvers approve
a policy, not each registration ([ethereum-signing.md](ethereum-signing.md#builder-registrations)):

- **What is signed.** The whole policy: the fee recipients (sorted; at most 64; none means no
  registration is signed), the gas limit range, `max_future_seconds` and `max_age_seconds` (how
  far a registration's timestamp may be from the nodes' clocks; default 30 and 3600). `show`
  prints every field and the policy's digest.
- **When it applies.** From the transaction after the one that sets it, in block order, on every
  node; it replaces the previous policy whole. A registration before it in the same block is
  decided by the previous policy. Without any policy, nothing is signed.
- **Retries.** A registration authorized under an earlier policy is refused, on a retry too, once
  the policy in force does not allow it (API, voters, block application, keyholders). A signature
  already returned stays valid.
- **The window and validator clients.** A client with a fixed registration timestamp (Lighthouse's
  `--builder-registration-timestamp-override`) is refused once that timestamp is older than
  `max_age_seconds`: raise it for such a client.
- **Status.** `GET /eth/registration-policy` answers the policy in force, its digest and the height
  it is read at; `mpc-admin status` shows each node's digest, and `submit` waits until every
  answering node applies it.
- **Gloas.** From Gloas on the same policy also decides on proposer preferences (their fee
  recipient and target gas limit) and on the envelopes of self-built payloads (their fee
  recipient), with the same order and retry rules
  ([ethereum-signing.md](ethereum-signing.md#gloas)). Without a policy, a self-built Gloas block
  loses its payload: set one before the fork. The node logs a warning at start, and
  `mpc-admin status` prints one (with each node's Gloas epoch), while Gloas is scheduled and no
  policy is set. The range must cover the target gas limit the validator client asks for in its
  preferences.

```sh
mpc-admin --nodes ... draft set-registration-policy --fee-recipient 0x<address> \
    --gas-limit-min 30000000 --gas-limit-max 60000000 --output policy.json
mpc-admin show --command policy.json
mpc-admin sign --command policy.json --key approver.key --output policy-1.json
mpc-admin --nodes ... submit --command policy-1.json --command policy-2.json
```

### EIP-3076 history imports (P0.1)

An import is approved over exactly what consensus applies, with no new hashing layer: the signed
payload is the `ImportSlashingProtection` command's canonical encoding,

```text
genesis validators root (32) ‖ interchange digest (32) ‖ varint count ‖
  count × (validator key (48) ‖ latest block: 0 | 1 ‖ slot ‖ signing root option
                              ‖ latest attestation: 0 | 1 ‖ source ‖ target ‖ signing root option)
```

- The summaries (the keys imported, in the request's order, and the floors each one gets) are
  what the state machine applies; they are signed directly.
- The interchange digest binds every other record: it is the SHA-256 of the parsed, validated
  interchange (every validator, every block and attestation, the chain), so a change to any
  record, even one below the floors, changes the signed bytes. It does not depend on the JSON's
  formatting: the same history written otherwise is the same command.
- The node builds the command from the request (`{"interchange", "validators"}`) as `mpc-admin`
  does, and checks the approvals against it: approvals of another history, another key selection,
  another chain or another operation do not verify (`403`).

Approvals do not lift any rule. An approved import is still parsed strictly, checked against the
network's records (`409` for a conflict, another chain, an activated key), and bounded by the
time horizon (`400`), by the API and, for the horizon, by every voter. All of this happens before
the import is submitted, so a refused import uses no nonce. Several validators in one import are
applied together or not at all. The one exception: an approved import that is finalized and then
refused by the state machine (the state changed between the API's check and the block, or the
command never went through the API) uses its nonce without changing any floor. Voters must know
the next nonce before they vote, without knowing that outcome.

A dry run (`"dry_run": true`) changes nothing and needs no approvals. A bare import, the form
used before approvals existed, is refused in new blocks and still applied from finalized
history.

## Approvers

Every node is started with the same approver file (`--approvers approvers.json`):

```json
{"threshold": 2, "approvers": ["0x<ed25519 public key>", "0x...", "0x..."]}
```

- From 1 to 8 distinct keys. The threshold is more than half of them and at most all of them
  (`2 of 3`, `3 of 4`, `3 of 5`, ...).
- A node without the file takes no protected operation. Its API answers `503`, its leader drops
  such commands, and its voter refuses blocks that carry them. A finalized one stops it (below).
- The replicated state records the set's digest with the first protected command it applies.
  A node started later with another set, or with none, refuses to start (`StartError::Approvers`,
  exit status 1): "the replicated state applied administrative nonce N under approver set 0x..,
  but this node is started with approver set 0x..". Restore the network's file.
- The **cluster id** is the SHA-256 of `"eth-mpc-signer/cluster/v1"`, the epoch 0 committee's
  keys (`--participants`), and the approver set's digest (SHA-256 of
  `"eth-mpc-signer/approvers/v1"`, the threshold byte, and the sorted keys). Approvals are bound
  to it. They are not valid on another network, or under another approver set of the same
  network.
- **Rotation is not implemented.** Changing the set changes the cluster id, and the nodes refuse
  to start against the recorded digest. Rotating would need a protected command of its own.
- Approver keys are created by the approvers themselves (`mpc-admin approver-key`), on their own
  machines, owner-only files. Nothing creates, distributes or stores them for anyone; there is no
  HSM support. A node never needs one.

## What an approver signs

```text
cluster_id (32 bytes) ‖ version (u16 BE, 1) ‖ command tag (u8) ‖ nonce (u64 BE)
  ‖ payload length (u32 BE) ‖ payload
```

The payload is the protected command's canonical encoding without its tag: every field the
node will apply. The signature is Commonware's namespaced Ed25519 with the namespace
`_ETH_MPC_SIGNER_ADMIN`. The bytes signed are `varint(len(namespace)) ‖ namespace ‖ message`, so
they never collide with consensus or p2p signatures.

On the wire a protected command travels as `Command::Admin` (tag 15):
`15 ‖ varint nonce ‖ the protected command (with its tag) ‖ varint count ‖ count × (approver
index u8 ‖ 64-byte signature)`. The indices refer to the sorted approver set. Approvals are
sorted by index, each index once, 1 to 8 of them. Only a protected command can be wrapped, and
only once: a nested tag 15 is refused before it is read, so decoding cannot recurse.

## The nonce

The replicated state holds the last administrative nonce applied (0 before the first). A
protected command is valid only with exactly the next one. So a signed command applies once, and
signed commands apply in their nonce order. The nonce is kept across consensus epochs (R3) and
restarts. The digest of the approver set is stored with it.

- **API:** a nonce at or below this node's last applied one is refused with `409`. A later one is
  accepted, since earlier commands may still be on their way, and waits in the mempool.
- **Leader:** it proposes approved commands only in consecutive nonce order, from its applied
  nonce plus the commands of its not yet applied ancestors. It drops a command whose nonce is
  used, or whose approvals do not verify. A reconfiguration goes alone in its block.
- **Voter (the security boundary):** it refuses a block carrying a bare protected command, an
  approval that does not verify, or nonces that are not exactly the next ones. "Next" is computed
  from its executor's applied height and nonce, read together, plus the protected commands of the
  block's ancestors it has not applied yet. If it cannot compute the next nonce (a parent below its
  applied height, or more than 1,024 unapplied ancestors), it refuses the block. That costs only
  its vote.
- **Apply:** a finalized protected command is checked once more: the next nonce, and approvals
  valid under this node's set. A failure means this node's configuration or state is not the
  network's. The node stops (a panic) rather than diverge.

Why exact matters: a reconfiguration ends its epoch as soon as a block carrying it is a parent
([reconfiguration.md](reconfiguration.md)). If a reconfiguration whose nonce was used could be
notarized, honest nodes would refuse its children, and the epoch could freeze on a command that
will never apply. Exactness at vote time means such a block is never notarized.

## The terminal guard

Only a reconfiguration **with approvals** ends an epoch (`epochs::reconfiguration`). A bare one
is no reconfiguration: honest voters refuse its block, and it ends nothing. In addition, a node
treats a parent as the epoch's end only if that parent's approvals verify under its own set. An
unauthorized `Reconfigure` from a faulty leader therefore cannot trigger the guard or stop the
network (test `admin_2`).

## The signed command document

`mpc-admin` and the approvers exchange one JSON document per operation:

```json
{
  "version": 1,
  "cluster_id": "0x5f1c..",
  "operation": "activate",
  "nonce": 4,
  "request": {"public_key": "0xa1b2..", "genesis_validators_root": "0x0470.."},
  "description": "activate validator 0xa1b2.. for the chain with genesis validators root 0x0470..",
  "message": "0x5f1c..0001..",
  "approvals": [{"approver": "0x<public key>", "signature": "0x<64 bytes>"}]
}
```

- `request` is the endpoint's body without `authorization`. The node builds the command from the
  same body, so what is signed is what is applied.
- `description` and `message` are derived from `cluster_id`, `nonce` and `request`. `show`,
  `sign` and `submit` derive them again and refuse a document whose fields were edited after
  drafting.
- The API receives the request with an `authorization` field:
  `{"nonce": 4, "approvals": [{"approver": "0x..", "signature": "0x.."}]}`. For `/keys/import`
  the body is `{"manifest": <manifest.json>, "authorization": {..}}`.

`GET /admin` returns `configured`, `cluster_id`, `threshold`, `approvers`, `approvers_digest`,
`nonce` (the last applied) and `next_nonce`.

API answers for a protected request: `403` without `authorization`, or with approvals that are
too few, repeated, unknown or do not verify; `409` for a used nonce; `503` on a node without an
approver set. Answers that do not depend on approvals come first: `400` for a malformed or
invalid request, `200` for an activation that already exists, `409` for one on another chain.

## CLI workflow

```bash
# Each approver, once, on its own machine: a new key (never overwritten), and its public key.
mpc-admin approver-key --output approver.key           # prints 0x<public key>
mpc-admin approver-public-key --key approver.key

# The operators write approvers.json with those public keys and a threshold, and start every node
# with --approvers approvers.json.

# Online: draft for the network's cluster and next nonce (from GET /admin on every node).
mpc-admin --nodes 127.0.0.1:8080,127.0.0.1:8081,127.0.0.1:8082,127.0.0.1:8083 \
  draft activate --request '{"public_key": "0xa1b2..", "genesis_validators_root": "0x0470.."}' \
  --output activate.json

# Each approver, offline: read the exact operation, then sign (asks to type "yes"; --yes skips).
mpc-admin show --command activate.json --approvers approvers.json
mpc-admin sign --command activate.json --key approver.key --output activate-alice.json

# Online: submit with the approvals of every copy (merged; the copies must be the same command).
mpc-admin --nodes ... submit --command activate-alice.json --command activate-bob.json
```

`--request` takes JSON or `@file`. Operations: `activate` (add `"acknowledgment"` for an imported
key), `register-import` (`{"manifest": ...}`), `reshare` (`public_key`, `ceremony_id`,
`from_round`, `dealers`, `players`), `reconfigure` (`remove`, `add`; `epoch` defaults to the next
one), `import-history` (`--interchange <file>` and optionally `--validator <key>`, repeatable,
instead of `--request`):

```bash
mpc-admin --nodes ... draft import-history --interchange interchange.json \
  --validator 0xa1b2.. --output import.json
mpc-admin show --command import.json      # a summary, not the whole interchange:
#   validators affected: 1 (of 1 in the interchange)
#     0xa1b2..: 412 blocks (slots 9..=8191), 6400 attestations (sources 0..=255, targets 1..=256);
#     floors: block slot 8191, attestation source 255 target 256
#   total: 412 block proposals (slots 9..=8191), 6400 attestations (sources 0..=255, targets 1..=256)
#   genesis validators root 0x..; interchange digest 0x.. (every record of the interchange)
#   signed bytes SHA-256: 0x.. (215 bytes)
```

`show` prints, for every operation, the SHA-256 of the exact bytes signed next to those bytes.

Replacing a consensus voter (R3) keeps its checks and its follow-up:

```bash
mpc-admin --nodes ... replace-node --old 3 --new 4 --output replace.json   # checks, drafts
# approvers sign replace.json offline, as above
mpc-admin --nodes ... replace-node --command replace-alice.json --command replace-bob.json
mpc-admin --nodes ... resume                                                # unchanged
```

`mpc-admin status` also shows each node's administrative nonce.

## Recovery after an interrupted operation

| Situation | What to do |
| --- | --- |
| A history import refused (`403`, `409`, `400`) | Nothing was submitted: no nonce used, no floor changed. Fix the cause; the same signed document stays valid while the network's nonce has not moved. |
| Drafted, not yet submitted | Nothing happened. If the network's nonce moved meanwhile (`GET /admin`), draft and sign again: the old document is stale. |
| Submitted, the API timed out (`504`) | Read `GET /admin` on every node. If the nonce reached the command's, it applied: check the operation's state (`/validators`, `/keys/import/{id}`, `/validators/reshare/{id}`, `/consensus`). A second submission is refused (`409`). If the nonce did not move, submit the same document again: it is still valid. |
| Two commands signed with the same nonce | Only the first one finalized applies. The other is dropped by leaders and refused by the API (`409`). Draft it again with a new nonce. |
| Commands signed with a gap (nonce N+2 before N+1) | N+2 waits in the mempools until N+1 applies. A mempool does not survive a restart: submit it again after N+1. |
| A reconfiguration submitted, then nodes stopped (exit 75) | As before, `mpc-admin resume` ([reconfiguration.md](reconfiguration.md)). The nonce is committed with the block that ends the epoch, so it is never applied twice. |
| A node refuses to start: "under approver set" | Start it with the network's approver file. |
| A node refuses to start: "for Ethereum network" (P0.3) | Start it with the network's `--eth-network` (or the same `--eth-genesis-*` values) as the others. |
| An approved exit or deposit answered `403` after an upgrade to P0.3 | The cluster id changed: draft and sign it again. |
| A node stopped while applying a protected command ("refusing to continue") | Its approver file or state is not the network's. Fix the file and restart. The block is applied again from the last commit. |
| A node crashed around the command's block | Nonce and command are one atomic commit with the block, so it restarts consistent. |

## Upgrade and compatibility

- **All nodes together.** Tag 15 and the new voting rules are consensus rules. An older node cannot
  decode a block carrying tag 15. Stop every node, replace the binaries, add `--approvers` (and
  the Ethereum network, `--eth-network` or the `--eth-genesis-*` flags), and start them.
- **Do not upgrade with an administrative operation in flight.** Wait until every node reports it
  applied (an R3 reconfiguration: every node in the new epoch). A bare reconfiguration in a block
  that was notarized but not finalized before the upgrade no longer ends the epoch afterwards.
- **Existing state.** The format is unchanged. History with bare protected commands (from before
  this version) is still applied as it was, so a node catching up replays it. In new blocks a bare
  protected command is refused. The administrative record is written with the first protected
  command.
- **Downgrade** is possible until the first protected command applies. From then on, the history
  carries tag 15, and the state carries the administrative record, which older binaries cannot read.
- **Clients.** The four protected endpoints keep their routes and bodies, plus `authorization`.
  Automation that called them must now draft, sign and submit (`mpc-admin`). For `/keys/import`,
  a bare manifest body is still understood, and refused for want of approvals.
- **P0.2.** The command encoding is unchanged (an approved exit or deposit is tag 15 around tag
  4). The state gains a record (key prefix 9, value tag 14) with the first approved exit or
  deposit; from then on, older binaries cannot read the state. Validator clients are unaffected
  (Lighthouse signs exits only on an operator's request); exits and deposits go through
  `mpc-admin`.
- **Builder registrations.** A new command tag (16, the policy), a new duty kind (10) and new
  state records (key prefix 10, value tags 16 and 17). Upgrade every node before setting a
  policy: until one is set, no registration enters a block, so older nodes see none of the new
  tags. Once a policy or a registration is written, older binaries cannot read the state.
- **Gloas.** New duty kinds (11 to 13), duty encoding tags (12 to 15) and a state record (key
  prefix 11, value tag 18: the policy terms of an authorized preference or envelope). The fork
  schedule is not part of the cluster id, so approvals stay valid. Upgrade every node at least
  two epochs before the fork: preferences for the first Gloas epoch are signed in the epoch
  before it, and an older node cannot decode a block that carries one. A rolling upgrade, one
  node at a time, works until then; a node without the release refuses the Gloas epochs' duties
  (fail closed). Once a Gloas duty is written, older binaries cannot read the state.
- **P0.3.** The cluster id now binds the Ethereum network's identity: approvals drafted before the
  upgrade must be drafted and signed again. The administrative record gains the network identity
  (value tag 15; tag 13 is read as "no network recorded"), and a node started for another network
  than the one the state recorded refuses to start. Every node needs the same network flags.

## Security properties and limits

Prevented, while at most one voter is faulty and fewer than `threshold` approver keys are
compromised:

- a protected operation by any client of the HTTP API, by a faulty leader, or by any peer that
  gossips a transaction, without the approvers;
- replaying an approved command (the nonce), within an epoch or across one;
- reusing approvals for another command, another nonce, another network or another approver set
  (every field is signed, with the cluster id);
- ending an epoch with an unauthorized or stale reconfiguration (exact nonce at vote time;
  signed reconfigurations only).
- changing a validator's slashing-protection history through an EIP-3076 import without the
  approvers, or with approvals of another history (P0.1: every record is bound through the
  interchange digest, every floor directly).
- a voluntary exit or a deposit signature without approvals of exactly that duty (P0.2): from an
  API client, a faulty leader, a gossiping peer, or a faulty coordinator asking keyholders for an
  unapproved root;
- reusing approvals on another Ethereum network with the same committee and approvers (P0.3: the
  cluster id binds the network's identity);
- a builder registration with a fee recipient or gas limit the approved policy does not allow,
  from an API client, a faulty leader, a gossiping peer, or a faulty coordinator asking
  keyholders.

Still possible:

- **Compromised approvers.** `threshold` approver keys sign anything. There is no time lock or
  governance by design, so a malicious signed reconfiguration applies as soon as it is finalized.
- **Approvers misled.** An approver who signs without reading. `show` prints the exact operation,
  and `sign` asks for confirmation, but nothing checks what an operator intended.
- **Unprotected operations** (above) remain open to API clients: denial of service, not
  compromise.
- **An exit for the wrong validator index** (P0.2): approvers must read it; the network cannot
  check it.
- **Registrations within the policy.** Any API client can get a registration signed with another
  allowed fee recipient or gas limit, or with a timestamp up to `max_future_seconds` ahead,
  overriding the operator's own until a later one. The policy bounds the damage.
- **Locally built blocks.** The registration policy does not cover the fee recipient of a block
  the beacon node builds itself (the signer signs only its header).
- **No rotation or revocation** of approver keys (it would change the cluster id).
- **More than one faulty voter** breaks this as it breaks consensus.
- **Whole-network rollback** (L-1) is not addressed: a network restored from an older snapshot
  forgets the nonces it applied, and a command signed for an old nonce becomes valid again. This
  is not solved here.

## Tests

- Unit: `tests/unit/admin.rs` covers the approver set rules, the message layout, tests 1–8 at the
  approval level, the codec, and the document. `tests/unit/epochs.rs` checks that a bare
  reconfiguration ends nothing. `tests/unit/storage.rs` (`administration`) covers test 16: the nonce
  committed and restored, a skipped nonce, too few approvals and a missing set stop the node.
- Simulation: `tests/eth_duties.rs` activations with approvals through real consensus, two in one
  join with consecutive nonces.
- End to end: `tests/e2e/admin.rs` covers `admin_1` (tests 1–9, 13, 16) and `admin_2` (test 11:
  bare, forged, used and future nonces from a faulty leader; nothing ends the epoch). Test 10 is in
  `reconfigure::r3_7_refusals`, 12 in `reconfigure::r3_1` (signed offline with `mpc-admin`), 14 in
  `replace` (R2), and 15 in `import::e2e_imp_1`.
- Builder registration policy: `tests/unit/admin.rs` (`a_registration_policy_approval_binds_every_field`),
  `tests/unit/eth/registration.rs` (the rules, the codec, the digest, the JSON form, Web3Signer's
  root), `tests/unit/storage.rs` (`registrations_follow_the_policy_in_force`: block order, retries
  after a change, no per-epoch limit, restart), `tests/unit/application.rs` (the mempool's
  priority and bounds, a voter's order of policies), `tests/e2e/registrations.rs` (`reg_1`: the API,
  a faulty leader, a faulty coordinator, a policy change, a restart; `reg_2`: a burst of 100).
