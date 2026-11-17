# Administration: operations signed by approvers (P0)

Some commands change who or what the network trusts. Such a **protected operation** takes effect
only with the Ed25519 signatures of a threshold of **approvers**. Approvers are the operators'
keys. They stay offline. No node holds an approver key, and the HTTP API never receives one: a node
only checks approvers' signatures.

Consensus accepting a block is not enough. Every honest voter checks the approvals and the nonce
before it votes. So no faulty leader, and no client of the API, can bring in a protected command
without valid approvals and the next nonce.

Code: `src/admin.rs` (approver set, signed message, document), `src/types.rs` (`Command::Admin`,
tag 15), `src/application.rs` (leaders and voters), `src/epochs.rs` (the terminal guard),
`src/storage.rs` (`admit`, the nonce), `src/rpc.rs` (`authorize`, `GET /admin`),
`src/bin/mpc-admin.rs` (the CLI).

## Protected operations

| Operation (`mpc-admin draft <operation>`) | Endpoint | Command | Why it is protected |
| --- | --- | --- | --- |
| `activate` | `POST /validators/activate` | `ActivateValidator`, or `ActivateImportedValidator` with an `acknowledgment` | Binds a key to a chain for good. A wrong chain bricks the key. For an imported key, it records the operator's statement that the previous signer is stopped. |
| `register-import` | `POST /keys/import` | `RegisterImportedKey` | Fixes the imported key's public sharing. A key is registered once, so fake commitments would block that key's import for good. |
| `reshare` with `from_round`, `dealers`, `players` (R2) | `POST /validators/reshare` | `StartResharing` with a membership | Hands key shares to new keyholders. |
| `reconfigure` (R3) | `POST /consensus/reconfigure` | `Reconfigure` | Changes the consensus voters. |
| `import-history` (P0.1) | `POST /slashing-protection/import` (not a dry run) | `ImportSlashingProtection` | Raises an imported key's slashing-protection floors for good. Floors chosen by an attacker would refuse the key's real duties. |
| `sign-exit` (P0.2) | `POST /api/v1/eth2/sign/{key}` (`VOLUNTARY_EXIT`) | `Duty` of a voluntary exit | An exit cannot be undone: the validator leaves for good. |
| `sign-deposit` (P0.2) | `POST /api/v1/eth2/sign/{key}` (`DEPOSIT`) | `Duty` of a deposit | A key signs one deposit message, ever. The first deposit on chain sets its withdrawal credentials for good. |
| `set-registration-policy` | `POST /eth/registration-policy` | `SetRegistrationPolicy` | Decides which fee recipients builder registrations may name: where relays pay for the validators' builder blocks. |

Not protected: starting a DKG ceremony (`POST /dkg/start`), a refresh of the keyholders' shares
(R1: `POST /validators/reshare` without a membership; it deals to the active generation's
keyholders, never to the committee, so it cannot change who holds a key, audit H-10), activating
or aborting a reshare
(`/validators/reshare/activate`, `/validators/reshare/abort`), a dry run of a history import, and
signing every other duty. Any client of the plain HTTP API can call them. That API is bound to
loopback and has no authentication. The optional mTLS listener (`--https-listen`) accepts only
clients with a certificate from `--client-ca` ([tee.md](tee.md)). These operations change no
trusted identity, and no slashing history except through signing itself. Misused, they deny
service. They cannot make the network sign a slashable message, an exit or a deposit, or give a
share to a new party. Nor can they take the ceremony id of a protected operation first: ids that
start with `approved.` are the protected commands' to start, and only theirs, and an imported
key's registration and a replacement of keyholders must use one (audit H-11,
[key-import.md](key-import.md#the-ceremony-id)).

### Voluntary exits and deposits (P0.2)

An exit or a deposit is a protected `Duty` (`DutyKind::needs_approval`).

- **What is signed.** The `Duty` command's canonical encoding: the validator's public key, the whole
  `fork_info` (both versions, the fork epoch, the genesis validators root), and the duty's type and
  SSZ object. For an exit, that is its epoch and validator index. For a deposit, it is the public
  key, the withdrawal credentials and the amount. The signing root follows from these bytes, so an
  approval of one signing root never authorizes another. The cluster id binds the cluster and the
  Ethereum network (P0.3). `show` prints every field, the fork version, the domain and the signing
  root; the validator index, exit epoch, withdrawal credentials, amount and signing root in capitals.
- **Consensus enforces it.** Honest leaders drop a bare exit or deposit, and honest voters refuse a
  block that carries one. For an approved one, voters check the approvals and the exact next nonce,
  as for every protected command. Approvals never lift a rule. Slashing protection (one deposit
  message per key, at most eight exit roots per epoch), the chain and the fork schedule still apply.
- **Keyholders enforce it.** The replicated state records each approved exit and deposit root:
  `(validator, nonce) → (root, kind, period)`. A keyholder learns only approved roots
  (`Protection::duties_of`). A coordinator that asks for an unapproved root gets `not_authorized`.
  An exit or a deposit that finalized history authorized without approvals (before P0.2) stays
  recorded and counts against its period. Keyholders sign it only once the same root is approved.
- **Retries.** An approved root is signed again without approvals, through any node, after
  restarts and epoch changes. The signature is the same. A retry never needs a new nonce.
- **The nonce.** An approved exit or deposit that finalizes and is then refused by the state
  machine uses its nonce. Examples: a second deposit message, or a key that is not activated yet. A
  refusal before submission (API, coordinator) uses no nonce.
- **`--enable-deposit-signing`** is a node-local API switch. A node without it answers `400` to every
  deposit request. It is not a consensus rule: a node started without it still votes for an
  approved deposit.
- **The validator index** of an exit is not checked against the beacon chain, because the network
  has no beacon state. An exit approved with another validator's index gives a signature that is
  invalid on chain. Approvers read the index in `show`.

```sh
mpc-admin --nodes ... draft sign-exit --validator 0x<key> --epoch 420000 --validator-index 123 \
    --output exit.json     # fork_info from the nodes' network: Capella's version from Deneb on
mpc-admin show --command exit.json
mpc-admin sign --command exit.json --key approver.key --output exit-1.json
mpc-admin --nodes ... submit --command exit-1.json --command exit-2.json --output signed-exit.json
# signed-exit.json is a SignedVoluntaryExit; nothing is broadcast. To publish it:
#   curl -X POST -H 'Content-Type: application/json' --data @signed-exit.json \
#     http://<beacon>/eth/v1/beacon/pool/voluntary_exits
mpc-admin --nodes ... draft sign-deposit --validator 0x<key> --withdrawal-credentials 0x01.. \
    --amount 32000000000 --output deposit.json   # the credentials are never inferred
```

For a deposit, `submit --output` writes the deposit data, with `deposit_message_root` and
`deposit_data_root`. The Web3Signer endpoint takes the approvals as `authorization` beside the usual
request. Without them, it answers `403` for a root that is not approved yet.

### Builder registration policy

A builder registration (`VALIDATOR_REGISTRATION`) names the fee recipient that relays pay for the
validator's builder blocks. Validator clients sign one at every restart. So the approvers approve a
policy, not each registration ([ethereum-signing.md](ethereum-signing.md#builder-registrations)).

- **What is signed.** The whole policy: the fee recipients (sorted, at most 64; none means that no
  registration is signed), the gas limit range, `max_future_seconds` and `max_age_seconds`. The last
  two bound how far a registration's timestamp may be from the nodes' clocks (default 30 and 3600).
  `show` prints every field and the policy's digest.
- **When it applies.** From the transaction after the one that sets it, in block order, on every
  node. It replaces the previous policy whole. A registration before it in the same block follows
  the previous policy. Without any policy, nothing is signed.
- **Retries.** A registration that the policy in force does not allow is refused. This includes a
  retry of a registration authorized under an earlier policy. The API, voters, block application
  and keyholders all check it. A signature already returned stays valid.
- **The window and validator clients.** A client with a fixed registration timestamp (Lighthouse's
  `--builder-registration-timestamp-override`) is refused once that timestamp is older than
  `max_age_seconds`. Raise it for such a client.
- **Status.** `POST /eth/registration-policy` answers `202` with the transaction id and the policy's
  digest. `submit` then waits until every answering node applies it. `GET /eth/registration-policy`
  answers the policy in force, its digest and the height it is read at. `mpc-admin status` shows
  each node's digest.
- **Gloas.** From Gloas on, the same policy also decides on proposer preferences (their fee
  recipient and target gas limit) and on the envelopes of self-built payloads (their fee
  recipient), with the same order and retry rules ([ethereum-signing.md](ethereum-signing.md#gloas)).
  Without a policy, a self-built Gloas block loses its payload: set one before the fork. While Gloas
  is scheduled and no policy is set, the node logs a warning at start, and `mpc-admin status`
  prints one (with each node's Gloas epoch). The range must cover the target gas limit that the
  validator client asks for in its preferences.

```sh
mpc-admin --nodes ... draft set-registration-policy --fee-recipient 0x<address> \
    --gas-limit-min 30000000 --gas-limit-max 60000000 --output policy.json
mpc-admin show --command policy.json
mpc-admin sign --command policy.json --key approver.key --output policy-1.json
mpc-admin --nodes ... submit --command policy-1.json --command policy-2.json
```

### EIP-3076 history imports (P0.1)

The approvers sign exactly what consensus applies, with no extra hashing layer. The signed payload
is the `ImportSlashingProtection` command's canonical encoding:

```text
genesis validators root (32) ‖ interchange digest (32) ‖ varint count ‖
  count × (validator key (48) ‖ latest block: 0 | 1 ‖ slot ‖ signing root option
                              ‖ latest attestation: 0 | 1 ‖ source ‖ target ‖ signing root option)
```

- **The summaries** are signed directly: the keys imported (in the request's order; every key of
  the interchange when the request names none) and the floors each one gets. The state machine
  applies them.
- **The interchange digest** binds every other record. It is the SHA-256 of the parsed, validated
  interchange: every validator, every block and attestation, and the chain. A change to any record,
  even one below the floors, changes the signed bytes. The digest does not depend on the JSON's
  formatting: the same history written another way is the same command.
- **The node builds the command** from the request (`{"interchange", "validators"}`) as `mpc-admin`
  does, and checks the approvals against it. Approvals of another history, key selection, chain or
  operation do not verify (`403`).

Approvals do not lift any rule. The API still parses an approved import strictly and checks it
against the network's records (`409` for a conflict, another chain, or an activated key). The API
and every voter bound it by the time horizon (`400` from the API). The API checks run before the
import is submitted, so an import the API refuses uses no nonce. Several validators in one import
apply together or not at all.

One exception: an approved import that finalizes and is then refused by the state machine uses its
nonce and changes no floor. This happens when the state changed between the API's check and the
block, or when the command did not go through the API. Voters must know the next nonce before they
vote, without knowing that outcome.

A dry run (`"dry_run": true`) changes nothing and needs no approvals. A bare import (without
approvals) is refused in new blocks and still applied from finalized history.

## Approvers

Every node starts with the same approver file (`--approvers approvers.json`). The file has no
other fields:

```json
{"threshold": 2, "approvers": ["0x<ed25519 public key>", "0x...", "0x..."]}
```

- **Size.** 1 to 8 distinct keys. The threshold is more than half of them and at most all of them
  (`2 of 3`, `3 of 4`, `3 of 5`, ...).
- **A node without the file** takes no protected operation. Its API answers `503`, its leader drops
  such commands, and its voter refuses blocks that carry them. A finalized one stops it
  ([The nonce](#the-nonce)).
- **The recorded set.** The replicated state records the set's digest with the first protected
  command it applies. After that, a node started with another set, or with none, refuses to start
  (`StartError::Approvers`, exit status 1): "the replicated state applied administrative nonce N
  under approver set 0x.., but this node is started with approver set 0x..". Restore the network's
  file.
- **The cluster id** is the SHA-256 of `"eth-mpc-signer/cluster/v2"`, the epoch 0 committee's keys
  (`--participants`), the approver set's digest, and the Ethereum network's identity
  (`Network::identity`). A node without an Ethereum network (`--eth-network`, or the
  `--eth-genesis-*` flags) uses `"eth-mpc-signer/cluster/v1"` and no identity. The approver set's
  digest is the SHA-256 of `"eth-mpc-signer/approvers/v1"`, the threshold byte and the sorted keys.
  Approvals are bound to the cluster id, so they are not valid on another network, or under another
  approver set of the same network.
- **Rotation is not implemented.** Changing the set changes the cluster id, and the nodes refuse to
  start against the recorded digest. A rotation would need a protected command of its own.
- **Approver keys** are created by the approvers themselves (`mpc-admin approver-key`), on their own
  machines, in owner-only files. Nothing creates, distributes or stores them for anyone. There is
  no HSM support. A node never needs one.

## What an approver signs

```text
cluster_id (32 bytes) ‖ version (u16 BE, 1) ‖ command tag (u8) ‖ nonce (u64 BE)
  ‖ payload length (u32 BE) ‖ payload
```

The payload is the protected command's canonical encoding without its tag: every field the node
applies. The signature is Commonware's namespaced Ed25519 with the namespace
`_ETH_MPC_SIGNER_ADMIN`. The bytes signed are `varint(len(namespace)) ‖ namespace ‖ message`, so
they never collide with consensus or p2p signatures.

In a block, a protected command travels as `Command::Admin` (tag 15):
`15 ‖ varint nonce ‖ the protected command (with its tag) ‖ varint count ‖ count × (approver index
u8 ‖ 64-byte signature)`. The indices refer to the sorted approver set. Approvals are sorted by
index, each index once, 1 to 8 of them. Only a protected command can be wrapped, and only once. A
nested tag 15 is refused before it is read, so decoding cannot recurse.

### Acknowledging a rollback (WORM anchor)

When the anchor shows a whole-network rollback and the newer state is lost for good, the approvers
sign an acknowledgment offline ([anchor.md](anchor.md#operating)). It is not a command. It goes to
no node's API and takes no nonce, because the lost state may have used any nonce. A node reads it
from the anchor, or writes it there when started with `--anchor-acknowledgment`.

```sh
mpc-admin anchor acknowledge --anchor s3://bucket/prefix --cluster 0x.. \
    --approvers approvers.json --output acknowledgment.json
mpc-admin show --command acknowledgment.json --approvers approvers.json
mpc-admin sign --command acknowledgment.json --key approver.key --output acknowledgment-1.json
```

```text
"eth-mpc-signer/anchor-acknowledgment/v1" ‖ cluster_id (32 bytes) ‖ generation (u64 BE)
  ‖ height (u64 BE) ‖ block digest (32 bytes) ‖ marks (block slot, source, target: each a flag
  byte, then a u64 BE if present)
```

The namespace is `_ETH_MPC_SIGNER_ANCHOR_ACKNOWLEDGMENT`, so an approval of a command is never
valid as an acknowledgment, or the other way round. The document carries the fields, a description
and the exact message. As for a command, the tool rebuilds and compares them before signing and
before use. `sign` asks the approver to confirm that the newer state is lost.

## The nonce

The replicated state holds the last administrative nonce applied (0 before the first). A protected
command is valid only with exactly the next one. So a signed command applies once, and signed
commands apply in nonce order. The nonce is kept across consensus epochs (R3) and restarts. The
approver set's digest is stored with it.

- **API.** It refuses a nonce at or below this node's last applied one (`409`). It accepts a later
  one, because earlier commands may still be on their way. That command waits in the mempool.
- **Leader.** It proposes approved commands only in consecutive nonce order. It counts from its
  applied nonce plus the commands of its ancestors that are not applied yet. It drops a command
  whose nonce is used, or whose approvals do not verify. A reconfiguration goes alone in its block.
- **Voter (the security boundary).** It refuses a block that carries a bare protected command, an
  approval that does not verify, or nonces that are not exactly the next ones. It computes "next"
  from its executor's applied height and nonce, read together, plus the protected commands of the
  block's ancestors it has not applied yet. If it cannot compute the next nonce (a parent below its
  applied height, or more than 1,024 unapplied ancestors), it refuses the block. That costs only its
  vote.
- **Apply.** The node checks a finalized protected command once more: the next nonce, and approvals
  valid under this node's set. A failure means that this node's configuration or state is not the
  network's. The node stops (a panic) rather than diverge.

Why the exact nonce matters: a reconfiguration ends its epoch as soon as a block that carries it is
a parent ([reconfiguration.md](reconfiguration.md)). If a reconfiguration with a used nonce could
be notarized, honest nodes would refuse its children. The epoch could then freeze on a command that
never applies. Because voters check the exact nonce, such a block is never notarized.

## The terminal guard

Only a reconfiguration **with approvals** ends an epoch (`epochs::reconfiguration`). A bare one is
no reconfiguration: honest voters refuse its block, and it ends nothing. In addition, a node treats
a parent as the epoch's end only if that parent's approvals verify under its own set. So an
unauthorized `Reconfigure` from a faulty leader cannot trigger the guard or stop the network (test
`admin_2`).

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
- `description` and `message` derive from `cluster_id`, `nonce` and `request`. `show`, `sign` and
  `submit` derive them again and refuse a document whose fields were edited after drafting.
- The API receives the request with an `authorization` field:
  `{"nonce": 4, "approvals": [{"approver": "0x..", "signature": "0x.."}]}`. For `/keys/import` the
  body is `{"manifest": <manifest.json>, "authorization": {..}}`. For an exit or a deposit, the
  validator's key goes in the endpoint's path, not in the body.

`GET /admin` returns `configured`, `cluster_id`, `threshold`, `approvers`, `approvers_digest`,
`network` (the Ethereum network's identity), `nonce` (the last applied) and `next_nonce`. Without
an approver set, only `configured`, `approvers` (empty), `nonce` and `next_nonce` are present.

API answers for a protected request:

| Status | When |
| --- | --- |
| `503` | The node has no approver set. |
| `403` | No `authorization`, or approvals that are too few, repeated, unknown or do not verify. |
| `409` | The nonce is used. |

Answers that do not depend on approvals come first: `400` for a malformed or invalid request, `200`
for an activation that already exists, `409` for an activation on another chain.

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

| Command | Online | What it does |
| --- | --- | --- |
| `approver-key --output FILE` | no | Creates an approver key in a new owner-only file and prints its public key. |
| `approver-public-key --key FILE` | no | Prints the key's public key, for the approver file. |
| `draft <operation> ... --output FILE` | yes | Drafts the operation for the cluster and the next nonce: the highest `nonce` that an answering node reports in `GET /admin`, plus one (`--nonce` overrides). Refuses if a node has no approver set or reports another cluster id. |
| `show --command FILE... [--approvers FILE]` | no | Prints the operation, endpoint, cluster, nonce, description, the SHA-256 of the signed bytes and the bytes. With `--approvers`, checks each approval. |
| `sign --command FILE --key FILE [--output FILE] [--yes]` | no | Shows the operation, asks to type `yes`, and adds the approval (default output: in place). The key file must be owner-only. |
| `submit --command FILE... [--output FILE]` | yes | Merges the copies and posts the request through the first answering voter. |
| `status` | yes | Each node's epoch, height, role, administrative nonce, Ethereum network, registration policy digest and anchor state. |
| `replace-node`, `resume` | yes | Replaces a consensus voter (R3, below). |
| `anchor check`, `anchor acknowledge` | — | Reads the WORM anchor, drafts a rollback acknowledgment ([anchor.md](anchor.md)). |

`--nodes` takes `host:port` values, or `https://host:port` with `--tls-cert`, `--tls-key` and
optionally `--tls-node-ca` for nodes' mTLS API ([tee.md](tee.md)).

What `draft` takes per operation (`--request` takes JSON or `@file`):

| Operation | Input |
| --- | --- |
| `activate` | `--request` with `public_key`, `genesis_validators_root`; add `acknowledgment` for an imported key |
| `register-import` | `--request '{"manifest": ...}'` |
| `reshare` | `--request` with `public_key`, `ceremony_id`, `from_round`, `dealers`, `players` |
| `reconfigure` | `--request` with `remove`, `add`; `epoch` defaults to the next one |
| `import-history` | `--interchange FILE`, and optionally `--validator KEY` (repeatable), instead of `--request` |
| `sign-exit` | `--validator`, `--epoch`, `--validator-index`; optionally `--fork-version`, `--genesis-validators-root` (default: the nodes' network, `GET /eth/network`) |
| `sign-deposit` | `--validator`, `--withdrawal-credentials`, `--amount` (gwei); optionally `--genesis-fork-version` (default: the nodes' network) |
| `set-registration-policy` | `--fee-recipient` (repeatable), `--gas-limit-min`, `--gas-limit-max`; optionally `--max-future-seconds` (default 30), `--max-age-seconds` (default 3600) |

For a history import, `show` prints a summary, not the whole interchange:

```bash
mpc-admin --nodes ... draft import-history --interchange interchange.json \
  --validator 0xa1b2.. --output import.json
mpc-admin show --command import.json
#   validators affected: 1 (of 1 in the interchange)
#     0xa1b2..: 412 blocks (slots 9..=8191), 6400 attestations (sources 0..=255, targets 1..=256);
#     floors: block slot 8191, attestation source 255 target 256
#   total: 412 block proposals (slots 9..=8191), 6400 attestations (sources 0..=255, targets 1..=256)
#   genesis validators root 0x..; interchange digest 0x.. (every record of the interchange)
#   signed bytes SHA-256: 0x.. (252 bytes)
```

Replacing a consensus voter (R3) runs its checks and follows the switch:

```bash
mpc-admin --nodes ... replace-node --old 3 --new 4 --output replace.json   # checks, drafts
# approvers sign replace.json offline, as above
mpc-admin --nodes ... replace-node --command replace-alice.json --command replace-bob.json
mpc-admin --nodes ... resume
```

## Recovery after an interrupted operation

| Situation | What to do |
| --- | --- |
| A history import refused (`403`, `404`, `409`, `400`) | Nothing was submitted: no nonce used, no floor changed. Fix the cause. The same signed document stays valid while the network's nonce has not moved. |
| Drafted, not yet submitted | Nothing happened. If the network's nonce moved meanwhile (`GET /admin`), draft and sign again: the old document is stale. |
| Submitted, the API timed out (`504`) | Read `GET /admin` on every node. If the nonce reached the command's, it applied: check the operation's state (`/validators`, `/keys/import/{id}`, `/validators/reshare/{id}`, `/consensus`). A second submission is refused (`409`). If the nonce did not move, submit the same document again: it is still valid. |
| Two commands signed with the same nonce | Only the first one finalized applies. Leaders drop the other, and the API refuses it (`409`). Draft it again with a new nonce. |
| Commands signed with a gap (nonce N+2 before N+1) | N+2 waits in the mempools until N+1 applies. A mempool does not survive a restart: submit N+2 again after N+1. |
| A reconfiguration submitted, then nodes stopped (exit status 75) | Run `mpc-admin resume` ([reconfiguration.md](reconfiguration.md)). The nonce is committed with the block that ends the epoch, so it never applies twice. |
| A node refuses to start: "under approver set" | Start it with the network's approver file. |
| A node refuses to start: "for Ethereum network" (P0.3) | Start it with the same `--eth-network` (or the same `--eth-genesis-*` values) as the other nodes. |
| An approved exit or deposit answered `403` after the upgrade to P0.3 | The cluster id changed: draft and sign it again. |
| A node stopped while it applied a protected command ("refusing to continue") | Its approver file or state is not the network's. Fix the file and restart. The node applies the block again from the last commit. |
| A node crashed around the command's block | The nonce and the command are one atomic commit with the block, so the node restarts consistent. |

## Upgrade and compatibility

- **All nodes together.** Tag 15 and the voting rules are consensus rules. An older node cannot
  decode a block that carries tag 15. Stop every node, replace the binaries, add `--approvers` and
  the Ethereum network (`--eth-network`, or the `--eth-genesis-*` flags), then start them.
- **Do not upgrade with an administrative operation in flight.** Wait until every node reports it
  applied (for an R3 reconfiguration: every node in the new epoch). A bare reconfiguration in a
  block that was notarized, but not finalized, before the upgrade no longer ends the epoch after it.
- **Existing state.** The format is unchanged. History with bare protected commands is still
  applied as it was, so a node that catches up replays it. New blocks refuse a bare protected
  command. The administrative record is written with the first protected command.
- **Downgrade** is possible until the first protected command applies. From then on, the history
  carries tag 15 and the state carries the administrative record, which older binaries cannot read.
- **Clients.** The protected endpoints keep their routes and bodies, plus `authorization`.
  Automation that called them must now draft, sign and submit (`mpc-admin`). `/keys/import` still
  understands a bare manifest body, and refuses it for want of approvals.
- **P0.2.** The command encoding is unchanged: an approved exit or deposit is tag 15 around tag 4.
  The state gains a record (key prefix 9, value tag 14) with the first approved exit or deposit.
  From then on, older binaries cannot read the state. Validator clients are unaffected (Lighthouse
  signs exits only on an operator's request). Exits and deposits go through `mpc-admin`.
- **Builder registrations.** A command tag (16, the policy), a duty kind (10), and state records:
  registrations under key prefix 10 (value tag 16), and the policy (value tag 17). Upgrade every
  node before you set a policy. Until a policy is set, no registration enters a block, so older
  nodes see none of the new tags. Once a policy or a registration is written, older binaries cannot
  read the state.
- **Gloas.** Duty kinds 11 to 13, duty encoding tags 12 to 15, and a state record (key prefix 11,
  value tag 18: the policy terms of an authorized preference or envelope). The fork schedule is not
  part of the cluster id, so approvals stay valid. Upgrade every node at least two epochs before
  the fork: preferences for the first Gloas epoch are signed in the epoch before it, and an older
  node cannot decode a block that carries one. A rolling upgrade, one node at a time, works until
  then. A node without the release refuses the Gloas epochs' duties (fail closed). Once a Gloas
  duty is written, older binaries cannot read the state.
- **P0.3.** The cluster id binds the Ethereum network's identity, so approvals drafted before the
  upgrade must be drafted and signed again. The administrative record gains the network identity
  (value tag 15; a tag 13 record reads as "no network recorded"). A node started for another network
  than the one the state recorded refuses to start. Every node needs the same network flags.

## Security properties and limits

Prevented, while at most one voter is faulty and fewer than `threshold` approver keys are
compromised:

- a protected operation without the approvers, by any client of the HTTP API, a faulty leader, or
  any peer that gossips a transaction;
- replaying an approved command (the nonce), within an epoch or across one;
- reusing approvals for another command, another nonce, another network or another approver set
  (every field is signed, with the cluster id);
- ending an epoch with an unauthorized or stale reconfiguration (exact nonce at vote time; only
  approved reconfigurations end an epoch);
- changing a validator's slashing-protection history through an EIP-3076 import without the
  approvers, or with approvals of another history (P0.1: the interchange digest binds every record,
  and every floor is signed directly);
- a voluntary exit or a deposit signature without approvals of exactly that duty (P0.2): from an
  API client, a faulty leader, a gossiping peer, or a faulty coordinator that asks keyholders for an
  unapproved root;
- reusing approvals on another Ethereum network with the same committee and approvers (P0.3: the
  cluster id binds the network's identity);
- a builder registration with a fee recipient or gas limit that the approved policy does not allow,
  from an API client, a faulty leader, a gossiping peer, or a faulty coordinator that asks
  keyholders.

Still possible:

- **Compromised approvers.** `threshold` approver keys sign anything. There is no time lock or
  governance, by design, so a malicious approved reconfiguration applies as soon as it finalizes.
- **Misled approvers.** An approver may sign without reading. `show` prints the exact operation and
  `sign` asks for confirmation, but nothing checks what an operator intended.
- **Unprotected operations** (above) remain open to API clients: denial of service, not compromise.
- **An exit for the wrong validator index** (P0.2). Approvers must read it. The network cannot check
  it.
- **Registrations within the policy.** Any API client can get a registration signed with another
  allowed fee recipient or gas limit, or with a timestamp up to `max_future_seconds` ahead. It
  overrides the operator's own registration until a later one. The policy bounds the damage.
- **Locally built blocks before Gloas.** The registration policy does not cover the fee recipient
  of a block that the beacon node builds itself: the signer signs only its header.
- **No rotation or revocation** of approver keys, because it would change the cluster id.
- **More than one faulty voter** breaks this, as it breaks consensus.
- **Whole-network rollback** (L-1) without an anchor. A network restored from an older snapshot
  forgets the nonces it applied, so a command signed for an old nonce becomes valid again. The
  keyholders' restart floor refuses double proposals and double votes; it does not apply to
  protected commands. With the WORM anchor ([anchor.md](anchor.md)), the nodes stop instead (exit
  status 77). They resume on newer state, or on the older state only with the approvers'
  acknowledgment ([above](#acknowledging-a-rollback-worm-anchor)), after the operators reconcile the
  commands the lost state had applied.

## Tests

The test numbers refer to the P0 test plan, as named in the tests' comments.

- **Unit.** `tests/unit/admin.rs`: the approver set rules, the message layout, tests 1–8 at the
  approval level, the codec and the document. `tests/unit/epochs.rs`
  (`a_bare_reconfiguration_ends_nothing`). `tests/unit/storage.rs`, module `administration`: test 16
  (`the_nonce_survives_restart`), and a skipped nonce, too few approvals and a missing set stop the
  node.
- **Simulation.** `tests/eth_duties.rs`: activations with approvals through real consensus, two in
  one join with consecutive nonces.
- **End to end.** `tests/e2e/admin.rs`: `admin_1_protected_operations_need_approvals` (tests 1–9, 13
  and 16) and `admin_2_a_faulty_leader_cannot_bring_in_protected_commands` (test 11: bare, forged,
  used and future nonces from a faulty leader; nothing ends the epoch). Test 10 is in
  `reconfigure::r3_7_refusals`, test 12 in `reconfigure::r3_1_replace_a_lost_voter` (signed offline
  with `mpc-admin`), test 14 in `replace` (R2), and test 15 in
  `import::e2e_imp_1_an_imported_key_signs_only_once_safely_activated`.
- **Exits and deposits (P0.2).** `tests/unit/admin.rs`
  (`an_exit_or_deposit_approval_binds_its_exact_signing_root`), `tests/unit/storage.rs`
  (`an_exit_or_a_deposit_is_signed_only_once_approved`), `tests/e2e/exits.rs`
  (`p02_1_exits_and_deposits_need_approvals`).
- **History imports (P0.1).** `tests/unit/admin.rs` (`an_import_approval_binds_its_exact_history`),
  `tests/e2e/import.rs` (E2E-IMP-1).
- **Builder registration policy.** `tests/unit/admin.rs`
  (`a_registration_policy_approval_binds_every_field`); `tests/unit/eth/registration.rs` (the rules,
  the codec, the digest, the JSON form, Web3Signer's root); `tests/unit/storage.rs`
  (`registrations_follow_the_policy_in_force`: block order, retries after a change, no per-epoch
  limit, restart); `tests/unit/application.rs` (the mempool's priority and bounds, a voter's order
  of policies); `tests/e2e/registrations.rs` (`reg_1`: the API, a faulty leader, a faulty
  coordinator, a policy change, a restart; `reg_2`: a burst of 100).
