# Importing an existing validator key

An Ethereum validator that already exists, with an EIP-2335 keystore and a signing history, can
move to this network without changing its public key. An offline tool splits the keystore into
3-of-4 Shamir shares, one encrypted per node. The public part is registered through consensus,
each node installs only its own share, the previous signer's EIP-3076 history is imported, and the
key is activated only after those checks. From then on it signs like a key the DKG created, under
the same authorization and slashing protection ([slashing-protection.md](slashing-protection.md)).

**Not the guarantee of a DKG.** A DKG key never exists in one place. An imported key existed in
full before the split: in the keystore, in its backups, wherever its password was kept, and in
the memory of the machine that ran the split. Whoever holds the keystore and its password can sign
outside this network, bypassing its slashing protection. The import moves the signing; it cannot
destroy copies of the key.

**Not production-ready**, like the rest of the network ([ethereum-signing.md](ethereum-signing.md)):
the node API has no authentication and binds to `127.0.0.1`, the committee is fixed (4 nodes,
threshold 3), and the whole-network rollback limitation L-1 is open and applies to imported keys
unchanged ([slashing-protection.md](slashing-protection.md#whole-network-rollback-l-1)).

## DKG and trusted dealer

| | DKG key (`/dkg/start`) | Imported key (`mpc-keytool split`) |
| --- | --- | --- |
| Who knew the secret | Nobody, ever | The previous signer, the keystore's holders, the machine that ran the split |
| Copies outside the network | None | The keystore and its backups, for as long as they exist |
| Shares from | Every node's dealing, verified by every player | One dealer, verified against the Feldman commitments by each node |
| Public key | New, random | The existing validator key, unchanged |
| History at the start | Empty | The previous signer's EIP-3076 history (floors) |
| Activation | `ActivateValidator` | `ActivateImportedValidator`: history imported, 3 shares acknowledged, operator acknowledgment |
| Signing after activation | One path for both: the same commands, records, authorization binding and refusals | same |

The split uses the DKG's own representation (commonware's `Sharing`, mode `NonZeroCounter`:
participant `i` holds `f(i + 1)`; Feldman commitments `a_k · G1`). The coordinator, the keyholders
and share recovery cannot tell the two apart, and no signing code distinguishes them. Only the
lifecycle before activation differs.

## Lifecycle

```
PREPARED          offline: mpc-keytool split ──> manifest.json + node-<i>.enc (no network)
   │  POST /keys/import (manifest, approved) ──> RegisterImportedKey ──consensus──>
REGISTERED        ceremony "Imported", validator key (not activated), empty import state
   │  POST /keys/import/share on each node ──> the node opens and verifies its own share, stores it,
   │  and submits a ReadyAck signed with its consensus key ──> ImportedShareReady ──consensus──>
   │  (ready set: the participants whose signed acknowledgment is committed)
   │  POST /slashing-protection/import (EIP-3076) ──> ImportSlashingProtection ──consensus──>
HISTORY_IMPORTED  floors from the previous signer's latest block and attestation, chain fixed
   │  POST /validators/activate + acknowledgment, approved ──> ActivateImportedValidator ──consensus──>
ACTIVATED         signs, through the Web3Signer API, like any validator key
```

The registration and the activation are protected operations: they take effect only with a
threshold of the approvers' offline signatures over the exact manifest or activation, and the
network's next administrative nonce ([administration.md](administration.md)). Without them the API
answers `403`, and honest voters refuse the command. The operator's acknowledgment is part of
what the approvers sign.

Shares can be installed before or after the history import. Activation checks everything at the
moment consensus decides it:

| Command | Decided by every node against the committed state | Refused when |
| --- | --- | --- |
| `RegisterImportedKey {manifest}` | the manifest is well formed: version, protocol, the committee in order, threshold, `n` commitments, distinct share-encryption keys, a valid G1 point at every position, the constant commitment equal to the validator key | the ceremony id is in use with another manifest (`409`), the key is already known as any validator, DKG or imported (`409`: a key is registered once), the manifest is invalid (`400`) |
| `ImportedShareReady {round, manifest digest, participant, signature}` | the participant's ed25519 signature, with its consensus key, over the round and the manifest digest (own namespace) | unknown import, another manifest digest, not a participant, bad signature: ignored |
| `ImportSlashingProtection {chain, digest, validators}` | every named key is an imported key, not activated, of that chain (its earlier imports'), and its summary is not slashable against what this network signed for it | the key is activated (`activated`: its floors are fixed while it signs), another chain, unknown or DKG key, conflict with local records (nothing imported) |
| `ActivateImportedValidator {key, chain, acknowledgment}` | history imported for `chain`; acknowledged shares `≥` threshold; all four acknowledgment flags set | `no_imported_history`, `history_for_another_chain`, `shares_not_ready`, `not_acknowledged`, `other_chain` (already active for another chain) |

`ActivateValidator` (the DKG activation) refuses an imported key (`imported_key`), and the imported
activation refuses a DKG key (`not_imported`), so neither path skips the other's checks.

**No reset.** There is no unregister, delete or reset command. The same manifest again is
idempotent; the same key under another manifest or ceremony id is refused, so a key's records,
floors and activation are never replaced by starting over. Imports only raise floors: an older or repeated interchange changes nothing
(`outcome: unchanged`). Once the key is activated, every import is refused (`activated`), by the
state machine itself: nothing changes its floors while it signs.

**The ready set is not the coordinator's word.** Each keyholder acknowledges its own share with its
consensus identity, after it decrypted it and checked it against the registered commitments. A
coordinator or a single node cannot claim another node's share.

## Formats

All files are JSON with fixed `format` and `version` fields and no unknown fields.

### Committee (`committee.json`, input of `split`)

```json
{"participants": [{"identity": "0x<ed25519 public key>", "share_encryption_key": "0x<X25519 public key>"}, ...]}
```

From `GET /identity` of each node, which also gives its `participant_index`. The tool sorts the
members as the network does; the manifest is refused at registration unless they are exactly the
network's committee.

### Share-encryption key (`mpc-keytool share-key --out FILE`)

One X25519 key pair per node, used for nothing else. The file holds the secret key
(`eth-mpc-signer/share-encryption-key`), is created with mode `0600` and never overwritten. The
node takes it with `--share-encryption-key FILE` and refuses to start if the file is readable by
group or others. A node without it serves the network normally but cannot install imported shares
(`409`).

### Manifest (`manifest.json`, public)

| Field | Content |
| --- | --- |
| `format`, `version` | `eth-mpc-signer/key-import-manifest`, `1` |
| `ceremony_id` | the id the key is registered under |
| `import_id` | 16 random bytes: two splits of one key never share a digest |
| `validator_public_key` | the keystore's public key (compressed G1) |
| `protocol_version`, `threshold` | the network's (`3`) |
| `participants` | per member: `index`, `identity`, `share_encryption_key`, `verification_share` (derived) |
| `commitments` | the Feldman commitments, constant term (the validator key) first |
| `curve`, `secret_sharing`, `share_encryption` | the algorithms, informational (fixed by the version) |
| `manifest_digest` | SHA-256 of a namespace and the binary manifest (derived) |

Derived fields are recomputed when the file is read; a file whose derived fields do not match is
refused. `mpc-keytool inspect --manifest FILE` checks a manifest offline and prints what it
describes. The `genesis_validators_root` is deliberately not in the manifest: the chain is bound
by the history import and the activation, where it is checked against the interchange.

### Encrypted share (`node-<index>.enc`)

| Field | Content |
| --- | --- |
| `format`, `version`, `suite` | `eth-mpc-signer/encrypted-key-share`, `1`, HPKE base mode, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305 (RFC 9180) |
| `ceremony_id`, `manifest_digest` | the import it belongs to |
| `participant_index`, `participant_identity`, `recipient_key` | the node it is for |
| `encapsulated_key`, `ciphertext` | the HPKE output; the plaintext is the share (index and scalar) |

HPKE's `info` holds a domain string, the manifest digest, the index, the identity and the
recipient key; the AEAD's associated data holds the whole public header. Moving an envelope to
another node, ceremony or manifest, or changing any header field, makes decryption fail. A node
opens an envelope only after checking, in order: the format, the registered manifest's digest and
ceremony, that the index and identity are its own, that the recipient key is its key; then it
decrypts, checks the decrypted index, and verifies the share against the registered commitments.
Installing the same share again answers `already_stored`; a different share for an index that
already has one is refused (`409`).

## Compatibility

**EIP-2335.** Keystore version 4, `scrypt` or `pbkdf2` (HMAC-SHA256) with `dklen` 32, checksum
`sha256`, cipher `aes-128-ctr`; the password processed as the EIP specifies (NFKD, control codes
removed). KDF parameters are bounded (scrypt memory 1 GiB, `p ≤ 16`, PBKDF2 at most 10 million
rounds) so a hostile keystore cannot exhaust the dealer. The decrypted secret must be a valid,
non-zero scalar, and its public key must equal the keystore's `pubkey` when present. The EIP's
scrypt and PBKDF2 test vectors decrypt to the published secret (`tests/fixtures/eip2335`). The
cryptography is RustCrypto's (`scrypt`, `pbkdf2`, `aes`, `ctr`, `sha2`) and commonware's BLS12-381
(`blst`); none of it is implemented here.

**Signatures.** Any 3 of the 4 shares recover exactly the signature the original secret gives
(compared byte for byte with `blst` signing with the original secret); 2 shares cannot.

**EIP-3076.** Interchange format version 5, complete or minimal; see
[slashing-protection.md](slashing-protection.md#imported-history-eip-3076).

## Migration procedure

The previous signer must be stopped before its history is exported, and must stay stopped. There
must never be a moment when two signers can sign for the key. Duties due between the stop and the
activation are missed: that is the price of the order. On the devnet the gap was 5.9 s, and no
attestation was missed ([ethereum-devnet.md](ethereum-devnet.md#migration-run-e)); by hand it is
the time the operator takes.

1. **Prepare the nodes.** On each node: `mpc-keytool share-key --out /secure/share-key.json`, and
   restart the node with `--share-encryption-key /secure/share-key.json`. Collect each node's
   `GET /identity` into `committee.json`.
2. **Stop the previous signer for this key, for good.** Remove the key from the validator client
   (or stop the client) and disable every automatic restart: service managers, orchestrators,
   failover or backup signers, other machines with a copy of the keystore. With Lighthouse, the
   keymanager API does both the removal and the export in one call:
   `DELETE /eth/v1/keystores {"pubkeys": ["0x.."]}` returns the key's EIP-3076 history in
   `slashing_protection` and deletes the keystore from the client (keep your backup of it).
3. **Export the history after the stop.** The interchange must include every message the previous
   signer signed. An export taken while it still ran may miss its latest duties.
4. **Split offline.** On a machine without network access:

   ```bash
   mpc-keytool split --keystore keystore.json --committee committee.json \
     --ceremony-id validator-migrated --output ./validator-shares
   # Keystore password:          (read from the terminal; or --password-file FILE, never an argument)
   ```

   The output directory is created with mode `0700` (it must not exist), each file with `0600`
   and never overwritten. It holds `manifest.json` and one `node-<index>.enc` per node. The tool
   verifies every share against the commitments, and the commitments' constant term against the
   keystore's public key, before writing anything. Nothing secret is printed or written in plain
   text. Randomness comes from the operating system.
5. **Register** through any node, approved:
   `mpc-admin --nodes ... draft register-import --request "{\"manifest\": $(cat validator-shares/manifest.json)}" --output register.json`,
   the approvers sign it offline (`mpc-admin sign`), then `mpc-admin --nodes ... submit --command
   register-alice.json --command register-bob.json`. It posts `POST /keys/import` with
   `{"manifest": .., "authorization": ..}`. The answer is the import's state
   (`GET /keys/import/validator-migrated` on any node).
6. **Install each share on its own node**:
   `curl -s localhost:<port of node i>/keys/import/share -H 'content-type: application/json' -d @validator-shares/node-<i>.enc`. A
   node refuses an envelope addressed to another node (`403`). Wait until `ready_shares` lists all
   four (three are the minimum for activation).
7. **Dry-run the history import** (changes nothing, decides nothing through consensus):

   ```bash
   jq -n --slurpfile i history.json '{interchange: $i[0], validators: ["0x.."], dry_run: true}' |
     curl -s localhost:8080/slashing-protection/import -H 'content-type: application/json' -d @-
   ```

   It parses the interchange, refuses it if it is slashable in itself, and checks every record of
   it against what the network already signed for the key. The answer gives the summary that would
   enter consensus.
8. **Import the history**: the same import, approved (P0.1): `mpc-admin --nodes ... draft
   import-history --interchange history.json --validator 0x.. --output import.json`, the
   approvers check it (`mpc-admin show`: every key, record counts and ranges, the floors, the
   interchange digest) and sign it offline, then `mpc-admin submit`. It is decided by consensus
   and answered with `outcome: imported` and the block height. Without approvals it is refused
   (`403`).
9. **Activate**, with the operator's acknowledgment, approved as in step 5 (`draft activate`):

   ```bash
   mpc-admin --nodes ... draft activate --output activate.json --request '{"public_key": "0x..",
     "genesis_validators_root": "0x..", "acknowledgment": {"previous_signer_stopped": true,
     "no_other_active_signer": true, "history_exported_after_stop": true,
     "automatic_restart_disabled": true}}'
   # each approver: mpc-admin sign --command activate.json --key <key> --output activate-<name>.json
   mpc-admin --nodes ... submit --command activate-alice.json --command activate-bob.json
   ```
10. **Point the validator client at the network** (Web3Signer API) and check that it attests in the
    beacon chain. `GET /slashing-protection/export/{public_key}` gives the history the network
    holds, for an audit. It is not a way to move the key out: the network has no command that stops
    it signing for a key, and the export is served while it may sign
    ([slashing-protection.md](slashing-protection.md#compared-with-eip-3076)).

## Failure recovery

| Situation | What happens | What to do |
| --- | --- | --- |
| Wrong keystore password | `split` stops; nothing written | Run again |
| Committee changed, or a node's share key replaced, after the split | Registration refused (`400`), or the node cannot open its envelope | Split again with the current committee (a new manifest) |
| Registration timed out (`504`) | It may still be decided | `GET /keys/import/{id}`; registering the same manifest again is idempotent |
| A node was offline during installation | Its share is not acknowledged | Install it when the node is back; 3 acknowledged shares suffice to activate and sign |
| A node restarts after installing | It reloads its share from its storage | Nothing |
| A node loses its storage after installing | It holds no share; the key still signs with the 3 others | Recover the node from a peer ([recovery.md](recovery.md)), then install its envelope again (kept, encrypted to that node's key). Without the envelope, the 4th share cannot be replaced: a new split is a new manifest, and the key cannot be registered twice (resharing is not implemented) |
| History refused as slashable in itself, or conflicting with the network's records | Nothing imported | Investigate: two signers may have used the key |
| History for another chain | Refused (`409`) | Use the interchange of the chain the key validates on |
| Activation refused | The `refusal.reason` names the missing step | Complete it; activation is idempotent once decided |
| A newer interchange appears after activation (the previous signer was not stopped) | Refused (`409 activated`): the floors are fixed once the key signs | Treat it as an incident: the key had two signers. Stop its validator client, and investigate |

## Assumptions

These are operational. Nothing in this network can verify them; the acknowledgment records that
an operator asserted them, at a block height, and nothing more:

- **The previous signer is stopped** for this key, with its automatic restart disabled, and no
  other signer (failover, backup, another machine with the keystore) controls it.
- **The history was exported after the stop** and is complete for the chain. An incomplete history
  lowers protection to what it contains: the network cannot know about messages that are not in
  it.
- **The dealer machine is trusted** while it holds the decrypted secret: offline, not
  compromised, wiped or destroyed according to the operator's policy afterwards.
- **The keystore and its backups are controlled**: anyone with them can sign outside the network.

A duplicate signer is therefore possible through operator error, and the network does not detect
it: slashing protection applies to what this network signs, not to what a copy of the key signs
elsewhere.

## Limitations

- **L-1 stays open.** A rollback of every node's storage loses the imported floors along with the
  rest of the history, and the network can then sign a slashable duty, exactly as for a DKG key.
- **The secret existed in full** (above). Zeroization is best effort: the buffers holding the
  password, the derived key, the decrypted secret and plaintext shares are `Zeroizing`; copies made
  by the libraries (commonware's scalar and polynomial types), the operating system or swap are not
  controlled.
- **Fixed committee.** The split is for the committee at that time. No resharing, no committee
  change.
- **The history enters consensus as EIP-3076's minimal form**: the latest block and the latest
  attestation per validator ([slashing-protection.md](slashing-protection.md#imported-history-eip-3076)).
  That is what makes import safe for histories of any size, and why the network refuses even the
  exact repetition of the previous signer's latest messages.
- **Imports cannot be undone.** Floors only rise. Before the activation, an interchange with a
  wrong far-future slot or epoch stops the key for good, and the key cannot be registered again;
  any client of the node API can submit one (no authentication). Check the import state
  (`GET /keys/import/{ceremony_id}`) before activating (audit L-17). After the activation, no
  import is accepted.
- **Interoperability of the export is modeled, not tested.** It is checked against a reference
  implementation of EIP-3076's conditions and by reading Lighthouse's import; no other client has
  imported one ([slashing-protection.md](slashing-protection.md#compared-with-eip-3076)).
- **The node operations are HTTP endpoints** of the existing localhost-only node API (like
  `/dkg/start` and `/validators/activate`), because they are consensus commands of the running node.
  The offline steps are the CLI.

## Operator checklist

- [ ] Each node has its own share-encryption key (`0600`), and `GET /identity` shows it.
- [ ] `committee.json` lists the current committee.
- [ ] The previous signer no longer has the key, and cannot get it back on its own: services,
      orchestrators and failover disabled; every other copy of the keystore accounted for.
- [ ] The EIP-3076 history was exported after the stop, from the signer that signed last.
- [ ] The split ran offline; the public key in its output is the validator's.
- [ ] Registration, then every node's share installed (`ready_shares`).
- [ ] The dry run is clean; the import answered `imported`.
- [ ] Activation with the acknowledgment, only once everything above is true.
- [ ] The validator client signs through the network only; attestations seen in the beacon chain.
- [ ] Envelopes and the manifest archived; the decrypted keystore and password removed from the
      dealer machine according to policy.

## Tests

| What | Tests |
| --- | --- |
| EIP-2335 vectors (scrypt, PBKDF2); wrong passwords; malformed, tampered, out-of-bounds keystores | `tests/key_import.rs`: `eip2335_vectors_decrypt_to_the_published_secret`, `wrong_passwords_and_malformed_keystores_are_refused` |
| Any 3 shares sign as the original key (against `blst` with the original secret); 2 cannot | `any_three_shares_sign_exactly_as_the_original_key_and_two_cannot` |
| Manifests: round trip, only public data; a changed commitment, committee or threshold refused | `manifests_round_trip_and_refuse_tampering` |
| Envelopes open only for their node, manifest and ceremony; a tampered header or ciphertext fails | `envelopes_open_only_for_their_node_manifest_and_ceremony` |
| The CLI: permissions, no overwrite, no secret in its output | `keytool_splits_a_keystore_into_four_encrypted_shares` |
| Lifecycle in the state machine: activation only after history, shares and acknowledgment; restart | `storage::tests::validator::imported::imported_keys_activate_only_after_history_shares_and_acknowledgement` |
| Altered import state on disk: the node refuses to start | `storage::tests::validator::imported::altered_import_state_fails_closed` |
| An activated key takes no history (far in the future, older, the same, another chain), and no command of any kind changes its floors; the same after a restart | `eth::interchange::tests::no_history_is_imported_once_the_key_is_activated`, `storage::tests::validator::imported::an_activated_imported_key_keeps_its_floors_whatever_the_command`, E2E-IMP-1 |
| EIP-3076 parsing, the official interchange tests, floors, export | [slashing-protection.md](slashing-protection.md#imported-history-eip-3076) |
| The whole flow on 4 real processes: registration, install, every refusal, dry run, import, activation, signatures equal to the original key's, one keyholder offline, restart, re-registration, export | `tests/e2e/import.rs`: E2E-IMP-1 |
| A node without a share-encryption key; a DKG key takes no imported history and no acknowledgment | E2E-IMP-2 |
| A genesis validator migrated from Lighthouse's local keystore on the devnet | `integration/ethereum` ([ethereum-devnet.md](ethereum-devnet.md#migration-of-a-genesis-validator)) |
