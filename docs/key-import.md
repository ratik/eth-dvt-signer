# Importing an existing validator key

An existing Ethereum validator, with an EIP-2335 keystore and a signing history, can move to this
network without changing its public key. An offline tool splits the keystore into 3-of-4 Shamir
shares, one encrypted share per node. Consensus registers the public part, each node installs only
its own share, consensus imports the previous signer's EIP-3076 history, and only then activates
the key. From then on, the key signs like a key the DKG created, under the same authorization and
slashing protection ([slashing-protection.md](slashing-protection.md)).

**Not the guarantee of a DKG.** A DKG key never exists in one place. An imported key existed in full
before the split: in the keystore, in its backups, wherever its password was kept, and in the memory
of the machine that ran the split. Whoever holds the keystore and its password can sign outside this
network and bypass its slashing protection. The import moves the signing. It cannot destroy copies
of the key.

**Not production-ready**, like the rest of the network ([ethereum-signing.md](ethereum-signing.md)).
The plain node API has no authentication and binds to `127.0.0.1`. The whole-network rollback
limitation L-1 applies to imported keys unchanged
([slashing-protection.md](slashing-protection.md#whole-network-rollback-l-1)).

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

The split uses the DKG's own representation: commonware's `Sharing` in mode `NonZeroCounter`.
Participant `i` (its position in the sorted committee) holds `f(i + 1)`. The Feldman commitments are
`a_k · G1`, and the constant commitment is the validator key. Signing uses only this sharing, which
every key origin exposes in the same form. So no signing code tells the two kinds of key apart. Only
the lifecycle before activation differs.

## Lifecycle

```
PREPARED          offline: mpc-keytool split ──> manifest.json + node-<i>.enc (no network)
   │  POST /keys/import (manifest, approved) ──> RegisterImportedKey ──consensus──>
REGISTERED        an imported ceremony, a validator key (not activated), an empty import state
   │  POST /keys/import/share on each node ──> the node opens and verifies its own share, stores it,
   │  and submits a ReadyAck signed with its consensus key ──> ShareReady ──consensus──>
   │  (ready set: the participants whose signed acknowledgment is committed)
   │  POST /slashing-protection/import (EIP-3076, approved) ──> ImportSlashingProtection ──consensus──>
HISTORY_IMPORTED  floors from the previous signer's latest block and attestation, chain fixed
   │  POST /validators/activate + acknowledgment, approved ──> ActivateImportedValidator ──consensus──>
ACTIVATED         signs, through the Web3Signer API, like any validator key
```

The registration, the history import and the activation are protected operations
([administration.md](administration.md)). Each one takes effect only with a threshold of the
approvers' offline signatures over the exact manifest, history or activation, and with the
network's next administrative nonce. Without them the API answers `403`, and honest voters refuse
the command. The operator's acknowledgment is part of what the approvers sign.

Shares can be installed before or after the history import. Every node decides each command
against the committed state. Activation checks everything at the moment consensus decides it:

| Command | Checked | Refused when |
| --- | --- | --- |
| `RegisterImportedKey {manifest}` | The manifest is well formed: version, protocol, the committee in committee order, the threshold, `threshold` commitments, distinct share-encryption keys, a valid G1 point at every position, the constant commitment equal to the validator key. | The ceremony id is in use with another manifest (`409`). The key is already registered, as a DKG or an imported key (`409`: a key is registered once). The manifest is invalid (`400`). |
| `ShareReady {round, manifest digest, participant, signature}` | The participant's Ed25519 signature, with its consensus key, over the round and the manifest digest (own namespace). | Ignored: unknown import, another manifest digest, not a participant, bad signature. |
| `ImportSlashingProtection {chain, digest, validators}` | Every named key is an imported key, not activated, of that chain (the chain of its earlier imports). Its summary is not slashable against what this network signed for it. | `activated` (its floors are fixed while it signs), `other_chain`, `unknown_validator`, `not_imported` (a DKG key), `conflict` with this network's records. Nothing is imported. |
| `ActivateImportedValidator {key, chain, acknowledgment}` | History imported for `chain`; acknowledged shares `≥` threshold; all four acknowledgment flags set. | `no_imported_history`, `history_for_another_chain`, `shares_not_ready`, `not_acknowledged`, `other_chain` (already active for another chain). |

`ActivateValidator` (the DKG activation) refuses an imported key (`imported_key`). The imported
activation refuses a DKG key (`not_imported`). So neither path skips the other's checks. The API
answers `400` for an imported key without an acknowledgment, and for an acknowledgment of a DKG key.

**No reset.** There is no unregister, delete or reset command. The same manifest again is
idempotent. The same key under another manifest or ceremony id is refused, so starting over never
replaces a key's records, floors or activation. Imports only raise floors: an older or repeated
interchange changes nothing (`outcome: unchanged`). Once the key is activated, the state machine
refuses every import (`activated`): nothing changes its floors while it signs.

**The ready set is not the coordinator's word.** Each keyholder acknowledges its own share with its
consensus identity, after it decrypted the share and checked it against the registered
commitments. A coordinator or a single node cannot claim another node's share.

## Formats

The manifest, the encrypted shares and the share-encryption key file carry fixed `format` and
`version` fields. Every file refuses unknown fields.

| `mpc-keytool` command | What it does |
| --- | --- |
| `share-key --out FILE` | Creates a node's share-encryption key file. |
| `split --keystore FILE --committee FILE --ceremony-id ID --output DIR` | Splits the keystore. Options: `--password-file FILE` (default: read from the terminal), `--attestation-policy FILE` with `--jwks FILE` (sealed nodes). |
| `inspect --manifest FILE` | Checks a manifest offline and prints what it describes. |

### Committee (`committee.json`, input of `split`)

```json
{"participants": [{"identity": "0x<ed25519 public key>", "share_encryption_key": "0x<X25519 public key>"}, ...]}
```

Take the values from `GET /identity` of each node, which also gives its `participant_index`. The
tool sorts the members as the network does. Registration refuses the manifest unless the members are
exactly the network's committee.

For sealed nodes ([tee.md](tee.md)), `mpc-admin --nodes ... attest --policy policy.json --committee
committee.json` writes this file with each member's `index` and attestation `evidence`. Then
`mpc-keytool split --attestation-policy policy.json --jwks jwks.json` encrypts only to keys that an
image the policy allows attested. Before it reads the keystore, it refuses if a member has no
evidence, if the evidence fails the policy (signature, freshness, TDX, debug state, measurements),
or if the evidence attests other keys than the member's.

### Share-encryption key (`mpc-keytool share-key --out FILE`)

Each node has one X25519 key pair, used for nothing else. The file holds the secret key
(`eth-mpc-signer/share-encryption-key`). It is created with mode `0600` and never overwritten. The
node takes it with `--share-encryption-key FILE`, and refuses to start if group or others can read
the file. A node without it serves the network normally, but cannot install imported shares (`409`).
A sealed node makes its share-encryption key in its vault and refuses `--share-encryption-key`.

### Manifest (`manifest.json`, public)

| Field | Content |
| --- | --- |
| `format`, `version` | `eth-mpc-signer/key-import-manifest`, `1` |
| `ceremony_id` | the id the key is registered under |
| `import_id` | 16 random bytes: two splits of one key never share a digest |
| `validator_public_key` | the keystore's public key (compressed G1) |
| `protocol_version`, `threshold` | the network's (`3`) |
| `participants` | per member: `index`, `identity`, `share_encryption_key`, `verification_share` (derived) |
| `commitments` | the Feldman commitments (`threshold` of them), constant term (the validator key) first |
| `curve`, `secret_sharing`, `share_encryption` | the algorithms' names, fixed by the version (other names are refused) |
| `manifest_digest` | SHA-256 of a namespace and the binary manifest (derived) |

Reading the file recomputes the derived fields, and refuses a file whose derived fields do not
match. The manifest has no `genesis_validators_root`, on purpose. The history import and the
activation bind the chain, and consensus checks it against the interchange.

### Encrypted share (`node-<index>.enc`)

| Field | Content |
| --- | --- |
| `format`, `version`, `suite` | `eth-mpc-signer/encrypted-key-share`, `1`, HPKE base mode, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305 (RFC 9180) |
| `ceremony_id`, `manifest_digest` | the import it belongs to |
| `participant_index`, `participant_identity`, `recipient_key` | the node it is for |
| `encapsulated_key`, `ciphertext` | the HPKE output; the plaintext is the share (index and scalar) |

HPKE's `info` holds a domain string, the manifest digest, the index, the identity and the recipient
key. The AEAD's associated data holds the version, the suite, the ceremony, the manifest digest, the
index, the identity and the recipient key. Decryption fails if the envelope moves to another node,
ceremony or manifest, or if any of these fields changes.

A node checks an envelope in this order:

1. the format, version and suite;
2. the registered manifest's digest and ceremony;
3. that the index and identity are its own (else `403`);
4. that the recipient key is its key (else `403`);
5. decryption, then the decrypted index;
6. the share against the registered commitments.

Installing the same share again answers `already_stored`. A different share for an index that
already has one is refused (`409`).

## Compatibility

**EIP-2335.** Keystore version 4. KDF `scrypt` or `pbkdf2` (`hmac-sha256`) with `dklen` 32, checksum
`sha256`, cipher `aes-128-ctr`. The password is processed as the EIP specifies (NFKD, control codes
removed). KDF parameters are bounded (scrypt memory 1 GiB, `p ≤ 16`, PBKDF2 at most 10 million
rounds), so a hostile keystore cannot exhaust the dealer machine. The decrypted secret must be a
valid, non-zero scalar. Its public key must equal the keystore's `pubkey` when present. The EIP's
scrypt and PBKDF2 test vectors decrypt to the published secret (`tests/fixtures/eip2335`). The
cryptography is RustCrypto's (`scrypt`, `pbkdf2`, `aes`, `ctr`, `sha2`) and commonware's BLS12-381
(`blst`). None of it is implemented here.

**Signatures.** Any 3 of the 4 shares recover exactly the signature that the original secret gives
(compared byte for byte with `blst` signing with the original secret). 2 shares cannot.

**EIP-3076.** Interchange format version 5, complete or minimal; see
[slashing-protection.md](slashing-protection.md#imported-history-eip-3076).

## Migration procedure

Stop the previous signer before you export its history, and keep it stopped. There must never be a
moment when two signers can sign for the key. Duties due between the stop and the activation are
missed: that is the price of this order. On the devnet (run E) the gap was 5.9 s, and the validator
still attested in that epoch ([ethereum-devnet.md](ethereum-devnet.md#migration-run-e)). By hand,
the gap is the time the operator takes.

1. **Prepare the nodes.** On each node, run `mpc-keytool share-key --out /secure/share-key.json`,
   and restart the node with `--share-encryption-key /secure/share-key.json`. Collect each node's
   `GET /identity` into `committee.json`.
2. **Stop the previous signer for this key, for good.** Remove the key from the validator client
   (or stop the client). Disable every automatic restart: service managers, orchestrators, failover
   or backup signers, other machines with a copy of the keystore. With Lighthouse, one keymanager
   API call does both the removal and the export: `DELETE /eth/v1/keystores {"pubkeys": ["0x.."]}`
   returns the key's EIP-3076 history in `slashing_protection` and deletes the keystore from the
   client. Keep your own backup of the keystore.
3. **Export the history after the stop.** The interchange must include every message the previous
   signer signed. An export taken while it still ran may miss its latest duties.
4. **Split offline.** On a machine without network access:

   ```bash
   mpc-keytool split --keystore keystore.json --committee committee.json \
     --ceremony-id validator-migrated --output ./validator-shares
   # Keystore password:          (read from the terminal; or --password-file FILE, never an argument)
   ```

   The tool creates the output directory with mode `0700`; the directory must not exist. Each file
   gets mode `0600` and is never overwritten. The directory holds `manifest.json` and one
   `node-<index>.enc` per node. Before it writes anything, the tool verifies every share against the
   commitments, and the constant commitment against the secret's public key. It prints and writes
   nothing secret in plain text. Randomness comes from the operating system.
5. **Register** through any node, approved:

   ```bash
   mpc-admin --nodes ... draft register-import \
     --request "{\"manifest\": $(cat validator-shares/manifest.json)}" --output register.json
   # each approver, offline: mpc-admin sign --command register.json --key <key> --output register-<name>.json
   mpc-admin --nodes ... submit --command register-alice.json --command register-bob.json
   ```

   `submit` posts `POST /keys/import` with `{"manifest": .., "authorization": ..}`. The answer is the
   import's state, as `GET /keys/import/validator-migrated` gives it on any node.
6. **Install each share on its own node:**

   ```bash
   curl -s localhost:<port of node i>/keys/import/share -H 'content-type: application/json' \
     -d @validator-shares/node-<i>.enc
   ```

   A node refuses an envelope addressed to another node (`403`). Wait until `ready_shares` lists all
   four. Three is the minimum for activation.
7. **Dry-run the history import.** A dry run changes nothing and submits nothing to consensus:

   ```bash
   jq -n --slurpfile i history.json '{interchange: $i[0], validators: ["0x.."], dry_run: true}' |
     curl -s localhost:8080/slashing-protection/import -H 'content-type: application/json' -d @-
   ```

   It parses the interchange and refuses it if it is slashable in itself. It checks every record
   against what the network already signed for the key, and the floors against the time horizon.
   The answer gives the summary that would enter consensus.
8. **Import the history**, approved (P0.1):

   ```bash
   mpc-admin --nodes ... draft import-history --interchange history.json --validator 0x.. \
     --output import.json
   # each approver, offline: mpc-admin show (every key, record counts and ranges, the floors,
   # the interchange digest), then mpc-admin sign
   mpc-admin --nodes ... submit --command import-alice.json --command import-bob.json
   ```

   Consensus decides it. The answer is `outcome: imported` with the block height. Without approvals
   the API refuses it (`403`).
9. **Activate**, with the operator's acknowledgment, approved as in step 5:

   ```bash
   mpc-admin --nodes ... draft activate --output activate.json --request '{"public_key": "0x..",
     "genesis_validators_root": "0x..", "acknowledgment": {"previous_signer_stopped": true,
     "no_other_active_signer": true, "history_exported_after_stop": true,
     "automatic_restart_disabled": true}}'
   # each approver: mpc-admin sign --command activate.json --key <key> --output activate-<name>.json
   mpc-admin --nodes ... submit --command activate-alice.json --command activate-bob.json
   ```
10. **Point the validator client at the network** (Web3Signer API), and check that it attests in the
    beacon chain. `GET /slashing-protection/export/{public_key}` gives the history the network holds,
    for an audit. It is not a way to move the key out. The network has no command that stops it
    signing for a key, and it serves the export while it may still sign
    ([slashing-protection.md](slashing-protection.md#compared-with-eip-3076)).

## Failure recovery

| Situation | What happens | What to do |
| --- | --- | --- |
| Wrong keystore password | `split` stops; nothing is written | Run it again |
| The committee changed, or a node's share key was replaced, after the split | Registration refused (`400`), or the node cannot open its envelope (`403`) | Split again with the current committee (a new manifest) |
| Registration timed out (`504`) | It may still be decided | Read `GET /admin` and `GET /keys/import/{id}`. If the nonce moved, the registration applied. If not, submit the same document again |
| A node was offline during installation | Its share is not acknowledged | Install it when the node is back. 3 acknowledged shares are enough to activate and sign |
| A node restarts after installation | It reloads its share from its storage | Nothing |
| A node loses its storage after installation | It holds no share; the key still signs with the 3 others | Recover the node from a peer ([recovery.md](recovery.md)), then install its envelope again (keep the envelopes: each is encrypted to its node's key). A new split cannot help: it is a new manifest, and a key is registered once. Once the key is activated, a reshare can give the node a new share ([resharing.md](resharing.md)) |
| History refused as slashable in itself, or in conflict with the network's records | Nothing is imported | Investigate: two signers may have used the key |
| History for another chain | Refused (`409`) | Use the interchange of the chain the key validates on |
| Activation refused | `refusal.reason` names the missing step. An approved activation that finalized and was refused used its nonce | Complete the step, then draft and sign the activation again. Activation is idempotent once decided |
| A newer interchange appears after activation (the previous signer was not stopped) | Refused (`409 activated`): the floors are fixed once the key signs | Treat it as an incident: the key had two signers. Stop its validator client and investigate |

## Assumptions

These assumptions are operational. Nothing in this network can verify them. The acknowledgment
records that an operator asserted them, at a block height, and nothing more:

- **The previous signer is stopped** for this key, with its automatic restart disabled. No other
  signer (failover, backup, another machine with the keystore) controls the key.
- **The history was exported after the stop** and is complete for the chain. An incomplete history
  lowers protection to what it contains: the network cannot know about messages that are not in it.
- **The dealer machine is trusted** while it holds the decrypted secret: offline, not compromised,
  and wiped or destroyed afterwards according to the operator's policy.
- **The keystore and its backups are controlled.** Anyone with them can sign outside the network.

So a duplicate signer is possible through operator error, and the network does not detect it.
Slashing protection applies to what this network signs, not to what a copy of the key signs
elsewhere.

## Limitations

- **L-1 stays open, narrowed.** A rollback of every node's storage loses the imported floors along
  with the rest of the history, exactly as for a DKG key. The keyholders' restart floor still refuses
  a double proposal or a double vote of a slot or epoch before the restart. Without an anchor, a
  crafted surround vote is not refused. With the WORM anchor ([anchor.md](anchor.md)), the anchored
  marks refuse it too, and the nodes stop (exit status 77) when the records show a rollback.
- **The secret existed in full** (above). Zeroization is best effort. The buffers that hold the
  password, the derived key, the decrypted secret and plaintext shares are `Zeroizing`. Copies made
  by the libraries (commonware's scalar and polynomial types), the operating system or swap are not
  controlled.
- **The split is for one committee.** Registration accepts the manifest only if it names exactly
  the network's committee. Once activated, the key can be reshared like a DKG key (R1, R2:
  [resharing.md](resharing.md)).
- **The history enters consensus in EIP-3076's minimal form**: the latest block and the latest
  attestation per validator ([slashing-protection.md](slashing-protection.md#imported-history-eip-3076)).
  That makes import safe for histories of any size. It is also why the network refuses even an exact
  repetition of the previous signer's latest messages.
- **Imports cannot be undone.** Floors only rise. An import needs the approvers' signatures over
  exactly its history. The API and every voter refuse floors whose slot or epoch has not started
  (the time horizon), so a far-future interchange cannot stop the key for good. Floors in the past
  remain the operator's decision. Check the import state (`GET /keys/import/{ceremony_id}`) before
  you activate (audit L-17). After the activation, no import is accepted.
- **Interoperability of the export is modeled, not tested.** It is checked against a reference
  implementation of EIP-3076's conditions and by reading Lighthouse's import. No other client has
  imported one ([slashing-protection.md](slashing-protection.md#compared-with-eip-3076)).
- **The node operations are HTTP endpoints** of the existing node API (like `/dkg/start` and
  `/validators/activate`), because they are consensus commands of the running node. The offline
  steps are the CLI.

## Operator checklist

- [ ] Each node has its own share-encryption key (`0600`), and `GET /identity` shows it.
- [ ] `committee.json` lists the current committee.
- [ ] The previous signer no longer has the key and cannot get it back on its own: services,
      orchestrators and failover disabled; every other copy of the keystore accounted for.
- [ ] The EIP-3076 history was exported after the stop, from the signer that signed last.
- [ ] The split ran offline; the public key in its output is the validator's.
- [ ] Registration done, then every node's share installed (`ready_shares`).
- [ ] The dry run is clean; the import answered `imported`.
- [ ] Activation with the acknowledgment, only once everything above is true.
- [ ] The validator client signs through the network only; its attestations appear in the beacon
      chain.
- [ ] Envelopes and the manifest archived; the decrypted keystore and the password removed from the
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
| The whole flow on 4 real processes: registration, installation, every refusal, dry run, import, activation, signatures equal to the original key's, one keyholder offline, restart, re-registration, export | `tests/e2e/import.rs`: E2E-IMP-1 (`e2e_imp_1_an_imported_key_signs_only_once_safely_activated`) |
| A node without a share-encryption key; a DKG key takes no imported history and no acknowledgment | E2E-IMP-2 (`e2e_imp_2_nodes_without_keys_and_dkg_keys`) |
| Resharing an imported key keeps its imported floors | `tests/e2e/replace.rs`: `r2_e2e_6_slashing_protection_continuity` |
| A genesis validator migrated from Lighthouse's local keystore on the devnet | `integration/ethereum` ([ethereum-devnet.md](ethereum-devnet.md#migration-of-a-genesis-validator)) |
