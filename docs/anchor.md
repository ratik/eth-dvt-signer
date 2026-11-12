# WORM anchor (audit L-1)

The anchor is an append-only log on S3, GCS or a local directory, outside the nodes' storage and
backups (`src/anchor/`, `--anchor`). Keyholders write to it before they sign past what they
wrote before. A node reads it at start and while it runs, and stops when it shows that the whole
network was rolled back.

What it adds to the restart floor ([slashing-protection.md](slashing-protection.md#the-restart-floor)):

| After a whole-network rollback | Restart floor alone | With the anchor |
| --- | --- | --- |
| Double proposal, double vote | Refused | Refused |
| A surround vote a client crafts | **Signed** | Refused: no source below the anchored one |
| Development `POST /sign` of a forgotten nonce | **Signed** | Refused until the node's chain is confirmed; the rollback stops the network first |
| Detection of the rollback (forgotten administrative nonces, share generations, state) | None | Every node stops with exit status 77 |
| Every node restarted, storage intact | Signs again from the next slot and epoch | The same, once the records are confirmed (at start) |

`rollback::a2_whole_network_rollback` and `eth2::e2e_eth_l1_*` still run without an anchor and
still fail: they show what the replicated state alone does.

## How it works

### Records

Each node keeps one chain of records:

```
<prefix>/<cluster id hex>/<node public key hex>/<sequence, 20 digits>
```

Each record is written create-only (`If-None-Match: *` on S3, `x-goog-if-generation-match: 0` on
GCS, a hard link on a local directory). It holds:

| Field | Content |
| --- | --- |
| `cluster` | the cluster id (`GET /admin`): a node needs `--approvers` to use an anchor |
| `node`, `sequence`, `previous` | the writer, its place in its chain from 0, the SHA-256 of its previous record |
| `generation` | 0, raised by each acknowledged rollback (below) |
| `height`, `digest` | the latest block the writer had applied |
| `marks` | `{block_slot, source, target}`: the cluster-wide highest block slot and attestation source and target the writer may sign up to |
| `written_at` | the writer's clock (informational) |
| signature | the node's Ed25519 key, namespace `_ETH_MPC_SIGNER_ANCHOR` |

A reader finds a node's latest record with `HEAD` requests (an exponential, then a binary search
over its contiguous sequences), and checks its signature, its place and its link to the record
before it.

### Writing ahead

A keyholder gives a partial for a block or an attestation only if its own latest record covers
it: a block's slot at or below `block_slot`; an attestation's target at or below `target` and its
source at or below `source`. Otherwise it first writes a record that raises its marks to the duty,
and holds the partial (its own coordinator's request, or a peer's) until the write completes.

- One write covers every duty up to its marks: in practice one per epoch (the first attestation)
  and one per proposal. Concurrent requests share one write.
- A heartbeat record every `--anchor-heartbeat-secs` (default 600) while blocks are applied, so
  the records name recent blocks.
- Duties loaded at start (signed again after a restart) and PTC votes, envelopes, registrations
  and the other kinds need no write: they are not slashable, or the restart floor bounds them.
- **Degraded.** A write that fails, or takes more than 2 s, leaves the keyholder degraded: it gives
  the held partials under the restart floor alone, tries the anchor again every 30 s, and then
  writes a catch-up record with the marks it signed meanwhile. Readiness says
  `anchor_unavailable` (state `degraded`); signing goes on.
- **A write whose answer was lost** (no answer within 2 s, a lost reply) may still have landed.
  - The node keeps the record it sent and reads its own latest record back before the next
    write.
  - Its next place holding that very record means the record is its own: it counts as written,
    and the next record follows it. So does a place the record took between the read-back and
    the next write.
  - Without this, a slow write that landed made the next one find its place taken, and the node
    stopped as if a clone ran (until 2026-11-12).
- **A clone.** A write whose place is taken by another record means another process writes as
  this node (a copy of its data directory, or an older copy of it): the node stops, exit status
  77. After a lost write, so does any other record at the sent record's place, or beyond it.

### Reading, and the rules

At start, before anything runs, a node reads every configured node's latest record (20 s at
most). With at most one faulty node (consensus's `f`) and three keyholders per signature, every
signed duty is covered by the records of at least two honest nodes. The rules below use that:
one faulty record (a forged height, digest or marks) can neither satisfy nor block any of them.

- **Anchored marks.** Each mark is the second-highest value across the nodes' records. The
  keyholder gives no partial for a new block at or below the anchored slot, nor for an
  attestation with a target at or below the anchored target or a source below the anchored source
  (a surround vote). They apply on top of the restart floor.
- **Confirmation gate.** The keyholder gives no new partial (Ethereum duty or development
  signature) until two of the three highest records (by height) lie on its own chain: its block at
  that height has the record's digest. While it waits, readiness says `anchor_behind` and the node
  submits no new authorization. With fewer than three records (a new cluster) the gate is open.
- **Rolled back: stop, exit status 77**, when:
  - (a) at start, two nodes' records name other blocks at heights this node has applied;
  - (b) the same, while it applies blocks;
  - (c) after 32 blocks applied since start, the network's finalized tip (marshal's) is still
    below the gate height: the network finalizes below what it had finalized.

  A node that only lags (restored alone from an old backup, or offline for a while) sees the
  network's tip above the gate, catches up from its peers, and is confirmed.
- **Unreachable at start.** The node starts degraded (gate open, no anchored marks: the restart
  floor alone) and warns; the keyholder writes a catch-up record once the anchor answers. The
  records are checked again at its next start.

## Configuration

```sh
eth-mpc-signer ... --approvers approvers.json --anchor s3://anchor-bucket/eth-mpc \
    [--anchor-heartbeat-secs 600]
```

- **Location:** `s3://bucket/prefix`, `gs://bucket/prefix` or `file:///directory` (tests,
  development). The same on every node, and outside every node's data directory and backups.
- **Credentials** come from the environment, as each SDK reads them: `AWS_ACCESS_KEY_ID`,
  `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`, `AWS_REGION`, web identity or instance metadata
  for S3; `GOOGLE_APPLICATION_CREDENTIALS` or `GOOGLE_SERVICE_ACCOUNT` for GCS.
- **Needs `--approvers`:** the records are bound to the cluster id.
- **Followers** (R2, R3) read the records like voters, and write them once they hold shares.

### The bucket

The anchor protects only if the node operators cannot delete or rewrite it. The bucket, its
account or project and its retention belong to people other than the node operators (the
approvers, for example). The node cannot set retention per object through `object_store`, so
retention is the bucket's default. The default here is one year.

**S3**

1. Create the bucket with Object Lock, default retention in compliance mode:

   ```sh
   aws s3api create-bucket --bucket anchor-bucket --object-lock-enabled-for-bucket \
       --create-bucket-configuration LocationConstraint=eu-central-1
   aws s3api put-object-lock-configuration --bucket anchor-bucket --object-lock-configuration \
       '{"ObjectLockEnabled":"Enabled","Rule":{"DefaultRetention":{"Mode":"COMPLIANCE","Days":365}}}'
   ```

2. **Deny deletes to everyone.** Compliance mode protects object versions, but a `DELETE`
   without a version still adds a delete marker, which hides the record from `GET` and `HEAD`. A
   hidden latest record would let a node, or someone with its credentials, write a different one
   at its place. A lifecycle rule can add delete markers too.

   ```json
   {
     "Version": "2012-10-17",
     "Statement": [{
       "Sid": "AnchorIsAppendOnly",
       "Effect": "Deny",
       "Principal": "*",
       "Action": ["s3:DeleteObject", "s3:DeleteObjectVersion", "s3:PutLifecycleConfiguration"],
       "Resource": ["arn:aws:s3:::anchor-bucket", "arn:aws:s3:::anchor-bucket/*"]
     }]
   }
   ```

3. **One role per node:** `s3:PutObject` on `eth-mpc/<cluster>/<its public key>/*` and
   `eth-mpc/<cluster>/acknowledgments/*`; `s3:GetObject` on `eth-mpc/<cluster>/*`;
   `s3:ListBucket` with the condition `s3:prefix` starting with `eth-mpc/<cluster>/`. The node
   sends a SHA-256 checksum with each write, which an Object Lock bucket requires.

**GCS**

1. Versioning off, a retention policy of 365 days, then locked (irreversible):

   ```sh
   gcloud storage buckets create gs://anchor-bucket --location=europe-west3 \
       --retention-period=365d --uniform-bucket-level-access
   gcloud storage buckets update gs://anchor-bucket --lock-retention-period
   ```

2. **One service account per node:** `roles/storage.objectCreator` with the IAM condition
   `resource.name.startsWith("projects/_/buckets/anchor-bucket/objects/eth-mpc/<cluster>/<its
   public key>/")` (and the acknowledgments prefix), and `roles/storage.objectViewer` on
   `eth-mpc/<cluster>/`. While an object is retained, nobody can overwrite or delete it.

**Changing the retention**

- **S3:** `put-object-lock-configuration` with the new number of days applies to new records.
  Existing records keep theirs; each can be extended (`put-object-retention` with a later date),
  never shortened in compliance mode.
- **GCS:** a locked policy can only be increased (`gcloud storage buckets update
  --retention-period=730d`), and the increase applies to existing objects too.
- After retention expires, only the bucket policy keeps records from deletion. A deleted record
  breaks its node's chain: the node finds no latest record, or a broken link, and the readers
  ignore it. Keep records at least as long as the cluster runs, or acknowledge a new generation
  (below) before retention ends.

**Size.** About 200 bytes per record, roughly one per epoch per node plus heartbeats: under 100 KB
per node per day on mainnet.

`mpc-admin anchor check` shows what the nodes would read. It cannot read the bucket's retention
or policy: check them with the provider's own tools. `integration/anchor/check.sh` checks a real
bucket's WORM behaviour (create-only, no overwrite, no delete) with credentials you provide.

## Operating

**Visibility.**

- `GET /status` gives `anchor: {state, location, generation, sequence, height, marks, anchored}`.
  The state is `confirmed`, `behind` (the gate is closed) or `degraded` (the anchor does not
  answer).
- Readiness gives `anchor_behind` (state `syncing`; no new authorization is submitted) and
  `anchor_unavailable` (state `degraded`).
- `mpc-admin status` prints it for each node.
- Logs: `anchor: records read` at start (generation, gate height, anchored marks), `anchor: not
  signing` for each refusal, `anchor: record not written; degraded` and `anchor: record written`.

**A node exits with status 77.** The anchor shows that what this network finalized was lost:
every node stops, and supervisors must not restart them in a loop. Then:

1. Find newer state. `mpc-admin anchor check --anchor <url> --cluster <id>` prints every node's
   latest record: the heights and blocks the network had reached. A node, a backup or a disk
   snapshot that holds them is the way back: restore every node from it, and they are confirmed
   at start.
2. **Only if the newer state is lost for good**, the approvers acknowledge the rollback:

   ```sh
   mpc-admin anchor acknowledge --anchor <url> --cluster <id> --approvers approvers.json \
       --output acknowledgment.json
   # Each approver, offline:
   mpc-admin show --command acknowledgment.json --approvers approvers.json
   mpc-admin sign --command acknowledgment.json --key approver.key --output acknowledgment-1.json
   # Start every node with the copy that has a threshold of approvals:
   eth-mpc-signer ... --anchor <url> --anchor-acknowledgment acknowledgment-2.json
   ```

   The acknowledgment names the next generation, the gate height and block given up, and the
   anchored marks, which stay floors. It is signed with namespace
   `_ETH_MPC_SIGNER_ANCHOR_ACKNOWLEDGMENT`. A node started with it checks the approvals, writes it
   to `<cluster>/acknowledgments/<generation>-<hash>` (create-only), and continues in the new
   generation. Readers compare only the records of the highest acknowledged generation, and keep
   the marks of every acknowledgment. Nothing signed before the rollback can be signed again
   differently (`anchor::an_6`). What the lost state had decided is gone: activations,
   authorizations, administrative nonces (L-25), and share generations of reshares completed
   since. Reconcile them before you resume. Keeping the flag on later starts is harmless.

**A node exits 77 alone, with "exists already".** Another process writes as this node: a copy of
its data directory, or an older copy of it started somewhere. Find it and stop it before you
restart this node.

## Limits

- **Degraded at run time.** While the anchor is down, a keyholder signs under the restart floor
  alone; the surround check and detection lapse for what it signs meanwhile. The alternative,
  refusing to sign, would make the anchor's availability the validators' availability.
- **Detection lags by one write.** A rollback to state newer than the latest records (about an
  epoch, or a heartbeat interval) is not detected. The marks and the floor still hold for
  slashing.
- **The development `POST /sign`** is covered by detection only: no record per nonce.
- **One faulty node.** The rules tolerate one faulty writer (`anchor::FAULTY`), as consensus
  does. Two colluding nodes can forge records that stop an honest network (a false rollback),
  open the gate on a rolled-back one, or lower the anchored marks below a duty only one honest
  keyholder covered.
- **Marks are cluster-wide** (one set for every validator key). After a restart, a new block of
  any key at or below the latest proposed slot is refused: proposals are of the current slot, so
  this costs nothing with honest clients. An attestation of any key with a source below the
  highest signed source is refused too: a client whose view of the justified checkpoint lags
  loses that attestation. A client cannot raise the source mark past the current epoch: an
  attestation's source is at most its target, and its target at most the current epoch (the time
  horizon). One forged record's marks are ignored (second-highest values).
- **Generation after a degraded start.** A node that started without the anchor writes its
  catch-up records in generation 0. If the cluster is in a later generation, readers ignore those
  records until the node's next start.
- **One provider.** One bucket: an outage degrades every node at once, and a provider that loses
  or rewrites objects defeats the anchor.

## Tests

| What | Tests |
| --- | --- |
| Record codec, signature, chain; marks | `anchor::tests` (`tests/unit/anchor.rs`) |
| Create-only writes, the latest-record search, faulty records (forged high, colluding, unsigned) | `anchor::tests` |
| Keeper: what needs a write, held partials, degraded and catch-up, heartbeats, the gate, refresh | `anchor::tests::keeper_tests` |
| Watch: confirmed, lagging, rolled back (rules a to c) | `anchor::tests::watch_tests` |
| Acknowledgments: threshold, edits, merges, floors, written once | `anchor::tests::acknowledgment_tests` |
| S3 and GCS as `object_store` speaks to them: `If-None-Match`, checksum, SigV4, `x-goog-if-generation-match`, 412 | `tests/anchor_protocol.rs` (in-process fake) |
| Real processes, `file://` anchor, restart floor on | `anchor::an_1` (records, restart of every node), `an_2` (whole-network rollback: nothing signed, exit 77), `an_3` (one node rolled back catches up), `an_4` (a forged record ignored), `an_5` (unreachable at start, then recovered), `an_6` (acknowledged rollback) in `tests/e2e/anchor.rs` |
