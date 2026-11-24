# WORM anchor (audit L-1)

The anchor is an append-only log on S3, GCS or a local directory, outside the nodes' storage and
backups (`src/anchor/`, `--anchor`). Keyholders write records to it before they sign past what
their earlier records cover. At start, a node reads every node's latest record. It then compares
those records with the blocks it applies, and stops when they show that the whole network was
rolled back.

What the anchor adds to the restart floor
([slashing-protection.md](slashing-protection.md#the-restart-floor)):

| After a whole-network rollback | Restart floor alone | With the anchor |
| --- | --- | --- |
| Double proposal, double vote | Refused | Refused |
| A surround vote that a client crafts | **Signed** | Refused: no source below the anchored one |
| Development `POST /sign` of a forgotten nonce | **Signed** | Refused while the node's chain is not confirmed; the rollback is detected and every node stops |
| Detection of the rollback (forgotten administrative nonces, share generations, state) | None | Every node stops with exit status 77 |
| Every node restarted, storage intact | Signs again from the next slot and epoch | The same, once the records are confirmed (at start) |

`rollback::a2_whole_network_rollback` and `eth2::e2e_eth_l1_*` run without an anchor and fail
(they are `#[ignore]`). They show what the replicated state alone does.

## How it works

### Records

Each node keeps one chain of records, at:

```
<prefix>/<cluster id hex>/<node public key hex>/<sequence, 20 digits>
```

The hex has no `0x`. Each record is written create-only (`object_store`'s create mode):
`If-None-Match: *` on S3, `x-goog-if-generation-match: 0` on GCS, a hard link on a local
directory. A record holds:

| Field | Content |
| --- | --- |
| `cluster` | the cluster id (`GET /admin`); this is why a node needs `--approvers` to use an anchor |
| `node`, `sequence`, `previous` | the writer; its place in its chain, from 0, without gaps; the SHA-256 of its previous record (zero for the first) |
| `generation` | 0, raised by each acknowledged rollback ([below](#operating)) |
| `height`, `digest` | the latest block the writer had applied |
| `marks` | `{block_slot, source, target}`: the highest block slot, attestation source and attestation target the writer may sign up to, one set for all validator keys |
| `written_at` | the writer's clock, Unix milliseconds (informational) |
| signature | the node's Ed25519 key, namespace `_ETH_MPC_SIGNER_ANCHOR` |

A reader finds a node's latest record with `HEAD` requests: an exponential search, then a binary
search over the node's contiguous sequences. It checks the record's signature, its place, and its
link to the record before it.

### Writing ahead

A keyholder gives a partial for a new block or attestation only when its own latest record covers
the duty:

- a block: its slot is at or below `block_slot`;
- an attestation: its target is at or below `target`, and its source is at or below `source`.

Otherwise, the keyholder first writes a record that raises its marks to cover the duty. It holds
the partial (for its own coordinator or for a peer) until the write completes.

- One write covers every duty up to its marks: in practice one per epoch (the first attestation)
  and one per proposal. Concurrent requests share one write.
- **Heartbeat.** When a node applies a block, it writes a record if its applied height has moved
  and its latest record is older than `--anchor-heartbeat-secs` (default 600). So the records name
  recent blocks.
- Some partials need no write: PTC votes, envelopes, registrations and the other kinds. They are
  not slashable, or the restart floor bounds them. A duty loaded at start needs a write, and
  passes the gate and the anchored marks, like any other (audit BUG-11): above the restart floor
  this process has not signed it yet.
- **Degraded.** A write that fails, or gets no answer within 2 s (`WRITE_TIMEOUT`), degrades the
  keyholder:
  - it gives the held partials, and later ones, under the restart floor alone;
  - as it applies blocks, it tries the anchor again every 30 s (`RETRY`) with a catch-up record
    that holds the marks it signed meanwhile;
  - one successful write ends the degraded state.

  Readiness says `anchor_unavailable` (state `degraded`). Signing goes on.
- **A write whose answer was lost** (no answer within 2 s, or a lost reply) may still have landed.
  - The keyholder keeps the record it sent, and reads its own latest record back before the next
    write.
  - If its next place holds that same record, the record is its own. It counts as written, and the
    next record follows it. The same applies when the record lands between the read-back and the
    next write.
  - Any other record at that place, or beyond it, is another process's: a clone.
- **A clone.** When a write finds its place taken by another record, another process writes as
  this node: a copy of its data directory, or an older copy of it. The node stops with exit
  status 77.

### Reading, and the rules

At start, before anything runs, a node reads the anchor (20 s at most, `ANCHOR_READ_TIMEOUT`):

- every acknowledgment of a rollback ([below](#operating)), keeping those with a threshold of valid
  approvals;
- the latest record of every configured node: committee members and followers.

It leaves out a record of another cluster, and a node whose records do not verify (a faulty
writer). If its own records do not verify, it starts degraded.

The nodes are read at once, each with its own deadline (10 s, `ANCHOR_NODE_TIMEOUT`), and a node
is left out whatever went wrong with it: a malformed record, an error, or no answer in time.
Otherwise one node would decide the anchor for everyone, which is what the rules below are built
not to allow. A node's own place in the store is its own to fill, so what it writes there (junk,
a record at the last possible sequence) must cost that node's chain only.

The rules assume at most one faulty node (consensus's `f`, `anchor::FAULTY`). A signature needs
three keyholders. Each of them writes a record that covers the duty before it gives its partial. So the
records of at least two honest nodes cover every signed duty. The rules below use that: one faulty
record (a forged height, digest or marks) can neither satisfy nor block any of them.

- **Anchored marks.** Each mark is the second-highest value across the nodes' records, and at
  least the marks of every acknowledged rollback.
  - The keyholder gives no partial for a new block at or below the anchored slot.
  - It gives none for a new attestation with a target at or below the anchored target, or a source
    below the anchored source (a surround vote).
  - These marks apply on top of the restart floor. The keyholder refuses with `anchored_marks`.
  - This refusal is final for the duty. When too few keyholders may sign, the client gets `412`
    with `"protection": "anchored_marks"`
    ([slashing-protection.md](slashing-protection.md#the-restart-floor)).
- **Confirmation gate.** The keyholder gives no new partial (an Ethereum duty or a development
  signature) until two of the three highest records (by height) lie on its own chain: its block at
  that height has the record's digest.
  - While it waits, readiness says `anchor_behind` (state `syncing`), and the node submits no new
    authorization.
  - With fewer than three records (a new cluster), the gate is open.
  - The gate's refusal is not final, since the keyholder may sign once confirmed. It is reported as
    `beyond_horizon`, and the client gets `503`, not `412`.
- **Rolled back: stop with exit status 77** when:
  - (a) at start, the records of two or more nodes name other blocks at heights this node has
    applied;
  - (b) while the node applies blocks and is not confirmed yet, the same happens;
  - (c) the node is still not confirmed after it applied 32 blocks since start
    (`TIP_GRACE_BLOCKS`), and the network's finalized tip (marshal's) is below the gate height:
    the network finalizes below what it had finalized.

  A node that only lags (restored alone from an old backup, or offline for a while) sees the
  network's tip above the gate height. It catches up from its peers and is confirmed.
- **Unreachable at start.** The node starts degraded: the gate is open, there are no anchored
  marks, and the restart floor alone applies. It logs a warning. The keyholder writes a catch-up
  record once the anchor answers. The node checks the records again at its next start.

## Configuration

```sh
eth-dvt-signer ... --approvers approvers.json --anchor s3://anchor-bucket/eth-mpc \
    [--anchor-heartbeat-secs 600] [--anchor-acknowledgment acknowledgment.json]
```

| Flag | Default | Meaning |
| --- | --- | --- |
| `--anchor` | none | `s3://bucket/prefix`, `gs://bucket/prefix` or `file:///directory` (tests, development). The same on every node, outside every node's data directory and backups. Needs `--approvers`: the records are bound to the cluster id. |
| `--anchor-heartbeat-secs` | 600 | the heartbeat interval in seconds (at least 1) |
| `--anchor-acknowledgment` | none | the approvers' acknowledgment of a rollback ([below](#operating)); needs `--anchor` |

- **Credentials** come from the environment, as `object_store` reads them:
  - S3: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`, `AWS_REGION`, web
    identity, or instance metadata. The node sends a SHA-256 checksum with each write, which an
    Object Lock bucket requires.
  - GCS: `GOOGLE_APPLICATION_CREDENTIALS` or `GOOGLE_SERVICE_ACCOUNT`, or the VM's metadata server.
- **Followers** (R2, R3) count like committee members: every node reads their records. Every node
  with `--anchor` writes heartbeat records. A node writes ahead of partials once it holds shares.

### The bucket

The anchor protects only if the node operators cannot delete or rewrite it. So the bucket, its
account or project, and its retention belong to people other than the node operators (the
approvers, for example). The node cannot set retention per object through `object_store`, so
retention is the bucket's default. The examples below use one year.

**S3**

1. Create the bucket with Object Lock, and a default retention in compliance mode:

   ```sh
   aws s3api create-bucket --bucket anchor-bucket --object-lock-enabled-for-bucket \
       --create-bucket-configuration LocationConstraint=eu-central-1
   aws s3api put-object-lock-configuration --bucket anchor-bucket --object-lock-configuration \
       '{"ObjectLockEnabled":"Enabled","Rule":{"DefaultRetention":{"Mode":"COMPLIANCE","Days":365}}}'
   ```

2. **Deny deletes to everyone.** Compliance mode protects object versions. But a `DELETE` without
   a version still adds a delete marker, which hides the record from `GET` and `HEAD`. A hidden
   latest record would let a node, or someone with its credentials, write a different record at
   its place. A lifecycle rule can add delete markers too.

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
   `eth-mpc/<cluster>/acknowledgments/*`; `s3:GetObject` on `eth-mpc/<cluster>/*`; `s3:ListBucket`
   with the condition that `s3:prefix` starts with `eth-mpc/<cluster>/`.

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
  Existing records keep theirs. Each can be extended (`put-object-retention` with a later date),
  never shortened in compliance mode.
- **GCS:** a locked policy can only be increased (`gcloud storage buckets update
  --retention-period=730d`). The increase applies to existing objects too.
- After retention expires, only the bucket policy keeps records from deletion. A deleted record
  breaks its node's chain: readers then find no record for that node, or a broken link, and leave
  the node out. Keep records at least as long as the cluster runs, or acknowledge a new generation
  ([below](#operating)) before retention ends.

**Size.** About 250 bytes per record. A node writes roughly one record per epoch, plus one per
proposal and its heartbeats: under 100 KB per node per day on mainnet.

**Checking a bucket.** `mpc-admin anchor check` shows what the nodes would read. It cannot read the
bucket's retention or policy. `integration/anchor/check.sh s3://bucket/prefix [cluster-id]` (or
`gs://`) checks a real bucket. It needs the provider's CLI (`aws` or `gcloud`), `python3`, and the
credentials of a node's role. It writes one probe object under `<prefix>/check/`, which the bucket
retains like a record. It never deletes anything the bucket allows to be deleted: a delete that
succeeds is the failure it reports. It checks:

- WORM behaviour: a second create-only write is refused, and a delete is refused (on S3, also a
  version delete; on GCS, also a plain overwrite);
- on S3, that an Object Lock configuration exists and that the bucket policy denies
  `s3:PutLifecycleConfiguration` to everyone;
- the lifecycle rules. A policy that denies new rules leaves a rule set before it running, so the
  script reads the rules:
  - an expiration on S3 hides records behind delete markers: FAIL;
  - a move to Glacier or Deep Archive makes records readable only after a restore: FAIL;
  - a Delete on GCS removes records once retention ends: FAIL;
  - another storage class on GCS is still read at once: PASS;
  - a setting these credentials cannot read: UNCHECKED, for the bucket's owner to check;
- with a cluster id, the records (`mpc-admin anchor check`).

**Tested on GCS** (2026-11-12, [tee.md](tee.md)). Four sealed nodes wrote their records to a real
bucket with their VMs' accounts. After one node restarted, every node confirmed its chain against
the records. `check.sh` passed the bucket, and failed it once a Delete rule was added. The test
bucket's retention was 1 hour and not locked. Not yet tested on S3.

## Operating

**Visibility.**

- `GET /status` gives `anchor: {state, location, generation, sequence, height, marks, anchored}`.
  `state` is `confirmed`, `behind` (the gate is closed) or `degraded` (the anchor does not answer).
  `sequence`, `height` and `marks` are the node's latest record; `anchored` holds the anchored
  marks read at start.
- Readiness gives `anchor_behind` (state `syncing`; no new authorization is submitted) and
  `anchor_unavailable` (state `degraded`).
- `mpc-admin status` prints the anchor state of each node.
- Logs: `anchor: records read` at start (generation, gate height, anchored marks);
  `anchor: not signing` for each refusal; `anchor: record not written; degraded`; and, at debug
  level, `anchor: record written`.

**A node exits with status 77.** The anchor shows that this network lost what it had finalized.
Every node stops. Supervisors must not restart them in a loop. Then:

1. Find newer state. `mpc-admin anchor check --anchor <url> --cluster <id>` prints every node's
   latest record: the heights and blocks the network had reached. Add `--approvers approvers.json`
   to check the acknowledgments. A node, a backup or a disk snapshot that holds those blocks is the
   way back. Restore every node from it, and the nodes are confirmed at start.
2. **Only if the newer state is lost for good**, the approvers acknowledge the rollback. The
   approvers sign in turn: each signs the previous approver's output.

   ```sh
   mpc-admin anchor acknowledge --anchor <url> --cluster <id> --approvers approvers.json \
       --output acknowledgment.json
   # Each approver, offline:
   mpc-admin show --command acknowledgment.json --approvers approvers.json
   mpc-admin sign --command acknowledgment.json --key approver.key --output acknowledgment-1.json
   # The next approver signs acknowledgment-1.json, and so on. Start every node with the copy
   # that has a threshold of approvals:
   eth-dvt-signer ... --anchor <url> --anchor-acknowledgment acknowledgment-2.json
   ```

   - The acknowledgment names the next generation, the gate height and the block given up, and the
     anchored marks, which stay floors. It is signed with namespace
     `_ETH_MPC_SIGNER_ANCHOR_ACKNOWLEDGMENT`.
   - A node started with it checks the approvals. It writes the acknowledgment to
     `<cluster>/acknowledgments/<generation>-<hash>` (create-only), then continues in the new
     generation. If the anchor does not take the write within 20 s, the node does not start.
   - The node goes by the document it checked itself, never by what is at that place. Anyone who
     can write to the anchor can take the name first, with a copy that carries no valid approval,
     and WORM means the name can never be reused. Such a copy only makes the node warn.
   - Readers compare only the records of the highest acknowledged generation. They keep the marks
     of every acknowledgment.
   - No block or attestation signed before the rollback can be signed again differently: the
     acknowledged marks refuse it (`anchor::an_6`).
   - What the lost state had decided is gone: activations, authorizations, administrative nonces
     (L-25), and the share generations of reshares completed since. Reconcile them before you
     resume.
   - Keeping the flag on later starts is harmless.

**A node exits with status 77 alone, and logs `another process wrote at this node's next
record`.** Another process writes as this node: a copy of its data directory, or an older copy of
it, started somewhere. Find it and stop it before you restart this node.

## Limits

- **Degraded at run time.** While the anchor is down, a keyholder signs under the restart floor
  alone. The surround check and detection lapse for what it signs meanwhile. The alternative,
  refusing to sign, would make the anchor's availability the validators' availability.
- **Detection lags by up to one record.** A rollback to state newer than the latest records (about
  an epoch, or a heartbeat interval) is not detected. The marks and the floor still hold for
  slashing.
- **The development `POST /sign`** is covered by detection only: there is no record per nonce.
- **One faulty node.** The rules tolerate one faulty writer (`anchor::FAULTY`), as consensus does.
  Two colluding nodes can forge records that stop an honest network (a false rollback), open the
  gate on a rolled-back one, or lower the anchored marks below a duty that only one honest
  keyholder covered.
- **The marks are one set for all validator keys.** After a restart:
  - a new block of any key at or below the latest proposed slot is refused. Proposals are of the
    current slot, so with honest clients this costs nothing;
  - an attestation of any key with a source below the highest signed source is refused. A client
    whose view of the justified checkpoint lags loses that attestation.

  A client cannot raise the source mark past the current epoch: an attestation's source is at most
  its target, and its target is at most the current epoch (the time horizon). One forged record's
  marks are ignored (second-highest values).
- **Generation after a degraded start.** A node that started without the anchor writes its catch-up
  records in generation 0. If the cluster is in a later generation, readers ignore those records
  until the node's next start.
- **One provider.** One bucket: an outage degrades every node at once, and a provider that loses or
  rewrites objects defeats the anchor.

## Tests

| What | Tests |
| --- | --- |
| Record codec, signature, chain; marks | `anchor::tests` (`tests/unit/anchor.rs`) |
| Create-only writes, the latest-record search, faulty records (forged high, colluding, unsigned) | `anchor::tests` |
| Keeper: what needs a write, held partials, degraded and catch-up, heartbeats, the gate, refresh | `anchor::tests::keeper_tests` |
| A write whose answer was lost: taken as the node's own; a clone still found | `anchor::tests::lost_write_tests` |
| Watch: confirmed, lagging, rolled back (rules a to c) | `anchor::tests::watch_tests` |
| Acknowledgments: threshold, edits, merges, floors, written once | `anchor::tests::acknowledgment_tests` |
| S3 and GCS as `object_store` speaks to them: `If-None-Match`, checksum, SigV4, `x-goog-if-generation-match`, 412 | `tests/anchor_protocol.rs` (in-process fake) |
| Real processes, `file://` anchor, restart floor on | `anchor::an_1` (records, restart of every node), `an_2` (whole-network rollback: nothing signed, exit 77), `an_3` (one node rolled back catches up), `an_4` (a forged record ignored), `an_5` (unreachable at start, then recovered), `an_6` (acknowledged rollback) in `tests/e2e/anchor.rs` |
| A real bucket | `integration/anchor/check.sh` |
