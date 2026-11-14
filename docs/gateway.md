# The gateway: a validator client's entry to the MPC network

`mpc-gateway` serves the Web3Signer Ethereum signing API (EIP-3030) to a validator client
(Lighthouse, Teku, Prysm). It signs through the nodes of the network:

```
validator client ──HTTP (loopback) or mTLS──> mpc-gateway ──mTLS 1.3, attested key──> node 0
                   (Web3Signer API)                                                ├─> node 1
                                                                                   └─> …
```

A validator client takes one URL per key, and any node of the network can coordinate a signature.
The gateway is that URL. It holds no key and no slashing state. The nodes decide every duty through
consensus and refuse whatever their slashing protection and policies refuse.

## What it does

### Signing (`POST /api/v1/eth2/sign/{key}`)

1. **The signing root.** The gateway computes the root itself, from the request and its pinned
   chain. It uses the nodes' own parser (`eth::web3signer::duty_request`).
2. **Hedged failover.** The gateway asks the usable nodes in their `--nodes` order. A node that
   failed in the last 2 s goes last; a node that returned a bad signature goes last for 60 s.
   - If a node has not answered after `--hedge-after-ms` (1000 ms), the gateway also asks the next
     node. The first final answer wins, and the other attempt is dropped.
   - A failure makes the gateway ask the next node at once. A failure is no answer, a timeout
     (`--node-timeout-ms`, 6000 ms), or status 502, 503 or 504.
   - **A node that answered 502, 503 or 504 is asked once more**, after the others
     (`route::MAX_TRIES`: 2 tries per node). Such a node could not finish in time, often while
     consensus waited out a stopped leader's view. By its second turn the duty is usually decided,
     and the repeat returns its signature.
   - No new attempt starts after `--request-deadline-ms` (10000 ms). Lighthouse waits 12 s.
   - A repeated request is safe. Consensus decides a duty once, and a repeat gets the same
     signature (`AlreadyAccepted`).
3. **Every signature is checked before it is returned.**
   - It must be the validator key's BLS signature of the root that the gateway computed.
   - A signature that does not verify is not passed on. The gateway logs it, counts it in
     `mpc_gateway_invalid_signatures_total`, puts the node last for 60 s, and asks the next node.
   - If the gateway cannot compute a request's root and a node still signs it, the gateway does
     not pass the signature on (`502`).
   - So a faulty coordinator (one node, within `f = 1`) cannot make the validator publish a wrong
     signature and miss the duty.
4. **A refusal needs two nodes.** Any other status (for example 400, 403, 404, 412 or 500) is one
   node's word, not the network's, so the gateway asks the next node and returns the refusal that
   `route::REFUSAL_AGREEMENT` (2) nodes gave the same status for. Consensus decides a duty once,
   so an honest network refuses it on every node, and the second node answers at once: a genuine
   refusal costs one extra request. This includes a duty that the keyholders' restart floor or
   anchored marks refuse (`412` with `protection`).
   - **A node whose refusal the others contradict is marked faulty** for 60 s, as a bad signature
     makes it: they agreed on another status, or one of them signed. So a faulty node (within
     `f = 1`) that refuses everything costs one attempt per request, and then goes last.
   - With the nodes exhausted and no two agreeing, the gateway returns the last refusal: it is
     still the nodes' own word on the request, and says more than a 503.

If no node gives a usable answer in time, the gateway returns the last refusal if there was one,
else the last 502, 503 or 504 answer it got. Otherwise it answers itself:

| Status | Error | When |
| --- | --- | --- |
| 503 | `no usable MPC node` | no node is usable |
| 503 | `no MPC node gave a signature that verifies` | every attempt failed, and no node answered 502, 503 or 504 |
| 502 | `the gateway cannot check this signature` | a node signed a request whose root the gateway cannot compute |

The other endpoints:
- `GET /api/v1/eth2/publicKeys` goes to the usable nodes in order, without hedging. The first
  answer that is not 502, 503 or 504 is returned (otherwise 503, `no MPC node answered`).
- `GET /upcheck` answers 200 while at least one node is usable, and 503 otherwise.
- A request body may be at most 32 MiB, the node's own limit (`rpc::MAX_SIGN_REQUEST_BYTES`).

### Which nodes it uses

**A sealed node** (`https://`, docs/tee.md) is used only while its last check passed. The gateway
checks every node at start and every `--attest-every-secs` (300 s). It checks a node that is not
usable every 10 s. A check passes when all of these hold:
- `GET /attestation` with a fresh nonce returns a token that verifies against `--policy`: a TDX VM
  with debug disabled, the image's RTMR1 and RTMR2, the project (if the policy names one), and the
  node's configuration (RTMR3, if the policy pins it);
- a key of the issuer's key set signed the token: Google's (fetched, and fetched again after an
  hour) or `--jwks`;
- the TLS key that answered is the attested one (`Keys::serves`);
- the node's chain (`GET /eth/network`) is the gateway's.

**Requests go only to the attested key.** After a check passes, the gateway pins the TLS verifier
of the node's connection to the attested key (`tls::AttestedServerKey`). A node that comes back
with another key gets no request until a new check passes. No node CA file is needed. The
attestation request uses a separate connection that accepts any key; the answer then checks the
key.

**A re-imaged or reconfigured node** stops being used at its next check: its token shows another
RTMR1/RTMR2, or another RTMR3.

**A node without evidence** is used only with `--allow-unattested`: a node with a plain vault, or an
`http://` node with development keys (the local devnet). It still gets the chain check.

## Running it

### Sealed nodes

```sh
mpc-gateway \
  --nodes https://node0.example:8443,https://node1.example:8443,https://node2.example:8443,https://node3.example:8443 \
  --tls-cert operator-client.pem --tls-key operator-client-key.pem \
  --policy policy.json \
  --eth-network mainnet \
  --listen 127.0.0.1:9000 --metrics-listen 127.0.0.1:9001
```

The gateway refuses to start when:
- no chain is given;
- an `https://` node is listed without `--tls-cert` and `--tls-key`, or without `--policy` (unless
  `--allow-unattested`);
- an `http://` node is listed without `--allow-unattested`;
- `--listen` is not a loopback address and no TLS is configured.

### Validator clients on another host

The gateway serves plain HTTP on a loopback address only. To serve another address, give it a TLS
certificate and the CA of the validator clients' certificates. Validator clients then need a
client certificate (mutual TLS, TLS 1.3):

```sh
mpc-gateway … --listen 0.0.0.0:9000 \
  --listen-tls-cert gateway.pem --listen-tls-key gateway-key.pem \
  --listen-client-ca validator-clients-ca.pem
```

`--listen-tls12` also accepts TLS 1.2. Teku speaks only TLS 1.2 to an external signer. rustls offers
TLS 1.2 with ECDHE key exchange and AEAD ciphers only.

`--listen-revoked-client-certs FILE` revokes validator clients' certificates, as a node's
`--revoked-client-certs` does (docs/tee.md):
- one SHA-256 fingerprint of a certificate's DER per line, with or without colons; the output of
  `openssl x509 -noout -fingerprint -sha256` is accepted as it is; blank lines and `#` comments
  are skipped;
- a listed certificate can be a client's leaf, an intermediate, or a CA of `--listen-client-ca`;
- the gateway reads the file again every 5 s, so a revocation needs no restart; a file that later
  cannot be read or parsed leaves the list in force;
- a revoked client's open connections close at their next read.

### Development nodes

```sh
mpc-gateway --nodes http://127.0.0.1:47100,http://127.0.0.1:47101,… --allow-unattested \
  --eth-genesis-time … --eth-seconds-per-slot … --eth-genesis-validators-root … \
  --eth-fork-schedule … --listen 127.0.0.1:47200
```

### Flags

| Flag | Default | Meaning |
| --- | --- | --- |
| `--nodes` | required | The nodes, comma-separated, in order of preference: `https://host:port` (a node's mTLS API) or `http://127.0.0.1:port` (a node with development keys). The first usable node coordinates. |
| `--tls-cert`, `--tls-key` | | The operator's client certificate for `https://` nodes (PEM). The nodes' `--client-ca` issued it. |
| `--policy` | | What a sealed node's attestation must show: the clients' policy of docs/tee.md, with each node's configuration in `rtmr3` (`mpc-admin config-rtmr3`). |
| `--jwks` | Google's key set | The attestation issuer's key set (JWKS). Needs `--policy`. |
| `--allow-unattested` | off | Use nodes without evidence. |
| `--eth-network`, or `--eth-genesis-time`, `--eth-seconds-per-slot`, `--eth-genesis-validators-root` and `--eth-fork-schedule` | required | The chain. Use the nodes' own values. |
| `--hedge-after-ms` | 1000 (at least 10) | Ask the next node too when a node has not answered after this long. |
| `--node-timeout-ms` | 6000 (at least 100) | How long one node may take to answer. |
| `--request-deadline-ms` | 10000 (at least 100) | No new attempt starts after this long into a request. |
| `--attest-every-secs` | 300 (at least 10) | How often every node is checked again. |
| `--listen` | `127.0.0.1:9000` | Where validator clients connect. |
| `--listen-tls-cert`, `--listen-tls-key`, `--listen-client-ca` | | TLS for validator clients: the certificate chain (PEM), its key (PEM, PKCS#8), and the CA of the clients' certificates. All three together. |
| `--listen-tls12` | off | Also accept TLS 1.2. |
| `--listen-revoked-client-certs` | | Revoked validator client certificates (above). |
| `--metrics-listen` | | Serve `GET /metrics` here. |
| `--request-log` | | Append one JSON line per request to this file. |
| `--requests` | | Keep each signing request's body and answer in this directory. |

## Validator clients

**Lighthouse** (`validator_definitions.yml`, one entry per key):

```yaml
- enabled: true
  voting_public_key: "0x…"
  type: web3signer
  url: "https://gateway.example:9000"
  root_certificate_path: /path/gateway-ca.pem        # mTLS only
  client_identity_path: /path/validator-client.p12   # mTLS only (PKCS#12)
  client_identity_password: "…"
  request_timeout_ms: 12000
```

**Teku:**
- `--validators-external-signer-url`;
- for mTLS: `--validators-external-signer-keystore` (the PKCS#12 client identity) with its password
  file, and `--validators-external-signer-truststore` (the gateway's CA) with its password file;
- the gateway with `--listen-tls12`.

**Prysm:** `--validators-external-signer-url` and `--validators-external-signer-public-keys`.

Keep each client's own slashing protection on. It refuses on top of the network's, never instead
of it. Do not sign the same keys through another signer at the same time.

## Metrics and logs

**`--metrics-listen`** serves `GET /metrics` in the OpenMetrics text format. The metrics hold
counts, times and node URLs, no key:

| Metric | Labels | Meaning |
| --- | --- | --- |
| `mpc_gateway_requests_total` | `type`, `status` | signing requests answered, by duty type and HTTP status |
| `mpc_gateway_request_duration_seconds` | `type` | their time (histogram, 5 ms to about 20 s) |
| `mpc_gateway_attempts_total` | `node`, `outcome` | signing attempts at nodes: `signed`, `refused`, `unavailable`, `error`, `timeout`, `invalid_signature` |
| `mpc_gateway_hedges_total` | | requests also sent to the next node |
| `mpc_gateway_invalid_signatures_total` | `node` | signatures that did not verify (never passed on) |
| `mpc_gateway_node_usable` | `node` | 1 while a node is used |
| `mpc_gateway_node_attested_timestamp_seconds` | `node` | when its last check passed (unix seconds) |

**`--request-log FILE`** appends one JSON line per request:
- `id`, `ts`, `method`, `path`, `client` (the `User-Agent`), `status`, `ms`;
- `attempts`, each with `backend` and `ms`; `status` if the node answered; `error` if it gave no
  answer or its answer was not used; `hedged` and `invalid_signature` when true;
- for a signing request: `type`, `slot`, `epoch`, `validator`, `signing_root` (the client's
  `signingRoot`) and `fork_version`.

This is the format of the development proxy (`integration/ethereum/scripts/proxy.py`), which the
devnet report reads.

**`--requests DIR`** keeps each signing request as one file (`<id>.json`): its `path`, `status`,
`body` and `response`. It holds duty data only.

## What it protects, and what not

**It adds:**
- **Answers are checked.** A coordinator's wrong signature never reaches the validator client.
- **Attestation is checked continuously.** The gateway uses a sealed node only while its
  attestation of the admitted image and of its own configuration holds. It talks to the attested
  TLS key only.
- **Slow and failed nodes are worked around.** A slow node costs at most `--hedge-after-ms`, and the
  gateway skips a failed one.

**It does not:**
- **It holds no slashing protection.** The nodes refuse a slashable duty whoever asks. The gateway
  only relays it, and the validator client's own database stays on.
- **It is trusted like the validator client.** Whoever controls it can ask for any signature the
  network would give the validator client, and can withhold or delay duties. It cannot obtain a
  signature the network refuses, and it cannot forge one.
- **It is a point of failure for its validator client.** Run one gateway per validator client, next
  to it.
- **It does not split client roles.** Any certificate of `--listen-client-ca` gets the signing API
  until it is revoked (`--listen-revoked-client-certs`).

## Tests

- **Unit (`gateway::tests`, `tests/unit/gateway.rs`)**, against fake nodes:
  - the first node signs;
  - a wrong signature is not passed on, and the next node signs;
  - one node refusing everything cannot lose a duty, and is tried last afterwards;
  - a refusal two nodes agree on is the answer, and no third node is asked;
  - a 503 fails over;
  - a slow node is hedged;
  - a node that answered 504 is asked once more, never more than twice;
  - a node of another chain is never used;
  - the log has the development proxy's shape.
- **E2E (`tests/e2e/gateway.rs`)**, against sealed nodes on the fake GCP:
  - **GW-1:** signing through attested nodes, each signature checked; the log, the metrics and the
    public keys.
  - **GW-2:**
    - a node that holds requests is hedged;
    - a node that returns corrupted signatures (`ETH_MPC_SIGNER_CORRUPT_SIGNATURE_FILE`) is never
      passed on;
    - a stopped node is failed over.
  - **GW-3:** a node is dropped while its token shows another image, and taken back after; a node
    whose configuration is not the pinned one is never used.
  - **GW-4:** validator clients need a certificate of the client CA; TLS 1.2 works only with
    `--listen-tls12`; a revoked validator client is refused once the gateway reads its list again.
- **Devnet.** Lighthouse signs through the gateway in every devnet run (docs/ethereum-devnet.md),
  and on GCP in front of sealed nodes (docs/tee.md, `integration/tee/gcp/run-validator.sh`).
  - **Devnet results.** Runs O to U, every mode: no signature failed the check, and every security
    check passed.
  - **GCP result.** Four attested nodes. The gateway's own time is p50 4.3 ms of 50.3 ms end to
    end.
