# The gateway: a validator client's entry to the MPC network

`mpc-gateway` serves the Web3Signer Ethereum signing API (EIP-3030) to a validator client
(Lighthouse, Teku, Prysm) and signs through the nodes of the network:

```
validator client ──HTTP (loopback) or mTLS──> mpc-gateway ──mTLS 1.3, attested key──> node 0
                   (Web3Signer API)                                                ├─> node 1
                                                                                   └─> …
```

A validator client takes one URL per key, while any node of the network can coordinate a
signature. The gateway is that URL. It holds no key and no slashing state: the nodes decide every
duty through consensus, and refuse whatever their slashing protection and policies refuse.

**Contents.** What it does · Running it · Validator clients · Metrics and logs · What it protects,
and what not · Tests.

## What it does

### Signing (`POST /api/v1/eth2/sign/{key}`)

1. **The signing root.** It computes the root itself, from the request and its pinned chain, with
   the nodes' own code (`eth::web3signer::duty_request`).
2. **Hedged failover.** It asks the nodes in their configured order (`--nodes`), with the nodes
   that failed recently last.
   - After `--hedge-after-ms` (1000 ms) without an answer, the next node is asked too, and the
     first usable answer wins.
   - A failure asks the next node at once: no answer, a timeout (`--node-timeout-ms`, 6000 ms),
     502, 503 or 504.
   - **A node that answered 502, 503 or 504 is asked once more**, after the others. It could not
     finish in time, typically while consensus waited out a stopped leader's view. By its second
     turn the duty is usually decided, and the repeat returns its signature.
   - No new attempt starts after `--request-deadline-ms` (10000 ms; Lighthouse waits 12 s).
   - Repeating a request is safe. Consensus decides a duty once, and a repeat gets the same
     signature (`AlreadyAccepted`).
3. **Every signature is checked before it is returned.**
   - It must be the validator key's BLS signature of the root the gateway computed.
   - If it is not, it is not passed on. The node is tried last for 60 s, the metric
     `invalid_signatures` counts it, the log records it, and the next node is asked.
   - So a faulty coordinator (one node, within `f = 1`) cannot make the validator publish a wrong
     signature and miss the duty.
4. **Refusals are final.** Every other answer (400, 403, 404, 412, 500) is returned as the node
   gave it: the refusal is the network's.

`GET /api/v1/eth2/publicKeys` goes to the first node that answers. `/upcheck` answers 200 while at
least one node is usable.

### Which nodes it uses

**A sealed node** (`https://`, docs/tee.md) is used only while its last check passed. The check
runs at start, every `--attest-every-secs` (300 s), and every 10 s while the node is not usable:
- `GET /attestation` with a fresh nonce;
- the token verified against `--policy`: the image's RTMR1 and RTMR2, the project, and the node's
  configuration (RTMR3, when the policy pins it);
- the token's key set: Google's (fetched, refreshed hourly) or `--jwks`;
- the TLS key that answered must be the attested one (`Keys::serves`);
- the node's chain (`GET /eth/network`) must be the gateway's.

**Requests go only to that key.** After a check, the connection's TLS verifier is pinned to the
attested key (`tls::AttestedServerKey`): a node re-provisioned with another key gets no request
until it is attested again. No node CA file is needed. The attestation requests go over a
separate connection that accepts any key; the answer then checks the key.

**A re-imaged or reconfigured node** stops being used at its next check: its token shows another
RTMR1/RTMR2, or another RTMR3.

**A node without evidence** is used only with `--allow-unattested`: a plain vault, or an `http://`
node with development keys (the local devnet). It still gets the chain check.

## Running it

### Sealed nodes

```sh
mpc-gateway \
  --nodes https://10.0.0.2:8443,https://10.0.0.3:8443,https://10.0.0.4:8443,https://10.0.0.5:8443 \
  --tls-cert operator-client.pem --tls-key operator-client-key.pem \
  --policy policy.json \
  --eth-network mainnet \
  --listen 127.0.0.1:9000 --metrics-listen 127.0.0.1:9001
```

**The flags:**
- **`--policy`** is the clients' policy of docs/tee.md, with each node's configuration in `rtmr3`
  (`mpc-admin config-rtmr3`).
- **The chain flags** are the nodes' own: `--eth-network`, or `--eth-genesis-time`,
  `--eth-seconds-per-slot`, `--eth-genesis-validators-root` and `--eth-fork-schedule`.
- **The client certificate** (`--tls-cert`, `--tls-key`) is one the nodes' `--client-ca` issued.
- **Order.** List the nodes in order of preference: the first usable one coordinates.

### Validator clients on another host

Plain HTTP is served on a loopback address only. To serve another address, give the gateway a
TLS certificate and the CA of the validator clients' certificates (mutual TLS, TLS 1.3):

```sh
mpc-gateway … --listen 0.0.0.0:9000 \
  --listen-tls-cert gateway.pem --listen-tls-key gateway-key.pem \
  --listen-client-ca validator-clients-ca.pem
```

`--listen-tls12` also accepts TLS 1.2. Teku speaks only TLS 1.2 to an external signer; rustls
offers TLS 1.2 with ECDHE and AEAD ciphers only.

`--listen-revoked-client-certs FILE` revokes validator clients' certificates, as a node's
`--revoked-client-certs` does (docs/tee.md):
- one SHA-256 fingerprint per line (`openssl x509 -noout -fingerprint -sha256`): a leaf, an
  intermediate, or a CA of `--listen-client-ca`;
- read again every 5 s, so a revocation needs no restart;
- a revoked client's open connections close at its next request.

### Development nodes

```sh
mpc-gateway --nodes http://127.0.0.1:47100,http://127.0.0.1:47101,… --allow-unattested \
  --eth-genesis-time … --eth-seconds-per-slot … --eth-genesis-validators-root … \
  --eth-fork-schedule … --listen 127.0.0.1:47200
```

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
- for mTLS, `--validators-external-signer-keystore` (PKCS#12 client identity) with its password
  file, and `--validators-external-signer-truststore` (the gateway's CA) with its password file;
- the gateway with `--listen-tls12`.

**Prysm:** `--validators-external-signer-url` and `--validators-external-signer-public-keys`.

Every client keeps its own slashing protection on: it refuses on top of the network's, never
instead of it. Do not sign the same keys through another signer at the same time.

## Metrics and logs

**`--metrics-listen`** serves `GET /metrics` (Prometheus text). The metrics hold counts, times and
node URLs, no key:

| Metric | Labels | Meaning |
| --- | --- | --- |
| `mpc_gateway_requests_total` | `type`, `status` | signing requests answered |
| `mpc_gateway_request_duration_seconds` | `type` | their time |
| `mpc_gateway_attempts_total` | `node`, `outcome` | attempts: `signed`, `refused`, `unavailable`, `error`, `timeout`, `invalid_signature` |
| `mpc_gateway_hedges_total` | | requests also sent to the next node |
| `mpc_gateway_invalid_signatures_total` | `node` | signatures that did not verify (never passed on) |
| `mpc_gateway_node_usable` | `node` | 1 while a node is used |
| `mpc_gateway_node_attested_timestamp_seconds` | `node` | its last verified check |

**`--request-log FILE`** appends one JSON line per request:
- `id`, `ts`, `method`, `path`, `client` (the `User-Agent`), `status`, `ms`;
- `attempts`: each with `backend`, `status` or `error`, `ms`, and `hedged`, `invalid_signature`
  when set;
- for a signing request: `type`, `slot`, `epoch`, `validator`, `signing_root`, `fork_version`.

It is the development proxy's format, which the devnet report reads.

**`--requests DIR`** keeps each signing request's body and answer (duty data only).

## What it protects, and what not

**It adds:**
- **Answers are checked.** A coordinator's wrong signature never reaches the validator client.
- **Attestation is checked continuously.** The gateway uses a sealed node only while its
  attestation of the admitted image and of its own configuration holds, and it talks to the
  attested TLS key only.
- **Slow and failed nodes are worked around.** A slow node costs at most `--hedge-after-ms`, and a
  failed one is skipped.

**It does not:**
- **It holds no slashing protection.** The nodes refuse a slashable duty whoever asks; the gateway
  only relays it, and the validator client's own database stays on.
- **It is trusted like the validator client.** Whoever controls it can ask for any signature the
  network would give the validator client, and can withhold or delay duties. It cannot obtain a
  signature the network refuses, nor forge one.
- **It is a point of failure for its validator client.** Run one per validator client, next to
  it.
- **It does not split client roles.** Any certificate of `--listen-client-ca` gets the signing API,
  until it is revoked (`--listen-revoked-client-certs`).

## Tests

- **Unit (`gateway::tests`)**, against fake nodes:
  - the first node signs;
  - a wrong signature is not passed on and the next node signs;
  - a refusal is final, and 503 fails over;
  - a slow node is hedged;
  - a node that answered 504 is asked once more, never more than twice;
  - a node of another chain is never used;
  - the log's shape.
- **E2E (`tests/e2e/gateway.rs`)**, against sealed nodes on the fake GCP:
  - **GW-1:** signing through attested nodes, each signature checked; the log, the metrics and
    the public keys.
  - **GW-2:**
    - a node holding requests is hedged;
    - a node returning corrupted signatures (`ETH_MPC_SIGNER_CORRUPT_SIGNATURE_FILE`) is never
      passed on;
    - a stopped node is failed over.
  - **GW-3:** a node is dropped while its token shows another image, and taken back after; a node
    whose configuration is not the pinned one is never used.
  - **GW-4:** validator clients need a certificate of the client CA; TLS 1.2 only with
    `--listen-tls12`; a revoked validator client is refused once the gateway reads its list
    again.
- **Devnet.** Lighthouse signs through the gateway in every devnet run (docs/ethereum-devnet.md),
  and on GCP in front of sealed nodes (docs/tee.md, `run-validator.sh`).
  - **Devnet results.** Runs O to U, every mode: no signature failed the check, and every
    security check passed.
  - **GCP result.** Four attested nodes; the gateway's own time is p50 4.3 ms of 50.3 ms end to
    end.
