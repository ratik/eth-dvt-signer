# Conformance with the remote-signing API specification

This report checks the signer against the Ethereum remote-signing API specification,
[ethereum/remote-signing-api](https://github.com/ethereum/remote-signing-api) **v1.4.0** (the
latest release, 2026-09-21). The specification is vendored, unchanged, in
`tests/vectors/remote-signing-api/v1.4.0`. `tests/eth_remote_signing_api.rs` runs the checks.

How a validator client uses the API, and every duty in detail: [ethereum-signing.md](ethereum-signing.md).

## Summary

| Check | Result |
| --- | --- |
| Endpoints | Both are implemented: `POST /api/v1/eth2/sign/{identifier}` and `GET /api/v1/eth2/publicKeys`, on each node and on `mpc-gateway` |
| Request types | 15 of 18 are signed. 3 are refused with `400`: `BLOCK` (deprecated), `EXECUTION_PAYLOAD_BID` and `BUILDER_REQUEST_AUTH` |
| Request examples | 32 in all. 21 are signed with the example's own signing root. 2 are signed, but the example has no root. 2 are signed with a root that differs from the example's: the example's root is wrong. 2 are refused because the example itself is invalid. 5 are refused because their type or fork is not supported |
| Status codes | All five codes of the specification are used with its meaning: `200`, `400`, `404`, `412`, `500`. The signer also uses `403`, `409`, `413`, `503` and `504` ([below](#status-codes)) |
| Response body | `200` is `{"signature": "0x.."}` when `Accept` includes `application/json`, and the bare signature as `text/plain` otherwise. `publicKeys` is a JSON array of `0x`-hex keys |

The test fails in each of these cases:

- an example has an outcome other than the one in its table;
- the specification has an example or a request type that the table does not name;
- the table names an example or a type that the specification no longer has.

So a new version of the specification cannot pass until someone reads it.

## Request examples

Each request example of the signing endpoint goes through the request parser that the node and
the gateway share (`eth::web3signer`). For each example the signer computes the signing root
from the parsed duty and compares it with the example's `signingRoot`.

| Example | Outcome | Signing root |
| --- | --- | --- |
| `BLOCK_V2 (BELLATRIX)` to `(GLOAS)`, 6 examples | Signed | Reproduced |
| `BLOCK_V2 (PHASE 0)`, `BLOCK_V2 (ALTAIR)` | `400` | A whole block: [refused](#refused-request-types) |
| `BLOCK (DEPRECATED)` | `400` | [Refused](#refused-request-types) |
| `ATTESTATION` | Signed | Reproduced |
| `AGGREGATION_SLOT` | Signed | Reproduced |
| `AGGREGATE_AND_PROOF (DEPRECATED)` | Signed | Reproduced |
| `AGGREGATE_AND_PROOF_V2 (PHASE 0)` to `(DENEB)`, 5 examples | Signed | Reproduced |
| `AGGREGATE_AND_PROOF_V2 (ELECTRA)`, `(FULU)` | Signed | **Differs**: [the example's root is wrong](#electra-and-fulu-aggregates) |
| `AGGREGATE_AND_PROOF_V2 (GLOAS)` | Signed | Reproduced (progressive merkleization) |
| `RANDAO_REVEAL` | Signed | Reproduced |
| `VOLUNTARY_EXIT` | Signed | Reproduced. On a live node, an exit needs the approvers ([administration.md](administration.md)) |
| `SYNC_COMMITTEE_MESSAGE` | Signed | Reproduced |
| `SYNC_COMMITTEE_SELECTION_PROOF` | Signed | Reproduced |
| `SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF` | `400` | **The example is invalid for mainnet**: [minimal preset](#the-contribution-example) |
| `VALIDATOR_REGISTRATION` | Signed | Reproduced, with the examples' genesis fork version `0x00000001`. On a live node, also under the registration policy |
| `DEPOSIT` | Signed | Reproduced. On a live node, only with `--enable-deposit-signing` and the approvers |
| `EXECUTION_PAYLOAD_BID (GLOAS)` | `400` | [Refused](#refused-request-types) |
| `EXECUTION_PAYLOAD_ENVELOPE (GLOAS)` | `400` | **The example is invalid**: [`logs_bloom`](#the-envelope-example) |
| `PAYLOAD_ATTESTATION_MESSAGE (GLOAS)` | Signed | The example has no root |
| `PROPOSER_PREFERENCES (GLOAS)` | Signed | The example has no root |
| `BUILDER_REQUEST_AUTH (GLOAS)` | `400` | [Refused](#refused-request-types) |

"Signed" means that the request is accepted as the duty of its type and its root is computed.
On a live node, the duty then still goes through activation, the fork schedule, the time
horizon, slashing protection and consensus ([ethereum-signing.md](ethereum-signing.md)).

### Where the specification's examples are wrong

These four examples are defects of the specification, not of the signer. For each one, an SSZ
implementation that shares no code with the signer (`tests/fixtures/web3signer/ssz_roots.py`,
Python standard library only) agrees with the signer.

#### Electra and Fulu aggregates

The `AGGREGATE_AND_PROOF_V2 (ELECTRA)` and `(FULU)` examples give the signing root
`0x2475..c9e0`. The signer and `ssz_roots.py` both compute
`0x1180bcb41bda522b3420274c6e4931c37ecf4eef99a57e4d04fc81e82b2ced40` with the mainnet preset.
The minimal preset cannot be the cause: in that preset the example's 8-byte `committee_bits` is
invalid (a `Bitvector[4]`). The Gloas example has the same aggregate, and the signer reproduces
its root. The Electra containers are also checked against the consensus-spec-tests vectors
(`tests/eth_vectors.rs`). Web3Signer's own Electra example had the same defect
(`tests/fixtures/web3signer/README.md`).

#### The contribution example

The example's `aggregation_bits` is `0x24`: one byte, a `Bitvector[8]` of the minimal preset.
On mainnet it is a `Bitvector[128]`, 16 bytes. The signer refuses the example (`400`).
`ssz_roots.py --minimal` reproduces its root. With the same first byte padded to 16 bytes, the
signer signs it and reproduces the example's root. Both bitvectors fit in one 32-byte chunk, so
the root does not change.

#### The envelope example

The example's `logs_bloom` has 262 bytes. A `logs_bloom` is a `ByteVector[256]`. The signer
refuses the example (`400`). With 256 zero bytes, the signer signs it. The example has no
signing root to compare.

`the_invalid_examples_are_signed_once_their_one_defect_is_fixed` tests both repairs. These
defects are worth an issue upstream.

## Refused request types

| Type | Why the signer refuses it |
| --- | --- |
| `BLOCK` (deprecated), `BLOCK_V2` with a whole `block` (Phase 0, Altair) | The signer computes a block's root from its header (`block_header`), which clients send from Bellatrix on. A whole Phase 0 or Altair block would need every body container of those forks. Mainnet and Hoodi are past these forks, so no current proposal needs them. |
| `EXECUTION_PAYLOAD_BID` | A builder signs a bid, not a validator. A self-built bid carries the point at infinity, and no signature. |
| `BUILDER_REQUEST_AUTH` | New in v1.4.0, and not implemented. It asks for a signature of opaque data (up to 4096 bytes) under `DOMAIN_BUILDER_REQUEST_AUTH`. To sign it safely, the signer needs a policy of what it may sign, for example the builders the approvers configured. A validator client sends it only when external builders are configured. Without it, such a client cannot authenticate to a builder. Its local blocks are not affected. |

The refusal tells the client which type it was and why (`{"error": "unsupported: .."}`).

## Status codes

The specification defines five codes for the signing endpoint. The signer uses them with their
meaning:

| Code | Specification | Signer |
| --- | --- | --- |
| `200` | The signature | The signature, as JSON or `text/plain` |
| `400` | Bad request format | Bad requests, unsupported types and forks, a `signingRoot` that is not the computed root, a `fork_info` that is not the pinned schedule's |
| `404` | Public key not found | An unknown key, or a key that is not activated |
| `412` | Refused by slashing protection | Slashing protection, the time horizon, the registration policy, the keyholders' restart floor and anchored marks |
| `500` | Internal server error | Anything else |

The signer adds these codes, which are not in the specification. A client treats them as
failures, as it treats any code other than `200`:

| Code | When | Retry |
| --- | --- | --- |
| `403` | An exit or deposit without the approvers' authorization; a signing request to a follower node | No |
| `409` | The authorization's administrative nonce is already used | No |
| `413` | A request over 32 MiB | No |
| `503` | No network configured; the node is not ready; too few signers; overload | Yes, it is transient |
| `504` | Consensus or the partial signatures timed out | Yes, it is transient |

`GET /upcheck` and `GET /ready` are also outside the specification. `/upcheck` is Web3Signer's
health check, and the signer has it for the same use.

## What this report does not cover

- **Live responses against the schema.** The examples are checked in the parser. The HTTP layer
  (status codes, `Content-Type`, the `publicKeys` body) is covered by the API tests and the
  devnet runs (`docs/ethereum-signing.md`, "Test coverage"), but no OpenAPI contract test has
  run yet against a live node and gateway.
- **Validator clients other than Lighthouse.** Only Lighthouse v8.3 has run against the API.

## Reproducing

```bash
cargo test --locked --test eth_remote_signing_api -- --nocapture
```

The test prints each example's outcome. To compute the roots of the four defective examples
independently, convert them to JSON (as `AGGREGATE_AND_PROOF` for the aggregates) and run
`python3 -I tests/fixtures/web3signer/ssz_roots.py [--minimal] FILE.json`.
