Web3Signer signing requests shaped as Lighthouse v8.3.2 serializes its `SigningRequest`
(`validator_client/signing_method/src/web3signer.rs`, tag object `6b6898e6`): `type`,
`fork_info`, `signingRoot`, and the flattened `Web3SignerObject` under its snake_case name,
integers quoted, bytes as `0x`-hex. Written by following that serialization path in the source,
not captured from a running client or produced by Lighthouse's code
(docs/ethereum-signing.md, "Lighthouse v8.3.2").

Requests produced by Lighthouse's own code are in `../lighthouse`. These hand-written ones have
exactly the same fields and top-level order as Lighthouse's output for the same duty.

`block_v2_mainnet_<fork>.json`: one `BLOCK_V2` request per fork from Bellatrix to Fulu, with the
fork Lighthouse sends (`ChainSpec::fork_at_epoch` with mainnet fork versions and epochs) and the
genesis validators root of Web3Signer's examples. They are written by
`ssz_roots.py --write-block-fixtures`, which also computes their roots. A blinded block gives the
same request: Lighthouse sends the header for both.

The duty data and the `signingRoot` of every file except `aggregate_and_proof_electra.json` come
from the examples of the Web3Signer API specification (Consensys/web3signer
`openapi-specs/eth2/signing/paths/sign.yaml`, master 92eed05), where Web3Signer computed them:

- `contribution_and_proof.json`: Web3Signer's example is written for the minimal preset (1-byte
  `aggregation_bits`, a `Bitvector[8]`). Here the bits are the mainnet `Bitvector[128]` (16 bytes,
  the same first byte). Its root is unchanged: both bitvectors fit one 32-byte chunk with the same
  content.
- `aggregate_and_proof_electra.json`: the Electra shape Lighthouse sends under the
  `AGGREGATE_AND_PROOF` type (with `committee_bits`). Web3Signer's Electra example root does not
  reproduce with either preset, so this root is not Web3Signer's: it is the one `ssz_roots.py`
  computes, and the Electra containers themselves are checked against the consensus
  specification vectors in `tests/vectors`.

- `validator_registration.json`: Web3Signer's `VALIDATOR_REGISTRATION` example, sent without
  `fork_info` as Lighthouse sends it. Its domain uses the network's genesis fork version, which
  the request does not carry: Web3Signer's root is for `0x00000001`, the network of its examples
  (its `DEPOSIT` example names it). `ssz_roots.py` takes it as `--genesis-fork-version`
  (default `0x00000001`).

`ssz_roots.py` computes signing roots with a minimal SSZ implementation that shares no code with the
signer (Python standard library only). It reproduces every Web3Signer root above, and the original
minimal-preset contribution example with `--minimal`:

    python3 -I tests/fixtures/web3signer/ssz_roots.py tests/fixtures/web3signer/*.json
