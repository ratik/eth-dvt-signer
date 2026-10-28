Web3Signer signing requests shaped exactly as Lighthouse v8.3.2 serializes its `SigningRequest`
(`validator_client/signing_method/src/web3signer.rs`): `type`, `fork_info`, `signingRoot`, and the
duty object under its snake_case name, integers quoted, bytes as `0x`-hex. Built from those type
definitions, not captured from a running client.

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

`ssz_roots.py` computes signing roots with a minimal SSZ implementation that shares no code with the
signer (Python standard library only). It reproduces every Web3Signer root above, and the original
minimal-preset contribution example with `--minimal`:

    python3 -I tests/fixtures/web3signer/ssz_roots.py tests/fixtures/web3signer/*.json
