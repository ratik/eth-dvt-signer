Gloas fixtures (consensus-specs v1.7.0-beta.4, remote-signing-api v1.4.0).

- `<Type>.json`: SSZ test vectors of consensus-specs v1.7.0-beta.4 (release asset
  `mainnet.tar.gz`, sha256 `67762986572372a08d3b182535aa760433c86e174e14e0bbd756f350dd19398c`,
  CC0-1.0), `tests/mainnet/gloas/ssz_static/<Type>/ssz_random/case_<n>`: each case's value in the
  Web3Signer API's JSON conventions (integers as decimal strings) and its `hash_tree_root`.
  Written by `extract.py` (`python3 -I extract.py <ssz_static directory> <output directory>`,
  PyYAML), and checked by `tests/unit/eth/gloas.rs`: the progressive merkleization and every
  Gloas container a validator signs, reproduced by code that shares nothing with the vectors'
  generator.
- `web3signer_*.json`: the Gloas request examples of the Web3Signer API specification
  (Consensys/web3signer `openapi-specs/eth2/signing/paths/sign.yaml`, master `60e3b2be4a`), as
  JSON. They carry no `signingRoot`; they check the request shapes (`tests/eth_web3signer.rs`).
  The envelope example's `builder_index` is 1 (a builder's payload): parsed, then refused by the
  self-build rule.
