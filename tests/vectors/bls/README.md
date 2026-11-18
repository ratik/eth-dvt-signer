Ethereum BLS signature test vectors, unchanged.

- Source: https://github.com/ethereum/bls12-381-tests, release `v0.1.2`, asset
  `bls_tests_yaml.tar.gz` (sha256
  `a4ef909b6248395094949a3bcdeb4e1b5b999733d4436f2c5006edba99d29279`). consensus-spec-tests no
  longer carries the generic BLS vectors (`sign`, `verify`, ...); consensus clients take them from
  this repository.
- Licence: CC0-1.0.
- Vendored: `sign`, `verify`, `deserialization_G1`, `deserialization_G2`. Not vendored:
  `aggregate`, `aggregate_verify`, `fast_aggregate_verify`, `batch_verify`, `hash_to_G2`. The
  signer never aggregates signatures of different keys: it combines partial signatures of one key
  by Lagrange interpolation, which `sign` covers.
- Run by `tests/eth_bls_vectors.rs`.
