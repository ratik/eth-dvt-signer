EIP-3076 slashing-protection interchange test vectors, unchanged.

- Source: https://github.com/eth-clients/slashing-protection-interchange-tests, tag `v5.3.0`,
  `tests/generated/*.json` (source archive sha256
  `516d551cfb3e50e4ac2f42db0992f4ceb573a7cb1616d727a725c8161485329f`).
- The repository has no license file.
- Run by `eth::interchange::tests::eip3076_interchange_vectors` (`tests/unit/eth/interchange.rs`).
  This signer keeps imported history in EIP-3076's minimal form and its own records in full, so
  each signing must succeed where the minimal strategy expects success (`should_succeed`), and
  must fail where even the complete strategy expects failure (`should_succeed_complete`).
