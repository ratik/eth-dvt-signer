The Ethereum remote-signing API specification, unchanged.

- Source: https://github.com/ethereum/remote-signing-api, tag `v1.4.0` (commit
  `44e9e0dcc115c91f8b739684f4789a8310476bd9`). The files are `remote-signing-oapi.yaml`,
  `signing/` and `LICENSE`, from the source archive with sha256
  `7a48131182539c26b97addd411bfa342b9c64ab04824b50405601043048d509f`.
- Licence: CC0 1.0 Universal (`v1.4.0/LICENSE`).
- `tests/eth_remote_signing_api.rs` runs these files. The report is `docs/remote-signing-api.md`.

For a new release, add a directory next to `v1.4.0` and point the test at it. The test fails
until every new example and request type has an expected outcome.
