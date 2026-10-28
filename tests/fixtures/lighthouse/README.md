Web3Signer signing requests produced by Lighthouse v8.3.2's own code (tag `v8.3.2`, commit
`a376defa`), one per duty this signer supports, plus an Altair block (which Lighthouse sends
whole and this signer refuses).

`generator/` builds them with Lighthouse's crates (`signing_method`, `types`, and the patched
`ethereum_ssz`/`tree_hash` revisions of its workspace):

- the duty object is `Web3SignerObject` as Lighthouse builds it (`beacon_block` for blocks; for
  each fork from Bellatrix to Fulu the generator checks that a blinded block gives the same request);
- `signingRoot` is `SignableMessage::signing_root(SigningContext::domain_hash(spec))`;
- the signing contexts are `validator_store::signing_context`'s (the domain epoch of each duty,
  `ChainSpec::fork_at_epoch` on mainnet, the Capella fork for exits from Deneb on);
- the `SigningRequest` envelope is private in Lighthouse; it is rebuilt from its public parts in
  its field order: `type`, `fork_info` (`fork`, `genesis_validators_root`), `signingRoot`, then the
  flattened object;
- aggregate and contribution data are the repository's Web3Signer fixtures, read through
  Lighthouse's serde, moved into the fork; the genesis validators root is Web3Signer's examples'.

They are not captured from a running validator client: Lighthouse's HTTP client and the request it
sends at run time are not exercised.

```sh
cd tests/fixtures/lighthouse/generator
CARGO_TARGET_DIR=/tmp/lh-fixtures cargo run --release -- ../../web3signer ..
```
