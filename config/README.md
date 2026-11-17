`roughtime.json`: the trusted clock's default configuration (`eth-mpc-signer --roughtime`,
`src/clock`, docs/ethereum-signing.md).

- **Servers:** every public Roughtime server that answered on 2026-11-13, 13 servers of 9
  independent operators. Inutile's four regions and Netnod's two servers count as one operator
  each.
- **Keys:** from tannerryan/roughtime's `ecosystem.json` (main `2a36e5bbe9`). The keys of
  txryan, roughtime.se and int08h are the same in cloudflare/roughtime's `ecosystem.json`.
  Every server's answer verified against its key on 2026-11-13 (signatures, Merkle proof, nonce).
- **Not listed:** Cloudflare's server (`roughtime.cloudflare.com:2003`) did not answer on any
  version from two networks; Google's sandbox, kyhwana.org, blackhatspottycat.net, dnov.se and
  0xt.ca are gone.
- **Quorum:** 5 of the 9 operators must agree. Fewer than 5 lying operators cannot move the
  node's time; 5 unreachable ones stop it signing (fail closed).
- **Times:** a sync every 10 s; a sync's time is used for at most 30 s; radii above 10 s are
  ignored. The node's time is then at most `30 + 2·10 = 50 s` ahead of the true time.

An operator may use other servers or another quorum (at least 3, at most the number of
operators). A sealed node's configuration includes this file, so clients that pin the
configuration pin the servers too.
