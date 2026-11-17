Roughtime fixtures: real answers of real servers, and the RFC's examples.

- `rfc10049-appendix-b.json`: the three request/response examples of RFC 10049 appendix B (version
  1), each with the server's long-term key, as tannerryan/roughtime carries them
  (`protocol/testdata/rfc10049-appendix-b.json`, main `2a36e5bbe9`, BSD-2-Clause); sha256
  `8f9e0732e724b123322a4f5d84df446ab3acd738c425f22e70890806ece46747`.
- `live-2026-11-13.json`: one request and its answer from each of seven public servers, captured
  2026-11-13 from the test server (`receivedAt`: the local Unix time of the answer): version 1
  (time.txryan.com, rough.time.nl), draft 07 (sth1.roughtime.netnod.se) and drafts 12–19 (the
  others). Public data only: the request is this client's (`clock::roughtime::request`'s format,
  a random nonce); sha256 `3d9781b602deda932ed969acc29c6646e0006b92e853377bf1fe78cbf60a4ff0`.

Checked by `tests/unit/clock/roughtime.rs`: every answer verifies, and every changed byte is
refused.
