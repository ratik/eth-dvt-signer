SEV-SNP fixtures: a real report and the VCEK of the chip that signed it.

- `report_milan.hex`: an attestation report (version 2, 1184 bytes as hex) from an EPYC Milan
  guest; sha256 `3d956e9104969a038031a6b63dd6c4b60000619d37702065994f7da76f88ae7d`.
- `vcek_milan.der`: that chip's VCEK (DER), issued by `SEV-Milan` and valid from 2023-04-03 to
  2030-04-03; sha256 `3bbfb6ee259f75a95d13168cfdf2e034181bb93c7c016825731cbe8ea16c95e1`.

Both from virtee/sev (`tests/certs_data/`, main `feaf142ec9`, Apache-2.0). Checked by
`tests/unit/attestation_snp.rs`: the VCEK chains to the pinned ARK-Milan
(`src/attestation/snp/amd/`), and it signed the report.
