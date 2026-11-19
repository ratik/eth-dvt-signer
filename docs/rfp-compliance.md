# Lido RFP compliance

How eth-dvt-signer meets the appendix of the Lido RFP
[open Ethereum validator signers for on-prem and isolated hardware](https://research.lido.fi/t/rfp-open-ethereum-validator-signers-for-on-prem-and-isolated-hardware/12209).
State as of 2026-11-19.

Status: **Met** (done and tested), **Gap** (met, with a limit named in the row), **Partial**, **Planned**.

## Conditions

| Condition | Status | Evidence |
| --- | --- | --- |
| On-prem support (cloud TEE optional) | Partial | AMD SEV-SNP guest on the operator's EPYC server: image, HOST_DATA check and launch measurement done, tested in a GCP N2D SNP VM; a launch on own SNP hardware is next ([tee.md](tee.md)). GCP Confidential VMs (Intel TDX) run as the cloud option. |
| Not tied to one consensus client: 3+ CL clients, stock validator clients, standard remote-signing API | Met | Lighthouse, Teku and Nimbus on a Kurtosis devnet ([ethereum-devnet.md](ethereum-devnet.md)); Lighthouse against sealed TDX nodes on GCP. Prysm and Lodestar planned. |
| No tee-signer code | Met | Independent Rust codebase on commonware. Some safety rules follow ideas from tee-signer's design; they are credited in [research/tee-signer-comparison.md](research/tee-signer-comparison.md). |
| Threshold signing (appreciated) | Met | Threshold n − f of n nodes, n ≥ 3f + 1, n is a setting (up to 64); tested with 4 nodes, 3 to sign ([architecture.md](architecture.md)). |

## Requirements

| Requirement | Status | Evidence |
| --- | --- | --- |
| Code open source; closed platforms listed | Met | MIT ([LICENSE](../LICENSE)). Closed parts: AMD SEV-SNP firmware, microcode and root keys; on GCP the Intel TDX module, Google firmware and vTPM, Cloud Attestation, KMS and IAM; optional S3/GCS Object Lock for the anchor. |
| Remote-signing API v1.4+ | Met | v1.4.0 spec vendored in `tests/vectors/remote-signing-api/v1.4.0`, checked by `tests/eth_remote_signing_api.rs` ([remote-signing-api.md](remote-signing-api.md)). |
| Key never leaves the boundary in plaintext; generated inside or imported encrypted; recovery by encrypted copy or new key | Met | Dealerless DKG; offline split of an EIP-2335 keystore into HPKE-encrypted shares ([key-import.md](key-import.md)); resharing and replacement keep the key ([resharing.md](resharing.md), [reconfiguration.md](reconfiguration.md), [recovery.md](recovery.md)). DKG and resharing need every node online. |
| Signer parses each request and computes the signing root itself | Met | `Protection::authorize` computes the root from the parsed duty (`src/slashing.rs`); a client root that differs is refused (`SignError::RootMismatch`, `src/signer/coordinator.rs`); the gateway recomputes it too (`src/gateway/route.rs`). |
| No slashable message without access to the TEE signing infrastructure | Gap | A signature needs n − f nodes. Without the WORM anchor, a rollback of every node at once can still sign a crafted surround vote ([threat-model.md](threat-model.md#not-covered)). |
| EIP-3076 inside the boundary, record written before the signature goes out | Met | The record is committed by consensus before keyholders receive the authorization ([slashing-protection.md](slashing-protection.md#atomicity-and-the-signing-gate)); interchange import and export ([slashing-protection.md](slashing-protection.md#imported-history-eip-3076)). |
| Survives host clock travel, restarts, rollback of stored state | Gap | Roughtime quorum, 5 of 9 operators by default ([ethereum-signing.md](ethereum-signing.md)); restart floor ([slashing-protection.md](slashing-protection.md#the-restart-floor)); optional WORM anchor ([anchor.md](anchor.md)). Sealed images do not pass `--roughtime` yet. No hardware monotonic counter. |
| Fee recipient, exit permissions changeable only with explicit confirmation; non-matching registrations and exits refused | Gap | m-of-n offline Ed25519 approvers ([administration.md](administration.md)); builder registrations and, from Gloas, proposer preferences checked against the policy. The fee recipient of locally built blocks before Gloas is not covered. |
| Signed releases | Planned | No tags or release signatures yet. |
| Reproducible builds | Met | The TEE image is built twice and the digests compared ([integration/tee/README.md](../integration/tee/README.md)). |
| Crypto dependencies pinned to exact versions | Met | commonware, blst, aws-lc, rustls, hpke, sha2 and the other crypto crates pinned with `=` in [Cargo.toml](../Cargo.toml); Rust 1.99.1 in [rust-toolchain.toml](../rust-toolchain.toml); Cargo.lock for the rest. |
| Short threat model and list of what the design trusts | Met | [threat-model.md](threat-model.md). |

## Nice to have

| Item | Status | Evidence |
| --- | --- | --- |
| Threshold signing | Met | See Conditions. |
| Formal model of the slashing-safety logic | Partial | Kani proofs that `src/slashing.rs` decides exactly the slashing specification, and a Quint model of the protocol (crashes, rollbacks, restart floor, WORM anchor) checked by TLC ([formal.md](formal.md)). Some checks still running; the model found F-1 (the restart floor exempts what a rollback authorized). |
| Remote attestation a third party can verify | Met | `mpc-admin attest`, `mpc-gateway` and `mpc-keytool split --attestation-policy` verify SNP reports (VCEK chained to pinned AMD ARK/ASK; measurement, TCB, HOST_DATA, chip_id) and TDX evidence ([tee.md](tee.md), [gateway.md](gateway.md)). |
| Protection against cloned devices | Partial | The anchor detects a clone ([anchor.md](anchor.md)); shares are sealed to the measured image ([tee.md](tee.md)). |

## What is checked

| Check | Status | Evidence |
| --- | --- | --- |
| BLS signatures and signing roots: consensus-spec-tests | Met | `ssz_static` vectors (`tests/eth_vectors.rs`); Ethereum BLS vectors (`tests/eth_bls_vectors.rs`). |
| Slashing protection, with restarts: EIP-3076 interchange tests | Met | Interchange tests v5.3.0 (`tests/vectors/eip3076`, `tests/unit/eth/interchange.rs`); restart floor tests ([slashing-protection.md](slashing-protection.md#tests)). |
| API: remote-signing API spec | Met | See Requirements. |
| Capacity: load test, signatures per slot within the attestation deadline | Planned | Plan in [load-test.md](load-test.md). Measured so far: latency p50 50 ms / p95 95 ms on GCP TDX; p50 330 ms / p95 669 ms on the devnet; 6,400 validators set up in 1,194 s. |
| Live duties: 7 days on Hoodi, 30 days on Hoodi or mainnet, no slashable signature | Planned | After the on-prem launch. |

Also: fuzzing of all decoders (`fuzz/`).
