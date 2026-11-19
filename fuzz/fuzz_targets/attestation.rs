//! `eth_dvt_signer::fuzzing::attestation`: see `src/fuzzing.rs`.
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| eth_dvt_signer::fuzzing::attestation(data));
