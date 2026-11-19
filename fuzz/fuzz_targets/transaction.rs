//! `eth_dvt_signer::fuzzing::transaction`: see `src/fuzzing.rs`.
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| eth_dvt_signer::fuzzing::transaction(data));
