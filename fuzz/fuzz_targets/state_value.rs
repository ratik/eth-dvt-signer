//! `eth_mpc_signer::fuzzing::state_value`: see `src/fuzzing.rs`.
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| eth_mpc_signer::fuzzing::state_value(data));
