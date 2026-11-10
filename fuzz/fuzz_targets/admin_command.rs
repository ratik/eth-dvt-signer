//! `eth_mpc_signer::fuzzing::admin_command`: see `src/fuzzing.rs`.
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| eth_mpc_signer::fuzzing::admin_command(data));
