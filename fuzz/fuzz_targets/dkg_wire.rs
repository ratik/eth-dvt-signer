//! `eth_mpc_signer::fuzzing::dkg_wire`: see `src/fuzzing.rs`.
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| eth_mpc_signer::fuzzing::dkg_wire(data));
