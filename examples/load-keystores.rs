//! Writes `COUNT` random validator keystores (EIP-2335, PBKDF2 with 2 iterations, password
//! `load`) to `DIR/key-<i>.json`, for the key-setup load test (docs/load-test.md). Test keys only:
//! the cheap key derivation is not for real keys.
//!
//!   cargo run --release --example load-keystores -- COUNT DIR

use aes::Aes128;
use commonware_codec::Encode as _;
use commonware_cryptography::bls12381::primitives::group::Scalar;
use commonware_math::algebra::Random as _;
use ctr::cipher::{KeyIvInit as _, StreamCipher as _};
use eth_dvt_signer::import::eip2335;
use rand::RngExt as _;
use sha2::{Digest as _, Sha256};

fn main() {
    let mut args = std::env::args().skip(1);
    let count: usize = args.next().expect("COUNT").parse().expect("COUNT");
    let dir = std::path::PathBuf::from(args.next().expect("DIR"));
    std::fs::create_dir_all(&dir).unwrap();
    let mut rng = rand::rng();
    let password = eip2335::process_password("load");
    for index in 0..count {
        let secret: [u8; 32] = Scalar::random(&mut rng)
            .encode()
            .as_ref()
            .try_into()
            .unwrap();
        let salt: [u8; 32] = rng.random();
        let iv: [u8; 16] = rng.random();
        let mut key = [0u8; 32];
        pbkdf2::pbkdf2_hmac::<Sha256>(&password, &salt, 2, &mut key);
        let mut ciphertext = secret;
        ctr::Ctr128BE::<Aes128>::new_from_slices(&key[..16], &iv)
            .unwrap()
            .apply_keystream(&mut ciphertext);
        let checksum = Sha256::new()
            .chain_update(&key[16..32])
            .chain_update(ciphertext)
            .finalize();
        let json = serde_json::json!({
            "crypto": {
                "kdf": {"function": "pbkdf2", "params": {"dklen": 32, "c": 2, "prf": "hmac-sha256", "salt": hex::encode(salt)}, "message": ""},
                "checksum": {"function": "sha256", "params": {}, "message": hex::encode(checksum)},
                "cipher": {"function": "aes-128-ctr", "params": {"iv": hex::encode(iv)}, "message": hex::encode(ciphertext)}
            },
            "path": "", "uuid": "00000000-0000-0000-0000-000000000000", "version": 4
        });
        std::fs::write(
            dir.join(format!("key-{index}.json")),
            serde_json::to_vec(&json).unwrap(),
        )
        .unwrap();
    }
}
