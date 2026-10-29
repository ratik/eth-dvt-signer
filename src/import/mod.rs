//! Import of an existing Ethereum validator key (an EIP-2335 keystore) as a threshold key of this
//! network, without changing its public key.
//!
//! The offline `mpc-keytool` is a trusted dealer: it decrypts the keystore, splits the secret with
//! the arithmetic of the DKG (the same evaluation points and Feldman commitments, see [dealer]), and
//! seals each share to its node ([envelope]). The public part ([manifest]) is registered through
//! consensus; each keyholder then opens, checks and stores only its own share. From there the key
//! signs exactly like a DKG key, under the same authorization and slashing-protection checks.
//!
//! This is not the guarantee of a DKG: the secret existed in complete form before the split, on the
//! machine that ran the dealer and wherever the keystore was kept (docs/key-import.md).
//!
//! - [eip2335]: keystore decryption.
//! - [dealer]: the split and its verification.
//! - [manifest]: the public description of an import and its digest.
//! - [envelope]: share encryption to one node (HPKE, RFC 9180).

pub mod dealer;
pub mod eip2335;
pub mod envelope;
pub mod manifest;

/// `0x`-prefixed lowercase hex.
pub fn hex0x(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

/// Bytes from hex, with or without `0x`.
pub fn unhex(text: &str) -> Option<Vec<u8>> {
    hex::decode(text.strip_prefix("0x").unwrap_or(text)).ok()
}

/// Exactly `N` bytes from hex, with or without `0x`.
pub fn unhex_array<const N: usize>(text: &str) -> Option<[u8; N]> {
    unhex(text)?.try_into().ok()
}
