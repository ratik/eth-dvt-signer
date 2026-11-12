//! Fuzzing entry points (feature `fuzzing`; never in a deployment): one function per input a peer,
//! an API client, the anchor or the disk can give a node. Each decodes or parses `bytes` and checks
//! what must hold for every input, panicking otherwise:
//!
//! - nothing panics, allocates without bound or loops (the fuzzer's limits);
//! - what peers send (transactions, blocks, signing and DKG messages) has one encoding per value:
//!   what decodes encodes back to the same bytes;
//! - what is stored (state values, epoch records, secrets) round-trips: a decoded value's encoding
//!   decodes to the same value (legacy layouts are read and rewritten in the current one);
//! - what is parsed (Web3Signer requests, EIP-3076 interchanges, signed commands, anchor records
//!   and acknowledgments, import manifests, peers files, attestation statements and tokens)
//!   yields values every later step accepts without panicking.
//!
//! The fuzz targets (`fuzz/fuzz_targets`) call these, and `fuzzing::tests` (`tests/unit/fuzzing.rs`)
//! replays every input a campaign found (`fuzz/regressions/<target>`) through them on stable Rust.

use crate::{
    admin::{Approvers, SignedCommand, duty_overview, history_overview},
    anchor::{AcknowledgmentDocument, SignedRecord},
    dkg::wire::Message as DkgMessage,
    epochs::EpochRecord,
    eth::{duty::DutyRequest, interchange, web3signer::parse_request},
    import::manifest::Manifest,
    signer::wire::Message as SignerMessage,
    slashing::HistoryImport,
    types::{Block, Transaction},
};
use commonware_codec::{DecodeExt, Encode};
use commonware_cryptography::{
    Hasher as _, Sha256, Signer as _, ed25519::PrivateKey, sha256::Digest,
};
use std::sync::OnceLock;

/// `bytes` decoded as `T`, if they are one; its encoding decodes again to the same encoding.
pub(crate) fn round_trip<T: DecodeExt<()> + Encode>(bytes: &[u8]) -> Option<T> {
    let value = T::decode(commonware_codec::Copying(bytes)).ok()?;
    let encoded = value.encode();
    let again = T::decode(commonware_codec::Copying(encoded.as_ref()))
        .expect("a value's own encoding decodes");
    assert_eq!(
        again.encode().as_ref(),
        encoded.as_ref(),
        "the encoding of a decoded value is not stable"
    );
    Some(value)
}

/// `bytes` decoded as `T`, if they are one, and they are its only encoding.
fn canonical<T: DecodeExt<()> + Encode>(bytes: &[u8]) -> Option<T> {
    let value = round_trip::<T>(bytes)?;
    assert_eq!(
        value.encode().as_ref(),
        bytes,
        "another encoding of a value decodes: one value, two byte strings"
    );
    Some(value)
}

/// A mempool transaction as peers gossip it.
pub fn transaction(bytes: &[u8]) {
    canonical::<Transaction>(bytes);
}

/// A block as marshal receives it.
pub fn block(bytes: &[u8]) {
    if let Some(block) = canonical::<Block>(bytes) {
        let _ = commonware_cryptography::Digestible::digest(&block);
    }
}

/// A signing-channel message (requests and partial signatures).
pub fn signer_wire(bytes: &[u8]) {
    canonical::<SignerMessage>(bytes);
}

/// A DKG-channel message.
pub fn dkg_wire(bytes: &[u8]) {
    canonical::<DkgMessage>(bytes);
}

/// A Web3Signer signing request's body (any API client): parsed, then what the node does with it
/// before consensus (its signing root, the codec form consensus carries, the approvers' overview).
pub fn web3signer(bytes: &[u8]) {
    let Ok(request) = parse_request(bytes) else {
        return;
    };
    let duty = DutyRequest {
        validator: [0x11; 48],
        fork: request.fork,
        duty: request.duty,
    };
    let _ = duty.signing_root();
    let _ = duty_overview(&duty);
    let decoded = round_trip::<DutyRequest>(duty.encode().as_ref())
        .expect("a parsed duty's encoding decodes");
    assert_eq!(
        decoded.signing_root(),
        duty.signing_root(),
        "the duty consensus carries is not the duty the client sent"
    );
}

/// An EIP-3076 interchange (an import request): parsed, summarized, and the import consensus
/// carries round-trips.
pub fn interchange(bytes: &[u8]) {
    let Ok(interchange) = interchange::parse(bytes) else {
        return;
    };
    for history in interchange.validators.values() {
        let _ = history.summary();
    }
    let _ = interchange.digest();
    if let Ok(import) = interchange.import(None) {
        round_trip::<HistoryImport>(import.encode().as_ref())
            .expect("an import's encoding decodes");
    }
}

/// Two of three approvers (seeds 1000 to 1002), as the tests' approver file.
fn approvers() -> &'static Approvers {
    static APPROVERS: OnceLock<Approvers> = OnceLock::new();
    APPROVERS.get_or_init(|| {
        let keys = (1_000..1_003)
            .map(|seed| PrivateKey::from_seed(seed).public_key())
            .collect();
        Approvers::new(2, keys).expect("a valid approver set")
    })
}

/// A signed command document (`mpc-admin`, and the protected endpoints' bodies).
pub fn admin_command(bytes: &[u8]) {
    let Ok(document) = serde_json::from_slice::<SignedCommand>(bytes) else {
        return;
    };
    if document.command().is_err() {
        return;
    }
    let _ = document.message();
    let _ = document.check(approvers());
    let _ = document.authorized(approvers());
    let _ = document.endpoint();
    let _ = document.body();
    if document.operation == "import-history" {
        let _ = history_overview(&document.request);
    }
}

/// An anchor record as read from the bucket.
pub fn anchor_record(bytes: &[u8]) {
    if let Some(record) = canonical::<SignedRecord>(bytes) {
        let _ = record.verify();
        let _ = record.hash();
    }
}

/// An acknowledgment of a rollback as read from the anchor or a file.
pub fn acknowledgment(bytes: &[u8]) {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return;
    };
    let Ok(document) = AcknowledgmentDocument::from_json(text) else {
        return;
    };
    let cluster: Digest = Sha256::hash(&[b"fuzz cluster"]);
    let _ = document.acknowledgment();
    let _ = document.check(approvers());
    let _ = document.verify(approvers(), &cluster);
    let _ = document.name();
}

/// A value of the state partition, an epoch record or a secret as read from disk (a damaged or
/// hostile medium): the first byte picks which.
pub fn state_value(bytes: &[u8]) {
    let Some((which, rest)) = bytes.split_first() else {
        return;
    };
    match which % 3 {
        0 => crate::storage::fuzz_value(rest),
        1 => {
            round_trip::<EpochRecord>(rest);
        }
        _ => crate::dkg::secrets::fuzz_value(rest),
    }
}

/// An import manifest (`mpc-keytool`), and the checks a node runs on it.
pub fn manifest(bytes: &[u8]) {
    if let Some(manifest) = canonical::<Manifest>(bytes) {
        let _ = manifest.digest();
        let _ = manifest.participants();
        let _ = manifest.config();
        let _ = manifest.sharing();
    }
}

/// A peers file (`--peers`): what parses writes back to a file that parses to the same peers.
pub fn peers(bytes: &[u8]) {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return;
    };
    if let Ok(peers) = crate::peers::Peers::from_json(text) {
        let again = crate::peers::Peers::from_json(&peers.to_json()).expect("its own file parses");
        assert_eq!(again, peers);
    }
}

/// An attestation statement (`GET /attestation`, `mpc-admin attest`, `mpc-keytool split`), and
/// the same bytes as a bare token: checked against a policy and a key set without panicking, and
/// never accepted (no token here is signed by the key set's key).
pub fn attestation(bytes: &[u8]) {
    use crate::attestation::{
        Statement,
        verify::{Jwk, Jwks, Policy, verify, verify_jwt},
    };
    let jwks = Jwks {
        keys: vec![Jwk {
            kid: "k".into(),
            kty: "RSA".into(),
            // A 2048-bit modulus of 0xc5 bytes and exponent 65537: no fuzzer forges its signatures.
            n: "xcXF".repeat(86),
            e: "AQAB".into(),
            alg: Some("RS256".into()),
        }],
    };
    let policy = Policy {
        issuer: crate::attestation::verify::GOOGLE_ISSUER.into(),
        audience: "eth-mpc-signer".into(),
        hwmodel: "GCP_INTEL_TDX".into(),
        dbgstat: "disabled-since-boot".into(),
        rtmr1: vec!["00".into()],
        rtmr2: vec!["00".into()],
        project_number: None,
        rtmr3: None,
        max_age_seconds: 600,
    };
    let Ok(text) = std::str::from_utf8(bytes) else {
        return;
    };
    assert!(
        verify_jwt(text, &jwks).is_err(),
        "an unsigned token verified"
    );
    if let Ok(statement) = serde_json::from_str::<Statement>(text)
        && let Some(evidence) = &statement.evidence
    {
        let _ = statement.keys.binding(b"nonce");
        let _ = statement.keys.serves(text.as_bytes());
        assert!(verify(evidence, &policy, &jwks, b"", 1_800_000_000, Some(0)).is_err());
    }
}

/// A fuzz target's entry point: panics if `bytes` break a property.
pub type Target = fn(&[u8]);

/// Every target, by its name in `fuzz/fuzz_targets` and `fuzz/regressions`.
pub const TARGETS: &[(&str, Target)] = &[
    ("transaction", transaction),
    ("block", block),
    ("signer_wire", signer_wire),
    ("dkg_wire", dkg_wire),
    ("web3signer", web3signer),
    ("interchange", interchange),
    ("admin_command", admin_command),
    ("anchor_record", anchor_record),
    ("acknowledgment", acknowledgment),
    ("state_value", state_value),
    ("manifest", manifest),
    ("peers", peers),
    ("attestation", attestation),
];

#[cfg(test)]
#[path = "../tests/unit/fuzzing.rs"]
mod tests;
