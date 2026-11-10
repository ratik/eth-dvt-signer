//! Unit tests of `crate::fuzzing`: every input a fuzz campaign found (`fuzz/regressions/<target>`)
//! and every checked-in seed (`fuzz/corpus/<target>/seed-*`) still holds its target's properties,
//! on stable Rust. `write_seeds` (ignored) writes the seeds of the public types again.

use super::*;
use crate::{
    admin::SignedCommand,
    anchor::{Acknowledgment, Marks, Record},
    dkg::{CeremonyConfig, CeremonyId},
    signer::wire::{Refusal, Request},
    types::{Command, SignRequest},
};
use commonware_utils::{TryCollect as _, ordered::Set};
use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    path::{Path, PathBuf},
};

fn fuzz_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz")
}

/// The files of `dir` whose name starts with `prefix` (none if it does not exist).
fn files(dir: &Path, prefix: &str) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut files: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.is_file()
                && path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with(prefix))
        })
        .collect();
    files.sort();
    files
}

#[test]
fn regressions_and_seeds_hold_their_properties() {
    let mut failures = Vec::new();
    let mut replayed = 0;
    for (name, target) in TARGETS {
        let inputs = files(&fuzz_dir().join("regressions").join(name), "")
            .into_iter()
            .chain(files(&fuzz_dir().join("corpus").join(name), "seed-"));
        for path in inputs {
            let bytes = std::fs::read(&path).unwrap();
            replayed += 1;
            if catch_unwind(AssertUnwindSafe(|| target(&bytes))).is_err() {
                failures.push(path.display().to_string());
            }
        }
    }
    assert!(
        failures.is_empty(),
        "inputs that break their target: {failures:#?}"
    );
    assert!(
        replayed > 0,
        "no seed or regression found under {}",
        fuzz_dir().display()
    );
}

/// Write `bytes` as the seed `name` of `target`.
fn seed(target: &str, name: &str, bytes: &[u8]) {
    let dir = fuzz_dir().join("corpus").join(target);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join(format!("seed-{name}")), bytes).unwrap();
}

fn committee() -> Set<commonware_cryptography::ed25519::PublicKey> {
    (0..4u64)
        .map(|seed| PrivateKey::from_seed(seed).public_key())
        .try_collect()
        .unwrap()
}

/// Every JSON file of `dir`, by name.
fn json_files(dir: &str) -> Vec<(String, Vec<u8>)> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join(dir);
    files(&dir, "")
        .into_iter()
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .map(|path| {
            let name = path.file_stem().unwrap().to_string_lossy().to_string();
            (name, std::fs::read(&path).unwrap())
        })
        .collect()
}

/// Write the seeds of the public types (`cargo test --lib write_seeds -- --ignored`). The state
/// values' and manifests' seeds come from `storage::tests::write_fuzz_seeds`.
#[test]
#[ignore]
fn write_seeds() {
    // Web3Signer requests: Lighthouse's, Web3Signer's examples, Gloas's.
    let mut duties = Vec::new();
    for dir in [
        "tests/fixtures/web3signer",
        "tests/fixtures/lighthouse",
        "tests/fixtures/gloas",
    ] {
        for (name, bytes) in json_files(dir) {
            if let Ok(request) = parse_request(&bytes) {
                seed("web3signer", &name, &bytes);
                duties.push(DutyRequest {
                    validator: [0x11; 48],
                    fork: request.fork,
                    duty: request.duty,
                });
            }
        }
    }
    // EIP-3076 interchanges: every step of the specification's vectors.
    for (name, bytes) in json_files("tests/vectors/eip3076/v5.3.0") {
        let test: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        for (index, step) in test["steps"].as_array().unwrap().iter().enumerate() {
            let interchange = serde_json::to_vec(&step["interchange"]).unwrap();
            seed("interchange", &format!("{name}-{index}"), &interchange);
        }
    }

    // Transactions and blocks.
    let ceremony = CeremonyId::new("seed").unwrap();
    let mut transactions = vec![
        Transaction {
            id: 1,
            command: Command::Sign(SignRequest {
                ceremony: ceremony.clone(),
                nonce: 7,
                payload_hash: [3; 32],
            }),
        },
        Transaction {
            id: 2,
            command: Command::StartValidatorCeremony(CeremonyConfig::new(
                ceremony.clone(),
                committee(),
            )),
        },
    ];
    for (index, duty) in duties.into_iter().enumerate() {
        transactions.push(Transaction {
            id: 10 + index as u64,
            command: Command::Duty(Box::new(duty)),
        });
    }
    for (index, transaction) in transactions.iter().enumerate() {
        seed("transaction", &index.to_string(), &transaction.encode());
    }
    let parent: Digest = Sha256::hash(&[b"parent"]);
    let height = commonware_consensus::types::Height::new(5);
    seed(
        "block",
        "empty",
        &Block::new(parent, height, 9, Vec::new()).encode(),
    );
    seed(
        "block",
        "duties",
        &Block::new(parent, height, 9, transactions).encode(),
    );

    // Signing-channel messages.
    let request = Request::duty(ceremony.clone(), [0x11; 48], [4; 32]);
    seed(
        "signer_wire",
        "request",
        &SignerMessage::Request(request.clone()).encode(),
    );
    seed(
        "signer_wire",
        "development",
        &SignerMessage::Request(Request::new(ceremony, 3, [5; 32])).encode(),
    );
    seed(
        "signer_wire",
        "refused",
        &SignerMessage::Refused {
            request: request.id,
            reason: Refusal::BeyondHorizon,
        }
        .encode(),
    );

    // Anchor records and acknowledgments.
    let writer = PrivateKey::from_seed(2);
    let cluster: Digest = Sha256::hash(&[b"fuzz cluster"]);
    let record = SignedRecord::sign(
        &writer,
        Record {
            cluster,
            node: writer.public_key(),
            generation: 0,
            sequence: 3,
            previous: Sha256::hash(&[b"previous"]),
            height: 120,
            digest: Sha256::hash(&[b"block"]),
            marks: Marks {
                block_slot: Some(900),
                source: Some(27),
                target: Some(28),
            },
            written_at: 1_794_000_000_000,
        },
    );
    seed("anchor_record", "record", &record.encode());
    let mut acknowledged = AcknowledgmentDocument::draft(&Acknowledgment {
        cluster,
        generation: 1,
        height: 120,
        digest: Sha256::hash(&[b"block"]),
        marks: Marks {
            block_slot: Some(900),
            source: Some(27),
            target: None,
        },
    });
    for approver in [1_000, 1_002] {
        acknowledged.sign(&PrivateKey::from_seed(approver)).unwrap();
    }
    seed(
        "acknowledgment",
        "signed",
        acknowledged.to_json().as_bytes(),
    );

    // Signed commands of every operation the tests draft.
    let gvr = format!("0x{}", hex::encode([9u8; 32]));
    let key = format!("0x{}", hex::encode([0x11u8; 48]));
    let requests = [
        (
            "activate",
            serde_json::json!({ "public_key": key, "genesis_validators_root": gvr }),
        ),
        (
            "set-registration-policy",
            serde_json::json!({
                "fee_recipients": [format!("0x{}", hex::encode([0xaa; 20]))],
                "gas_limit_min": 30_000_000,
                "gas_limit_max": 60_000_000,
                "max_future_seconds": 30,
                "max_age_seconds": 3600,
            }),
        ),
    ];
    for (operation, request) in requests {
        let Ok(mut document) = SignedCommand::draft(&cluster, operation, 4, request) else {
            continue;
        };
        document.sign(&PrivateKey::from_seed(1_001)).unwrap();
        seed(
            "admin_command",
            operation,
            serde_json::to_string_pretty(&document).unwrap().as_bytes(),
        );
    }
}

/// Write the seeds of the TEE inputs (`cargo test --lib write_tee_seeds -- --ignored`): a peers
/// file, and attestation statements with a token (signed by a test issuer the target's key set
/// does not hold) and without.
#[test]
#[ignore]
fn write_tee_seeds() {
    use crate::attestation::{
        Evidence, GCP_TDX, Keys, Statement,
        testing::{Issuer, Vm},
    };
    let peers = crate::peers::Peers::new(
        committee()
            .iter()
            .enumerate()
            .map(|(index, key)| {
                (
                    key.clone(),
                    std::net::SocketAddr::from(([10, 0, 0, index as u8 + 2], 3000)),
                )
            })
            .collect(),
    )
    .unwrap();
    seed("peers", "four-nodes", peers.to_json().as_bytes());

    let keys = Keys::new(
        &PrivateKey::from_seed(0).public_key(),
        Some(&[7u8; 32]),
        Some(b"spki"),
    );
    let issuer = Issuer::new("k");
    let nonce = hex::encode(keys.binding(b""));
    let token = issuer.sign(&issuer.claims(
        &Vm::new("mpc-tee-0"),
        "eth-mpc-signer",
        &[nonce],
        1_800_000_000,
    ));
    let statement = Statement {
        index: 0,
        vault: GCP_TDX.into(),
        keys: keys.clone(),
        tls_certificate: Some(crate::tls::make(&["127.0.0.1".into()]).unwrap().chain),
        evidence: Some(Evidence {
            platform: GCP_TDX.into(),
            keys: keys.clone(),
            nonce: String::new(),
            token: token.clone(),
        }),
    };
    seed(
        "attestation",
        "sealed-statement",
        serde_json::to_string_pretty(&statement).unwrap().as_bytes(),
    );
    seed(
        "attestation",
        "plain-statement",
        serde_json::to_string(&Statement {
            vault: "plain".into(),
            evidence: None,
            tls_certificate: None,
            ..statement
        })
        .unwrap()
        .as_bytes(),
    );
    seed("attestation", "token", token.as_bytes());
}
