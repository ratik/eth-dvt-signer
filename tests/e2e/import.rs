//! E2E-IMP: an existing validator key imported into the network (`mpc-keytool`, docs/key-import.md)
//! on real processes: registration, each node opening its own share, the slashing-protection
//! import, the activation barriers, then signing exactly as the original key and the imported
//! history's refusals.

use crate::{
    eth2::{CHAIN, activation, attestation, block, refused, signed, signing_root},
    harness::{NODES, TestNetwork, unhex},
};
use eth_mpc_signer::import::envelope::ShareKey;
use serde_json::{Value, json};
use std::{
    os::unix::fs::OpenOptionsExt as _,
    path::{Path, PathBuf},
    process::Command,
};

/// The EIP-2335 test vector (tests/fixtures/eip2335): its key is the one imported.
const PASSWORD: &str = "𝔱𝔢𝔰𝔱𝔭𝔞𝔰𝔰𝔴𝔬𝔯𝔡🔑";
const SECRET: &str = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
const PUBKEY: &str = "0x9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07";
const CEREMONY: &str = "imported-validator";

const ACKNOWLEDGED: &str = r#"{"previous_signer_stopped": true, "no_other_active_signer": true, "history_exported_after_stop": true, "automatic_restart_disabled": true}"#;

fn write_secret(path: &Path, contents: &[u8]) {
    use std::io::Write as _;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(contents).unwrap();
}

fn keytool(args: &[&str]) -> std::process::Output {
    let output = Command::new(env!("CARGO_BIN_EXE_mpc-keytool"))
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "mpc-keytool {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

/// A network whose nodes each have a share-encryption key, and the directory of the import
/// (keys, committee, keystore, password).
fn import_network() -> (TestNetwork, PathBuf) {
    let dir = std::env::temp_dir().join(format!(
        "eth-mpc-signer-import-{}-{}",
        std::process::id(),
        rand_suffix()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    for node in 0..NODES {
        write_secret(
            &dir.join(format!("node-{node}.key")),
            ShareKey::generate().to_file().as_bytes(),
        );
    }
    let keys = dir.clone();
    let network = TestNetwork::start_with_node_args(
        NODES,
        Vec::new(),
        move |node| {
            vec![
                "--share-encryption-key".into(),
                keys.join(format!("node-{node}.key")).display().to_string(),
            ]
        },
        |_| Vec::new(),
    );
    network.wait_for_ready(&network.all());
    (network, dir)
}

fn rand_suffix() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos()
}

/// Split the vector keystore for the network's committee (as `GET /identity` gives it) into `out`.
fn split(network: &TestNetwork, dir: &Path, ceremony: &str, out: &str) -> (Value, Vec<Value>) {
    let participants: Vec<Value> = network
        .all()
        .into_iter()
        .map(|node| {
            let (status, identity) = network.get(node, "/identity");
            assert_eq!(status, 200, "{identity}");
            json!({"identity": identity["identity"], "share_encryption_key": identity["share_encryption_key"]})
        })
        .collect();
    std::fs::write(
        dir.join("committee.json"),
        json!({"participants": participants}).to_string(),
    )
    .unwrap();
    if !dir.join("keystore.json").exists() {
        std::fs::copy(
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/eip2335/pbkdf2.json"
            ),
            dir.join("keystore.json"),
        )
        .unwrap();
        write_secret(&dir.join("password"), PASSWORD.as_bytes());
    }
    let path = |name: &str| dir.join(name).display().to_string();
    keytool(&[
        "split",
        "--keystore",
        &path("keystore.json"),
        "--password-file",
        &path("password"),
        "--committee",
        &path("committee.json"),
        "--ceremony-id",
        ceremony,
        "--output",
        &path(out),
    ]);
    let read = |name: &str| -> Value {
        serde_json::from_slice(&std::fs::read(dir.join(out).join(name)).unwrap()).unwrap()
    };
    let manifest = read("manifest.json");
    // Node `n` gets the envelope addressed to its identity.
    let envelopes = network
        .all()
        .into_iter()
        .map(|node| {
            let (_, identity) = network.get(node, "/identity");
            let index = identity["participant_index"].as_u64().unwrap();
            let envelope = read(&format!("node-{index}.enc"));
            assert_eq!(envelope["participant_identity"], identity["identity"]);
            envelope
        })
        .collect();
    (manifest, envelopes)
}

fn interchange(pubkey: &str, gvr: &str, blocks: Value, attestations: Value) -> Value {
    json!({
        "metadata": {"interchange_format_version": "5", "genesis_validators_root": gvr},
        "data": [{"pubkey": pubkey, "signed_blocks": blocks, "signed_attestations": attestations}],
    })
}

fn status(network: &TestNetwork, node: usize) -> Value {
    let (code, status) = network.get(node, &format!("/keys/import/{CEREMONY}"));
    assert_eq!(code, 200, "{status}");
    status
}

/// The signature the original key gives `root` (blst, directly): what the network must produce.
fn original_signature(root: &[u8; 32]) -> String {
    let secret = hex::decode(SECRET).unwrap();
    let signature = blst::min_pk::SecretKey::from_bytes(&secret)
        .unwrap()
        .sign(root, b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_", &[])
        .compress();
    format!("0x{}", hex::encode(signature))
}

/// E2E-IMP-1: the whole import, its barriers and refusals, then signing as the original key.
#[test]
fn e2e_imp_1_an_imported_key_signs_only_once_safely_activated() {
    let (network, dir) = import_network();
    let (manifest, envelopes) = split(&network, &dir, CEREMONY, "shares");
    assert_eq!(manifest["validator_public_key"], PUBKEY);

    // Nothing to install into before the registration.
    let (code, answer) = network.post(0, "/keys/import/share", &envelopes[0]);
    assert_eq!(code, 404, "{answer}");

    // Registration through any node, idempotent; the id and the key are registered once.
    let (code, registered) = network.post(1, "/keys/import", &manifest);
    assert_eq!(code, 200, "{registered}");
    assert_eq!(registered["status"], "inactive");
    assert_eq!(registered["ready_shares"], json!([]));
    let (code, again) = network.post(2, "/keys/import", &manifest);
    assert_eq!(
        (code, &again["manifest_digest"]),
        (200, &registered["manifest_digest"]),
        "{again}"
    );
    let (resplit, _) = split(&network, &dir, CEREMONY, "resplit");
    let (code, answer) = network.post(0, "/keys/import", &resplit);
    assert_eq!(code, 409, "same id, other split: {answer}");
    let (other_id, _) = split(&network, &dir, "imported-elsewhere", "other-id");
    let (code, answer) = network.post(0, "/keys/import", &other_id);
    assert_eq!(code, 409, "same key, other id: {answer}");
    let mut tampered = manifest.clone();
    tampered["threshold"] = json!(2);
    assert_eq!(network.post(0, "/keys/import", &tampered).0, 400);

    // Registered, not signable: not listed, duties refused.
    let (_, keys) = network.get(0, "/api/v1/eth2/publicKeys");
    assert!(!keys.as_array().unwrap().contains(&json!(PUBKEY)));
    let (code, _) = network.eth2_sign(0, PUBKEY, &block(200, 1));
    assert_eq!(code, 404);

    // Each node installs its own share; another node's share, a modified one, or a share of
    // another split of the same key are refused.
    for node in network.all() {
        network.wait_until(&format!("registration on node {node}"), || {
            network.get(node, &format!("/keys/import/{CEREMONY}")).0 == 200
        });
        assert_eq!(status(&network, node)["share"], "pending");
    }
    let (code, answer) = network.post(1, "/keys/import/share", &envelopes[2]);
    assert_eq!(code, 403, "{answer}");
    let mut modified = envelopes[1].clone();
    let mut ciphertext = unhex(&modified["ciphertext"]);
    ciphertext[3] ^= 1;
    modified["ciphertext"] = json!(format!("0x{}", hex::encode(ciphertext)));
    assert_eq!(network.post(1, "/keys/import/share", &modified).0, 400);
    let resplit_envelope: Value = serde_json::from_slice(
        &std::fs::read(
            dir.join("resplit")
                .join(format!("node-{}.enc", envelopes[1]["participant_index"])),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        network.post(1, "/keys/import/share", &resplit_envelope).0,
        400
    );
    for (node, envelope) in envelopes.iter().enumerate() {
        let (code, answer) = network.post(node, "/keys/import/share", envelope);
        assert_eq!(
            (code, answer["installed"].as_str()),
            (200, Some("stored")),
            "node {node}: {answer}"
        );
    }
    let (code, answer) = network.post(0, "/keys/import/share", &envelopes[0]);
    assert_eq!(
        (code, answer["installed"].as_str()),
        (200, Some("already_stored")),
        "{answer}"
    );
    for node in network.all() {
        network.wait_until(&format!("four acknowledged shares on node {node}"), || {
            status(&network, node)["ready_shares"]
                .as_array()
                .unwrap()
                .len()
                == NODES
        });
        assert_eq!(status(&network, node)["share"], "stored");
    }

    // Activation needs the acknowledgement, then the history.
    let activate = |acknowledgment: Option<&str>| {
        let mut body = json!({"public_key": PUBKEY, "genesis_validators_root": CHAIN});
        if let Some(acknowledgment) = acknowledgment {
            body["acknowledgment"] = serde_json::from_str(acknowledgment).unwrap();
        }
        network.post(0, "/validators/activate", &body)
    };
    let (code, answer) = activate(None);
    assert_eq!(code, 400, "{answer}");
    let (code, answer) = activate(Some(ACKNOWLEDGED));
    assert_eq!(
        (code, answer["refusal"]["reason"].as_str()),
        (409, Some("no_imported_history")),
        "{answer}"
    );

    // The previous signer's history: a dry run changes nothing; then the import, idempotent; a
    // history for another chain, or slashable in itself, is refused.
    let history = interchange(
        PUBKEY,
        CHAIN,
        json!([{"slot": "100"}]),
        json!([{"source_epoch": "10", "target_epoch": "11"}]),
    );
    let (code, dry) = network.post(
        2,
        "/slashing-protection/import",
        &json!({"interchange": history, "dry_run": true}),
    );
    assert_eq!(
        (code, dry["dry_run"].as_bool(), dry["outcome"].as_str()),
        (200, Some(true), Some("imported")),
        "{dry}"
    );
    assert_eq!(status(&network, 2)["history"]["imported"], false);
    let (code, imported) = network.post(
        2,
        "/slashing-protection/import",
        &json!({"interchange": history}),
    );
    assert_eq!(
        (code, imported["outcome"].as_str()),
        (200, Some("imported")),
        "{imported}"
    );
    let (code, again) = network.post(
        3,
        "/slashing-protection/import",
        &json!({"interchange": history}),
    );
    assert_eq!(
        (code, again["outcome"].as_str()),
        (200, Some("unchanged")),
        "{again}"
    );
    let other_chain = interchange(
        PUBKEY,
        &format!("0x{}", "11".repeat(32)),
        json!([]),
        json!([]),
    );
    assert_eq!(
        network
            .post(
                0,
                "/slashing-protection/import",
                &json!({"interchange": other_chain})
            )
            .0,
        409
    );
    let slashable = interchange(
        PUBKEY,
        CHAIN,
        json!([{"slot": "5", "signing_root": format!("0x{}", "01".repeat(32))}, {"slot": "5", "signing_root": format!("0x{}", "02".repeat(32))}]),
        json!([]),
    );
    assert_eq!(
        network
            .post(
                0,
                "/slashing-protection/import",
                &json!({"interchange": slashable})
            )
            .0,
        400
    );
    let floors = &status(&network, 0)["history"]["floors"];
    assert_eq!(
        floors,
        &json!({"block_slot": 100, "source_epoch": 10, "target_epoch": 11})
    );

    // An incomplete acknowledgement, then the complete one; repeated activations are idempotent.
    let (code, answer) = activate(Some(&ACKNOWLEDGED.replace(
        r#""automatic_restart_disabled": true"#,
        r#""automatic_restart_disabled": false"#,
    )));
    assert_eq!(
        (code, answer["refusal"]["reason"].as_str()),
        (409, Some("not_acknowledged")),
        "{answer}"
    );
    let (code, activated) = activate(Some(ACKNOWLEDGED));
    assert_eq!(
        (
            code,
            activated["status"].as_str(),
            activated["origin"].as_str()
        ),
        (200, Some("active"), Some("imported")),
        "{activated}"
    );
    assert_eq!(activate(Some(ACKNOWLEDGED)).0, 200);
    for node in network.all() {
        network.wait_until(&format!("activation on node {node}"), || {
            activation(&network, node, PUBKEY).is_some()
        });
    }

    // The same signatures as the original key, through the same checks as any validator key.
    let first = block(101, 1);
    let signature = signed(&network, 0, PUBKEY, &first);
    assert_eq!(signature, json!(original_signature(&signing_root(&first))));
    let vote = attestation(10, 12, 1);
    assert_eq!(
        signed(&network, 1, PUBKEY, &vote),
        json!(original_signature(&signing_root(&vote)))
    );
    refused(
        &network,
        2,
        PUBKEY,
        &block(100, 9),
        "block_at_or_below_imported",
    );
    refused(
        &network,
        2,
        PUBKEY,
        &block(60, 9),
        "block_at_or_below_imported",
    );
    refused(&network, 3, PUBKEY, &block(101, 2), "double_proposal");
    refused(
        &network,
        0,
        PUBKEY,
        &attestation(9, 13, 1),
        "source_below_imported",
    );
    refused(
        &network,
        1,
        PUBKEY,
        &attestation(10, 11, 1),
        "target_at_or_below_imported",
    );
    refused(&network, 2, PUBKEY, &attestation(10, 12, 2), "double_vote");
    // No raw signing for a validator key (development API, present in this build).
    let (code, answer) = network.sign(0, CEREMONY, 1, [5; 32]);
    assert_eq!(code, 403, "{answer}");

    // One keyholder down: three still sign; it reloads its share on restart.
    network.stop_node(3);
    let next = block(102, 1);
    assert_eq!(
        signed(&network, 0, PUBKEY, &next),
        json!(original_signature(&signing_root(&next)))
    );
    network.restart_node(3);
    network.wait_for_ready(&[3]);
    assert_eq!(status(&network, 3)["share"], "stored");
    let later = block(103, 1);
    signed(&network, 3, PUBKEY, &later);

    // A registration of the same key resets nothing.
    assert_eq!(network.post(0, "/keys/import", &manifest).0, 200);
    assert_eq!(network.post(0, "/keys/import", &other_id).0, 409);
    refused(&network, 1, PUBKEY, &block(101, 3), "double_proposal");

    // The export: the floors, then what the network signed above them.
    let (code, export) = network.get(0, &format!("/slashing-protection/export/{PUBKEY}"));
    assert_eq!(code, 200, "{export}");
    assert_eq!(export["metadata"]["genesis_validators_root"], CHAIN);
    let blocks: Vec<&str> = export["data"][0]["signed_blocks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| b["slot"].as_str().unwrap())
        .collect();
    assert_eq!(blocks, ["100", "101", "102", "103"]);
    assert!(
        export["data"][0]["signed_blocks"][0]
            .get("signing_root")
            .is_none()
    );
    let attestations: Vec<(&str, &str)> = export["data"][0]["signed_attestations"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| {
            (
                a["source_epoch"].as_str().unwrap(),
                a["target_epoch"].as_str().unwrap(),
            )
        })
        .collect();
    assert_eq!(attestations, [("10", "11"), ("10", "12")]);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// E2E-IMP-2: a node without a share-encryption key installs nothing, and a DKG key takes no
/// imported history and needs no acknowledgement.
#[test]
fn e2e_imp_2_nodes_without_keys_and_dkg_keys() {
    let network = TestNetwork::start(NODES);
    network.wait_for_ready(&network.all());
    let (_, identity) = network.get(0, "/identity");
    assert!(identity["share_encryption_key"].is_null(), "{identity}");
    network.start_validator_dkg(0, "dkg-validator");
    let key = network.wait_for_dkg("dkg-validator", &network.all());
    let history = interchange(&key, CHAIN, json!([{"slot": "1"}]), json!([]));
    let (code, answer) = network.post(
        0,
        "/slashing-protection/import",
        &json!({"interchange": history}),
    );
    assert_eq!(
        (code, answer["refusal"]["reason"].as_str()),
        (409, Some("not_imported")),
        "{answer}"
    );
    let body = json!({"public_key": key, "genesis_validators_root": CHAIN, "acknowledgment": serde_json::from_str::<Value>(ACKNOWLEDGED).unwrap()});
    assert_eq!(network.post(0, "/validators/activate", &body).0, 400);
    let body = json!({"public_key": key, "genesis_validators_root": CHAIN});
    assert_eq!(network.post(0, "/validators/activate", &body).0, 200);
    let (_, validators) = network.get(0, "/validators");
    assert_eq!(validators[0]["origin"], "dkg");
}
