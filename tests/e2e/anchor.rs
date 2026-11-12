//! The WORM anchor (`anchor`, docs/anchor.md) on real processes, with a `file://` anchor outside
//! the nodes' data directories (a restore of the nodes' storage does not reach it), the restart
//! floor on, and duties of the test chain's current slots (1-second slots from the Unix epoch).
//!
//! - an_1: keyholders write records ahead of their partials; after a restart of every node the
//!   chain is confirmed at once and signing goes on, under the anchored marks.
//! - an_2: a whole-network rollback: every node signs nothing new and stops with exit status 77.
//! - an_3: one node rolled back: it is behind, catches up from its peers, is confirmed, never
//!   stops.
//! - an_4: one node's forged record (far above, another block): ignored by every node.
//! - an_5: the anchor unreachable at start: every node starts degraded and signs under the floor
//!   alone; once it answers, a catch-up record and the anchor is used again.
//! - an_6: after an_2, the approvers acknowledge the rollback (`mpc-admin anchor acknowledge`,
//!   `sign`): the nodes started with it continue in generation 1, and the anchored marks still
//!   refuse a vote surrounding the one signed before the rollback.
//!
//! Elsewhere: the records, the store and the rules in `tests/unit/anchor.rs`.

use crate::{
    eth2::{CHAIN, activation, attestation, block, sign, signed},
    harness::{NODES, TestNetwork, approver_keys, approvers_json},
};
use commonware_codec::Encode as _;
use commonware_cryptography::{Signer as _, ed25519::PrivateKey};
use eth_mpc_signer::anchor::{Marks, Record, SignedRecord};
use serde_json::{Value, json};
use std::{
    io::Write as _,
    os::unix::fs::OpenOptionsExt as _,
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

const ADMIN: &str = env!("CARGO_BIN_EXE_mpc-admin");

const VALIDATOR: &str = "validator-anchor";

/// The test chain's current slot.
fn slot() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn anchor_dir(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "eth-mpc-signer-anchor-{name}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}

/// Four nodes with the restart floor and the anchor at `anchor` (heartbeats every 5 s), plus
/// `env`; an activated validator key.
fn start(anchor: &Path, env: Vec<(String, String)>) -> (TestNetwork, String) {
    let location = format!("file://{}", anchor.display());
    let network = TestNetwork::start_with_args(
        NODES,
        vec![
            "--anchor".into(),
            location,
            "--anchor-heartbeat-secs".into(),
            "5".into(),
        ],
        move |_| {
            let mut all = vec![(
                "ETH_MPC_SIGNER_NO_RESTART_FLOOR".to_string(),
                "0".to_string(),
            )];
            all.extend(env.iter().cloned());
            all
        },
    );
    // Ready, or degraded by the anchor alone (an_5).
    for node in network.all() {
        network.wait_until(&format!("node {node} ready"), || {
            network
                .try_call(node, "GET", "/ready", None)
                .is_ok_and(|(_, readiness)| {
                    let reasons = &readiness["reasons"];
                    *reasons == json!([]) || *reasons == json!(["anchor_unavailable"])
                })
        });
    }
    network.start_validator_dkg(0, VALIDATOR);
    let key = network.wait_for_dkg(VALIDATOR, &network.all());
    let (status, activated) = network.approved(
        0,
        "activate",
        json!({ "public_key": key, "genesis_validators_root": CHAIN }),
    );
    assert_eq!(status, 200, "{activated}");
    for node in network.all() {
        network.wait_until(&format!("activation on node {node}"), || {
            activation(&network, node, &key).is_some()
        });
    }
    (network, key)
}

fn anchor_of(network: &TestNetwork, node: usize) -> Value {
    network.get(node, "/status").1["anchor"].clone()
}

fn wait_state(network: &TestNetwork, nodes: &[usize], state: &str) {
    for node in nodes {
        network.wait_until(&format!("node {node}'s anchor {state}"), || {
            anchor_of(network, *node)["state"] == state
        });
    }
}

/// Wait for the start of an epoch after every restart floor of a node started before the call
/// (the floor is the slot 4 s after a node's start).
fn next_epoch(network: &TestNetwork) -> u64 {
    let next = (slot() + 5) / 32 + 1;
    network.wait_until(&format!("epoch {next} to start"), || slot() >= next * 32);
    next
}

fn restart_every_node(network: &TestNetwork) {
    for node in network.all() {
        network.stop_node(node);
    }
    for node in network.all() {
        network.restart_node(node);
    }
}

/// A block and an attestation of the current slot and epoch, signed; returns the block's slot
/// and the attestation's target.
fn sign_duties(network: &TestNetwork, key: &str) -> (u64, u64) {
    let target = next_epoch(network);
    let proposed = slot();
    signed(network, 0, key, &block(proposed, 1));
    signed(network, 1, key, &attestation(target - 1, target, 1));
    (proposed, target)
}

/// Records written ahead of the partials; a restart of every node is confirmed at once, the
/// anchored marks cover what was signed, and signing goes on.
#[test]
fn an_1_records_are_written_and_a_restart_is_confirmed() {
    let dir = anchor_dir("an1");
    let (network, key) = start(&dir, Vec::new());
    let (proposed, target) = sign_duties(&network, &key);
    network.wait_until(
        "three keyholders' records to cover the block and the attestation",
        || {
            network
                .all()
                .iter()
                .filter(|node| {
                    let marks = &anchor_of(&network, **node)["marks"];
                    marks["block_slot"] == json!(proposed) && marks["target"] == json!(target)
                })
                .count()
                >= 3
        },
    );

    restart_every_node(&network);
    network.wait_for_ready(&network.all());
    wait_state(&network, &network.all(), "confirmed");
    let anchored = anchor_of(&network, 2)["anchored"].clone();
    assert_eq!(anchored["block_slot"], json!(proposed), "{anchored}");
    assert_eq!(anchored["target"], json!(target), "{anchored}");
    // The next epoch's duties sign.
    sign_duties(&network, &key);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Every node restored to storage from before a block and an attestation and restarted: none is
/// confirmed, none signs anything new (the conflicting block, a surround vote), and every one
/// stops with exit status 77 once the network finalizes below the anchored height.
#[test]
fn an_2_a_whole_network_rollback_stops_every_node() {
    let dir = anchor_dir("an2");
    let (network, key) = start(&dir, Vec::new());
    roll_back_everything(&network, &key);
    let _ = std::fs::remove_dir_all(&dir);
}

/// an_2's rollback: every node's storage from before a block and an attestation, restarted; every
/// node stops with exit status 77. Returns the attestation's target.
fn roll_back_everything(network: &TestNetwork, key: &str) -> u64 {
    for node in network.all() {
        network.stop_node(node);
        network.snapshot(node, &format!("before-{node}"));
    }
    for node in network.all() {
        network.restart_node(node);
    }
    network.wait_for_ready(&network.all());
    wait_state(network, &network.all(), "confirmed");
    let (proposed, target) = sign_duties(network, key);

    for node in network.all() {
        network.stop_node(node);
        network.restore(node, &format!("before-{node}"));
    }
    for node in network.all() {
        network.restart_node(node);
    }
    // Nothing new is signed while the network runs on the rolled-back chain: the conflicting
    // block, a vote surrounding the signed one (a node may have stopped already).
    // Of the current epoch: at least the signed vote's, which it surrounds or doubles.
    let surround = attestation(0, (slot() / 32).max(target), 2);
    for (via, body) in [(1, block(proposed, 2)), (2, surround)] {
        if let Some((status, answer)) = try_sign(network, via, key, &body) {
            assert_ne!(
                status, 200,
                "signed on a rolled-back network: {answer} for {body}"
            );
        }
    }
    for node in network.all() {
        let status = network.wait_exit(node);
        assert_eq!(status.code(), Some(77), "node {node}: {status:?}");
    }
    target
}

/// `POST /api/v1/eth2/sign/{key}` on node `via`: its status and answer, `None` if the node does
/// not answer (it stopped).
fn try_sign(network: &TestNetwork, via: usize, key: &str, body: &Value) -> Option<(u16, String)> {
    network
        .eth2_call(
            via,
            &format!("/api/v1/eth2/sign/{key}"),
            &[("Accept", "application/json")],
            body,
        )
        .ok()
        .map(|(status, _, text)| (status, text))
}

/// One node restored from old storage: behind at start, it catches up from its peers, is
/// confirmed, and never stops; the network signs throughout.
#[test]
fn an_3_one_rolled_back_node_catches_up() {
    let dir = anchor_dir("an3");
    let (network, key) = start(&dir, Vec::new());
    network.stop_node(3);
    network.snapshot(3, "before");
    network.restart_node(3);
    network.wait_for_ready(&[3]);
    sign_duties(&network, &key);
    network.stop_node(3);
    network.restore(3, "before");
    network.restart_node(3);
    wait_state(&network, &[3], "confirmed");
    sign_duties(&network, &key);
    assert!(anchor_of(&network, 3)["state"] == "confirmed");
    let _ = std::fs::remove_dir_all(&dir);
}

/// The cluster id the records are filed under (`GET /admin`).
fn cluster(network: &TestNetwork) -> String {
    network.get(0, "/admin").1["cluster_id"]
        .as_str()
        .unwrap()
        .trim_start_matches("0x")
        .to_string()
}

/// Node 3 (seed 3) writes a forged record far above everything, naming another block: every
/// node ignores it (the second-highest marks, two of the three highest records), and nobody
/// stops.
#[test]
fn an_4_a_forged_record_of_one_node_is_ignored() {
    let dir = anchor_dir("an4");
    let (network, key) = start(&dir, Vec::new());
    let (proposed, _) = sign_duties(&network, &key);
    let forger = PrivateKey::from_seed(3);
    let chain = dir
        .join(cluster(&network))
        .join(hex::encode(forger.public_key().encode()));
    network.wait_until("node 3's records", || chain.exists());
    // Stopped first: node 3's own next record would race the forged one for its place.
    for node in network.all() {
        network.stop_node(node);
    }
    let latest = (0u64..)
        .take_while(|sequence| chain.join(format!("{sequence:020}")).exists())
        .last()
        .expect("node 3 wrote a record");
    let head: SignedRecord = commonware_codec::DecodeExt::decode(
        std::fs::read(chain.join(format!("{latest:020}"))).unwrap(),
    )
    .unwrap();
    let forged = SignedRecord::sign(
        &forger,
        Record {
            sequence: latest + 1,
            previous: head.hash(),
            height: 1_000_000_000,
            digest: commonware_cryptography::sha256::Digest::from([0xee; 32]),
            marks: Marks {
                block_slot: Some(u64::MAX / 2),
                source: Some(u64::MAX / 2),
                target: Some(u64::MAX / 2),
            },
            ..head.record.clone()
        },
    );
    std::fs::write(chain.join(format!("{:020}", latest + 1)), forged.encode()).unwrap();

    for node in network.all() {
        network.restart_node(node);
    }
    network.wait_for_ready(&network.all());
    wait_state(&network, &[0, 1, 2], "confirmed");
    let anchored = anchor_of(&network, 0)["anchored"].clone();
    assert_eq!(anchored["block_slot"], json!(proposed), "{anchored}");
    sign_duties(&network, &key);
    let _ = std::fs::remove_dir_all(&dir);
}

/// The anchor unreachable at start: every node starts degraded (`anchor_unavailable`) and signs
/// under the restart floor alone; once the anchor answers, a catch-up record and the anchor is
/// used again.
#[test]
fn an_5_an_unreachable_anchor_degrades_then_recovers() {
    let dir = anchor_dir("an5");
    let unreachable = anchor_dir("an5-unreachable");
    std::fs::write(&unreachable, b"").unwrap();
    let (network, key) = start(
        &dir,
        vec![(
            "ETH_MPC_SIGNER_ANCHOR_UNREACHABLE_FILE".into(),
            unreachable.display().to_string(),
        )],
    );
    wait_state(&network, &network.all(), "degraded");
    let readiness = network.readiness(0);
    assert_eq!(readiness["state"], "degraded", "{readiness}");
    assert_eq!(
        readiness["reasons"],
        json!(["anchor_unavailable"]),
        "{readiness}"
    );
    sign_duties(&network, &key);
    std::fs::remove_file(&unreachable).unwrap();
    wait_state(&network, &network.all(), "confirmed");
    network.wait_for_ready(&network.all());
    let caught_up: Vec<Value> = network
        .all()
        .iter()
        .map(|node| anchor_of(&network, *node))
        .collect();
    assert!(
        caught_up.iter().all(|anchor| anchor["sequence"].is_u64()),
        "every node wrote a record once the anchor answered: {caught_up:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// `mpc-admin args`: its standard output; fails the test if it fails.
fn admin(args: &[&str]) -> String {
    let output = Command::new(ADMIN).args(args).output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    assert!(
        output.status.success(),
        "mpc-admin {args:?}: {stdout}{}",
        String::from_utf8_lossy(&output.stderr)
    );
    println!(
        "mpc-admin {}:\n{stdout}",
        args.first().copied().unwrap_or_default()
    );
    stdout
}

/// After a whole-network rollback (an_2), two approvers acknowledge it offline; the nodes started
/// with the acknowledgment continue in generation 1, sign again, and still refuse a vote
/// surrounding the one signed before the rollback (the acknowledged marks).
#[test]
fn an_6_an_acknowledged_rollback_resumes_under_the_anchored_marks() {
    let dir = anchor_dir("an6");
    let files = anchor_dir("an6-files");
    std::fs::create_dir_all(&files).unwrap();
    let (network, key) = start(&dir, Vec::new());
    let cluster = format!("0x{}", cluster(&network));
    let target = roll_back_everything(&network, &key);

    let approvers = files.join("approvers.json");
    std::fs::write(&approvers, approvers_json()).unwrap();
    let location = format!("file://{}", dir.display());
    let path = |name: &str| files.join(name).display().to_string();
    let checked = admin(&[
        "anchor",
        "check",
        "--anchor",
        &location,
        "--cluster",
        &cluster,
        "--approvers",
        &path("approvers.json"),
    ]);
    assert!(checked.contains("generation 0:"), "{checked}");
    admin(&[
        "anchor",
        "acknowledge",
        "--anchor",
        &location,
        "--cluster",
        &cluster,
        "--approvers",
        &path("approvers.json"),
        "--output",
        &path("ack.json"),
    ]);
    let mut signed_by = path("ack.json");
    for (index, approver) in approver_keys().iter().take(2).enumerate() {
        let key_file = path(&format!("approver-{index}.key"));
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&key_file)
            .unwrap();
        writeln!(file, "0x{}", hex::encode(approver.encode())).unwrap();
        let output = path(&format!("ack-{index}.json"));
        admin(&[
            "sign",
            "--command",
            &signed_by,
            "--key",
            &key_file,
            "--output",
            &output,
            "--yes",
        ]);
        signed_by = output;
    }
    let shown = admin(&[
        "show",
        "--command",
        &signed_by,
        "--approvers",
        &path("approvers.json"),
    ]);
    assert!(shown.contains("2 valid approvals of 2 required"), "{shown}");

    for node in network.all() {
        network.restart_node_with_args(node, &["--anchor-acknowledgment", &signed_by]);
    }
    network.wait_for_ready(&network.all());
    wait_state(&network, &network.all(), "confirmed");
    for node in network.all() {
        let anchor = anchor_of(&network, node);
        assert_eq!(anchor["generation"], json!(1), "{anchor}");
        assert!(
            anchor["anchored"]["source"].as_u64() >= Some(target - 1),
            "the acknowledged marks: {anchor}"
        );
    }
    // Past every restart floor: a vote surrounding the one signed before the rollback is refused
    // by the acknowledged marks; a new block signs.
    let epoch = next_epoch(&network);
    let refused: usize = network
        .all()
        .iter()
        .map(|node| network.count(*node, "anchor: not signing"))
        .sum();
    let (status, answer) = sign(&network, 1, &key, &attestation(0, epoch, 3));
    // Refused for good by the keyholders' protection (412), not unavailable (503).
    assert_eq!(
        status, 412,
        "a surround vote after the acknowledgment: {answer}"
    );
    assert_eq!(answer["protection"], "anchored_marks", "{answer}");
    let now: usize = network
        .all()
        .iter()
        .map(|node| network.count(*node, "anchor: not signing"))
        .sum();
    assert!(
        now > refused,
        "the keyholders refused it for the anchored marks"
    );
    signed(&network, 2, &key, &block(slot(), 3));
    let checked = admin(&[
        "anchor",
        "check",
        "--anchor",
        &location,
        "--cluster",
        &cluster,
        "--approvers",
        &path("approvers.json"),
    ]);
    assert!(checked.contains("generation 1:"), "{checked}");
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&files);
}
