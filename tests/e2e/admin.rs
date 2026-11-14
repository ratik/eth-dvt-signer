//! P0: protected operations need the approvers' authorization (docs/administration.md), on real
//! processes. Every test node runs with the approvers of `harness::approver_keys` (2 of 3).
//!
//! Elsewhere: test 10 (stale after an epoch transition) in `reconfigure::r3_7_refusals`, 12 (an
//! authorized R3 transition, signed offline with `mpc-admin`) in `reconfigure::r3_1`, 14 (an
//! authorized R2 replacement) in `replace`, 15 (an unauthorized imported-key activation) in
//! `import::e2e_imp_1`, and 16 (the nonce's persistence) also in the storage unit tests.

use crate::{
    eth2::{CHAIN, activation, hex32},
    follower::network_with_follower,
    harness::{NODES, TestNetwork, approvers, peer::FakePeer},
    reconfigure::{admin as mpc_admin, approve, finished, offline},
};
use commonware_codec::Encode as _;
use commonware_cryptography::{Hasher as _, Sha256, Signer as _, ed25519::PrivateKey};
use eth_mpc_signer::{
    admin::{NAMESPACE, SignedCommand},
    engine,
    types::{Approval, Authorized, Command, Reconfiguration, Transaction},
};
use serde_json::{Value, json};
use std::{
    os::unix::fs::PermissionsExt as _,
    time::{SystemTime, UNIX_EPOCH},
};

const VALIDATOR: &str = "validator-admin";

fn identity(node: u64) -> String {
    format!(
        "0x{}",
        hex::encode(PrivateKey::from_seed(node).public_key().encode())
    )
}

fn admin_nonce(network: &TestNetwork, node: usize) -> u64 {
    let (status, admin) = network.get(node, "/admin");
    assert_eq!(status, 200, "{admin}");
    admin["nonce"].as_u64().unwrap()
}

/// Tests 1 to 9, 13 and 16: through the API, an activation is refused without a threshold of
/// valid approvals of exactly that command, for this cluster, with the next nonce; with them it
/// applies once, on every node, and the nonce survives restarts.
#[test]
fn admin_1_protected_operations_need_approvals() {
    let network = TestNetwork::start(NODES);
    network.wait_for_ready(&network.all());
    network.start_validator_dkg(0, VALIDATOR);
    let key = network.wait_for_dkg(VALIDATOR, &network.all());
    let request = json!({ "public_key": key, "genesis_validators_root": CHAIN });

    // Every node: the same cluster and approvers, nothing applied yet.
    let (_, admin) = network.get(0, "/admin");
    assert_eq!(admin["configured"], true, "{admin}");
    assert_eq!(
        (admin["nonce"].as_u64(), admin["threshold"].as_u64()),
        (Some(0), Some(2))
    );
    assert_eq!(admin["approvers"].as_array().unwrap().len(), 3, "{admin}");
    for node in network.all() {
        assert_eq!(
            network.get(node, "/admin").1["cluster_id"],
            admin["cluster_id"]
        );
    }

    let refused = |body: &Value, status: u16, why: &str| {
        let (code, answer) = network.post(1, "/validators/activate", body);
        assert_eq!(code, status, "{answer}");
        assert!(
            answer["error"].as_str().unwrap_or_default().contains(why),
            "expected {why}: {answer}"
        );
    };
    // 2: no approvals.
    refused(&request, 403, "needs the approvers' authorization");
    // 3: one of the two required.
    let one = network.signed("activate", request.clone(), 1, &[0]);
    refused(&one.body().unwrap(), 403, "1 approvals, 2 required");
    // 4: one approver twice.
    let mut twice = one.clone();
    twice.approvals.push(twice.approvals[0].clone());
    refused(&twice.body().unwrap(), 403, "signed twice");
    // 5: a key outside the approver set (its signature is valid).
    let mut stranger = one.clone();
    stranger.sign(&PrivateKey::from_seed(4_242)).unwrap();
    refused(&stranger.body().unwrap(), 403, "is not an approver");
    // 6: an approver's signature of something else.
    let signed = network.signed("activate", request.clone(), 1, &[0, 1]);
    let mut invalid = signed.clone();
    let other = network.signed("activate", request.clone(), 2, &[1]);
    let forged = invalid
        .approvals
        .iter_mut()
        .find(|approval| approval.approver == other.approvals[0].approver)
        .unwrap();
    forged.signature = other.approvals[0].signature.clone();
    refused(&invalid.body().unwrap(), 403, "does not verify");
    // 7: the request changed after signing.
    let mut modified = signed.body().unwrap();
    modified["genesis_validators_root"] = json!(hex32(0x42));
    refused(&modified, 403, "does not verify");
    // 8: approvals of another cluster, by the same approvers.
    let elsewhere_cluster = Sha256::hash(&[b"another network"]);
    let mut elsewhere =
        SignedCommand::draft(&elsewhere_cluster, "activate", 1, request.clone()).unwrap();
    for key in &crate::harness::approver_keys()[..2] {
        elsewhere.sign(key).unwrap();
    }
    refused(&elsewhere.body().unwrap(), 403, "does not verify");
    // None of it reached consensus.
    for node in network.all() {
        assert_eq!(admin_nonce(&network, node), 0);
        assert!(activation(&network, node, &key).is_none());
    }

    // 1: two of the three approvers.
    let (code, activated) = network.post_signed(1, &signed);
    assert_eq!(code, 200, "{activated}");
    for node in network.all() {
        network.wait_until(&format!("the activation on node {node}"), || {
            admin_nonce(&network, node) == 1 && activation(&network, node, &key).is_some()
        });
    }

    // 9: the nonce is used: another command signed with it is refused, and the same command
    // again changes nothing.
    let round = network.get(0, &format!("/dkg/status/{VALIDATOR}")).1["round"]
        .as_u64()
        .unwrap();
    let committee: Vec<String> = (0..NODES as u64).map(identity).collect();
    let reshare = json!({
        "public_key": key,
        "ceremony_id": "approved.validator-admin-reshare",
        "from_round": round,
        "dealers": committee,
        "players": committee,
    });
    let (code, answer) =
        network.post_signed(0, &network.signed("reshare", reshare.clone(), 1, &[0, 2]));
    assert_eq!(code, 409, "{answer}");
    assert!(
        answer["error"].as_str().unwrap().contains("is used"),
        "{answer}"
    );
    assert_eq!(network.post_signed(2, &signed).0, 200);
    assert_eq!(admin_nonce(&network, 2), 1);

    // 13: a reshare to new keyholders needs approvals; a refresh within the committee takes none.
    let (code, answer) = network.post(0, "/validators/reshare", &reshare);
    assert_eq!(code, 403, "{answer}");
    let mut refresh = json!({ "public_key": key, "ceremony_id": "validator-admin-refresh" });
    refresh["authorization"] = signed.body().unwrap()["authorization"].clone();
    let (code, answer) = network.post(0, "/validators/reshare", &refresh);
    assert_eq!(code, 400, "{answer}");

    // 16: restarted, a node keeps the nonce. Started with another approver set, it refuses to
    // start; with the network's, it starts.
    network.restart_node(2);
    network.wait_for_ready(&[2]);
    assert_eq!(admin_nonce(&network, 2), 1);
    let other = network.dir.join("other-approvers.json");
    let keys: Vec<String> = (2_000..2_003).map(identity).collect();
    std::fs::write(
        &other,
        json!({ "threshold": 2, "approvers": keys }).to_string(),
    )
    .unwrap();
    network.restart_node_with_args(3, &["--approvers", other.to_str().unwrap()]);
    let exit = network.wait_exit(3);
    assert_eq!(exit.code(), Some(1), "{exit}");
    assert!(network.log(3).contains("under approver set"), "node 3 log");
    network.restart_node_with_args(3, &[]);
    network.wait_for_ready(&[3]);
    assert_eq!(admin_nonce(&network, 3), 1);

    // An approver's key, from the tool: owner-only, printed public key, never overwritten.
    let key_file = network.dir.join("new-approver.key");
    let key_path = key_file.to_str().unwrap();
    let (success, printed) = offline(&["approver-key", "--output", key_path]);
    assert!(success, "{printed}");
    let mode = std::fs::metadata(&key_file).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
    let (success, public) = offline(&["approver-public-key", "--key", key_path]);
    assert!(success, "{public}");
    assert_eq!(public.trim(), printed.trim());
    assert!(!offline(&["approver-key", "--output", key_path]).0);

    // The next command takes the next nonce: drafted from the network, signed offline by two
    // approvers, submitted with `mpc-admin`.
    let draft = network.dir.join("reshare.json");
    let (success, output) = finished(mpc_admin(
        &network,
        &[
            "draft",
            "reshare",
            "--request",
            &reshare.to_string(),
            "--output",
            draft.to_str().unwrap(),
        ],
    ));
    assert!(success, "{output}");
    assert!(output.contains("nonce:       2"), "{output}");
    let signed = approve(&network, &draft);
    let (success, output) = finished(mpc_admin(
        &network,
        &[
            "submit",
            "--command",
            signed[0].to_str().unwrap(),
            "--command",
            signed[1].to_str().unwrap(),
        ],
    ));
    assert!(success, "{output}");
    for node in network.all() {
        network.wait_until(&format!("nonce 2 on node {node}"), || {
            admin_nonce(&network, node) == 2
        });
    }
}

/// `commands`, one hex-encoded transaction per line, for the injection hook.
pub(crate) fn injection(commands: Vec<Command>) -> String {
    commands
        .into_iter()
        .enumerate()
        .map(|(index, command)| {
            hex::encode(
                Transaction {
                    id: 9_000 + index as u64,
                    command,
                }
                .encode(),
            ) + "\n"
        })
        .collect()
}

/// Test 11 and the guard: a faulty leader (B, with a test hook) puts a reconfiguration of D by E
/// into every block it proposes: without approvals, with forged ones, with a used nonce, with a
/// nonce ahead; then an EIP-3076 import the same four ways (P0.1). The honest voters refuse every
/// such block: it is never notarized, so it cannot end the epoch or change a history, nobody
/// stops, and consensus goes on. B's own API refuses it too.
#[test]
fn admin_2_a_faulty_leader_cannot_bring_in_protected_commands() {
    let inject = std::env::temp_dir().join(format!(
        "eth-mpc-signer-inject-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let path = inject.display().to_string();
    let network = network_with_follower(
        move |node| {
            if node == 1 {
                vec![("ETH_MPC_SIGNER_INJECT_FILE".into(), path.clone())]
            } else {
                Vec::new()
            }
        },
        true,
    );
    network.wait_for_ready(&network.all());
    let honest = [0, 2, 3];
    let request = json!({ "epoch": 1, "remove": identity(3), "add": identity(4) });
    let bare = || {
        Command::Reconfigure(Box::new(Reconfiguration {
            epoch: 1,
            remove: PrivateKey::from_seed(3).public_key(),
            add: PrivateKey::from_seed(4).public_key(),
        }))
    };
    let approved = |nonce| {
        Command::Admin(Box::new(
            network
                .signed("reconfigure", request.clone(), nonce, &[0, 1])
                .authorized(&approvers())
                .unwrap(),
        ))
    };
    // Approvals by strangers under the approvers' indices.
    let forged = {
        let message = network
            .signed("reconfigure", request.clone(), 1, &[])
            .message()
            .unwrap();
        Command::Admin(Box::new(Authorized {
            nonce: 1,
            command: bare(),
            approvals: (0..2)
                .map(|approver| Approval {
                    approver,
                    signature: PrivateKey::from_seed(5_000 + u64::from(approver))
                        .sign(NAMESPACE, &message),
                })
                .collect(),
        }))
    };
    // P0.1 tests 13 to 17: an EIP-3076 import of a (made-up) key's history of slot 1 (long
    // started: the horizon passes it), bare, with forged approvals, with a used or a skipped
    // nonce.
    let history = json!({"interchange": crate::import::interchange(
        &format!("0x{}", "ab".repeat(48)),
        crate::eth2::CHAIN,
        json!([{"slot": "1"}]),
        json!([]),
    )});
    let import = |nonce| {
        network
            .signed("import-history", history.clone(), nonce, &[0, 1])
            .authorized(&approvers())
            .unwrap()
    };
    let bare_import = import(1).command;
    let forged_import = {
        let mut forged = import(1);
        for approval in &mut forged.approvals {
            approval.signature = PrivateKey::from_seed(6_000).sign(NAMESPACE, b"another message");
        }
        Command::Admin(Box::new(forged))
    };
    let cases = [
        (bare(), "a protected command without approvals"),
        (forged, "signature does not verify"),
        (approved(0), "out of nonce order"),
        (approved(2), "out of nonce order"),
        (bare_import, "a protected command without approvals"),
        (forged_import, "signature does not verify"),
        (Command::Admin(Box::new(import(0))), "out of nonce order"),
        (Command::Admin(Box::new(import(2))), "out of nonce order"),
    ];
    for (command, why) in cases {
        let seen: Vec<usize> = honest
            .iter()
            .map(|node| network.count(*node, why))
            .collect();
        std::fs::write(&inject, injection(vec![command])).unwrap();
        network.wait_until(
            &format!("an honest voter to refuse B's block: {why}"),
            || {
                honest
                    .iter()
                    .zip(&seen)
                    .any(|(node, seen)| network.count(*node, why) > *seen)
            },
        );
    }
    std::fs::write(&inject, "").unwrap();

    // Nothing ended the epoch: everyone runs epoch 0, saw no last block, and goes on.
    let height = honest
        .iter()
        .filter_map(|node| network.height(*node))
        .max()
        .unwrap();
    network.wait_until("consensus to go on", || {
        network.all().iter().all(|node| {
            network
                .height(*node)
                .is_some_and(|applied| applied > height + 2)
        })
    });
    for node in network.all() {
        let (_, consensus) = network.get(node, "/consensus");
        assert_eq!(consensus["epoch"]["epoch"], 0, "{consensus}");
        assert!(consensus.get("ended_at").is_none(), "{consensus}");
        assert_eq!(admin_nonce(&network, node), 0);
        assert!(
            !network.log(node).contains("the consensus epoch ended"),
            "node {node}"
        );
    }

    // B's API refuses the reconfiguration without approvals, like any node's.
    let (code, answer) = network.post(1, "/consensus/reconfigure", &request);
    assert_eq!(code, 403, "{answer}");

    // Gossiped by a peer, a bare one is dropped by an honest leader.
    network.stop_node(3);
    let peer = FakePeer::start(&network, 3, &[], Box::new(|_, _, _| Vec::new()));
    let bare_transaction = Transaction {
        id: 9_100,
        command: bare(),
    }
    .encode()
    .to_vec();
    network.wait_until("an honest leader to drop the bare reconfiguration", || {
        for node in [0, 2] {
            peer.send_on(engine::MEMPOOL_CHANNEL, node, bare_transaction.clone());
        }
        [0, 2].iter().any(|node| {
            network.log(*node).lines().any(|line| {
                line.contains("dropping a transaction")
                    && line.contains("a protected command without approvals")
            })
        })
    });
    drop(peer);
    let _ = std::fs::remove_file(&inject);
}
