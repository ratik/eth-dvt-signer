//! P0.2: a voluntary exit or a deposit is signed only with the approvers' authorization over
//! exactly it (docs/administration.md), on real processes. Every test node runs with the
//! approvers of `harness::approver_keys` (2 of 3) and `--enable-deposit-signing`.
//!
//! Elsewhere: the approvals' binding to every field (tests 5 to 10) at the level of the approvals
//! in `tests/unit/admin.rs`; a bare exit or deposit from history, recorded but never handed to a
//! keyholder until approved, and the approvals across restarts (tests 12, 21) in
//! `tests/unit/storage.rs`; R1, R2 and R3 (test 25) and slashing protection (26) by their own
//! suites.

use crate::{
    admin::injection,
    eth2::{CHAIN, activation, attestation, block, fixture, hex32, pinned, signed, signing_root},
    failures::ask,
    harness::{NODES, TestNetwork, approver_keys, approvers, ethereum_verify, peer::FakePeer},
    reconfigure::{admin as mpc_admin, approve, finished},
};
use commonware_cryptography::{Hasher as _, Sha256, Signer as _, ed25519::PrivateKey};
use eth_mpc_signer::{
    admin::{NAMESPACE, SignedCommand, command},
    dkg::CeremonyId,
    eth::types::Root,
    signer::wire::{Message, Refusal, Request},
    types::Command,
};
use serde_json::{Value, json};
use std::time::{SystemTime, UNIX_EPOCH};

const VALIDATOR: &str = "validator-exit";

/// A `sign-exit` request of `key` (the test chain, the fork of the exit's epoch).
fn exit(key: &str, epoch: u64, index: u64) -> Value {
    let mut request = fixture("voluntary_exit.json");
    request["voluntary_exit"] =
        json!({ "epoch": epoch.to_string(), "validator_index": index.to_string() });
    let mut request = pinned(request);
    let object = request.as_object_mut().unwrap();
    object.remove("signingRoot");
    object.insert("public_key".into(), json!(key));
    request
}

/// A `sign-deposit` request of `key`'s own deposit, with withdrawal credentials `credentials`.
fn deposit(key: &str, credentials: u8) -> Value {
    json!({
        "public_key": key,
        "type": "DEPOSIT",
        "deposit": {
            "pubkey": key,
            "withdrawal_credentials": hex32(credentials),
            "amount": "32000000000",
            "genesis_fork_version": "0x00000000",
        },
    })
}

/// The Web3Signer request of a `sign-exit` or `sign-deposit` request, without approvals.
fn web3signer(request: &Value) -> Value {
    let mut body = request.clone();
    body.as_object_mut().unwrap().remove("public_key");
    body
}

/// `body` carrying `from`'s authorization.
fn with(body: &Value, from: &SignedCommand) -> Value {
    let mut body = body.clone();
    body["authorization"] = from.body().unwrap()["authorization"].clone();
    body
}

fn admin_nonce(network: &TestNetwork, node: usize) -> u64 {
    network.get(node, "/admin").1["nonce"].as_u64().unwrap()
}

/// Tests 1 to 24 end to end. A faulty leader (B, with a test hook) puts an exit and a deposit
/// without approvals, and an exit with forged ones, into every block it proposes: honest voters
/// refuse each, and ordinary duties go on. Through the API, every malformed authorization is
/// refused; a coordinator asking keyholders directly gets no partial of either root. Approved,
/// both are signed once (the deposit through `mpc-admin`, its deposit data written, not sent),
/// and signed again without approvals, through any node and after a restart.
#[test]
fn p02_1_exits_and_deposits_need_approvals() {
    let inject = std::env::temp_dir().join(format!(
        "eth-mpc-signer-inject-exit-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let path = inject.display().to_string();
    let network = TestNetwork::start_with_args(
        NODES,
        vec!["--enable-deposit-signing".into()],
        move |node| {
            if node == 1 {
                vec![("ETH_MPC_SIGNER_INJECT_FILE".into(), path.clone())]
            } else {
                Vec::new()
            }
        },
    );
    network.wait_for_ready(&network.all());
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
    let honest = [0, 2, 3];
    let exit_request = exit(&key, 300, 12);
    let deposit_request = deposit(&key, 1);
    let exit_root: Root = signing_root(&web3signer(&exit_request));
    let deposit_root: Root = signing_root(&web3signer(&deposit_request));

    // 13 to 16: B's blocks carry an exit and a deposit without approvals, then an exit whose
    // approvals are by strangers under the approvers' indices. Honest voters refuse each block.
    let duty = |operation, request: &Value| command(operation, request).unwrap();
    let forged = {
        let mut authorized = network
            .signed("sign-exit", exit_request.clone(), 2, &[0, 1])
            .authorized(&approvers())
            .unwrap();
        for approval in &mut authorized.approvals {
            approval.signature = PrivateKey::from_seed(7_000).sign(NAMESPACE, b"another message");
        }
        Command::Admin(Box::new(authorized))
    };
    let cases = [
        (
            duty("sign-exit", &exit_request),
            "a protected command without approvals",
        ),
        (
            duty("sign-deposit", &deposit_request),
            "a protected command without approvals",
        ),
        (forged, "signature does not verify"),
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
    let _ = std::fs::remove_file(&inject);

    // 17, 22, 23: consensus goes on, ordinary duties sign without approvals; nothing used a nonce.
    signed(&network, 0, &key, &attestation(1, 2, 1));
    signed(&network, 2, &key, &block(5, 1));
    for node in network.all() {
        assert_eq!(admin_nonce(&network, node), 1, "node {node}");
    }

    // 3 to 11 through the API.
    let refuse = |via: usize, body: &Value, status: u16, why: &str| {
        let (code, answer) = network.eth2_sign(via, &key, body);
        assert_eq!(code, status, "{answer}");
        assert!(
            answer["error"].as_str().unwrap_or_default().contains(why),
            "expected {why}: {answer}"
        );
        assert!(answer.get("signature").is_none(), "{answer}");
    };
    let next = 2;
    let approved_exit = network.signed("sign-exit", exit_request.clone(), next, &[0, 1]);
    // 3, 4: no approvals.
    refuse(
        0,
        &web3signer(&exit_request),
        403,
        "needs the approvers' authorization",
    );
    refuse(
        2,
        &web3signer(&deposit_request),
        403,
        "needs the approvers' authorization",
    );
    // 5: an approver's signature of another exit in place of its own.
    let other = network.signed("sign-exit", exit(&key, 301, 12), next, &[1]);
    let mut forged = approved_exit.clone();
    forged
        .approvals
        .iter_mut()
        .find(|approval| approval.approver == other.approvals[0].approver)
        .unwrap()
        .signature = other.approvals[0].signature.clone();
    refuse(3, &forged.body().unwrap(), 403, "does not verify");
    // 6: one approval of the two required.
    refuse(
        0,
        &network
            .signed("sign-exit", exit_request.clone(), next, &[0])
            .body()
            .unwrap(),
        403,
        "1 approvals, 2 required",
    );
    // 7, 8, 9: approvals of another validator's exit, of another exit epoch (another signing
    // root), of the deposit (another duty type).
    let other_key = format!("0x{}", "ab".repeat(48));
    for (operation, request) in [
        ("sign-exit", exit(&other_key, 300, 12)),
        ("sign-exit", exit(&key, 301, 12)),
        ("sign-deposit", deposit_request.clone()),
    ] {
        let approvals = network.signed(operation, request, next, &[0, 1]);
        refuse(
            2,
            &with(&web3signer(&exit_request), &approvals),
            403,
            "does not verify",
        );
    }
    // 10: approvals of the exit on another chain, and of another cluster by the same approvers.
    let mut other_chain = exit_request.clone();
    other_chain["fork_info"]["genesis_validators_root"] = json!(hex32(0x42));
    let approvals = network.signed("sign-exit", other_chain, next, &[0, 1]);
    refuse(
        0,
        &with(&web3signer(&exit_request), &approvals),
        403,
        "does not verify",
    );
    let mut elsewhere = SignedCommand::draft(
        &Sha256::hash(&[b"another network"]),
        "sign-exit",
        next,
        exit_request.clone(),
    )
    .unwrap();
    for approver in &approver_keys()[..2] {
        elsewhere.sign(approver).unwrap();
    }
    refuse(0, &elsewhere.body().unwrap(), 403, "does not verify");
    // 11: a used nonce.
    refuse(
        3,
        &network
            .signed("sign-exit", exit_request.clone(), 1, &[0, 1])
            .body()
            .unwrap(),
        409,
        "is used",
    );
    for node in network.all() {
        assert_eq!(admin_nonce(&network, node), 1, "node {node}");
    }

    // 18 to 20: a coordinator (D's identity) asks every keyholder for a partial of either root
    // directly: refused, nothing is authorized.
    network.stop_node(3);
    let peer = FakePeer::start(&network, 3, &[], Box::new(|_, _, _| Vec::new()));
    let ceremony = CeremonyId::new(VALIDATOR).unwrap();
    let validator: [u8; 48] = hex::decode(key.trim_start_matches("0x"))
        .unwrap()
        .try_into()
        .unwrap();
    for root in [exit_root, deposit_root] {
        for node in [0, 1, 2] {
            let answer = ask(
                &network,
                &peer,
                node,
                &Request::duty(ceremony.clone(), validator, root),
            );
            assert!(
                matches!(
                    answer,
                    Message::Refused {
                        reason: Refusal::NotAuthorized,
                        ..
                    }
                ),
                "node {node}: {answer:?}"
            );
        }
    }
    drop(peer);
    network.restart_node(3);
    network.wait_for_ready(&[3]);

    // 1: the approved exit is signed once (nonce 2), and the signature verifies.
    let (code, answer) = network.eth2_sign(2, &key, &approved_exit.body().unwrap());
    assert_eq!(code, 200, "{answer}");
    assert!(ethereum_verify(
        &json!(key),
        &exit_root,
        &answer["signature"]
    ));
    let exit_signature = answer["signature"].clone();
    for node in network.all() {
        network.wait_until(&format!("nonce 2 on node {node}"), || {
            admin_nonce(&network, node) == 2
        });
    }

    // 2: the deposit, drafted with `mpc-admin`, signed offline by two approvers, submitted: the
    // deposit data is written, not sent anywhere.
    let draft = network.dir.join("deposit.json");
    let (success, output) = finished(mpc_admin(
        &network,
        &[
            "draft",
            "sign-deposit",
            "--validator",
            &key,
            "--withdrawal-credentials",
            &hex32(1),
            "--amount",
            "32000000000",
            "--output",
            draft.to_str().unwrap(),
        ],
    ));
    assert!(success, "{output}");
    assert!(output.contains("nonce:       3"), "{output}");
    assert!(
        output.contains(&format!("WITHDRAWAL CREDENTIALS: {}", hex32(1))),
        "{output}"
    );
    let signed_copies = approve(&network, &draft);
    let data = network.dir.join("deposit-data.json");
    let (success, output) = finished(mpc_admin(
        &network,
        &[
            "submit",
            "--command",
            signed_copies[0].to_str().unwrap(),
            "--command",
            signed_copies[1].to_str().unwrap(),
            "--output",
            data.to_str().unwrap(),
        ],
    ));
    assert!(success, "{output}");
    let data: Value = serde_json::from_str(&std::fs::read_to_string(&data).unwrap()).unwrap();
    assert_eq!(data["withdrawal_credentials"], hex32(1), "{data}");
    assert_eq!(data["amount"], 32_000_000_000u64, "{data}");
    assert!(ethereum_verify(
        &json!(key),
        &deposit_root,
        &data["signature"]
    ));

    // 12, 21: signed again without approvals, through any node, and after a restart: the same
    // signatures, no nonce used. The same signed exit again is a retry too.
    let (code, answer) = network.eth2_sign(3, &key, &web3signer(&exit_request));
    assert_eq!((code, &answer["signature"]), (200, &exit_signature));
    let (code, answer) = network.eth2_sign(1, &key, &approved_exit.body().unwrap());
    assert_eq!((code, &answer["signature"]), (200, &exit_signature));
    network.restart_node(0);
    network.wait_for_ready(&[0]);
    let (code, answer) = network.eth2_sign(0, &key, &web3signer(&exit_request));
    assert_eq!((code, &answer["signature"]), (200, &exit_signature));
    let (code, answer) = network.eth2_sign(0, &key, &web3signer(&deposit_request));
    assert_eq!((code, &answer["signature"]), (200, &data["signature"]));
    for node in network.all() {
        network.wait_until(&format!("nonce 3 on node {node}"), || {
            admin_nonce(&network, node) == 3
        });
    }

    // 26: approvals never lift slashing protection: a second deposit message is refused.
    let second = network.signed("sign-deposit", deposit(&key, 2), 4, &[0, 1]);
    let (code, answer) = network.eth2_sign(2, &key, &second.body().unwrap());
    assert_eq!(code, 412, "{answer}");
    assert_eq!(answer["refusal"]["reason"], "too_many_roots", "{answer}");

    // 24: ordinary duties still sign without approvals.
    signed(
        &network,
        1,
        &key,
        &crate::eth2::with_root(fixture("randao_reveal.json")),
    );
}
