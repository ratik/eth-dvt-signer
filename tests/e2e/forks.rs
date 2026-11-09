//! P0.3: a duty is signed only under the fork schedule pinned for the node's network
//! (`eth::network`, docs/ethereum-signing.md), on real processes. The test chain runs mainnet's
//! schedule (`harness`), so Lighthouse's own requests pass (E2E-ETH-1).
//!
//! Elsewhere: every rule against mainnet's and Hoodi's schedules, the boundaries and custom
//! schedules in `tests/unit/eth/network.rs`; an R3 transition (test 17) in `reconfigure::r3_1`,
//! whose restarted nodes start against the network identity recorded with the reconfiguration.

use crate::{
    admin::injection,
    eth2::{CHAIN, activation, block, fixture, hex32, sign, signed, signing_root, with_root},
    failures::ask,
    harness::{NODES, TestNetwork, fork_schedule, peer::FakePeer},
};
use eth_mpc_signer::{
    dkg::CeremonyId,
    eth::duty::format_root,
    signer::wire::{Message, Refusal, Request},
    types::Command,
};
use serde_json::{Value, json};
use std::time::{SystemTime, UNIX_EPOCH};

const VALIDATOR: &str = "validator-forks";

/// Fulu's first slot on the test chain (mainnet's schedule).
const FULU: u64 = 411_392 * 32;

/// `body` naming the fork `(previous, current, epoch)`, with the signing root a client would
/// compute under it (no fork is pinned).
fn with_fork(body: &Value, previous: &str, current: &str, epoch: u64) -> Value {
    let mut body = body.clone();
    body["fork_info"]["fork"] = json!({
        "previous_version": previous,
        "current_version": current,
        "epoch": epoch.to_string(),
    });
    body["signingRoot"] = json!(format_root(&signing_root(&body)));
    body
}

/// `body` refused through `via` with HTTP `status` and the fork reason `reason`.
fn refused(network: &TestNetwork, via: usize, key: &str, body: &Value, status: u16, reason: &str) {
    let (code, answer) = sign(network, via, key, body);
    assert_eq!(code, status, "{answer}");
    assert_eq!(answer["fork"]["reason"], reason, "{answer}");
    assert!(answer.get("signature").is_none(), "{answer}");
}

/// Tests 1, 3 to 16 and 18 end to end. Requests with another chain, version, fork epoch, network
/// or an unknown fork are refused by the API; a faulty leader (B, with a test hook) proposing a
/// block whose duty names the previous fork at Fulu's first slots is refused by honest voters; a
/// coordinator asking keyholders for an authorized duty's root under another fork gets nothing.
/// Around Fulu's first slot, the right fork signs. A node restarted with the same network signs
/// on; started for another network, it refuses to start.
#[test]
fn p03_1_fork_info_follows_the_pinned_schedule() {
    let inject = std::env::temp_dir().join(format!(
        "eth-mpc-signer-inject-fork-{}-{}",
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
    // Every node reports the same network and schedule.
    let (_, reported) = network.get(0, "/eth/network");
    assert_eq!(reported["forks"].as_array().unwrap().len(), 7, "{reported}");
    for node in network.all() {
        let (status, other) = network.get(node, "/eth/network");
        assert_eq!(status, 200, "{other}");
        assert_eq!(other["identity"], reported["identity"]);
        assert_eq!(other["schedule_digest"], reported["schedule_digest"]);
    }
    assert_eq!(
        network.get(0, "/admin").1["network"],
        reported["identity"],
        "approvals are bound to the network"
    );

    // 1, 7 to 9: the fork a validator client names, just before Fulu, at its first slot, after.
    for (index, slot) in [FULU - 1, FULU, FULU + 33].into_iter().enumerate() {
        signed(&network, index, &key, &block(slot, 1));
    }
    // The beacon state's form, which Lighthouse sends after a blob-parameter-only fork (and from
    // genesis on a network that started at a later fork): Fulu's version twice.
    signed(
        &network,
        3,
        &key,
        &with_fork(&block(FULU + 34, 1), "0x06000000", "0x06000000", 419_072),
    );

    // 3 to 6, 10, and the deposit's and the exit's own domains, through the API.
    let electra = ("0x04000000", "0x05000000", 364_032);
    let fulu = ("0x05000000", "0x06000000", 411_392);
    let target = block(FULU + 64, 2);
    let mut other_chain = target.clone();
    other_chain["fork_info"]["genesis_validators_root"] = json!(hex32(0x42));
    let other_chain = with_root(other_chain);
    let (code, answer) = sign(&network, 2, &key, &other_chain);
    assert_eq!(code, 412, "{answer}");
    assert_eq!(answer["refusal"]["reason"], "other_chain", "{answer}");
    let cases = [
        // 4: Electra's fork at a Fulu slot.
        (
            with_fork(&target, electra.0, electra.1, electra.2),
            "wrong_version",
        ),
        // 5: Fulu's versions at another epoch.
        (with_fork(&target, fulu.0, fulu.1, 411_391), "not_a_fork"),
        // 6: Hoodi's Fulu.
        (
            with_fork(&target, "0x60000910", "0x70000910", 50_688),
            "unknown_version",
        ),
        // 10: a fork after Fulu (Gloas's version), not in the schedule.
        (
            with_fork(&target, "0x06000000", "0x07000000", 500_000),
            "unknown_version",
        ),
    ];
    for (body, reason) in &cases {
        refused(&network, 3, &key, body, 400, reason);
    }
    // A deposit under Hoodi's genesis fork version; an exit after Deneb under Fulu's fork
    // instead of Capella's version (EIP-7044).
    let deposit = with_root(json!({
        "type": "DEPOSIT",
        "deposit": {
            "pubkey": key,
            "withdrawal_credentials": hex32(1),
            "amount": "32000000000",
            "genesis_fork_version": "0x10000910",
        },
    }));
    refused(&network, 0, &key, &deposit, 400, "deposit");
    let mut exit = fixture("voluntary_exit.json");
    exit["voluntary_exit"] = json!({ "epoch": "411402", "validator_index": "7" });
    let exit = with_fork(&exit, fulu.0, fulu.1, fulu.2);
    refused(&network, 1, &key, &exit, 400, "exit");

    // 12, 13, 17: B proposes the duty of Fulu's slot FULU + 96 under Electra's fork. Honest
    // voters refuse its blocks; consensus goes on.
    let wrong = with_fork(&block(FULU + 96, 3), electra.0, electra.1, electra.2);
    let request =
        eth_mpc_signer::eth::web3signer::parse_request(wrong.to_string().as_bytes()).unwrap();
    let command = Command::Duty(Box::new(eth_mpc_signer::eth::duty::DutyRequest {
        validator: hex::decode(key.trim_start_matches("0x"))
            .unwrap()
            .try_into()
            .unwrap(),
        fork: request.fork,
        duty: request.duty,
    }));
    let why = "refusing a block with a duty of another fork schedule";
    let honest = [0, 2, 3];
    let seen: Vec<usize> = honest
        .iter()
        .map(|node| network.count(*node, why))
        .collect();
    std::fs::write(&inject, injection(vec![command])).unwrap();
    network.wait_until("an honest voter to refuse B's block", || {
        honest
            .iter()
            .zip(&seen)
            .any(|(node, seen)| network.count(*node, why) > *seen)
    });
    std::fs::write(&inject, "").unwrap();
    let _ = std::fs::remove_file(&inject);
    // Nothing of it, or of the API's refusals, was authorized: the right fork signs those slots
    // (another root at the slot would be a double proposal).
    signed(&network, 0, &key, &block(FULU + 96, 3));
    signed(&network, 2, &key, &target);

    // 14: a coordinator (D's identity) asks for the root of an authorized proposal computed under
    // the previous fork: every keyholder refuses; under the right fork, it gets a partial.
    network.stop_node(3);
    let peer = FakePeer::start(&network, 3, &[], Box::new(|_, _, _| Vec::new()));
    let ceremony = CeremonyId::new(VALIDATOR).unwrap();
    let validator: [u8; 48] = hex::decode(key.trim_start_matches("0x"))
        .unwrap()
        .try_into()
        .unwrap();
    let authorized = block(FULU, 1);
    let under_electra = signing_root(&with_fork(&authorized, electra.0, electra.1, electra.2));
    assert_ne!(under_electra, signing_root(&authorized));
    for node in [0, 1, 2] {
        let answer = ask(
            &network,
            &peer,
            node,
            &Request::duty(ceremony.clone(), validator, under_electra),
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
    let answer = ask(
        &network,
        &peer,
        0,
        &Request::duty(ceremony, validator, signing_root(&authorized)),
    );
    assert!(matches!(answer, Message::Partial { .. }), "{answer:?}");
    drop(peer);

    // 16: started for another network (another genesis time), D refuses to start: the state
    // applied the activation's approvals for this one.
    let schedule = fork_schedule();
    network.restart_node_with_args(
        3,
        &[
            "--eth-genesis-time",
            "1",
            "--eth-seconds-per-slot",
            "1",
            "--eth-genesis-validators-root",
            CHAIN,
            "--eth-fork-schedule",
            &schedule,
        ],
    );
    let exit = network.wait_exit(3);
    assert_eq!(exit.code(), Some(1), "{exit}");
    assert!(
        network.log(3).contains("for Ethereum network"),
        "node 3 log"
    );
    // 15: restarted with the network's configuration, it signs again.
    network.restart_node_with_args(3, &[]);
    network.wait_for_ready(&[3]);
    network.restart_node(2);
    network.wait_for_ready(&[2]);
    signed(&network, 3, &key, &block(FULU + 128, 1));
    signed(
        &network,
        2,
        &key,
        &crate::eth2::attestation(411_500, 411_501, 1),
    );
}
