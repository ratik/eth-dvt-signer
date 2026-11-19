//! Builder registrations (`VALIDATOR_REGISTRATION`, `eth::registration`) on real processes: signed
//! only under the policy the approvers set, its timestamp window and the per-block limit, by the
//! API, a faulty leader's blocks and a faulty coordinator alike; a burst of them does not delay
//! other duties.
//!
//! Elsewhere: the policy's rules and its encoding in `tests/unit/eth/registration.rs`; the
//! signing root against Web3Signer's example there too; the policy in block order, retries after a
//! change, the absence of a per-epoch limit and restarts in `tests/unit/storage.rs`; the
//! mempool's priority and bounds and a voter's order of policies in
//! `tests/unit/application.rs`; the approvals' binding in `tests/unit/admin.rs`.

use crate::{
    admin::injection,
    eth2::{CHAIN, activation, attestation, block, signed, test_network},
    failures::ask,
    harness::{NODES, TestNetwork, ethereum_verify, peer::FakePeer},
};
use eth_dvt_signer::{
    dkg::CeremonyId,
    eth::{
        duty::{Duty, DutyRequest, format_root},
        types::Root,
        web3signer::parse_request,
    },
    signer::wire::{Message, Refusal, Request},
    types::Command,
};
use serde_json::{Value, json};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const VALIDATOR: &str = "validator-registration";

pub(crate) const A: &str = "0x1111111111111111111111111111111111111111";
pub(crate) const B: &str = "0x2222222222222222222222222222222222222222";

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn validator(key: &str) -> [u8; 48] {
    hex::decode(key.trim_start_matches("0x"))
        .unwrap()
        .try_into()
        .unwrap()
}

/// The duty of a registration request, with the test chain's fork (what the API puts in).
fn duty(body: &Value) -> DutyRequest {
    let request = parse_request(body.to_string().as_bytes()).unwrap();
    let Duty::ValidatorRegistration(registration) = &request.duty else {
        panic!("a registration");
    };
    DutyRequest {
        validator: registration.pubkey,
        fork: test_network().fork_info(&request.duty),
        duty: request.duty.clone(),
    }
}

/// A `VALIDATOR_REGISTRATION` request as Lighthouse sends it (no `fork_info`), with the signing
/// root it computes.
fn registration(key: &str, fee_recipient: &str, gas_limit: u64, timestamp: u64) -> Value {
    let mut body = json!({
        "type": "VALIDATOR_REGISTRATION",
        "validator_registration": {
            "fee_recipient": fee_recipient,
            "gas_limit": gas_limit.to_string(),
            "timestamp": timestamp.to_string(),
            "pubkey": key,
        },
    });
    body["signingRoot"] = json!(format_root(&duty(&body).signing_root()));
    body
}

fn root(body: &Value) -> Root {
    duty(body).signing_root()
}

/// Sign a registration through `via` and check the signature against the key and the root.
fn registered(network: &TestNetwork, via: usize, key: &str, body: &Value) -> Value {
    let (status, answer) = network.eth2_sign(via, key, body);
    assert_eq!(status, 200, "node {via}: {answer} for {body}");
    assert!(
        ethereum_verify(&json!(key), &root(body), &answer["signature"]),
        "{answer}"
    );
    answer["signature"].clone()
}

/// A registration refused through `via` with `status` and, for a policy refusal, `reason`.
fn refused(network: &TestNetwork, via: usize, key: &str, body: &Value, status: u16, reason: &str) {
    let (code, answer) = network.eth2_sign(via, key, body);
    assert_eq!(code, status, "node {via}: {answer} for {body}");
    if status == 412 {
        assert_eq!(answer["registration"]["reason"], reason, "{answer}");
    }
    assert!(answer.get("signature").is_none(), "{answer}");
}

pub(crate) fn policy(fee_recipients: &[&str]) -> Value {
    json!({
        "fee_recipients": fee_recipients,
        "gas_limit_min": 30_000_000u64,
        "gas_limit_max": 60_000_000u64,
        "max_future_seconds": 30,
        "max_age_seconds": 3600,
    })
}

/// Set `policy` with two approvers' authorization and wait until `nodes` apply it.
pub(crate) fn set_policy(network: &TestNetwork, via: usize, policy: Value, nodes: &[usize]) {
    let (status, answer) = network.approved(via, "set-registration-policy", policy);
    assert_eq!(status, 202, "{answer}");
    let digest = answer["digest"].as_str().unwrap().to_string();
    for &node in nodes {
        network.wait_until(&format!("policy {digest} on node {node}"), || {
            network.get(node, "/eth/registration-policy").1["digest"] == json!(digest)
        });
    }
}

fn start(inject: Option<&std::path::Path>) -> (TestNetwork, String) {
    let path = inject.map(|path| path.display().to_string());
    let network = TestNetwork::start_with_args(NODES, Vec::new(), move |node| match &path {
        Some(path) if node == 1 => vec![("ETH_MPC_SIGNER_INJECT_FILE".into(), path.clone())],
        _ => Vec::new(),
    });
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
    (network, key)
}

/// Each B block's refusal by an honest voter, for `why`.
pub(crate) fn refused_by_voters(
    network: &TestNetwork,
    inject: &std::path::Path,
    commands: Vec<Command>,
    why: &str,
) {
    let honest = [0, 2, 3];
    let seen: Vec<usize> = honest
        .iter()
        .map(|node| network.count(*node, why))
        .collect();
    std::fs::write(inject, injection(commands)).unwrap();
    network.wait_until(
        &format!("an honest voter to refuse B's block: {why}"),
        || {
            honest
                .iter()
                .zip(&seen)
                .any(|(node, seen)| network.count(*node, why) > *seen)
        },
    );
    std::fs::write(inject, "").unwrap();
}

/// No registration without a policy; under an approved one, the allowed fee recipient within the
/// gas limit range and the timestamp window signs, through any node, again on a retry; anything
/// else is refused by the API, by honest voters in a faulty leader's block (also a block with more
/// registrations than the limit), and by keyholders asked directly by a faulty coordinator. Once
/// the policy no longer allows a fee recipient, a retry of its authorized registration is refused
/// too, by the API and by keyholders. The policy survives a restart.
#[test]
fn reg_1_registrations_follow_the_approved_policy() {
    let inject = std::env::temp_dir().join(format!(
        "eth-mpc-signer-inject-registration-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let (network, key) = start(Some(&inject));
    let t = now();

    // No policy: nothing signs.
    let (status, answer) = network.get(0, "/eth/registration-policy");
    assert_eq!(status, 200, "{answer}");
    assert_eq!(answer["policy"], Value::Null, "{answer}");
    refused(
        &network,
        0,
        &key,
        &registration(&key, A, 30_000_000, t),
        412,
        "no_policy",
    );
    // Bare, the policy is a protected command: refused without approvals.
    let (status, answer) = network.post(0, "/eth/registration-policy", &policy(&[A]));
    assert_eq!(status, 403, "{answer}");

    // The policy of A.
    set_policy(&network, 0, policy(&[A]), &network.all());
    let allowed = registration(&key, A, 30_000_000, now());
    let signature = registered(&network, 1, &key, &allowed);
    // A retry through other nodes: the same signature.
    for via in [0, 2, 3] {
        assert_eq!(registered(&network, via, &key, &allowed), signature);
    }
    // At the bounds of the gas limit range and of the window.
    let t = now();
    registered(
        &network,
        2,
        &key,
        &registration(&key, A, 60_000_000, t + 25),
    );
    registered(
        &network,
        3,
        &key,
        &registration(&key, A, 30_000_000, t - 3500),
    );

    // Refused through the API.
    let t = now();
    refused(
        &network,
        0,
        &key,
        &registration(&key, B, 30_000_000, t),
        412,
        "fee_recipient",
    );
    refused(
        &network,
        1,
        &key,
        &registration(&key, A, 29_999_999, t),
        412,
        "gas_limit",
    );
    refused(
        &network,
        2,
        &key,
        &registration(&key, A, 60_000_001, t),
        412,
        "gas_limit",
    );
    refused(
        &network,
        3,
        &key,
        &registration(&key, A, 30_000_000, t + 120),
        412,
        "too_new",
    );
    refused(
        &network,
        0,
        &key,
        &registration(&key, A, 30_000_000, t - 7200),
        412,
        "too_old",
    );
    // Another key in the body than the path's; a `fork_info`.
    let other_key = format!("0x{}", "8f".repeat(48));
    let mut other = registration(&key, A, 30_000_000, t);
    other["validator_registration"]["pubkey"] = json!(other_key);
    refused(&network, 1, &key, &other, 400, "");
    let mut with_fork = registration(&key, A, 30_000_000, t);
    with_fork["fork_info"] = json!({
        "fork": {"previous_version": "0x00000000", "current_version": "0x00000000", "epoch": "0"},
        "genesis_validators_root": CHAIN,
    });
    refused(&network, 2, &key, &with_fork, 400, "");

    // A faulty leader (B) proposes a registration of B, then seventeen of A: honest voters refuse
    // both blocks; consensus goes on.
    let bare = |body: &Value| Command::Duty(Box::new(duty(body)));
    let t = now();
    refused_by_voters(
        &network,
        &inject,
        vec![bare(&registration(&key, B, 30_000_000, t))],
        "refusing a block with a duty the registration policy in force refuses",
    );
    refused_by_voters(
        &network,
        &inject,
        (0..17)
            .map(|index| bare(&registration(&key, A, 30_000_000, t - index)))
            .collect(),
        "refusing a block with too many builder registrations",
    );
    let _ = std::fs::remove_file(&inject);
    signed(&network, 0, &key, &attestation(1, 2, 1));
    signed(&network, 2, &key, &block(5, 1));

    // A faulty coordinator (D's identity) asks keyholders for a registration nothing authorized,
    // and for the authorized one.
    network.stop_node(3);
    let peer = FakePeer::start(&network, 3, &[], Box::new(|_, _, _| Vec::new()));
    let ceremony = CeremonyId::new(VALIDATOR).unwrap();
    let ask_all = |body: &Value| -> Vec<Message> {
        [0, 1, 2]
            .into_iter()
            .map(|node| {
                ask(
                    &network,
                    &peer,
                    node,
                    &Request::duty(ceremony.clone(), validator(&key), root(body)),
                )
            })
            .collect()
    };
    let not_authorized = |answers: Vec<Message>, what: &str| {
        for answer in answers {
            assert!(
                matches!(
                    answer,
                    Message::Refused {
                        reason: Refusal::NotAuthorized,
                        ..
                    }
                ),
                "{what}: {answer:?}"
            );
        }
    };
    not_authorized(
        ask_all(&registration(&key, B, 30_000_000, now())),
        "an unauthorized registration",
    );
    assert!(
        ask_all(&allowed)
            .iter()
            .all(|answer| matches!(answer, Message::Partial { .. })),
        "the authorized registration"
    );

    // The policy of B: A's authorized registration is refused on a retry, by the API and by the
    // keyholders; B's signs.
    set_policy(&network, 0, policy(&[B]), &[0, 1, 2]);
    not_authorized(ask_all(&allowed), "A's registration once the policy is B's");
    drop(peer);
    network.restart_node(3);
    network.wait_for_ready(&[3]);
    let digest = network.get(0, "/eth/registration-policy").1["digest"].clone();
    network.wait_until("node 3 to apply B's policy", || {
        network.get(3, "/eth/registration-policy").1["digest"] == digest
    });
    refused(&network, 0, &key, &allowed, 412, "fee_recipient");
    let by_b = registration(&key, B, 30_000_000, now());
    registered(&network, 3, &key, &by_b);

    // Restarted, a node applies the same policy.
    network.restart_node(2);
    network.wait_for_ready(&[2]);
    assert_eq!(
        network.get(2, "/eth/registration-policy").1["digest"],
        digest
    );
    registered(&network, 2, &key, &registration(&key, B, 45_000_000, now()));
    refused(&network, 2, &key, &allowed, 412, "fee_recipient");
}

/// A burst of 100 registrations (a validator client restarting with many keys) submitted at once
/// through every node, while blocks are signed one after another: every registration signs (a
/// `503` from a full queue is retried, as validator clients do at the next slot), and the blocks'
/// latency during the burst stays within the authorization timeout. Both latencies are printed.
#[test]
fn reg_2_a_burst_of_registrations_does_not_stop_other_duties() {
    let (network, key) = start(None);
    set_policy(&network, 0, policy(&[A]), &network.all());
    let latency = |slot: u64, via: usize| {
        let started = Instant::now();
        signed(&network, via, &key, &block(slot, 1));
        started.elapsed()
    };
    let baseline: Vec<Duration> = (0..10)
        .map(|index| latency(100 + index, (index % 4) as usize))
        .collect();
    let t = now();
    let (during, outcomes) = std::thread::scope(|scope| {
        let workers: Vec<_> = (0..10u64)
            .map(|worker| {
                let (network, key) = (&network, &key);
                scope.spawn(move || {
                    (0..10u64)
                        .map(|index| {
                            let body = registration(key, A, 30_000_000, t - worker * 10 - index);
                            let via = ((worker + index) % 4) as usize;
                            let deadline = Instant::now() + Duration::from_secs(60);
                            loop {
                                let (status, answer) = network.eth2_sign(via, key, &body);
                                match status {
                                    200 => {
                                        assert!(
                                            ethereum_verify(
                                                &json!(key),
                                                &root(&body),
                                                &answer["signature"]
                                            ),
                                            "{answer}"
                                        );
                                        return 200;
                                    }
                                    503 | 504 if Instant::now() < deadline => {
                                        std::thread::sleep(Duration::from_millis(500));
                                    }
                                    other => return other,
                                }
                            }
                        })
                        .collect::<Vec<u16>>()
                })
            })
            .collect();
        let during: Vec<Duration> = (0..20)
            .map(|index| latency(200 + index, (index % 4) as usize))
            .collect();
        let outcomes: Vec<u16> = workers
            .into_iter()
            .flat_map(|worker| worker.join().unwrap())
            .collect();
        (during, outcomes)
    });
    assert_eq!(outcomes.len(), 100);
    assert!(outcomes.iter().all(|status| *status == 200), "{outcomes:?}");
    let max = |values: &[Duration]| values.iter().max().copied().unwrap_or_default();
    let mean = |values: &[Duration]| values.iter().sum::<Duration>() / values.len() as u32;
    println!(
        "block signing latency: baseline mean {:?} max {:?}; during 100 registrations mean {:?} \
         max {:?}",
        mean(&baseline),
        max(&baseline),
        mean(&during),
        max(&during)
    );
    assert!(max(&during) < Duration::from_secs(5), "{during:?}");
    // Every block applied carried at most the limit of registrations (voters refuse more).
    for node in network.all() {
        assert_eq!(
            network.count(node, "refusing a block with too many builder registrations"),
            0,
            "node {node}"
        );
    }
}
