//! Gloas (EIP-7732, `eth::gloas`) on real processes, on a test chain whose Gloas started at
//! [GLOAS_EPOCH] (1-second slots: every slot here has started): PTC votes, envelopes of
//! self-built payloads, proposer preferences, aggregates in the Gloas form and Gloas blocks, as
//! Lighthouse v8.3 sends them, through the API, a faulty leader's blocks and a faulty
//! coordinator.
//!
//! Elsewhere: the roots against the consensus-specs vectors in `tests/unit/eth/gloas.rs`; the
//! request shapes in `tests/eth_web3signer.rs`; the schedule's gate and the aggregate form in
//! `tests/unit/eth/network.rs`; the slot rules in `tests/unit/eth/horizon.rs`; the rules of the
//! state, in block order and across a restart, in `tests/unit/slashing.rs` and
//! `tests/unit/storage.rs`.

use crate::{
    admin::injection,
    eth2::{CHAIN, activation, hex32},
    failures::ask,
    harness::{NODES, TestNetwork, ethereum_verify, fork_schedule, peer::FakePeer},
    registrations::{A, B, policy, set_policy},
};
use eth_mpc_signer::{
    dkg::CeremonyId,
    eth::{
        duty::{Duty, DutyRequest, format_root},
        network::Network,
        types::Root,
        web3signer::parse_request,
    },
    signer::wire::{Message, Refusal, Request},
    types::Command,
};
use serde_json::{Value, json};
use std::{
    io::{Read as _, Write as _},
    net::TcpStream,
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tree_hash::TreeHash as _;

const VALIDATOR: &str = "validator-gloas";

/// The test chain's Gloas epoch (`--eth-fork-schedule`): long started with 1-second slots, and
/// with long-started epochs before it.
const GLOAS_EPOCH: u64 = 50_000_000;
/// Gloas's first slot.
const GLOAS_SLOT: u64 = GLOAS_EPOCH * 32;
/// Gloas's version on mainnet (`configs/mainnet.yaml`; not scheduled there yet).
const GLOAS_VERSION: &str = "0x07000000";

fn schedule() -> String {
    format!("{},gloas={GLOAS_VERSION}@{GLOAS_EPOCH}", fork_schedule())
}

/// The test chain with Gloas: what the nodes run with.
fn gloas_network() -> Network {
    Network {
        genesis_time: 0,
        seconds_per_slot: 1,
        genesis_validators_root: hex::decode(CHAIN.trim_start_matches("0x"))
            .unwrap()
            .try_into()
            .unwrap(),
        forks: Vec::leak(Network::parse_schedule(&schedule()).unwrap()),
        ..Network::MAINNET
    }
}

fn args() -> Vec<String> {
    [
        "--eth-genesis-time",
        "0",
        "--eth-seconds-per-slot",
        "1",
        "--eth-genesis-validators-root",
        CHAIN,
        "--eth-fork-schedule",
        &schedule(),
    ]
    .map(str::to_string)
    .to_vec()
}

/// The duty of `body` as the nodes sign it (an aggregate in its epoch's form).
fn duty(body: &Value) -> DutyRequest {
    let request = parse_request(body.to_string().as_bytes()).unwrap();
    DutyRequest {
        validator: [0; 48],
        fork: request.fork,
        duty: gloas_network().resolve(request.duty),
    }
}

fn root(body: &Value) -> Root {
    duty(body).signing_root()
}

/// `body` with the `fork_info` Lighthouse names for its duty on the Gloas test chain and the
/// signing root it computes.
fn finished(mut body: Value) -> Value {
    body["fork_info"] = json!({
        "fork": {"previous_version": "0x00000000", "current_version": "0x00000000", "epoch": "0"},
        "genesis_validators_root": CHAIN,
    });
    let request = parse_request(body.to_string().as_bytes()).unwrap();
    body["fork_info"]["fork"] =
        serde_json::to_value(gloas_network().fork_info(&request.duty).fork).unwrap();
    body["signingRoot"] = json!(format_root(&root(&body)));
    body
}

fn fixture(directory: &str, name: &str) -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(directory)
        .join(name);
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

/// A Gloas block proposal (`BLOCK_V2` `GLOAS`, its header) at `slot`; `body` changes its root.
fn gloas_block(slot: u64, body: u8) -> Value {
    let mut request = fixture("web3signer", "block_v2_electra.json");
    request["beacon_block"]["version"] = json!("GLOAS");
    let header = &mut request["beacon_block"]["block_header"];
    header["slot"] = json!(slot.to_string());
    header["body_root"] = json!(hex32(body));
    finished(request)
}

/// The block root of a block proposal request (what its envelope names).
fn block_root(body: &Value) -> String {
    let Duty::BlockProposal(header) = duty(body).duty else {
        panic!("a block");
    };
    format_root(&header.tree_hash_root().0)
}

/// A PTC vote for `slot`; `present` changes it.
fn ptc_vote(slot: u64, present: bool) -> Value {
    finished(json!({
        "type": "PAYLOAD_ATTESTATION_MESSAGE",
        "payload_attestation_message": {
            "version": "GLOAS",
            "data": {
                "beacon_block_root": hex32(4),
                "slot": slot.to_string(),
                "payload_present": present,
                "blob_data_available": true,
            },
        },
    }))
}

/// The envelope of a self-built payload of `slot` for the block with root `block_root`, paying
/// `fee_recipient`, with `transactions` (hex) in its payload.
fn envelope(slot: u64, block_root: &str, fee_recipient: &str, transactions: Vec<String>) -> Value {
    let mut request = fixture("gloas", "web3signer_execution_payload_envelope.json");
    let data = &mut request["execution_payload_envelope"]["data"];
    data["builder_index"] = json!(u64::MAX.to_string());
    data["beacon_block_root"] = json!(block_root);
    data["payload"]["slot_number"] = json!(slot.to_string());
    data["payload"]["fee_recipient"] = json!(fee_recipient);
    data["payload"]["transactions"] = json!(transactions);
    finished(request)
}

/// Proposer preferences for `proposal_slot`; `dependent` changes their root.
fn preferences(proposal_slot: u64, fee_recipient: &str, gas: u64, dependent: u8) -> Value {
    finished(json!({
        "type": "PROPOSER_PREFERENCES",
        "proposer_preferences": {
            "version": "GLOAS",
            "data": {
                "dependent_root": hex32(dependent),
                "proposal_slot": proposal_slot.to_string(),
                "validator_index": "12",
                "fee_recipient": fee_recipient,
                "target_gas_limit": gas.to_string(),
            },
        },
    }))
}

/// An aggregate of `slot`, as Lighthouse sends it (unversioned, Electra's shape).
fn aggregate(slot: u64) -> Value {
    let mut request = fixture("web3signer", "aggregate_and_proof_electra.json");
    request["aggregate_and_proof"]["aggregate"]["data"]["slot"] = json!(slot.to_string());
    finished(request)
}

/// Sign `body` through `via`; the signature verifies under the key for the root the nodes
/// compute.
fn signed(network: &TestNetwork, via: usize, key: &str, body: &Value) -> Value {
    let (status, answer) = network.eth2_sign(via, key, body);
    assert_eq!(status, 200, "node {via}: {answer} for {body}");
    assert!(
        ethereum_verify(&json!(key), &root(body), &answer["signature"]),
        "{answer}"
    );
    answer["signature"].clone()
}

/// `body` refused through `via` with `status`; `field` (`refusal`, `fork`, `registration`) names
/// the reason `reason` when given.
fn refused(
    network: &TestNetwork,
    via: usize,
    key: &str,
    body: &Value,
    status: u16,
    field: &str,
    reason: &str,
) {
    let (code, answer) = network.eth2_sign(via, key, body);
    assert_eq!(code, status, "node {via}: {answer} for {body}");
    if !field.is_empty() {
        assert_eq!(answer[field]["reason"], reason, "{answer}");
    }
    assert!(answer.get("signature").is_none(), "{answer}");
}

fn inject_path(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "eth-mpc-signer-inject-{name}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}

/// Four nodes on the Gloas test chain (node 1 a faulty leader that adds `inject`'s
/// transactions to its blocks), with a validator key activated.
fn start(inject: Option<&Path>) -> (TestNetwork, String) {
    let path = inject.map(|path| path.display().to_string());
    let network = TestNetwork::start_with_args(NODES, args(), move |node| match &path {
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

/// Let the faulty leader put `commands` into its blocks until every node has applied one whose
/// log matches `applied` (an honest voter accepts such a block: only the state refuses it).
fn applied_by_state(network: &TestNetwork, inject: &Path, commands: Vec<Command>, applied: &str) {
    let seen: Vec<usize> = network
        .all()
        .iter()
        .map(|node| network.count(*node, applied))
        .collect();
    std::fs::write(inject, injection(commands)).unwrap();
    network.wait_until(&format!("every node to apply: {applied}"), || {
        network
            .all()
            .iter()
            .zip(&seen)
            .all(|(node, seen)| network.count(*node, applied) > *seen)
    });
    std::fs::write(inject, "").unwrap();
}

fn bare(body: &Value, key: &str) -> Command {
    let mut request = duty(body);
    request.validator = hex::decode(key.trim_start_matches("0x"))
        .unwrap()
        .try_into()
        .unwrap();
    Command::Duty(Box::new(request))
}

/// PTC votes: one per slot (an exact retry signs the same), refused before Gloas; a faulty
/// leader's second vote of a slot is applied as a refusal, never signed.
#[test]
fn gl_1_ptc_votes() {
    let inject = inject_path("gloas-ptc");
    let (network, key) = start(Some(&inject));
    let slot = GLOAS_SLOT + 100;
    let vote = ptc_vote(slot, true);
    let signature = signed(&network, 0, &key, &vote);
    for via in [1, 2, 3] {
        assert_eq!(signed(&network, via, &key, &vote), signature);
    }
    refused(
        &network,
        2,
        &key,
        &ptc_vote(slot, false),
        412,
        "refusal",
        "too_many_roots",
    );
    signed(&network, 3, &key, &ptc_vote(slot + 1, false));
    // Before Gloas: no PTC.
    refused(
        &network,
        1,
        &key,
        &ptc_vote(GLOAS_SLOT - 1, true),
        400,
        "fork",
        "before_gloas",
    );

    // A faulty leader proposes the other vote of a signed slot: voters accept the block (no
    // policy or clock refuses it), the state refuses the vote; it never signs.
    let other = ptc_vote(slot + 1, true);
    applied_by_state(
        &network,
        &inject,
        vec![bare(&other, &key)],
        "TooManyRoots { kind: PayloadAttestation",
    );
    let _ = std::fs::remove_file(&inject);
    refused(&network, 0, &key, &other, 412, "refusal", "too_many_roots");
}

/// Envelopes: only for the validator's own block of the slot, self-built, once per slot, and only
/// under the registration policy's fee recipients, a retry after a policy change included (API
/// and keyholders); a faulty leader's envelope without its block is applied as a refusal.
#[test]
fn gl_2_envelopes() {
    let inject = inject_path("gloas-envelope");
    let (network, key) = start(Some(&inject));
    let slot = GLOAS_SLOT + 200;
    let block = gloas_block(slot, 1);
    let own = block_root(&block);
    let allowed = envelope(slot, &own, A, vec!["0x02f8".into()]);
    // No policy: refused (the API checks the policy before the history).
    refused(
        &network,
        2,
        &key,
        &allowed,
        412,
        "registration",
        "no_policy",
    );
    set_policy(&network, 0, policy(&[A]), &network.all());
    // Before its block: refused.
    refused(
        &network,
        0,
        &key,
        &allowed,
        412,
        "refusal",
        "envelope_without_own_block",
    );
    signed(&network, 1, &key, &block);
    let signature = signed(&network, 3, &key, &allowed);
    assert_eq!(signed(&network, 0, &key, &allowed), signature);
    // Another payload of the slot; another block's root; a builder's payload; B's fee recipient.
    refused(
        &network,
        1,
        &key,
        &envelope(slot, &own, A, vec!["0x03".into()]),
        412,
        "refusal",
        "too_many_roots",
    );
    refused(
        &network,
        2,
        &key,
        &envelope(slot, &hex32(0xee), A, vec![]),
        412,
        "refusal",
        "envelope_without_own_block",
    );
    let mut built = allowed.clone();
    built["execution_payload_envelope"]["data"]["builder_index"] = json!("7");
    let built = finished(built);
    refused(&network, 3, &key, &built, 400, "refusal", "not_self_built");
    let next = gloas_block(slot + 1, 1);
    signed(&network, 0, &key, &next);
    refused(
        &network,
        0,
        &key,
        &envelope(slot + 1, &block_root(&next), B, vec![]),
        412,
        "registration",
        "fee_recipient",
    );

    // A faulty leader proposes an envelope of a slot this validator signed no block for.
    let foreign = envelope(slot + 5, &own, A, vec![]);
    applied_by_state(
        &network,
        &inject,
        vec![bare(&foreign, &key)],
        "EnvelopeWithoutOwnBlock",
    );
    let _ = std::fs::remove_file(&inject);
    refused(
        &network,
        1,
        &key,
        &foreign,
        412,
        "refusal",
        "envelope_without_own_block",
    );

    // The policy of B: A's authorized envelope is refused on a retry, by the API and by the
    // keyholders a faulty coordinator (D's identity) asks.
    network.stop_node(3);
    let peer = FakePeer::start(&network, 3, &[], Box::new(|_, _, _| Vec::new()));
    let ceremony = CeremonyId::new(VALIDATOR).unwrap();
    let validator: [u8; 48] = hex::decode(key.trim_start_matches("0x"))
        .unwrap()
        .try_into()
        .unwrap();
    let ask_all = || -> Vec<Message> {
        [0, 1, 2]
            .into_iter()
            .map(|node| {
                ask(
                    &network,
                    &peer,
                    node,
                    &Request::duty(ceremony.clone(), validator, root(&allowed)),
                )
            })
            .collect()
    };
    assert!(
        ask_all()
            .iter()
            .all(|answer| matches!(answer, Message::Partial { .. })),
        "the authorized envelope under A's policy"
    );
    set_policy(&network, 0, policy(&[B]), &[0, 1, 2]);
    for answer in ask_all() {
        assert!(
            matches!(
                answer,
                Message::Refused {
                    reason: Refusal::NotAuthorized,
                    ..
                }
            ),
            "A's envelope once the policy is B's: {answer:?}"
        );
    }
    refused(
        &network,
        0,
        &key,
        &allowed,
        412,
        "registration",
        "fee_recipient",
    );
    drop(peer);
    network.restart_node(3);
    network.wait_for_ready(&[3]);
}

/// Proposer preferences under the policy (signed again for a new dependent root); aggregates
/// rooted in the Gloas form at Gloas epochs and in Electra's before; Gloas blocks.
#[test]
fn gl_3_preferences_aggregates_and_blocks() {
    let (network, key) = start(None);
    set_policy(&network, 0, policy(&[A]), &network.all());
    let proposal = GLOAS_SLOT + 300;
    signed(&network, 0, &key, &preferences(proposal, A, 60_000_000, 1));
    signed(&network, 1, &key, &preferences(proposal, A, 60_000_000, 2));
    refused(
        &network,
        2,
        &key,
        &preferences(proposal, B, 60_000_000, 3),
        412,
        "registration",
        "fee_recipient",
    );
    refused(
        &network,
        3,
        &key,
        &preferences(proposal, A, 90_000_000, 4),
        412,
        "registration",
        "gas_limit",
    );
    // Preferences for Gloas's first epoch name Gloas's version, also before the fork; a
    // proposal before Gloas has none.
    signed(
        &network,
        0,
        &key,
        &preferences(GLOAS_SLOT, A, 60_000_000, 5),
    );
    refused(
        &network,
        0,
        &key,
        &preferences(GLOAS_SLOT - 1, A, 60_000_000, 6),
        400,
        "fork",
        "before_gloas",
    );

    // Aggregates: Gloas's form at a Gloas slot, Electra's before.
    let gloas_aggregate = aggregate(GLOAS_SLOT + 5);
    signed(&network, 1, &key, &gloas_aggregate);
    signed(&network, 2, &key, &aggregate(GLOAS_SLOT - 5));
    // A client that roots a Gloas aggregate as Electra's: its root is not the signed one.
    let request = parse_request(gloas_aggregate.to_string().as_bytes()).unwrap();
    let mut electra_rooted = gloas_aggregate.clone();
    electra_rooted["signingRoot"] = json!(format_root(&request.duty.signing_root(&request.fork)));
    let (status, answer) = network.eth2_sign(3, &key, &electra_rooted);
    assert_eq!(status, 400, "{answer}");

    // Gloas blocks, by their header.
    signed(&network, 3, &key, &gloas_block(GLOAS_SLOT + 7, 1));
    refused(
        &network,
        0,
        &key,
        &gloas_block(GLOAS_SLOT + 7, 2),
        412,
        "refusal",
        "double_proposal",
    );
}

/// A raw `POST` of `length` bytes to node `via`'s signing API, written by another thread while
/// this one reads the answer (the node answers before it has read them all): the status code.
fn oversized(network: &TestNetwork, via: usize, key: &str, length: usize) -> u16 {
    let stream = TcpStream::connect(network.http_addr(via)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(60)))
        .unwrap();
    let mut writer = stream.try_clone().unwrap();
    let path = format!("/api/v1/eth2/sign/{key}");
    let sender = std::thread::spawn(move || {
        let head = format!(
            "POST {path} HTTP/1.1\r\nHost: node\r\nContent-Type: application/json\r\n\
             Content-Length: {length}\r\nConnection: close\r\n\r\n"
        );
        if writer.write_all(head.as_bytes()).is_err() {
            return;
        }
        let chunk = vec![b' '; 1 << 20];
        for _ in 0..length.div_ceil(chunk.len()) {
            if writer.write_all(&chunk).is_err() {
                return;
            }
        }
    });
    let mut reader = stream;
    let mut response = Vec::new();
    let mut buffer = [0u8; 4096];
    while !response.windows(2).any(|window| window == b"\r\n") {
        match reader.read(&mut buffer) {
            Ok(0) | Err(_) => break,
            Ok(read) => response.extend_from_slice(&buffer[..read]),
        }
    }
    drop(reader);
    let _ = sender.join();
    let text = String::from_utf8_lossy(&response);
    text.split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or_else(|| panic!("no status line: {text:?}"))
}

/// An envelope of a 12 MB payload (well beyond axum's default 2 MiB) signs after its block, both
/// within the slot's payload deadline here; a request beyond 32 MiB is refused with `413` before
/// it is read. The latencies are printed.
#[test]
fn gl_4_a_large_envelope() {
    let (network, key) = start(None);
    set_policy(&network, 0, policy(&[A]), &network.all());
    let slot = GLOAS_SLOT + 400;
    // 400 transactions of 15 000 bytes: 6 MB of payload, 12 MB of hex.
    let transactions: Vec<String> = (0..400u32)
        .map(|index| format!("0x{}", hex::encode(vec![(index % 251) as u8; 15_000])))
        .collect();
    let block = gloas_block(slot, 1);
    let body = envelope(slot, &block_root(&block), A, transactions);
    let size = body.to_string().len();
    assert!(size > 12_000_000, "{size}");
    let started = Instant::now();
    signed(&network, 0, &key, &block);
    let block_done = started.elapsed();
    signed(&network, 0, &key, &body);
    let both = started.elapsed();
    println!(
        "a 12 MB envelope: block signed in {} ms, block and envelope in {} ms ({size} bytes)",
        block_done.as_millis(),
        both.as_millis()
    );
    assert!(both < Duration::from_secs(6), "{both:?}");
    assert_eq!(oversized(&network, 1, &key, 33 * 1024 * 1024), 413);
    // The node goes on.
    signed(&network, 1, &key, &ptc_vote(slot, true));
}
