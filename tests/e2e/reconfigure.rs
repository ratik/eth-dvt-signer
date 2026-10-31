//! R3-E2E: replacing a lost consensus voter (docs/reconfiguration.md) on real processes. The
//! committee A, B, C, D (nodes 0 to 3) loses D for good; E (node 4) follows it without voting. A
//! reconfiguration finalized by A, B and C ends epoch 0 with its block: every node commits epoch 1
//! (A, B, C, E) together with that block and exits (status 75); restarted (here by the test, as
//! a supervisor would), it runs epoch 1 from that block.

use crate::{
    eth2::{block, refused, signed},
    follower::{FOLLOWER, max_height, network_with_follower},
    harness::{TestNetwork, peer::FakePeer},
    replace::replacement,
    reshare::crash_at,
};
use commonware_codec::Encode as _;
use commonware_cryptography::{
    Signer as _,
    ed25519::{PrivateKey, PublicKey},
};
use eth_mpc_signer::{
    engine,
    types::{Command, Reconfiguration, Transaction},
};
use serde_json::{Value, json};
use std::{
    path::PathBuf,
    process::{Child, Command as Process, Stdio},
};

/// The lost voter.
const D: usize = 3;
/// Its replacement, a follower.
const E: usize = FOLLOWER;
const C: usize = 2;
/// Epoch 1's voters.
const NEW_COMMITTEE: [usize; 4] = [0, 1, 2, E];
const ADMIN: &str = env!("CARGO_BIN_EXE_mpc-admin");

fn key(node: usize) -> PublicKey {
    PrivateKey::from_seed(node as u64).public_key()
}

/// Node `node`'s consensus identity, as the API shows it.
fn identity(node: usize) -> String {
    format!("0x{}", hex::encode(key(node).encode()))
}

fn consensus(network: &TestNetwork, node: usize) -> Value {
    let (status, body) = network.get(node, "/consensus");
    assert_eq!(status, 200, "{body}");
    body
}

/// Whether a log line carries the field `name=value` (fields follow the message, space separated).
fn field(line: &str, name: &str, value: u64) -> bool {
    let field = format!("{name}={value}");
    line.split_whitespace().any(|word| word == field)
}

/// The epoch node `node` runs, if it answers.
fn epoch(network: &TestNetwork, node: usize) -> Option<u64> {
    match network.try_call(node, "GET", "/consensus", None) {
        Ok((200, body)) => body["epoch"]["epoch"].as_u64(),
        _ => None,
    }
}

fn reconfigure(network: &TestNetwork, via: usize, remove: usize, add: usize) -> (u16, Value) {
    network.post(
        via,
        "/consensus/reconfigure",
        &json!({ "remove": identity(remove), "add": identity(add) }),
    )
}

/// What a node's supervisor does: wait until node `node` exits with `code`, then start it again.
fn restart_after(network: &TestNetwork, node: usize, code: i32) {
    let status = network.wait_exit(node);
    if status.code() != Some(code) {
        network.fail(&format!(
            "node {node} exited with {status}, expected status {code}"
        ));
    }
    network.start_node(node);
}

/// Wait until every one of `nodes` is above `height`.
fn wait_above(network: &TestNetwork, nodes: &[usize], height: u64) {
    for &node in nodes {
        network.wait_until(&format!("node {node} above height {height}"), || {
            network.height(node).is_some_and(|applied| applied > height)
        });
    }
}

/// Every one of `nodes` runs epoch 1, started after the same block, whose voters are A, B, C and E
/// (E replaced D). Returns that block's height.
fn switched(network: &TestNetwork, nodes: &[usize]) -> u64 {
    let mut committee: Vec<String> = NEW_COMMITTEE.iter().map(|node| identity(*node)).collect();
    committee.sort();
    let mut boundary = None;
    for &node in nodes {
        network.wait_until(&format!("node {node} in epoch 1"), || {
            epoch(network, node) == Some(1)
        });
        let status = consensus(network, node);
        let current = &status["epoch"];
        let mut reported: Vec<String> =
            serde_json::from_value(current["committee"].clone()).unwrap();
        reported.sort();
        assert_eq!(reported, committee, "node {node}: {status}");
        assert_eq!(current["removed"], json!(identity(D)), "{status}");
        assert_eq!(current["added"], json!(identity(E)), "{status}");
        let height = current["boundary"].as_u64().unwrap();
        assert_eq!(
            *boundary.get_or_insert(height),
            height,
            "every node starts epoch 1 after the same block"
        );
        assert_eq!(
            status["voting"],
            json!(NEW_COMMITTEE.contains(&node)),
            "node {node}: {status}"
        );
    }
    boundary.unwrap()
}

/// `mpc-admin` with every node of `network`.
fn admin(network: &TestNetwork, args: &[&str]) -> Child {
    let nodes: Vec<String> = network
        .all()
        .iter()
        .map(|node| network.http_addr(*node).to_string())
        .collect();
    Process::new(ADMIN)
        .arg("--nodes")
        .arg(nodes.join(","))
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to start mpc-admin")
}

/// Whether `mpc-admin` succeeded, and what it printed.
fn finished(child: Child) -> (bool, String) {
    let output = child.wait_with_output().unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    (output.status.success(), text)
}

/// The R3 starting point: A, B, C, D and the follower E ran together; D is lost for good; A, B and
/// C keep finalizing without it. Node `i` gets `env(i)`.
fn d_lost_with(env: impl Fn(usize) -> Vec<(String, String)>) -> TestNetwork {
    let network = network_with_follower(env, true);
    network.wait_for_ready(&network.all());
    network.wait_until("some history", || {
        network.height(E).is_some_and(|height| height >= 3)
    });
    network.stop_node(D);
    let height = max_height(&network, &[0, 1, 2]);
    wait_above(&network, &[0, 1, 2], height + 1);
    network
}

fn d_lost() -> TestNetwork {
    d_lost_with(|_| Vec::new())
}

/// Submit the replacement of D by E through node `via` and restart A, B, C and E when they stop
/// at the end of epoch 0; returns the block that ended it.
fn replace_d(network: &TestNetwork, via: usize) -> u64 {
    let (status, answer) = reconfigure(network, via, D, E);
    assert_eq!(status, 202, "{answer}");
    assert_eq!(answer["epoch"], 1, "{answer}");
    for node in NEW_COMMITTEE {
        restart_after(network, node, engine::EXIT_RECONFIGURED);
    }
    switched(network, &NEW_COMMITTEE)
}

/// R3-1: with D lost, the operator replaces it with E (`mpc-admin replace-node`). A, B, C and E
/// stop after the same block and, restarted, run epoch 1, E voting and leading; it finalizes.
#[test]
fn r3_1_replace_a_lost_voter() {
    let network = d_lost();
    let admin = admin(&network, &["replace-node", "--old", "3", "--new", "4"]);
    for node in NEW_COMMITTEE {
        restart_after(&network, node, engine::EXIT_RECONFIGURED);
    }
    let (success, output) = finished(admin);
    assert!(success, "{output}");
    let boundary = switched(&network, &NEW_COMMITTEE);
    assert!(
        output.contains(&format!("epoch 1 started after block {boundary}")),
        "{output}"
    );
    wait_above(&network, &NEW_COMMITTEE, boundary + 3);

    // Each node stopped right after that block: the last it applied in epoch 0.
    for node in NEW_COMMITTEE {
        assert!(
            network.log(node).lines().any(|line| {
                line.contains("the consensus epoch ended with this block")
                    && field(line, "height", boundary)
            }),
            "node {node}"
        );
    }
    // E votes: it has a committee index and leads its views (a follower never proposes).
    let (_, me) = network.get(E, "/identity");
    assert!(me["participant_index"].as_u64().is_some(), "{me}");
    network.wait_until("E to lead a view of epoch 1", || {
        network.log(E).contains("proposing a block")
    });
}

/// R3-2 and R3-3: E, a keyholder since R2, becomes a voter and a coordinator. After the switch the
/// key, its generation and its slashing records are unchanged; with C lost as well, A, B and E
/// finalize and sign, E coordinating with A's and B's shares.
#[test]
fn r3_2_e_votes_and_signs_without_c() {
    let r2 = replacement();
    r2.replace_and_activate("validator-r3");
    let network = &r2.network;
    let proposal = block(20, 1);
    let signature = signed(network, 0, &r2.key, &proposal);
    let (status, validators) = network.get(0, "/validators");
    assert_eq!(status, 200, "{validators}");

    replace_d(network, 0);
    network.wait_for_ready(&NEW_COMMITTEE);

    // R3-3: the same key, generation and history on every node.
    for node in NEW_COMMITTEE {
        assert_eq!(
            network.get(node, "/validators").1,
            validators,
            "node {node}"
        );
    }
    assert_eq!(
        signed(network, 1, &r2.key, &proposal),
        signature,
        "the same request is the same signature"
    );
    refused(network, 1, &r2.key, &block(20, 2), "double_proposal");

    // R3-2: C is lost too; A, B and E are a quorum of epoch 1.
    network.stop_node(C);
    let height = max_height(network, &[0, 1, E]);
    wait_above(network, &[0, 1, E], height + 3);
    let next = block(21, 1);
    signed(network, E, &r2.key, &next);
    let mut expected: Vec<u64> = [0, 1, E]
        .iter()
        .map(|node| r2.index(*node, "validator-r3"))
        .collect();
    expected.sort_unstable();
    assert_eq!(r2.signers(E, &next), expected, "A, B and E signed");
}

/// R3-4: D comes back after the switch, with its old data. In epoch 0 it finalizes nothing and
/// nobody follows or blocks it; asked to fetch the block that ended epoch 0 (`mpc-admin resume`),
/// it stops, restarts in epoch 1 as a non-voter, and follows.
#[test]
fn r3_4_d_returns_after_the_switch() {
    let network = d_lost();
    let boundary = replace_d(&network, 0);
    network.start_node(D);
    assert_eq!(epoch(&network, D), Some(0));
    let height = max_height(&network, &NEW_COMMITTEE);
    wait_above(&network, &NEW_COMMITTEE, height + 3);
    assert!(
        network.height(D).unwrap() < boundary,
        "D applied nothing of the end of epoch 0 on its own"
    );
    assert_eq!(epoch(&network, D), Some(0));

    let (success, output) = finished(admin(&network, &["resume"]));
    assert!(success, "{output}");
    assert!(
        output.contains(&format!("asked to fetch block {boundary}")),
        "{output}"
    );
    restart_after(&network, D, engine::EXIT_RECONFIGURED);
    network.wait_until("D in epoch 1", || epoch(&network, D) == Some(1));
    assert_eq!(consensus(&network, D)["voting"], false);
    let height = max_height(&network, &NEW_COMMITTEE);
    network.wait_until("D to follow epoch 1", || {
        network.height(D).is_some_and(|applied| applied >= height)
    });
}

/// R3-5: E is down when epoch 0 ends (A, B and C need no follower to finalize it). They run epoch
/// 1 without E; restarted, E is still in epoch 0 and catches up once asked to fetch the block that
/// ended it (`mpc-admin resume`); then it votes: with C down, A, B and E finalize.
#[test]
fn r3_5_a_node_left_in_epoch_0_catches_up() {
    let network = d_lost();
    network.stop_node(E);
    let (status, answer) = reconfigure(&network, 0, D, E);
    assert_eq!(status, 202, "{answer}");
    for node in [0, 1, 2] {
        restart_after(&network, node, engine::EXIT_RECONFIGURED);
    }
    let boundary = switched(&network, &[0, 1, 2]);
    wait_above(&network, &[0, 1, 2], boundary + 2);

    network.start_node(E);
    assert_eq!(epoch(&network, E), Some(0));
    let (success, output) = finished(admin(&network, &["resume"]));
    assert!(success, "{output}");
    restart_after(&network, E, engine::EXIT_RECONFIGURED);
    assert_eq!(switched(&network, &[E]), boundary);
    let height = max_height(&network, &[0, 1, 2]);
    wait_above(&network, &[E], height);

    network.stop_node(C);
    let height = max_height(&network, &[0, 1, E]);
    wait_above(&network, &[0, 1, E], height + 3);
}

/// R3-6: crashes around the end of epoch 0. A crashes before applying the block that ends it, B
/// right after committing it, C at its first start in epoch 1 before consensus starts. Each
/// restarts in the right epoch, without a missing-journal refusal, and epoch 1 runs.
#[test]
fn r3_6_crashes_around_the_switch() {
    let network = d_lost_with(|node| match node {
        0 => crash_at("before-apply-reconfiguration"),
        1 => crash_at("after-apply-reconfiguration"),
        _ => Vec::new(),
    });
    let (status, answer) = reconfigure(&network, C, D, E);
    assert_eq!(status, 202, "{answer}");

    // A: restarted without the crash point, it applies the block and stops.
    let crashed = network.wait_exit(0);
    assert_eq!(crashed.code(), None, "A aborted: {crashed}");
    network.restart_node_with(0, Vec::new());
    restart_after(&network, 0, engine::EXIT_RECONFIGURED);
    // B committed epoch 1 before crashing: restarted, it runs epoch 1 directly.
    let crashed = network.wait_exit(1);
    assert_eq!(crashed.code(), None, "B aborted: {crashed}");
    network.restart_node_with(1, Vec::new());
    // C: its first start in epoch 1 crashes before consensus starts.
    let stopped = network.wait_exit(C);
    assert_eq!(stopped.code(), Some(engine::EXIT_RECONFIGURED));
    network.restart_node_with(C, crash_at("epoch-started"));
    let crashed = network.wait_exit(C);
    assert_eq!(crashed.code(), None, "C aborted: {crashed}");
    network.restart_node_with(C, Vec::new());
    restart_after(&network, E, engine::EXIT_RECONFIGURED);

    let boundary = switched(&network, &NEW_COMMITTEE);
    wait_above(&network, &NEW_COMMITTEE, boundary + 3);
    for node in NEW_COMMITTEE {
        assert!(
            !network.log(node).contains("refusing to start"),
            "node {node}"
        );
    }
}

/// R3-7: what is refused. Before the switch, through the API: removing a non-voter, adding a voter
/// or a key that is no configured follower. After it: a reconfiguration naming the past epoch,
/// gossiped under D's identity, is dropped by the leaders, and the API computes the next epoch; a
/// closing height at or below the state refuses to start.
#[test]
fn r3_7_refusals() {
    let network = d_lost();
    let refusal = |remove, add, why: &str| {
        let (status, answer) = reconfigure(&network, 0, remove, add);
        assert_eq!(status, 400, "{answer}");
        assert!(answer.to_string().contains(why), "{answer}");
    };
    refusal(E, 0, "not a member");
    refusal(D, 1, "already a member");
    refusal(D, 9, "not a configured follower");
    let (status, answer) = network.post(
        0,
        "/consensus/reconfigure",
        &json!({ "remove": "0x12", "add": identity(E) }),
    );
    assert_eq!(status, 400, "{answer}");

    let boundary = replace_d(&network, 0);
    // A reconfiguration of epoch 1 (the current one), from D's identity, now a known non-voter.
    let peer = FakePeer::start(&network, D, &[], Box::new(|_, _, _| Vec::new()));
    let stale = Transaction {
        id: 77,
        command: Command::Reconfigure(Box::new(Reconfiguration {
            epoch: 1,
            remove: key(C),
            add: key(D),
        })),
    }
    .encode()
    .to_vec();
    network.wait_until("a leader to drop the stale reconfiguration", || {
        for node in NEW_COMMITTEE {
            peer.send_on(engine::MEMPOOL_CHANNEL, node, stale.clone());
        }
        NEW_COMMITTEE
            .iter()
            .any(|node| network.log(*node).contains("dropping a reconfiguration"))
    });
    drop(peer);
    let height = max_height(&network, &NEW_COMMITTEE);
    wait_above(&network, &NEW_COMMITTEE, height + 2);
    for node in NEW_COMMITTEE {
        assert_eq!(epoch(&network, node), Some(1));
        assert_eq!(consensus(&network, node)["epoch"]["boundary"], boundary);
    }
    // D is no voter of epoch 1 any more.
    let (status, answer) = reconfigure(&network, 0, D, E);
    assert_eq!(status, 400, "{answer}");

    let height = network.height(0).unwrap();
    network.restart_node_with_args(0, &["--close-epoch-at", &height.to_string()]);
    let refused_start = network.wait_exit(0);
    assert_eq!(refused_start.code(), Some(1));
    assert!(network.log(0).contains("would never reach it"));
    network.restart_node_with_args(0, &[]);
    network.wait_for_ready(&[0]);
}

/// R3-8: a faulty leader builds on the block that ended epoch 0 (B, with a test hook). A, B and C
/// keep running epoch 0 (their executors held, so none stops); A and C refuse B's block, so
/// nothing past the end of epoch 0 is finalized, and every node starts epoch 1 after the same
/// block (and finds no epoch-0 finalization above it at startup).
#[test]
fn r3_8_nothing_is_finalized_after_the_end_of_epoch_0() {
    let hold: PathBuf = std::env::temp_dir().join(format!(
        "eth-mpc-signer-r3-8-hold-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let path = hold.display().to_string();
    let network = d_lost_with(move |node| {
        let mut env = Vec::new();
        if node < 3 {
            env.push(("ETH_MPC_SIGNER_HOLD_FILE".to_string(), path.clone()));
            env.push((
                "ETH_MPC_SIGNER_HOLD_FROM".to_string(),
                "transactions".to_string(),
            ));
        }
        if node == 1 {
            env.push((
                "ETH_MPC_SIGNER_PROPOSE_PAST_TERMINAL".to_string(),
                "1".to_string(),
            ));
        }
        env
    });
    std::fs::write(&hold, b"").unwrap();
    let (status, answer) = reconfigure(&network, 0, D, E);
    assert_eq!(status, 202, "{answer}");
    network.wait_until(
        "A and C to refuse B's block after the end of epoch 0",
        || {
            [0, C].iter().all(|node| {
                network
                    .log(*node)
                    .contains("refusing a block after the epoch's last block")
            })
        },
    );
    std::fs::remove_file(&hold).unwrap();
    for node in NEW_COMMITTEE {
        restart_after(&network, node, engine::EXIT_RECONFIGURED);
    }
    let boundary = switched(&network, &NEW_COMMITTEE);
    assert!(
        network.log(1).lines().any(|line| {
            line.contains("proposing a block") && field(line, "height", boundary + 1)
        }),
        "B built on the end of epoch 0"
    );
    wait_above(&network, &NEW_COMMITTEE, boundary + 3);
}

/// R3-9: closing epoch 0 at a height (`--close-epoch-at`), the recovery for an epoch whose last
/// block is never finalized. Without a reconfiguration, the voters finalize exactly up to that
/// height and stop (status 76); restarted without it, they continue epoch 0.
#[test]
fn r3_9_closing_an_epoch() {
    let network = TestNetwork::start(4);
    network.wait_for_ready(&network.all());
    network.stop_node(D);
    let height = max_height(&network, &[0, 1, 2]);
    wait_above(&network, &[0, 1, 2], height + 1);

    let close = max_height(&network, &[0, 1, 2]) + 12;
    for node in [0, 1, 2] {
        network.restart_node_with_args(node, &["--close-epoch-at", &close.to_string()]);
    }
    for node in [0, 1, 2] {
        let status = network.wait_exit(node);
        assert_eq!(status.code(), Some(engine::EXIT_CLOSED), "node {node}");
        assert!(
            network.log(node).lines().any(|line| {
                line.contains("closed here without a reconfiguration")
                    && field(line, "height", close)
            }),
            "node {node}"
        );
    }
    // Nothing above the closing height: A alone (B and C stopped) is exactly there.
    network.restart_node_with_args(0, &[]);
    assert_eq!(network.height(0), Some(close));
    for node in [1, 2] {
        network.restart_node_with_args(node, &[]);
    }
    wait_above(&network, &[0, 1, 2], close + 3);
    for node in [0, 1, 2] {
        assert_eq!(epoch(&network, node), Some(0));
    }
}
