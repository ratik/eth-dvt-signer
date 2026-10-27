//! Audit F1, F2, F4: process lifecycle, port reservation, corrupted storage.

use crate::{
    KEY,
    failures::wait_applied,
    harness::{NODES, Ports, TestNetwork, root},
    signing::network_with_key,
};
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

fn alive(pid: u32) -> bool {
    Command::new("kill")
        .args(["-0", &pid.to_string()])
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

fn wait_for_file(path: &Path) -> String {
    let start = Instant::now();
    loop {
        if let Ok(text) = fs::read_to_string(path)
            && text.ends_with('\n')
        {
            return text;
        }
        assert!(
            start.elapsed() < Duration::from_secs(120),
            "no {}",
            path.display()
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Run one test of this binary in a child process (an external supervisor for F1, F2).
fn spawn_helper(name: &str, env: &[(&str, &Path)]) -> std::process::Child {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--ignored", "--exact", name, "--nocapture"])
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    for (key, value) in env {
        command.env(key, value);
    }
    command.spawn().unwrap()
}

/// Helper of F1: start a network, report its node pids and directory, then wait to be killed.
#[test]
#[ignore = "helper process of f1_nodes_die_with_their_test_process"]
fn f1_helper_hold_network() {
    let Some(report) = std::env::var_os("E2E_F1_REPORT") else {
        return;
    };
    let network = TestNetwork::start(NODES);
    network.wait_for_ready(&network.all());
    let pids: Vec<String> = network
        .all()
        .into_iter()
        .map(|node| network.pid(node).unwrap().to_string())
        .collect();
    fs::write(
        &report,
        format!("{}\n{}\n", pids.join(" "), network.dir.display()),
    )
    .unwrap();
    loop {
        std::thread::sleep(Duration::from_secs(1));
    }
}

/// F1: the test process is SIGKILLed (no destructor runs). Its nodes must exit on their own.
#[test]
fn f1_nodes_die_with_their_test_process() {
    let scratch = std::env::temp_dir().join(format!("eth-mpc-signer-f1-{}", std::process::id()));
    fs::create_dir_all(&scratch).unwrap();
    let report = scratch.join("report");
    let mut helper = spawn_helper(
        "lifecycle::f1_helper_hold_network",
        &[("E2E_F1_REPORT", &report)],
    );
    let text = wait_for_file(&report);
    let mut lines = text.lines();
    let pids: Vec<u32> = lines
        .next()
        .unwrap()
        .split_whitespace()
        .map(|pid| pid.parse().unwrap())
        .collect();
    let network_dir = PathBuf::from(lines.next().unwrap());
    assert_eq!(pids.len(), NODES);
    assert!(pids.iter().all(|pid| alive(*pid)));

    helper.kill().unwrap(); // SIGKILL
    helper.wait().unwrap();
    let start = Instant::now();
    while pids.iter().any(|pid| alive(*pid)) {
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "orphaned nodes: {:?}",
            pids.iter().filter(|pid| alive(**pid)).collect::<Vec<_>>()
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    // Nothing could delete the killed process's directory: the supervisor does.
    assert!(network_dir.exists());
    fs::remove_dir_all(&network_dir).unwrap();
    fs::remove_dir_all(&scratch).unwrap();
}

/// Helper of F2: reserve port blocks, report them, keep them until told to stop.
#[test]
#[ignore = "helper process of f2_port_blocks_never_overlap"]
fn f2_helper_reserve() {
    let (Some(report), Some(stop)) = (
        std::env::var_os("E2E_F2_REPORT"),
        std::env::var_os("E2E_F2_STOP"),
    ) else {
        return;
    };
    let blocks: Vec<Ports> = (0..20).map(|_| Ports::reserve(NODES)).collect();
    let bases: Vec<String> = blocks.iter().map(|ports| ports.base.to_string()).collect();
    fs::write(&report, format!("{}\n", bases.join(" "))).unwrap();
    while !Path::new(&stop).exists() {
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// F2: port blocks reserved concurrently, by threads and by other processes, never overlap; and
/// networks started at the same time all come up.
#[test]
fn f2_port_blocks_never_overlap() {
    let scratch = std::env::temp_dir().join(format!("eth-mpc-signer-f2-{}", std::process::id()));
    fs::create_dir_all(&scratch).unwrap();
    let stop = scratch.join("stop");
    let reports: Vec<PathBuf> = (0..3)
        .map(|i| scratch.join(format!("report-{i}")))
        .collect();
    let mut helpers: Vec<_> = reports
        .iter()
        .map(|report| {
            spawn_helper(
                "lifecycle::f2_helper_reserve",
                &[("E2E_F2_REPORT", report), ("E2E_F2_STOP", &stop)],
            )
        })
        .collect();
    let local: Vec<Ports> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..20)
            .map(|_| scope.spawn(|| Ports::reserve(NODES)))
            .collect();
        handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect()
    });
    let mut bases: Vec<u16> = local.iter().map(|ports| ports.base).collect();
    for report in &reports {
        bases.extend(
            wait_for_file(report)
                .split_whitespace()
                .map(|base| base.parse::<u16>().unwrap()),
        );
    }
    fs::write(&stop, b"").unwrap();
    for helper in &mut helpers {
        helper.wait().unwrap();
    }
    bases.sort();
    assert_eq!(bases.len(), 80);
    assert!(
        bases.windows(2).all(|pair| pair[1] - pair[0] >= 32),
        "overlapping blocks: {bases:?}"
    );
    drop(local);
    fs::remove_dir_all(&scratch).unwrap();

    let networks: Vec<TestNetwork> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..3)
            .map(|_| {
                scope.spawn(|| {
                    let network = TestNetwork::start(NODES);
                    network.wait_for_ready(&network.all());
                    network
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect()
    });
    let mut addresses: Vec<_> = networks
        .iter()
        .flat_map(|network| {
            network
                .all()
                .into_iter()
                .map(|node| network.http_addr(node))
        })
        .collect();
    addresses.sort();
    addresses.dedup();
    assert_eq!(addresses.len(), 3 * NODES);
}

/// The copy of node `node`'s replicated state written last.
fn newest_state_copy(network: &TestNetwork, node: usize) -> PathBuf {
    let partition = network.data_dir(node).join("registry-state");
    fs::read_dir(&partition)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .max_by_key(|path| fs::metadata(path).unwrap().modified().unwrap())
        .unwrap()
}

fn flip_last_byte(path: &Path) {
    let mut bytes = fs::read(path).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0xff;
    fs::write(path, bytes).unwrap();
}

/// After a damaged restart, node 3 must stop (fail closed) instead of running with replicated
/// state that does not match the finalized history.
fn assert_fails_closed(network: &TestNetwork, why: &str) {
    network.restart_node(3);
    let status = network.wait_exit(3);
    assert!(!status.success(), "{why}: node 3 exited with {status}");
}

/// F4: the copy of the replicated state written last is damaged after its block was acknowledged
/// to marshal (pinned: the node is held on the next block). The other copy is a block behind, which
/// marshal will not re-deliver: the node must stop instead of skipping the block.
#[test]
fn f4_corrupted_state_fails_closed() {
    let (network, _) = network_with_key();
    let hold = network.dir.join("hold-3");
    network.restart_node_with(
        3,
        vec![(
            "ETH_MPC_SIGNER_HOLD_FILE".into(),
            hold.display().to_string(),
        )],
    );
    network.wait_for_ready(&[3]);
    let (status, body) = network.sign(0, KEY, 100, root(0xaa));
    assert_eq!(status, 200, "{body}");
    wait_applied(&network, &network.all(), 100);

    let held = network.count(3, "test hook: holding block execution");
    fs::write(&hold, b"").unwrap();
    network.wait_until("node 3 to hold the next block", || {
        network.count(3, "test hook: holding block execution") > held
    });
    network.stop_node(3);
    fs::remove_file(&hold).unwrap();
    flip_last_byte(&newest_state_copy(&network, 3));
    assert_fails_closed(&network, "state one block behind its acknowledged history");
    assert!(network.count(3, "blocks are missing") > 0);
}

/// F4: a torn write of a block that was not acknowledged yet (crash between the state commit and
/// the acknowledgement) is repaired: marshal re-delivers the block and the node ends with the
/// same state as the others.
#[test]
fn f4_torn_unacknowledged_write_is_replayed() {
    let (network, _) = network_with_key();
    network.restart_node_with(
        3,
        vec![(
            "ETH_MPC_SIGNER_CRASH_AT".into(),
            "after-apply-authorization".into(),
        )],
    );
    network.wait_for_ready(&[3]);
    let (status, body) = network.sign(0, KEY, 100, root(0xaa));
    assert_eq!(status, 200, "{body}");
    assert!(!network.wait_exit(3).success());
    flip_last_byte(&newest_state_copy(&network, 3));

    network.restart_node_with(3, Vec::new());
    wait_applied(&network, &[3], 100);
    assert!(
        network.count(3, "checksum mismatch") > 0,
        "the damaged copy was detected"
    );
    let expected = network.get(0, &format!("/authorizations/{KEY}/100")).1;
    assert_eq!(
        network.get(3, &format!("/authorizations/{KEY}/100")).1,
        expected
    );
    network.wait_until("node 3 to keep up", || {
        network.height(3) >= network.height(0).map(|height| height - 1)
    });
    assert_eq!(
        network.status(3)["authorizations"],
        network.status(0)["authorizations"]
    );
}

/// F4: the replicated state is gone while the key share, the block archive and the consensus
/// journal remain. The node must not start from empty state with its signing key.
#[test]
fn f4_lost_state_fails_closed() {
    let (network, _) = network_with_key();
    let (status, body) = network.sign(0, KEY, 100, root(0xaa));
    assert_eq!(status, 200, "{body}");
    wait_applied(&network, &network.all(), 100);

    network.stop_node(3);
    fs::remove_dir_all(network.data_dir(3).join("registry-state")).unwrap();
    assert_fails_closed(&network, "replicated state deleted");
    assert!(network.count(3, "blocks are missing") > 0);
}

/// F4: both copies of the replicated state are corrupted.
#[test]
fn f4_both_copies_corrupted_fails_closed() {
    let (network, _) = network_with_key();
    network.stop_node(3);
    let partition = network.data_dir(3).join("registry-state");
    for entry in fs::read_dir(&partition).unwrap() {
        flip_last_byte(&entry.unwrap().path());
    }
    assert_fails_closed(&network, "both state copies corrupted");
    assert!(network.count(3, "failed to open replicated state") > 0);
}
