//! Audit F1, F2, F4 and R5: process lifecycle, port reservation, corrupted or inconsistent
//! storage.

use crate::{
    KEY,
    failures::{index_of, wait_applied},
    harness::{NODES, Ports, TestNetwork, root},
    signing::network_with_key,
};
use std::{
    collections::BTreeMap,
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

/// Every file under `dir`, with its contents.
fn files(dir: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    let mut files = BTreeMap::new();
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            files.extend(self::files(&path));
        } else {
            files.insert(path.clone(), fs::read(&path).unwrap());
        }
    }
    files
}

/// Partitions whose contents are evidence: the replicated state, the key shares, the consensus
/// journal and marshal's progress.
const EVIDENCE: [&str; 4] = [
    "registry-state",
    "registry-secrets",
    "registry-consensus",
    "registry-marshal-application-metadata",
];

/// Where a node saves, before opening its stores, the copies that fail their integrity check.
const DIAGNOSTICS: &str = "registry-diagnostics";

/// Contents of every file node 3 saved for investigation.
fn saved_copies(network: &TestNetwork) -> Vec<Vec<u8>> {
    let dir = network.data_dir(3).join(DIAGNOSTICS);
    if !dir.exists() {
        return Vec::new();
    }
    files(&dir).into_values().collect()
}

/// After a damaged restart, node 3 must stop (fail closed, exit status not 0) instead of running
/// with durable state that contradicts itself, and delete no file. A file of [EVIDENCE] may change
/// only through commonware's recovery of a copy that failed its integrity check, and then its
/// original bytes are saved in [DIAGNOSTICS].
fn assert_fails_closed(network: &TestNetwork, why: &str) {
    let data = network.data_dir(3);
    let before = files(&data);
    network.restart_node(3);
    let status = network.wait_exit(3);
    assert!(!status.success(), "{why}: node 3 exited with {status}");
    assert!(network.count(3, "refusing to start") > 0, "{why}");
    let after = files(&data);
    let saved = saved_copies(network);
    let relative = |path: &Path| path.strip_prefix(&data).unwrap().to_path_buf();
    let removed: Vec<PathBuf> = before
        .keys()
        .filter(|path| !after.contains_key(*path))
        .map(|path| relative(path))
        .collect();
    assert!(removed.is_empty(), "{why}: removed {removed:?}");
    let lost: Vec<PathBuf> = before
        .iter()
        .filter(|(path, contents)| {
            EVIDENCE
                .iter()
                .any(|partition| relative(path).starts_with(partition))
                && after.get(*path) != Some(contents)
                && !saved.contains(contents)
        })
        .map(|(path, _)| relative(path))
        .collect();
    assert!(
        lost.is_empty(),
        "{why}: changed without a saved copy {lost:?}"
    );
}

/// The damaged newest state copy of a node held after its last acknowledged block (F4's setup).
fn damage_acknowledged_state(network: &TestNetwork) -> PathBuf {
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
    wait_applied(network, &network.all(), 100);
    let held = network.count(3, "test hook: holding block execution");
    fs::write(&hold, b"").unwrap();
    network.wait_until("node 3 to hold the next block", || {
        network.count(3, "test hook: holding block execution") > held
    });
    network.stop_node(3);
    fs::remove_file(&hold).unwrap();
    let copy = newest_state_copy(network, 3);
    flip_last_byte(&copy);
    copy
}

/// F4: the copy of the replicated state written last is damaged after its block was acknowledged
/// to marshal (pinned: the node is held on the next block). The other copy is a block behind, which
/// marshal will not re-deliver: the node must stop instead of skipping the block.
#[test]
fn f4_corrupted_state_fails_closed() {
    let (network, _) = network_with_key();
    damage_acknowledged_state(&network);
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

/// R5: the consensus journal is gone while the node has finalized history. It may have voted in
/// views it no longer remembers, so it refuses to start. The README's operator procedure lets it
/// start once the network is well past those views, explicitly.
#[test]
fn r5_missing_consensus_journal_fails_closed() {
    let (network, _) = network_with_key();
    let (status, signed) = network.sign(0, KEY, 100, root(0xaa));
    assert_eq!(status, 200, "{signed}");
    wait_applied(&network, &network.all(), 100);
    let index_3 = index_of(&network, 3);

    network.stop_node(3);
    let journal = network.data_dir(3).join("registry-consensus");
    fs::remove_dir_all(&journal).unwrap();
    assert_fails_closed(&network, "consensus journal deleted");
    assert!(
        network.count(
            3,
            "consensus journal (partition registry-consensus) is missing"
        ) > 0
    );
    assert!(!journal.exists(), "nothing was recreated");

    // The procedure: let the others finalize more views than peers keep (10) past anything node 3
    // can have voted in, then allow the start.
    let stopped_at = network.height(0).unwrap();
    network.wait_until("the network to move past node 3's last views", || {
        network.height(0).unwrap() >= stopped_at + 15
    });
    network.restart_node_with_args(3, &["--allow-missing-consensus-journal"]);
    network.wait_for_ready(&[3]);
    let readiness = network.readiness(3);
    assert_eq!(readiness["consensus"]["journal_missing_at_start"], true);

    network.freeze(1);
    let (status, again) = network.sign(0, KEY, 100, root(0xaa));
    network.thaw(1);
    assert_eq!(status, 200, "{again}");
    assert!(
        again["signers"]
            .as_array()
            .unwrap()
            .contains(&index_3.into()),
        "{again}"
    );
    assert_eq!(again["signature"], signed["signature"]);
    assert_eq!(network.blocked_for_equivocation(3), Vec::<usize>::new());
}

/// R5: the replicated state and the finalized history are gone but the key share remains: the
/// node would hold a share without the authorizations it signs under. It refuses to start.
#[test]
fn r5_share_without_state_fails_closed() {
    let (network, _) = network_with_key();
    network.stop_node(3);
    for entry in fs::read_dir(network.data_dir(3)).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_str().unwrap().to_string();
        if path.is_dir() && name != "registry-secrets" && name != "registry-consensus" {
            fs::remove_dir_all(&path).unwrap();
        }
    }
    assert_fails_closed(&network, "state and history deleted, key share kept");
    assert!(network.count(3, "a key share of ceremony round 0 is stored") > 0);
}

/// R5: the damaged copy is saved, durably, before any store is opened: a start interrupted right
/// after saving leaves the working copy untouched; the following starts let commonware recover it
/// and refuse, and the saved evidence stays exactly one unchanged copy.
#[test]
fn r5_damaged_copy_is_saved_before_opening() {
    let (network, _) = network_with_key();
    let copy = damage_acknowledged_state(&network);
    let damaged = fs::read(&copy).unwrap();

    network.restart_node_with(
        3,
        vec![("ETH_MPC_SIGNER_CRASH_AT".into(), "after-diagnostics".into())],
    );
    assert!(!network.wait_exit(3).success());
    assert!(network.count(3, "test hook: crashing at after-diagnostics") > 0);
    assert_eq!(saved_copies(&network), std::slice::from_ref(&damaged));
    assert_eq!(
        fs::read(&copy).unwrap(),
        damaged,
        "the working copy is untouched"
    );

    for attempt in 1..=2 {
        network.restart_node_with(3, Vec::new());
        assert!(!network.wait_exit(3).success(), "start {attempt}");
        assert_eq!(
            saved_copies(&network),
            std::slice::from_ref(&damaged),
            "start {attempt}"
        );
    }
    assert!(network.count(3, "blocks are missing") >= 2);
    assert!(network.count(3, "a copy fails its integrity check") >= 1);
}
