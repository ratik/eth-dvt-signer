//! Real-process test network: the actual `eth-mpc-signer` binary, one OS process per node, real
//! authenticated p2p over loopback, real HTTP and real on-disk storage in a temporary directory.
//!
//! - Ports: a block of 32 ports per network, reserved with a lock file shared by every test process
//!   (and checked free), so concurrent networks never get the same ports.
//! - Lifecycle: nodes are killed when the [TestNetwork] is dropped (also on panic) and exit on
//!   their own if the test process dies (they watch their stdin).
//! - Diagnostics: logs go to `<dir>/node-<i>.log`; on failure the tail of every log and every
//!   exit status is printed and the directory is kept.
//! - Synchronization: [TestNetwork::wait_until] polls observable state with a deadline; nothing
//!   relies on fixed sleeps.

pub mod http;
pub mod peer;

use blst::{
    BLST_ERROR,
    min_pk::{PublicKey as EthPublicKey, Signature as EthSignature},
};
use commonware_cryptography::{Signer as _, ed25519::PrivateKey};
use eth_mpc_signer::dkg::signing::ETHEREUM_DST;
use serde_json::{Value, json};
use std::{
    fs::{self, OpenOptions},
    net::{Ipv4Addr, SocketAddr, TcpListener},
    path::PathBuf,
    process::{Child, ChildStdin, Command, ExitStatus, Stdio},
    sync::{
        Condvar, Mutex,
        atomic::{AtomicU32, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

pub const NODES: usize = 4;

/// The binary built for this test run (with the `test-hooks` feature).
const BINARY: &str = env!("CARGO_BIN_EXE_eth-mpc-signer");

/// Seconds a coordinator waits for partial signatures (short, so failures fail fast).
pub const SIGNING_TIMEOUT_SECS: u64 = 5;

/// Default deadline of every wait.
pub const DEADLINE: Duration = Duration::from_secs(90);

/// Reasons commonware consensus gives when it blocks a peer for voting twice in one view.
const EQUIVOCATIONS: [&str; 6] = [
    "blocking equivocator",
    "conflicting notarize",
    "conflicting nullify",
    "conflicting finalize",
    "nullify after finalize",
    "finalize after nullify",
];

/// Timeout of one HTTP request (`POST /sign` can wait for consensus and signers).
const HTTP_TIMEOUT: Duration = Duration::from_secs(70);

static NETWORKS: AtomicU32 = AtomicU32::new(0);

struct Node {
    child: Option<Child>,
    /// Kept open: the node exits when it closes.
    stdin: Option<ChildStdin>,
    env: Vec<(String, String)>,
    /// Command-line arguments of this node only (after the network's).
    args: Vec<String>,
}

/// Networks allowed to run at once in this process (`E2E_MAX_NETWORKS`, default 4): the suite's
/// timeouts assume the machine is not saturated by dozens of nodes.
fn max_networks() -> usize {
    std::env::var("E2E_MAX_NETWORKS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(4)
}

static RUNNING: (Mutex<usize>, Condvar) = (Mutex::new(0), Condvar::new());

/// A running-network slot, released when dropped.
struct Slot;

impl Slot {
    fn acquire() -> Self {
        let (count, freed) = &RUNNING;
        let mut running = count.lock().unwrap();
        while *running >= max_networks() {
            running = freed.wait(running).unwrap();
        }
        *running += 1;
        Self
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        let (count, freed) = &RUNNING;
        *count
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) -= 1;
        freed.notify_one();
    }
}

pub struct TestNetwork {
    pub dir: PathBuf,
    _ports: Ports,
    p2p_base: u16,
    http_base: u16,
    /// Extra command-line arguments of every node.
    args: Vec<String>,
    nodes: Mutex<Vec<Node>>,
    _slot: Slot,
}

/// Ports per reserved block (p2p ports first, then HTTP ports).
const BLOCK: u16 = 32;

/// Directory of port-block lock files shared by every test process on this machine.
fn locks() -> PathBuf {
    std::env::temp_dir().join("eth-mpc-signer-e2e-ports")
}

fn alive(pid: u32) -> bool {
    Command::new("kill")
        .args(["-0", &pid.to_string()])
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

/// A reserved block of ports, released when dropped.
pub struct Ports {
    pub base: u16,
    lock: PathBuf,
}

impl Ports {
    /// Reserve a block: an exclusive lock file (stale ones, whose process is gone, are taken
    /// over), then a check that every port is free. Other programs may still race for a port;
    /// test processes cannot.
    pub fn reserve(n: usize) -> Self {
        assert!(2 * n as u16 <= BLOCK);
        fs::create_dir_all(locks()).unwrap();
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .subsec_nanos()
            ^ std::process::id().wrapping_mul(2_654_435_761);
        for attempt in 0..5000u32 {
            // Between 10240 and 32000: below the ephemeral ranges of macOS (49152+) and Linux
            // (32768+), so outgoing connections never take a reserved port.
            let slot = seed
                .wrapping_add(NETWORKS.fetch_add(1, Ordering::Relaxed).wrapping_mul(7919))
                .wrapping_add(attempt.wrapping_mul(104_729))
                % 680;
            let base = 10_240 + slot as u16 * BLOCK;
            let lock = locks().join(format!("{base}.lock"));
            match OpenOptions::new().write(true).create_new(true).open(&lock) {
                Ok(mut file) => {
                    use std::io::Write as _;
                    write!(file, "{}", std::process::id()).unwrap();
                }
                Err(_) => {
                    let owner = fs::read_to_string(&lock)
                        .ok()
                        .and_then(|pid| pid.trim().parse().ok());
                    if owner.is_some_and(alive) {
                        continue;
                    }
                    // Stale (its process died): take it over, racing other takers fairly.
                    let _ = fs::remove_file(&lock);
                    continue;
                }
            }
            let free = (0..2 * n as u16)
                .all(|offset| TcpListener::bind((Ipv4Addr::LOCALHOST, base + offset)).is_ok());
            if free {
                return Self { base, lock };
            }
            let _ = fs::remove_file(&lock);
        }
        panic!("no free port block");
    }
}

impl Drop for Ports {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.lock);
    }
}

impl TestNetwork {
    /// Start `n` nodes with empty storage.
    pub fn start(n: usize) -> Self {
        Self::start_with(n, |_| Vec::new())
    }

    /// Start `n` nodes, node `i` with the extra environment `env(i)` (test hooks).
    pub fn start_with(n: usize, env: impl Fn(usize) -> Vec<(String, String)>) -> Self {
        Self::start_with_args(n, Vec::new(), env)
    }

    /// Like [TestNetwork::start_with], with extra command-line arguments for every node.
    pub fn start_with_args(
        n: usize,
        args: Vec<String>,
        env: impl Fn(usize) -> Vec<(String, String)>,
    ) -> Self {
        let slot = Slot::acquire();
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "eth-mpc-signer-e2e-{}-{}-{nanos}",
            std::process::id(),
            NETWORKS.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&dir).unwrap();
        let ports = Ports::reserve(n);
        let (p2p_base, http_base) = (ports.base, ports.base + n as u16);
        let network = Self {
            dir,
            _ports: ports,
            p2p_base,
            http_base,
            args,
            _slot: slot,
            nodes: Mutex::new(
                (0..n)
                    .map(|i| Node {
                        child: None,
                        stdin: None,
                        env: env(i),
                        args: Vec::new(),
                    })
                    .collect(),
            ),
        };
        for id in 0..n {
            network.spawn(id);
        }
        network
    }

    fn len(&self) -> usize {
        self.nodes.lock().unwrap().len()
    }

    fn spawn(&self, id: usize) {
        let mut nodes = self.nodes.lock().unwrap();
        let log = OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.log_path(id))
            .unwrap();
        let mut child = Command::new(BINARY)
            .args([
                "--id",
                &id.to_string(),
                "--participants",
                &nodes.len().to_string(),
                "--p2p-port",
                &self.p2p_base.to_string(),
                "--http-port",
                &self.http_base.to_string(),
                "--signing-timeout",
                &SIGNING_TIMEOUT_SECS.to_string(),
            ])
            .arg("--data-dir")
            .arg(self.dir.join("data"))
            .args(&self.args)
            .args(&nodes[id].args)
            .env(
                "RUST_LOG",
                std::env::var("E2E_RUST_LOG")
                    .unwrap_or_else(|_| "info,eth_mpc_signer=debug".into()),
            )
            .env("ETH_MPC_SIGNER_EXIT_ON_STDIN_EOF", "1")
            .envs(nodes[id].env.iter().cloned())
            .stdin(Stdio::piped())
            .stdout(Stdio::from(log.try_clone().unwrap()))
            .stderr(Stdio::from(log))
            .spawn()
            .expect("failed to start node");
        nodes[id].stdin = child.stdin.take();
        nodes[id].child = Some(child);
    }

    /// Kill node `id` (like a crash: no shutdown).
    pub fn stop_node(&self, id: usize) {
        let mut nodes = self.nodes.lock().unwrap();
        nodes[id].stdin = None;
        if let Some(mut child) = nodes[id].child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }

    /// Restart node `id` on its existing storage; returns once it serves HTTP.
    pub fn restart_node(&self, id: usize) {
        self.stop_node(id);
        self.spawn(id);
        self.wait_until(&format!("node {id} to serve HTTP"), || self.serves(id));
    }

    /// Restart node `id` with a new extra environment; returns once it serves HTTP.
    pub fn restart_node_with(&self, id: usize, env: Vec<(String, String)>) {
        self.stop_node(id);
        self.nodes.lock().unwrap()[id].env = env;
        self.spawn(id);
        self.wait_until(&format!("node {id} to serve HTTP"), || self.serves(id));
    }

    /// Restart node `id` with extra command-line arguments (kept for later restarts).
    pub fn restart_node_with_args(&self, id: usize, args: &[&str]) {
        self.stop_node(id);
        self.nodes.lock().unwrap()[id].args = args.iter().map(ToString::to_string).collect();
        self.spawn(id);
        self.wait_until(&format!("node {id} to serve HTTP"), || self.serves(id));
    }

    /// Whether node `id` answers HTTP (or has exited, which the caller will notice).
    fn serves(&self, id: usize) -> bool {
        let exited = self.nodes.lock().unwrap()[id]
            .child
            .as_mut()
            .is_none_or(|child| child.try_wait().ok().flatten().is_some());
        exited || std::net::TcpStream::connect(self.http_addr(id)).is_ok()
    }

    /// Process id of node `id`, if running.
    pub fn pid(&self, id: usize) -> Option<u32> {
        self.nodes.lock().unwrap()[id].child.as_ref().map(Child::id)
    }

    /// Freeze node `id` (SIGSTOP): its connections stay open but it answers nothing.
    pub fn freeze(&self, id: usize) {
        signal(self.pid(id).expect("node is running"), "-STOP");
    }

    /// Resume a frozen node (SIGCONT).
    pub fn thaw(&self, id: usize) {
        signal(self.pid(id).expect("node is running"), "-CONT");
    }

    /// Resident memory of node `id`, in KiB.
    pub fn rss_kib(&self, id: usize) -> u64 {
        let pid = self.pid(id).expect("node is running").to_string();
        let output = Command::new("ps")
            .args(["-o", "rss=", "-p", &pid])
            .output()
            .unwrap();
        String::from_utf8_lossy(&output.stdout)
            .trim()
            .parse()
            .unwrap()
    }

    /// Copy the storage of stopped node `id` to snapshot `name`.
    pub fn snapshot(&self, id: usize, name: &str) {
        assert!(
            self.pid(id).is_none(),
            "stop node {id} before taking a snapshot"
        );
        let target = self.dir.join("snapshots").join(name);
        let _ = fs::remove_dir_all(&target);
        copy_dir(&self.data_dir(id), &target);
    }

    /// Replace the storage of stopped node `id` with snapshot `name` (the bytes, as copied).
    pub fn restore(&self, id: usize, name: &str) {
        assert!(self.pid(id).is_none(), "stop node {id} before restoring it");
        let data = self.data_dir(id);
        fs::remove_dir_all(&data).unwrap();
        copy_dir(&self.dir.join("snapshots").join(name), &data);
    }

    /// Replace only partition `partition` of stopped node `id` with its copy in snapshot `name`.
    pub fn restore_partition(&self, id: usize, name: &str, partition: &str) {
        assert!(self.pid(id).is_none(), "stop node {id} before restoring it");
        let target = self.data_dir(id).join(partition);
        let _ = fs::remove_dir_all(&target);
        copy_dir(
            &self.dir.join("snapshots").join(name).join(partition),
            &target,
        );
    }

    /// Like [TestNetwork::restore], but the partitions in `keep` keep their current bytes.
    pub fn restore_keeping(&self, id: usize, name: &str, keep: &[&str]) {
        let data = self.data_dir(id);
        let aside = self.dir.join("snapshots").join(format!("kept-{id}"));
        let _ = fs::remove_dir_all(&aside);
        fs::create_dir_all(&aside).unwrap();
        for partition in keep {
            fs::rename(data.join(partition), aside.join(partition)).unwrap();
        }
        self.restore(id, name);
        for partition in keep {
            let _ = fs::remove_dir_all(data.join(partition));
            fs::rename(aside.join(partition), data.join(partition)).unwrap();
        }
        fs::remove_dir(&aside).unwrap();
    }

    /// `GET /status` of node `id`.
    pub fn status(&self, id: usize) -> Value {
        let (code, body) = self.get(id, "/status");
        assert_eq!(code, 200, "{body}");
        body
    }

    /// Wait until node `id` exits on its own.
    pub fn wait_exit(&self, id: usize) -> ExitStatus {
        let start = Instant::now();
        loop {
            {
                let mut nodes = self.nodes.lock().unwrap();
                let child = nodes[id].child.as_mut().expect("node is not running");
                if let Some(status) = child.try_wait().unwrap() {
                    nodes[id].child = None;
                    nodes[id].stdin = None;
                    return status;
                }
            }
            if start.elapsed() > DEADLINE {
                self.fail(&format!("node {id} did not exit"));
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    pub fn http_addr(&self, id: usize) -> SocketAddr {
        SocketAddr::from((Ipv4Addr::LOCALHOST, self.http_base + id as u16))
    }

    pub fn p2p_addr(&self, id: usize) -> SocketAddr {
        SocketAddr::from((Ipv4Addr::LOCALHOST, self.p2p_base + id as u16))
    }

    /// Storage directory of node `id`.
    pub fn data_dir(&self, id: usize) -> PathBuf {
        self.dir.join("data").join(format!("node-{id}"))
    }

    fn log_path(&self, id: usize) -> PathBuf {
        self.dir.join(format!("node-{id}.log"))
    }

    pub fn log(&self, id: usize) -> String {
        fs::read_to_string(self.log_path(id)).unwrap_or_default()
    }

    /// Lines of node `id`'s log containing `pattern`.
    pub fn count(&self, id: usize, pattern: &str) -> usize {
        self.log(id)
            .lines()
            .filter(|line| line.contains(pattern))
            .count()
    }

    /// The nodes that blocked node `id` for voting twice in one consensus view (equivocation), as
    /// their logs report it.
    pub fn blocked_for_equivocation(&self, id: usize) -> Vec<usize> {
        let peer = format!("peer={}", PrivateKey::from_seed(id as u64).public_key());
        self.all()
            .into_iter()
            .filter(|node| *node != id)
            .filter(|node| {
                self.log(*node).lines().any(|line| {
                    line.contains(&peer) && EQUIVOCATIONS.iter().any(|why| line.contains(why))
                })
            })
            .collect()
    }

    /// `method path` on node `id`: status and JSON body (`Value::Null` if not JSON).
    pub fn try_call(
        &self,
        id: usize,
        method: &str,
        path: &str,
        body: Option<&Value>,
    ) -> std::io::Result<(u16, Value)> {
        let body = body.map(Value::to_string);
        let (status, text) = http::request(
            self.http_addr(id),
            method,
            path,
            body.as_deref(),
            HTTP_TIMEOUT,
        )?;
        // The router's own 404 (no route) has an empty body; the API's 404s are JSON.
        if status == 404
            && text.is_empty()
            && (path == "/sign" || path.starts_with("/authorizations/"))
        {
            panic!(
                "{path} is not served: {BINARY} was built without the `dev-api` feature. Another \
                 cargo build with other features replaced it; rebuild it with \
                 `touch src/main.rs && cargo build --features test-hooks`"
            );
        }
        let value = serde_json::from_str(&text).unwrap_or(Value::String(text));
        Ok((status, value))
    }

    pub fn get(&self, id: usize, path: &str) -> (u16, Value) {
        self.try_call(id, "GET", path, None)
            .unwrap_or_else(|err| self.fail(&format!("GET {path} on node {id}: {err}")))
    }

    pub fn post(&self, id: usize, path: &str, body: &Value) -> (u16, Value) {
        self.try_call(id, "POST", path, Some(body))
            .unwrap_or_else(|err| self.fail(&format!("POST {path} on node {id}: {err}")))
    }

    /// Height of node `id`, if it answers.
    pub fn height(&self, id: usize) -> Option<u64> {
        match self.try_call(id, "GET", "/status", None) {
            Ok((200, status)) => status["height"].as_u64(),
            _ => None,
        }
    }

    /// Poll `condition` until it holds; fail with diagnostics after [DEADLINE].
    pub fn wait_until(&self, what: &str, mut condition: impl FnMut() -> bool) {
        let start = Instant::now();
        while !condition() {
            if start.elapsed() > DEADLINE {
                self.fail(&format!("timed out waiting for {what}"));
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// Wait until every given node reports itself ready (`GET /ready` is `200`): it applied a
    /// block since it started, knows of no finalized block it has not applied, and sees consensus
    /// progress.
    pub fn wait_for_ready(&self, nodes: &[usize]) {
        for &id in nodes {
            self.wait_until(&format!("node {id} ready"), || {
                matches!(self.try_call(id, "GET", "/ready", None), Ok((200, _)))
            });
        }
    }

    /// Readiness of node `id` (`GET /ready`, whatever its code).
    pub fn readiness(&self, id: usize) -> Value {
        match self.try_call(id, "GET", "/ready", None) {
            Ok((200 | 503, body)) => body,
            other => panic!("node {id}: no readiness: {other:?}"),
        }
    }

    pub fn all(&self) -> Vec<usize> {
        (0..self.len()).collect()
    }

    pub fn start_dkg(&self, via: usize, name: &str) -> Value {
        let (status, body) = self.post(via, "/dkg/start", &json!({ "ceremony_id": name }));
        assert_eq!(status, 200, "{body}");
        body
    }

    /// Wait until every given node reports the ceremony completed with its share stored; return
    /// the (common) group public key.
    pub fn wait_for_dkg(&self, name: &str, nodes: &[usize]) -> String {
        let mut keys = Vec::new();
        for &id in nodes {
            let mut key = None;
            self.wait_until(&format!("ceremony {name} on node {id}"), || {
                let (status, body) = self.get(id, &format!("/dkg/status/{name}"));
                if status == 200 && body["status"] == "completed" && body["share"] == "stored" {
                    key = body["public_key"].as_str().map(str::to_string);
                }
                key.is_some()
            });
            keys.push(key.unwrap());
        }
        assert!(keys.windows(2).all(|pair| pair[0] == pair[1]), "{keys:?}");
        keys.pop().unwrap()
    }

    /// Start the ceremony `name` as an Ethereum validator key.
    pub fn start_validator_dkg(&self, via: usize, name: &str) -> Value {
        let body = json!({ "ceremony_id": name, "validator": true });
        let (status, body) = self.post(via, "/dkg/start", &body);
        assert_eq!(status, 200, "{body}");
        assert_eq!(body["validator"], true, "{body}");
        body
    }

    /// `POST /api/v1/eth2/sign/{key}` on node `via`, as Lighthouse sends it (`Accept:
    /// application/json`): status and JSON body.
    pub fn eth2_sign(&self, via: usize, key: &str, body: &Value) -> (u16, Value) {
        let path = format!("/api/v1/eth2/sign/{key}");
        let (status, _, text) = self
            .eth2_call(via, &path, &[("Accept", "application/json")], body)
            .unwrap_or_else(|err| self.fail(&format!("POST {path} on node {via}: {err}")));
        let value = serde_json::from_str(&text).unwrap_or(Value::String(text));
        (status, value)
    }

    /// `POST path` on node `via` with extra headers: status, `Content-Type` and raw body.
    pub fn eth2_call(
        &self,
        via: usize,
        path: &str,
        headers: &[(&str, &str)],
        body: &Value,
    ) -> std::io::Result<(u16, String, String)> {
        http::request_typed(
            self.http_addr(via),
            "POST",
            path,
            headers,
            Some(&body.to_string()),
            HTTP_TIMEOUT,
        )
    }

    /// `POST /sign` on node `via`.
    pub fn sign(&self, via: usize, ceremony: &str, nonce: u64, root: [u8; 32]) -> (u16, Value) {
        self.post(via, "/sign", &sign_body(ceremony, nonce, root))
    }

    /// Fail the test with the state of every node.
    pub fn fail(&self, message: &str) -> ! {
        panic!("{message}\n{}", self.diagnostics());
    }

    fn diagnostics(&self) -> String {
        let mut out = format!("test network directory: {}\n", self.dir.display());
        let mut nodes = self
            .nodes
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for (id, node) in nodes.iter_mut().enumerate() {
            let state = match node.child.as_mut().map(Child::try_wait) {
                Some(Ok(None)) => "running".to_string(),
                Some(Ok(Some(status))) => format!("exited: {status}"),
                Some(Err(err)) => format!("unknown: {err}"),
                None => "stopped".to_string(),
            };
            let log = fs::read_to_string(self.log_path(id)).unwrap_or_default();
            let lines: Vec<&str> = log.lines().collect();
            let tail = lines[lines.len().saturating_sub(25)..].join("\n");
            out.push_str(&format!(
                "--- node {id} ({state}), last log lines:\n{tail}\n"
            ));
        }
        out
    }
}

impl Drop for TestNetwork {
    fn drop(&mut self) {
        let failed = std::thread::panicking();
        if failed {
            eprintln!("{}", self.diagnostics());
        }
        let mut nodes = self
            .nodes
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for node in nodes.iter_mut() {
            node.stdin = None;
            if let Some(mut child) = node.child.take() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
        if failed || std::env::var_os("E2E_KEEP").is_some() {
            eprintln!("kept {}", self.dir.display());
        } else {
            let _ = fs::remove_dir_all(&self.dir);
        }
    }
}

fn signal(pid: u32, signal: &str) {
    let status = Command::new("kill")
        .args([signal, &pid.to_string()])
        .status()
        .unwrap();
    assert!(status.success(), "kill {signal} {pid}");
}

/// Recursive copy, preserving permissions.
pub fn copy_dir(from: &std::path::Path, to: &std::path::Path) {
    fs::create_dir_all(to).unwrap();
    fs::set_permissions(to, fs::metadata(from).unwrap().permissions()).unwrap();
    for entry in fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), &target).unwrap();
        }
    }
}

pub fn sign_body(ceremony: &str, nonce: u64, root: [u8; 32]) -> Value {
    json!({
        "ceremony_id": ceremony,
        "nonce": nonce,
        "payload_hash": format!("0x{}", hex::encode(root)),
    })
}

pub fn unhex(value: &Value) -> Vec<u8> {
    let text = value.as_str().expect("hex string");
    hex::decode(text.strip_prefix("0x").unwrap_or(text)).expect("valid hex")
}

/// Verify like an Ethereum consensus client: blst, minimal-pubkey-size, POP ciphersuite DST,
/// key validation and signature subgroup check.
pub fn ethereum_verify(public_key: &Value, root: &[u8; 32], signature: &Value) -> bool {
    let Ok(key) = EthPublicKey::key_validate(&unhex(public_key)) else {
        return false;
    };
    let signature = unhex(signature);
    if signature.len() != 96 {
        return false;
    }
    let Ok(signature) = EthSignature::sig_validate(&signature, true) else {
        return false;
    };
    signature.verify(true, root, ETHEREUM_DST, &[], &key, true) == BLST_ERROR::BLST_SUCCESS
}

pub fn root(byte: u8) -> [u8; 32] {
    [byte; 32]
}
