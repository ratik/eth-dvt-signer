//! The HTTP API of a default build (no `dev-api` feature): the Web3Signer API is served, the raw
//! signing API is not. One node process of a four-node network, without its peers: nothing here
//! needs consensus.

#![cfg(not(feature = "dev-api"))]

#[path = "e2e/harness/http.rs"]
#[allow(dead_code)]
mod http;

use serde_json::{Value, json};
use std::{
    net::{Ipv4Addr, SocketAddr, TcpListener},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

/// Node 0, killed and its data removed when dropped.
struct Node {
    child: Child,
    dir: PathBuf,
    http: SocketAddr,
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if std::thread::panicking() {
            eprintln!("kept {}", self.dir.display());
        } else {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }
}

fn free_port() -> u16 {
    TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

impl Node {
    fn start() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "eth-mpc-signer-production-api-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let (p2p, http) = (free_port(), free_port());
        let log = std::fs::File::create(dir.join("node.log")).unwrap();
        let child = Command::new(env!("CARGO_BIN_EXE_eth-mpc-signer"))
            .args(["--id", "0", "--participants", "4"])
            .args(["--p2p-port", &p2p.to_string()])
            .args(["--http-port", &http.to_string()])
            .arg("--data-dir")
            .arg(dir.join("data"))
            .stdin(Stdio::null())
            .stdout(Stdio::from(log.try_clone().unwrap()))
            .stderr(Stdio::from(log))
            .spawn()
            .unwrap();
        let node = Self {
            child,
            dir,
            http: SocketAddr::from((Ipv4Addr::LOCALHOST, http)),
        };
        let start = Instant::now();
        while !matches!(node.call("GET", "/upcheck", None), Ok((200, _))) {
            assert!(
                start.elapsed() < Duration::from_secs(60),
                "node did not serve HTTP: {}",
                std::fs::read_to_string(node.dir.join("node.log")).unwrap_or_default()
            );
            std::thread::sleep(Duration::from_millis(100));
        }
        node
    }

    fn call(
        &self,
        method: &str,
        path: &str,
        body: Option<&Value>,
    ) -> std::io::Result<(u16, String)> {
        let body = body.map(Value::to_string);
        http::request_with(
            self.http,
            method,
            path,
            &[("Accept", "application/json")],
            body.as_deref(),
            Duration::from_secs(10),
        )
    }
}

fn fixture(name: &str) -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/web3signer")
        .join(name);
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

#[test]
fn default_build_serves_no_raw_signing() {
    let node = Node::start();

    // The development API does not exist.
    let raw = json!({ "ceremony_id": "validator-001", "nonce": 1, "payload_hash": format!("0x{}", "aa".repeat(32)) });
    let (status, _) = node.call("POST", "/sign", Some(&raw)).unwrap();
    assert_eq!(status, 404);
    let (status, _) = node
        .call("GET", "/authorizations/validator-001/1", None)
        .unwrap();
    assert_eq!(status, 404);

    // The Web3Signer API does.
    let (status, body) = node.call("GET", "/api/v1/eth2/publicKeys", None).unwrap();
    assert_eq!((status, body.as_str()), (200, "[]"));
    let sign = format!("/api/v1/eth2/sign/0x{}", "ab".repeat(48));
    let (status, body) = node
        .call("POST", &sign, Some(&fixture("block_v2_electra.json")))
        .unwrap();
    assert_eq!(status, 404, "unknown key: {body}");
    let (status, body) = node
        .call("POST", &sign, Some(&json!({ "type": "BLOCK" })))
        .unwrap();
    assert_eq!(status, 400, "{body}");
}
