//! Fake Roughtime servers for tests (`test-hooks` builds): RFC 10049 answers signed by keys of
//! their own, with a time that tests can shift. Never in a deployment.

use super::{Config, FORMAT, Server, roughtime};
use aws_lc_rs::{
    digest::{SHA512, digest},
    rand::SystemRandom,
    signature::{Ed25519KeyPair, KeyPair as _},
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use std::{
    net::{SocketAddr, UdpSocket},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicI64, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

/// A fake server's keys and behaviour.
pub struct Keys {
    long_term: Ed25519KeyPair,
    delegated: Ed25519KeyPair,
}

impl Keys {
    pub fn generate() -> Self {
        let generate = || {
            let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).expect("a key");
            Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("a key")
        };
        Self {
            long_term: generate(),
            delegated: generate(),
        }
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.long_term
            .public_key()
            .as_ref()
            .try_into()
            .expect("32 bytes")
    }
}

/// How a fake server answers.
pub struct Behaviour {
    /// Seconds added to the true time.
    pub offset: AtomicI64,
    /// Whether it answers at all.
    pub answering: AtomicBool,
}

impl Default for Behaviour {
    fn default() -> Self {
        Self {
            offset: AtomicI64::new(0),
            answering: AtomicBool::new(true),
        }
    }
}

fn message(mut pairs: Vec<(&[u8; 4], Vec<u8>)>) -> Vec<u8> {
    pairs.sort_by_key(|(tag, _)| u32::from_le_bytes(**tag));
    let mut out = (pairs.len() as u32).to_le_bytes().to_vec();
    let mut offset = 0u32;
    for (index, (_, value)) in pairs.iter().enumerate() {
        if index > 0 {
            out.extend_from_slice(&offset.to_le_bytes());
        }
        offset += value.len() as u32;
    }
    for (tag, _) in &pairs {
        out.extend_from_slice(tag.as_slice());
    }
    for (_, value) in &pairs {
        out.extend_from_slice(value);
    }
    out
}

/// The RFC answer to `request` (a whole packet) at `seconds` (Unix), radius 1 s; `None` if the
/// request carries no nonce.
pub fn answer(keys: &Keys, request: &[u8], seconds: u64) -> Option<Vec<u8>> {
    let nonce = find_nonce(request)?;
    let leaf = digest(&SHA512, &[&[0x00][..], request].concat());
    let root = &leaf.as_ref()[..32];
    let srep = message(vec![
        (b"VER\0", 1u32.to_le_bytes().to_vec()),
        (b"RADI", 1u32.to_le_bytes().to_vec()),
        (b"MIDP", seconds.to_le_bytes().to_vec()),
        (b"VERS", 1u32.to_le_bytes().to_vec()),
        (b"ROOT", root.to_vec()),
    ]);
    let dele = message(vec![
        (b"PUBK", keys.delegated.public_key().as_ref().to_vec()),
        (b"MINT", 0u64.to_le_bytes().to_vec()),
        (b"MAXT", u64::MAX.to_le_bytes().to_vec()),
    ]);
    let sign = |key: &Ed25519KeyPair, context: &[u8], value: &[u8]| {
        key.sign(&[context, value].concat()).as_ref().to_vec()
    };
    let cert = message(vec![
        (
            b"SIG\0",
            sign(
                &keys.long_term,
                b"Roughtime v1 delegation signature\0",
                &dele,
            ),
        ),
        (b"DELE", dele),
    ]);
    let response = message(vec![
        (
            b"SIG\0",
            sign(&keys.delegated, b"Roughtime v1 response signature\0", &srep),
        ),
        (b"NONC", nonce.to_vec()),
        (b"TYPE", 1u32.to_le_bytes().to_vec()),
        (b"PATH", Vec::new()),
        (b"SREP", srep),
        (b"CERT", cert),
        (b"INDX", 0u32.to_le_bytes().to_vec()),
    ]);
    let mut packet = b"ROUGHTIM".to_vec();
    packet.extend_from_slice(&(response.len() as u32).to_le_bytes());
    packet.extend_from_slice(&response);
    Some(packet)
}

/// The `NONC` of a request packet (no other check: a fake server).
fn find_nonce(request: &[u8]) -> Option<[u8; 32]> {
    let message = request.get(12..)?;
    let count = u32::from_le_bytes(message.get(..4)?.try_into().ok()?) as usize;
    let header = 8 * count;
    let values = message.get(header..)?;
    let offset = |i: usize| -> Option<usize> {
        if i == 0 {
            Some(0)
        } else if i == count {
            Some(values.len())
        } else {
            Some(u32::from_le_bytes(message.get(4 * i..4 * i + 4)?.try_into().ok()?) as usize)
        }
    };
    for i in 0..count {
        let tag = message.get(4 * count + 4 * i..4 * count + 4 * i + 4)?;
        if tag == b"NONC" {
            return values.get(offset(i)?..offset(i + 1)?)?.try_into().ok();
        }
    }
    None
}

/// A running fake server on a loopback UDP port.
pub struct FakeServer {
    pub address: SocketAddr,
    pub public_key: [u8; 32],
    pub behaviour: Arc<Behaviour>,
}

impl FakeServer {
    /// Start one on `127.0.0.1:0`, answering in a thread for the life of the process.
    pub fn start() -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("a UDP port");
        let address = socket.local_addr().expect("an address");
        let keys = Keys::generate();
        let public_key = keys.public_key();
        let behaviour = Arc::new(Behaviour::default());
        let shared = behaviour.clone();
        std::thread::spawn(move || {
            let mut buffer = [0u8; 2048];
            while let Ok((length, from)) = socket.recv_from(&mut buffer) {
                if !shared.answering.load(Ordering::SeqCst) {
                    continue;
                }
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("after the epoch")
                    .as_secs() as i64;
                let seconds = (now + shared.offset.load(Ordering::SeqCst)).max(0) as u64;
                if let Some(packet) = answer(&keys, &buffer[..length], seconds) {
                    let _ = socket.send_to(&packet, from);
                }
            }
        });
        Self {
            address,
            public_key,
            behaviour,
        }
    }

    pub fn server(&self, operator: &str) -> Server {
        Server {
            name: format!("fake-{}", self.address.port()),
            operator: operator.into(),
            address: self.address.to_string(),
            public_key: BASE64.encode(self.public_key),
        }
    }
}

/// A configuration of `servers`, one operator each.
pub fn config(servers: &[FakeServer], quorum: usize) -> Config {
    Config {
        format: FORMAT.into(),
        version: 1,
        quorum,
        max_age_seconds: 30,
        interval_seconds: 1,
        max_radius_seconds: 10,
        servers: servers
            .iter()
            .enumerate()
            .map(|(index, server)| server.server(&format!("operator-{index}")))
            .collect(),
    }
}

/// Re-exported for tests: the request format the client sends.
pub use roughtime::request;
