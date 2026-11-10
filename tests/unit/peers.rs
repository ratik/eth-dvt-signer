use super::*;
use commonware_cryptography::{Signer as _, ed25519::PrivateKey};

fn node(seed: u64, port: u16) -> (PublicKey, SocketAddr) {
    (
        PrivateKey::from_seed(seed).public_key(),
        SocketAddr::from(([10, 0, 0, 2], port)),
    )
}

#[test]
fn a_peers_file_round_trips() {
    let peers = Peers::new(vec![node(1, 3000), node(2, 3001), node(3, 3002)]).unwrap();
    let parsed = Peers::from_json(&peers.to_json()).unwrap();
    assert_eq!(parsed, peers);
    assert_eq!(parsed.len(), 3);
    assert_eq!(parsed.get(1), Some(&node(2, 3001)));
    assert_eq!(parsed.get(3), None);
}

#[test]
fn duplicates_and_malformed_entries_are_refused() {
    assert!(Peers::new(vec![node(1, 3000), node(1, 3001)]).is_err());
    assert!(Peers::new(vec![node(1, 3000), node(2, 3000)]).is_err());
    assert!(Peers::new(Vec::new()).is_err());

    let good = Peers::new(vec![node(1, 3000)]).unwrap().to_json();
    for (from, to) in [
        ("eth-mpc-signer/peers", "something-else"),
        ("10.0.0.2:3000", "10.0.0.2"),
        ("\"version\": 1", "\"version\": 2"),
        ("0x", "0xzz"),
    ] {
        let bad = good.replacen(from, to, 1);
        assert!(Peers::from_json(&bad).is_err(), "accepted {bad}");
    }
    let extra = good.replacen("\"nodes\"", "\"extra\": 1, \"nodes\"", 1);
    assert!(
        Peers::from_json(&extra).is_err(),
        "unknown fields are refused"
    );
}
