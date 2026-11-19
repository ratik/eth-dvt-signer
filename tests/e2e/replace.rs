//! R2-E2E: replacing a permanently lost keyholder (docs/resharing.md, R2) on real processes. The
//! committee A, B, C, D (nodes 0 to 3) is never reconfigured. D stops for good; E (node 4) joins as
//! a non-voting follower; A, B and C reshare the validator key to A, B, C and E. The key does not
//! change; E's share signs where C's would; consensus still needs every one of A, B and C.

use crate::{
    eth2::{CHAIN, activation, attestation, block, refused, signed, signing_root},
    follower::{FOLLOWER, VOTERS},
    harness::{TestNetwork, approvers, peer::FakePeer},
    import::{
        ACKNOWLEDGED, CEREMONY as IMPORTED, PUBKEY as IMPORTED_KEY, import_network_with,
        interchange, original_signature, split,
    },
    reshare::{
        acknowledgement, crash_at, dkg_status, generation_call, reshare_status, session,
        wait_generation,
    },
};
use commonware_codec::Encode as _;
use commonware_cryptography::{
    Signer as _,
    ed25519::{PrivateKey, PublicKey},
};
use commonware_utils::{TryCollect as _, ordered::Set};
use eth_dvt_signer::{
    dkg::ceremony::Membership,
    engine,
    types::{Command, Transaction},
};
use serde_json::{Value, json};
use std::{
    path::{Path, PathBuf},
    time::Duration,
};

const VALIDATOR: &str = "validator-r2";
/// The lost keyholder.
const D: usize = 3;
/// Its replacement, a follower.
const E: usize = FOLLOWER;
/// The keyholder whose partial signatures are switched off to show that E's count.
const C: usize = 2;
/// The new generation's keyholders.
const KEYHOLDERS: [usize; 4] = [0, 1, 2, E];

/// The approval file of node `node` (`--approved-reshares`).
fn approvals(dir: &Path, node: usize) -> PathBuf {
    dir.join(format!("approved-reshares-{node}"))
}

/// While it exists, C answers no partial-signature request (it keeps voting).
fn no_partials(dir: &Path) -> PathBuf {
    dir.join("no-partials-c")
}

fn approval_args(dir: &Path, node: usize) -> Vec<String> {
    if node < VOTERS {
        vec![
            "--approved-reshares".into(),
            approvals(dir, node).display().to_string(),
        ]
    } else {
        Vec::new()
    }
}

/// Node `node`'s consensus identity (`GET /identity`).
fn identity(network: &TestNetwork, node: usize) -> String {
    let (status, body) = network.get(node, "/identity");
    assert_eq!(status, 200, "{body}");
    body["identity"].as_str().unwrap().to_string()
}

/// A network about to replace D: the activated validator `key` signed some history with the
/// original committee; D is stopped for good; E runs as a follower and has applied everything.
/// The operators of A, B and C approved giving `key`'s shares to A, B, C, E.
pub(crate) struct Replacement {
    pub(crate) network: TestNetwork,
    dir: PathBuf,
    pub(crate) key: String,
    /// The generation replaced: its ceremony id and round.
    from: (String, u64),
}

impl Drop for Replacement {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }
}

fn test_dir(name: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "eth-mpc-signer-r2-{name}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Every node's environment: C's partial-signature switch, plus `env(node)`.
fn environment(
    dir: &Path,
    env: impl Fn(usize) -> Vec<(String, String)>,
) -> impl Fn(usize) -> Vec<(String, String)> {
    let switch = no_partials(dir);
    move |node| {
        let mut vars = env(node);
        if node == C {
            vars.push((
                "ETH_MPC_SIGNER_NO_PARTIALS_FILE".into(),
                switch.display().to_string(),
            ));
        }
        vars
    }
}

/// The R2 starting point with a DKG validator key ([VALIDATOR]); node `i` gets `env(i)` (E's applies
/// from its first start).
fn replacement_with(env: impl Fn(usize) -> Vec<(String, String)>) -> Replacement {
    let dir = test_dir("dkg");
    let args = dir.clone();
    let network = TestNetwork::start_with_followers(
        VOTERS,
        1,
        Vec::new(),
        move |node| approval_args(&args, node),
        environment(&dir, env),
        |node| node < VOTERS,
    );
    network.wait_for_ready(&network.voters());
    network.start_validator_dkg(0, VALIDATOR);
    let key = network.wait_for_dkg(VALIDATOR, &network.voters());
    let (status, activated) = network.approved(
        0,
        "activate",
        json!({ "public_key": key, "genesis_validators_root": CHAIN }),
    );
    assert_eq!(status, 200, "{activated}");
    for node in network.voters() {
        network.wait_until(&format!("activation on node {node}"), || {
            activation(&network, node, &key).is_some()
        });
    }
    // History signed by the original committee.
    signed(&network, 0, &key, &block(10, 1));
    signed(&network, 1, &key, &attestation(1, 2, 1));
    signed(&network, D, &key, &attestation(2, 5, 1));
    let round = dkg_status(&network, 0, VALIDATOR)["round"]
        .as_u64()
        .unwrap();
    lose_d_and_join_e(
        network,
        dir,
        key,
        (VALIDATOR.to_string(), round),
        &block(11, 1),
    )
}

pub(crate) fn replacement() -> Replacement {
    replacement_with(|_| Vec::new())
}

/// D stops for good; A, B, C keep signing (`probe`); E joins and catches up; A, B, C approve the
/// replacement.
fn lose_d_and_join_e(
    network: TestNetwork,
    dir: PathBuf,
    key: String,
    from: (String, u64),
    probe: &Value,
) -> Replacement {
    network.stop_node(D);
    signed(&network, 0, &key, probe);
    network.start_node(E);
    network.wait_for_ready(&[E]);
    network.wait_until("E to apply the validator's activation", || {
        activation(&network, E, &key).is_some()
    });
    let replacement = Replacement {
        network,
        dir,
        key,
        from,
    };
    for node in 0..3 {
        replacement.approve(node, &replacement.keyholders());
    }
    replacement
}

impl Replacement {
    /// Identities of the new keyholders.
    fn keyholders(&self) -> Vec<String> {
        KEYHOLDERS
            .iter()
            .map(|node| identity(&self.network, *node))
            .collect()
    }

    fn dealers(&self) -> Vec<String> {
        (0..3).map(|node| identity(&self.network, node)).collect()
    }

    /// Node `node`'s operator approves giving the key's shares to exactly `players`.
    fn approve(&self, node: usize, players: &[String]) {
        let line = format!("{} {}\n", self.key, players.join(","));
        let path = approvals(&self.dir, node);
        let mut text = std::fs::read_to_string(&path).unwrap_or_default();
        text.push_str(&line);
        std::fs::write(path, text).unwrap();
    }

    /// The replacement request: the active generation, dealers A, B, C, `players`.
    fn body(&self, name: &str, players: &[String]) -> Value {
        json!({
            "public_key": self.key,
            "ceremony_id": name,
            "from_round": self.from.1,
            "dealers": self.dealers(),
            "players": players,
        })
    }

    fn replace(&self, via: usize, name: &str) -> (u16, Value) {
        self.network
            .approved(via, "reshare", self.body(name, &self.keyholders()))
    }

    fn start(&self, via: usize, name: &str) -> Value {
        let (status, started) = self.replace(via, name);
        assert_eq!(status, 200, "{started}");
        started
    }

    /// Wait until each of `nodes` reports the reshare `name` in `state`.
    fn wait(&self, nodes: &[usize], name: &str, state: &str) {
        for &node in nodes {
            self.network
                .wait_until(&format!("reshare {name} {state} on node {node}"), || {
                    reshare_status(&self.network, node, name)["status"] == state
                });
        }
    }

    /// Activate the reshare `name` (every new share acknowledged) through A, and wait until every
    /// new keyholder signs with it.
    fn activate(&self, name: &str, generation: u64) {
        self.wait(&KEYHOLDERS, name, "ready");
        let (status, activated) = generation_call(&self.network, 0, "activate", &self.key, name);
        assert_eq!(status, 200, "{activated}");
        assert_eq!(activated["status"], "active", "{activated}");
        wait_generation(&self.network, &KEYHOLDERS, &self.key, (generation, name));
    }

    pub(crate) fn replace_and_activate(&self, name: &str) {
        self.start(0, name);
        self.activate(name, 1);
    }

    /// C stops answering partial-signature requests (it keeps voting), or answers again.
    fn c_signs(&self, signs: bool) {
        let switch = no_partials(&self.dir);
        if signs {
            let _ = std::fs::remove_file(switch);
        } else {
            std::fs::write(switch, b"").unwrap();
        }
    }

    /// The share indices whose partials produced the signature of `body` through `via`, from the
    /// coordinator's log.
    pub(crate) fn signers(&self, via: usize, body: &Value) -> Vec<u64> {
        let root = format!("0x{}", hex::encode(signing_root(body)));
        let log = self.network.log(via);
        let line = log
            .lines()
            .rfind(|line| line.contains("signed validator duty") && line.contains(&root))
            .unwrap_or_else(|| panic!("node {via} logged no signature of {root}"));
        let list = line
            .split("signers=[")
            .nth(1)
            .unwrap()
            .split(']')
            .next()
            .unwrap();
        list.split(',')
            .map(|index| index.trim().parse().unwrap())
            .collect()
    }

    /// Node `node`'s share index in the generation `name`.
    pub(crate) fn index(&self, node: usize, name: &str) -> u64 {
        dkg_status(&self.network, node, name)["participant_index"]
            .as_u64()
            .unwrap()
    }

    /// Sign `body` through A with C's partials switched off: the signature verifies, and the
    /// coordinator combined A's, B's and E's shares of generation `name`.
    fn signed_with_e(&self, name: &str, body: &Value) -> Value {
        self.c_signs(false);
        let signature = signed(&self.network, 0, &self.key, body);
        self.c_signs(true);
        let mut expected: Vec<u64> = [0, 1, E]
            .iter()
            .map(|node| self.index(*node, name))
            .collect();
        expected.sort_unstable();
        assert_eq!(self.signers(0, body), expected, "A, B and E signed, not C");
        signature
    }
}

/// R2-E2E-1: permanent loss of D. The key, signed with A, B, C, D, then A, B, C, is reshared by
/// A, B, C to A, B, C, E (D offline throughout) and activated: the public key is unchanged and A,
/// B, C, E sign with fresh shares of the new generation.
#[test]
fn r2_e2e_1_permanent_loss_of_d() {
    let r2 = replacement();
    let network = &r2.network;
    let g0 = dkg_status(network, 0, VALIDATOR);

    let started = r2.start(1, "approved.validator-r2-g1");
    assert_eq!(started["from_round"], g0["round"], "{started}");
    let sorted = |mut identities: Vec<String>| {
        identities.sort();
        json!(identities)
    };
    // As sets (the API lists them in share-index order).
    let listed = |field: &str| {
        sorted(
            started[field]
                .as_array()
                .unwrap()
                .iter()
                .map(|identity| identity.as_str().unwrap().to_string())
                .collect(),
        )
    };
    assert_eq!(listed("dealers"), sorted(r2.dealers()), "{started}");
    assert_eq!(listed("players"), sorted(r2.keyholders()), "{started}");
    r2.wait(&KEYHOLDERS, "approved.validator-r2-g1", "ready");
    // Not activated yet: the generation of A, B, C, D signs (with A, B, C).
    signed(network, 1, &r2.key, &block(12, 1));
    for node in KEYHOLDERS {
        assert_eq!(
            crate::reshare::generation(network, node, &r2.key),
            (0, VALIDATOR.to_string())
        );
    }
    r2.activate("approved.validator-r2-g1", 1);

    // The same public key, byte for byte; every verification share and the generation changed.
    let g1 = dkg_status(network, E, "approved.validator-r2-g1");
    assert_eq!(g1["public_key"], json!(r2.key));
    assert_eq!(g1["public_key"], g0["public_key"]);
    assert_ne!(g1["generation_id"], g0["generation_id"]);
    for (old, new) in g0["verification_shares"]
        .as_array()
        .unwrap()
        .iter()
        .zip(g1["verification_shares"].as_array().unwrap())
    {
        assert_ne!(old, new);
    }
    // Every new keyholder holds its share; A, B, C erased their old ones; E never had one.
    for node in KEYHOLDERS {
        assert_eq!(
            dkg_status(network, node, "approved.validator-r2-g1")["share"],
            "stored"
        );
    }
    for node in 0..3 {
        network.wait_until(&format!("node {node} to retire generation 0"), || {
            dkg_status(network, node, VALIDATOR)["share"] == "retired"
        });
    }
    assert_eq!(dkg_status(network, E, VALIDATOR)["share"], "pending");
    // E took part as a player only.
    assert!(
        network
            .log(E)
            .contains("not a dealer of this round: playing only")
    );

    // A, B, C, E sign: through each committee member.
    for (via, slot) in [(0, 13), (1, 14), (2, 15)] {
        signed(network, via, &r2.key, &block(slot, 1));
    }
    // E coordinates nothing: no signing API.
    let (status, body) = network.eth2_sign(E, &r2.key, &block(16, 1));
    assert_eq!(status, 403, "{body}");
}

/// R2-E2E-2: E actually replaces D. With C's partials switched off (C still votes: consensus
/// needs it), A, B and E sign; with E stopped as well, A and B alone cannot; E back, it signs again.
#[test]
fn r2_e2e_2_the_replacement_signs_in_place_of_c() {
    let r2 = replacement();
    let network = &r2.network;
    r2.replace_and_activate("approved.validator-r2-g1");

    let height = network.height(C).unwrap();
    r2.signed_with_e("approved.validator-r2-g1", &block(20, 1));
    r2.signed_with_e("approved.validator-r2-g1", &attestation(5, 6, 1));
    // C voted for those authorizations (no quorum without it), and still follows.
    assert!(network.height(C).unwrap() > height);
    assert!(network.count(C, "test hook: not answering a signing request") > 0);

    // A and B alone are below the threshold: no signature, whatever the coordinator.
    network.stop_node(E);
    r2.c_signs(false);
    let (status, answer) = network.eth2_sign(0, &r2.key, &block(21, 1));
    assert_ne!(status, 200, "{answer}");
    assert!(answer.get("signature").is_none(), "{answer}");
    r2.c_signs(true);

    // E back: the authorized duty is signed (the same authorization), with E's share.
    network.start_node(E);
    network.wait_for_ready(&[E]);
    r2.signed_with_e("approved.validator-r2-g1", &block(21, 1));
}

/// R2-E2E-3: E restarts after the activation (and after missing blocks), recovers its share from
/// its own storage and signs in C's place.
#[test]
fn r2_e2e_3_the_replacement_restarts() {
    let r2 = replacement();
    let network = &r2.network;
    r2.replace_and_activate("approved.validator-r2-g1");
    r2.signed_with_e("approved.validator-r2-g1", &block(30, 1));

    network.restart_node(E);
    network.wait_for_ready(&[E]);
    assert!(network.log(E).contains("loaded key share"));
    r2.signed_with_e("approved.validator-r2-g1", &block(31, 1));

    // Down while blocks are finalized, then back.
    network.stop_node(E);
    for slot in 32..35 {
        signed(network, 0, &r2.key, &block(slot, 1));
    }
    network.start_node(E);
    network.wait_for_ready(&[E]);
    r2.signed_with_e("approved.validator-r2-g1", &block(35, 1));
}

/// E crashes at `point` of the replacement, restarts without the hook, and the replacement
/// completes and activates; E's share signs in C's place.
fn e_crashes_at(point: &str) {
    let r2 = replacement_with(|node| {
        if node == E {
            crash_at(point)
        } else {
            Vec::new()
        }
    });
    let network = &r2.network;
    let started = r2.start(0, "approved.validator-r2-g1");
    if point == "after-apply-activation" {
        r2.wait(&[0, 1, 2], "approved.validator-r2-g1", "ready");
        let (status, activated) =
            generation_call(network, 0, "activate", &r2.key, "approved.validator-r2-g1");
        assert_eq!(status, 200, "{activated}");
    }
    assert!(!network.wait_exit(E).success());
    assert!(network.count(E, &format!("test hook: crashing at {point}")) > 0);
    // The generation of A, B, C, D still signs meanwhile, unless already replaced.
    if point != "after-apply-activation" {
        signed(network, 1, &r2.key, &block(40, 1));
        let status = reshare_status(network, 0, "approved.validator-r2-g1");
        assert_ne!(status["status"], "active", "{status}");
    }
    network.restart_node_with(E, Vec::new());
    network.wait_for_ready(&[E]);
    if point == "after-apply-activation" {
        wait_generation(
            network,
            &KEYHOLDERS,
            &r2.key,
            (1, "approved.validator-r2-g1"),
        );
    } else {
        r2.activate("approved.validator-r2-g1", 1);
    }
    assert_eq!(
        reshare_status(network, E, "approved.validator-r2-g1")["round"],
        started["round"]
    );
    r2.signed_with_e("approved.validator-r2-g1", &block(41, 1));
}

/// Before receiving its new share (it crashes when it joins the ceremony).
#[test]
fn r2_e2e_restart_e_before_its_share() {
    e_crashes_at("reshare-before-dealing");
}

/// After persisting its share, before its readiness is finalized.
#[test]
fn r2_e2e_restart_e_after_its_share_is_stored() {
    e_crashes_at("reshare-after-share-stored");
}

/// After submitting its readiness, before the activation.
#[test]
fn r2_e2e_restart_e_after_readiness() {
    e_crashes_at("reshare-after-ready");
}

/// While applying the activation (its state durable, its keyholder not told yet).
#[test]
fn r2_e2e_restart_e_during_activation() {
    e_crashes_at("after-apply-activation");
}

/// R2-E2E-4: invalid or stale membership. Malformed dealer and player sets and a stale generation
/// are refused; a replacement identity no operator approved gets no dealing at all and is
/// aborted; replayed messages (D's acknowledgement, a repeated start) change nothing; once the
/// replacement is active, a start naming the replaced generation is stale.
#[test]
fn r2_e2e_4_invalid_or_stale_membership() {
    let r2 = replacement();
    let network = &r2.network;
    let ids = r2.keyholders();
    let (a, b, c, e) = (&ids[0], &ids[1], &ids[2], &ids[3]);
    // D is stopped: its identity from its (development) key; F is no node at all.
    let seeded = |seed: u64| {
        format!(
            "0x{}",
            hex::encode(PrivateKey::from_seed(seed).public_key().encode())
        )
    };
    let (d, f) = (seeded(D as u64), seeded(5));
    let post = |body: Value| network.approved(0, "reshare", body);
    let with = |dealers: Vec<&String>, players: Vec<&String>| {
        let mut body = r2.body("approved.validator-r2-bad", &[]);
        body["dealers"] = json!(dealers);
        body["players"] = json!(players);
        body
    };
    for (body, expected) in [
        (with(vec![a, b, c], vec![a, b, e]), "exactly 4"),
        (with(vec![a, b, c], vec![a, b, c, &d, e]), "exactly 4"),
        (with(vec![a, b, e], vec![a, b, c, e]), "not a keyholder"),
        (with(vec![a, b], vec![a, b, c, e]), "at least 3"),
        (with(vec![a, b, c], vec![a, b, c, c]), "listed twice"),
        (
            with(vec![a, b, c], vec![a, b, c, &"0x1234".to_string()]),
            "ed25519",
        ),
    ] {
        let (status, refused) = post(body);
        assert_eq!(status, 400, "{refused}");
        assert!(
            refused["error"].as_str().unwrap().contains(expected),
            "{refused}"
        );
    }
    // Empty sets never reach consensus (a command with one would not decode).
    for field in ["dealers", "players"] {
        let mut empty = r2.body("approved.validator-r2-bad", &ids);
        empty[field] = json!([]);
        let (status, refused) = post(empty);
        assert_eq!(status, 400, "{refused}");
        assert!(
            refused["error"].as_str().unwrap().contains("1 to 64"),
            "{refused}"
        );
    }
    let mut partial = r2.body("approved.validator-r2-bad", &ids);
    partial.as_object_mut().unwrap().remove("dealers");
    assert_eq!(post(partial).0, 400);
    let mut stale = r2.body("approved.validator-r2-bad", &ids);
    stale["from_round"] = json!(99);
    let (status, refused) = post(stale);
    assert_eq!(status, 409, "{refused}");
    assert!(
        refused["error"]
            .as_str()
            .unwrap()
            .contains("not the key's active generation")
    );
    // Nothing was started by the refused requests: the id is still unknown.
    assert_eq!(
        network.get(0, "/validators/reshare/validator-r2-bad").0,
        404
    );

    // An unapproved replacement identity (F, approved by no operator): accepted by consensus,
    // dealt by nobody. No dealer log, no dealing; then aborted, the old generation signs.
    let (status, started) = post(r2.body(
        "approved.validator-r2-f",
        &[a.clone(), b.clone(), c.clone(), f],
    ));
    assert_eq!(status, 200, "{started}");
    let round = started["round"].as_u64().unwrap();
    for node in 0..3 {
        network.wait_until(&format!("node {node} to refuse dealing"), || {
            network.count(
                node,
                "reshare to new keyholders not approved here: not dealing",
            ) > 0
        });
    }
    let at = network.height(0).unwrap();
    network.wait_until("blocks after the start", || {
        network.height(0).is_some_and(|height| height >= at + 4)
    });
    let status = reshare_status(network, 0, "approved.validator-r2-f");
    assert_eq!(status["status"], "in_progress", "{status}");
    assert_eq!(status["dealer_logs"], json!([]), "{status}");
    for node in 0..3 {
        assert!(!network.log(node).lines().any(|line| {
            line.contains("submitting dealer log") && line.contains(&format!("round={round}"))
        }));
    }
    let (code, aborted) = generation_call(network, 1, "abort", &r2.key, "approved.validator-r2-f");
    assert_eq!(code, 200, "{aborted}");
    signed(network, 2, &r2.key, &block(50, 1));

    // The approved replacement, with replays from D's identity (a scripted peer in its place):
    // its acknowledgement is not a keyholder's; the start again, bare, is dropped for want of
    // approvals, and with its approvals, for its used nonce (P0); through the API, `409`.
    let approved = network.signed(
        "reshare",
        r2.body("approved.validator-r2-g1", &r2.keyholders()),
        network.next_nonce(),
        &[0, 1],
    );
    let (status, started) = network.post_signed(0, &approved);
    assert_eq!(status, 200, "{started}");
    let round = started["round"].as_u64().unwrap();
    let peer = FakePeer::start(network, D, &[], Box::new(|_, _, _| Vec::new()));
    let d_ack = acknowledgement(D as u64, round, session(&started), 7);
    let keys = |seeds: &[u64]| -> Set<PublicKey> {
        seeds
            .iter()
            .map(|seed| PrivateKey::from_seed(*seed).public_key())
            .try_collect()
            .unwrap()
    };
    let membership = Membership {
        from: r2.from.1,
        dealers: keys(&[0, 1, 2]),
        players: keys(&[0, 1, 2, E as u64]),
    };
    let bare = Transaction {
        id: 8,
        command: Command::StartResharing {
            validator: hex::decode(r2.key.trim_start_matches("0x"))
                .unwrap()
                .try_into()
                .unwrap(),
            ceremony: eth_dvt_signer::dkg::CeremonyId::new("approved.validator-r2-g1").unwrap(),
            membership: Some(Box::new(membership)),
        },
    }
    .encode()
    .to_vec();
    let replayed = Transaction {
        id: 9,
        command: Command::Admin(Box::new(approved.authorized(&approvers()).unwrap())),
    }
    .encode()
    .to_vec();
    r2.wait(&KEYHOLDERS, "approved.validator-r2-g1", "ready");
    network.wait_until("node 0 to ignore the replays", || {
        peer.send_on(engine::MEMPOOL_CHANNEL, 0, d_ack.clone());
        peer.send_on(engine::MEMPOOL_CHANNEL, 0, bare.clone());
        peer.send_on(engine::MEMPOOL_CHANNEL, 0, replayed.clone());
        let log = network.log(0);
        log.lines().any(|line| {
            line.contains("ignored share acknowledgement") && line.contains("not a participant")
        }) && log.lines().any(|line| {
            line.contains("dropping a transaction id=8")
                && line.contains("a protected command without approvals")
        }) && log.lines().any(|line| {
            line.contains("id=9") && line.contains("protected command whose nonce is used")
        })
    });
    drop(peer);
    let (status, answer) = network.post_signed(1, &approved);
    assert_eq!(status, 409, "{answer}");
    assert!(
        !network
            .log(0)
            .lines()
            .any(|line| line.contains("applied reshare start") && line.contains("Exists")),
        "a replay applied"
    );
    let status = reshare_status(network, 0, "approved.validator-r2-g1");
    assert_eq!(
        status["ready_shares"].as_array().unwrap().len(),
        4,
        "{status}"
    );
    r2.activate("approved.validator-r2-g1", 1);
    // The replaced generation is no longer the active one: a new start naming it is stale.
    let (status, refused) = r2.replace(0, "approved.validator-r2-g2");
    assert_eq!(status, 409, "{refused}");
    assert!(
        refused["error"]
            .as_str()
            .unwrap()
            .contains("not the key's active generation")
    );
    r2.signed_with_e("approved.validator-r2-g1", &block(51, 1));
}

/// R2-E2E-5: a replacement interrupted before its activation (E down mid-ceremony) is aborted;
/// the old generation keeps signing with A, B and C; a new replacement then completes.
#[test]
fn r2_e2e_5_aborted_replacement() {
    let r2 = replacement_with(|node| {
        if node == E {
            crash_at("reshare-after-first-dealing")
        } else {
            Vec::new()
        }
    });
    let network = &r2.network;
    r2.start(0, "approved.validator-r2-g1");
    assert!(!network.wait_exit(E).success());
    std::thread::sleep(Duration::from_secs(2));
    let status = reshare_status(network, 0, "approved.validator-r2-g1");
    assert_eq!(status["status"], "in_progress", "{status}");
    let (code, early) =
        generation_call(network, 0, "activate", &r2.key, "approved.validator-r2-g1");
    assert_eq!(
        (code, early["refusal"]["reason"].as_str()),
        (409, Some("not_completed")),
        "{early}"
    );
    let (code, aborted) = generation_call(network, 1, "abort", &r2.key, "approved.validator-r2-g1");
    assert_eq!(code, 200, "{aborted}");
    r2.wait(&[0, 1, 2], "approved.validator-r2-g1", "aborted");

    // The old generation, with A, B and C (D lost, E not a keyholder of it): C's share is needed.
    let body = block(60, 1);
    signed(network, 0, &r2.key, &body);
    let mut expected: Vec<u64> = (0..3).map(|node| r2.index(node, VALIDATOR)).collect();
    expected.sort_unstable();
    assert_eq!(r2.signers(0, &body), expected);
    assert_eq!(
        crate::reshare::generation(network, 0, &r2.key),
        (0, VALIDATOR.to_string())
    );

    // E back (it learns of the abort, its dealings of that round erased), then a new replacement.
    network.restart_node_with(E, Vec::new());
    network.wait_for_ready(&[E]);
    r2.wait(&[E], "approved.validator-r2-g1", "aborted");
    r2.start(0, "approved.validator-r2-g2");
    r2.activate("approved.validator-r2-g2", 1);
    r2.signed_with_e("approved.validator-r2-g2", &block(61, 1));
}

/// R2-E2E-6: slashing protection across the replacement, for a DKG key (its whole history) and an
/// imported key (its imported floors too).
#[test]
fn r2_e2e_6_slashing_protection_continuity() {
    // DKG key: history signed by A, B, C, D (blocks at slot 10, attestations 1-2 and 2-5).
    let r2 = replacement();
    let network = &r2.network;
    let first = network.eth2_sign(0, &r2.key, &block(10, 1)).1["signature"].clone();
    r2.replace_and_activate("approved.validator-r2-g1");
    r2.c_signs(false);
    assert_eq!(signed(network, 1, &r2.key, &block(10, 1)), first);
    refused(network, 0, &r2.key, &block(10, 2), "double_proposal");
    refused(network, 1, &r2.key, &attestation(1, 2, 2), "double_vote");
    refused(
        network,
        2,
        &r2.key,
        &attestation(0, 6, 1),
        "surrounds_signed",
    );
    refused(
        network,
        0,
        &r2.key,
        &attestation(3, 4, 1),
        "surrounded_by_signed",
    );
    r2.c_signs(true);
    r2.signed_with_e("approved.validator-r2-g1", &block(70, 1));
    drop(r2);

    // Imported key, with an imported history (floors at slot 100, epochs 10 and 11).
    let (network, dir) = import_network_with(1, approval_args, |dir, node| {
        environment(dir, |_| Vec::new())(node)
    });
    network.wait_for_ready(&network.voters());
    let (manifest, envelopes) = split(&network, &dir, IMPORTED, "shares");
    assert_eq!(
        network
            .approved(0, "register-import", json!({ "manifest": manifest }))
            .0,
        200
    );
    for (node, envelope) in envelopes.iter().enumerate() {
        network.wait_until(&format!("the registration on node {node}"), || {
            network.get(node, &format!("/keys/import/{IMPORTED}")).0 == 200
        });
        let (status, installed) = network.post(node, "/keys/import/share", envelope);
        assert_eq!(status, 200, "{installed}");
    }
    let history = interchange(
        IMPORTED_KEY,
        CHAIN,
        json!([{"slot": "100"}]),
        json!([{"source_epoch": "10", "target_epoch": "11"}]),
    );
    let (status, imported) = network.approved(1, "import-history", json!({"interchange": history}));
    assert_eq!(status, 200, "{imported}");
    network.wait_until("every share acknowledged", || {
        let (_, status) = network.get(0, &format!("/keys/import/{IMPORTED}"));
        status["ready_shares"]
            .as_array()
            .is_some_and(|ready| ready.len() == VOTERS)
    });
    let acknowledgment: Value = serde_json::from_str(ACKNOWLEDGED).unwrap();
    let (status, activated) = network.approved(
        0,
        "activate",
        json!({"public_key": IMPORTED_KEY, "genesis_validators_root": CHAIN, "acknowledgment": acknowledgment}),
    );
    assert_eq!(status, 200, "{activated}");
    for node in network.voters() {
        network.wait_until(&format!("activation on node {node}"), || {
            activation(&network, node, IMPORTED_KEY).is_some()
        });
    }
    let before = block(101, 1);
    assert_eq!(
        signed(&network, 0, IMPORTED_KEY, &before),
        json!(original_signature(&signing_root(&before)))
    );
    let round = dkg_status(&network, 0, IMPORTED)["round"].as_u64().unwrap();
    let r2 = lose_d_and_join_e(
        network,
        dir,
        IMPORTED_KEY.to_string(),
        (IMPORTED.to_string(), round),
        &block(102, 1),
    );
    let network = &r2.network;
    r2.replace_and_activate("approved.imported-r2");
    let reshared = activation(network, 0, IMPORTED_KEY).unwrap();
    assert_eq!(reshared["origin"], "imported", "{reshared}");
    // Still the original key's signatures, now with E's share in C's place.
    let after = block(103, 1);
    assert_eq!(
        r2.signed_with_e("approved.imported-r2", &after),
        json!(original_signature(&signing_root(&after)))
    );
    // The imported floors and the import state stay.
    refused(
        network,
        1,
        IMPORTED_KEY,
        &block(100, 1),
        "block_at_or_below_imported",
    );
    refused(
        network,
        0,
        IMPORTED_KEY,
        &attestation(10, 11, 1),
        "target_at_or_below_imported",
    );
    let (_, status) = network.get(1, &format!("/keys/import/{IMPORTED}"));
    assert_eq!(
        status["history"]["floors"],
        json!({"block_slot": 100, "source_epoch": 10, "target_epoch": 11}),
        "{status}"
    );
}
