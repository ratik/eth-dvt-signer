//! Operator tool for consensus reconfiguration (R3, docs/reconfiguration.md): replace a lost
//! consensus voter with a follower, follow the switch to the next epoch, and help nodes left
//! behind. It only talks to the nodes' HTTP APIs; it never starts, stops or restarts a process
//! (each node exits by itself at the end of its epoch, status 75, and its supervisor restarts it).
//!
//! ```sh
//! mpc-admin --nodes 127.0.0.1:8080,127.0.0.1:8081,127.0.0.1:8082,127.0.0.1:8083,127.0.0.1:8084 status
//! mpc-admin --nodes ... replace-node --old 3 --new 4
//! mpc-admin --nodes ... resume
//! ```
//!
//! Nothing the tool does decides safety: the switch is a block finalized by the current committee,
//! after which no honest node builds or votes for anything in that epoch. Running it twice, or
//! after it was interrupted, is harmless: `replace-node` refuses once the epoch ended, and
//! `resume` only reads and asks lagging nodes to fetch the block that ended their epoch.

use clap::{Parser, Subcommand};
use commonware_cryptography::{Signer as _, ed25519::PrivateKey};
use serde_json::{Value, json};
use std::{
    io::{self, Read as _, Write as _},
    net::{SocketAddr, TcpStream, ToSocketAddrs as _},
    process::ExitCode,
    thread::sleep,
    time::{Duration, Instant},
};

#[derive(Parser)]
#[command(about = "Replace a consensus voter (docs/reconfiguration.md)")]
struct Args {
    /// Every node's HTTP API, `host:port` (comma separated), the lost one included.
    #[arg(long, value_delimiter = ',', required = true)]
    nodes: Vec<String>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Each node's consensus epoch, height and role.
    Status,
    /// End the current epoch, replacing the voter `old` with the follower `new`, and follow the
    /// switch until the next epoch finalizes blocks.
    ReplaceNode {
        /// The voter to remove: a node index (development keys) or a `0x` consensus identity.
        #[arg(long)]
        old: String,
        /// The follower to add, as `old`.
        #[arg(long)]
        new: String,
        /// Seconds to wait for the switch.
        #[arg(long, default_value_t = 600)]
        wait: u64,
    },
    /// Help a switch that did not complete: ask nodes left in an earlier epoch to fetch the block
    /// that ended it, and tell whether the current epoch's last block is stuck unfinalized.
    Resume {
        /// Seconds to watch for an unfinalized last block.
        #[arg(long, default_value_t = 30)]
        stall: u64,
    },
}

const TIMEOUT: Duration = Duration::from_secs(10);
const POLL: Duration = Duration::from_secs(1);

fn main() -> ExitCode {
    let args = Args::parse();
    let nodes: Vec<Node> = match args.nodes.iter().map(|node| Node::new(node)).collect() {
        Ok(nodes) => nodes,
        Err(err) => {
            eprintln!("error: {err}");
            return ExitCode::FAILURE;
        }
    };
    let result = match args.command {
        Command::Status => status(&nodes),
        Command::ReplaceNode { old, new, wait } => replace(&nodes, &old, &new, wait),
        Command::Resume { stall } => resume(&nodes, stall),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}

/// One node's HTTP API.
struct Node {
    name: String,
    addr: SocketAddr,
}

/// What a node says about its consensus epoch.
#[derive(Clone, Debug)]
struct View {
    epoch: u64,
    committee: Vec<String>,
    candidates: Vec<String>,
    voting: bool,
    height: u64,
    /// The current epoch's last block, once the node saw it.
    ended_at: Option<u64>,
    /// `(epoch, boundary)` of every epoch the node knows.
    boundaries: Vec<(u64, u64)>,
    identity: String,
}

impl Node {
    fn new(spec: &str) -> Result<Self, String> {
        let address = spec.strip_prefix("http://").unwrap_or(spec);
        let addr = address
            .to_socket_addrs()
            .ok()
            .and_then(|mut addrs| addrs.next())
            .ok_or_else(|| format!("{spec} is not host:port"))?;
        Ok(Self {
            name: address.to_string(),
            addr,
        })
    }

    fn call(&self, method: &str, path: &str, body: Option<&Value>) -> io::Result<(u16, Value)> {
        let body = body.map(Value::to_string).unwrap_or_default();
        let mut stream = TcpStream::connect_timeout(&self.addr, Duration::from_secs(2))?;
        stream.set_read_timeout(Some(TIMEOUT))?;
        stream.set_write_timeout(Some(TIMEOUT))?;
        write!(
            stream,
            "{method} {path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\
             Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            self.addr,
            body.len()
        )?;
        let mut raw = Vec::new();
        stream.read_to_end(&mut raw)?;
        let text = String::from_utf8_lossy(&raw);
        let invalid = |what: &str| io::Error::new(io::ErrorKind::InvalidData, what.to_string());
        let (head, body) = text
            .split_once("\r\n\r\n")
            .ok_or_else(|| invalid("no end of headers"))?;
        let status = head
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|code| code.parse().ok())
            .ok_or_else(|| invalid("bad status line"))?;
        let chunked = head
            .to_ascii_lowercase()
            .contains("transfer-encoding: chunked");
        let body = if chunked {
            dechunk(body).ok_or_else(|| invalid("bad chunked body"))?
        } else {
            body.to_string()
        };
        Ok((
            status,
            serde_json::from_str(&body).unwrap_or(Value::String(body)),
        ))
    }

    fn get(&self, path: &str) -> Option<Value> {
        match self.call("GET", path, None) {
            Ok((200, value)) => Some(value),
            _ => None,
        }
    }

    /// The node's view, or `None` if it does not answer.
    fn view(&self) -> Option<View> {
        let consensus = self.get("/consensus")?;
        let status = self.get("/status")?;
        let identity = self.get("/identity")?;
        let strings = |value: &Value| -> Vec<String> {
            value
                .as_array()
                .map(|items| {
                    items
                        .iter()
                        .filter_map(|item| item.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default()
        };
        Some(View {
            epoch: consensus["epoch"]["epoch"].as_u64()?,
            committee: strings(&consensus["epoch"]["committee"]),
            candidates: strings(&consensus["candidates"]),
            voting: consensus["voting"].as_bool().unwrap_or(false),
            height: status["height"].as_u64().unwrap_or(0),
            ended_at: consensus["ended_at"].as_u64(),
            boundaries: consensus["epochs"]
                .as_array()
                .map(|epochs| {
                    epochs
                        .iter()
                        .filter_map(|epoch| {
                            Some((epoch["epoch"].as_u64()?, epoch["boundary"].as_u64()?))
                        })
                        .collect()
                })
                .unwrap_or_default(),
            identity: identity["identity"].as_str()?.to_string(),
        })
    }
}

fn dechunk(mut body: &str) -> Option<String> {
    let mut out = String::new();
    loop {
        let (size, rest) = body.split_once("\r\n")?;
        let size = usize::from_str_radix(size.trim(), 16).ok()?;
        if size == 0 {
            return Some(out);
        }
        out.push_str(rest.get(..size)?);
        body = rest.get(size + 2..).unwrap_or("");
    }
}

/// A consensus identity: a node index (its development key) or `0x`-hex.
fn identity(value: &str) -> Result<String, String> {
    if let Ok(index) = value.parse::<u64>() {
        let key = PrivateKey::from_seed(index).public_key();
        return Ok(format!(
            "0x{}",
            hex::encode(commonware_codec::Encode::encode(&key))
        ));
    }
    let hex = value.strip_prefix("0x").unwrap_or(value);
    match hex::decode(hex) {
        Ok(bytes) if bytes.len() == 32 => Ok(format!("0x{hex}")),
        _ => Err(format!(
            "{value} is neither a node index nor a 0x consensus identity"
        )),
    }
}

fn short(identity: &str) -> &str {
    identity.get(..10).unwrap_or(identity)
}

fn views(nodes: &[Node]) -> Vec<(&Node, Option<View>)> {
    nodes.iter().map(|node| (node, node.view())).collect()
}

fn status(nodes: &[Node]) -> Result<(), String> {
    for (node, view) in views(nodes) {
        match view {
            Some(view) => println!(
                "{:<22} {}  epoch {}  height {}  {}{}",
                node.name,
                short(&view.identity),
                view.epoch,
                view.height,
                if view.voting { "voter" } else { "follower" },
                view.ended_at
                    .map(|height| format!("  epoch ended at block {height}"))
                    .unwrap_or_default()
            ),
            None => println!("{:<22} not answering", node.name),
        }
    }
    Ok(())
}

fn replace(nodes: &[Node], old: &str, new: &str, wait: u64) -> Result<(), String> {
    let (old, new) = (identity(old)?, identity(new)?);
    let views = views(nodes);
    let answering: Vec<(&Node, View)> = views
        .iter()
        .filter_map(|(node, view)| view.clone().map(|view| (*node, view)))
        .collect();
    let Some((_, first)) = answering.first() else {
        return Err("no node answers".into());
    };

    // Prepare: every answering node in the same epoch, with the same committee.
    if let Some((node, view)) = answering
        .iter()
        .find(|(_, view)| view.epoch != first.epoch || view.committee != first.committee)
    {
        return Err(format!(
            "{} runs epoch {} while another runs epoch {}: finish that switch first (mpc-admin \
             resume)",
            node.name, view.epoch, first.epoch
        ));
    }
    if let Some(height) = answering.iter().find_map(|(_, view)| view.ended_at) {
        return Err(format!(
            "epoch {} already ended with block {height}: use mpc-admin resume",
            first.epoch
        ));
    }
    if !first.committee.contains(&old) {
        return Err(format!(
            "{} is not a voter of epoch {}",
            short(&old),
            first.epoch
        ));
    }
    if first.committee.contains(&new) {
        return Err(format!("{} is already a voter", short(&new)));
    }
    if !first.candidates.contains(&new) {
        return Err(format!("{} is not a configured follower", short(&new)));
    }
    let tip = answering
        .iter()
        .map(|(_, view)| view.height)
        .max()
        .unwrap_or(0);
    let mut warnings = Vec::new();
    match answering.iter().find(|(_, view)| view.identity == new) {
        Some((node, view)) => {
            if view.height + 5 < tip {
                warnings.push(format!(
                    "{} (the new voter) is {} blocks behind",
                    node.name,
                    tip - view.height
                ));
            }
            warnings.extend(keyholder_warnings(node));
        }
        None => warnings.push(format!(
            "{} (the new voter) does not answer: it must be running and caught up to vote",
            short(&new)
        )),
    }
    if answering.iter().any(|(_, view)| view.identity == old) {
        warnings.push(format!(
            "{} (the voter to remove) still answers: it is removed anyway",
            short(&old)
        ));
    }
    let missing: Vec<&str> = views
        .iter()
        .filter(|(_, view)| view.is_none())
        .map(|(node, _)| node.name.as_str())
        .collect();
    if !missing.is_empty() {
        warnings.push(format!("not answering: {}", missing.join(", ")));
    }
    for warning in &warnings {
        println!("warning: {warning}");
    }

    // Submit through a voter that stays.
    let (submitter, _) = answering
        .iter()
        .find(|(_, view)| view.voting && view.identity != old)
        .ok_or("no remaining voter answers")?;
    let body = json!({ "remove": old, "add": new });
    let (code, answer) = submitter
        .call("POST", "/consensus/reconfigure", Some(&body))
        .map_err(|err| format!("{}: {err}", submitter.name))?;
    if code != 202 {
        return Err(format!("{} refused ({code}): {answer}", submitter.name));
    }
    let next = first.epoch + 1;
    println!(
        "submitted through {} (transaction {}): epoch {next} committee {}",
        submitter.name, answer["transaction_id"], answer["committee"]
    );

    // Follow the switch: each node ends the epoch, exits, and its supervisor restarts it.
    let deadline = Instant::now() + Duration::from_secs(wait);
    let mut reported: Vec<Option<String>> = vec![None; nodes.len()];
    let watched: Vec<usize> = views
        .iter()
        .enumerate()
        .filter(|(_, (_, view))| view.as_ref().is_some_and(|view| view.identity != old))
        .map(|(index, _)| index)
        .collect();
    loop {
        let mut done = true;
        for &index in &watched {
            let node = &nodes[index];
            let state = match node.view() {
                Some(view) if view.epoch >= next => {
                    format!("epoch {} (height {})", view.epoch, view.height)
                }
                Some(view) => {
                    done = false;
                    match view.ended_at {
                        Some(height) => {
                            format!("epoch {} ended at block {height}, applying it", view.epoch)
                        }
                        None => format!("epoch {}", view.epoch),
                    }
                }
                None => {
                    done = false;
                    "stopped: waiting for its restart (exit status 75 ends an epoch)".to_string()
                }
            };
            if reported[index].as_ref() != Some(&state) {
                println!("{}: {state}", node.name);
                reported[index] = Some(state);
            }
        }
        if done {
            break;
        }
        if Instant::now() > deadline {
            return Err("the switch did not complete in time: run mpc-admin resume".into());
        }
        sleep(POLL);
    }

    // The next epoch finalizes blocks.
    let boundary = watched
        .iter()
        .filter_map(|&index| nodes[index].view())
        .find_map(|view| {
            view.boundaries
                .iter()
                .find(|(epoch, _)| *epoch == next)
                .map(|(_, b)| *b)
        })
        .ok_or("no node reports the new epoch's start")?;
    loop {
        let finalized = watched
            .iter()
            .filter_map(|&index| nodes[index].view())
            .any(|view| view.height > boundary);
        if finalized {
            println!("epoch {next} started after block {boundary} and finalizes blocks");
            return Ok(());
        }
        if Instant::now() > deadline {
            return Err(format!("epoch {next} finalized nothing in time"));
        }
        sleep(POLL);
    }
}

/// Whether the node at `node` holds a share of every activated validator key (a voter that is
/// no keyholder cannot add its partial signature).
fn keyholder_warnings(node: &Node) -> Vec<String> {
    let Some(validators) = node.get("/validators") else {
        return vec![format!("{}: could not list validator keys", node.name)];
    };
    validators
        .as_array()
        .into_iter()
        .flatten()
        .filter(|validator| validator["status"] == "active")
        .filter_map(|validator| {
            let id = validator["ceremony_id"].as_str()?;
            let share = node
                .get(&format!("/validators/reshare/{id}"))
                .or_else(|| node.get(&format!("/dkg/status/{id}")))
                .map(|ceremony| ceremony["share"].clone());
            (share != Some(json!("stored"))).then(|| {
                format!(
                    "{} holds no share of validator {} (ceremony {id}): reshare to it first (R2)",
                    node.name,
                    validator["public_key"].as_str().unwrap_or("?")
                )
            })
        })
        .collect()
}

fn resume(nodes: &[Node], stall: u64) -> Result<(), String> {
    let views = views(nodes);
    let answering: Vec<(&Node, View)> = views
        .iter()
        .filter_map(|(node, view)| view.clone().map(|view| (*node, view)))
        .collect();
    let latest = answering
        .iter()
        .map(|(_, view)| view.epoch)
        .max()
        .ok_or("no node answers")?;
    let reference = &answering
        .iter()
        .find(|(_, view)| view.epoch == latest)
        .expect("latest epoch exists")
        .1;
    for (node, view) in &views {
        if view.is_none() {
            println!("{}: not answering (stopped? restart it)", node.name);
        }
    }

    // Nodes left in an earlier epoch: fetch the block that ended it.
    let mut behind = false;
    for (node, view) in &answering {
        if view.epoch == latest {
            continue;
        }
        behind = true;
        let Some((_, boundary)) = reference
            .boundaries
            .iter()
            .find(|(epoch, _)| *epoch == view.epoch + 1)
        else {
            continue;
        };
        let (code, _) = node
            .call(
                "POST",
                "/consensus/sync",
                Some(&json!({ "height": boundary })),
            )
            .map_err(|err| format!("{}: {err}", node.name))?;
        println!(
            "{}: in epoch {} at height {}, asked to fetch block {boundary} that ended it ({code})",
            node.name, view.epoch, view.height
        );
    }
    if behind {
        println!(
            "nodes that apply the block that ended their epoch exit (status 75): restart them"
        );
        return Ok(());
    }

    // Every node in the same epoch: is its last block stuck unfinalized?
    let Some(ended) = answering.iter().find_map(|(_, view)| view.ended_at) else {
        println!("every answering node runs epoch {latest}; its end is not in sight");
        return Ok(());
    };
    let start = Instant::now();
    let height = |answering: &[(&Node, View)]| answering.iter().map(|(_, view)| view.height).max();
    while start.elapsed() < Duration::from_secs(stall) {
        sleep(POLL);
        let now: Vec<(&Node, View)> = nodes
            .iter()
            .filter_map(|node| node.view().map(|view| (node, view)))
            .collect();
        // A node that applied the block exits (and stops answering) to restart in the next epoch.
        if now.len() < answering.len()
            || now.iter().any(|(_, view)| view.epoch > latest)
            || height(&now) >= Some(ended)
        {
            println!(
                "block {ended}, the last of epoch {latest}, is finalized: nodes are switching"
            );
            return Ok(());
        }
    }
    println!(
        "block {ended} ended epoch {latest} but is not finalized after {stall} s. Restart every \
         voter of epoch {latest} with --close-epoch-at {ended}: the block is proposed again until \
         it is finalized (docs/reconfiguration.md, closing an epoch)"
    );
    Err("the epoch's last block is not finalized".into())
}
