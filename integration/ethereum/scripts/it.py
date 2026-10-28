#!/usr/bin/env python3
"""The Ethereum devnet integration of the MPC signer (docs/ethereum-devnet.md).

Runs inside the isolated environment (`scripts/env.sh`): Kurtosis and the devnet, the four signer
nodes (containers on that environment's loopback), the failover proxy and Lighthouse's validator
client. Python standard library only.

Every wait is bounded and fails with its stage, so a failed run says where it failed:
environment, dkg, activation, deposit, lighthouse, signing, beacon or timeout. Success is never
inferred from an HTTP 200: attestations and proposals are checked in the beacon chain's state.

Usage (inside the environment):
    it.py run                     everything, then a report (WORK/report.md, WORK/report.json)
    it.py devnet up|down          the Kurtosis enclave
    it.py signers start|stop      the four signer nodes
    it.py report                  the report from the logs of a run
"""

import argparse
import calendar
import importlib.util
import json
import os
import re
import shutil
import statistics
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

IT = "/it"
SRC = f"{IT}/src"
WORK = os.environ.get("IT_WORK", f"{IT}/work")
KURTOSIS = f"{IT}/bin/kurtosis"
SIGNER = f"{IT}/target/release/eth-mpc-signer"
HERE = f"{SRC}/integration/ethereum"
NETWORK_ARGS = f"{HERE}/kurtosis/network.yaml"

ENCLAVE = "eth-mpc-it"
CL_SERVICE = "cl-1-lighthouse-geth"
EL_SERVICE = "el-1-geth-lighthouse"
NODES = 4
P2P_BASE = 47000
HTTP_BASE = 47100
PROXY_PORT = 47200
VC_METRICS_PORT = 47301
CEREMONY = "validator-devnet"
# The `User-Agent` of the security checks' signing requests: the report keeps them apart from
# Lighthouse's.
PROBE_AGENT = "eth-mpc-it-security-check"

# ethereum-package's published devnet test account m/44'/60'/0'/0/20 (prefunded at genesis): pays
# the deposit and is the validator's withdrawal address. A devnet-only key.
FUNDER_ADDRESS = "0xafF0CA253b97e54440965855cec0A8a2E2399896"
FUNDER_KEY = "0x04b9f63ecf84210c5366c66d68fa1f5da1fa4f634fad6dfc86178e4d79ff9e59"
DEPOSIT_CONTRACT = "0x00000000219ab540356cBB839Cbe05303d7705Fa"
DEPOSIT_GWEI = 32_000_000_000


def versions():
    pins = {}
    with open(f"{HERE}/config/versions.env") as file:
        for line in file:
            if "=" in line and not line.lstrip().startswith("#"):
                key, value = line.strip().split("=", 1)
                pins[key] = value
    return pins


VERSIONS = versions()
UID = os.environ.get("IT_UID") or str(os.stat(IT).st_uid)
GID = os.environ.get("IT_GID") or str(os.stat(IT).st_gid)


class Failure(Exception):
    def __init__(self, stage, message):
        super().__init__(f"[{stage}] {message}")
        self.stage = stage


def log(message):
    line = f"{time.strftime('%H:%M:%S', time.gmtime())} {message}"
    print(line, flush=True)
    os.makedirs(WORK, exist_ok=True)
    with open(f"{WORK}/run.log", "a") as file:
        file.write(line + "\n")


def run(args, timeout=600, check=True):
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    if check and result.returncode != 0:
        raise RuntimeError(
            f"{' '.join(args[:4])}... exited with {result.returncode}: "
            f"stdout: {result.stdout.strip()[-2000:]} stderr: {result.stderr.strip()[-2000:]}")
    return result.stdout


def http(method, url, body=None, timeout=10, headers=None):
    """(status, parsed JSON or text); raises ConnectionError when nothing answers."""
    data = None if body is None else (body if isinstance(body, bytes) else json.dumps(body).encode())
    request = urllib.request.Request(url, data=data, method=method)
    request.add_header("Content-Type", "application/json")
    for name, value in (headers or {}).items():
        request.add_header(name, value)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            status, text = response.status, response.read().decode()
    except urllib.error.HTTPError as error:
        status, text = error.code, error.read().decode()
    except (urllib.error.URLError, OSError) as error:
        raise ConnectionError(str(error)) from error
    try:
        return status, json.loads(text)
    except ValueError:
        return status, text


def wait(what, stage, timeout, interval, predicate):
    deadline = time.monotonic() + timeout
    while True:
        try:
            value = predicate()
        except ConnectionError:
            value = None
        if value:
            return value
        if time.monotonic() > deadline:
            raise Failure(stage, f"timed out after {timeout:.0f} s waiting for {what}")
        time.sleep(interval)


def own(path):
    """Directories and files the containers use belong to the host user (their uid), even though
    this driver runs as root inside the environment."""
    if os.geteuid() == 0:
        subprocess.run(["chown", "-R", f"{UID}:{GID}", path], check=False)


def workdir(*parts):
    path = os.path.join(WORK, *parts)
    os.makedirs(path, exist_ok=True)
    own(path)
    return path


def save(name, value):
    with open(f"{WORK}/{name}", "w") as file:
        json.dump(value, file, indent=2)


def load(name, default=None):
    try:
        with open(f"{WORK}/{name}") as file:
            return json.load(file)
    except FileNotFoundError:
        return default


# ---------------------------------------------------------------------------------------------
# Devnet


def port_print(service, port_id):
    address = run([KURTOSIS, "port", "print", ENCLAVE, service, port_id]).strip()
    return address if address.startswith("http") else f"http://{address}"


def devnet_up():
    log(f"devnet: {VERSIONS['ETHEREUM_PACKAGE']} (enclave {ENCLAVE})")
    os.makedirs(f"{WORK}/logs", exist_ok=True)
    with open(f"{WORK}/logs/kurtosis-run.log", "w") as out:
        result = subprocess.run(
            [KURTOSIS, "run", "--enclave", ENCLAVE, VERSIONS["ETHEREUM_PACKAGE"],
             "--args-file", NETWORK_ARGS],
            stdout=out, stderr=subprocess.STDOUT, timeout=1800)
    if result.returncode != 0:
        raise Failure("environment", f"kurtosis run failed (logs/kurtosis-run.log)")
    endpoints = {"beacon": port_print(CL_SERVICE, "http"), "execution": port_print(EL_SERVICE, "rpc")}
    artifact = f"{WORK}/network-artifact"
    shutil.rmtree(artifact, ignore_errors=True)
    run([KURTOSIS, "files", "download", ENCLAVE, "el_cl_genesis_data", artifact])
    configs = [root for root, _, files in os.walk(artifact) if "config.yaml" in files]
    if not configs:
        raise Failure("environment", "no config.yaml in the el_cl_genesis_data artifact")
    endpoints["testnet_dir"] = configs[0]
    save("endpoints.json", endpoints)
    wait("the beacon node's genesis", "environment", 600, 2,
         lambda: http("GET", f"{endpoints['beacon']}/eth/v1/beacon/genesis")[0] == 200)
    log(f"devnet: beacon {endpoints['beacon']}, execution {endpoints['execution']}")
    return endpoints


def devnet_down():
    run([KURTOSIS, "enclave", "rm", "-f", ENCLAVE], check=False)


def endpoints():
    value = load("endpoints.json")
    if not value:
        raise Failure("environment", "no devnet (run `it.py devnet up`)")
    return value


def beacon(path, method="GET", body=None):
    status, value = http(method, f"{endpoints()['beacon']}{path}", body, timeout=20)
    if status != 200:
        raise Failure("beacon", f"{method} {path}: {status} {str(value)[:300]}")
    return value["data"] if isinstance(value, dict) and "data" in value else value


class Chain:
    """Slot arithmetic of the devnet, from the beacon node."""

    def __init__(self):
        genesis = beacon("/eth/v1/beacon/genesis")
        spec = beacon("/eth/v1/config/spec")
        self.genesis_time = int(genesis["genesis_time"])
        self.genesis_validators_root = genesis["genesis_validators_root"]
        self.genesis_fork_version = genesis["genesis_fork_version"]
        self.seconds_per_slot = int(spec["SECONDS_PER_SLOT"])
        self.slots_per_epoch = int(spec["SLOTS_PER_EPOCH"])

    def slot(self):
        return max(0, int((time.time() - self.genesis_time) // self.seconds_per_slot))

    def epoch(self):
        return self.slot() // self.slots_per_epoch

    def epoch_seconds(self):
        return self.seconds_per_slot * self.slots_per_epoch

    def wait_epoch(self, epoch, stage="timeout"):
        start = self.genesis_time + epoch * self.epoch_seconds()
        wait(f"epoch {epoch}", stage, max(0, start - time.time()) + 60, 1,
             lambda: self.epoch() >= epoch)


def validator(pubkey):
    status, value = http("GET", f"{endpoints()['beacon']}/eth/v1/beacon/states/head/validators/{pubkey}")
    if status == 404:
        return None
    if status != 200:
        raise Failure("beacon", f"validator lookup: {status} {value}")
    return value["data"]


# ---------------------------------------------------------------------------------------------
# Signer nodes


def node_url(node):
    return f"http://127.0.0.1:{HTTP_BASE + node}"


def signer_start(node, env=None):
    name = f"it-signer-{node}"
    run(["docker", "rm", "-f", name], check=False)
    args = [SIGNER, "--id", str(node), "--participants", str(NODES),
            "--p2p-port", str(P2P_BASE), "--http-port", str(HTTP_BASE),
            "--data-dir", f"{WORK}/signers", "--signing-timeout", "2",
            "--authorization-timeout", "4"]
    if node == 0:
        # Validator onboarding: node 0 alone accepts the one DEPOSIT signing request.
        args.append("--enable-deposit-signing")
    environment = ["-e", "RUST_LOG=info"]
    for key, value in (env or {}).items():
        environment += ["-e", f"{key}={value}"]
    command = " ".join(args) + f" >> {WORK}/logs/signer-{node}.log 2>&1"
    run(["docker", "run", "-d", "--name", name, "--network", "host", "--user", f"{UID}:{GID}",
         "-v", f"{IT}:{IT}", *environment, VERSIONS["RUNTIME_IMAGE"], "sh", "-c",
         f"exec {command}"])


def signer_stop(node, crash=False):
    name = f"it-signer-{node}"
    if crash:
        run(["docker", "kill", name], check=False)
    else:
        run(["docker", "stop", "-t", "5", name], check=False)
    run(["docker", "rm", "-f", name], check=False)


def signer_running(node):
    out = run(["docker", "inspect", "-f", "{{.State.Running}}", f"it-signer-{node}"], check=False)
    return out.strip() == "true"


def ready(node):
    try:
        return http("GET", f"{node_url(node)}/ready", timeout=3)[0] == 200
    except ConnectionError:
        return False


def height(node):
    status, value = http("GET", f"{node_url(node)}/status", timeout=3)
    return value["height"] if status == 200 else None


def signers_start():
    workdir("logs")
    workdir("signers")
    for node in range(NODES):
        signer_start(node)
    for node in range(NODES):
        wait(f"signer node {node} ready", "environment", 180, 1, lambda node=node: ready(node))
    log("signers: 4 nodes ready")


def signers_stop():
    for node in range(NODES):
        signer_stop(node)


# ---------------------------------------------------------------------------------------------
# Validator: DKG, activation, deposit


def dkg():
    status, body = http("POST", f"{node_url(0)}/dkg/start",
                        {"ceremony_id": CEREMONY, "validator": True}, timeout=40)
    if status != 200:
        raise Failure("dkg", f"start: {status} {body}")
    keys = []
    for node in range(NODES):
        def completed(node=node):
            status, body = http("GET", f"{node_url(node)}/dkg/status/{CEREMONY}", timeout=5)
            if status == 200 and body.get("status") == "failed":
                raise Failure("dkg", f"ceremony failed on node {node}: {body}")
            if status == 200 and body.get("status") == "completed" and body.get("share") == "stored":
                return body["public_key"]
            return None
        keys.append(wait(f"the DKG on node {node}", "dkg", 300, 1, completed))
    if len(set(keys)) != 1:
        raise Failure("dkg", f"nodes disagree on the key: {keys}")
    log(f"dkg: validator key {keys[0]}")
    return keys[0]


def activate(key, chain):
    status, body = http("POST", f"{node_url(0)}/validators/activate",
                        {"public_key": key, "genesis_validators_root": chain.genesis_validators_root},
                        timeout=40)
    if status != 200 or body.get("status") != "active":
        raise Failure("activation", f"{status} {body}")
    for node in range(NODES):
        def activated(node=node):
            status, validators = http("GET", f"{node_url(node)}/validators", timeout=5)
            return status == 200 and any(
                v["public_key"] == key and v.get("genesis_validators_root") == chain.genesis_validators_root
                for v in validators)
        wait(f"the activation on node {node}", "activation", 120, 1, activated)
    log(f"activation: {key} signs for genesis validators root {chain.genesis_validators_root} "
        f"(block {body['activated_at']})")
    return body


def ssz():
    spec = importlib.util.spec_from_file_location(
        "ssz_roots", f"{SRC}/tests/fixtures/web3signer/ssz_roots.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def deposit(key, chain):
    existing = load("deposit.json")
    if existing:
        log(f"deposit: already sent in transaction {existing['transaction']}")
        return existing
    roots = ssz()
    credentials = "0x01" + "00" * 11 + FUNDER_ADDRESS[2:].lower()
    request = {"type": "DEPOSIT", "deposit": {
        "pubkey": key, "withdrawal_credentials": credentials, "amount": str(DEPOSIT_GWEI),
        "genesis_fork_version": chain.genesis_fork_version}}
    request["signingRoot"] = "0x" + roots.signing_root(request, roots.preset(False)).hex()
    status, body = http("POST", f"{node_url(0)}/api/v1/eth2/sign/{key}", request, timeout=30,
                        headers={"Accept": "application/json"})
    if status != 200:
        raise Failure("deposit", f"signing the deposit message: {status} {body}")
    signature = body["signature"]
    data_root = "0x" + roots.container(
        roots.merkleize(roots.pack(roots.hexbytes(key, 48))),
        roots.bytes32(credentials),
        roots.uint64(DEPOSIT_GWEI),
        roots.signature(signature),
    ).hex()
    log(f"deposit: signed by the MPC network (signing root {request['signingRoot']})")
    rpc = endpoints()["execution"]

    def cast(arguments):
        return run(["docker", "run", "--rm", "--network", "host", VERSIONS["FOUNDRY_IMAGE"],
                    f"cast {arguments} --rpc-url {rpc}"], timeout=300).strip()

    # Sent once (`--async`: the hash, without waiting), then the receipt is polled: geth answers
    # receipt queries with "transaction indexing is in progress" for a while after it starts.
    try:
        transaction = cast(
            f"send --async --private-key {FUNDER_KEY} {DEPOSIT_CONTRACT} "
            f"'deposit(bytes,bytes,bytes,bytes32)' {key} {credentials} {signature} {data_root} "
            f"--value 32ether").splitlines()[-1]
    except RuntimeError as error:
        raise Failure("deposit", f"sending the deposit transaction: {error}") from error
    log(f"deposit: transaction {transaction} sent")

    def mined():
        try:
            answer = json.loads(cast(f"receipt --json {transaction}"))
        except RuntimeError as error:
            if "indexing is in progress" in str(error) or "not found" in str(error).lower():
                return None
            raise Failure("deposit", f"the deposit transaction's receipt: {error}") from error
        # Foundry's JSON envelope: {"schema_version", "success", "data", "errors"}.
        return answer.get("data") if "schema_version" in answer else answer
    receipt = wait("the deposit transaction to be mined", "deposit", 300, 4, mined)
    if receipt.get("status") not in ("0x1", 1, "1"):
        raise Failure("deposit", f"transaction failed: {receipt}")
    result = {"transaction": receipt["transactionHash"], "block": int(str(receipt["blockNumber"]), 0),
              "withdrawal_credentials": credentials, "signature": signature,
              "deposit_data_root": data_root, "signing_root": request["signingRoot"]}
    save("deposit.json", result)
    log(f"deposit: transaction {result['transaction']} in execution block {result['block']}")
    return result


# ---------------------------------------------------------------------------------------------
# Proxy and Lighthouse validator client


def proxy_start():
    proxy_stop()
    args = [sys.executable, f"{HERE}/scripts/proxy.py", "--listen", f"127.0.0.1:{PROXY_PORT}",
            "--log", f"{WORK}/logs/proxy.jsonl", "--requests", f"{WORK}/requests"]
    for node in range(NODES):
        args += ["--backend", node_url(node)]
    with open(f"{WORK}/logs/proxy.log", "a") as out:
        process = subprocess.Popen(args, stdout=out, stderr=subprocess.STDOUT, start_new_session=True)
    with open(f"{WORK}/proxy.pid", "w") as file:
        file.write(str(process.pid))
    wait("the proxy", "environment", 20, 0.5,
         lambda: http("GET", f"http://127.0.0.1:{PROXY_PORT}/upcheck", timeout=3)[0] == 200)


def proxy_stop():
    try:
        with open(f"{WORK}/proxy.pid") as file:
            os.kill(int(file.read()), 15)
    except (FileNotFoundError, ProcessLookupError, ValueError):
        pass


def vc_start(key):
    """Lighthouse's validator client with one remote-signer validator: the DKG key, signed by the
    MPC network through the proxy. No keystore exists anywhere."""
    datadir = workdir("vc")
    workdir("vc", "validators")
    workdir("vc-home")
    with open(f"{datadir}/validators/validator_definitions.yml", "w") as file:
        file.write(
            "---\n"
            "- enabled: true\n"
            f'  voting_public_key: "{key}"\n'
            '  description: "DKG-generated key, signed by the MPC network"\n'
            "  type: web3signer\n"
            f'  url: "http://127.0.0.1:{PROXY_PORT}"\n'
            "  request_timeout_ms: 12000\n")
    own(datadir)
    run(["docker", "rm", "-f", "it-vc"], check=False)
    devnet = endpoints()
    command = (
        f"exec lighthouse --testnet-dir {devnet['testnet_dir']} vc --datadir {datadir} "
        f"--beacon-nodes {devnet['beacon']} --init-slashing-protection "
        f"--suggested-fee-recipient {FUNDER_ADDRESS} --disable-auto-discover "
        f"--metrics --metrics-address 127.0.0.1 --metrics-port {VC_METRICS_PORT} "
        f"--debug-level info >> {WORK}/logs/vc.log 2>&1")
    run(["docker", "run", "-d", "--name", "it-vc", "--network", "host", "--user", f"{UID}:{GID}",
         "-e", f"HOME={WORK}/vc-home", "-v", f"{IT}:{IT}", "--entrypoint", "sh",
         VERSIONS["LIGHTHOUSE_IMAGE"], "-c", command])

    def enabled():
        text = read(f"{WORK}/logs/vc.log")
        if "Enabled validator" in text and key[2:10] in text.lower():
            return True
        if not run(["docker", "inspect", "-f", "{{.State.Running}}", "it-vc"], check=False).startswith("true"):
            raise Failure("lighthouse", "the validator client exited (logs/vc.log)")
        return False
    wait("Lighthouse to enable the remote-signer validator", "lighthouse", 120, 1, enabled)
    log("lighthouse: validator client running, the DKG key enabled as a web3signer validator")


def vc_stop():
    run(["docker", "stop", "-t", "10", "it-vc"], check=False)
    run(["docker", "rm", "-f", "it-vc"], check=False)


def read(path):
    try:
        with open(path, errors="replace") as file:
            return file.read()
    except FileNotFoundError:
        return ""


# ---------------------------------------------------------------------------------------------
# Beacon-chain evidence


def wait_active(key, chain):
    seen = None
    timeout = 45 * chain.epoch_seconds()

    def active():
        nonlocal seen
        entry = validator(key)
        status = entry["status"] if entry else "unknown (deposit not processed yet)"
        if status != seen:
            log(f"beacon: validator {status} at epoch {chain.epoch()}")
            seen = status
        return entry if entry and entry["status"].startswith("active") else None
    entry = wait("the validator to become active", "activation", timeout, 4, active)
    index = int(entry["index"])
    activation_epoch = int(entry["validator"]["activation_epoch"])
    log(f"beacon: validator index {index}, active from epoch {activation_epoch}")
    return index, activation_epoch


def epoch_evidence(index, epoch, chain):
    """Attestation and proposal evidence for `epoch`, read once the next two epochs have passed."""
    chain.wait_epoch(epoch + 2)
    duties = beacon(f"/eth/v1/validator/duties/attester/{epoch}", "POST", [str(index)])
    inclusion = beacon(f"/lighthouse/validator_inclusion/{epoch + 1}/{index}")
    rewards = beacon(f"/eth/v1/beacon/rewards/attestations/{epoch}", "POST", [str(index)])
    total = next((r for r in rewards.get("total_rewards", []) if int(r["validator_index"]) == index), {})
    return {
        "epoch": epoch,
        "attestation_slot": int(duties[0]["slot"]) if duties else None,
        "target_attester": inclusion["is_previous_epoch_target_attester"],
        "head_attester": inclusion["is_previous_epoch_head_attester"],
        "rewards": {k: int(v) for k, v in total.items() if k in ("head", "target", "source")},
        "proposals": proposals_of(index, epoch),
    }


def block_at(slot):
    status, header = http("GET", f"{endpoints()['beacon']}/eth/v1/beacon/headers/{slot}")
    block = header.get("data") if status == 200 else None
    return {
        "slot": slot,
        "block_root": block["root"] if block else None,
        "canonical": bool(block and block["canonical"]),
        "proposer_index": int(block["header"]["message"]["proposer_index"]) if block else None,
    }


def proposals_of(index, epoch):
    """The validator's assigned proposals in `epoch`, each with the block at its slot."""
    return [block_at(int(duty["slot"])) for duty in beacon(f"/eth/v1/validator/duties/proposer/{epoch}")
            if int(duty["validator_index"]) == index]


def proposed(block, index):
    return block["canonical"] and block["proposer_index"] == index


class Recorder(threading.Thread):
    """Attestation flags and proposals for every epoch from the validator's activation, each read
    two epochs later, while the beacon node still has the states (it prunes finalized ones): the
    whole active period, including what the scenario windows leave out (restarts, waits). Kept in
    `lifetime.jsonl`; an epoch it could not read is recorded with the error."""

    def __init__(self, index, first, chain):
        super().__init__(name="recorder", daemon=True)
        self.index, self.first, self.chain = index, first, chain
        self.stopped = threading.Event()

    def run(self):
        epoch = self.first
        while True:
            due = self.chain.genesis_time + (epoch + 2) * self.chain.epoch_seconds() + self.chain.seconds_per_slot
            if self.stopped.wait(max(0, due - time.time())):
                return
            try:
                inclusion = beacon(f"/lighthouse/validator_inclusion/{epoch + 1}/{self.index}")
                entry = {"epoch": epoch,
                         "target_attester": inclusion["is_previous_epoch_target_attester"],
                         "head_attester": inclusion["is_previous_epoch_head_attester"],
                         "proposals": proposals_of(self.index, epoch)}
            except Exception as error:  # noqa: BLE001 - recorded, the report counts it
                entry = {"epoch": epoch, "error": str(error)}
            with open(f"{WORK}/lifetime.jsonl", "a") as file:
                file.write(json.dumps(entry) + "\n")
            epoch += 1

    def stop(self):
        self.stopped.set()
        self.join(timeout=60)


def observe(label, index, epochs, chain, until_proposal=0):
    """Evidence for `epochs` whole epochs from the next one; then, if `until_proposal`, up to that
    many more epochs until a proposal of the validator is assigned and checked."""
    first = chain.epoch() + 1
    results = []
    epoch = first
    while True:
        evidence = epoch_evidence(index, epoch, chain)
        evidence["scenario"] = label
        results.append(evidence)
        with open(f"{WORK}/epochs.jsonl", "a") as file:
            file.write(json.dumps(evidence) + "\n")
        attested = "attested" if evidence["target_attester"] else "MISSED attestation"
        blocks = ", ".join(
            f"slot {p['slot']} {'proposed (canonical)' if proposed(p, index) else 'MISSED'}"
            for p in evidence["proposals"]) or "no proposal assigned"
        log(f"{label}: epoch {epoch}: {attested} (head {evidence['head_attester']}); {blocks}")
        epoch += 1
        if epoch - first < epochs:
            continue
        has_proposal = any(p["proposals"] for p in results)
        if until_proposal and not has_proposal and epoch - first < epochs + until_proposal:
            continue
        return results


# ---------------------------------------------------------------------------------------------
# Scenarios


def scenario(name, function):
    started = time.time()
    log(f"== scenario {name}")
    details = function() or {}
    entry = {"name": name, "start": started, "end": time.time(), **details}
    scenarios = load("scenarios.json", [])
    scenarios.append(entry)
    save("scenarios.json", scenarios)
    return entry


def converged(nodes):
    heights = [height(node) for node in nodes]
    return None not in heights and max(heights) - min(heights) <= 2


def node_offline(index, chain, observed=3):
    def body():
        signer_stop(2)
        stopped = time.time()
        wait("nodes 0, 1, 3 ready", "signing", 60, 1, lambda: all(ready(n) for n in (0, 1, 3)))
        observe("node-offline", index, observed, chain)
        signer_start(2)
        restarted = time.time()
        wait("node 2 ready", "environment", 300, 1, lambda: ready(2))
        wait("all nodes at the same height", "environment", 300, 1, lambda: converged(range(NODES)))
        recovered = time.time()
        log(f"node-offline: node 2 back, ready and converged {recovered - restarted:.1f} s after restart")
        return {"stopped": stopped, "restarted": restarted, "recovered": recovered,
                "recovery_seconds": round(recovered - restarted, 1)}
    return body


def coordinator_failover(index, chain, observed=3):
    def body():
        signer_stop(0)
        stopped = time.time()
        observe("coordinator-failover", index, observed, chain)
        signer_start(0)
        restarted = time.time()
        wait("node 0 ready", "environment", 300, 1, lambda: ready(0))
        wait("all nodes at the same height", "environment", 300, 1, lambda: converged(range(NODES)))
        recovered = time.time()
        return {"stopped": stopped, "restarted": restarted, "recovered": recovered,
                "recovery_seconds": round(recovered - restarted, 1)}
    return body


def inflight_retry(index, chain, crashes=3):
    """Node 0 (the proxy's first choice) crashes right after a duty's authorization, before
    returning the signature: the deterministic `authorized` crash point. The proxy retries on
    node 1, which must return the signature of the same authorization.

    The crash point follows either a new authorization (node 0 submitted the duty and consensus
    accepted it) or a duty accepted before (Lighthouse repeats some requests, and node 1 may have
    coordinated the first one). Node 0 is armed again, up to `crashes` times, until a crash
    follows a new authorization; every crash is checked and reported."""
    def body():
        observed = []
        for _ in range(crashes):
            before = read(f"{WORK}/logs/signer-0.log").count("test hook: crashing at authorized")
            signer_start(0, {"ETH_MPC_SIGNER_CRASH_AT": "authorized"})
            wait("node 0 ready", "environment", 300, 1, lambda: ready(0))
            armed = time.time()
            wait("node 0 to crash at the authorized point", "signing", 4 * chain.epoch_seconds(), 1,
                 lambda: not signer_running(0))
            crashed_at = time.time()
            if read(f"{WORK}/logs/signer-0.log").count("test hook: crashing at authorized") <= before:
                raise Failure("signing", "node 0 stopped without reaching the crash point")
            time.sleep(chain.seconds_per_slot)
            retried = [r for r in proxy_records() if armed - 1 <= r["ts"] <= crashed_at
                       and r["attempts"] and r["attempts"][0]["backend"] == node_url(0)
                       and "error" in r["attempts"][0]]
            if not retried:
                raise Failure("signing", "no signing request was retried after node 0 crashed")
            requests = []
            for r in retried:
                evidence = duty_log(r["signing_root"])
                new = any(node == 0 and ts >= armed for node, ts in evidence["submitted"])
                requests.append({**{k: r.get(k) for k in ("id", "type", "slot", "epoch", "signing_root",
                                                          "status", "attempts")},
                                 **evidence, "authorization": "new" if new else "existing"})
                log(f"inflight-retry: {r['type']} {duty_time(r)}: HTTP {r['status']} after "
                    f"{[a.get('error') or a.get('status') for a in r['attempts']]}; "
                    f"{'new' if new else 'existing'} authorization, accepted at heights "
                    f"{evidence['authorized_at']}, signed by nodes {evidence['signed_by']}")
                if r["status"] != 200:
                    raise Failure("signing", f"the retried {r['type']} request ended with HTTP {r['status']}")
                if len(evidence["authorized_at"]) != 1:
                    raise Failure("signing", f"the retried {r['type']} duty was accepted at heights "
                                  f"{evidence['authorized_at']}, expected exactly one")
            observed.append({"armed": armed, "crashed": crashed_at, "retried_requests": requests})
            if any(r["authorization"] == "new" for r in requests):
                break
        else:
            raise Failure("signing", f"node 0 crashed {crashes} times, never right after a new "
                          "authorization")
        signer_start(0)
        wait("node 0 ready", "environment", 300, 1, lambda: ready(0))
        observe("inflight-retry", index, 1, chain)
        return {"crashes": observed}
    return body


def duty_time(request):
    return f"slot {request['slot']}" if request.get("slot") is not None else f"epoch {request.get('epoch')}"


def log_time(line):
    """The UTC timestamp at the start of a signer log line, or None."""
    stamp = line.split()[0] if line.strip() else ""
    try:
        ts = calendar.timegm(time.strptime(stamp[:19], "%Y-%m-%dT%H:%M:%S"))
    except ValueError:
        return None
    return ts + (float("0." + stamp[20:26]) if len(stamp) > 20 else 0)


def duty_log(signing_root):
    """What every node logged about one duty: the heights at which consensus accepted it (a retry
    of an accepted duty is `AlreadyAccepted`, not a second acceptance), the nodes that submitted it
    to consensus (with the time) and the nodes that coordinated its signature."""
    heights, submitted, signed_by = set(), [], set()
    for node in range(NODES):
        for line in read(f"{WORK}/logs/signer-{node}.log").splitlines():
            line = re.sub(r"\x1b\[[0-9;]*m", "", line)
            if f"signing_root={signing_root}" not in line:
                continue
            if "applied validator duty" in line and "decision=Accepted" in line:
                heights.add(int(re.search(r"height=(\d+)", line).group(1)))
            elif "submitted validator duty" in line:
                submitted.append((node, log_time(line)))
            elif "signed validator duty" in line:
                signed_by.add(node)
    return {"authorized_at": sorted(heights), "submitted": submitted, "signed_by": sorted(signed_by)}


def proxy_records():
    records = []
    for line in read(f"{WORK}/logs/proxy.jsonl").splitlines():
        try:
            records.append(json.loads(line))
        except ValueError:
            pass
    return records


# ---------------------------------------------------------------------------------------------
# Security checks on the live devnet


def recorded(kind):
    """The latest signing request of `kind` that the MPC network signed (kept by the proxy)."""
    directory = f"{WORK}/requests"
    for name in sorted(os.listdir(directory), reverse=True):
        with open(f"{directory}/{name}") as file:
            record = json.load(file)
        if record["status"] == 200 and json.loads(record["body"]).get("type") == kind:
            return record
    return None


def sign_via(url, path, body):
    return http("POST", f"{url}{path}", body.encode() if isinstance(body, str) else body,
                timeout=30, headers={"Accept": "application/json", "User-Agent": PROBE_AGENT})


def security_checks(key, chain):
    proxy = f"http://127.0.0.1:{PROXY_PORT}"
    roots = ssz()
    checks = []

    def check(name, passed, detail):
        checks.append({"check": name, "passed": bool(passed), "detail": detail})
        log(f"security: {'ok  ' if passed else 'FAIL'} {name}: {detail}")

    attestation = recorded("ATTESTATION")
    if attestation:
        status, body = sign_via(proxy, attestation["path"], attestation["body"])
        same = status == 200 and body.get("signature") == json.loads(attestation["response"])["signature"]
        check("an identical retry returns the same signature", same, f"HTTP {status}")
        conflicting = json.loads(attestation["body"])
        conflicting["attestation"]["beacon_block_root"] = "0x" + "ee" * 32
        conflicting["signingRoot"] = "0x" + roots.signing_root(conflicting, roots.preset(False)).hex()
        for node in (None, 2):
            url = proxy if node is None else node_url(node)
            status, body = sign_via(url, attestation["path"], json.dumps(conflicting))
            check(f"a conflicting attestation is refused ({'proxy' if node is None else f'node {node}'})",
                  status == 412 and body.get("refusal", {}).get("reason") == "double_vote",
                  f"HTTP {status} {body.get('refusal') if isinstance(body, dict) else body}")
    else:
        check("a recorded attestation exists", False, "none signed")

    block = recorded("BLOCK_V2")
    if block:
        conflicting = json.loads(block["body"])
        conflicting["beacon_block"]["block_header"]["body_root"] = "0x" + "ee" * 32
        conflicting["signingRoot"] = "0x" + roots.signing_root(conflicting, roots.preset(False)).hex()
        status, body = sign_via(proxy, block["path"], json.dumps(conflicting))
        check("a conflicting block proposal is refused",
              status == 412 and body.get("refusal", {}).get("reason") == "double_proposal",
              f"HTTP {status} {body.get('refusal') if isinstance(body, dict) else body}")
    else:
        check("a recorded block proposal exists", False, "none signed")

    status, body = http("POST", f"{node_url(1)}/sign",
                        {"ceremony_id": CEREMONY, "nonce": 1, "payload_hash": "0x" + "aa" * 32})
    check("the development /sign refuses the validator key",
          status == 403 and isinstance(body, dict) and body.get("result") == "VALIDATOR_KEY",
          f"HTTP {status}")
    status, body = http("POST", f"{node_url(3)}/validators/activate",
                        {"public_key": key, "genesis_validators_root": "0x" + "42" * 32}, timeout=40)
    check("the chain identity cannot be changed", status == 409, f"HTTP {status} {body}")
    vc_files = sorted(os.path.relpath(os.path.join(root, f), f"{WORK}/vc")
                      for root, _, files in os.walk(f"{WORK}/vc") for f in files)
    keystores = [f for f in vc_files if "keystore" in f.lower() or f.endswith(".json")]
    check("no keystore in the validator client", not keystores, f"files: {vc_files}")
    save("security.json", checks)
    return checks


# ---------------------------------------------------------------------------------------------
# Report


SIGNED = re.compile(r"^(\S+) .*signed validator duty")
FIELD = re.compile(r"(\w+)=(\"[^\"]*\"|\S+)")


def signer_records():
    """`signed validator duty` and `validator duty not signed` lines of every node."""
    records = []
    for node in range(NODES):
        for line in read(f"{WORK}/logs/signer-{node}.log").splitlines():
            line = re.sub(r"\x1b\[[0-9;]*m", "", line)
            if "signed validator duty" not in line and "validator duty not signed" not in line:
                continue
            ts = log_time(line)
            if ts is None:
                continue
            fields = {k: v.strip('"') for k, v in FIELD.findall(line)}
            fields["ts"] = ts
            fields["node"] = node
            fields["ok"] = "validator duty not signed" not in line
            records.append(fields)
    return records


def percentiles(values):
    values = sorted(values)
    if not values:
        return {"n": 0}

    def pick(p):
        return round(values[min(len(values) - 1, int(round(p / 100 * (len(values) - 1))))], 1)
    return {"n": len(values), "p50": pick(50), "p95": pick(95), "p99": pick(99) if len(values) >= 100 else None,
            "min": round(values[0], 1), "max": round(values[-1], 1),
            "mean": round(statistics.mean(values), 1)}


def report(chain=None):
    scenarios = load("scenarios.json", [])
    epochs = [json.loads(l) for l in read(f"{WORK}/epochs.jsonl").splitlines() if l.strip()]
    records = proxy_records()
    # Lighthouse's signing requests; the security checks' are counted apart.
    proxy = [r for r in records if r.get("type") and r.get("client") != PROBE_AGENT]
    probes = [r for r in records if r.get("type") and r.get("client") == PROBE_AGENT]
    signed = signer_records()
    vc_log = read(f"{WORK}/logs/vc.log")
    windows = [(s["name"], s["start"], s["end"]) for s in scenarios]
    validator_info = load("validator.json") or {}
    index = validator_info.get("index")

    def in_window(ts, name):
        return any(n == name and start <= ts <= end for n, start, end in windows)

    per_scenario = {}
    for name, _, _ in windows:
        requests = [r for r in proxy if in_window(r["ts"], name)]
        ok = [r for r in requests if r["status"] == 200]
        retried = [r for r in requests if len(r["attempts"]) > 1]
        fresh = [s for s in signed if in_window(s["ts"], name) and s["ok"] and s.get("authorization_ms")]
        per_scenario[name] = {
            "signing_requests": len(requests),
            "http_errors": len(requests) - len(ok),
            "retried_by_proxy": len(retried),
            "end_to_end_ms": percentiles([r["ms"] for r in ok]),
            "authorization_ms": percentiles([float(s["authorization_ms"]) for s in fresh]),
            "collect_ms": percentiles([float(s["collect_ms"]) for s in fresh if s.get("collect_ms")]),
            "attestations": {
                "epochs": sum(1 for e in epochs if e["scenario"] == name),
                "missed": sum(1 for e in epochs if e["scenario"] == name and not e["target_attester"]),
            },
            "proposals": {
                "assigned": sum(len(e["proposals"]) for e in epochs if e["scenario"] == name),
                "canonical": sum(1 for e in epochs if e["scenario"] == name for p in e["proposals"]
                                 if proposed(p, index)),
            },
        }
        for s in scenarios:
            if s["name"] == name and "recovery_seconds" in s:
                per_scenario[name]["recovery_seconds"] = s["recovery_seconds"]

    by_type = {}
    for r in proxy:
        entry = by_type.setdefault(r["type"], {"requested": 0, "signed": 0, "retried": 0})
        entry["requested"] += 1
        entry["signed"] += r["status"] == 200
        entry["retried"] += len(r["attempts"]) > 1
    finalized = None
    try:
        finalized = int(beacon("/eth/v1/beacon/states/head/finality_checkpoints")["finalized"]["epoch"])
    except Exception:
        pass
    proposals = [p for e in epochs for p in e["proposals"]]
    slots_per_epoch = chain.slots_per_epoch if chain else 32
    # The whole active period and every block the MPC network signed for Lighthouse, while the
    # devnet is up (`it.py report` on an archived run has neither).
    # The whole active period (`Recorder`), and every block the MPC network signed for
    # Lighthouse while the devnet is up (`it.py report` on an archived run has no beacon node).
    whole = [json.loads(l) for l in read(f"{WORK}/lifetime.jsonl").splitlines() if l.strip()] or None
    blocks = None
    try:
        blocks = [block_at(r["slot"]) for r in proxy if r["type"] == "BLOCK_V2" and r["status"] == 200]
    except Exception as error:  # noqa: BLE001 - the report still has the per-epoch evidence
        log(f"report: no beacon evidence for the signed blocks ({error})")
    read_epochs = [e for e in whole or [] if "error" not in e]
    lifetime_proposals = [p for e in read_epochs for p in e["proposals"]]
    result = {
        "deposit": load("deposit.json"),
        "validator": load("validator.json"),
        "duties": by_type,
        "whole_active_period": None if whole is None else {
            "epochs": [whole[0]["epoch"], whole[-1]["epoch"]],
            "read": len(read_epochs),
            "unreadable_epochs": [e["epoch"] for e in whole if "error" in e],
            "target_attester": sum(e["target_attester"] for e in read_epochs),
            "head_attester": sum(e["head_attester"] for e in read_epochs),
            "missed_attestation_epochs": [e["epoch"] for e in read_epochs if not e["target_attester"]],
            "proposals_assigned": len(lifetime_proposals),
            "proposals_canonical": sum(proposed(p, index) for p in lifetime_proposals),
            "missed_proposal_slots": [p["slot"] for p in lifetime_proposals if not proposed(p, index)],
        },
        "signed_blocks": None if blocks is None else {
            "signed": len(blocks),
            "canonical": sum(proposed(b, index) for b in blocks),
            "finalized": sum(1 for b in blocks if proposed(b, index) and finalized is not None
                             and b["slot"] < finalized * slots_per_epoch),
            "not_canonical_slots": [b["slot"] for b in blocks if not proposed(b, index)],
        },
        "security_check_requests": [{k: r.get(k) for k in ("type", "slot", "status")} for r in probes],
        "attestations": {"epochs": len(epochs), "target_attester": sum(e["target_attester"] for e in epochs),
                         "head_attester": sum(e["head_attester"] for e in epochs)},
        "proposals": {"assigned": len(proposals),
                      "canonical": sum(proposed(p, index) for p in proposals),
                      "finalized": sum(1 for p in proposals if proposed(p, index) and finalized is not None
                                       and p["slot"] < finalized * slots_per_epoch),
                      "slots": proposals},
        "lighthouse": {
            "published_attestations": vc_log.count("Successfully published attestations"),
            # "attestation" (one aggregate) without the "s" of "attestations".
            "published_aggregates": vc_log.count("Successfully published attestation")
            - vc_log.count("Successfully published attestations"),
            "published_blocks": vc_log.count("Successfully published block"),
            "failed_to_sign": len(re.findall(r"Failed to sign|Unable to sign", vc_log)),
        },
        "scenarios": per_scenario,
        "scenario_details": scenarios,
        "security": load("security.json", []),
        "finalized_epoch": finalized,
    }
    save("report.json", result)
    lines = ["# Ethereum devnet integration report", ""]
    lines.append(f"- validator: `{(result['validator'] or {}).get('public_key')}` "
                 f"index {(result['validator'] or {}).get('index')}")
    lines.append(f"- attestations: {result['attestations']['target_attester']} of "
                 f"{result['attestations']['epochs']} epochs with a correct target in the beacon state "
                 f"({result['attestations']['head_attester']} with the correct head)")
    lines.append(f"- proposals: {result['proposals']['canonical']} canonical of "
                 f"{result['proposals']['assigned']} assigned, {result['proposals']['finalized']} finalized")
    period, signed_blocks = result["whole_active_period"], result["signed_blocks"]
    if period is not None:
        lines.append(f"- whole active period, epochs {period['epochs']} ({period['read']} read, unreadable "
                     f"{period['unreadable_epochs']}): {period['target_attester']} epochs "
                     f"with a correct target, {period['head_attester']} with the correct head, missed "
                     f"{period['missed_attestation_epochs']}; proposals {period['proposals_canonical']} "
                     f"canonical of {period['proposals_assigned']} assigned, missed "
                     f"{period['missed_proposal_slots']}")
    if signed_blocks is not None:
        lines.append(f"- blocks signed for Lighthouse: {signed_blocks['signed']}, canonical "
                     f"{signed_blocks['canonical']}, finalized {signed_blocks['finalized']}, not canonical "
                     f"{signed_blocks['not_canonical_slots']}")
    lines.append("")
    lines.append("| Scenario | Requests | HTTP errors | Proxy retries | End-to-end p50/p95 ms (n) | "
                 "Authorization p50/p95 ms (n) | Missed attestations | Proposals | Recovery s |")
    lines.append("| --- | --- | --- | --- | --- | --- | --- | --- | --- |")
    for name, s in per_scenario.items():
        e2e, auth = s["end_to_end_ms"], s["authorization_ms"]
        lines.append(
            f"| {name} | {s['signing_requests']} | {s['http_errors']} | {s['retried_by_proxy']} | "
            f"{e2e.get('p50')}/{e2e.get('p95')} ({e2e['n']}) | {auth.get('p50')}/{auth.get('p95')} ({auth['n']}) | "
            f"{s['attestations']['missed']} of {s['attestations']['epochs']} | "
            f"{s['proposals']['canonical']} of {s['proposals']['assigned']} | {s.get('recovery_seconds', '')} |")
    lines.append("")
    lines.append("Lighthouse's signing requests (the security checks' are not counted):")
    lines.append("")
    lines.append("| Duty type | Requested | Signed | Retried by the proxy |")
    lines.append("| --- | --- | --- | --- |")
    for kind, entry in sorted(by_type.items()):
        lines.append(f"| {kind} | {entry['requested']} | {entry['signed']} | {entry['retried']} |")
    lines.append("")
    by_id = {r["id"]: r for r in proxy}
    for s in scenarios:
        for crash in s.get("crashes", [s] if "retried_requests" in s else []):
            for r in crash["retried_requests"]:
                r = {**r, **{k: by_id.get(r["id"], {}).get(k) for k in ("slot", "epoch")}}
                attempts = ", ".join(f"port {a['backend'].rsplit(':', 1)[-1]} {a.get('error') or a.get('status')} "
                                     f"{a['ms']} ms" for a in r["attempts"])
                evidence = duty_log(r["signing_root"])
                new = any(node == 0 and ts and ts >= crash["armed"] for node, ts in evidence["submitted"])
                lines.append(f"- {s['name']}: {r['type']} {duty_time(r)}: {attempts}; "
                             f"{'new' if new else 'existing'} authorization, accepted by consensus at "
                             f"heights {evidence['authorized_at']}, signed by nodes {evidence['signed_by']}")
    lines.append("")
    for item in result["security"]:
        lines.append(f"- security: {'ok' if item['passed'] else 'FAILED'}: {item['check']} ({item['detail']})")
    with open(f"{WORK}/report.md", "w") as file:
        file.write("\n".join(lines) + "\n")
    print("\n".join(lines))
    return result


# ---------------------------------------------------------------------------------------------


def pull_images():
    """The images the run starts later, pulled first: a failing pull is an environment failure,
    and pull progress does not hide a later command's error."""
    for image in ("RUNTIME_IMAGE", "LIGHTHOUSE_IMAGE", "FOUNDRY_IMAGE"):
        try:
            run(["docker", "pull", "-q", VERSIONS[image]], timeout=900)
        except RuntimeError as error:
            raise Failure("environment", f"pulling {VERSIONS[image]}: {error}") from error


def run_all(observed=3, proposal_epochs=12):
    os.makedirs(f"{WORK}/logs", exist_ok=True)
    pull_images()
    devnet_up()
    chain = Chain()
    log(f"devnet: {chain.seconds_per_slot} s slots, {chain.slots_per_epoch} slots per epoch, "
        f"genesis fork version {chain.genesis_fork_version}")
    signers_start()
    key = dkg()
    activation = activate(key, chain)
    deposit(key, chain)
    proxy_start()
    vc_start(key)
    index, activation_epoch = wait_active(key, chain)
    recorder = Recorder(index, activation_epoch, chain)
    recorder.start()
    save("validator.json", {"public_key": key, "index": index, "activation_epoch": activation_epoch,
                            "mpc_activation_height": activation["activated_at"],
                            "genesis_validators_root": chain.genesis_validators_root})
    chain.wait_epoch(activation_epoch)
    def baseline():
        observe("baseline", index, observed, chain, until_proposal=proposal_epochs)
    scenario("baseline", baseline)
    scenario("node-offline", node_offline(index, chain, observed))
    scenario("coordinator-failover", coordinator_failover(index, chain, observed))
    scenario("inflight-retry", inflight_retry(index, chain))
    security_checks(key, chain)
    recorder.stop()
    return report(chain)


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("run")
    devnet = sub.add_parser("devnet")
    devnet.add_argument("action", choices=["up", "down"])
    signers = sub.add_parser("signers")
    signers.add_argument("action", choices=["start", "stop"])
    sub.add_parser("report")
    sub.add_parser("stop")
    args = parser.parse_args()
    workdir()
    workdir("logs")
    try:
        if args.command == "run":
            run_all()
        elif args.command == "devnet":
            devnet_up() if args.action == "up" else devnet_down()
        elif args.command == "signers":
            signers_start() if args.action == "start" else signers_stop()
        elif args.command == "report":
            report()
        elif args.command == "stop":
            vc_stop()
            proxy_stop()
            signers_stop()
            devnet_down()
    except Failure as failure:
        log(f"FAILED {failure}")
        save("failure.json", {"stage": failure.stage, "message": str(failure)})
        sys.exit(1)
    except Exception as error:  # noqa: BLE001 - reported with its stage, then re-raised
        log(f"FAILED [unexpected] {type(error).__name__}: {error}")
        save("failure.json", {"stage": "unexpected", "message": f"{type(error).__name__}: {error}"})
        raise
    finally:
        # The driver runs as root inside the environment: the host user keeps its work files.
        if os.geteuid() == 0:
            subprocess.run(["chown", "-R", f"{UID}:{GID}", WORK], check=False)


if __name__ == "__main__":
    main()
