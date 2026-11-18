#!/usr/bin/env python3
"""Key setup at scale (docs/load-test.md, section 4): how fast four nodes on one host take
thousands of validator keys through consensus, and how their state grows.

Runs inside one container with no network (integration/load/run-keys.sh): four signers on
loopback (`--eth-network hoodi`, approvers 2 of 3, development consensus keys), then

  dkg     N DKG ceremonies (`POST /dkg/start`, validator keys), C at a time, then one approved
          activation each (`mpc-admin draft activate`, two offline approvals);
  import  N keystores split offline (`mpc-keytool split`), then per key an approved registration,
          the four share installs and, per batch of B keys, one approved history import of an
          empty interchange, then one approved activation each.

Every protected operation uses the network's next administrative nonce, so they go one at a
time. With --activate-batch K, the activations go K keys per approved operation
(`POST /validators/activate/batch`) instead of one; with --register-batch R, the registrations
of imported keys R per operation (`POST /keys/import/batch`). A sampler records every 10 s the
size of each node's data directory, the nodes' RSS and the keys done (samples.jsonl). The summary is summary.json.

  keys.py WORK --dkg N --import N [--concurrency C] [--batch B] [--activate-batch K]
                [--register-batch R]
"""
import argparse
import concurrent.futures
import json
import os
import statistics
import subprocess
import threading
import time
import urllib.error
import urllib.request

BIN = "/it/target/release"
SIGNER, ADMIN, KEYTOOL = f"{BIN}/eth-mpc-signer", f"{BIN}/mpc-admin", f"{BIN}/mpc-keytool"
KEYSTORES = f"{BIN}/examples/load-keystores"
NODES = 4
HTTP = 8080
ACK = {"previous_signer_stopped": True, "no_other_active_signer": True,
       "history_exported_after_stop": True, "automatic_restart_disabled": True}

START = time.time()
PROGRESS = {"phase": "setup", "dkg_done": 0, "dkg_active": 0, "import_registered": 0,
            "import_active": 0}
ACTIVATE_BATCH = 0
REGISTER_BATCH = 0


def log(message):
    print(f"{time.time() - START:8.1f}s {message}", flush=True)


def http(method, url, body=None, timeout=60):
    data = None if body is None else json.dumps(body).encode()
    request = urllib.request.Request(url, data=data, method=method,
                                     headers={"content-type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, json.loads(response.read() or b"null")
    except urllib.error.HTTPError as error:
        text = error.read()
        try:
            return error.code, json.loads(text)
        except ValueError:
            return error.code, text.decode(errors="replace")
    except (urllib.error.URLError, ConnectionError, TimeoutError) as error:
        return 0, str(error)


def node(i):
    return f"http://127.0.0.1:{HTTP + i}"


def run(*args):
    result = subprocess.run(args, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"{args[0]} {args[1]}: {result.returncode}: {result.stderr[-2000:]}")
    return result.stdout


def percentiles(values):
    if not values:
        return None
    ordered = sorted(values)
    pick = lambda q: ordered[min(len(ordered) - 1, int(q * len(ordered)))]
    return {"n": len(values), "p50": round(pick(0.5), 1), "p95": round(pick(0.95), 1),
            "p99": round(pick(0.99), 1), "max": round(ordered[-1], 1),
            "mean": round(statistics.mean(values), 1), "sum_s": round(sum(values) / 1000, 1)}


class Network:
    def __init__(self, work):
        self.work = work
        self.data = f"{work}/signers"
        self.processes = []
        os.makedirs(f"{work}/approvers", exist_ok=True)
        os.makedirs(f"{work}/logs", exist_ok=True)
        self.approver_keys = []
        for index in range(3):
            path = f"{work}/approvers/approver-{index}.key"
            if not os.path.exists(path):
                run(ADMIN, "approver-key", "--output", path)
            self.approver_keys.append(path)
        public = [run(ADMIN, "approver-public-key", "--key", key).strip()
                  for key in self.approver_keys]
        self.approvers = f"{work}/approvers/approvers.json"
        with open(self.approvers, "w") as file:
            json.dump({"threshold": 2, "approvers": public}, file)
        self.share_keys = []
        for index in range(NODES):
            path = f"{work}/share-key-{index}"
            if not os.path.exists(path):
                run(KEYTOOL, "share-key", "--out", path)
            self.share_keys.append(path)
        self.drafts = 0

    def start(self):
        for i in range(NODES):
            out = open(f"{self.work}/logs/signer-{i}.log", "a")
            self.processes.append(subprocess.Popen(
                [SIGNER, "--id", str(i), "--participants", str(NODES), "--data-dir", self.data,
                 "--eth-network", "hoodi", "--approvers", self.approvers,
                 "--share-encryption-key", self.share_keys[i]],
                stdout=out, stderr=subprocess.STDOUT, env={**os.environ, "RUST_LOG": "info"}))
        deadline = time.time() + 120
        while time.time() < deadline:
            if all(http("GET", f"{node(i)}/ready", timeout=2)[0] == 200 for i in range(NODES)):
                log("network ready")
                return
            time.sleep(1)
        raise RuntimeError("the nodes did not become ready")

    def stop(self):
        for process in self.processes:
            process.terminate()
        for process in self.processes:
            try:
                process.wait(timeout=20)
            except subprocess.TimeoutExpired:
                process.kill()

    def authorized(self, operation, request, timings):
        """`request` with the approvers' authorization for the network's next nonce."""
        self.drafts += 1
        base = f"{self.work}/approvers/op"
        with open(f"{base}-request.json", "w") as file:
            json.dump(request, file)
        for path in (f"{base}.json", f"{base}-0.json", f"{base}-1.json"):
            if os.path.exists(path):
                os.remove(path)
        t0 = time.time()
        nodes = ",".join(f"127.0.0.1:{HTTP + i}" for i in range(NODES))
        run(ADMIN, "--nodes", nodes, "draft", operation, "--request", f"@{base}-request.json",
            "--output", f"{base}.json")
        t1 = time.time()
        approvals = []
        for index in range(2):
            run(ADMIN, "sign", "--command", f"{base}.json", "--key", self.approver_keys[index],
                "--output", f"{base}-{index}.json", "--yes")
            with open(f"{base}-{index}.json") as file:
                approvals += json.load(file)["approvals"]
        t2 = time.time()
        with open(f"{base}.json") as file:
            command = json.load(file)
        timings["draft"].append((t1 - t0) * 1000)
        timings["approve"].append((t2 - t1) * 1000)
        return {**command["request"],
                "authorization": {"nonce": command["nonce"], "approvals": approvals}}

    def submit(self, operation, url, request, timings, accept=lambda status, body: status == 200):
        body = self.authorized(operation, request, timings)
        t0 = time.time()
        status, answer = http("POST", url, body, timeout=120)
        timings["submit"].append((time.time() - t0) * 1000)
        if not accept(status, answer):
            raise RuntimeError(f"{operation}: {status} {answer}")
        return answer


def tree_size(path):
    total = 0
    for root, _, files in os.walk(path):
        for name in files:
            try:
                total += os.lstat(os.path.join(root, name)).st_size
            except FileNotFoundError:
                pass
    return total


def partitions(path):
    """Bytes per top-level entry of a node's data directory."""
    sizes = {}
    if os.path.isdir(path):
        for entry in os.listdir(path):
            full = os.path.join(path, entry)
            sizes[entry] = tree_size(full) if os.path.isdir(full) else os.lstat(full).st_size
    return sizes


def rss(pid):
    try:
        with open(f"/proc/{pid}/status") as file:
            for line in file:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1]) * 1024
    except FileNotFoundError:
        return None


def host_load():
    """The host's load average and pressure stall shares (avg10, %): other work on the host slows
    consensus, so every sample says how busy the host was."""
    load = {}
    try:
        with open("/proc/loadavg") as file:
            load["loadavg"] = [float(v) for v in file.read().split()[:3]]
    except OSError:
        pass
    for resource in ("cpu", "io"):
        try:
            with open(f"/proc/pressure/{resource}") as file:
                for line in file:
                    kind, *fields = line.split()
                    load[f"psi_{resource}_{kind}"] = float(dict(
                        f.split("=") for f in fields)["avg10"])
        except OSError:
            pass
    return load


def sampler(network, path, stop):
    with open(path, "a") as out:
        while not stop.wait(10):
            sample = {"t": round(time.time() - START, 1), **PROGRESS,
                      "bytes": [tree_size(f"{network.data}/node-{i}") for i in range(NODES)],
                      "rss": [rss(p.pid) for p in network.processes], **host_load()}
            status, body = http("GET", f"{node(0)}/status", timeout=5)
            if status == 200 and isinstance(body, dict):
                sample["status"] = {k: v for k, v in body.items()
                                    if isinstance(v, (int, float, str, bool))}
            out.write(json.dumps(sample) + "\n")
            out.flush()


def genesis_validators_root():
    status, body = http("GET", f"{node(0)}/eth/network")
    if status != 200:
        raise RuntimeError(f"/eth/network: {status} {body}")
    for key in ("genesis_validators_root", "genesisValidatorsRoot"):
        if key in body:
            return body[key]
    raise RuntimeError(f"/eth/network: no genesis validators root in {body}")


def timings():
    return {"draft": [], "approve": [], "submit": []}


def dkg_phase(network, count, concurrency, gvr, summary, activate=True):
    PROGRESS["phase"] = "dkg"
    concurrency = min(concurrency, 4)  # dkg::MAX_ACTIVE ceremonies at once
    durations = []

    def ceremony(index):
        ceremony_id = f"load-dkg-{index}"
        t0 = time.time()
        status, body = http("POST", f"{node(index % NODES)}/dkg/start",
                            {"ceremony_id": ceremony_id, "validator": True}, timeout=60)
        if status != 200:
            raise RuntimeError(f"dkg start {ceremony_id}: {status} {body}")
        while True:
            status, body = http("GET", f"{node(index % NODES)}/dkg/status/{ceremony_id}")
            if status == 200 and body.get("status") == "completed":
                durations.append((time.time() - t0) * 1000)
                PROGRESS["dkg_done"] += 1
                return body["public_key"]
            if status == 200 and body.get("status") not in ("in_progress", "completed"):
                raise RuntimeError(f"dkg {ceremony_id}: {body}")
            time.sleep(0.2)

    t0 = time.time()
    with concurrent.futures.ThreadPoolExecutor(concurrency) as pool:
        keys = list(pool.map(ceremony, range(count)))
    ceremonies_s = time.time() - t0
    log(f"dkg: {count} ceremonies in {ceremonies_s:.0f} s")

    times = timings()
    t0 = time.time()
    activate_keys(network, keys if activate else [], gvr, None, times, "dkg_active",
                  ACTIVATE_BATCH)
    activation_s = time.time() - t0
    summary["dkg"] = {"keys": count, "concurrency": concurrency,
                      "ceremonies_s": round(ceremonies_s, 1),
                      "ceremony_ms": percentiles(durations),
                      "activations_s": round(activation_s, 1),
                      "activation_ms": {k: percentiles(v) for k, v in times.items()}}
    return keys


def activate_keys(network, keys, gvr, acknowledgment, times, progress, per_batch):
    """Activate `keys`, one approved operation per key, or per `per_batch` keys."""
    extra = {"acknowledgment": acknowledgment} if acknowledgment else {}
    if not per_batch:
        for done, key in enumerate(keys, 1):
            network.submit("activate", f"{node(done % NODES)}/validators/activate",
                           {"public_key": key, "genesis_validators_root": gvr, **extra}, times)
            PROGRESS[progress] = done
            if done % 100 == 0:
                log(f"{progress}: {done}")
        return
    for start in range(0, len(keys), per_batch):
        group = keys[start:start + per_batch]
        request = {"genesis_validators_root": gvr,
                   "validators": [{"public_key": key, **extra} for key in group]}
        network.submit("activate-batch", f"{node(start % NODES)}/validators/activate/batch",
                       request, times)
        PROGRESS[progress] = start + len(group)
        log(f"{progress}: {start + len(group)}")


def import_phase(network, count, concurrency, batch, gvr, summary):
    PROGRESS["phase"] = "import"
    keys_dir = f"{network.work}/keystores"
    if not os.path.isdir(keys_dir) or len(os.listdir(keys_dir)) < count:
        t0 = time.time()
        run(KEYSTORES, str(count), keys_dir)
        log(f"import: {count} keystores in {time.time() - t0:.0f} s")
    with open(f"{network.work}/password", "w") as file:
        file.write("load")
    identities = sorted((http("GET", f"{node(i)}/identity")[1] for i in range(NODES)),
                        key=lambda identity: identity["participant_index"])
    committee = f"{network.work}/committee.json"
    with open(committee, "w") as file:
        json.dump({"participants": [{"identity": i["identity"],
                                     "share_encryption_key": i["share_encryption_key"]}
                                    for i in identities]}, file)
    index_of = {i: identity["participant_index"]
                for i in range(NODES)
                for identity in [http("GET", f"{node(i)}/identity")[1]]}

    def split(index):
        output = f"{network.work}/shares/{index}"
        if not os.path.exists(f"{output}/manifest.json"):
            run(KEYTOOL, "split", "--keystore", f"{keys_dir}/key-{index}.json",
                "--password-file", f"{network.work}/password", "--committee", committee,
                "--ceremony-id", f"approved.load-import-{index}", "--output", output)
        with open(f"{output}/manifest.json") as file:
            return json.load(file)

    os.makedirs(f"{network.work}/shares", exist_ok=True)
    t0 = time.time()
    with concurrent.futures.ThreadPoolExecutor(concurrency) as pool:
        manifests = list(pool.map(split, range(count)))
    split_s = time.time() - t0
    log(f"import: {count} splits in {split_s:.0f} s")

    register, history, activate = timings(), timings(), timings()
    install_ms = []
    keys = []
    pool = concurrent.futures.ThreadPoolExecutor(NODES * 2)

    def install(index, i):
        with open(f"{network.work}/shares/{index}/node-{index_of[i]}.enc") as file:
            envelope = json.load(file)
        t = time.time()
        while True:  # the node may not have applied the registration's block yet
            status, body = http("POST", f"{node(i)}/keys/import/share", envelope, timeout=120)
            if status != 404 or time.time() - t > 60:
                break
            time.sleep(0.1)
        if status != 200:
            raise RuntimeError(f"share {index} on node {i}: {status} {body}")
        install_ms.append((time.time() - t) * 1000)

    t0 = time.time()
    installs = []
    per_batch = REGISTER_BATCH or 1
    for start in range(0, count, per_batch):
        group = list(enumerate(manifests))[start:start + per_batch]
        if REGISTER_BATCH:
            network.submit("register-import-batch", f"{node(start % NODES)}/keys/import/batch",
                           {"manifests": [manifest for _, manifest in group]}, register)
        else:
            network.submit("register-import", f"{node(start % NODES)}/keys/import",
                           {"manifest": group[0][1]}, register)
        for index, manifest in group:
            keys.append(manifest["validator_public_key"])
            installs += [pool.submit(install, index, i) for i in range(NODES)]
        done = start + len(group)
        PROGRESS["import_registered"] = done
        if done % 100 < per_batch:
            log(f"import: {done} registered")
    for future in installs:
        future.result()
    register_s = time.time() - t0
    log(f"import: {count} registered and installed in {register_s:.0f} s")

    t0 = time.time()
    for start in range(0, count, batch):
        group = keys[start:start + batch]
        interchange = {"metadata": {"interchange_format_version": "5",
                                    "genesis_validators_root": gvr},
                       "data": [{"pubkey": key, "signed_blocks": [], "signed_attestations": []}
                                for key in group]}
        network.submit("import-history", f"{node(start % NODES)}/slashing-protection/import",
                       {"interchange": interchange, "validators": group}, history)
    history_s = time.time() - t0
    log(f"import: histories in {history_s:.0f} s ({batch} keys per import)")

    t0 = time.time()
    activate_keys(network, keys, gvr, ACK, activate, "import_active", ACTIVATE_BATCH)
    activate_s = time.time() - t0
    pool.shutdown()
    summary["import"] = {
        "keys": count, "split_s": round(split_s, 1),
        "register_and_install_s": round(register_s, 1),
        "register_ms": {k: percentiles(v) for k, v in register.items()},
        "share_install_ms": percentiles(install_ms),
        "history_batch": batch, "history_s": round(history_s, 1),
        "history_ms": {k: percentiles(v) for k, v in history.items()},
        "activations_s": round(activate_s, 1),
        "activation_ms": {k: percentiles(v) for k, v in activate.items()}}
    return keys


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("work")
    parser.add_argument("--dkg", type=int, default=0)
    parser.add_argument("--import", dest="imports", type=int, default=0)
    parser.add_argument("--concurrency", type=int, default=8)
    parser.add_argument("--batch", type=int, default=100)
    parser.add_argument("--no-activate", dest="activate", action="store_false",
                        help="DKG only: do not activate the generated keys")
    parser.add_argument("--activate-batch", type=int, default=0,
                        help="keys per approved activation (0: one activation per key)")
    parser.add_argument("--register-batch", type=int, default=0,
                        help="imported keys per approved registration (0: one per key)")
    args = parser.parse_args()
    global ACTIVATE_BATCH, REGISTER_BATCH
    ACTIVATE_BATCH = args.activate_batch
    REGISTER_BATCH = args.register_batch
    os.makedirs(args.work, exist_ok=True)
    network = Network(args.work)
    stop = threading.Event()
    summary = {"args": vars(args)}
    try:
        network.start()
        gvr = genesis_validators_root()
        summary["start_bytes"] = [partitions(f"{network.data}/node-{i}") for i in range(NODES)]
        thread = threading.Thread(target=sampler,
                                  args=(network, f"{args.work}/samples.jsonl", stop), daemon=True)
        thread.start()
        if args.dkg:
            dkg_phase(network, args.dkg, args.concurrency, gvr, summary, args.activate)
            summary["after_dkg_bytes"] = [tree_size(f"{network.data}/node-{i}")
                                          for i in range(NODES)]
        if args.imports:
            import_phase(network, args.imports, args.concurrency, args.batch, gvr, summary)
        PROGRESS["phase"] = "done"
        status, validators = http("GET", f"{node(0)}/validators", timeout=60)
        summary["validators"] = len(validators) if status == 200 else f"{status}"
        summary["end_bytes"] = [partitions(f"{network.data}/node-{i}") for i in range(NODES)]
        summary["end_rss"] = [rss(p.pid) for p in network.processes]
        summary["total_s"] = round(time.time() - START, 1)
    finally:
        stop.set()
        with open(f"{args.work}/summary.json", "w") as file:
            json.dump(summary, file, indent=1)
        network.stop()
        log("stopped; summary.json written")


if __name__ == "__main__":
    main()
