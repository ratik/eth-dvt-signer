"""Signing roots of Web3Signer requests, computed with a minimal SSZ implementation that shares no
code with the signer (Python standard library only), to cross-check fixtures whose root Web3Signer
did not publish.

    python3 -I ssz_roots.py [--minimal] [--genesis-fork-version 0x..] FILE.json...
    python3 -I ssz_roots.py --write-block-fixtures DIRECTORY

Prints the computed signing root and the request's `signingRoot` for each file. `--minimal` uses
the minimal preset's list and vector limits (Web3Signer's contribution example is written for it).
`--genesis-fork-version` is the network's for a `VALIDATOR_REGISTRATION`, which carries none
(default `0x00000001`, the network of Web3Signer's examples, as their `DEPOSIT` shows).
`--write-block-fixtures` writes the per-fork BLOCK_V2 requests (see `block_fixtures`).
"""

import hashlib
import json
import sys

SLOTS_PER_EPOCH = 32  # Both presets differ here (minimal: 8); the fixtures stay below one epoch.


def preset(minimal):
    if minimal:
        return {"committee": 2048, "committees": 4, "sync_subcommittee": 8}
    return {"committee": 2048, "committees": 64, "sync_subcommittee": 128}


def sha(a, b):
    return hashlib.sha256(a + b).digest()


def zero_hash(depth):
    node = b"\0" * 32
    for _ in range(depth):
        node = sha(node, node)
    return node


def merkleize(chunks, limit=None):
    count = len(chunks) if limit is None else limit
    assert len(chunks) <= max(count, 1)
    depth = max(count - 1, 0).bit_length()
    layer = list(chunks)
    for level in range(depth):
        if len(layer) % 2:
            layer.append(zero_hash(level))
        layer = [sha(layer[i], layer[i + 1]) for i in range(0, len(layer), 2)]
    return layer[0] if layer else zero_hash(depth)


def pack(data):
    chunks = [data[i : i + 32] for i in range(0, len(data), 32)]
    return [chunk.ljust(32, b"\0") for chunk in chunks]


def hexbytes(text, size=None):
    assert text.startswith("0x"), text
    data = bytes.fromhex(text[2:])
    assert size is None or len(data) == size, (text, size)
    return data


def uint64(value):
    return int(value).to_bytes(8, "little").ljust(32, b"\0")


def bytes32(text):
    return hexbytes(text, 32)


def signature(text):
    return merkleize(pack(hexbytes(text, 96)))


def bitvector(text, bits):
    data = hexbytes(text, (bits + 7) // 8)
    return merkleize(pack(data), (bits + 255) // 256)


def bitlist(text, limit):
    data = bytearray(hexbytes(text))
    assert data and data[-1], "a bitlist ends with its delimiter bit"
    length = (len(data) - 1) * 8 + data[-1].bit_length() - 1
    data[-1] &= ~(1 << (data[-1].bit_length() - 1))
    data = bytes(data[: (length + 7) // 8])
    root = merkleize(pack(data), (limit + 255) // 256)
    return sha(root, length.to_bytes(32, "little"))


def container(*fields):
    return merkleize(list(fields))


def checkpoint(value):
    return container(uint64(value["epoch"]), bytes32(value["root"]))


def attestation_data(value):
    return container(
        uint64(value["slot"]),
        uint64(value["index"]),
        bytes32(value["beacon_block_root"]),
        checkpoint(value["source"]),
        checkpoint(value["target"]),
    )


def attestation(value, p):
    fields = [
        bitlist(value["aggregation_bits"], p["committee"] * (p["committees"] if "committee_bits" in value else 1)),
        attestation_data(value["data"]),
        signature(value["signature"]),
    ]
    if "committee_bits" in value:
        fields.append(bitvector(value["committee_bits"], p["committees"]))
    return container(*fields)


DOMAINS = {
    "BLOCK_V2": 0,
    "ATTESTATION": 1,
    "RANDAO_REVEAL": 2,
    "VOLUNTARY_EXIT": 4,
    "AGGREGATION_SLOT": 5,
    "AGGREGATE_AND_PROOF": 6,
    "SYNC_COMMITTEE_MESSAGE": 7,
    "SYNC_COMMITTEE_SELECTION_PROOF": 8,
    "SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF": 9,
    "DEPOSIT": 3,
}

# DOMAIN_APPLICATION_BUILDER (builder-specs).
APPLICATION_BUILDER = bytes([0, 0, 0, 1])


def object_root_and_epoch(request, p):
    kind = request["type"]
    if kind == "BLOCK_V2":
        h = request["beacon_block"]["block_header"]
        root = container(
            uint64(h["slot"]),
            uint64(h["proposer_index"]),
            bytes32(h["parent_root"]),
            bytes32(h["state_root"]),
            bytes32(h["body_root"]),
        )
        return root, int(h["slot"]) // SLOTS_PER_EPOCH
    if kind == "ATTESTATION":
        a = request["attestation"]
        return attestation_data(a), int(a["target"]["epoch"])
    if kind == "RANDAO_REVEAL":
        epoch = int(request["randao_reveal"]["epoch"])
        return uint64(epoch), epoch
    if kind == "VOLUNTARY_EXIT":
        e = request["voluntary_exit"]
        return container(uint64(e["epoch"]), uint64(e["validator_index"])), int(e["epoch"])
    if kind == "AGGREGATION_SLOT":
        slot = int(request["aggregation_slot"]["slot"])
        return uint64(slot), slot // SLOTS_PER_EPOCH
    if kind == "AGGREGATE_AND_PROOF":
        a = request["aggregate_and_proof"]
        root = container(
            uint64(a["aggregator_index"]),
            attestation(a["aggregate"], p),
            signature(a["selection_proof"]),
        )
        return root, int(a["aggregate"]["data"]["slot"]) // SLOTS_PER_EPOCH
    if kind == "SYNC_COMMITTEE_MESSAGE":
        m = request["sync_committee_message"]
        return bytes32(m["beacon_block_root"]), int(m["slot"]) // SLOTS_PER_EPOCH
    if kind == "SYNC_COMMITTEE_SELECTION_PROOF":
        s = request["sync_aggregator_selection_data"]
        root = container(uint64(s["slot"]), uint64(s["subcommittee_index"]))
        return root, int(s["slot"]) // SLOTS_PER_EPOCH
    if kind == "SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF":
        c = request["contribution_and_proof"]
        k = c["contribution"]
        contribution = container(
            uint64(k["slot"]),
            bytes32(k["beacon_block_root"]),
            uint64(k["subcommittee_index"]),
            bitvector(k["aggregation_bits"], p["sync_subcommittee"]),
            signature(k["signature"]),
        )
        root = container(
            uint64(c["aggregator_index"]), contribution, signature(c["selection_proof"])
        )
        return root, int(k["slot"]) // SLOTS_PER_EPOCH
    if kind == "DEPOSIT":
        d = request["deposit"]
        root = container(
            merkleize(pack(hexbytes(d["pubkey"], 48))),
            bytes32(d["withdrawal_credentials"]),
            uint64(d["amount"]),
        )
        return root, 0
    if kind == "VALIDATOR_REGISTRATION":
        r = request["validator_registration"]
        root = container(
            hexbytes(r["fee_recipient"], 20).ljust(32, b"\0"),
            uint64(r["gas_limit"]),
            uint64(r["timestamp"]),
            merkleize(pack(hexbytes(r["pubkey"], 48))),
        )
        return root, 0
    raise ValueError(f"unsupported type {kind}")


def genesis_domain(domain_type, version):
    """compute_domain with the genesis fork version and a zero genesis validators root."""
    fork_data_root = container(hexbytes(version, 4).ljust(32, b"\0"), b"\0" * 32)
    return domain_type + fork_data_root[:28]


def signing_root(request, p, genesis_fork_version="0x00000001"):
    root, epoch = object_root_and_epoch(request, p)
    if request["type"] == "DEPOSIT":
        # compute_domain(DOMAIN_DEPOSIT): genesis fork version, zero genesis validators root.
        version = request["deposit"]["genesis_fork_version"]
        return container(root, genesis_domain(bytes([DOMAINS["DEPOSIT"], 0, 0, 0]), version))
    if request["type"] == "VALIDATOR_REGISTRATION":
        # compute_domain(DOMAIN_APPLICATION_BUILDER): the network's genesis fork version.
        return container(root, genesis_domain(APPLICATION_BUILDER, genesis_fork_version))
    fork = request["fork_info"]["fork"]
    version = fork["previous_version"] if epoch < int(fork["epoch"]) else fork["current_version"]
    fork_data_root = container(
        hexbytes(version, 4).ljust(32, b"\0"),
        bytes32(request["fork_info"]["genesis_validators_root"]),
    )
    domain = bytes([DOMAINS[request["type"]], 0, 0, 0]) + fork_data_root[:28]
    return container(root, domain)


# Mainnet fork versions and epochs (Lighthouse v8.3.2 `ChainSpec::mainnet`), in order.
MAINNET_FORKS = [
    ("PHASE0", "0x00000000", 0),
    ("ALTAIR", "0x01000000", 74240),
    ("BELLATRIX", "0x02000000", 144896),
    ("CAPELLA", "0x03000000", 194048),
    ("DENEB", "0x04000000", 269568),
    ("ELECTRA", "0x05000000", 364032),
    ("FULU", "0x06000000", 411392),
]

# The genesis validators root of Web3Signer's examples (the other fixtures).
GENESIS_VALIDATORS_ROOT = "0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673"


def block_fixtures(out_dir):
    """One BLOCK_V2 request per fork from Bellatrix to Fulu, as Lighthouse v8.3.2 builds it:
    `Web3SignerObject::beacon_block` sends `{version, block_header}` from Bellatrix on, and the
    fork info is `ChainSpec::fork_at_epoch(block epoch)` (the fork's previous and current versions
    and its epoch). Full and blinded blocks give the same header, hence the same request."""
    for index, (name, version, epoch) in enumerate(MAINNET_FORKS):
        if index < 2:
            continue  # Phase 0 and Altair send the whole block.
        previous = MAINNET_FORKS[index - 1][1]
        slot = (epoch + 1) * SLOTS_PER_EPOCH + index
        request = {
            "type": "BLOCK_V2",
            "fork_info": {
                "fork": {"previous_version": previous, "current_version": version, "epoch": str(epoch)},
                "genesis_validators_root": GENESIS_VALIDATORS_ROOT,
            },
            "signingRoot": None,
            "beacon_block": {
                "version": name,
                "block_header": {
                    "slot": str(slot),
                    "proposer_index": str(1000 + index),
                    "parent_root": "0x" + bytes([index] * 32).hex(),
                    "state_root": "0x" + bytes([0x10 + index] * 32).hex(),
                    "body_root": "0x" + bytes([0x20 + index] * 32).hex(),
                },
            },
        }
        request["signingRoot"] = "0x" + signing_root(request, preset(False)).hex()
        path = f"{out_dir}/block_v2_mainnet_{name.lower()}.json"
        with open(path, "w") as file:
            file.write(json.dumps(request, separators=(",", ":")) + "\n")
        print(f"wrote {path}")


def main(args):
    if args[:1] == ["--write-block-fixtures"]:
        block_fixtures(args[1])
        return
    minimal = "--minimal" in args
    p = preset(minimal)
    version = "0x00000001"
    if "--genesis-fork-version" in args:
        at = args.index("--genesis-fork-version")
        version = args[at + 1]
        args = args[:at] + args[at + 2 :]
    for path in (arg for arg in args if arg != "--minimal"):
        with open(path) as file:
            request = json.load(file)
        computed = "0x" + signing_root(request, p, version).hex()
        given = request.get("signingRoot")
        mark = "match" if computed == given else "DIFFERENT"
        print(f"{path}: computed {computed} given {given} {mark}")


if __name__ == "__main__":
    main(sys.argv[1:])
