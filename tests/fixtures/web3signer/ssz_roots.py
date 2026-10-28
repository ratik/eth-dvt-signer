"""Signing roots of Web3Signer requests, computed with a minimal SSZ implementation that shares no
code with the signer (Python standard library only), to cross-check fixtures whose root Web3Signer
did not publish.

    python3 -I ssz_roots.py [--minimal] FILE.json...

Prints the computed signing root and the request's `signingRoot` for each file. `--minimal` uses
the minimal preset's list and vector limits (Web3Signer's contribution example is written for it).
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
}


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
    raise ValueError(f"unsupported type {kind}")


def signing_root(request, p):
    root, epoch = object_root_and_epoch(request, p)
    fork = request["fork_info"]["fork"]
    version = fork["previous_version"] if epoch < int(fork["epoch"]) else fork["current_version"]
    fork_data_root = container(
        hexbytes(version, 4).ljust(32, b"\0"),
        bytes32(request["fork_info"]["genesis_validators_root"]),
    )
    domain = bytes([DOMAINS[request["type"]], 0, 0, 0]) + fork_data_root[:28]
    return container(root, domain)


def main(args):
    minimal = "--minimal" in args
    p = preset(minimal)
    for path in (arg for arg in args if arg != "--minimal"):
        with open(path) as file:
            request = json.load(file)
        computed = "0x" + signing_root(request, p).hex()
        given = request.get("signingRoot")
        mark = "match" if computed == given else "DIFFERENT"
        print(f"{path}: computed {computed} given {given} {mark}")


if __name__ == "__main__":
    main(sys.argv[1:])
