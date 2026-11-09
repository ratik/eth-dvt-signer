#!/usr/bin/env python3
"""Gloas SSZ test vectors for the unit tests (tests/unit/eth/gloas.rs).

Source: consensus-specs v1.7.0-beta.4 release asset `mainnet.tar.gz`
(https://github.com/ethereum/consensus-specs/releases/tag/v1.7.0-beta.4,
sha256 67762986572372a08d3b182535aa760433c86e174e14e0bbd756f350dd19398c, CC0-1.0),
directory `tests/mainnet/gloas/ssz_static`, mode `ssz_random`.

Each case's `value.yaml` is written in the Web3Signer API's JSON conventions (integers as decimal
strings, bytes as 0x-hex, booleans as booleans) next to its `roots.yaml` root, one file per type:

    {"source": ..., "type": ..., "cases": [{"case": "ssz_random/case_0", "value": {...}, "root": "0x.."}]}

Usage: extract.py <tests/mainnet/gloas/ssz_static> <output directory>
"""

import json
import pathlib
import sys

import yaml

SOURCE = (
    "consensus-specs v1.7.0-beta.4 mainnet.tar.gz "
    "(sha256 67762986572372a08d3b182535aa760433c86e174e14e0bbd756f350dd19398c), "
    "tests/mainnet/gloas/ssz_static"
)

# Type -> number of cases kept (the payload types are ~25 KB a case).
TYPES = {
    "Attestation": 5,
    "AggregateAndProof": 5,
    "PayloadAttestationData": 5,
    "ProposerPreferences": 5,
    "ExecutionRequests": 5,
    "ExecutionPayload": 3,
    "ExecutionPayloadEnvelope": 3,
}


def quoted(value):
    """The Web3Signer JSON form: integers (u64, uint256) as decimal strings."""
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return str(value)
    if isinstance(value, list):
        return [quoted(item) for item in value]
    if isinstance(value, dict):
        return {key: quoted(item) for key, item in value.items()}
    return value


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    source, output = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
    output.mkdir(parents=True, exist_ok=True)
    for name, count in TYPES.items():
        cases = []
        for index in range(count):
            directory = source / name / "ssz_random" / f"case_{index}"
            with open(directory / "value.yaml") as file:
                value = yaml.safe_load(file)
            with open(directory / "roots.yaml") as file:
                root = yaml.safe_load(file)["root"]
            cases.append({"case": f"ssz_random/case_{index}", "value": quoted(value), "root": root})
        with open(output / f"{name}.json", "w") as file:
            json.dump({"source": SOURCE, "type": name, "cases": cases}, file, indent=1)
            file.write("\n")
        print(f"{name}: {len(cases)} cases")


if __name__ == "__main__":
    main()
