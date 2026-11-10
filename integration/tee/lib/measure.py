#!/usr/bin/env python3
"""Measurements of the TEE image (integration/tee/README.md).

  measure.py uki UKI            the UKI's hashes, PE sections and command line (verity root hash)
  measure.py gpt DISK           the disk's partitions and the digest of its UEFI GPT event
  measure.py extract DISK TYPE OUT   copy the partition of GPT type TYPE (root, esp...) to OUT
  measure.py rtmr3 DIGEST       RTMR3 after one extension with DIGEST (hex SHA-384) from zero

On TDX, the firmware measures the UKI (its Authenticode SHA-384, the same digest a TPM's PCR 4
gets) and the GPT of the boot disk into RTMR1. The full expected RTMR1 also depends on the
firmware's other events in that register, which are confirmed against a real event log on GCP.
"""

import hashlib
import struct
import sys
import uuid

import pefile

GPT_TYPES = {
    "esp": uuid.UUID("c12a7328-f81f-11d2-ba4b-00a0c93ec93b"),
    "root": uuid.UUID("4f68bce3-e8cd-4db1-96e7-fbcaf984b709"),  # root-x86-64
    "root-verity": uuid.UUID("2c7357ed-ebd2-46d9-aec1-23d437ec2bf5"),
}
SECTOR = 512


def authenticode(path, algorithm="sha384"):
    """The PE image hash of the Authenticode specification, as UEFI firmware measures it."""
    data = open(path, "rb").read()
    pe = pefile.PE(data=data, fast_load=True)
    digest = hashlib.new(algorithm)
    checksum = pe.OPTIONAL_HEADER.get_field_absolute_offset("CheckSum")
    security = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]]
    security_entry = security.get_file_offset()
    headers = pe.OPTIONAL_HEADER.SizeOfHeaders
    digest.update(data[:checksum])
    digest.update(data[checksum + 4 : security_entry])
    digest.update(data[security_entry + 8 : headers])
    hashed = headers
    for section in sorted(pe.sections, key=lambda s: s.PointerToRawData):
        if section.SizeOfRawData == 0:
            continue
        start = section.PointerToRawData
        digest.update(data[start : start + section.SizeOfRawData])
        hashed += section.SizeOfRawData
    end = len(data) - security.Size
    if end > hashed:
        digest.update(data[hashed:end])
    return digest.hexdigest()


def uki(path):
    data = open(path, "rb").read()
    print(f"uki.sha384 {hashlib.sha384(data).hexdigest()}")
    print(f"uki.sha256 {hashlib.sha256(data).hexdigest()}")
    print(f"uki.authenticode-sha384 {authenticode(path)}")
    pe = pefile.PE(data=data, fast_load=True)
    cmdline = ""
    for section in pe.sections:
        name = section.Name.rstrip(b"\0").decode()
        raw = section.get_data()[: section.Misc_VirtualSize]
        print(f"uki.section {name} {len(raw)} {hashlib.sha384(raw).hexdigest()}")
        if name == ".cmdline":
            cmdline = raw.rstrip(b"\0").decode().strip()
        if name == ".osrel":
            for line in raw.decode(errors="replace").splitlines():
                if line.startswith(("VERSION_CODENAME=", "IMAGE_ID=")):
                    print(f"uki.osrel {line}")
        if name == ".uname":
            kernel = raw.rstrip(b"\0").decode()
            print(f"uki.kernel {kernel}")
    print(f"uki.cmdline {cmdline}")
    for word in cmdline.split():
        if word.startswith("roothash="):
            print(f"roothash {word.removeprefix('roothash=')}")


def read_gpt(path):
    with open(path, "rb") as disk:
        disk.seek(SECTOR)
        header = disk.read(SECTOR)
        if header[:8] != b"EFI PART":
            sys.exit(f"{path}: no GPT")
        header_size = struct.unpack_from("<I", header, 12)[0]
        entries_lba, count, entry_size = struct.unpack_from("<QII", header, 72)
        disk.seek(entries_lba * SECTOR)
        table = disk.read(count * entry_size)
    entries = []
    for index in range(count):
        entry = table[index * entry_size : (index + 1) * entry_size]
        if entry[:16] == bytes(16):
            continue
        type_guid = uuid.UUID(bytes_le=entry[:16])
        part_guid = uuid.UUID(bytes_le=entry[16:32])
        first, last = struct.unpack_from("<QQ", entry, 32)
        label = entry[56:128].decode("utf-16-le").rstrip("\0")
        entries.append((entry, type_guid, part_guid, first, last, label))
    return header[:header_size], entries


def gpt(path):
    header, entries = read_gpt(path)
    names = {v: k for k, v in GPT_TYPES.items()}
    for _, type_guid, part_guid, first, last, label in entries:
        size = (last - first + 1) * SECTOR
        print(f"partition {names.get(type_guid, type_guid)} uuid={part_guid} label={label} "
              f"offset={first * SECTOR} size={size}")
    # EV_EFI_GPT_EVENT: UEFI_GPT_DATA = the header, the number of entries, the non-empty entries.
    event = header + struct.pack("<Q", len(entries)) + b"".join(e[0] for e in entries)
    print(f"gpt-event.sha384 {hashlib.sha384(event).hexdigest()}")


def extract(path, kind, out):
    _, entries = read_gpt(path)
    want = GPT_TYPES[kind]
    for _, type_guid, _, first, last, _ in entries:
        if type_guid == want:
            with open(path, "rb") as disk, open(out, "wb") as target:
                disk.seek(first * SECTOR)
                remaining = (last - first + 1) * SECTOR
                while remaining:
                    chunk = disk.read(min(remaining, 1 << 20))
                    target.write(chunk)
                    remaining -= len(chunk)
            return
    sys.exit(f"{path}: no {kind} partition")


def rtmr3(digest):
    print(hashlib.sha384(bytes(48) + bytes.fromhex(digest)).hexdigest())


if __name__ == "__main__":
    command, *rest = sys.argv[1:] or ["help"]
    {"uki": uki, "gpt": gpt, "extract": extract, "rtmr3": rtmr3}.get(
        command, lambda *_: sys.exit(__doc__)
    )(*rest)
