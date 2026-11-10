#!/usr/bin/env python3
"""Measurements of the TEE image (integration/tee/README.md).

  measure.py uki UKI            the UKI's hashes, PE sections and command line (verity root hash)
  measure.py gpt DISK           the disk's partitions and the digest of its UEFI GPT event
  measure.py boot DISK GRUB GRUBCFG UKI
                                GRUB's and the kernel's measurements, and the events and values
                                of RTMR1 and RTMR2 this boot chain gives on GCE (below)
  measure.py extract DISK TYPE OUT   copy the partition of GPT type TYPE (root, esp...) to OUT
  measure.py rtmr3 DIGEST       RTMR3 after one extension with DIGEST (hex SHA-384) from zero
  measure.py console SERIAL OUT [MEASUREMENTS]
                                the measure mode's output (README) in a serial console log: the
                                token (and its claims), the CCEL table and event log (checked
                                against their SHA-256), the TPM's event log, the configuration
                                digest, written to OUT; with the image's measurements, replayed
  measure.py replay --eventlog FILE (--claims JSON | --token JWT) --expected MEASUREMENTS
                    [--config-digest HEX]
                                RTMR0..3 recomputed from a CCEL event log and compared with the
                                token's `tdx` claims; then the boot chain, as the build's
                                measurements file names it: RTMR1 holds GRUB's and the UKI's
                                Authenticode digests; RTMR2 GRUB's commands, the UKI file and its
                                command line (roothash=), and Google's GRUB rule holds; RTMR3 the
                                configuration digest, if given. Also compared with the predicted
                                RTMR1 and RTMR2 (not a check). Prints JSON; exit 0 only if every
                                check holds. Standard library only.
  measure.py grub-rule EVENTLOG [--tpm]
                                Google's rule for GRUB's events (below) on a CCEL log, or with
                                --tpm on a TPM log (PCRs 8 to 15 as RTMR2). JSON; exit 0 if it holds
  measure.py tpm-replay --eventlog FILE --expected MEASUREMENTS
                                a TPM event log (QEMU with swtpm) mapped to the TDX registers as
                                TDVF maps PCRs: its RTMR2 events (but Linux's EV_EVENT_TAG, which
                                go to a TPM only) must be the predicted ones, GRUB's rule must
                                hold, and PCR 4 must hold GRUB, the UKI and the kernel in order
  measure.py selftest MEASUREMENTS [FIXTURE]
                                the replay on synthetic CCEL logs made from the predicted events,
                                good and tampered; then, on a real GCE log (FIXTURE, default
                                testdata/*.json here), Google's GRUB rule and the prediction model

On TDX the firmware measures into RTMR1 the GPT of the boot disk and each EFI application it
loads (their Authenticode SHA-384, as a TPM's PCR 4 gets them): GRUB, the UKI GRUB chainloads, the
kernel systemd-stub loads. RTMR2 gets PCRs 8 to 15: GRUB's file (PCR 9) and command (PCR 8)
measurements, then systemd-stub's measurement of the UKI's sections (PCR 11), the command line
among them. RTMR3 holds what user space extends: the configuration digest (`config`). The CCEL
event log's MR index is 1 for RTMR0 ... 4 for RTMR3.

Google's attestation verifier (go-eventlog, extract.GrubStateFromRTMRLog) refuses a TDX log
unless RTMR2 has only EV_IPL and EV_EVENT_TAG events, at least one EV_IPL starts with a GRUB
prefix (`grub_cmd: `, `kernel_cmdline: `...) and carries the SHA-384 of the rest, and at most one
is a kernel command line. `grub_rule` mirrors it.
"""

import base64
import hashlib
import json
import os
import re
import struct
import sys
import uuid

GPT_TYPES = {
    "esp": uuid.UUID("c12a7328-f81f-11d2-ba4b-00a0c93ec93b"),
    "root": uuid.UUID("4f68bce3-e8cd-4db1-96e7-fbcaf984b709"),  # root-x86-64
    "root-verity": uuid.UUID("2c7357ed-ebd2-46d9-aec1-23d437ec2bf5"),
}
SECTOR = 512
# Where GRUB finds the UKI on the ESP (image/grub/grub.cfg, mkosi.repart/00-esp.conf).
UKI_ON_ESP = "/EFI/Linux/eth-mpc-signer.efi"


def sha384(data):
    return hashlib.sha384(data).digest()


def authenticode_data(data, algorithm="sha384"):
    """The PE image hash of the Authenticode specification, as UEFI firmware measures it."""
    import pefile  # the replay runs where only the standard library is

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


def authenticode(path, algorithm="sha384"):
    return authenticode_data(open(path, "rb").read(), algorithm)


def pe_sections(data):
    """A PE file's sections, each as systemd-stub measures it (its virtual size)."""
    import pefile

    pe = pefile.PE(data=data, fast_load=True)
    return [(s.Name.rstrip(b"\0").decode(), s.get_data()[: s.Misc_VirtualSize]) for s in pe.sections]


def uki(path):
    data = open(path, "rb").read()
    print(f"uki.sha384 {hashlib.sha384(data).hexdigest()}")
    print(f"uki.sha256 {hashlib.sha256(data).hexdigest()}")
    print(f"uki.authenticode-sha384 {authenticode_data(data)}")
    cmdline = ""
    for name, raw in pe_sections(data):
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


def gpt_event(path):
    # EV_EFI_GPT_EVENT: UEFI_GPT_DATA = the header, the number of entries, the non-empty entries.
    header, entries = read_gpt(path)
    return sha384(header + struct.pack("<Q", len(entries)) + b"".join(e[0] for e in entries))


def gpt(path):
    _, entries = read_gpt(path)
    names = {v: k for k, v in GPT_TYPES.items()}
    for _, type_guid, part_guid, first, last, label in entries:
        size = (last - first + 1) * SECTOR
        print(f"partition {names.get(type_guid, type_guid)} uuid={part_guid} label={label} "
              f"offset={first * SECTOR} size={size}")
    print(f"gpt-event.sha384 {gpt_event(path).hex()}")


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
    print(sha384(bytes(48) + bytes.fromhex(digest)).hex())


# --- the boot chain's events, as GCE's firmware, GRUB and systemd-stub measure them --------------

EV_NO_ACTION, EV_SEPARATOR, EV_EVENT_TAG, EV_IPL = 0x3, 0x4, 0x6, 0xD
EV_EFI_BOOT_SERVICES_APPLICATION, EV_EFI_GPT_EVENT, EV_EFI_ACTION = 0x80000003, 0x80000006, 0x80000007
EVENT_TYPES = {
    0x0: "EV_PREBOOT_CERT", 0x1: "EV_POST_CODE", 0x3: "EV_NO_ACTION", 0x4: "EV_SEPARATOR",
    0x5: "EV_ACTION", 0x6: "EV_EVENT_TAG", 0x7: "EV_S_CRTM_CONTENTS", 0x8: "EV_S_CRTM_VERSION",
    0x9: "EV_CPU_MICROCODE", 0xA: "EV_PLATFORM_CONFIG_FLAGS", 0xB: "EV_TABLE_OF_DEVICES",
    0xC: "EV_COMPACT_HASH", 0xD: "EV_IPL", 0xE: "EV_IPL_PARTITION_DATA",
    0xF: "EV_NONHOST_CODE", 0x10: "EV_NONHOST_CONFIG", 0x11: "EV_NONHOST_INFO",
    0x12: "EV_OMIT_BOOT_DEVICE_EVENTS",
    0x80000001: "EV_EFI_VARIABLE_DRIVER_CONFIG", 0x80000002: "EV_EFI_VARIABLE_BOOT",
    0x80000003: "EV_EFI_BOOT_SERVICES_APPLICATION", 0x80000004: "EV_EFI_BOOT_SERVICES_DRIVER",
    0x80000005: "EV_EFI_RUNTIME_SERVICES_DRIVER", 0x80000006: "EV_EFI_GPT_EVENT",
    0x80000007: "EV_EFI_ACTION", 0x80000008: "EV_EFI_PLATFORM_FIRMWARE_BLOB",
    0x80000009: "EV_EFI_HANDOFF_TABLES", 0x8000000A: "EV_EFI_PLATFORM_FIRMWARE_BLOB2",
    0x8000000B: "EV_EFI_HANDOFF_TABLES2", 0x8000000C: "EV_EFI_VARIABLE_BOOT2",
    0x800000E0: "EV_EFI_VARIABLE_AUTHORITY",
}
TYPE_CODES = {name: code for code, name in EVENT_TYPES.items()}
SHA384 = 0x000C

CALLING = b"Calling EFI Application from Boot Option"
EXIT_BOOT_SERVICES = b"Exit Boot Services Invocation"
EXIT_BOOT_SERVICES_OK = b"Exit Boot Services Returned with Success"
# The sections systemd-stub (257) measures, in its order (.pcrsig is never measured).
STUB_SECTIONS = (".linux", ".osrel", ".cmdline", ".initrd", ".ucode", ".splash", ".dtb", ".uname",
                 ".sbat", ".pcrpkey", ".profile", ".dtbauto", ".hwids")
GRUB_PREFIXES = (b"grub_cmd: ", b"kernel_cmdline: ", b"module_cmdline: ", b"grub_kernel_cmdline ",
                 b"grub_cmd ")
KERNEL_CMDLINE_PREFIXES = (b"grub_kernel_cmdline ", b"kernel_cmdline: ")


def chain(digests):
    value = bytes(48)
    for digest in digests:
        value = sha384(value + digest)
    return value


def predict_rtmr1(gpt_digest, applications):
    """RTMR1's events on GCE (C3, TDX): as its firmware measured the UKI booted alone on
    2026-11-10 (testdata/), with each application loaded in turn. applications: [(name, digest)]."""
    return ([(sha384(CALLING), "EV_EFI_ACTION", CALLING.decode()),
             (sha384(bytes(4)), "EV_SEPARATOR", "00000000"),
             (gpt_digest, "EV_EFI_GPT_EVENT", "the boot disk's GPT")]
            + [(digest, "EV_EFI_BOOT_SERVICES_APPLICATION", name) for name, digest in applications]
            + [(sha384(EXIT_BOOT_SERVICES), "EV_EFI_ACTION", EXIT_BOOT_SERVICES.decode()),
               (sha384(EXIT_BOOT_SERVICES_OK), "EV_EFI_ACTION", EXIT_BOOT_SERVICES_OK.decode())])


def grub_commands(cfg):
    """The commands of a literal grub.cfg (one per line, no variables, quotes or blocks), as GRUB
    measures them: its words joined by single spaces."""
    commands = []
    for line in cfg.decode().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if re.search(r"[$;{}\"'\\|&<>]", line):
            sys.exit(f"grub.cfg: not a literal command: {line}")
        commands.append(" ".join(line.split()))
    return commands


def grub_events(cfg, uki_digest):
    """GRUB's measurements in order: grub.cfg as a file (PCR 9) twice, since Debian's GRUB opens
    it once to find it (grub_try_normal_prefix) before normal mode reads it; then each command it
    runs as `grub_cmd: <text>` (PCR 8) up to `boot`; `chainloader` measures the file it reads
    (PCR 9), the UKI. (Files on a memdisk would not be measured.)"""
    events = [(sha384(cfg), "EV_IPL", "file <ESP>/EFI/BOOT/grub.cfg (found)"),
              (sha384(cfg), "EV_IPL", "file <ESP>/EFI/BOOT/grub.cfg (read)")]
    for command in grub_commands(cfg):
        events.append((sha384(command.encode()), "EV_IPL", f"grub_cmd: {command}"))
        words = command.split()
        if words[0] == "chainloader":
            if words[1:] != [UKI_ON_ESP]:
                sys.exit(f"grub.cfg: chainloader {' '.join(words[1:])}: expected {UKI_ON_ESP} alone")
            events.append((uki_digest, "EV_IPL", f"file {UKI_ON_ESP}"))
        if words[0] == "boot":
            break
    return events


def stub_events(sections):
    """systemd-stub's measurements: each section's name (with its NUL), then its content."""
    events = []
    for name, digest in sections:
        events += [(sha384(name.encode() + b"\0"), "EV_IPL", f"section name {name}"),
                   (digest, "EV_IPL", f"section {name}")]
    return events


def boot(disk, grub, grubcfg, uki_path):
    """GRUB's and the kernel's measurements, and RTMR1 and RTMR2 as predicted for GCE."""
    grub_data, cfg, uki_data = (open(p, "rb").read() for p in (grub, grubcfg, uki_path))
    sections = dict(pe_sections(uki_data))
    grub_digest = bytes.fromhex(authenticode_data(grub_data))
    uki_digest = bytes.fromhex(authenticode_data(uki_data))
    kernel_digest = bytes.fromhex(authenticode_data(sections[".linux"]))
    print(f"grub.sha384 {sha384(grub_data).hex()}")
    print(f"grub.authenticode-sha384 {grub_digest.hex()}")
    print(f"grub.cfg.sha384 {sha384(cfg).hex()}")
    for command in grub_commands(cfg):
        print(f"grub.cmd {command}")
    print(f"kernel.authenticode-sha384 {kernel_digest.hex()}")
    rtmr1 = predict_rtmr1(gpt_event(disk), [("GRUB", grub_digest), ("UKI", uki_digest),
                                            ("kernel", kernel_digest)])
    rtmr2 = grub_events(cfg, sha384(uki_data)) + stub_events(
        [(name, sha384(sections[name])) for name in STUB_SECTIONS if name in sections])
    for register, events in (("rtmr1", rtmr1), ("rtmr2", rtmr2)):
        for digest, kind, what in events:
            print(f"{register}.event {digest.hex()} {kind} {what}")
        print(f"gce.{register} {chain(d for d, _, _ in events).hex()}")


# --- event logs and their replay ------------------------------------------------------------

def parse_eventlog(data):
    """The events of a TCG crypto-agile log: (MR index or PCR, type, {algorithm: digest}, data)."""
    pcr, kind, _, size = struct.unpack_from("<II20sI", data, 0)
    header = data[32 : 32 + size]
    if kind != EV_NO_ACTION or not header.startswith(b"Spec ID Event03"):
        sys.exit("not a crypto-agile event log (no Spec ID Event03)")
    count = struct.unpack_from("<I", header, 24)[0]
    sizes = {}
    for index in range(count):
        algorithm, digest_size = struct.unpack_from("<HH", header, 28 + 4 * index)
        sizes[algorithm] = digest_size
    events = [(pcr, kind, {}, header)]
    offset = 32 + size
    while offset + 12 <= len(data):
        pcr, kind, count = struct.unpack_from("<III", data, offset)
        if (pcr, kind) in ((0xFFFFFFFF, 0xFFFFFFFF), (0, 0)) or count == 0 or count > len(sizes):
            break
        offset += 12
        digests = {}
        for _ in range(count):
            algorithm = struct.unpack_from("<H", data, offset)[0]
            if algorithm not in sizes:
                sys.exit(f"event at {offset}: unknown digest algorithm {algorithm:#x}")
            digests[algorithm] = data[offset + 2 : offset + 2 + sizes[algorithm]]
            offset += 2 + sizes[algorithm]
        size = struct.unpack_from("<I", data, offset)[0]
        events.append((pcr, kind, digests, data[offset + 4 : offset + 4 + size]))
        offset += 4 + size
    return events


# TDVF's mapping of TPM PCRs to the CCEL's MR index (1 = RTMR0 ... 3 = RTMR2).
TDX_MR_OF_PCR = {1: 1, 7: 1, 2: 2, 3: 2, 4: 2, 5: 2, 6: 2, **{pcr: 3 for pcr in range(8, 16)}}


def as_tdx(events):
    """A TPM log's events with the MR index TDVF would give them (others dropped)."""
    return [(TDX_MR_OF_PCR[pcr], kind, digests, data) for pcr, kind, digests, data in events
            if pcr in TDX_MR_OF_PCR]


def replay_events(events):
    """RTMR0..3: every event of MR index i + 1 extended into RTMR i (SHA-384), EV_NO_ACTION not."""
    rtmrs = [bytes(48)] * 4
    for pcr, kind, digests, _ in events:
        if kind == EV_NO_ACTION or not 1 <= pcr <= 4 or SHA384 not in digests:
            continue
        rtmrs[pcr - 1] = sha384(rtmrs[pcr - 1] + digests[SHA384])
    return rtmrs


def register_events(events, mr):
    return [(digests.get(SHA384, b""), kind, data) for pcr, kind, digests, data in events
            if pcr == mr and kind != EV_NO_ACTION]


def grub_rule(events):
    """Google's GRUB rule on MR index 3 (go-eventlog @1991f15bc4b0: extract/rtmr.go
    GrubStateFromRTMRLog, extract.go LinuxKernelStateFromGRUB)."""
    commands = []
    for number, (pcr, kind, digests, data) in enumerate(events):
        if pcr != 3 or kind in (EV_NO_ACTION, EV_EVENT_TAG):
            continue
        if kind != EV_IPL:
            return {"ok": False, "error": f"invalid event type {EVENT_TYPES.get(kind, hex(kind))} "
                                           f"for MR 3 (event #{number}), expected EV_IPL"}
        prefix = next((p for p in GRUB_PREFIXES if data.startswith(p)), None)
        if prefix is None:
            continue
        rest, digest = data[len(prefix):], digests.get(SHA384)
        if not (digest == sha384(rest) or (rest.endswith(b"\0") and digest == sha384(rest[:-1]))):
            return {"ok": False, "error": f"invalid GRUB event #{number}: digest is not the SHA-384 "
                                           f"of {rest[:80]!r}"}
        commands.append(data.rstrip(b"\0").decode("utf-8", "replace"))
    if not commands:
        return {"ok": False, "error": "no GRUB measurements found", "commands": []}
    kernel = [c for c in commands if c.encode().startswith(KERNEL_CMDLINE_PREFIXES)]
    if len(kernel) > 1:
        return {"ok": False, "error": "more than one kernel commandline in GRUB commands",
                "commands": commands}
    return {"ok": True, "commands": commands}


def token_claims(token):
    payload = token.strip().split(".")[1]
    return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))


def find_tdx(claims):
    """The claims object holding rtmr0..3 (`tdx`, wherever it is), and its path."""
    stack = [("", claims)]
    while stack:
        path, value = stack.pop()
        if isinstance(value, dict):
            if all(f"rtmr{i}" in value for i in range(4)):
                return path or ".", value
            stack.extend((f"{path}.{key}", child) for key, child in value.items())
    return None, None


def decode_register(value):
    """A register as a token carries it: hex, or base64 (standard or URL-safe)."""
    if isinstance(value, str):
        text = value.strip()
        if re.fullmatch(r"(0x)?[0-9a-fA-F]{96}", text):
            return bytes.fromhex(text.removeprefix("0x"))
        try:
            raw = base64.b64decode(text + "=" * (-len(text) % 4), altchars=b"-_" if "-" in text or "_" in text else None)
            if len(raw) == 48:
                return raw
        except ValueError:
            pass
    return None


def uki_cmdline(path):
    for name, raw in pe_sections(open(path, "rb").read()):
        if name == ".cmdline":
            return raw
    sys.exit(f"{path}: no .cmdline section")


def expected_measurements(path):
    """What the build measured (`qemu.sh build`'s `measurements`): single values by key, and the
    lists grub.cmd, rtmr1.event and rtmr2.event ((digest, type, what) for the events)."""
    expected = {"grub.cmd": [], "rtmr1.event": [], "rtmr2.event": []}
    for line in open(path):
        key, _, value = line.rstrip("\n").partition(" ")
        if key == "grub.cmd":
            expected[key].append(value)
        elif key in ("rtmr1.event", "rtmr2.event"):
            digest, kind, what = (value.split(" ", 2) + [""])[:3]
            expected[key].append((bytes.fromhex(digest), kind, what))
        elif key == "uki.section" and value.startswith(".cmdline "):
            expected["uki.cmdline-section-sha384"] = value.split()[2]
        elif key not in ("uki.section", "partition", "uki.osrel"):
            expected[key] = value
    missing = {"uki.authenticode-sha384", "uki.cmdline", "uki.cmdline-section-sha384"} - set(expected)
    if missing:
        sys.exit(f"{path}: no {', '.join(sorted(missing))}")
    return expected


def describe(data):
    text = data[:120].decode("utf-16-le" if data[1:2] == b"\0" else "latin-1", "replace")
    return "".join(c if c.isprintable() else "." for c in text)


def event_list(events):
    return [{"mr": pcr, "rtmr": pcr - 1 if 1 <= pcr <= 4 else None,
             "type": EVENT_TYPES.get(kind, hex(kind)), "sha384": digests.get(SHA384, b"").hex(),
             "size": len(data), "data": describe(data)} for pcr, kind, digests, data in events]


def boot_chain_checks(events, expected):
    """The checks on RTMR1 and RTMR2 shared by `replay` (CCEL) and `tpm-replay` (a TPM log as
    TDVF maps it): (results, ok)."""
    result, ok = {}, True
    rtmr1 = register_events(events, 2)
    rtmr2 = register_events(events, 3)
    applications = [d for d, kind, _ in rtmr1 if kind == EV_EFI_BOOT_SERVICES_APPLICATION]

    # RTMR1: the firmware's measurement of GRUB and the UKI (their Authenticode SHA-384).
    for name, key in (("grub", "grub.authenticode-sha384"), ("uki", "uki.authenticode-sha384")):
        if key in expected:
            result[f"{name}_in_rtmr1"] = bytes.fromhex(expected[key]) in applications
            ok &= result[f"{name}_in_rtmr1"]

    # RTMR2: Google's GRUB rule, GRUB's commands and the UKI file, as the build expects them.
    result["google_grub_rule"] = grub_rule(events)
    ok &= result["google_grub_rule"]["ok"]
    run = [what.removeprefix("grub_cmd: ") for _, _, what in expected["rtmr2.event"]
           if what.startswith("grub_cmd: ")]  # the commands up to `boot`
    if run:
        seen = {(d, data.rstrip(b"\0")) for d, kind, data in rtmr2 if kind == EV_IPL}
        missing = [c for c in run if (sha384(c.encode()), b"grub_cmd: " + c.encode()) not in seen]
        result["grub_commands_missing_in_rtmr2"] = missing
        ok &= not missing
        result["uki_file_in_rtmr2"] = bytes.fromhex(expected["uki.sha384"]) in [d for d, _, _ in rtmr2]
        ok &= result["uki_file_in_rtmr2"]

    # RTMR2: the command line, as systemd-stub measures the .cmdline section or the kernel its
    # load options (text or UTF-16, with or without a NUL).
    text = expected["uki.cmdline"]
    roothash = next((word for word in text.split() if word.startswith("roothash=")), None)
    candidates = {bytes.fromhex(expected["uki.cmdline-section-sha384"]): ".cmdline section"}
    for name, blob in (
        ("text", text.encode()), ("text+NUL", text.encode() + b"\0"),
        ("UTF-16", text.encode("utf-16-le")), ("UTF-16+NUL", (text + "\0").encode("utf-16-le")),
    ):
        candidates.setdefault(sha384(blob), name)
    found, named = [], []
    for digest, kind, data in rtmr2:
        if digest in candidates:
            found.append(f"{EVENT_TYPES.get(kind, hex(kind))}: {candidates[digest]}")
        elif roothash and (roothash.encode() in data or roothash.encode("utf-16-le") in data):
            named.append(EVENT_TYPES.get(kind, hex(kind)))
    result["roothash"] = roothash
    result["cmdline_in_rtmr2"] = found
    result["roothash_named_in_rtmr2_event_data"] = named
    ok &= bool(found)
    return result, ok


def compare_prediction(events, expected):
    """The registers' events against the build's prediction (informative)."""
    prediction = {}
    for register, mr in (("rtmr1", 2), ("rtmr2", 3)):
        want = [d for d, _, _ in expected[f"{register}.event"]]
        if not want:
            continue
        have = [d for d, _, _ in register_events(events, mr)]
        first = next((i for i, (a, b) in enumerate(zip(want, have)) if a != b), min(len(want), len(have)))
        prediction[register] = {
            "predicted": expected.get(f"gce.{register}"), "replayed": chain(have).hex(),
            "match": want == have, "events": len(have), "predicted_events": len(want),
            "first_difference": None if want == have else first,
        }
    return prediction


def replay(*argv):
    import argparse

    parser = argparse.ArgumentParser(prog="measure.py replay")
    parser.add_argument("--eventlog", required=True)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--claims", help="the token's decoded payload (JSON)")
    source.add_argument("--token", help="the token (JWT) itself")
    parser.add_argument("--expected", required=True, help="the build's measurements file")
    parser.add_argument("--config-digest", help="the configuration digest (RTMR3)")
    args = parser.parse_args(argv)

    events = parse_eventlog(open(args.eventlog, "rb").read())
    rtmrs = replay_events(events)
    claims = (json.load(open(args.claims)) if args.claims
              else token_claims(open(args.token).read()))
    expected = expected_measurements(args.expected)
    path, tdx = find_tdx(claims)
    result = {"claims_path": path, "claims_tdx": tdx, "registers": {}}
    ok = tdx is not None

    config = None
    if args.config_digest:
        config = sha384(bytes(48) + bytes.fromhex(args.config_digest))
    for index in range(4):
        carried = tdx.get(f"rtmr{index}") if tdx else None
        decoded = decode_register(carried)
        entry = {"token": carried, "replayed": rtmrs[index].hex()}
        if index == 3:
            # User space extends RTMR3 (`config`); the CCEL log does not record it.
            entry["expected_from_config_digest"] = config.hex() if config else None
            entry["match"] = decoded == config if config else None
            ok &= entry["match"] is not False
        else:
            entry["match"] = decoded == rtmrs[index]
            ok &= entry["match"]
        result["registers"][f"rtmr{index}"] = entry

    checks, chain_ok = boot_chain_checks(events, expected)
    result.update(checks)
    ok &= chain_ok
    result["prediction"] = compare_prediction(events, expected)
    result["events"] = event_list(events)
    result["ok"] = ok
    print(json.dumps(result, indent=2))
    sys.exit(0 if ok else 1)


def grub_rule_command(*argv):
    import argparse

    parser = argparse.ArgumentParser(prog="measure.py grub-rule")
    parser.add_argument("eventlog")
    parser.add_argument("--tpm", action="store_true", help="a TPM log: PCRs 8 to 15 as RTMR2")
    args = parser.parse_args(argv)
    events = parse_eventlog(open(args.eventlog, "rb").read())
    result = grub_rule(as_tdx(events) if args.tpm else events)
    print(json.dumps(result, indent=2))
    sys.exit(0 if result["ok"] else 1)


def tpm_replay(*argv):
    import argparse

    parser = argparse.ArgumentParser(prog="measure.py tpm-replay")
    parser.add_argument("--eventlog", required=True, help="the TPM's event log (SHA-384 bank)")
    parser.add_argument("--expected", required=True, help="the build's measurements file")
    args = parser.parse_args(argv)
    raw = parse_eventlog(open(args.eventlog, "rb").read())
    events = as_tdx(raw)
    expected = expected_measurements(args.expected)
    result = {}
    ok = any(SHA384 in digests for _, _, digests, _ in raw)
    result["sha384_bank"] = ok
    checks, chain_ok = boot_chain_checks(events, expected)
    result.update(checks)
    ok &= chain_ok
    # RTMR2's events as TDVF would extend them: exactly the predicted ones, in order. Linux's
    # EFI stub measures its load options and initrd (EV_EVENT_TAG, PCR 9) into the TPM when there
    # is one, into the CC registers only when there is none: on GCE they are in the vTPM alone
    # (testdata/), so they are left out here.
    tagged = [(d, data) for d, kind, data in register_events(events, 3) if kind == EV_EVENT_TAG]
    result["tpm_only_tagged_events"] = [describe(data) for _, data in tagged]
    rtmr2 = [d for d, kind, _ in register_events(events, 3) if kind != EV_EVENT_TAG]
    want = [d for d, _, _ in expected["rtmr2.event"]]
    result["rtmr2_events_as_predicted"] = rtmr2 == want
    result["rtmr2_as_tdx"] = chain(rtmr2).hex()
    result["rtmr2_predicted"] = expected.get("gce.rtmr2")
    ok &= rtmr2 == want
    # PCR 4: GRUB, the UKI and the kernel, in this order (OVMF's other PCR 4 and 5 events differ
    # from GCE's, so RTMR1 as a whole is not compared).
    applications = [digests.get(SHA384) for pcr, kind, digests, _ in raw
                    if pcr == 4 and kind == EV_EFI_BOOT_SERVICES_APPLICATION]
    order = [bytes.fromhex(expected[k]) for k in ("grub.authenticode-sha384", "uki.authenticode-sha384",
                                                  "kernel.authenticode-sha384") if k in expected]
    result["pcr4_applications"] = [d.hex() if d else None for d in applications]
    result["pcr4_grub_uki_kernel_in_order"] = applications[: len(order)] == order
    ok &= result["pcr4_grub_uki_kernel_in_order"]
    result["events"] = [{"pcr": pcr, "type": EVENT_TYPES.get(kind, hex(kind)),
                         "sha384": digests.get(SHA384, b"").hex(), "size": len(data),
                         "data": describe(data)}
                        for pcr, kind, digests, data in raw if pcr in (4, 5) or 8 <= pcr <= 15]
    result["ok"] = ok
    print(json.dumps(result, indent=2))
    sys.exit(0 if ok else 1)


def console(serial, out, measurements=None):
    """The measure mode's lines in a serial log (the last of each), written to OUT and checked."""
    os.makedirs(out, exist_ok=True)
    found, sums, token, error, digest = {}, {}, None, None, None
    text = open(serial, "rb").read().decode("utf-8", "replace").replace("\r", "")
    for line in text.split("\n"):
        if m := re.search(r"(EMS-MEASURE-(?:CCEL|EVENTLOG|TPMLOG)) ([A-Za-z0-9+/=]+)\s*$", line):
            found[m.group(1)] = m.group(2)
        elif m := re.search(r"(EMS-MEASURE-(?:CCEL|EVENTLOG|TPMLOG))-SHA256 ([0-9a-f]{64}) (\d+)", line):
            sums[m.group(1)] = (m.group(2), int(m.group(3)))
        elif m := re.search(r"EMS-MEASURE-TOKEN ([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)", line):
            token, error = m.group(1), None
        elif m := re.search(r"EMS-MEASURE-TOKEN-ERROR (.*)", line):
            token, error = None, m.group(1).strip()
        elif m := re.search(r"configuration digest \(sha384 of the manifest above\) ([0-9a-f]{96})", line):
            digest = m.group(1)
    complete = True
    for tag, name, required in (("EMS-MEASURE-CCEL", "ccel.bin", True),
                                ("EMS-MEASURE-EVENTLOG", "eventlog.bin", True),
                                ("EMS-MEASURE-TPMLOG", "tpmlog.bin", False)):
        if tag not in found:
            print(f"{tag}: none", file=sys.stderr)
            complete &= not required
            continue
        data = base64.b64decode(found[tag])
        if sums.get(tag) != (hashlib.sha256(data).hexdigest(), len(data)):
            print(f"{tag}: SHA-256 or size differs from the console's {sums.get(tag)}", file=sys.stderr)
            complete &= not required
            continue
        open(os.path.join(out, name), "wb").write(data)
        print(f"{tag}: {len(data)} bytes, SHA-256 checked -> {name}", file=sys.stderr)
    if token:
        open(os.path.join(out, "token.jwt"), "w").write(token + "\n")
        json.dump(token_claims(token), open(os.path.join(out, "claims.json"), "w"), indent=2)
        print("token -> token.jwt, claims.json", file=sys.stderr)
    else:
        print(f"no token: {error or 'no EMS-MEASURE-TOKEN line'}", file=sys.stderr)
        complete = False
    if digest:
        open(os.path.join(out, "config-digest"), "w").write(digest + "\n")
        print(f"configuration digest {digest}", file=sys.stderr)
    if not complete:
        sys.exit(1)
    if measurements:
        replay("--eventlog", os.path.join(out, "eventlog.bin"),
               "--claims", os.path.join(out, "claims.json"), "--expected", measurements,
               *(["--config-digest", digest] if digest else []))


def selftest(measurements, fixture=None):
    """The replay on synthetic CCEL logs built from the build's predicted RTMR1 and RTMR2 events
    (claims carrying each log's own registers, so that each tampering meets its own check), then
    Google's rule and the prediction model on a real GCE log. Standard library only."""
    import subprocess
    import tempfile

    expected = expected_measurements(measurements)
    if not expected["rtmr1.event"] or not expected["rtmr2.event"]:
        sys.exit(f"{measurements}: no predicted rtmr1/rtmr2 events (measure.py boot)")
    digest = hashlib.sha384(b"configuration").hexdigest()

    def event(pcr, kind, data, value=None):
        value = value if value is not None else sha384(data)
        return (struct.pack("<III", pcr, kind, 1) + struct.pack("<H", SHA384) + value
                + struct.pack("<I", len(data)) + data)

    def predicted(mr, events):
        out = []
        for value, kind, what in events:
            data = (what + "\0").encode() if what.startswith("grub_cmd: ") else what.encode()
            out.append((mr, TYPE_CODES[kind], data, value))
        return out

    spec = (b"Spec ID Event03\0" + struct.pack("<IBBBBI", 0, 0, 2, 0, 2, 1)
            + struct.pack("<HH", SHA384, 48) + b"\0")
    header = struct.pack("<II20sI", 0, EV_NO_ACTION, bytes(20), len(spec)) + spec
    firmware = [(1, 0x80000008, b"firmware volume", None), (1, EV_SEPARATOR, bytes(4), None)]
    good = firmware + predicted(2, expected["rtmr1.event"]) + predicted(3, expected["rtmr2.event"])
    uki_digest = bytes.fromhex(expected["uki.authenticode-sha384"])
    grub_cmd = next(i for i, e in enumerate(good) if e[0] == 3 and e[2].startswith(b"grub_cmd: "))
    cmdline = bytes.fromhex(expected["uki.cmdline-section-sha384"])
    cases = [
        ("good", good, 0),
        ("another UKI in RTMR1", [e[:3] + (bytes(48) if e[3] == uki_digest else e[3],) for e in good], 1),
        ("no GRUB commands in RTMR2", [e for e in good if not e[2].startswith(b"grub_cmd: ")], 1),
        ("a non-EV_IPL event in RTMR2", good + [(3, EV_EFI_ACTION, b"action", None)], 1),
        ("a GRUB command whose digest is not its text's",
         good[:grub_cmd] + [good[grub_cmd][:2] + (b"grub_cmd: something else\0", good[grub_cmd][3])]
         + good[grub_cmd + 1:], 1),
        ("two kernel command lines", good + [(3, EV_IPL, b"kernel_cmdline: a\0", sha384(b"a")),
                                             (3, EV_IPL, b"kernel_cmdline: b\0", sha384(b"b"))], 1),
        ("no command line in RTMR2", [e for e in good if e[3] != cmdline], 1),
        ("EV_EVENT_TAG in RTMR2 (Linux's, allowed)", good + [(3, EV_EVENT_TAG, b"tag", None)], 0),
    ]
    failed = 0
    with tempfile.TemporaryDirectory() as tmp:
        for number, (name, events, want) in enumerate(cases):
            log = header + b"".join(event(*e) for e in events) + b"\xff" * 64
            rtmrs = replay_events(parse_eventlog(log))
            rtmrs[3] = sha384(bytes(48) + bytes.fromhex(digest))
            open(f"{tmp}/{number}.log", "wb").write(log)
            json.dump({"hwmodel": "GCP_INTEL_TDX", "tdx": {f"rtmr{i}": rtmrs[i].hex() for i in range(4)}},
                      open(f"{tmp}/{number}.json", "w"))
            result = subprocess.run(
                [sys.executable, "-I", "-S", __file__, "replay", "--eventlog", f"{tmp}/{number}.log",
                 "--claims", f"{tmp}/{number}.json", "--expected", measurements,
                 "--config-digest", digest],
                capture_output=True, text=True, env={"PYTHONPATH": ""})
            print(f"selftest {name}: exit {result.returncode} (want {want})")
            if result.returncode != want:
                print(result.stdout[-3000:] + result.stderr)
                failed += 1
            if name == "good":
                prediction = json.loads(result.stdout)["prediction"]
                if not all(p["match"] for p in prediction.values()):
                    print(f"selftest good: prediction does not match its own events: {prediction}")
                    failed += 1

    # A real log: GCE (C3, TDX) booting the UKI alone, which Google refused for want of GRUB.
    here = os.path.dirname(os.path.abspath(__file__))
    fixtures = [fixture] if fixture else sorted(
        os.path.join(here, "testdata", f) for f in os.listdir(os.path.join(here, "testdata"))
        if f.endswith(".json")) if os.path.isdir(os.path.join(here, "testdata")) else []
    for path in fixtures:
        meta = json.load(open(path))
        events = parse_eventlog(open(os.path.join(os.path.dirname(path), meta["eventlog"]), "rb").read())
        rule = grub_rule(events)
        verdict = meta["google_verdict"]
        same = rule.get("error") == verdict if verdict else rule["ok"]
        print(f"selftest {os.path.basename(path)}: Google's GRUB rule says {rule.get('error') or 'ok'}"
              f" (Google said {verdict or 'ok'})")
        failed += not same
        r1 = predict_rtmr1(bytes.fromhex(meta["gpt_event"]),
                           [(n, bytes.fromhex(d)) for n, d in meta["applications"]])
        r2 = stub_events([(n, bytes.fromhex(d)) for n, d in meta["stub_sections"]])
        for register, mr, events_predicted in (("rtmr1", 2, r1), ("rtmr2", 3, r2)):
            match = [d for d, _, _ in events_predicted] == [d for d, _, _ in register_events(events, mr)]
            print(f"selftest {os.path.basename(path)}: predicted {register} events "
                  f"{'match' if match else 'DIFFER from'} the log")
            failed += not match
    if failed:
        sys.exit(f"selftest: {failed} failed")
    print("selftest: the replay accepts the predicted boot and refuses each tampering; the model "
          "and Google's GRUB rule agree with the real GCE logs")


if __name__ == "__main__":
    command, *rest = sys.argv[1:] or ["help"]
    {"uki": uki, "gpt": gpt, "boot": boot, "extract": extract, "rtmr3": rtmr3, "console": console,
     "replay": replay, "grub-rule": grub_rule_command, "tpm-replay": tpm_replay,
     "selftest": selftest}.get(
        command, lambda *_: sys.exit(__doc__)
    )(*rest)
