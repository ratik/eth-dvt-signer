#!/usr/bin/env python3
"""Probes of the QEMU harness (integration/tee/qemu.sh).

  vm.py console SOCKET SECONDS   type a command on the serial console; exit 0 if a shell ran it
  vm.py ssh-banner PORT SECONDS  exit 0 if an SSH server answers on 127.0.0.1:PORT
  vm.py monitor SOCKET COMMAND   send a command to the QEMU human monitor

The console probe prints everything the console sent back. The command is `echo console-$((40+2))`:
a terminal only echoes the typed text, so `console-42` shows up only when a shell evaluated it.
"""

import socket
import sys
import time

MARK = b"console-42"


def console(path, seconds):
    seconds = float(seconds)
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(path)
    sock.settimeout(0.5)
    received = b""
    deadline = time.monotonic() + seconds
    next_send = time.monotonic()
    while time.monotonic() < deadline:
        if time.monotonic() >= next_send:
            sock.sendall(b"\r\n")
            time.sleep(0.3)
            sock.sendall(b"echo console-$((40+2))\r\n")
            next_send = time.monotonic() + 3
        try:
            chunk = sock.recv(65536)
            if not chunk:
                break
            received += chunk
        except socket.timeout:
            pass
        if MARK in received:
            break
    sock.close()
    sys.stdout.write(received.decode(errors="replace"))
    sys.exit(0 if MARK in received else 1)


def ssh_banner(port, seconds):
    deadline = time.monotonic() + float(seconds)
    received = b""
    try:
        sock = socket.create_connection(("127.0.0.1", int(port)), timeout=float(seconds))
        while time.monotonic() < deadline and b"\n" not in received:
            sock.settimeout(max(0.1, deadline - time.monotonic()))
            chunk = sock.recv(256)
            if not chunk:
                break
            received += chunk
        sock.close()
    except OSError as err:
        print(f"no connection: {err}")
    print(received.decode(errors="replace").strip() or "no banner")
    sys.exit(0 if received.startswith(b"SSH-") else 1)


def monitor(path, command):
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(path)
    sock.settimeout(2)
    try:
        sock.recv(65536)
    except socket.timeout:
        pass
    sock.sendall(command.encode() + b"\n")
    time.sleep(0.5)
    sock.close()


if __name__ == "__main__":
    command, *rest = sys.argv[1:] or ["help"]
    {"console": console, "ssh-banner": ssh_banner, "monitor": monitor}.get(
        command, lambda *_: sys.exit(__doc__)
    )(*rest)
