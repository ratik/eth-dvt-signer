#!/usr/bin/env python3
"""Development failover proxy in front of the MPC coordinators (integration only).

Lighthouse takes one URL per remote signer, so this proxy gives it one address for the four nodes.
It forwards each request unchanged (method, path, body, `Content-Type` and `Accept`) to the first
available node in preference order, and returns that node's answer unchanged.

Retries go to the next node only when the attempt did not give a final answer: a connection
failure or reset (the coordinator may have died, possibly after consensus authorized the duty),
or 502, 503 or 504. Retrying is safe because the replicated state machine decides each duty once:
an identical retry is `AlreadyAccepted` and returns the same signature, and a conflicting duty is
refused whoever asks. 4xx answers (400, 404, 412) and 200 are never retried. Nothing about the
duty is read or changed, except to log its type and slot.

Each request is logged as one JSON line (the client's `User-Agent`, attempts, nodes, statuses,
latencies); with
`--requests DIR`, each signing request body is kept for the security checks (duty data only,
nothing secret).

An `https://` backend is a sealed node's mTLS API (docs/tee.md): the proxy presents the
operator's client certificate (`--tls-cert`, `--tls-key`) and pins that node's attested CA
(`--ca URL=FILE`), over TLS 1.3, and keeps its connections open between requests, as a validator
client's HTTP pool does. With one such backend, the proxy is a loopback bridge to that node.

Usage: proxy.py --listen 127.0.0.1:47200 --backend http://127.0.0.1:47100 ... --log FILE
       proxy.py --listen 127.0.0.1:47100 --backend https://IP:8443 --ca https://IP:8443=CA.pem
                --tls-cert client.pem --tls-key client-key.pem --log FILE
"""

import argparse
import http.client
import http.server
import json
import os
import socket
import ssl
import threading
import time
import urllib.parse

ATTEMPT_TIMEOUT = 6.0
DOWN_FOR = 2.0
RETRIED_STATUSES = {502, 503, 504}


class Backends:
    def __init__(self, urls, tls=None):
        self.urls = urls
        self.down_until = {url: 0.0 for url in urls}
        self.lock = threading.Lock()
        # url -> SSL context (https backends); url -> idle connections.
        self.tls = tls or {}
        self.idle = {url: [] for url in urls}

    def connection(self, url, fresh=False):
        """A connection to `url` and whether it is reused: an idle one of an https backend
        (unless `fresh`), or a new one (http backends: a new one each time)."""
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme != "https":
            return http.client.HTTPConnection(parsed.hostname, parsed.port,
                                              timeout=ATTEMPT_TIMEOUT), False
        with self.lock:
            if self.idle[url] and not fresh:
                return self.idle[url].pop(), True
        return http.client.HTTPSConnection(parsed.hostname, parsed.port, timeout=ATTEMPT_TIMEOUT,
                                           context=self.tls[url]), False

    def release(self, url, connection, reusable):
        if reusable and urllib.parse.urlsplit(url).scheme == "https":
            with self.lock:
                self.idle[url].append(connection)
        else:
            connection.close()

    def order(self):
        """Nodes that answered recently first, in preference order, then the others."""
        now = time.monotonic()
        with self.lock:
            up = [url for url in self.urls if self.down_until[url] <= now]
            down = [url for url in self.urls if self.down_until[url] > now]
        return up + down

    def mark(self, url, ok):
        with self.lock:
            self.down_until[url] = 0.0 if ok else time.monotonic() + DOWN_FOR


# Where each request type keeps its slot (or epoch).
SLOT_PATHS = {
    "BLOCK_V2": ("beacon_block", "block_header", "slot"),
    "ATTESTATION": ("attestation", "slot"),
    "AGGREGATION_SLOT": ("aggregation_slot", "slot"),
    "AGGREGATE_AND_PROOF": ("aggregate_and_proof", "aggregate", "data", "slot"),
    "AGGREGATE_AND_PROOF_V2": ("aggregate_and_proof", "data", "aggregate", "data", "slot"),
    "SYNC_COMMITTEE_MESSAGE": ("sync_committee_message", "slot"),
    "SYNC_COMMITTEE_SELECTION_PROOF": ("sync_aggregator_selection_data", "slot"),
    "SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF": ("contribution_and_proof", "contribution", "slot"),
    # Gloas (remote-signing-api v1.4.0): `{"version": "GLOAS", "data": ...}`.
    "PAYLOAD_ATTESTATION_MESSAGE": ("payload_attestation_message", "data", "slot"),
    "EXECUTION_PAYLOAD_ENVELOPE": ("execution_payload_envelope", "data", "payload", "slot_number"),
    "PROPOSER_PREFERENCES": ("proposer_preferences", "data", "proposal_slot"),
}
EPOCH_PATHS = {
    "RANDAO_REVEAL": ("randao_reveal", "epoch"),
    "VOLUNTARY_EXIT": ("voluntary_exit", "epoch"),
}


def dig(value, path):
    for key in path:
        if not isinstance(value, dict):
            return None
        value = value.get(key)
    return int(value) if isinstance(value, (str, int)) and str(value).isdigit() else None


def describe(path, body):
    """Duty type, slot or epoch, validator and client root of a Web3Signer signing request."""
    if not path.startswith("/api/v1/eth2/sign/") or not body:
        return {}
    try:
        request = json.loads(body)
    except ValueError:
        return {}
    kind = request.get("type")
    return {
        "type": kind,
        "slot": dig(request, SLOT_PATHS[kind]) if kind in SLOT_PATHS else None,
        "epoch": dig(request, EPOCH_PATHS[kind]) if kind in EPOCH_PATHS else None,
        "validator": path.rsplit("/", 1)[-1],
        "signing_root": request.get("signingRoot"),
        "fork_version": ((request.get("fork_info") or {}).get("fork") or {}).get("current_version"),
    }


def make_handler(backends, log_path, requests_dir):
    log_lock = threading.Lock()
    counter = {"next": 0}

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):
            pass

        def do_GET(self):
            self.forward()

        def do_POST(self):
            self.forward()

        def forward(self):
            started = time.time()
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length else b""
            headers = {name: self.headers[name] for name in ("Content-Type", "Accept")
                       if self.headers.get(name)}
            with log_lock:
                counter["next"] += 1
                request_id = counter["next"]
            attempts = []
            answer = None
            for url in backends.order():
                attempt_started = time.monotonic()
                try:
                    # A kept connection the node closed meanwhile fails at once: one new one then
                    # (not after a timeout).
                    for fresh in (False, True):
                        connection, reused = backends.connection(url, fresh)
                        try:
                            connection.request(self.command, self.path, body=body, headers=headers)
                            response = connection.getresponse()
                            data = response.read()
                            break
                        except (OSError, http.client.HTTPException) as error:
                            connection.close()
                            if not reused or isinstance(error, socket.timeout):
                                raise
                    content_type = response.getheader("Content-Type", "")
                    backends.release(url, connection, not response.will_close)
                except (OSError, http.client.HTTPException, socket.timeout) as error:
                    backends.mark(url, False)
                    attempts.append({"backend": url, "error": type(error).__name__,
                                     "ms": round((time.monotonic() - attempt_started) * 1000, 2)})
                    continue
                backends.mark(url, True)
                attempts.append({"backend": url, "status": response.status,
                                 "ms": round((time.monotonic() - attempt_started) * 1000, 2)})
                answer = (response.status, content_type, data)
                if response.status not in RETRIED_STATUSES:
                    break
            if answer is None:
                answer = (503, "application/json",
                          json.dumps({"error": "no MPC coordinator reachable"}).encode())
            status, content_type, data = answer
            self.send_response(status)
            if content_type:
                self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

            record = {"id": request_id, "ts": round(started, 3), "method": self.command,
                      "path": self.path, "client": self.headers.get("User-Agent"), "status": status,
                      "ms": round((time.time() - started) * 1000, 2),
                      "attempts": attempts, **describe(self.path, body)}
            if requests_dir and self.path.startswith("/api/v1/eth2/sign/"):
                name = os.path.join(requests_dir, f"{request_id:07d}.json")
                with open(name, "w") as file:
                    json.dump({"path": self.path, "status": status,
                               "body": body.decode("utf-8", "replace"),
                               "response": data.decode("utf-8", "replace")}, file)
            with log_lock, open(log_path, "a") as file:
                file.write(json.dumps(record) + "\n")

    return Handler


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--listen", default="127.0.0.1:47200")
    parser.add_argument("--backend", action="append", required=True)
    parser.add_argument("--log", required=True)
    parser.add_argument("--requests")
    parser.add_argument("--tls-cert", help="the operator's client certificate (https backends)")
    parser.add_argument("--tls-key", help="its private key")
    parser.add_argument("--ca", action="append", default=[],
                        help="URL=FILE: the CA an https backend's certificate must chain to")
    args = parser.parse_args()
    host, port = args.listen.rsplit(":", 1)
    if host not in ("127.0.0.1", "localhost", "::1"):
        raise SystemExit("the development proxy listens on loopback only")
    if args.requests:
        os.makedirs(args.requests, exist_ok=True)
    cas = dict(entry.split("=", 1) for entry in args.ca)
    tls = {}
    for url in args.backend:
        if urllib.parse.urlsplit(url).scheme != "https":
            continue
        if url not in cas or not args.tls_cert or not args.tls_key:
            raise SystemExit(f"{url}: an https backend needs --ca {url}=FILE, --tls-cert and --tls-key")
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.load_verify_locations(cafile=cas[url])
        context.load_cert_chain(args.tls_cert, args.tls_key)
        tls[url] = context
    server = http.server.ThreadingHTTPServer(
        (host, int(port)), make_handler(Backends(args.backend, tls), args.log, args.requests))
    server.daemon_threads = True
    server.serve_forever()


if __name__ == "__main__":
    main()
