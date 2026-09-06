#!/usr/bin/env python3
"""VEILNET devnet test-server: observation point for integration tests.

Endpoints (all JSON):
  GET  /whoami            {"ip": "<client source IP>"} — exit-IP observation
  GET  /dns?name=X        {"name": X, "answer": "NX.<sha>", "via": "tunnel-stub"}
                          authoritative stub for veilnet.test (proves DNS path)
  GET  /health            {"ok": true, "network": "devnet"}

Refuses to run unless VEILNET_NETWORK=devnet (never mainnet-adjacent).
Stdlib only.
"""
import hashlib
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

if os.environ.get("VEILNET_NETWORK") != "devnet":
    sys.exit("refusing to run outside VEILNET_NETWORK=devnet")

PORT = int(os.environ.get("TEST_SERVER_PORT", "18080"))


class Handler(BaseHTTPRequestHandler):
    server_version = "VeilnetTestServer/0.1"

    def _send(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/whoami":
            self._send(200, {"ip": self.client_address[0]})
        elif u.path == "/dns":
            q = parse_qs(u.query)
            name = (q.get("name") or [""])[0]
            if not name.endswith(".veilnet.test"):
                self._send(400, {"error": "stub authoritative for veilnet.test only"})
                return
            digest = hashlib.sha256(name.encode()).hexdigest()[:12]
            self._send(200, {"name": name, "answer": "NX." + digest, "via": "tunnel-stub"})
        elif u.path == "/health":
            self._send(200, {"ok": True, "network": "devnet"})
        else:
            self._send(404, {"error": "not found"})

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
