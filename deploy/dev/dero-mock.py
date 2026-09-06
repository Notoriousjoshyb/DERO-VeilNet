#!/usr/bin/env python3
"""VEILNET devnet dero-mock: worthless-token fake chain/wallet.

Endpoints (all JSON):
  GET  /height                 {"height": N, "network": "devnet"}
  GET  /balance?account=X      {"account": X, "balance_dev": N}
  POST /approve                {"account","node","amount_dev"} -> {"approval_id": "DEV-..."}
  POST /settle                 {"approval_id"} -> {"receipt": "DEV-RCPT-..."}
  GET  /health                 {"ok": true, "network": "devnet"}

Every id carries a DEV- prefix so mock value can never be mistaken for real
DERO. Balances are infinite test credits. Refuses to run unless
VEILNET_NETWORK=devnet.
"""
import itertools
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

if os.environ.get("VEILNET_NETWORK") != "devnet":
    sys.exit("refusing to run outside VEILNET_NETWORK=devnet")

PORT = int(os.environ.get("DERO_MOCK_PORT", "18091"))
counter = itertools.count(1)
settled = {}


class Handler(BaseHTTPRequestHandler):
    server_version = "VeilnetDeroMock/0.1"

    def _send(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self):
        length = int(self.headers.get("Content-Length", "0") or "0")
        raw = self.rfile.read(length) if length else b"{}"
        try:
            return json.loads(raw.decode() or "{}")
        except Exception:
            return {}

    def do_GET(self):
        if self.path.startswith("/balance"):
            self._send(200, {"balance_dev": 10 ** 15, "network": "devnet"})
        elif self.path == "/height":
            self._send(200, {"height": next(counter), "network": "devnet"})
        elif self.path == "/health":
            self._send(200, {"ok": True, "network": "devnet"})
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        if self.path == "/approve":
            body = self._body()
            aid = "DEV-APPROVAL-%d" % next(counter)
            settled[aid] = body
            self._send(200, {"approval_id": aid, "network": "devnet"})
        elif self.path == "/settle":
            body = self._body()
            aid = body.get("approval_id", "")
            if aid not in settled:
                self._send(400, {"error": "unknown approval"})
                return
            self._send(200, {"receipt": "DEV-RCPT-%d" % next(counter), "network": "devnet"})
        else:
            self._send(404, {"error": "not found"})

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
