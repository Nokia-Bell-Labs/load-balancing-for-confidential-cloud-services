# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

"""Oak baseline -- attested-session client.

Per-phase measurement client for ``oak.server``, in the style of
``baselines/httpa/httpa/client.py``:

    tcp_ms     TCP connect
    tls_ms     outer TLS 1.3 handshake (plain, untrusted; nothing verified)
    attest_ms  ATTEST round trip + client-side evidence verification:
               JWT signature with the cached AS key, validity, measurement
               policy, TPM-quote binding of the server's session key
               (the same checks the Janus frontend runs on a backend bundle)
    noise_ms   Noise NN handshake round trip + verification of the server's
               signature over the handshake hash with the bound key
    http_ms    request over the session -> first decrypted response byte

Only the inner session is trusted; the client never inspects the outer TLS
certificate.  Env: OAK_MOCK_VERIFY=1 for servers running OAK_MOCK_ATTEST=1.
Usage: python3 -m oak.client --host H --port 8543 --path /
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import socket
import ssl
import struct
import sys
import time
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from noise.connection import NoiseConnection

_HERE = Path(__file__).resolve()
for p in (str(_HERE.parents[3]), str(_HERE.parents[1])):
    if p not in sys.path:
        sys.path.insert(0, p)

from oak import wire  # noqa: E402

MOCK_VERIFY = os.environ.get("OAK_MOCK_VERIFY") == "1"


class _NoJwksCache:
    def get(self, issuer, kid):
        return None

    def put(self, issuer, kid, entry):
        pass


class OakClient:
    def __init__(self, *, host: str, port: int, maa_issuer: str,
                 timeout_s: float = 30.0, expected_measurement: Optional[str] = None):
        self.host, self.port = host, port
        self.maa_issuer = maa_issuer
        self.timeout_s = timeout_s
        self.expected_measurement = expected_measurement
        ctx = ssl.create_default_context()
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE      # outer TLS is untrusted transport
        self.ctx = ctx

    def request(self, method: str, path: str, body: bytes = b"",
                headers: Optional[dict] = None, timing: Optional[dict] = None,
                jwks_cache=None, on_chunk=None) -> tuple[int, bytes]:
        """``on_chunk`` (optional) receives each decrypted response chunk."""
        t = timing if timing is not None else {}
        jwks_cache = jwks_cache or _NoJwksCache()
        with _phase(t, "tcp_ms"):
            s = socket.create_connection((self.host, self.port), timeout=self.timeout_s)
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        with _phase(t, "tls_ms"):
            ss = self.ctx.wrap_socket(s, server_hostname=self.host)
        try:
            # 1. ATTESTATION
            with _phase(t, "attest_ms"):
                nonce = os.urandom(wire.NONCE_LEN)     # forces a fresh quote, bound to this session
                with _phase(t, "attest_rtt_ms"):
                    wire.send_frame(ss, b"ATTEST" + nonce)
                    msg = json.loads(wire.recv_frame(ss))
                with _phase(t, "attest_verify_ms"):
                    pub_der = base64.b64decode(msg["binding_pub_der_b64"])
                    bundle = base64.b64decode(msg["bundle_b64"])
                    if MOCK_VERIFY:
                        wire.mock_verify_evidence(bundle, pub_der, nonce)
                    else:
                        info = wire.verify_evidence(
                            bundle, msg["jwt"], pub_der, nonce, jwks_cache=jwks_cache,
                            maa_issuer=self.maa_issuer, timeout_s=self.timeout_s,
                            expected_measurement=self.expected_measurement)
                        t["_jwks_cold"] = info["jwks_cold"]
                    binding_pub = serialization.load_der_public_key(pub_der)
                for k, v in msg.get("server_ms", {}).items():
                    t[f"server_{k}"] = float(v)
            # 2. HANDSHAKE
            with _phase(t, "noise_ms"):
                noise = NoiseConnection.from_name(wire.NOISE_PROTOCOL)
                noise.set_as_initiator()
                noise.start_handshake()
                wire.send_frame(ss, noise.write_message())
                resp = wire.recv_frame(ss)
                (n,) = struct.unpack(">H", resp[:2])
                m2, sig = resp[2:2 + n], resp[2 + n:]
                noise.read_message(m2)
                assert noise.handshake_finished
                binding_pub.verify(sig, noise.get_handshake_hash(), ec.ECDSA(hashes.SHA256()))
            # 3. OPEN: HTTP over the session
            hdrs = dict(headers or {})
            hdrs.setdefault("host", self.host)
            hdrs.setdefault("connection", "close")
            if body:
                hdrs.setdefault("content-length", str(len(body)))
            req = (f"{method} {path} HTTP/1.1\r\n" +
                   "".join(f"{k}: {v}\r\n" for k, v in hdrs.items()) + "\r\n").encode() + body
            t0 = time.perf_counter()
            wire.send_frame(ss, noise.encrypt(req))
            # No half-close after the request: Go's net/http treats a client
            # EOF as "client gone" and cancels the handler's context (the
            # hotel frontend answered 500 "context canceled").  The app closes
            # the connection itself after the response (Connection: close).
            out = bytearray()
            first = None
            while True:
                ct = wire.recv_frame(ss)
                if not ct:
                    break
                pt = noise.decrypt(ct)
                if first is None:
                    first = time.perf_counter()
                out += pt
                if on_chunk:
                    on_chunk(pt)
            t["http_ms"] = ((first or time.perf_counter()) - t0) * 1000
        finally:
            ss.close()
        status = 0
        if out.startswith(b"HTTP/"):
            try:
                status = int(out.split(b" ", 2)[1])
            except (IndexError, ValueError):
                pass
        return status, bytes(out)


class _phase:
    def __init__(self, target: dict, key: str):
        self.target, self.key = target, key

    def __enter__(self):
        self.t0 = time.perf_counter()

    def __exit__(self, *exc):
        self.target[self.key] = self.target.get(self.key, 0.0) + (time.perf_counter() - self.t0) * 1000


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8543)
    p.add_argument("--path", default="/")
    p.add_argument("--post", default=None)
    p.add_argument("--runs", type=int, default=1)
    p.add_argument("--maa", default=os.environ.get("MAA_URL", "https://sharedweu.weu.attest.azure.net"))
    a = p.parse_args()
    c = OakClient(host=a.host, port=a.port, maa_issuer=a.maa)
    for i in range(a.runs):
        t: dict = {}
        method, body = ("POST", a.post.encode()) if a.post else ("GET", b"")
        status, out = c.request(method, a.path, body,
                                {"content-type": "application/json"} if a.post else {}, t)
        print(f"run {i}: status={status} bytes={len(out)} " +
              " ".join(f"{k}={v:.2f}" for k, v in t.items() if isinstance(v, float)))


if __name__ == "__main__":
    main()
