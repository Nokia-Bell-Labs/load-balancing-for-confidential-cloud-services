# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

"""OHTTP+KMS baseline -- the client.

Per-phase measurement client, in the style of ``baselines/httpa/httpa/client.py``.

    1. (cold only) TLS to the KMS, GET /keyconfig, verify the KMS's evidence
       with the SAME checks the Janus client runs on the frontend certificate
       (janus.client.attest: JWT signature with the cached AS key, validity,
       REPORTDATA binding), then the KMS signature over the key config.
    2. Seal the request under HPKE with a fresh context (RFC 9458 s6.1).
    3. TLS to the untrusted front end, POST the encapsulated request; the
       front end forwards it to any gateway.  The TLS here is plain transport
       (no attestation is checked on it), as in Azure's deployment.
    4. Read the sealed response; first decrypted application body byte = "first byte".

Phases reported (ms):
    kms_tcp_ms, kms_tls_ms, kms_fetch_ms, kms_verify_ms   (cold only)
    hpke_seal_ms, tcp_ms, tls_ms, request_ms (POST -> first decrypted body byte)
    response_headers_ms (overlapping diagnostic, not an additive phase)

Usage:
    python3 -m ohttp.client --kms https://KMS:6038 --frontend https://FE:6039 \
        --path /reservation [--cold] [--insecure]
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import http.client
import json
import os
import socket
import ssl
import sys
import time
from pathlib import Path
from typing import Optional

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

_HERE = Path(__file__).resolve()
_CODEBASE = _HERE.parents[3]
for p in (str(_CODEBASE), str(_HERE.parents[1])):
    if p not in sys.path:
        sys.path.insert(0, p)

from janus.client import attest  # noqa: E402
from ohttp import wire  # noqa: E402

MOCK_VERIFY = os.environ.get("OHTTP_MOCK_VERIFY") == "1"


class _NoJwksCache:
    def get(self, issuer, kid):
        return None

    def put(self, issuer, kid, entry):
        pass


class OhttpClient:
    def __init__(self, *, kms_host: str, kms_port: int, frontend_host: str,
                 frontend_port: int, forward_path: str = "/forward/ohttp",
                 maa_issuer: str = "https://sharedweu.weu.attest.azure.net",
                 timeout_s: float = 30.0, insecure: bool = True,
                 ca_bundle: Optional[str] = None):
        self.kms_host, self.kms_port = kms_host, kms_port
        self.frontend_host, self.frontend_port = frontend_host, frontend_port
        self.forward_path = forward_path
        self.maa_issuer = maa_issuer
        self.timeout_s = timeout_s
        ctx = ssl.create_default_context()
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        if ca_bundle:
            ctx.load_verify_locations(cafile=ca_bundle)
        elif insecure:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        self.ctx = ctx
        self.keyconfig: Optional[wire.KeyConfig] = None
        self.keyconfig_not_after: int = 0

    # ── step 1: key configuration from the KMS ──────────────────────────────

    def fetch_keyconfig(self, jwks_cache=None, timing: Optional[dict] = None) -> wire.KeyConfig:
        t = timing if timing is not None else {}
        jwks_cache = jwks_cache or _NoJwksCache()
        with _phase(t, "kms_tcp_ms"):
            s = socket.create_connection((self.kms_host, self.kms_port), timeout=self.timeout_s)
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        with _phase(t, "kms_tls_ms"):
            ss = self.ctx.wrap_socket(s, server_hostname=self.kms_host)
        try:
            with _phase(t, "kms_fetch_ms"):
                ss.sendall(f"GET /keyconfig HTTP/1.1\r\nHost: {self.kms_host}\r\n"
                           f"Connection: close\r\n\r\n".encode())
                body = _recv_http_body(ss)
            with _phase(t, "kms_verify_ms"):
                data = json.loads(body)
                cfg_bytes = base64.b64decode(data["key_config_b64"])
                chain = x509.load_pem_x509_certificates(data["kms_cert_chain_pem"].encode())
                kms_cert = chain[0]
                if not MOCK_VERIFY:
                    # Same four checks as RedirectClient.attest_frontend steps (i)-(iv).
                    jwt_token = attest.extract_jwt(kms_cert)
                    header, payload, _ = attest.parse_jwt(jwt_token)
                    issuer = payload.get("iss") or self.maa_issuer
                    jwks = attest.get_maa_public_key(
                        issuer, header.get("kid", ""),
                        header.get("jku") or f"{self.maa_issuer}/certs",
                        jwks_cache, self.timeout_s,
                        trusted_issuer=self.maa_issuer)   # pin the AS, as the Janus client does
                    t["_jwks_cold"] = jwks.cold
                    attest.verify_jwt_rs256(jwt_token, jwks.public_key)
                    attest.verify_jwt_validity(payload)
                    attest.verify_reportdata_ctls(kms_cert, payload)
                # KMS signature binds the config to that attested identity.
                signed = cfg_bytes + int(data["not_after"]).to_bytes(8, "big")
                kms_cert.public_key().verify(base64.b64decode(data["kms_sig_b64"]),
                                             signed, ec.ECDSA(hashes.SHA256()))
                self.keyconfig = wire.KeyConfig.decode(cfg_bytes)
                self.keyconfig_not_after = int(data["not_after"])
        finally:
            ss.close()
        return self.keyconfig

    def invalidate(self):
        """Forget the key configuration (the cold case)."""
        self.keyconfig = None

    # ── steps 2-4: one request ──────────────────────────────────────────────

    def request(self, method: str, path: str, body: bytes = b"",
                headers: Optional[dict] = None, timing: Optional[dict] = None,
                jwks_cache=None, on_chunk=None) -> tuple[int, bytes]:
        """Send one OHTTP request via the front end; return (status, body).

        ``timing`` gets the per-phase fields; ``request_ms`` is POST to first
        decrypted application body byte (headers for an empty response),
        ``body_ms`` the remainder of the stream. ``response_headers_ms`` is
        an overlapping diagnostic and must not be added to the phase total.  ``on_chunk``
        (optional) is called with each decrypted body chunk as it arrives
        (streaming responses, e.g. LLM tokens).
        """
        t = timing if timing is not None else {}
        if self.keyconfig is not None and getattr(self, "keyconfig_not_after", 0) \
                and time.time() > self.keyconfig_not_after:
            self.invalidate()                      # the configuration expired (RFC 9458)
        if self.keyconfig is None:
            self.fetch_keyconfig(jwks_cache, t)
        with _phase(t, "hpke_seal_ms"):
            sctx = wire.SenderContext(self.keyconfig)
            inner = wire.encode_inner_request(method, path, headers or {}, body)
            encapsulated = sctx.seal(inner)
            opener = sctx.response_opener()
        with _phase(t, "tcp_ms"):
            s = socket.create_connection((self.frontend_host, self.frontend_port),
                                         timeout=self.timeout_s)
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        with _phase(t, "tls_ms"):
            ss = self.ctx.wrap_socket(s, server_hostname=self.frontend_host)
        response = None
        try:
            t0 = time.perf_counter()
            ss.sendall((f"POST {self.forward_path} HTTP/1.1\r\nHost: {self.frontend_host}\r\n"
                        f"Content-Type: {wire.MT_REQUEST}\r\n"
                        f"Content-Length: {len(encapsulated)}\r\n"
                        f"Connection: close\r\n\r\n").encode() + encapsulated)
            # Decode HTTP transfer framing before passing bytes to the sealed
            # response parser. A streaming relay normally uses chunked HTTP.
            response = http.client.HTTPResponse(ss)
            response.begin()
            if response.status != 200:
                raise RuntimeError(f"front end returned HTTP {response.status}")
            if response.getheader("X-Key-Fetch-Ms") is not None:
                t["gw_key_fetch_ms"] = float(response.getheader("X-Key-Fetch-Ms"))
            out = bytearray()
            first = None
            headers_at = None
            inner_status = None
            while not opener.done:
                # read1 returns available decoded bytes instead of waiting for
                # a large fixed buffer or the end of a streamed response.
                buf = response.read1(65536)
                if not buf:
                    raise RuntimeError("truncated sealed response")
                for pt in opener.feed(buf):
                    if inner_status is None:
                        headers_at = time.perf_counter()
                        # inner response head: "<status>\n<headers>\n\n"
                        hdr, separator, tail = pt.partition(b"\n\n")
                        if not separator:
                            raise RuntimeError("invalid inner response headers")
                        inner_status = int(hdr.split(b"\n", 1)[0])
                        out += tail
                        if tail:
                            first = time.perf_counter()
                            if on_chunk:
                                on_chunk(tail)
                    else:
                        if first is None and pt:
                            first = time.perf_counter()
                        out += pt
                        if on_chunk:
                            on_chunk(pt)
            if inner_status is None:
                raise RuntimeError("sealed response has no inner status")
            t["response_headers_ms"] = ((headers_at or time.perf_counter()) - t0) * 1000
            t["request_ms"] = ((first or headers_at or time.perf_counter()) - t0) * 1000
            t["body_ms"] = (time.perf_counter() - (first or t0)) * 1000
        finally:
            if response is not None:
                response.close()
            ss.close()
        return inner_status or 0, bytes(out)


# ── helpers ─────────────────────────────────────────────────────────────────

class _phase:
    def __init__(self, target: dict, key: str):
        self.target, self.key = target, key

    def __enter__(self):
        self.t0 = time.perf_counter()

    def __exit__(self, *exc):
        self.target[self.key] = self.target.get(self.key, 0.0) + (time.perf_counter() - self.t0) * 1000


def _read_until_blank(sock, max_hdr: int = 16384) -> tuple[bytes, bytes]:
    buf = b""
    while b"\r\n\r\n" not in buf:
        if len(buf) >= max_hdr:
            raise RuntimeError("response headers too large")
        chunk = sock.recv(4096)
        if not chunk:
            raise RuntimeError("connection closed before headers")
        buf += chunk
    head, _, rest = buf.partition(b"\r\n\r\n")
    return head, rest


def _recv_http_body(sock) -> bytes:
    head, rest = _read_until_blank(sock)
    n = None
    for line in head.split(b"\r\n"):
        if line.lower().startswith(b"content-length:"):
            n = int(line.split(b":", 1)[1])
    buf = bytearray(rest)
    while n is None or len(buf) < n:
        chunk = sock.recv(65536)
        if not chunk:
            break
        buf += chunk
    return bytes(buf[:n] if n is not None else buf)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--kms", default="https://127.0.0.1:6038")
    p.add_argument("--frontend", default="https://127.0.0.1:6039")
    p.add_argument("--path", default="/")
    p.add_argument("--post", default=None, help="JSON body -> POST")
    p.add_argument("--cold", action="store_true", help="refetch key config first")
    p.add_argument("--runs", type=int, default=1)
    a = p.parse_args()
    from urllib.parse import urlparse
    k, f = urlparse(a.kms), urlparse(a.frontend)
    c = OhttpClient(kms_host=k.hostname, kms_port=k.port, frontend_host=f.hostname,
                    frontend_port=f.port)
    for i in range(a.runs):
        if a.cold:
            c.invalidate()
        t: dict = {}
        method, body = ("POST", a.post.encode()) if a.post else ("GET", b"")
        status, out = c.request(method, a.path, body,
                                {"content-type": "application/json"} if a.post else {}, t)
        print(f"run {i}: status={status} bytes={len(out)} " +
              " ".join(f"{k}={v:.2f}" for k, v in t.items() if isinstance(v, float)))


if __name__ == "__main__":
    main()
