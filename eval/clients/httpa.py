# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

"""HTTPA/2 baseline client.

Per-connection attestation as a post-TLS-1.3 exchange:

1. TCP connect, TLS-1.3 handshake to the HTTPA2 server.
2. POST /attest with a fresh 32-byte nonce.
3. Server returns its SEV-SNP evidence bundle with REPORT_DATA bound to
   the nonce.
4. Client verifies the bundle via Azure MAA (same endpoint as cTLS /
   RA+TLS) so the AS round-trip cost is comparable across protocols.
5. HTTP GET on the now-attested connection → first response byte.

``attest_ms`` covers steps 2--4 (the post-handshake attestation work,
including the MAA RTT if the JWKS cache is cold).  ``http_ms`` is the
GET → first-byte time on the same connection.  ``tls_ms`` is the
standard TLS-1.3 handshake only.

The verification logic delegates to ``janus/common/snp_attestation``
— the same module the existing standalone HTTPA client uses — so the
bench measures the same work, not a re-implementation.
"""

from __future__ import annotations

import hashlib
import os
import socket
import ssl
import struct
import sys
import time
from pathlib import Path

from clients import _http
from clients._base import AttemptResult, phase

# Add the repository root to sys.path so ``from janus.common.snp_attestation import …`` works
# regardless of where the runner was invoked from.
_CODEBASE = Path(__file__).resolve().parent.parent.parent
if str(_CODEBASE) not in sys.path:
    sys.path.insert(0, str(_CODEBASE))

NONCE_LEN = 32
REPORT_DATA_OFFSET = 0x50


class HttpaClient:
    protocol_name = "httpa"
    mode_name = ""

    def __init__(
        self,
        *,
        host: str,
        port: int,
        payload_path: str,
        http_template: str,
        timeout_s: float,
        maa_url: str,
        ca_bundle: str | None,
        mock_verify: bool = False,
    ):
        self.host = host
        self.port = int(port)
        self.payload_path = payload_path
        self.http_template = http_template
        self.timeout_s = float(timeout_s)
        self.maa_url = maa_url
        self.mock_verify = mock_verify

        ctx = ssl.create_default_context()
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        if ca_bundle:
            ctx.load_verify_locations(cafile=ca_bundle)
        else:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        self.ctx = ctx

    def _verify_bundle(self, bundle: bytes, nonce: bytes) -> None:
        if self.mock_verify:
            expected = hashlib.sha256(nonce).digest()
            rlen = struct.unpack(">I", bundle[:4])[0]
            hcl = bundle[4 : 4 + rlen]
            snp = hcl[32 : 32 + 0x4A0]
            if (
                snp[REPORT_DATA_OFFSET : REPORT_DATA_OFFSET + len(expected)]
                != expected
            ):
                raise RuntimeError("REPORT_DATA mismatch (mock)")
            return
        from janus.common.snp_attestation import verify_snp_bundle  # type: ignore
        ok, info = verify_snp_bundle(
            bundle, expected_nonce=nonce, maa_url=self.maa_url
        )
        if not ok:
            raise RuntimeError(f"MAA verification failed: {info.get('error')}")

    def measure_one_attempt(
        self, attempt_id: int, run_id: str, is_warmup: bool = False
    ) -> AttemptResult:
        result = AttemptResult(
            protocol=self.protocol_name,
            mode=self.mode_name,
            run_id=run_id,
            attempt_id=attempt_id,
        )
        timing: dict[str, float] = {}
        breakdown: dict[str, float] = {}
        t_start = time.perf_counter()

        sock = None
        ssock = None
        try:
            with phase(timing, "tcp_ms"):
                sock = socket.create_connection(
                    (self.host, self.port), timeout=self.timeout_s
                )
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            with phase(timing, "tls_ms"):
                ssock = self.ctx.wrap_socket(sock, server_hostname=self.host)

            nonce = os.urandom(NONCE_LEN)
            with phase(timing, "attest_ms"):
                with phase(breakdown, "bundle_rtt_ms"):
                    req = (
                        f"POST /attest HTTP/1.1\r\n"
                        f"Host: {self.host}\r\n"
                        f"Content-Length: {NONCE_LEN}\r\n"
                        f"Content-Type: application/octet-stream\r\n"
                        f"Connection: keep-alive\r\n\r\n"
                    ).encode() + nonce
                    ssock.sendall(req)
                    headers, leftover = _read_until_blank(ssock)
                    status_line = headers.split(b"\r\n", 1)[0]
                    if b" 200 " not in status_line and not status_line.endswith(b" 200"):
                        raise RuntimeError(
                            f"/attest returned: {status_line.decode(errors='replace')}"
                        )
                    body_len = _parse_content_length(headers)
                    bundle = _read_exactly(ssock, leftover, body_len)
                with phase(breakdown, "maa_verify_ms"):
                    self._verify_bundle(bundle, nonce)

            # HTTPA end-state: the attestation bundle IS the first
            # application-visible response over the established channel,
            # and its arrival + verification is the point at which the
            # client has a verified-TEE channel ready for app data.  We
            # therefore measure e2e through attestation verification
            # (matching the reference httpa/client.py and the paper's
            # "connection-establishment latency" framing) rather than
            # appending a trailing GET — the post-handshake /attest round
            # trip already exercised the channel and returned a full HTTP
            # response.  http_ms stays 0; attest_ms carries the round trip.
            if len(bundle) < 64:
                result.ok = False
                result.notes = f"short_bundle={len(bundle)}"
        finally:
            for s in (ssock, sock):
                if s is not None:
                    try:
                        s.close()
                    except Exception:
                        pass

        result.tcp_ms = timing.get("tcp_ms", 0.0)
        result.tls_ms = timing.get("tls_ms", 0.0)
        result.attest_ms = timing.get("attest_ms", 0.0)
        result.http_ms = timing.get("http_ms", 0.0)
        # Establishment = TCP + TLS + post-handshake attestation (POST /attest
        # + MAA verify).  HTTPA pays one more round trip here than RA+TLS,
        # whose attestation rides inside the handshake.
        result.total_e2e_ms = result.establishment_ms()
        result.breakdown = breakdown
        # Note: ``verify_snp_bundle`` in janus/common/snp_attestation
        # maintains its own internal JWKS state, which our JwksCache
        # cannot wipe.  In cold-cache runs HTTPA may therefore appear
        # warmer than cTLS / RA+TLS; the eval section flags this so the
        # comparison stays explainable.  We do not set jwks_cold here.
        return result


def _read_until_blank(sock, max_hdr: int = 8192) -> tuple[bytes, bytes]:
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


def _parse_content_length(headers: bytes) -> int:
    for line in headers.split(b"\r\n"):
        if line.lower().startswith(b"content-length:"):
            return int(line.split(b":", 1)[1].strip())
    raise RuntimeError("no Content-Length in response")


def _read_exactly(sock, already: bytes, n: int) -> bytes:
    buf = bytearray(already[:n])
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise RuntimeError("connection closed before body fully read")
        buf.extend(chunk)
    return bytes(buf)


def build_client(env, runs, *, jwks_cache, cache_policy):
    cfg = env["protocols"]["httpa"]
    return HttpaClient(
        host=cfg["host"],
        port=cfg["port"],
        payload_path=env["payload"]["path"],
        http_template=runs["http_request_template"],
        timeout_s=runs.get("http_timeout_s", 30),
        maa_url=env["maa"]["url"],
        ca_bundle=cfg.get("server_cert_ca") or None,
        mock_verify=os.environ.get("HTTPA_MOCK_VERIFY") == "1",
    )
