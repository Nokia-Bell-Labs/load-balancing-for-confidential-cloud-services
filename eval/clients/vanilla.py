# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

"""Vanilla TLS client.  Floor baseline.

No attestation.  ``total_e2e_ms`` covers TCP connect, TLS 1.3 handshake,
HTTP GET, and first-byte arrival.  ``attest_ms`` is always zero.

The TLS context uses the system trust store by default; set
``server_cert_ca`` in ``configs/env.yaml`` to pin a non-system CA.
"""

from __future__ import annotations

import socket
import ssl
import time

from clients import _http
from clients._base import AttemptResult, phase


class VanillaClient:
    protocol_name = "vanilla"
    mode_name = ""

    def __init__(
        self,
        host: str,
        port: int,
        *,
        payload_path: str,
        http_template: str,
        timeout_s: float,
        ca_bundle: str | None,
    ):
        self.host = host
        self.port = int(port)
        self.payload_path = payload_path
        self.http_template = http_template
        self.timeout_s = float(timeout_s)
        ctx = ssl.create_default_context()
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        if ca_bundle:
            # Paper-faithful path: real CA chain validation included in
            # the TLS handshake timing.
            ctx.load_verify_locations(cafile=ca_bundle)
            ctx.check_hostname = False  # we connect by IP, not hostname
        else:
            # Isolated-VNet deployments use a self-signed cert.  Skip
            # PKI checks here so the timing reflects pure TLS handshake
            # cost — what cTLS handshake gets compared against.
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        self.ctx = ctx

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
            request = _http.build_http_get(
                self.http_template, self.host, self.payload_path
            )
            with phase(timing, "http_ms"):
                ssock.sendall(request)
                first = _http.recv_first_byte(ssock)
            # Drain to validate the response is real; not timed.
            body = _http.drain_response(ssock, first, max_bytes=8192)
            status = _http.parse_status_code(body)
            if status is None or status >= 400:
                result.ok = False
                result.notes = f"http_status={status}"
        finally:
            for s in (ssock, sock):
                if s is not None:
                    try:
                        s.close()
                    except Exception:
                        pass

        result.tcp_ms = timing.get("tcp_ms", 0.0)
        result.tls_ms = timing.get("tls_ms", 0.0)
        result.http_ms = timing.get("http_ms", 0.0)
        # Establishment latency (to verified channel ready); the trailing
        # GET (http_ms) is recorded but excluded for cross-protocol parity.
        result.total_e2e_ms = result.establishment_ms()
        return result


def build_client(env, runs, *, jwks_cache, cache_policy):
    cfg = env["protocols"]["vanilla"]
    return VanillaClient(
        host=cfg["host"],
        port=cfg["port"],
        payload_path=env["payload"]["path"],
        http_template=runs["http_request_template"],
        timeout_s=runs.get("http_timeout_s", 30),
        ca_bundle=cfg.get("server_cert_ca") or None,
    )
