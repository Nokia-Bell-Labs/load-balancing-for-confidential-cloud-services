# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

"""cTLS proxy-mode measurement client.

A thin measurement wrapper over the reference client in ``janus.client.proxy``:
it drives the protocol, records per-phase latencies, and packages them into the
eval ``AttemptResult`` schema. The protocol itself (TLS to the frontend +
attestation validation + relayed HTTP) lives in ``janus/client/proxy.py``.

``total_e2e_ms`` is the establishment latency (verified channel ready); the
trailing GET (``http_ms``) is excluded. Protocol-specific sub-timings
(``jwks_fetch_ms``/``jwt_sig_ms``/``reportdata_ms``) go to the breakdown CSV.
"""
from __future__ import annotations
import os

from janus.client.proxy import ProxyClient
from clients._base import AttemptResult


class CtlsProxyClient:
    protocol_name = "ctls"
    mode_name = "proxy"

    def __init__(
        self,
        *,
        frontend_host: str,
        frontend_port: int,
        payload_path: str,
        http_template: str,
        timeout_s: float,
        maa_issuer: str,
        jwks_cache,
    ):
        self.payload_path = payload_path
        self.http_template = http_template
        self.jwks_cache = jwks_cache
        self.client = ProxyClient(
            frontend_host=frontend_host,
            frontend_port=frontend_port,
            timeout_s=timeout_s,
            maa_issuer=maa_issuer,
        )

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

        ok, status, jwks_cold = self.client.connect_validate_request(
            self.jwks_cache, self.http_template, self.payload_path,
            timing=timing, breakdown=breakdown)
        result.jwks_cold = jwks_cold
        if not ok:
            result.ok = False
            result.notes = f"http_status={status}"

        result.tcp_ms = timing.get("tcp_ms", 0.0)
        result.tls_ms = timing.get("tls_ms", 0.0)
        result.attest_ms = timing.get("attest_ms", 0.0)
        result.http_ms = timing.get("http_ms", 0.0)
        # Establishment latency (verified channel ready); GET excluded.
        result.total_e2e_ms = result.establishment_ms()
        result.breakdown = breakdown
        return result


def build_client(env, runs, *, jwks_cache, cache_policy):
    cfg = env["protocols"]["ctls_proxy"]
    return CtlsProxyClient(
        frontend_host=cfg["frontend_host"],
        frontend_port=cfg["frontend_port"],
        # Proxy-mode GET hits the FRONTEND (which serves only /forward*), not the
        # backend directly, and is excluded from establishment latency — so
        # default to "/" (frontend index → 200), matching the measured runs.
        # Override via protocols.ctls_proxy.path for a real forwarded path.
        # JANUS_PROXY_PATH overrides it for a run: the throughput run
        # (eval/ae/run_fig6.sh, Fig. 6) sets /forward/health so every request
        # is relayed to a backend, as the paper's runs did.
        payload_path=os.environ.get("JANUS_PROXY_PATH") or cfg.get("path", "/"),
        http_template=runs["http_request_template"],
        timeout_s=runs.get("http_timeout_s", 30),
        maa_issuer=env["maa"]["url"],
        jwks_cache=jwks_cache,
    )
