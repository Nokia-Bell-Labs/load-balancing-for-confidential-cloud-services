# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

"""OHTTP+KMS baseline client (Azure AI confidential inferencing model).

Attest-once-per-key-epoch design, load-balanced in proxy mode through an
untrusted front end:

  1. (cold) TCP+TLS to the KMS, GET /keyconfig, verify the KMS's attestation
     evidence with the same checks the Janus client runs on the frontend
     certificate (janus.client.attest), then the KMS signature over the key
     configuration.  Warm: the configuration is cached from a previous attempt.
  2. Seal the request under HPKE with a fresh context (RFC 9458 s6.1).
  3. TCP+TLS to the untrusted front end (plain TLS, no attestation on it),
     POST the encapsulated request; the front end forwards it to any gateway.
  4. First decrypted byte of the sealed, chunked response.

Phase mapping (see ``_base.AttemptResult``):
    tcp_ms / tls_ms       the client->KMS connection (cold) -- the control leg,
                          the analogue of Janus-redirection's frontend leg
    attest_ms             cold only: key-config fetch + KMS verification on the
                          client, plus the gateway's lazy attestation to the
                          KMS (``X-Key-Fetch-Ms``), which blocks the first
                          request after a rotation
    extra_tcp_ms/extra_tls_ms   the client->front-end connection; extra_tls
                          also carries the HPKE context setup (the client's
                          only per-request key agreement, ~0.3 ms)
    http_ms               POST -> first decrypted byte, net of the gateway's
                          key fetch

``total_e2e_ms`` is the time to the first verified response: TLS to the front
end, the HPKE context and the sealed request round trip (``http_ms``). The
gateway proves that it holds the attested key only with the response, so
Table 2 reports this end point for OHTTP+KMS.
In the rotation case ``attest_ms`` also carries the gateway's lazy attestation
to the KMS, which blocks the first request.

Cold semantics: ``cache_policy: cold`` wipes the client's key configuration
before every attempt.  If ``protocols.ohttp_kms.rotate_on_cold`` is true the
client additionally asks the KMS to rotate first (evaluation-only endpoint),
so the gateway also misses its key cache and attests lazily -- the "first
request after a rotation" case; the gateway's fetch time is surfaced in the
breakdown as ``gw_key_fetch_ms`` from the ``X-Key-Fetch-Ms`` header.

The implementation is the standalone baseline client
(``baselines/ohttp/ohttp/client.py``), not a re-implementation.
"""
from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import requests

from clients._base import AttemptResult, JwksCache

_CODEBASE = Path(__file__).resolve().parent.parent.parent
for _p in (str(_CODEBASE), str(_CODEBASE / "baselines" / "ohttp")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from ohttp.client import OhttpClient  # noqa: E402


class OhttpKmsClient:
    protocol_name = "ohttp_kms"
    mode_name = "proxy"

    def __init__(self, *, kms_host, kms_port, frontend_host, frontend_port,
                 forward_path, request_path, request_method, request_body,
                 timeout_s, maa_issuer, jwks_cache, cache_policy,
                 rotate_on_cold, kms_url, ca_bundle, cold_jwks="warm"):
        self.client = OhttpClient(kms_host=kms_host, kms_port=kms_port,
                                  frontend_host=frontend_host, frontend_port=frontend_port,
                                  forward_path=forward_path, maa_issuer=maa_issuer,
                                  timeout_s=timeout_s, insecure=not ca_bundle,
                                  ca_bundle=ca_bundle)
        self.request_path = request_path
        self.request_method = request_method
        self.request_body = request_body
        self.cold = cache_policy == "cold"
        # "cold" for OHTTP means the first request after a key rotation: the client
        # refetches the key configuration and the gateway attests again.  A rotation
        # does not invalidate the attestation service's signing keys, so the JWKS
        # cache stays warm (protocols.ohttp_kms.cold_jwks: cold also empties it).
        if self.cold and cold_jwks != "cold":
            jwks_cache = JwksCache(jwks_cache.cache_dir, policy="warm")
        self.jwks_cache = jwks_cache
        self.rotate_on_cold = rotate_on_cold
        # OHTTP_ROTATE_ALWAYS=1: "first request after a key rotation" with a
        # warm JWKS cache -- the client refetches and verifies the key
        # configuration and the gateway attests lazily, but the attestation
        # service's signing keys stay cached (a rotation does not invalidate
        # them).  Use with cache_policy warm and a separate output directory.
        self.rotate_always = os.environ.get("OHTTP_ROTATE_ALWAYS") == "1"
        self.kms_url = kms_url

    def measure_one_attempt(self, attempt_id: int, run_id: str,
                            is_warmup: bool = False) -> AttemptResult:
        result = AttemptResult(protocol=self.protocol_name, mode=self.mode_name,
                               run_id=run_id, attempt_id=attempt_id)
        t: dict = {}
        breakdown: dict = {"app_status": 0, "session_completed": 0,
                           "application_ok": 0, "success_criterion": "http_200",
                           "rotate_admin_ms": 0.0, "rotation_requested": 0,
                           "rotation_succeeded": 0}
        try:
            if self.cold or self.rotate_always:
                self.client.invalidate()
                if self.rotate_on_cold or self.rotate_always:
                    breakdown["rotation_requested"] = 1
                    t0 = time.perf_counter()
                    try:
                        response = requests.post(f"{self.kms_url}/rotate", verify=False, timeout=30)
                        response.raise_for_status()
                        breakdown["rotation_succeeded"] = 1
                    finally:
                        breakdown["rotate_admin_ms"] = (time.perf_counter() - t0) * 1000
            status, body = self.client.request(
                self.request_method, self.request_path, self.request_body,
                {"content-type": "application/json"} if self.request_body else {},
                t, self.jwks_cache)
            breakdown.update(app_status=status, session_completed=int(status != 0),
                             application_ok=int(status == 200))
            if status != 200:
                result.ok = False
                result.notes = f"status={status}"
        except Exception as exc:
            result.ok = False
            result.notes = f"error={type(exc).__name__}:{str(exc)[:80]}"
        # Control leg (KMS) -> tcp/tls/attest; data leg (front end) -> extra_*.
        # The gateway's lazy key fetch (attestation to the KMS) is reported by
        # the gateway per request; it is attestation on the path, so it moves
        # from the request phase into attest_ms.
        gw_fetch = t.get("gw_key_fetch_ms", 0.0)
        result.tcp_ms = t.get("kms_tcp_ms", 0.0)
        result.tls_ms = t.get("kms_tls_ms", 0.0)
        result.attest_ms = (t.get("kms_fetch_ms", 0.0) + t.get("kms_verify_ms", 0.0)
                            + gw_fetch)
        result.extra_tcp_ms = t.get("tcp_ms", 0.0)
        result.extra_tls_ms = t.get("tls_ms", 0.0) + t.get("hpke_seal_ms", 0.0)
        result.http_ms = max(0.0, t.get("request_ms", 0.0) - gw_fetch)
        result.jwks_cold = bool(t.get("_jwks_cold", False))
        # Table 2 reports OHTTP+KMS up to the first verified response: the gateway proves that it holds
        # the attested key only with the response. So the total includes the request (http_ms).
        result.total_e2e_ms = result.phase_sum_ms()
        for k in ("kms_fetch_ms", "kms_verify_ms", "hpke_seal_ms", "request_ms",
                  "body_ms", "gw_key_fetch_ms"):
            if k in t:
                breakdown[k] = t[k]
        breakdown["key_id"] = self.client.keyconfig.key_id if self.client.keyconfig else -1
        result.breakdown = breakdown
        return result


def build_client(env, runs, *, jwks_cache, cache_policy):
    cfg = env["protocols"]["ohttp_kms"]
    # kms_url is the untimed admin path (key rotation before a cold attempt). With a relay in front
    # (kms_host/frontend_host = the relay), it must go to the KMS directly: a relay forwards only the
    # key configuration and encapsulated requests.
    kms_url = cfg.get("kms_admin_url") or f"https://{cfg['kms_host']}:{cfg['kms_port']}"
    body = cfg.get("request_body", "")
    return OhttpKmsClient(
        kms_host=cfg["kms_host"], kms_port=int(cfg["kms_port"]),
        frontend_host=cfg["frontend_host"], frontend_port=int(cfg["frontend_port"]),
        forward_path=cfg.get("forward_path", "/forward/ohttp"),
        # protocols.ohttp_kms.path, if set, overrides the shared payload path (the paper runs requested /)
        request_path=cfg.get("path") or env["payload"].get("backend_path", env["payload"]["path"]),
        request_method="POST" if body else "GET",
        request_body=body.encode() if body else b"",
        timeout_s=runs.get("http_timeout_s", 30),
        maa_issuer=env["maa"]["url"],
        jwks_cache=jwks_cache,
        cache_policy=cache_policy,
        rotate_on_cold=bool(cfg.get("rotate_on_cold", True)),
        kms_url=kms_url,
        ca_bundle=cfg.get("server_cert_ca") or None,
        cold_jwks=cfg.get("cold_jwks", "warm"),
    )
