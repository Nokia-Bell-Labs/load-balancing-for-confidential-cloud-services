# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

"""Oak baseline client -- attested session nested inside untrusted TLS.

Single client-server (no load balancing), fresh evidence per connection:

  1. TCP + outer TLS 1.3 to the Oak server (plain transport; not verified).
  2. ATTEST round trip: the server sends a fresh binding key, an SNP
     evidence bundle whose TPM quote binds that key, and the MAA JWT it
     obtained for it.  The client verifies locally with cached AS keys
     (JWT signature, validity, measurement, quote binding).
  3. Noise NN handshake (one round trip); the server signs the handshake
     hash with the bound key; the client verifies the signature.
  4. HTTP GET over the session -> first decrypted byte.

Phase mapping: ``tls_ms`` = outer TLS; ``attest_ms`` = step 2;
``extra_tls_ms`` = step 3 (the inner handshake); ``http_ms`` = step 4.
``establishment_ms()`` = tcp + tls + attest + extra_tls, i.e. time to an
attested, open session, comparable with the other rows.

Implementation: ``baselines/oak/oak/client.py`` (not a re-implementation).
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

from clients._base import AttemptResult

_CODEBASE = Path(__file__).resolve().parent.parent.parent
for _p in (str(_CODEBASE), str(_CODEBASE / "baselines" / "oak")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from oak.client import OakClient  # noqa: E402


class OakEvalClient:
    protocol_name = "oak"
    mode_name = ""

    def __init__(self, *, host, port, request_path, timeout_s, maa_issuer,
                 jwks_cache, expected_measurement, success_criterion="http_200"):
        if success_criterion not in ("http_200", "session_completed"):
            raise ValueError(f"Unknown Oak success criterion: {success_criterion!r}")
        self.success_criterion = success_criterion
        self.client = OakClient(host=host, port=port, maa_issuer=maa_issuer,
                                timeout_s=timeout_s, expected_measurement=expected_measurement)
        self.request_path = request_path
        self.jwks_cache = jwks_cache

    def measure_one_attempt(self, attempt_id: int, run_id: str,
                            is_warmup: bool = False) -> AttemptResult:
        result = AttemptResult(protocol=self.protocol_name, mode=self.mode_name,
                               run_id=run_id, attempt_id=attempt_id)
        t: dict = {"app_status": 0}
        session_completed = False
        try:
            status, _ = self.client.request("GET", self.request_path, timing=t,
                                            jwks_cache=self.jwks_cache)
            # Preserve the former Oak convention as an explicit option, but
            # default to successful application responses. Both outcomes are
            # recorded so one run can be analysed under either criterion.
            t["app_status"] = status
            session_completed = status != 0
            result.ok = (status == 200 if self.success_criterion == "http_200"
                         else session_completed)
            if not session_completed:
                result.notes = "no HTTP response over the session"
            elif status != 200:
                result.notes = f"app_status={status}"
        except Exception as exc:
            result.ok = False
            result.notes = f"error={type(exc).__name__}:{str(exc)[:80]}"
        result.tcp_ms = t.get("tcp_ms", 0.0)
        result.tls_ms = t.get("tls_ms", 0.0)
        result.attest_ms = t.get("attest_ms", 0.0)
        result.extra_tls_ms = t.get("noise_ms", 0.0)
        result.http_ms = t.get("http_ms", 0.0)
        result.jwks_cold = bool(t.get("_jwks_cold", False))
        result.total_e2e_ms = result.establishment_ms()
        result.breakdown = {k: v for k, v in t.items()
                            if k in ("attest_rtt_ms", "attest_verify_ms", "noise_ms", "app_status")
                            or k.startswith("server_")}
        result.breakdown.update({
            "session_completed": int(session_completed),
            "application_ok": int(session_completed and t["app_status"] == 200),
            "success_criterion": self.success_criterion,
        })
        return result


def build_client(env, runs, *, jwks_cache, cache_policy):
    cfg = env["protocols"]["oak"]
    return OakEvalClient(
        host=cfg["host"], port=int(cfg["port"]),
        # protocols.oak.path, if set, overrides the shared payload path (the paper runs requested /)
        request_path=cfg.get("path") or env["payload"].get("backend_path", env["payload"]["path"]),
        timeout_s=runs.get("http_timeout_s", 30),
        maa_issuer=env["maa"]["url"],
        jwks_cache=jwks_cache,
        expected_measurement=cfg.get("expected_measurement") or os.environ.get("EXPECTED_CVM_MEASUREMENT"),
        success_criterion=cfg.get("success_criterion", "http_200"),
    )
