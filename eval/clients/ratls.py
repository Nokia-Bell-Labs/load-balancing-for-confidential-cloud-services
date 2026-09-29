# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

"""RA+TLS baseline client.

Per-connection attestation piggybacked into the TLS-1.3 handshake via
extension 421: the server generates a fresh SEV-SNP evidence bundle bound
to the handshake's binder secret, sends it in the Certificate flight, and
the client verifies it (against Azure MAA) mid-handshake.  Every
connection therefore carries a fresh hardware quote — the defining cost
of RA+TLS.

This wraps the reference client ``ratls/client.py::RATLSHTTPClient`` so
the bench measures the same attestation work as the upstream prototype,
not a re-implementation.  It MUST run under the custom ``python-ratls``
interpreter (OpenSSL 1.1.1m with the binder-secret API + the
``ratls_bridge`` extension); under stock CPython ``build_client`` raises
a clear error.

Schema mapping (per the wrapper's own per-phase ``timing`` dict):
  tls_ms     = tls_handshake_baseline  (TLS handshake incl. server-side
               per-connection quote generation, which happens in-band)
  attest_ms  = ra_verification         (client-side MAA verify, mid-handshake)
  http_ms    = http_request            (GET to first response)
  total_e2e  = wall-clock around fetch_page
"""

from __future__ import annotations

import logging
import os
import sys
import time
from pathlib import Path

from clients._base import AttemptResult, phase


def _locate_codebase() -> Path | None:
    """Find the ``codebase`` dir holding ratls/, common/, python-ratls/.

    The bench may be deployed anywhere (e.g. /home/janus/bench on the
    client VM), so a path relative to this file is unreliable.  Prefer an
    explicit env var, then the canonical deployment path, then the
    relative guess.
    """
    candidates = []
    if os.environ.get("RATLS_CODEBASE"):
        candidates.append(Path(os.environ["RATLS_CODEBASE"]))
    candidates.append(Path(__file__).resolve().parent.parent.parent)
    for c in candidates:
        # in-repo layout (baselines/ratls) or flat deployment layout (ratls/)
        for sub in (c / "baselines" / "ratls", c / "ratls"):
            if (sub / "server").is_dir():
                return sub.parent
    return None


_CODEBASE = _locate_codebase()
if _CODEBASE is not None:
    for p in (_CODEBASE, _CODEBASE / "ratls", _CODEBASE / "ratls" / "server"):
        if str(p) not in sys.path:
            sys.path.insert(0, str(p))

try:
    import ratls_bridge  # type: ignore  # noqa: F401
    _HAS_RATLS = True
    _RATLS_IMPORT_ERROR = ""
except Exception as _e:  # pragma: no cover
    _HAS_RATLS = False
    _RATLS_IMPORT_ERROR = repr(_e)


class RatlsClient:
    protocol_name = "ratls"
    mode_name = ""

    def __init__(self, *, host: str, port: int, payload_path: str,
                 timeout_s: float):
        self.host = host
        self.port = int(port)
        self.payload_path = payload_path
        self.timeout_s = float(timeout_s)
        from ratls.client import RATLSHTTPClient  # type: ignore
        self._wrapper_cls = RATLSHTTPClient
        # The reference client is chatty; quiet it so it doesn't dominate
        # wall-clock with logging during measurement.
        logging.getLogger().setLevel(logging.WARNING)
        for n in ("ratls", "__main__"):
            logging.getLogger(n).setLevel(logging.WARNING)

    def measure_one_attempt(self, attempt_id: int, run_id: str,
                            is_warmup: bool = False) -> AttemptResult:
        result = AttemptResult(
            protocol=self.protocol_name, mode=self.mode_name,
            run_id=run_id, attempt_id=attempt_id)
        breakdown: dict[str, float] = {}
        timing: dict[str, float] = {}

        # Fresh client per attempt → fresh connection → fresh quote, with a
        # clean per-attempt timing dict.
        wrapper = self._wrapper_cls(
            server_url=f"https://{self.host}:{self.port}",
            verify_quote=True, ca_cert_path=None)

        content = wrapper.fetch_page(self.payload_path)

        w = getattr(wrapper, "timing", {}) or {}
        # tls_handshake_baseline is the handshake minus client RA verify, and
        # it includes the server's in-band quote generation.
        result.tls_ms = float(w.get("tls_handshake_baseline",
                                    w.get("tls_handshake_total", 0.0)))
        result.attest_ms = float(w.get("ra_verification", 0.0))
        result.http_ms = float(w.get("http_request", 0.0))
        result.tcp_ms = 0.0  # folded into the wrapper's handshake timing
        breakdown.update({k: float(v) for k, v in w.items()
                          if isinstance(v, (int, float))})
        # Establishment = handshake (with in-band quote + RA verify); the
        # data GET (http_request) is excluded so RA+TLS and HTTPA are
        # compared at the same end-state.  RA+TLS attests inside the
        # handshake, so it pays one fewer round trip than HTTPA's POST.
        result.total_e2e_ms = result.establishment_ms()

        if not content:
            result.ok = False
            result.notes = "empty_response_or_quote_fail"
        result.breakdown = breakdown
        return result


def build_client(env, runs, *, jwks_cache, cache_policy):
    if not _HAS_RATLS:
        raise RuntimeError(
            "ratls_bridge not importable: " + _RATLS_IMPORT_ERROR +
            "\nRun the bench under the patched Python:\n"
            "  <repo>/baselines/python-ratls/bin/python3 runner.py "
            "--protocol ratls ...")
    cfg = env["protocols"]["ratls"]
    return RatlsClient(
        host=cfg["host"], port=cfg["port"],
        payload_path=env["payload"].get("ratls_path", "/"),
        timeout_s=runs.get("http_timeout_s", 30))
