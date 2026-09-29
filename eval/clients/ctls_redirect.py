# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

"""cTLS redirection-mode measurement client.

A thin measurement wrapper over the reference client in
``janus.client.redirect``: it drives the two-leg protocol (control connection to
the frontend, then a direct DC-validated data connection to a routed backend),
records per-phase latencies, fans data connections out across the
frontend-provided backend pool, and packages results into the eval
``AttemptResult`` schema. The protocol itself lives in
``janus/client/redirect.py``; the in-band RFC 9345 DC handshake is performed by
``nss_dc_helper`` (``janus/client/native/``).

Control-plane amortization
--------------------------
Redirect's defining property is that the frontend is off the data path: validate
once, then make many direct backend connections. ``amortize_control`` models
this — the control connection (steps i-iv) runs once at construction, and each
attempt is a data connection to a round-robin backend. With
``amortize_control=False`` (latency mode) every attempt does the full
control+data flow (the conservative per-connection cost).

Schema mapping:
  tcp_ms / tls_ms / attest_ms  → control connection (0 when amortized)
  extra_tcp_ms / extra_tls_ms  → data connection (extra_tls_ms includes the
                                 in-band DC validation, step v)
  http_ms                      → data-connection GET to first response byte
  breakdown.validate_ms / route_ms → split of attest_ms (crypto vs routing RTT)
"""
from __future__ import annotations
import os

import itertools
import queue
import subprocess
import threading
from pathlib import Path

from janus.client.redirect import RedirectClient
from clients._base import AttemptResult


class _NssHelperPool:
    """Pool of nss_dc_helper subprocesses for concurrent DC handshakes.

    A single helper serialises handshakes through one stdin/stdout pipe, which
    is correct for sequential latency runs but would itself cap throughput under
    the concurrent open-loop scale driver. The pool pre-spawns ``size`` helper
    processes and hands one to each caller via a checkout/checkin queue, so
    concurrency is bounded by the pool size (the scale driver's worker count),
    not by a global lock.
    """

    def __init__(self, helper_bin: str, nss_db: str, size: int):
        self.helper_bin = helper_bin
        self.nss_db = nss_db
        self._free: queue.Queue = queue.Queue()
        self._all = []
        for _ in range(max(1, size)):
            p = self._spawn()
            self._all.append(p)
            self._free.put(p)

    def _spawn(self):
        return subprocess.Popen(
            [self.helper_bin, self.nss_db],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, text=True, bufsize=1,
        )

    def request(self, host: str, port: int, path: str,
                timeout: float = 30.0) -> dict:
        proc = self._free.get()
        try:
            if proc.poll() is not None:  # respawn a dead helper
                proc = self._spawn()
            proc.stdin.write(f"{host} {port} {path}\n")
            proc.stdin.flush()
            out = proc.stdout.readline().strip()
        finally:
            self._free.put(proc)
        if not out.startswith("OK "):
            raise RuntimeError(f"nss_dc_helper: {out}")
        fields = {}
        for tok in out[3:].split():
            if "=" in tok:
                k, v = tok.split("=", 1)
                fields[k] = v
        return fields

    def close(self):
        for p in self._all:
            try:
                p.stdin.write("QUIT\n")
                p.stdin.flush()
                p.wait(timeout=3)
            except Exception:
                try:
                    p.kill()
                except Exception:
                    pass


class CtlsRedirectClient:
    protocol_name = "ctls"
    mode_name = "redirect"

    def __init__(
        self,
        *,
        frontend_host: str,
        frontend_port: int,
        backends: list[tuple[str, int]],
        routing_path: str,
        data_path: str,
        timeout_s: float,
        maa_issuer: str,
        jwks_cache,
        helper_pool: _NssHelperPool,
        amortize_control: bool,
    ):
        self.client = RedirectClient(
            frontend_host=frontend_host,
            frontend_port=frontend_port,
            routing_path=routing_path,
            timeout_s=timeout_s,
            maa_issuer=maa_issuer,
        )
        self.backends = backends
        self.data_path = data_path
        self.timeout_s = float(timeout_s)
        self.jwks_cache = jwks_cache
        self.helper = helper_pool
        self.amortize_control = amortize_control

        self._rr = itertools.cycle(range(len(backends))) if backends else None
        self._rr_lock = threading.Lock()
        self._frontend_fp = None
        if amortize_control:
            # Validate the frontend once AND fetch the in-service pool from it
            # (real routing data), then fan out across that pool. Cache the cert
            # fingerprint so the data-connection binding check still holds.
            self._frontend_fp, pool = self.client.attest_frontend(
                self.jwks_cache, want_pool=True)
            if pool:
                self.backends = pool
                self._rr = itertools.cycle(range(len(pool)))
            if not self.backends:
                raise RuntimeError(
                    "ctls_redirect: frontend returned no in-service backends "
                    "and none configured as fallback")

    def _next_backend(self) -> tuple[str, int]:
        with self._rr_lock:
            if not self.backends or self._rr is None:
                raise RuntimeError("ctls_redirect: no backend available")
            return self.backends[next(self._rr)]

    def measure_one_attempt(
        self, attempt_id: int, run_id: str, is_warmup: bool = False
    ) -> AttemptResult:
        result = AttemptResult(
            protocol=self.protocol_name, mode=self.mode_name,
            run_id=run_id, attempt_id=attempt_id)
        timing: dict = {}
        breakdown: dict = {}

        # Control connection (skipped when amortized — validated once at
        # construction).
        routed = None
        if self.amortize_control:
            frontend_fp = self._frontend_fp
        else:
            frontend_fp, routed = self.client.attest_frontend(
                self.jwks_cache, timing=timing, breakdown=breakdown)
            result.jwks_cold = bool(timing.pop("_jwks_cold", False))

        # Data connection (step v, via NSS) to the routed backend; amortized we
        # fan out client-side over the frontend-provided pool.
        if routed:
            be_host, be_port = routed
        else:
            be_host, be_port = self._next_backend()
        fields = self.client.data_connect(
            self.helper, be_host, be_port, self.data_path, self.timeout_s)
        result.extra_tcp_ms = float(fields.get("tcp_ms", 0.0))
        result.extra_tls_ms = float(fields.get("tls_ms", 0.0))
        result.http_ms = float(fields.get("http_ms", 0.0))
        breakdown["dc_used"] = int(fields.get("dc", "0"))
        breakdown["backend"] = f"{be_host}:{be_port}"

        ok, reason = self.client.check_binding(fields, frontend_fp)
        if not ok:
            result.ok = False
            result.notes = reason

        result.tcp_ms = timing.get("tcp_ms", 0.0)
        result.tls_ms = timing.get("tls_ms", 0.0)
        result.attest_ms = timing.get("attest_ms", 0.0)
        # extra_tcp_ms/extra_tls_ms (data-conn DC handshake) already set from the
        # helper; http_ms is the trailing GET, excluded from establishment.
        result.total_e2e_ms = result.establishment_ms()
        result.breakdown = breakdown
        return result


def _parse_backends(cfg) -> list[tuple[str, int]]:
    """Accept either a single backend_host/port or a backends list."""
    out = []
    if cfg.get("backends"):
        for b in cfg["backends"]:
            if isinstance(b, str) and ":" in b:
                h, p = b.rsplit(":", 1)
                out.append((h, int(p)))
            elif isinstance(b, dict):
                out.append((b["host"], int(b["port"])))
    if not out and cfg.get("backend_host"):
        out.append((cfg["backend_host"], int(cfg.get("backend_port", 8443))))
    return out


def build_client(env, runs, *, jwks_cache, cache_policy):
    cfg = env["protocols"]["ctls_redirect"]
    helper_bin = cfg.get("nss_helper_bin")
    nss_db = cfg.get("nss_db")
    if not helper_bin or not Path(helper_bin).exists():
        raise RuntimeError(
            f"ctls_redirect needs a built nss_dc_helper; set "
            f"protocols.ctls_redirect.nss_helper_bin (got {helper_bin!r})")
    if not nss_db or not Path(nss_db).exists():
        raise RuntimeError(
            f"ctls_redirect needs an NSS trust DB with the deployment CA; "
            f"set protocols.ctls_redirect.nss_db (got {nss_db!r})")
    # Optional fallback only; the frontend's /route is authoritative for which
    # backend(s) the client connects to.
    backends = _parse_backends(cfg)
    pool_size = int(cfg.get("helper_pool_size",
                            runs.get("scale", {}).get("max_workers", 16)))
    # JANUS_AMORTIZE_CONTROL=1 overrides it for a run: the throughput run (eval/ae/run_fig6.sh, Fig. 6)
    # establishes the control connection once per client and amortizes it over the pool, as the shipped
    # Fig. 6 data was measured (no per-request control phases); the latency series (Table 2) pays the control leg on every attempt.
    amortize = bool(cfg.get("amortize_control", False)) if not os.environ.get("JANUS_AMORTIZE_CONTROL") else os.environ["JANUS_AMORTIZE_CONTROL"] == "1"
    helper_pool = _NssHelperPool(helper_bin, nss_db, pool_size)
    return CtlsRedirectClient(
        frontend_host=cfg["frontend_host"],
        frontend_port=cfg["frontend_port"],
        backends=backends,
        routing_path=cfg.get("routing_path", "/route"),
        data_path=env["payload"].get("backend_path", "/health"),
        timeout_s=runs.get("http_timeout_s", 30),
        maa_issuer=env["maa"]["url"],
        jwks_cache=jwks_cache,
        helper_pool=helper_pool,
        amortize_control=amortize,
    )
