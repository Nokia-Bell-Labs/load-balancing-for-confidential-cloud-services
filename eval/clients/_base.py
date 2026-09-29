# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

"""Shared measurement primitives for the evaluation infrastructure.

All protocol clients return an :class:`AttemptResult` from a single
``measure_one_attempt`` call.  The runner is responsible for serializing
those results to the uniform CSV schema described in the README; protocol
modules never write CSVs directly.

End-to-end semantics
--------------------
``total_e2e_ms`` is the wall-clock from the start of a fresh attempt to the
first byte of the HTTP response.  It includes:

* TCP connect(s)
* All TLS handshakes the protocol requires (one for vanilla / proxy /
  RA+TLS / HTTPA; two for cTLS redirection)
* Attestation verification work, including any AS round trip incurred
* HTTP GET request and first-byte arrival

Per-phase fields (``tcp_ms``, ``tls_ms``, ``attest_ms``, ``extra_tcp_ms``,
``extra_tls_ms``, ``http_ms``) sum to ``total_e2e_ms`` within timing noise.

Timer choice
------------
We use :func:`time.perf_counter` for all phase deltas and the end-to-end
total: it is monotonic and the highest-resolution timer available, with no
NTP/clock-skew exposure.  The epoch is unspecified but irrelevant for
differences.
"""

from __future__ import annotations

import json
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

CSV_SCHEMA_VERSION = 1

MAIN_FIELDS = [
    "timestamp_iso",
    "schema_version",
    "protocol",
    "mode",
    "run_id",
    "attempt_id",
    "tcp_ms",
    "tls_ms",
    "attest_ms",
    "extra_tcp_ms",
    "extra_tls_ms",
    "http_ms",
    "total_e2e_ms",
    "jwks_cold",
    "ok",
    "notes",
]


@dataclass
class AttemptResult:
    """A single measurement attempt.

    The fields in ``MAIN_FIELDS`` go into the primary CSV; the optional
    ``breakdown`` dict goes into a sibling ``*_breakdown.csv`` keyed by
    ``(run_id, attempt_id)``.  Protocol-specific fields belong only in
    ``breakdown`` so the primary schema stays cross-protocol uniform.
    """

    protocol: str
    mode: str
    run_id: str
    attempt_id: int
    tcp_ms: float = 0.0
    tls_ms: float = 0.0
    attest_ms: float = 0.0
    extra_tcp_ms: float = 0.0
    extra_tls_ms: float = 0.0
    http_ms: float = 0.0
    total_e2e_ms: float = 0.0
    jwks_cold: bool = False
    ok: bool = True
    notes: str = ""
    breakdown: dict[str, Any] = field(default_factory=dict)
    timestamp_iso: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_main_row(self) -> dict[str, Any]:
        return {
            "timestamp_iso": self.timestamp_iso,
            "schema_version": CSV_SCHEMA_VERSION,
            "protocol": self.protocol,
            "mode": self.mode,
            "run_id": self.run_id,
            "attempt_id": self.attempt_id,
            "tcp_ms": _round(self.tcp_ms),
            "tls_ms": _round(self.tls_ms),
            "attest_ms": _round(self.attest_ms),
            "extra_tcp_ms": _round(self.extra_tcp_ms),
            "extra_tls_ms": _round(self.extra_tls_ms),
            "http_ms": _round(self.http_ms),
            "total_e2e_ms": _round(self.total_e2e_ms),
            "jwks_cold": int(self.jwks_cold),
            "ok": int(self.ok),
            "notes": self.notes,
        }

    def to_breakdown_row(self) -> dict[str, Any] | None:
        if not self.breakdown:
            return None
        row: dict[str, Any] = {
            "timestamp_iso": self.timestamp_iso,
            "protocol": self.protocol,
            "mode": self.mode,
            "run_id": self.run_id,
            "attempt_id": self.attempt_id,
        }
        for k, v in self.breakdown.items():
            row[k] = _round(v) if isinstance(v, float) else v
        return row

    def phase_sum_ms(self) -> float:
        """Sum of all per-phase fields.  Should equal total_e2e_ms within noise."""
        return (
            self.tcp_ms
            + self.tls_ms
            + self.attest_ms
            + self.extra_tcp_ms
            + self.extra_tls_ms
            + self.http_ms
        )

    def establishment_ms(self) -> float:
        """Connection-establishment latency: time to a verified-TEE channel
        ready for application data, EXCLUDING the trailing application GET.

        This is the cross-protocol-comparable metric (matches the
        "handshake latency" of the RA+TLS ATC'25 paper).  Measuring to a
        uniform end-state is what makes the round-trip structure faithful:
        e.g. HTTPA's post-handshake /attest round trip is counted while
        RA+TLS's in-handshake attestation is not double-charged, and no
        protocol is unfairly credited/charged a trailing data GET.
        """
        return (
            self.tcp_ms
            + self.tls_ms
            + self.attest_ms
            + self.extra_tcp_ms
            + self.extra_tls_ms
        )


def _round(x: float) -> float:
    return round(x, 4)


@contextmanager
def phase(target: dict[str, float], key: str) -> Iterator[None]:
    """Time a block and accumulate the elapsed ms into ``target[key]``.

    Accumulation (rather than assignment) lets a protocol charge multiple
    code regions to the same logical phase — useful when a handshake
    helper is invoked twice in one attempt.
    """
    t0 = time.perf_counter()
    try:
        yield
    finally:
        target[key] = target.get(key, 0.0) + (time.perf_counter() - t0) * 1000.0


def ms_since(t0: float) -> float:
    return (time.perf_counter() - t0) * 1000.0


import os      # noqa: E402  (JwksCache reads JANUS_JWKS_MAX_AGE_S)
import time    # noqa: E402  (JwksCache TTL)


class JwksCache:
    """Disk-persistent JWKS cache keyed by ``(issuer, kid)``.

    ``warm`` policy: read/write to disk; cache survives across attempts in
        the same run.  Matches the paper's "AS verification off the
        per-connection critical path" claim.

    ``cold`` policy: every ``get`` returns ``None`` and ``put`` is a no-op,
        so every attempt incurs a JWKS RTT.  Used to characterise the
        cold-path cost separately, not to invalidate the warm path.

    Protocols call ``get`` before the AS RTT and ``put`` after fetching a
    new ``(n, e)`` pair.  The cache itself does no MAA HTTP; it is a
    storage layer only.
    """

    def __init__(self, cache_dir: Path, policy: str = "warm"):
        if policy not in ("warm", "cold"):
            raise ValueError(f"JwksCache: bad policy {policy!r}")
        self.policy = policy
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        # The scale driver shares one JwksCache across worker threads.
        # Lock guards the read-then-write path; the on-disk write itself
        # uses tmp+rename to be atomic against concurrent readers.
        self._lock = threading.Lock()
        # Design §4.4: a cached AS signing key is refreshed when the AS's
        # key-rotation window lapses.  Production ASes rotate rarely (paper
        # §6), so the default window is generous; JANUS_JWKS_MAX_AGE_S
        # overrides it.  Failure-driven refresh is handled by the callers
        # (force_refresh in attest.get_maa_public_key).
        self.max_age_s = float(os.environ.get("JANUS_JWKS_MAX_AGE_S", str(30 * 24 * 3600)))

    def _path(self, issuer: str, kid: str) -> Path:
        safe_issuer = issuer.replace("/", "_").replace(":", "_")
        safe_kid = kid.replace("/", "_").replace(":", "_")
        return self.cache_dir / f"{safe_issuer}__{safe_kid}.json"

    def get(self, issuer: str, kid: str) -> dict[str, Any] | None:
        if self.policy == "cold":
            return None
        p = self._path(issuer, kid)
        with self._lock:
            if not p.exists():
                return None
            try:
                if time.time() - p.stat().st_mtime > self.max_age_s:
                    # Rotation window lapsed: treat as a miss so the caller
                    # re-fetches the current key set (design §4.4).
                    p.unlink(missing_ok=True)
                    return None
                return json.loads(p.read_text())
            except Exception:
                # Treat a corrupt cache file as a miss; the caller will
                # re-fetch and atomically rewrite it.
                return None

    def evict(self, issuer: str, kid: str) -> None:
        """Drop a cached key (used after a verification failure)."""
        with self._lock:
            self._path(issuer, kid).unlink(missing_ok=True)

    def put(self, issuer: str, kid: str, entry: dict[str, Any]) -> None:
        if self.policy == "cold":
            return
        p = self._path(issuer, kid)
        data = json.dumps(entry)
        tmp = p.with_suffix(p.suffix + ".tmp")
        with self._lock:
            tmp.write_text(data)
            tmp.replace(p)  # atomic on POSIX
