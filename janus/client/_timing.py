# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

"""Minimal phase timer for the reference client — records per-step latency into
a caller-provided dict. Stdlib only, so the client carries no eval dependency.
"""
from __future__ import annotations

import time
from contextlib import contextmanager


@contextmanager
def phase(target: dict, key: str):
    """Time the block and accumulate the elapsed milliseconds into target[key]."""
    t0 = time.perf_counter()
    try:
        yield
    finally:
        target[key] = target.get(key, 0.0) + (time.perf_counter() - t0) * 1000.0
