# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

"""Per-protocol measurement clients.

Each protocol module (vanilla.py, ctls_proxy.py, ctls_redirect.py, ratls.py,
httpa.py) exposes a single entry point::

    def build_client(env: dict, runs: dict, *, jwks_cache, cache_policy) -> Client

where Client implements::

    def measure_one_attempt(self, attempt_id: int, run_id: str,
                            is_warmup: bool = False) -> AttemptResult

The runner is protocol-agnostic; per-protocol logic lives only in these
modules.
"""
