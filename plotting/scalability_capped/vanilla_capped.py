#!/usr/bin/env python3
# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

"""Standalone capped vanilla-TLS server for the equal-setting scale-out
microbenchmark (fig:scale-backends N=1 baseline dot).

No attestation — the TLS floor baseline.  Serves a capped /health that performs
the SAME representative backend work (CTLS_SERVICE_MS at CTLS_MAX_INFLIGHT
concurrency) a Janus backend serves, so the single-server vanilla point is
measured under the identical backend cap as a Janus backend.  TLS 1.3,
self-signed cert.  Standalone (no frontend registration / pool pollution).

  usage: vanilla_capped.py <host> <port> <cert.pem> <key.pem>
  env:   CTLS_SERVICE_MS=100 CTLS_MAX_INFLIGHT=1   (c=10 req/s)
"""
import os
import ssl
import sys
import threading
import time

from flask import Flask

_SVC_S = float(os.environ.get("CTLS_SERVICE_MS", "0") or "0") / 1000.0
_INFLIGHT = int(os.environ.get("CTLS_MAX_INFLIGHT", "0") or "0")
_SEM = threading.Semaphore(_INFLIGHT) if _INFLIGHT > 0 else None

app = Flask(__name__)


def _cap() -> bool:
    if _SVC_S <= 0:
        return True
    if _SEM is not None and not _SEM.acquire(timeout=max(_SVC_S, 0.001)):
        return False
    try:
        time.sleep(_SVC_S)
    finally:
        if _SEM is not None:
            _SEM.release()
    return True


@app.route("/health")
def health():
    if not _cap():
        return "overloaded", 503
    return "ok\n", 200


if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else "0.0.0.0"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 8444
    cert, key = sys.argv[3], sys.argv[4]
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(cert, key)
    app.run(host=host, port=port, threaded=True, ssl_context=ctx,
            load_dotenv=False)
