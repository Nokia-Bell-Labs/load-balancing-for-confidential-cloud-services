# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

"""
HTTPA/2 baseline server.

Represents the post-handshake-attestation pattern used by Weinhold et al.
(USENIX ATC 2025) to model HTTPA/2 in their comparison. This is *not* a
full HTTPA/2 implementation — it captures only the latency-relevant property:
one extra round trip after the TLS handshake to exchange a fresh attestation
report bound to a client-supplied nonce.

After the TLS 1.3 handshake, the wire protocol is:

    POST /attest HTTP/1.1
    Content-Length: 32                ← raw 32-byte client nonce in body

    HTTP/1.1 200 OK
    Content-Length: ...
    Content-Type: application/octet-stream

    <body> = report_len:4 BE | report | vcek_len:4 BE | vcek_der

`report` is an SEV-SNP attestation report with REPORT_DATA bound to the
nonce. `vcek` is the matching VCEK in DER, included so the client verifies
the report's signature chain locally without an extra round trip to AMD's
KDS.

Run:
    python3 server.py --port 5443 --cert cert.pem --key key.pem
"""

import argparse
import hashlib
import logging
import os
import secrets
import struct
import subprocess
import sys
import tempfile
import threading
import time

from flask import Flask, Response, request
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

# Allow `from janus.common.snp_attestation import …` regardless of CWD.
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))  # parent of baselines/
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

NONCE_LEN = 32

# None: detect the EPYC generation from /proc/cpuinfo (Milan vs Genoa), so the fetched
# ASK/ARK matches the VCEK; SNP_PROCESSOR overrides it.
SNP_PROCESSOR = os.environ.get("SNP_PROCESSOR") or None

# When set (e.g. for local dry-runs without an SNP CVM), return a stub bundle
# instead of invoking the real attestation pipeline.
MOCK_ATTEST = os.environ.get("HTTPA_MOCK_ATTEST") == "1"

app = Flask(__name__)
log = logging.getLogger("httpa")

# ── Optional per-request backend-work cap (scalability microbenchmark) ────────
# For the equal-setting scale-out figure every protocol's backend must do the
# SAME representative work (CTLS_SERVICE_MS at CTLS_MAX_INFLIGHT concurrency) on
# top of its own attestation cost.  HTTPA pays a fresh vTPM quote per /attest;
# this models the identical downstream service the \sys{} backends perform, so
# the single-server HTTPA point is measured under the same backend cap as a
# \sys{} backend.  No-op when CTLS_SERVICE_MS is unset (normal HTTPA behaviour).
_CAP_SVC_S = float(os.environ.get("CTLS_SERVICE_MS", "0") or "0") / 1000.0
_CAP_INFLIGHT = int(os.environ.get("CTLS_MAX_INFLIGHT", "0") or "0")
_CAP_SEM = threading.Semaphore(_CAP_INFLIGHT) if _CAP_INFLIGHT > 0 else None


def _cap_backend_work() -> bool:
    """Serialise + delay to model the shared per-request backend cost.
    Returns False (→ 503) if the in-flight slot can't be acquired in time."""
    if _CAP_SVC_S <= 0:
        return True
    if _CAP_SEM is not None and not _CAP_SEM.acquire(timeout=max(_CAP_SVC_S, 0.001)):
        return False
    try:
        time.sleep(_CAP_SVC_S)
    finally:
        if _CAP_SEM is not None:
            _CAP_SEM.release()
    return True

# Cached AMD cert chain for this VM lifetime (filled lazily on first /attest).
_VCEK_CHAIN_CACHE: bytes = None

# ── HTTPA nested (second) encrypted channel ──────────────────────────────────
# Real HTTPA/2 nests an attested secure session *inside* TLS, so application
# payload is encrypted twice (inner AES-GCM + outer TLS). Weinhold et al. (Fig 6)
# attribute HTTPA's lower channel throughput to exactly this double encryption.
# We model it faithfully: after /attest the peers share a 32-byte inner secret,
# derive an inner AES-GCM key, and frame all payload into authenticated records
# (like a TLS record layer) on top of the outer TLS connection.
_INNER_RECORD = 16384  # 16 KiB inner-channel records


def _inner_key(inner_secret: bytes, nonce: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=nonce,
                info=b"httpa-inner-channel").derive(inner_secret)


def _seal_records(key: bytes, data_iter):
    """Yield AES-GCM records [4-byte ct-len | ct] over chunks of `data_iter`.
    Per-record 12-byte counter nonce; this is the inner channel's wire format."""
    aes = AESGCM(key)
    ctr = 0
    for chunk in data_iter:
        ct = aes.encrypt(ctr.to_bytes(12, "big"), chunk, None)
        yield len(ct).to_bytes(4, "big") + ct
        ctr += 1


def _run(cmd: list[str]) -> None:
    subprocess.run(cmd, check=True, capture_output=True)


def _generate_attestation(nonce: bytes) -> bytes:
    """Build an SEV-SNP evidence bundle for the client to verify.

    The bundle (raw bytes from janus.common.snp_attestation.build_snp_evidence_bundle)
    contains:
      - HCL report from NV 0x01400001 (AMD-signed SNP report + boot runtime data)
      - VCEK + ASK + ARK PEM chain (cached after first call; per-VM stable)
      - TPM2 quote with qualifyingData = SHA256(nonce) (per-connection freshness)

    Verifier-side (client): POST (SnpReport, VcekCertChain) extracted from the
    HCL report to Azure MAA /attest/SevSnpVm; the JWT MAA returns is cross-
    checked against the local TPM2-quote signature for nonce binding.

    Mock mode (HTTPA_MOCK_ATTEST=1) returns a stub bundle with REPORT_DATA
    spliced at offset 0x50 of a fake SNP report so the wire-format infrastructure can
    be exercised on a non-CVM host without snpguest/tpm2-tools.
    """
    if MOCK_ATTEST:
        rd = hashlib.sha256(nonce).digest()
        snp = bytearray(0x4a0)
        snp[0x50:0x50 + len(rd)] = rd
        hcl = b"HCLA" + b"\x00" * 28 + bytes(snp) + b"\x00" * 1384
        return (struct.pack(">I", len(hcl)) + hcl
              + struct.pack(">I", len(b"MOCK-VCEK")) + b"MOCK-VCEK"
              + struct.pack(">I", 0) + struct.pack(">I", 0))

    global _VCEK_CHAIN_CACHE
    from janus.common.snp_attestation import build_snp_evidence_bundle, parse_snp_evidence_bundle
    bundle = build_snp_evidence_bundle(nonce=nonce,
                                        vcek_chain_cache=_VCEK_CHAIN_CACHE,
                                        processor=SNP_PROCESSOR)
    if _VCEK_CHAIN_CACHE is None:
        _VCEK_CHAIN_CACHE = parse_snp_evidence_bundle(bundle).pem_chain
    return bundle


@app.route("/", methods=["GET"])
def index():
    return "ok\n"


# Reverse-proxy to a backend application (e.g. the hotelReservation frontend)
# so HTTPA/2 can front a real application for the application benchmarks.
# Set HOTEL_URL=http://<host>:<port> to enable.
import os as _os
_HOTEL_URL = _os.environ.get("HOTEL_URL", "")
# Front a streaming LLM endpoint for the LLM-inference benchmark.
# Set LLM_URL=http://<host>:<port> to enable.
_LLM_URL = _os.environ.get("LLM_URL", "")


@app.route("/reservation", methods=["GET"])
def reservation():
    import requests as _rq
    from flask import request as _req
    if not _HOTEL_URL:
        return Response("HOTEL_URL not set", status=503)
    r = _rq.get(f"{_HOTEL_URL}/reservation", params=_req.args, timeout=15)
    return Response(r.content, status=r.status_code,
                    content_type=r.headers.get("content-type", "application/json"))


@app.route("/generate", methods=["GET", "POST"])
def generate():
    # Forward to the LLM server's /generate. With max_tokens=1 the response is
    # a single token, so this non-streaming forward returns ~at first token and
    # the client's total time ≈ TTFT (the metric we report).
    import requests as _rq
    from flask import request as _req
    if not _LLM_URL:
        return Response("LLM_URL not set", status=503)
    j = _req.get_json(silent=True) or {}
    prompt = _req.args.get("prompt", j.get("prompt", ""))
    max_tokens = int(_req.args.get("max_tokens", j.get("max_tokens", 1)))
    r = _rq.post(f"{_LLM_URL}/generate",
                 json={"prompt": prompt, "max_tokens": max_tokens}, timeout=300)
    return Response(r.content, status=r.status_code,
                    content_type="text/event-stream")


@app.route("/attest", methods=["GET", "POST"])
def attest():
    import time as _t
    # Nonce via POST body, or (for keep-alive friendliness with a following
    # application GET) via the X-Nonce hex header on a GET.  Either way it is
    # one post-handshake attestation round trip.
    if request.method == "GET":
        hx = request.headers.get("X-Nonce", "")
        try:
            nonce = bytes.fromhex(hx)
        except ValueError:
            nonce = b""
    else:
        nonce = request.get_data()
    if len(nonce) != NONCE_LEN:
        return Response(f"expected {NONCE_LEN}-byte nonce, got {len(nonce)}",
                        status=400)

    t0 = _t.monotonic()
    try:
        bundle = _generate_attestation(nonce)
    except subprocess.CalledProcessError as e:
        log.error("snp_attestation failed: %s",
                  e.stderr.decode("utf-8", "replace") if e.stderr else "")
        return Response("attestation failed", status=500)
    except FileNotFoundError as e:
        return Response(f"missing tool: {e}", status=500)
    except Exception as e:
        log.error("evidence build error: %s", e)
        return Response(f"attestation error: {e}", status=500)
    gen_ms = (_t.monotonic() - t0) * 1000.0
    log.info(f"/attest bundle generated in {gen_ms:.2f} ms ({len(bundle)} B)")

    # Equal-setting backend work (no-op unless CTLS_SERVICE_MS is set): the same
    # representative request cost a \sys{} backend serves, stacked on the quote.
    if not _cap_backend_work():
        return Response("backend overloaded", status=503)

    # Surface server-side bundle generation time so the client can decompose
    # bundle_ms (= server gen + RTT) into "server work" vs "network".
    # Also mint the inner-channel secret: HTTPA establishes a nested encrypted
    # session after attestation, so all subsequent payload is double-encrypted.
    # The secret is confidential under the outer TLS; the client carries it back
    # on data requests (X-Inner-Secret) so the channel is stateless server-side.
    inner_secret = secrets.token_bytes(32)
    return Response(bundle, mimetype="application/octet-stream",
                    headers={"X-Server-Gen-Ms": f"{gen_ms:.3f}",
                             "X-Inner-Secret": inner_secret.hex()})


@app.route("/bulk", methods=["GET"])
def bulk():
    """Stream ``n`` bytes of payload, for the channel-throughput experiment.
    With X-Inner-Secret + X-Nonce present (HTTPA's nested channel) the payload
    is framed and AES-GCM-encrypted on the inner key, i.e. double-encrypted on
    top of TLS; without them (vanilla / RA+TLS / \\sys{}, single TLS channel)
    it is sent in the clear over TLS. Run client+server co-located (loopback)
    so the measurement is crypto-bound, not network-bound (per Weinhold Fig 6)."""
    n = int(request.args.get("n", 1 << 20))
    inner = request.headers.get("X-Inner-Secret", "")
    nonce_hex = request.headers.get("X-Nonce", "")

    def chunks():
        sent = 0
        buf = b"\x00" * _INNER_RECORD
        while sent < n:
            m = min(_INNER_RECORD, n - sent)
            yield buf[:m]
            sent += m

    if inner and nonce_hex:  # HTTPA nested channel: inner AES-GCM layer
        key = _inner_key(bytes.fromhex(inner), bytes.fromhex(nonce_hex))
        body = _seal_records(key, chunks())
        return Response(body, mimetype="application/octet-stream",
                        headers={"X-Nested": "1"})
    return Response(chunks(), mimetype="application/octet-stream")  # single channel


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--port", type=int, default=5443)
    p.add_argument("--bind", default="0.0.0.0")
    p.add_argument("--cert", required=True, help="PEM certificate")
    p.add_argument("--key", required=True, help="PEM private key")
    args = p.parse_args()

    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    log.info("HTTPA/2 baseline server on %s:%d (mock=%s)",
             args.bind, args.port, MOCK_ATTEST)

    if not (os.path.exists(args.cert) and os.path.exists(args.key)):
        log.error("cert/key not found — run `make cert` first")
        sys.exit(1)

    # TCP_NODELAY needs to be set BEFORE the TLS handshake — Werkzeug's
    # disable_nagle_algorithm flag only takes effect in WSGIRequestHandler.setup(),
    # which runs after SSL wrap. We patch server_bind so the listening socket
    # has TCP_NODELAY, which Linux inherits onto every accept()'d socket. The
    # post-handshake flag stays as belt-and-braces.
    import socket as _socket
    from werkzeug.serving import BaseWSGIServer, WSGIRequestHandler
    _orig_bind = BaseWSGIServer.server_bind
    def _bind_nodelay(self):
        _orig_bind(self)
        self.socket.setsockopt(_socket.IPPROTO_TCP, _socket.TCP_NODELAY, 1)
    BaseWSGIServer.server_bind = _bind_nodelay
    WSGIRequestHandler.disable_nagle_algorithm = True
    # HTTP/1.1 so keep-alive persists across the post-handshake /attest
    # exchange and the subsequent application GET on the SAME TLS
    # connection — this is the channel-reuse model HTTPA/2 actually uses,
    # and it keeps the bench's "to first byte of a GET" end-to-end
    # definition uniform with the other protocols.
    WSGIRequestHandler.protocol_version = "HTTP/1.1"

    # threaded=True: a real attested-TLS server handles concurrent connections,
    # and Janus (threaded frontend, multi-backend pool) is measured with its
    # natural concurrency -- so the baselines must be too, for an apples-to-apples
    # THROUGHPUT comparison. Single-threading artificially caps both baselines
    # below the hardware's concurrent quote-gen rate (~16 req/s vs ~10 serial).
    app.run(host=args.bind, port=args.port,
            ssl_context=(args.cert, args.key),
            threaded=True, load_dotenv=False)


if __name__ == "__main__":
    main()
