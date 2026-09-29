# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

"""
HTTPA/2 baseline client.

Connects to an HTTPA/2 baseline server over TLS 1.3, then performs the
post-handshake attestation exchange:

    1. Generate a fresh 32-byte nonce.
    2. POST it to /attest.
    3. Receive (report, vcek), verify via snpguest, check REPORT_DATA == nonce.

Reports the per-phase timings:

    tls_handshake_ms — SSL_connect equivalent
    attest_ms        — post-handshake exchange + verification
    total_ms         — sum

Run:
    python3 client.py --host <cvm-ip> --port 5443 --insecure

For benchmark loops:
    python3 client.py --runs 100 --warmup 2 --insecure
"""

import argparse
import base64
import hashlib
import json
import logging
import os
import socket
import ssl
import statistics
import struct
import sys
import time

import requests

# Allow `from janus.common.snp_attestation import …` regardless of CWD.
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))  # parent of baselines/
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)


NONCE_LEN = 32
REPORT_DATA_OFFSET = 0x50  # offset of REPORT_DATA inside an SEV-SNP report

# Azure MAA endpoint used by cTLS and the existing RATLS baseline; using the
# same instance for all three protocols keeps the MAA round trip comparable.
MAA_URL = os.environ.get(
    "MAA_URL", "https://sharedweu.weu.attest.azure.net"
)
MAA_API_VERSION = "2022-08-01"

# When set, skip the MAA round trip and just check REPORT_DATA == SHA256(nonce)
# against the report bytes locally.  Useful for the timing infrastructure on a non-SNP
# machine against a server running with HTTPA_MOCK_ATTEST=1.
MOCK_VERIFY = os.environ.get("HTTPA_MOCK_VERIFY") == "1"

log = logging.getLogger("httpa-client")


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def _build_ssl_context(insecure: bool, ca: str | None) -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    elif ca:
        ctx.load_verify_locations(cafile=ca)
    return ctx


def _read_until_blank(sock: ssl.SSLSocket, max_hdr: int = 8192) -> tuple[bytes, bytes]:
    """Read until the end of HTTP headers; return (headers, leftover_body_bytes)."""
    buf = b""
    while b"\r\n\r\n" not in buf:
        if len(buf) >= max_hdr:
            raise RuntimeError("response headers too large")
        chunk = sock.recv(4096)
        if not chunk:
            raise RuntimeError("connection closed before headers")
        buf += chunk
    head, _, rest = buf.partition(b"\r\n\r\n")
    return head, rest


def _parse_content_length(headers: bytes) -> int:
    for line in headers.split(b"\r\n"):
        if line.lower().startswith(b"content-length:"):
            return int(line.split(b":", 1)[1].strip())
    raise RuntimeError("no Content-Length in response")


def _read_exactly(sock: ssl.SSLSocket, already: bytes, n: int) -> bytes:
    buf = bytearray(already[:n])
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise RuntimeError("connection closed before body fully read")
        buf.extend(chunk)
    return bytes(buf)


def _verify_bundle(bundle: bytes, nonce: bytes) -> None:
    """Verify the SEV-SNP evidence bundle the server produced.

    Delegates to common.snp_attestation.verify_snp_bundle, which:
      1. Splits HCL → SNP report + boot runtime claims
      2. POSTs (SnpReport, VcekCertChain) to Azure MAA /attest/SevSnpVm
      3. Receives an MAA-signed JWT, verifies signature + claims
      4. (Optional) cross-checks the local TPM2 quote against the AK pub
         from the MAA-verified runtime claims for per-connection nonce binding.

    In MOCK mode (HTTPA_MOCK_VERIFY=1) we just check that REPORT_DATA in the
    stub-server's bundle matches SHA256(nonce); no MAA round trip.
    """
    expected = hashlib.sha256(nonce).digest()

    if MOCK_VERIFY:
        # Parse the mock bundle: hcl_len:4 | hcl | chain_len:4 | chain | qm:4 | qs:4
        rlen = struct.unpack(">I", bundle[:4])[0]
        hcl = bundle[4:4 + rlen]
        # In mock mode the HCL is HCLA-header (32B) + fake SNP (1184B) + zeros
        snp = hcl[32:32 + 0x4a0]
        if snp[REPORT_DATA_OFFSET:REPORT_DATA_OFFSET + len(expected)] != expected:
            raise RuntimeError("REPORT_DATA mismatch (mock)")
        return

    from janus.common.snp_attestation import verify_snp_bundle
    ok, info = verify_snp_bundle(
        bundle, expected_nonce=nonce, maa_url=MAA_URL,
    )
    if not ok:
        raise RuntimeError(f"MAA verification failed: {info.get('error')}")


def one_run(host: str, port: int, ctx: ssl.SSLContext) -> dict:
    """Run a single TLS+attestation round and return per-phase timings (ms).

    Phase decomposition (post-handshake attestation):
      tcp_ms       — TCP connect (kernel)
      tls_ms       — TLS 1.3 handshake (ClientHello → Finished)
      bundle_ms    — POST nonce + receive evidence bundle
                     (≈ server-side bundle generation + network RTT)
      maa_ms       — client-side verification (MAA POST + JWT verify)
      total_ms     — sum of all phases above
    """
    t0 = time.monotonic()
    raw = socket.create_connection((host, port))
    raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    t1 = time.monotonic()

    ssock = ctx.wrap_socket(raw, server_hostname=host)
    t2 = time.monotonic()

    nonce = os.urandom(NONCE_LEN)
    req = (
        f"POST /attest HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Length: {NONCE_LEN}\r\n"
        f"Content-Type: application/octet-stream\r\n\r\n"
    ).encode() + nonce
    ssock.sendall(req)

    headers, leftover = _read_until_blank(ssock)
    status_line = headers.split(b"\r\n", 1)[0]
    if b" 200 " not in status_line and not status_line.endswith(b" 200"):
        raise RuntimeError(f"server returned: {status_line.decode(errors='replace')}")
    body_len = _parse_content_length(headers)
    bundle = _read_exactly(ssock, leftover, body_len)
    t3 = time.monotonic()

    # Server-reported bundle-generation time (header set by httpa/server.py)
    server_gen_ms = None
    for line in headers.split(b"\r\n"):
        if line.lower().startswith(b"x-server-gen-ms:"):
            try:
                server_gen_ms = float(line.split(b":", 1)[1].strip())
            except ValueError:
                server_gen_ms = None
            break

    _verify_bundle(bundle, nonce)
    t4 = time.monotonic()

    try:
        ssock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    ssock.close()

    bundle_ms = (t3 - t2) * 1000
    return {
        "tcp_ms":           (t1 - t0) * 1000,
        "tls_ms":           (t2 - t1) * 1000,
        "bundle_ms":        bundle_ms,
        "server_gen_ms":    server_gen_ms,                         # server work, from header
        "network_ms":       (bundle_ms - server_gen_ms) if server_gen_ms else None,
        "maa_ms":           (t4 - t3) * 1000,
        "total_ms":         (t4 - t0) * 1000,
        "bundle_len":       len(bundle),
    }


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=5443)
    p.add_argument("--ca", help="trust this CA cert (PEM); default: system trust")
    p.add_argument("--insecure", action="store_true",
                   help="skip TLS certificate verification (testing only)")
    p.add_argument("--runs", type=int, default=1, help="number of measurement runs")
    p.add_argument("--warmup", type=int, default=0,
                   help="warmup runs to discard before measurement")
    args = p.parse_args()

    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    ctx = _build_ssl_context(args.insecure, args.ca)

    for _ in range(args.warmup):
        try:
            one_run(args.host, args.port, ctx)
        except Exception as e:
            log.warning("warmup run failed: %s", e)

    samples: list[dict] = []
    for i in range(args.runs):
        try:
            r = one_run(args.host, args.port, ctx)
        except Exception as e:
            log.error("run %d failed: %s", i, e)
            sys.exit(2)
        samples.append(r)
        if args.runs == 1:
            sg = r.get("server_gen_ms")
            nw = r.get("network_ms")
            sg_str = f"{sg:.2f}" if sg is not None else "?"
            nw_str = f"{nw:.2f}" if nw is not None else "?"
            print(f"tcp={r['tcp_ms']:.2f} tls={r['tls_ms']:.2f} "
                  f"bundle={r['bundle_ms']:.2f} "
                  f"(server_gen={sg_str} network={nw_str}) "
                  f"maa={r['maa_ms']:.2f} total={r['total_ms']:.2f} (ms) "
                  f"bundle_len={r['bundle_len']} verify=ok")

    if args.runs > 1:
        keys = ["tcp_ms", "tls_ms", "bundle_ms", "server_gen_ms",
                "network_ms", "maa_ms", "total_ms"]
        for k in keys:
            xs = [s[k] for s in samples if s.get(k) is not None]
            if not xs:
                print(f"{k}: (no data)")
                continue
            xs.sort()
            print(f"{k}: median={statistics.median(xs):.3f} "
                  f"p95={xs[int(0.95 * (len(xs) - 1))]:.3f} "
                  f"min={min(xs):.3f} max={max(xs):.3f} "
                  f"stdev={statistics.pstdev(xs):.3f} "
                  f"n={len(xs)}")


if __name__ == "__main__":
    main()
