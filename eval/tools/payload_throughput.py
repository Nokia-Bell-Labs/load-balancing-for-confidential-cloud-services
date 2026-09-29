#!/usr/bin/env python3
# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

"""Channel-throughput microbenchmark: single TLS channel vs HTTPA's nested
(double-encrypted) channel, reproducing Weinhold et al. (ATC'25) Fig 6's
methodology.

Run CO-LOCATED with the HTTPA server (loopback) so the measurement is
crypto-bound, not network-bound:

    python3 payload_throughput.py --host 127.0.0.1 --port 5002 --n $((1<<30))

  plain   GiB/s  -> vanilla TLS / RA+TLS / Janus  (all a single TLS channel)
  nested  GiB/s  = HTTPA/2  (TLS outer + inner AES-GCM = payload encrypted twice)

The gap is exactly the inner-channel double-encryption cost; it is why HTTPA's
channel throughput is below RA+TLS's (and Janus's), independent of attestation.
"""
import argparse
import secrets
import statistics
import time

import urllib3
import requests
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

urllib3.disable_warnings()


def _inner_key(secret: bytes, nonce: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=nonce,
                info=b"httpa-inner-channel").derive(secret)


def _transfer(sess, url, n, nested):
    headers, aes = {}, None
    if nested:
        s, nc = secrets.token_bytes(32), secrets.token_bytes(32)
        headers = {"X-Inner-Secret": s.hex(), "X-Nonce": nc.hex()}
        aes = AESGCM(_inner_key(s, nc))
    t0 = time.perf_counter()
    r = sess.get(url, params={"n": n}, headers=headers, stream=True,
                 verify=False, timeout=600)
    total = 0
    if nested:                       # parse [4B len | ct] records, decrypt each
        buf, ctr = b"", 0
        for chunk in r.iter_content(65536):
            buf += chunk
            while len(buf) >= 4:
                clen = int.from_bytes(buf[:4], "big")
                if len(buf) < 4 + clen:
                    break
                pt = aes.decrypt(ctr.to_bytes(12, "big"), buf[4:4 + clen], None)
                buf = buf[4 + clen:]
                ctr += 1
                total += len(pt)
    else:
        for chunk in r.iter_content(65536):
            total += len(chunk)
    return total, time.perf_counter() - t0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=5002)
    ap.add_argument("--n", type=int, default=1 << 30, help="payload bytes")
    ap.add_argument("--runs", type=int, default=5)
    args = ap.parse_args()
    url = f"https://{args.host}:{args.port}/bulk"
    sess = requests.Session()
    print(f"payload={args.n >> 20} MiB, {args.runs} runs (+1 warmup), {url}")
    for mode in ("plain", "nested"):
        rates = []
        for i in range(args.runs + 1):
            total, dt = _transfer(sess, url, args.n, mode == "nested")
            assert total == args.n, f"{mode}: got {total} of {args.n} bytes"
            if i > 0:
                rates.append(total / dt / (1 << 30))
        print("  %-7s %.3f GiB/s  (median; min %.3f max %.3f)" % (
            mode, statistics.median(rates), min(rates), max(rates)))


if __name__ == "__main__":
    main()
