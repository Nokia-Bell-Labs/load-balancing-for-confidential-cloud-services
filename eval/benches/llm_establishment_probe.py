#!/usr/bin/env python3
# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

"""Measure per-connection establishment-to-verified-channel (p50/p95/p99) for
the LLM fronts, hitting a trivial /healthz (no inference) so it's fast. Emits
CSV lines `protocol,p50_ms,p95_ms,p99_ms`. The Janus/vanilla protocols run under
system python3; RA+TLS must run under the python-ratls interpreter.
"""
import argparse, json, socket, ssl, subprocess, time, sys


def pct(xs, p):
    s = sorted(xs); k = (len(s)-1)*p/100; f = int(k); c = min(f+1, len(s)-1)
    return s[f] if f == c else s[f]+(s[c]-s[f])*(k-f)


def tls_get_healthz(host, port, timeout=30):
    ctx = ssl.create_default_context(); ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE; ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    t0 = time.perf_counter()
    s = socket.create_connection((host, port), timeout=timeout)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    ss = ctx.wrap_socket(s, server_hostname="localhost")
    ss.sendall((f"GET /healthz HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").encode())
    ss.recv(256); dt = (time.perf_counter()-t0)*1000; ss.close()
    return dt


def helper_est(helper, db, host, port, n, warmup):
    p = subprocess.Popen([helper, db], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         stderr=subprocess.DEVNULL, text=True, bufsize=1)
    out = []
    try:
        for i in range(n+warmup):
            p.stdin.write(f"{host} {port} /healthz\n"); p.stdin.flush()
            r = p.stdout.readline().strip()
            if r.startswith("OK "):
                f = {k: v for k, v in (t.split("=", 1) for t in r[3:].split() if "=" in t)}
                if i >= warmup and f.get("status") == "200":
                    out.append(float(f["tcp_ms"]) + float(f["tls_ms"]))
    finally:
        try: p.stdin.write("QUIT\n"); p.stdin.flush(); p.wait(3)
        except Exception: p.kill()
    return out


def httpa_est(host, port, n, warmup):
    import os
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
    from janus.common.snp_attestation import verify_snp_bundle
    maa = os.environ.get("MAA_URL", "https://sharedweu.weu.attest.azure.net")
    ctx = ssl.create_default_context(); ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE; ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    out = []
    for i in range(n+warmup):
        t0 = time.perf_counter()
        s = socket.create_connection((host, port), timeout=60)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        ss = ctx.wrap_socket(s, server_hostname=host); nonce = os.urandom(32)
        ss.sendall((f"GET /attest HTTP/1.1\r\nHost: {host}\r\nX-Nonce: {nonce.hex()}\r\n"
                    f"Connection: close\r\n\r\n").encode())
        hdr = b""
        while b"\r\n\r\n" not in hdr: hdr += ss.recv(4096)
        head, _, rest = hdr.partition(b"\r\n\r\n")
        cl = int([l.split(b":", 1)[1] for l in head.split(b"\r\n")
                  if l.lower().startswith(b"content-length")][0])
        while len(rest) < cl: rest += ss.recv(8192)
        ss.close(); ok, _ = verify_snp_bundle(rest, expected_nonce=nonce, maa_url=maa)
        if i >= warmup and ok: out.append((time.perf_counter()-t0)*1000)
    return out


def ratls_est(url, n, warmup):
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "baselines"))   # the ratls package lives in baselines/ratls
    import logging; logging.disable(logging.CRITICAL)
    from ratls.client import RATLSHTTPClient
    out = []
    for i in range(n+warmup):
        t0 = time.perf_counter()
        try:
            RATLSHTTPClient(server_url=url, verify_quote=True, ca_cert_path=None).fetch_page("/healthz")
            if i >= warmup: out.append((time.perf_counter()-t0)*1000)
        except Exception:
            pass
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--backend", default="janus-be.local")
    ap.add_argument("--frontend", default="janus-fe.local")
    ap.add_argument("--httpa-host", default="janus-be.local")
    ap.add_argument("--ratls-url", default="https://janus-be.local:5004")
    ap.add_argument("--nss-helper", default=os.path.expanduser("~/nss_client/nss_dc_helper"))
    ap.add_argument("--nss-db", default=os.path.expanduser("~/nss_client/nssdb"))
    ap.add_argument("--n", type=int, default=20)
    ap.add_argument("--warmup", type=int, default=5)
    ap.add_argument("--only", default="")
    a = ap.parse_args()
    sel = set(a.only.split(",")) if a.only else {"vanilla", "redirect", "proxy", "httpa", "ratls"}

    def emit(name, xs):
        if xs:
            print(f"{name},{pct(xs,50):.1f},{pct(xs,95):.1f},{pct(xs,99):.1f}")

    if "vanilla" in sel:
        xs = [tls_get_healthz(a.backend, 8444) for i in range(a.n+a.warmup)][a.warmup:]
        emit("vanilla", xs)
    if "redirect" in sel:
        emit("ctls_redirect", helper_est(a.nss_helper, a.nss_db, a.backend, 8443, a.n, a.warmup))
    if "proxy" in sel:
        emit("ctls_proxy", helper_est(a.nss_helper, a.nss_db, a.frontend, 5043, a.n, a.warmup))
    if "httpa" in sel:
        emit("httpa", httpa_est(a.httpa_host, 5002, a.n, a.warmup))
    if "ratls" in sel:
        emit("ratls", ratls_est(a.ratls_url, a.n, a.warmup))


if __name__ == "__main__":
    main()
