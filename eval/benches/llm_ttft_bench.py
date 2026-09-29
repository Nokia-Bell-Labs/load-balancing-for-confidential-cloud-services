#!/usr/bin/env python3
# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

"""LLM inference benchmark: time-to-first-token (TTFT) of Llama-3.1-8B served
behind cTLS vs vanilla TLS.

TTFT = wall-clock from connection start to the first streamed token, the
paper's primary LLM metric. Both fronts relay to the SAME model server
(127.0.0.1:8000) on the backend CVM, so the model's first-token compute is
identical and the delta is purely the protocol's establishment cost.

  vanilla       : plain TLS-1.3 streaming client -> dc_proxy(--x509) :8444 -> :8000
  cTLS redirect : NSS Delegated-Credential client -> dc_proxy(DC)    :8443 -> :8000
                  (nss_dc_helper: POST /generate, reports ttft_ms over the DC path)

Requests use max_tokens=1 so each call returns right after the first token.

Usage (on the load-gen client):
  python3 llm_ttft_bench.py --backend janus-be.local --prompts ~/llm_prompts.json \
      --nss-helper /home/janus/nss_client/nss_dc_helper --nss-db /home/janus/nss_client/nssdb
"""
import argparse, json, os, socket, ssl, subprocess, time, statistics, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from janus.client import attest as _attest                       # noqa: E402
from clients._base import JwksCache               # noqa: E402
from cryptography import x509                     # noqa: E402
from cryptography.hazmat.backends import default_backend  # noqa: E402


def _control_leg(fe_host, fe_port, maa_url, jc):
    """Cold redirect leg 1 (same as microservice_bench): TLS to the frontend,
    validate cert JWT (cached AS key) + REPORTDATA, one routing GET."""
    ctx = ssl.create_default_context(); ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE; ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    t0 = time.perf_counter()
    sck = socket.create_connection((fe_host, fe_port), timeout=15)
    sck.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    ss = ctx.wrap_socket(sck, server_hostname=fe_host)
    cert = x509.load_der_x509_certificate(ss.getpeercert(True), default_backend())
    jwt = _attest.extract_jwt(cert)
    h, p, _ = _attest.parse_jwt(jwt)
    jwks = _attest.get_maa_public_key(p.get("iss") or maa_url, h.get("kid", ""),
                                      h.get("jku") or f"{maa_url}/certs", jc, 15)
    _attest.verify_jwt_rs256(jwt, jwks.public_key)
    _attest.verify_reportdata_ctls(cert, p)
    ss.sendall(f"GET / HTTP/1.1\r\nHost: {fe_host}\r\nConnection: close\r\n\r\n".encode())
    ss.recv(64)
    dt = (time.perf_counter() - t0) * 1000
    ss.close()
    return dt


def pct(xs, p):
    s = sorted(xs); k = (len(s)-1)*p/100; f = int(k); c = min(f+1, len(s)-1)
    return s[f] if f == c else s[f]+(s[c]-s[f])*(k-f)


def vanilla_ttft(host, port, prompt, max_tokens=1, timeout=180):
    body = json.dumps({"prompt": prompt, "max_tokens": max_tokens}).encode()
    req = (f"POST /generate HTTP/1.1\r\nHost: {host}\r\n"
           f"Content-Type: application/json\r\nContent-Length: {len(body)}\r\n"
           f"Connection: close\r\n\r\n").encode() + body
    ctx = ssl.create_default_context(); ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE; ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    t0 = time.perf_counter()
    s = socket.create_connection((host, port), timeout=timeout)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    ss = ctx.wrap_socket(s, server_hostname="localhost")
    ss.sendall(req)
    buf = b""; ttft = None
    while True:
        chunk = ss.recv(4096)
        if not chunk:
            break
        buf += chunk
        if b"data:" in buf:           # first SSE token event
            ttft = (time.perf_counter() - t0) * 1000
            break
    ss.close()
    return ttft


def proxy_ttft(fe_host, fe_port, maa_url, jc, prompt, max_tokens=1, timeout=180):
    """Proxy mode: one TLS connection to the Janus frontend (attestation
    validated from the certificate, AS key cached), POST /forward/generate;
    the frontend relays the token stream from the backend as it arrives."""
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    body = json.dumps({"prompt": prompt, "max_tokens": max_tokens}).encode()
    req = (f"POST /forward/generate HTTP/1.1\r\nHost: {fe_host}\r\n"
           f"Content-Type: application/json\r\nContent-Length: {len(body)}\r\n"
           f"Connection: close\r\n\r\n").encode() + body
    ctx = ssl.create_default_context(); ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE; ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    t0 = time.perf_counter()
    s = socket.create_connection((fe_host, fe_port), timeout=timeout)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    ss = ctx.wrap_socket(s, server_hostname=fe_host)
    cert = x509.load_der_x509_certificate(ss.getpeercert(True), default_backend())
    jwt = _attest.extract_jwt(cert)
    h, p, _ = _attest.parse_jwt(jwt)
    jwks = _attest.get_maa_public_key(p.get("iss") or maa_url, h.get("kid", ""),
                                      h.get("jku") or f"{maa_url}/certs", jc, 15)
    _attest.verify_jwt_rs256(jwt, jwks.public_key)
    _attest.verify_reportdata_ctls(cert, p)
    ss.sendall(req)
    buf = b""; ttft = None
    while True:
        chunk = ss.recv(4096)
        if not chunk:
            break
        buf += chunk
        if b"data:" in buf:           # first SSE token event
            ttft = (time.perf_counter() - t0) * 1000
            break
    ss.close()
    return ttft


def redirect_driver(helper, db):
    p = subprocess.Popen([helper, db], stdin=subprocess.PIPE,
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1)
    return p


def redirect_ttft(proc, host, port, prompt, max_tokens=1, require_dc=True):
    body = json.dumps({"prompt": prompt, "max_tokens": max_tokens})
    proc.stdin.write(f"POST {host} {port} /generate {body}\n"); proc.stdin.flush()
    out = proc.stdout.readline().strip()
    if not out.startswith("OK "):
        return None
    f = {k: v for k, v in (t.split("=", 1) for t in out[3:].split() if "=" in t)}
    if f.get("status") != "200" or (require_dc and f.get("dc") != "1"):
        return None
    # total TTFT (connection start -> first token) = tcp + tls + ttft
    return (float(f["tcp_ms"]) + float(f["tls_ms"]) + float(f["ttft_ms"]),
            float(f["tcp_ms"]) + float(f["tls_ms"]))   # (total, establishment)


def measure_httpa(host, port, prompt, max_tokens=1, timeout=300):
    """HTTPA/2 TTFT: TLS + post-handshake /attest (verify SNP bundle) =
    verified channel, then GET /generate first token. The werkzeug dev server
    won't keep-alive after the large /attest response, so /generate runs on a
    fresh TLS connection; TTFT = attest establishment + generate first token
    (the extra handshake is ~ms, negligible vs the attestation + inference)."""
    import os as _os, sys as _sys
    _sys.path.insert(0, _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "..", ".."))
    from janus.common.snp_attestation import verify_snp_bundle
    maa = _os.environ.get("MAA_URL", "https://sharedweu.weu.attest.azure.net")
    ctx = ssl.create_default_context(); ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE; ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    t0 = time.perf_counter()
    # --- conn 1: TLS + post-handshake attestation -> verified channel ---
    s = socket.create_connection((host, port), timeout=timeout)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    ss = ctx.wrap_socket(s, server_hostname=host)
    nonce = _os.urandom(32)
    ss.sendall((f"GET /attest HTTP/1.1\r\nHost: {host}\r\n"
                f"X-Nonce: {nonce.hex()}\r\nConnection: close\r\n\r\n").encode())
    hdr = b""
    while b"\r\n\r\n" not in hdr:
        c = ss.recv(4096)
        if not c: break
        hdr += c
    head, _, rest = hdr.partition(b"\r\n\r\n")
    cl = int([l.split(b":", 1)[1] for l in head.split(b"\r\n")
              if l.lower().startswith(b"content-length")][0])
    while len(rest) < cl:
        rest += ss.recv(8192)
    ss.close()
    ok, _ = verify_snp_bundle(rest, expected_nonce=nonce, maa_url=maa)
    if not ok:
        return None
    est = (time.perf_counter() - t0) * 1000   # establishment to verified channel
    # --- conn 2: GET /generate on the verified server, first token ---
    s2 = socket.create_connection((host, port), timeout=timeout)
    s2.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    ss2 = ctx.wrap_socket(s2, server_hostname=host)
    from urllib.parse import quote
    ss2.sendall((f"GET /generate?prompt={quote(prompt)}&max_tokens={max_tokens} "
                 f"HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").encode())
    buf = b""; ttft = None
    while True:
        c = ss2.recv(4096)
        if not c: break
        buf += c
        if b"data:" in buf:
            ttft = (time.perf_counter() - t0) * 1000
            break
    ss2.close()
    return (ttft, est) if ttft else None


def measure_ratls(server_url, prompt, max_tokens=1):
    """RA+TLS TTFT: in-handshake remote attestation, then GET /generate first
    token. Must run under the python-ratls interpreter (needs ratls_bridge)."""
    import os as _os, sys as _sys
    _sys.path.insert(0, _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "..", "..", "baselines"))   # the ratls package lives in baselines/ratls
    from ratls.client import RATLSHTTPClient
    import logging; logging.getLogger().setLevel(logging.WARNING)   # the reference client logs every handshake at INFO
    for _n in ("ratls", "ratls.client", "__main__"): logging.getLogger(_n).setLevel(logging.WARNING)
    from urllib.parse import quote
    # establishment-to-verified-channel: a fresh RA+TLS handshake + trivial GET
    te = time.perf_counter()
    RATLSHTTPClient(server_url=server_url, verify_quote=True, ca_cert_path=None).fetch_page("/health")
    est = (time.perf_counter() - te) * 1000
    # full TTFT: fresh RA+TLS handshake + /generate first token
    t0 = time.perf_counter()
    c = RATLSHTTPClient(server_url=server_url, verify_quote=True, ca_cert_path=None)
    body = c.fetch_page(f"/generate?prompt={quote(prompt)}&max_tokens={max_tokens}")
    ttft = (time.perf_counter() - t0) * 1000
    return (ttft, est) if body else None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--backend", default="janus-be.local")
    ap.add_argument("--ctls-port", type=int, default=8443)
    ap.add_argument("--vanilla-port", type=int, default=8444)
    ap.add_argument("--prompts", default=os.path.expanduser("~/llm_prompts.json"))
    ap.add_argument("--nss-helper", default=os.path.expanduser("~/nss_client/nss_dc_helper"))
    ap.add_argument("--nss-db", default=os.path.expanduser("~/nss_client/nssdb"))
    ap.add_argument("--frontend-port", type=int, default=6037)
    ap.add_argument("--frontend", default="janus-fe.local")
    ap.add_argument("--httpa-host", default="janus-be.local")
    ap.add_argument("--httpa-port", type=int, default=5002)
    ap.add_argument("--ratls-url", default="https://janus-be.local:5004")
    ap.add_argument("--warmup", type=int, default=2)
    ap.add_argument("--only", default="")
    ap.add_argument("--maa", default="https://sharedweu.weu.attest.azure.net")
    ap.add_argument("--raw-out", default="", help="append per-request samples CSV")
    a = ap.parse_args()
    prompts = json.load(open(a.prompts))
    raw_rows = []
    results = {}                     # dump-name -> number of samples (explicit; not locals())
    def dump(name, samples):
        results[name] = len(samples)
        raw_rows.extend((name, i, f"{v:.3f}") for i, v in enumerate(samples))
    sel = (set(a.only.split(",")) if a.only
           else {"vanilla", "redirect", "proxy", "httpa", "ratls"})
    print(f"LLM TTFT: {len(prompts)} ShareGPT prompts, max_tokens=1, "
          f"backend={a.backend} (warmup={a.warmup})")

    if "vanilla" in sel:
        # Measure vanilla with the SAME C NSS helper as cTLS (plain TLS, dc=0)
        # for an apples-to-apples comparison — the vanilla front's CA is trusted
        # in the NSS db. (Avoids the Python-ssl-vs-C tail artifact.)
        proc = redirect_driver(a.nss_helper, a.nss_db)
        van = []; vest = []
        try:
            for i, pr in enumerate(prompts + prompts[:a.warmup]):
                r = redirect_ttft(proc, a.backend, a.vanilla_port, pr, require_dc=False)
                if r and i >= a.warmup:
                    van.append(r[0]); vest.append(r[1])
        finally:
            try: proc.stdin.write("QUIT\n"); proc.stdin.flush(); proc.wait(3)
            except Exception: proc.kill()
        if van:
            print(f"  vanilla      : n={len(van):2d}  TTFT p50={pct(van,50):7.0f}  "
                  f"p95={pct(van,95):7.0f}  p99={pct(van,99):7.0f} ms  "
                  f"(TLS establishment median={statistics.median(vest):.1f} ms)")
            dump("vanilla", van)

    if "redirect" in sel:
        _jc_red = JwksCache("/tmp/llm_jwks_ctl", "warm")
        proc = redirect_driver(a.nss_helper, a.nss_db)
        red = []; est = []
        try:
            for i, pr in enumerate(prompts + prompts[:a.warmup]):
                try:
                    ctl = _control_leg(a.frontend, a.frontend_port, a.maa, _jc_red)
                except Exception as e:
                    print(f"   [redirect ctl {i}] {repr(e)[:100]}", file=sys.stderr); continue
                r = redirect_ttft(proc, a.backend, a.ctls_port, pr)
                if r and i >= a.warmup:
                    red.append(ctl + r[0]); est.append(r[1])
        finally:
            try: proc.stdin.write("QUIT\n"); proc.stdin.flush(); proc.wait(3)
            except Exception: proc.kill()
        if red:
            print(f"  cTLS-redirect: n={len(red):2d}  TTFT p50={pct(red,50):7.0f}  "
                  f"p95={pct(red,95):7.0f}  p99={pct(red,99):7.0f} ms  "
                  f"(DC establishment median={statistics.median(est):.1f} ms)")
            dump("cTLS-redirect", red)

    if "proxy" in sel:
        jc = JwksCache("/tmp/llm_jwks", "warm")
        prox = []; est = []
        for i, pr in enumerate(prompts + prompts[:a.warmup]):
            try:
                r = proxy_ttft(a.frontend, a.frontend_port, a.maa, jc, pr)
            except Exception as e:
                print(f"  [proxy {i}] {e!r}", file=sys.stderr); r = None
            if r and i >= a.warmup:
                prox.append(r); est.append(_control_leg(a.frontend, a.frontend_port, a.maa, jc))
        if prox:
            print(f"  cTLS-proxy   : n={len(prox):2d}  TTFT p50={pct(prox,50):7.0f}  "
                  f"p95={pct(prox,95):7.0f}  p99={pct(prox,99):7.0f} ms  "
                  f"(DC+FE-hop establishment median={statistics.median(est):.1f} ms)")
            dump("cTLS-proxy", prox)

    if "httpa" in sel:
        hp = []; hest = []
        for i, pr in enumerate(prompts + prompts[:a.warmup]):
            try:
                r = measure_httpa(a.httpa_host, a.httpa_port, pr)
            except Exception as e:
                print(f"   [httpa {i}] {repr(e)[:120]}", file=sys.stderr); r = None
            if r and i >= a.warmup:
                hp.append(r[0]); hest.append(r[1])
        if hp:
            print(f"  HTTPA/2      : n={len(hp):2d}  TTFT p50={pct(hp,50):7.0f}  "
                  f"p95={pct(hp,95):7.0f}  p99={pct(hp,99):7.0f} ms  "
                  f"(attest establishment median={statistics.median(hest):.0f} ms)")
            dump("HTTPA/2", hp)

    if "ratls" in sel and a.ratls_url:
        rt = []; rest = []
        for i, pr in enumerate(prompts + prompts[:a.warmup]):
            try:
                r = measure_ratls(a.ratls_url, pr)
            except Exception as e:
                print(f"   [ratls {i}] {repr(e)[:120]}", file=sys.stderr); r = None
            if r and i >= a.warmup:
                rt.append(r[0]); rest.append(r[1])
        if rt:
            print(f"  RA+TLS       : n={len(rt):2d}  TTFT p50={pct(rt,50):7.0f}  "
                  f"p95={pct(rt,95):7.0f}  p99={pct(rt,99):7.0f} ms  "
                  f"(RA establishment median={statistics.median(rest):.0f} ms)")
            dump("RA+TLS", rt)


    _res = {"vanilla": "vanilla", "redirect": "cTLS-redirect", "proxy": "cTLS-proxy", "httpa": "HTTPA/2", "ratls": "RA+TLS"}
    missing = [f"{k} ({results.get(dn, 0)}/{len(prompts)})" for k, dn in _res.items() if k in sel and results.get(dn, 0) < 0.9 * len(prompts)]
    if a.raw_out and raw_rows:
        import csv as _csv, os as _os
        new = not _os.path.exists(a.raw_out)
        with open(a.raw_out, "a", newline="") as f:
            w = _csv.writer(f)
            if new: w.writerow(["protocol", "attempt", "latency_ms"])
            w.writerows(raw_rows)
        print(f"raw samples appended to {a.raw_out} ({len(raw_rows)} rows)")
    if missing:
        print(f"FAILED (fewer than 90 % successful samples): {', '.join(missing)}", file=sys.stderr); sys.exit(1)


if __name__ == "__main__":
    main()
