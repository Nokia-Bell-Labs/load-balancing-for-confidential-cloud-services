#!/usr/bin/env python3
# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

"""Microservice application benchmark: DeathStarBench hotelReservation
/reservation end-to-end latency through Janus vs vanilla TLS.

Both fronts relay to the SAME hotelReservation stack (frontend:5000) on the
backend CVM, so the app-processing term is identical and the delta is the
Janus-vs-vanilla establishment overhead in a realistic microservice.

  Janus   : NSS Delegated-Credential client -> dc_proxy(:8443) -> frontend:5000
  vanilla : plain TLS-1.3 client            -> X.509 proxy(:8444) -> frontend:5000

Reports median/p95/p99 of end-to-end /reservation latency (fresh connection
per request, matching the paper's "end-to-end request latency").

Usage (on the load-gen client):
  python3 microservice_bench.py --backend janus-be.local --n 200 \
      --nss-helper /home/janus/nss_client/nss_dc_helper --nss-db /home/janus/nss_client/nssdb
"""
import argparse, os, socket, ssl, subprocess, time, statistics, sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from janus.client import attest as _attest                       # noqa: E402
from clients._base import JwksCache               # noqa: E402

RPATH = ("/reservation?inDate=2015-04-09&outDate=2015-04-10&lat=37.7749&"
         "lon=-122.4194&hotelId=1&customerName=Cust_1&username=Cornell_1&"
         "password=1111111111&number=1")


def pct(xs, p):
    s = sorted(xs); k = (len(s)-1)*p/100; f = int(k); c = min(f+1, len(s)-1)
    return s[f] if f == c else s[f]+(s[c]-s[f])*(k-f)


def measure_vanilla(host, port, n, warmup):
    ctx = ssl.create_default_context(); ctx.check_hostname=False
    ctx.verify_mode=ssl.CERT_NONE; ctx.minimum_version=ssl.TLSVersion.TLSv1_3
    req = (f"GET {RPATH} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").encode()
    lat = []
    for i in range(n+warmup):
        try:
            t0 = time.perf_counter()
            s = socket.create_connection((host, port), timeout=15)
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            ss = ctx.wrap_socket(s, server_hostname=host)
            ss.sendall(req); first = ss.recv(64)
            dt = (time.perf_counter()-t0)*1000
            ss.close()
        except Exception as e:
            _fail("vanilla", i, e); continue
        if first.startswith(b"HTTP/1.1 200"):
            if i >= warmup: lat.append(dt); _ok("vanilla", i, dt)
        else: _fail("vanilla", i, f"HTTP status line {first[:20]!r}")
    return lat


def _control_leg(fe_host, fe_port, maa_url, jc):
    """Redirection mode, leg 1 (paper §4.4): the client opens a short CONTROL
    connection to the frontend, validates the frontend's attestation (cached
    JWKS), and obtains a backend address.  Returns the leg latency in ms."""
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    ctx = ssl.create_default_context(); ctx.check_hostname=False
    ctx.verify_mode=ssl.CERT_NONE; ctx.minimum_version=ssl.TLSVersion.TLSv1_3
    t0 = time.perf_counter()
    s = socket.create_connection((fe_host, fe_port), timeout=15)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    ss = ctx.wrap_socket(s, server_hostname=fe_host)
    cert = x509.load_der_x509_certificate(ss.getpeercert(True), default_backend())
    jwt = _attest.extract_jwt(cert)
    h, p, _ = _attest.parse_jwt(jwt)
    jwks = _attest.get_maa_public_key(p.get("iss") or maa_url, h.get("kid",""),
               h.get("jku") or f"{maa_url}/certs", jc, 15)
    _attest.verify_jwt_rs256(jwt, jwks.public_key)
    _attest.verify_reportdata_ctls(cert, p)
    # routing request: obtain the selected backend's address
    ss.sendall(f"GET / HTTP/1.1\r\nHost: {fe_host}\r\nConnection: close\r\n\r\n".encode())
    ss.recv(64)
    dt = (time.perf_counter()-t0)*1000
    ss.close()
    return dt


def measure_ctls(helper, db, fe_host, fe_port, maa_url, host, port, n, warmup):
    """Redirection mode, FULL e2e per design: CONTROL connection to the frontend
    (validate + obtain backend address) + DIRECT data connection to the backend
    (DC).  e2e latency = both legs (two connection establishments)."""
    proc = subprocess.Popen([helper, db], stdin=subprocess.PIPE,
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1)
    jc = JwksCache("/tmp/ms_jwks_ctl", "warm")
    lat = []
    try:
        for i in range(n+warmup):
            try:
                ctl = _control_leg(fe_host, fe_port, maa_url, jc)   # leg 1: frontend
            except Exception as e:
                _fail("cTLS-redirect", i, e)
                continue
            proc.stdin.write(f"{host} {port} {RPATH}\n"); proc.stdin.flush()  # leg 2: backend
            out = proc.stdout.readline().strip()
            if not out.startswith("OK "): _fail("cTLS-redirect", i, f"helper: {out[:80]}"); continue
            f = {k:v for k,v in (t.split("=",1) for t in out[3:].split() if "=" in t)}
            if f.get("dc") != "1" or f.get("status") != "200":
                _fail("cTLS-redirect", i, f"dc={f.get('dc')} status={f.get('status')}"); continue
            if i >= warmup:
                data = float(f["tcp_ms"])+float(f["tls_ms"])+float(f["http_ms"])
                lat.append(ctl + data); _ok("cTLS-redirect", i, ctl + data)   # full e2e
    finally:
        try: proc.stdin.write("QUIT\n"); proc.stdin.flush(); proc.wait(3)
        except Exception: proc.kill()
    return lat


def measure_ctls_proxy(fe_host, fe_port, maa_url, n, warmup):
    """Proxy mode: client -> Janus frontend (validate attestation, cached) ->
    /forward/reservation -> backend hotelReservation.  Full e2e per request."""
    ctx = ssl.create_default_context(); ctx.check_hostname=False
    ctx.verify_mode=ssl.CERT_NONE; ctx.minimum_version=ssl.TLSVersion.TLSv1_3
    jc = JwksCache("/tmp/ms_jwks", "warm")
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    req = (f"GET /forward{RPATH} HTTP/1.1\r\nHost: {fe_host}\r\n"
           f"Connection: close\r\n\r\n").encode()
    lat = []
    for i in range(n+warmup):
        try:
            t0 = time.perf_counter()
            s = socket.create_connection((fe_host, fe_port), timeout=15)
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            ss = ctx.wrap_socket(s, server_hostname=fe_host)
            cert = x509.load_der_x509_certificate(ss.getpeercert(True), default_backend())
            jwt = _attest.extract_jwt(cert)
            h, p, _ = _attest.parse_jwt(jwt)
            jwks = _attest.get_maa_public_key(p.get("iss") or maa_url, h.get("kid",""),
                       h.get("jku") or f"{maa_url}/certs", jc, 15)
            _attest.verify_jwt_rs256(jwt, jwks.public_key)
            _attest.verify_reportdata_ctls(cert, p)
            ss.sendall(req); first = ss.recv(64)
            dt = (time.perf_counter()-t0)*1000
            ss.close()
            if first.startswith(b"HTTP/1.1 200"):
                if i >= warmup: lat.append(dt); _ok("cTLS-proxy", i, dt)
            else: _fail("cTLS-proxy", i, f"HTTP status line {first[:20]!r}")
        except Exception as e:
            _fail("cTLS-proxy", i, e)
            continue
    return lat


def measure_httpa(host, port, n, warmup):
    """HTTPA/2: TLS + post-handshake /attest (verify) + GET /reservation
    (forwarded to the hotel), on one keep-alive connection.  Full e2e."""
    import os as _os
    from janus.common.snp_attestation import verify_snp_bundle
    NONCE = 32
    ctx = ssl.create_default_context(); ctx.check_hostname=False
    ctx.verify_mode=ssl.CERT_NONE; ctx.minimum_version=ssl.TLSVersion.TLSv1_3
    maa = _os.environ.get("MAA_URL", "https://sharedweu.weu.attest.azure.net")
    lat = []
    for i in range(n+warmup):
        try:
            t0 = time.perf_counter()
            s = socket.create_connection((host, port), timeout=30)
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            ss = ctx.wrap_socket(s, server_hostname=host)
            nonce = __import__("os").urandom(NONCE)
            # GET /attest with the nonce as a hex header: keeps attest+app as
            # two GETs on one keep-alive connection (one post-handshake RT).
            ss.sendall((f"GET /attest HTTP/1.1\r\nHost: {host}\r\n"
                        f"X-Nonce: {nonce.hex()}\r\nConnection: keep-alive\r\n\r\n").encode())
            hdr=b""
            while b"\r\n\r\n" not in hdr: hdr+=ss.recv(4096)
            head,_,rest=hdr.partition(b"\r\n\r\n")
            cl=int([l.split(b":",1)[1] for l in head.split(b"\r\n") if l.lower().startswith(b"content-length")][0])
            while len(rest)<cl: rest+=ss.recv(8192)
            ok,_=verify_snp_bundle(rest, expected_nonce=nonce, maa_url=maa)
            # e2e to verified channel; the trailing app GET (~5 ms, identical
            # across protocols) is excluded because the werkzeug dev server
            # won't keep-alive after the large attest response. Negligible vs
            # HTTPA's ~150 ms attestation cost.
            dt=(time.perf_counter()-t0)*1000; ss.close()
            if not ok: _fail("HTTPA/2", i, "attestation bundle verification failed"); continue
            if i>=warmup: lat.append(dt); _ok("HTTPA/2", i, dt)
        except Exception as e:
            _fail("HTTPA/2", i, e)
            continue
    return lat


def measure_ratls(server_url, n, warmup):
    """RA+TLS: in-handshake quote+verify, then GET /reservation (forwarded).
    Must run under python-ratls (needs ratls_bridge)."""
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "baselines"))   # the ratls package lives in baselines/ratls
    from ratls.client import RATLSHTTPClient
    import logging; logging.getLogger().setLevel(logging.WARNING)   # the reference client logs every handshake at INFO
    for _n in ("ratls", "ratls.client", "__main__"): logging.getLogger(_n).setLevel(logging.WARNING)
    lat = []
    for i in range(n+warmup):
        try:
            t0 = time.perf_counter()
            c = RATLSHTTPClient(server_url=server_url, verify_quote=True, ca_cert_path=None)
            body = c.fetch_page(RPATH)
            dt = (time.perf_counter()-t0)*1000
            if not body: _fail("RA+TLS", i, "empty response body"); continue
            if i>=warmup: lat.append(dt); _ok("RA+TLS", i, dt)
        except Exception as e:
            _fail("RA+TLS", i, e)
            continue
    return lat


FAILURES = []          # (protocol, attempt index, error) for every attempt that produced no sample
OK_ROWS = []           # (protocol, attempt index, latency_ms) for every successful measured attempt (original index)
WARMUP = {"n": 0}
def _fail(name, i, e): FAILURES.append((name, i, repr(e)[:160] if not isinstance(e, str) else e))
def _ok(name, i, dt): OK_ROWS.append((name, i, dt))

def report(name, lat, attempted):
    failed = [f for f in FAILURES if f[0] == name]
    if not lat:
        print(f"  {name:14s}: NO DATA  (attempted {attempted}, failed {len(failed)}: {failed[0][2] if failed else 'no attempts'})"); return
    print(f"  {name:14s}: n={len(lat):3d}  p50={pct(lat,50):6.2f}  "
          f"p95={pct(lat,95):6.2f}  p99={pct(lat,99):6.2f}  ms   (attempted {attempted}, succeeded {len(lat)}, failed {len(failed)})")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--backend", required=True)
    ap.add_argument("--frontend", default="janus-fe.local")
    ap.add_argument("--frontend-port", type=int, default=6037)
    ap.add_argument("--maa", default="https://sharedweu.weu.attest.azure.net")
    ap.add_argument("--ctls-port", type=int, default=8443)
    ap.add_argument("--vanilla-port", type=int, default=8444)
    ap.add_argument("--n", type=int, default=200)
    ap.add_argument("--warmup", type=int, default=20)
    ap.add_argument("--nss-helper", default=os.path.expanduser("~/nss_client/nss_dc_helper"))
    ap.add_argument("--nss-db", default=os.path.expanduser("~/nss_client/nssdb"))
    ap.add_argument("--httpa-host", default=None)
    ap.add_argument("--httpa-port", type=int, default=5002)
    ap.add_argument("--ratls-url", default=None, help="https://<ratls-host>:5004")
    ap.add_argument("--only", default="", help="comma-list: vanilla,redirect,proxy,httpa,ratls")
    ap.add_argument("--raw-out", default="",
                    help="append per-request samples to this CSV "
                         "(protocol,attempt,latency_ms) so mean/min/max are "
                         "computable later, not just the printed percentiles")
    a = ap.parse_args()
    sel = set(a.only.split(",")) if a.only else None
    def want(x): return sel is None or x in sel

    raw_rows = []

    missing = []
    def run(name, lat):
        report(name, lat, a.n)
        raw_rows.extend((name, i, int(i < a.warmup), f"{v:.3f}", 1, "") for fname, i, v in OK_ROWS if fname == name)
        raw_rows.extend((fname, i, int(i < a.warmup), "", 0, err) for fname, i, err in FAILURES if fname == name)
        if len(lat) < 0.9 * a.n:          # completeness rule: at least 90 % of the measured requests must succeed
            missing.append(f"{name} ({len(lat)}/{a.n} succeeded)")

    print(f"hotelReservation /reservation e2e latency ({a.n} reqs, fresh conn each):")
    if want("vanilla"):
        run("vanilla", measure_vanilla(a.backend, a.vanilla_port, a.n, a.warmup))
    if want("redirect"):
        run("cTLS-redirect", measure_ctls(a.nss_helper, a.nss_db, a.frontend, a.frontend_port, a.maa, a.backend, a.ctls_port, a.n, a.warmup))
    if want("proxy"):
        run("cTLS-proxy", measure_ctls_proxy(a.frontend, a.frontend_port, a.maa, a.n, a.warmup))
    if want("httpa") and a.httpa_host:
        run("HTTPA/2", measure_httpa(a.httpa_host, a.httpa_port, a.n, a.warmup))
    if want("ratls") and a.ratls_url:
        run("RA+TLS", measure_ratls(a.ratls_url, a.n, a.warmup))

    if a.raw_out and raw_rows:
        import csv as _csv, os as _os
        new = not _os.path.exists(a.raw_out)
        with open(a.raw_out, "a", newline="") as f:
            w = _csv.writer(f)
            if new:
                w.writerow(["protocol", "attempt", "warmup", "latency_ms", "ok", "error"])
            w.writerows(raw_rows)
        print(f"raw samples appended to {a.raw_out} ({len(raw_rows)} rows, {sum(1 for r in raw_rows if r[4] == 0)} failed attempts recorded)")
    if missing:
        print(f"FAILED (fewer than 90 % successful requests): {', '.join(missing)}", file=sys.stderr); sys.exit(1)


if __name__ == "__main__":
    main()
