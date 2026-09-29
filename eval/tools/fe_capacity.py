#!/usr/bin/env python3
# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

"""Frontend control-plane capacity driver (RQ-S2).

Measures how many routing exchanges/s the SGX frontend sustains -- the ceiling
that caps Janus-redirection aggregate throughput when clients route per
connection.  Two regimes:

  fresh    : a new TLS connection + GET /pool_status per op (== redirection's
             per-connection control cost when routing is NOT amortized).
  keepalive: reuse one TLS connection, GET /pool_status per op (pure routing
             handler throughput once the connection is warm).

Closed-loop concurrency run: for each concurrency C, run C worker threads
hammering the frontend for WINDOW seconds; report achieved req/s and latency
percentiles.  The plateau in achieved req/s is the frontend's capacity.

Usage:
  fe_capacity.py --host janus-be.local --port 6037 --mode fresh \
      --concurrency 1,2,4,8,16,32,64 --window 8 --out cap_fresh.csv
"""
from __future__ import annotations
import argparse, csv, math, socket, ssl, statistics, threading, time

REQ = ("GET /pool_status HTTP/1.1\r\nHost: {h}\r\n"
       "User-Agent: fe-cap/1\r\nConnection: {conn}\r\nAccept: */*\r\n\r\n")


def _ctx():
    c = ssl.create_default_context(); c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE; c.minimum_version = ssl.TLSVersion.TLSv1_3
    return c


def _pctl(v, q):
    s = sorted(v); return s[min(len(s) - 1, max(0, math.ceil(q / 100 * len(s)) - 1))] if s else 0.0


def run_concurrency(host, port, mode, C, window, ctx):
    stop = time.perf_counter() + window
    lats: list[float] = []; lock = threading.Lock(); counts = [0] * C

    def worker(idx):
        local = []
        if mode == "keepalive":
            s = socket.create_connection((host, port), timeout=10); s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            ss = ctx.wrap_socket(s, server_hostname=host); ss.settimeout(10)
            req = REQ.format(h=host, conn="keep-alive").encode()
            while time.perf_counter() < stop:
                t0 = time.perf_counter()
                try:
                    ss.sendall(req); ss.recv(512)
                except Exception:
                    # server dropped keep-alive (Werkzeug dev server does after
                    # a few reqs); reopen and continue so we keep measuring.
                    try: ss.close()
                    except Exception: pass
                    try:
                        s = socket.create_connection((host, port), timeout=10)
                        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                        ss = ctx.wrap_socket(s, server_hostname=host); ss.settimeout(10)
                        continue
                    except Exception:
                        break
                local.append((time.perf_counter() - t0) * 1000); counts[idx] += 1
            try: ss.close()
            except Exception: pass
        else:  # fresh
            req = REQ.format(h=host, conn="close").encode()
            while time.perf_counter() < stop:
                t0 = time.perf_counter()
                try:
                    s = socket.create_connection((host, port), timeout=10)
                    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                    ss = ctx.wrap_socket(s, server_hostname=host); ss.settimeout(10)
                    ss.sendall(req); ss.recv(256); ss.close()
                except Exception:
                    continue
                local.append((time.perf_counter() - t0) * 1000); counts[idx] += 1
        with lock:
            lats.extend(local)

    ts = [threading.Thread(target=worker, args=(i,)) for i in range(C)]
    t_start = time.perf_counter()
    for t in ts: t.start()
    for t in ts: t.join()
    elapsed = time.perf_counter() - t_start
    total = sum(counts)
    return {
        "concurrency": C, "achieved_rps": total / elapsed, "n": total,
        "p50_ms": statistics.median(lats) if lats else 0.0,
        "p95_ms": _pctl(lats, 95), "p99_ms": _pctl(lats, 99),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", required=True); ap.add_argument("--port", type=int, default=6037)
    ap.add_argument("--mode", choices=("fresh", "keepalive"), default="fresh")
    ap.add_argument("--concurrency", default="1,2,4,8,16,32,64")
    ap.add_argument("--window", type=float, default=8.0)
    ap.add_argument("--warmup", type=float, default=2.0)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    ctx = _ctx()
    cs = [int(x) for x in a.concurrency.split(",")]
    # warmup
    run_concurrency(a.host, a.port, a.mode, 4, a.warmup, ctx)
    rows = []
    for C in cs:
        r = run_concurrency(a.host, a.port, a.mode, C, a.window, ctx)
        rows.append(r)
        print(f"C={C:>3}  achieved={r['achieved_rps']:8.1f} rps  p50={r['p50_ms']:7.2f}ms  p95={r['p95_ms']:8.2f}ms  n={r['n']}")
    with open(a.out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys())); w.writeheader(); w.writerows(rows)
    peak = max(r["achieved_rps"] for r in rows)
    print(f"\n{a.mode} routing CEILING = {peak:.0f} req/s")


if __name__ == "__main__":
    main()
