#!/usr/bin/env python3
# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

"""Rate-capped microbenchmark backend for the §6.1 scalability experiment.

Models a *heavier, more realistic* backend with a fixed per-request service
time and bounded concurrency, so its maximum serving rate is approximately
  cap ~= workers / service_time   (e.g. 4 workers * 100 ms -> ~40 req/s).

This is a throwaway microbenchmark stub (trivial static response), NOT any of
the application workloads. It runs as plain HTTP behind the dc_proxy(DC) front,
so BOTH proxy (/forward) and redirect data connections terminate here and the
cap applies to both modes.

Overflow beyond the worker pool is rejected (503) rather than queued without
bound, so the process stays stable under open-loop overload; achieved 200-rate
saturates at the cap, which is what runner.py measures.
"""
import argparse, time, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

_SEM = None
_SERVICE_S = 0.0
_BODY = b"ok\n"


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _serve(self):
        # Non-blocking-ish admission: wait at most one service time for a slot;
        # reject (503) beyond that so threads don't pile up under overload.
        got = _SEM.acquire(timeout=max(_SERVICE_S, 0.001))
        if not got:
            self.send_response(503)
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "close")
            self.end_headers()
            return
        try:
            if _SERVICE_S:
                time.sleep(_SERVICE_S)
            self.send_response(200)
            self.send_header("Content-Length", str(len(_BODY)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(_BODY)
        finally:
            _SEM.release()

    def do_GET(self):
        self._serve()

    def do_POST(self):
        # drain any body, then serve identically
        ln = int(self.headers.get("Content-Length", 0) or 0)
        if ln:
            self.rfile.read(ln)
        self._serve()

    def log_message(self, *a):
        pass


def main():
    global _SEM, _SERVICE_S
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--bind", default="0.0.0.0")
    ap.add_argument("--workers", type=int, default=4,
                    help="concurrent service slots (queue depth)")
    ap.add_argument("--service-ms", type=float, default=100.0,
                    help="fixed per-request service time (ms)")
    a = ap.parse_args()
    _SEM = threading.Semaphore(a.workers)
    _SERVICE_S = a.service_ms / 1000.0
    srv = ThreadingHTTPServer((a.bind, a.port), Handler)
    srv.daemon_threads = True
    cap = a.workers * 1000.0 / a.service_ms if a.service_ms else float("inf")
    print(f"[capped_backend] :{a.port} workers={a.workers} "
          f"service={a.service_ms}ms -> cap ~= {cap:.0f} req/s", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
