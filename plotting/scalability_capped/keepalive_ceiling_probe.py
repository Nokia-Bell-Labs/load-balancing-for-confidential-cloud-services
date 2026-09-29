#!/usr/bin/env python3
# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

"""Frontend proxy-ceiling probe: measure /forward/health throughput with
KEEP-ALIVE persistent connections (K workers), to compare against the
fresh-connection rate. If keep-alive >> fresh, the 162 ceiling is the
per-connection TLS-handshake cost, not the forward path.
  usage: keepalive_ceiling_probe.py <host> <port> <K workers> <seconds>
"""
import ssl, socket, time, threading, sys

HOST = sys.argv[1] if len(sys.argv) > 1 else "janus-be.local"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 6037
K    = int(sys.argv[3]) if len(sys.argv) > 3 else 32
DUR  = float(sys.argv[4]) if len(sys.argv) > 4 else 8.0

ctx = ssl.create_default_context(); ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE; ctx.minimum_version = ssl.TLSVersion.TLSv1_3
REQ = b"GET /forward/health HTTP/1.1\r\nHost: f\r\nConnection: keep-alive\r\n\r\n"

counts = [0] * K
errs = [0] * K
stop = False


def worker(i):
    global stop
    try:
        s = socket.create_connection((HOST, PORT), timeout=10)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        ss = ctx.wrap_socket(s, server_hostname=HOST)
    except Exception:
        errs[i] += 1; return
    while not stop:
        try:
            ss.sendall(REQ)
            resp = b""
            while b"\r\n\r\n" not in resp:
                c = ss.recv(4096)
                if not c: raise IOError("closed")
                resp += c
            head, _, rest = resp.partition(b"\r\n\r\n")
            cl = 0
            for l in head.split(b"\r\n"):
                if l.lower().startswith(b"content-length"):
                    cl = int(l.split(b":", 1)[1]); break
            while len(rest) < cl:
                rest += ss.recv(4096)
            counts[i] += 1
        except Exception:
            errs[i] += 1
            try:
                s = socket.create_connection((HOST, PORT), timeout=10)
                s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                ss = ctx.wrap_socket(s, server_hostname=HOST)
            except Exception:
                return


ths = [threading.Thread(target=worker, args=(i,), daemon=True) for i in range(K)]
t0 = time.time()
for t in ths: t.start()
time.sleep(DUR); stop = True
time.sleep(0.6)
dt = time.time() - t0
tot = sum(counts)
print(f"keep-alive K={K} dur={dt:.1f}s: {tot} reqs = {tot/dt:.0f} req/s  (errs={sum(errs)})")
