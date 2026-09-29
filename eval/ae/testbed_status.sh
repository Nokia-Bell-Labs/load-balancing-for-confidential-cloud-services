#!/bin/bash
# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

# Current state of the testbed, in a few lines: frontend, backend pool and its profile, application backend,
# H100 CVM, and whether the Fig. 6 window is open. Reads only. Takes a few seconds.
#   ./testbed_status.sh
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"; ROOT="$(cd "$HERE/../.." && pwd)"
source "$HERE/testbed.env" 2>/dev/null || { echo "missing $HERE/testbed.env"; exit 1; }
tcp() { timeout 3 bash -c "</dev/tcp/$1/$2" 2>/dev/null; }
echo "== testbed status ($(date -u +%H:%M) UTC)"
# frontend
if tcp "$FRONTEND_HOST" "$FRONTEND_PORT"; then
  python3 - "$FRONTEND_HOST" "$FRONTEND_PORT" "$ROOT" <<'PY'
import sys, ssl, socket, json, urllib.request
sys.path.insert(0, sys.argv[3])
from cryptography import x509
from janus.client import attest
host, port = sys.argv[1], int(sys.argv[2])
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
with socket.create_connection((host, port), timeout=5) as s, ctx.wrap_socket(s, server_hostname=host) as ss:
    cert = x509.load_der_x509_certificate(ss.getpeercert(True))
try:
    _, p, _ = attest.parse_jwt(attest.extract_jwt(cert)); mr = p.get("x-ms-sgx-mrenclave", "")[:16]
    print(f"  frontend        up   {host}:{port}  SGX, attested (MRENCLAVE {mr}...)")
except Exception as e:
    print(f"  frontend        up   {host}:{port}  (attestation extension not readable: {e})")
d = json.load(urllib.request.urlopen(f"https://{host}:{port}/pool_status", context=ctx, timeout=10))
bs = [b for b in d["backends"] if b["cvm_mode"] == "in-service"]
ports = sorted({int(b["port"]) for b in bs})
prof = {8443: "default (test application; Fig. 6 sizes when the window is open)", 8543: "hotel (Fig. 7c)", 8643: "browser (Fig. 7a)"}
label = "none" if not ports else (prof.get(ports[0], "?") if len(ports) == 1 else "mixed")
print(f"  backend pool    {len(bs)} in service  profile: {label}")
for b in bs[:6]: print(f"                  {b['ip_address']}:{b['port']}")
if len(bs) > 6: print(f"                  ... and {len(bs) - 6} more")
PY
else
  echo "  frontend        DOWN $FRONTEND_HOST:$FRONTEND_PORT"
fi
# application backend and baseline servers
up=""; down=""
for p in "${APP_DC_PORT:-8543}" "${APP_VANILLA_PORT:-8544}" "${WEB_DC_PORT:-8643}" "${WEB_VANILLA_PORT:-8644}" "$HTTPA_PORT" "$RATLS_PORT"; do
  if tcp "$BACKEND_HOST" "$p"; then up="$up $p"; else down="$down $p"; fi
done
echo "  app backend     $BACKEND_HOST  fronts up:$up${down:+  down:$down}"
# H100
if [ -n "${GPU_HOST:-}" ]; then
  if tcp "$GPU_HOST" "${BACKEND_PORT:-8443}"; then echo "  H100 CVM        up   $GPU_HOST (LLM served; profile gpu, Fig. 7b)"; else echo "  H100 CVM        not serving ($GPU_HOST set, :${BACKEND_PORT:-8443} closed)"; fi
else
  echo "  H100 CVM        not started (on request, Fig. 7b)"
fi
# Fig. 6 window: the pool-size service leaves a heartbeat on this VM
if [ -f /tmp/janus-pool-service.alive ]; then
  read -r ts ncvm < /tmp/janus-pool-service.alive; age=$(( $(date +%s) - ${ts:-0} ))
  if [ "$age" -lt 90 ]; then echo "  Fig. 6 window   open: ${ncvm:-?} backend CVMs up for the curve, the pool-size service answered ${age}s ago (-e fig6 can run; it registers 32, 16, 8, 4, 2, 1 in turn)"; else echo "  Fig. 6 window   closed (service last seen ${age}s ago; ask in the thread)"; fi
else
  echo "  Fig. 6 window   closed (ask in the thread to open it)"
fi
# a run in progress?
if pgrep -u "$USER" -f '[a]e.py -m data' >/dev/null; then echo "  evaluation run  in progress (ae-remote.sh ... status shows it)"; else echo "  evaluation run  none in progress"; fi
