#!/bin/bash
# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

# Table 1: frontend startup and per-backend registration latencies.
#
# These are SERVER-SIDE events. A frontend start has these steps: keypair, SGX quote, AS
# verification, CA issuance. A backend registration has these steps: keypair, SNP quote,
# AS verification, DC issuance.  The client VM cannot drive them. By design
# the client VM never logs into a TEE machine (docs/ACCESS.md).
#
# What the artifact provides instead:
#   * the collectors that produced the numbers of the paper:
#       plotting/startup_latency/run_frontend_startup.sh   (frontend host, docker)
#       plotting/startup_latency/run_backend_startup.sh    (frontend host, ssh to the CVM)
#       plotting/startup_latency/dc_sign_microbench.py     (DC issuance cost)
#   * on request, a repetition that an author runs during your window. The author shares the
#     container and backend logs in the HotCRP thread.
#
# From the client you can still observe the *effects* that the table describes:
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; ROOT="$(cd "$HERE/../.." && pwd)"; source "$HERE/testbed.env"; python3 "$HERE/render_env.py" >/dev/null || { echo "testbed.env is incomplete"; exit 1; }
cd "$ROOT"
echo "== live: the certificate of the frontend is the one that the startup of Table 1 produced (AS JWT issued at):"
python3 - "$FRONTEND_HOST" "$FRONTEND_PORT" <<'PY'
import sys, ssl, socket, json, base64, datetime
from cryptography import x509
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
with socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=10) as s, ctx.wrap_socket(s, server_hostname=sys.argv[1]) as ss:
    c = x509.load_der_x509_certificate(ss.getpeercert(True))
tok = c.extensions.get_extension_for_oid(x509.ObjectIdentifier("1.3.6.1.4.1.99999.3.1")).value.value.decode()
p = json.loads(base64.urlsafe_b64decode(tok.split(".")[1] + "=="))
print("   JWT iat", datetime.datetime.utcfromtimestamp(p["iat"]), "UTC | cert notBefore", c.not_valid_before, "| serial", hex(c.serial_number))
print("   (the certificate stays the same across frontend restarts, design §4.2. The authors can restart the frontend during your window. Then run this again to see that the serial is unchanged)")
PY

echo; echo "== LIVE: DC-issuance signing cost (the per-backend step of registration), on this client"
mkdir -p "$RUN_ROOT/table1"; (cd "$RUN_ROOT/table1" && python3 "$ROOT/plotting/startup_latency/dc_sign_microbench.py" 2>&1 | grep -E "median|p95|mean|N=" | sed "s/^/   /")
echo "   (samples: $RUN_ROOT/table1/dc_sign_microbench.csv. )"
echo "   (a CPU-local ECDSA-P256 signature over the DC signing input)"
