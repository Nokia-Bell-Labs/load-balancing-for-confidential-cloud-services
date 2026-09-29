#!/bin/bash
# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

# Pre-flight check for the artifact evaluation. It tests that this client VM can
# reach everything that the experiments need. Run this first. Every other eval/ae
# script assumes that it passed. Nothing here changes any state.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"; ROOT="$(cd "$HERE/../.." && pwd)"
source "$HERE/testbed.env" 2>/dev/null || { echo "missing $HERE/testbed.env (copy testbed.env.example)"; exit 1; }
python3 "$HERE/render_env.py" >/dev/null || echo "  (testbed.env still has TBD values)"
ok=0; bad=0
"$HERE/testbed_status.sh"; echo
pass() { echo "  ok   $1"; ok=$((ok+1)); }
fail() { echo "  FAIL $1"; bad=$((bad+1)); }
tcp()  { timeout 3 bash -c "</dev/tcp/$1/$2" 2>/dev/null; }

echo "== configuration of the measurement scripts"
if grep -vE "^\s*#" "$ROOT/eval/configs/env.yaml" | grep -q "TBD"; then fail "eval/configs/env.yaml still has TBD endpoints"; else pass "eval/configs/env.yaml endpoints filled in"; fi
for m in cryptography requests yaml; do python3 -c "import $m" 2>/dev/null && pass "python module $m" || fail "python module $m"; done
[ -x "$RATLS_PYTHON" ] && pass "RA+TLS interpreter $RATLS_PYTHON" || fail "RA+TLS interpreter $RATLS_PYTHON"
[ -x "$NSS_HELPER" ] && pass "NSS DC client $NSS_HELPER" || fail "NSS DC client $NSS_HELPER"
[ -d "$NSS_DB" ] && pass "NSS trust DB $NSS_DB" || fail "NSS trust DB $NSS_DB"
sudo -n tc qdisc show dev "$IFACE" >/dev/null 2>&1 && pass "tc-netem usable on $IFACE (sudo)" || fail "sudo tc on $IFACE"

echo "== frontend (SGX host)"
if tcp "$FRONTEND_HOST" "$FRONTEND_PORT"; then
  pass "TCP $FRONTEND_HOST:$FRONTEND_PORT"
  EXPECTED_MRENCLAVE="${EXPECTED_MRENCLAVE:-TBD}" python3 - "$FRONTEND_HOST" "$FRONTEND_PORT" "$MAA_URL" "$ROOT" <<'PY' && pass "frontend certificate carries a valid AS JWT (checks 2-3)" || fail "frontend attestation check"
import sys, ssl, socket, json, base64
sys.path.insert(0, sys.argv[4])          # janus.client.attest from this checkout
from cryptography import x509
from janus.client import attest
host, port, maa = sys.argv[1], int(sys.argv[2]), sys.argv[3]
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
with socket.create_connection((host, port), timeout=10) as s, ctx.wrap_socket(s, server_hostname=host) as ss:
    cert = x509.load_der_x509_certificate(ss.getpeercert(True))
tok = attest.extract_jwt(cert); hdr, payload, _ = attest.parse_jwt(tok)
class C:  # a cache that stores nothing
    def get(self, *a): return None
    def put(self, *a): pass
k = attest.get_maa_public_key(payload.get("iss",""), hdr.get("kid",""), hdr.get("jku",""), C(), trusted_issuer=maa)
attest.verify_jwt_rs256(tok, k.public_key); attest.verify_jwt_validity(payload); attest.verify_reportdata_ctls(cert, payload)
mr = payload.get("x-ms-sgx-mrenclave") or ""
print("     JWT issuer", payload.get("iss"), "| MRENCLAVE", mr)
exp = __import__("os").environ.get("EXPECTED_MRENCLAVE", "TBD")
if exp not in ("", "TBD"):
    assert mr.lower() == exp.lower(), f"MRENCLAVE {mr} != expected {exp} (the running frontend is not the image of the artifact)"
    print("     MRENCLAVE matches the artifact image (testbed.env EXPECTED_MRENCLAVE)")
else:
    print("     MRENCLAVE not checked (EXPECTED_MRENCLAVE is unset in testbed.env)")
PY
  python3 - "$FRONTEND_HOST" "$FRONTEND_PORT" <<'PY'
import sys, ssl, urllib.request, json
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
d = json.load(urllib.request.urlopen(f"https://{sys.argv[1]}:{sys.argv[2]}/pool_status", context=ctx, timeout=10))
n = sum(1 for b in d["backends"] if b["cvm_mode"] == "in-service")
print(f"     pool: {d['count']} registered, {n} in service", "(each row carries public_key_pem + cert_fp)" if all(b.get("cert_fp") for b in d["backends"]) else "(WARNING: a backend has no pinned certificate)")
PY
else fail "TCP $FRONTEND_HOST:$FRONTEND_PORT"; fi

echo "== backend CVM and baseline servers"
tcp "$BACKEND_HOST" "$BACKEND_PORT" && pass "dc_proxy (DC-TLS) $BACKEND_HOST:$BACKEND_PORT" || fail "dc_proxy $BACKEND_HOST:$BACKEND_PORT"
tcp "$BACKEND_HOST" "$VANILLA_PORT" && pass "vanilla TLS $BACKEND_HOST:$VANILLA_PORT" || fail "vanilla TLS $BACKEND_HOST:$VANILLA_PORT"
tcp "$RATLS_HOST" "$RATLS_PORT" && pass "RA+TLS $RATLS_HOST:$RATLS_PORT" || fail "RA+TLS $RATLS_HOST:$RATLS_PORT"
tcp "$HTTPA_HOST" "$HTTPA_PORT" && pass "HTTPA/2 $HTTPA_HOST:$HTTPA_PORT" || fail "HTTPA/2 $HTTPA_HOST:$HTTPA_PORT"

echo "== browser workload (Fig. 7a), optional pieces"
[ -x "$FIREFOX" ] && pass "Firefox $FIREFOX" || echo "  skip Firefox not found ($FIREFOX). Fig. 7a is unavailable"
[ -x "$GECKODRIVER" ] && pass "geckodriver" || echo "  skip geckodriver not found"
[ -f "$EXT_XPI" ] && pass "extension $EXT_XPI" || echo "  skip extension .xpi not found"

echo; echo "$ok checks passed, $bad failed"; [ "$bad" -eq 0 ]
