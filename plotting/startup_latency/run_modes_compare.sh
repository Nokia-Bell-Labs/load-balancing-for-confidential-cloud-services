#!/bin/bash
# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

# Historical collector for the paper's Table 1 (server side). Every value below is a parameter:
# override with environment variables; by default a NEW timestamped CSV is written next to this
# script so the archived CSV is never modified.
# Backend startup, PROXY vs REDIRECTION, full per-mode phase breakdown + the
# test of whether redirection adds a frontend round trip for the DC.
# Real SEV-SNP backend-1, real frontend. N runs per mode (uniform with frontend).
#
# Per run captures:
#   keygen_ms       : backend "TLS key generation"
#   quote_gen_ms    : backend "Quote generation" (SNP evidence; cold VCEK fetch)
#   maa_verify_ms   : frontend "Attestation verification (backend)" (real MAA)
#   register_e2e_ms : backend "Credential issuance (E2E with frontend)" = the one
#                     /register_backend round trip (incl. MAA verify + DC sign)
#   frontend_reqs   : # HTTP requests this backend made to the frontend during the
#                     bring-up. DECISIVE: 1 in both modes => no extra DC RTT.
#   dcproxy_ms      : (redirection only) LOCAL dc_proxy bring-up -> :8443 listening
#                     (reads the sealed DC, registers with BoringSSL; no FE contact)
#
# Usage: bash run_modes_compare.sh [N_PER_MODE]
set -uo pipefail

N="${1:-50}"
IP="${BACKEND_IP:?set BACKEND_IP}"
KEY="${SSH_KEY:?set SSH_KEY to the private key that reaches the backend CVM}"
FE="${FRONTEND_URL:?set FRONTEND_URL, e.g. https://<frontend>:6037}"
CB="${BACKEND_REPO:-/home/janus/Janus}"
SEALED="$CB/janus/backend/sealed"
DCPROXY="${DC_PROXY_BIN:-$CB/janus/backend/dc_proxy/dc_proxy}"
OUT="${OUT:-$(cd "$(dirname "$0")" && pwd)/modes_compare-$(date -u +%Y%m%dT%H%M%SZ).csv}"

ssh_cmd() { ssh -i "$KEY" -o StrictHostKeyChecking=no -o ConnectTimeout=10 "${SSH_USER:-$USER}@${IP}" "$@" 2>/dev/null; }
num() { grep -oP '[0-9.]+(?= ms)' | tail -1; }

echo "mode,run,keygen_ms,quote_gen_ms,maa_verify_ms,register_e2e_ms,frontend_reqs,dcproxy_ms" > "$OUT"

run_one() {
  local mode="$1" run="$2"
  local SINCE; SINCE="$(date -u +%Y-%m-%dT%H:%M:%S)"
  # fresh state + register (--plain, Flask :8080). Wait for summary, let Flask
  # bind, then kill it so this ssh returns; the DC is already on disk.
  ssh_cmd "fuser -k 8443/tcp 8080/tcp 2>/dev/null; sleep 1; rm -f $SEALED/*.pem $SEALED/*.bin $SEALED/*.db 2>/dev/null; cd $CB && setsid env APP_HOME=$CB python3 -m janus.backend.backend_server --frontend-url $FE --cvm-type snp --my-ip $IP --port 8080 --bind 127.0.0.1 --plain --type cvm > /tmp/be_mode.log 2>&1 < /dev/null & for i in \$(seq 1 80); do grep -q 'BACKEND STARTUP LATENCY' /tmp/be_mode.log 2>/dev/null && break; sleep 0.5; done; sleep 1; fuser -k 8080/tcp 2>/dev/null; sleep 0.3" >/dev/null
  local L; L=$(ssh_cmd "cat /tmp/be_mode.log")
  local keygen quote reg
  keygen=$(echo "$L" | grep "TLS key generation" | num)
  quote=$(echo "$L"  | grep "Quote generation"   | num)
  reg=$(echo "$L"    | grep "Credential issuance" | num)

  local dcp="-"
  if [ "$mode" = "redirection" ]; then
    local raw; raw=$(ssh_cmd "cd $CB && t0=\$(date +%s.%N); setsid $DCPROXY --listen 8443 --backend 127.0.0.1:8080 --sealed-dir $SEALED > /tmp/dcproxy.log 2>&1 < /dev/null & for i in \$(seq 1 500); do (echo >/dev/tcp/127.0.0.1/8443) 2>/dev/null && break; sleep 0.01; done; t1=\$(date +%s.%N); python3 -c \"print(f'{(\$t1-\$t0)*1000:.1f}')\"; fuser -k 8443/tcp 2>/dev/null")
    dcp=$(echo "$raw" | grep -oE '[0-9]+\.[0-9]+' | head -1)
  fi

  local FL; FL=$(docker logs --since "$SINCE" janus-frontend 2>&1)
  local maa reqs
  maa=$(echo "$FL" | grep "Attestation verification (backend)" | num)
  reqs=$(echo "$FL" | grep -c "$IP - -")
  echo "$mode,$run,${keygen:-NA},${quote:-NA},${maa:-NA},${reg:-NA},${reqs:-NA},${dcp:-NA}" | tee -a "$OUT"
}

for run in $(seq 1 "$N"); do run_one proxy "$run"; done
for run in $(seq 1 "$N"); do run_one redirection "$run"; done

echo ""; echo "=== per-mode summary (medians; MAA excludes sub-ms parse artifacts) ==="
python3 - "$OUT" <<'PY'
import csv,sys,statistics
rows=list(csv.DictReader(open(sys.argv[1])))
def med(r,c,flt=lambda v:True):
    v=[float(x[c]) for x in r if x[c] not in("NA","-","") and flt(float(x[c]))]
    return (statistics.median(v),min(v),max(v),len(v)) if v else (None,)*4
for mode in ("proxy","redirection"):
    r=[x for x in rows if x["mode"]==mode]
    print(f"[{mode}] n={len(r)}")
    for c in ("keygen_ms","quote_gen_ms","register_e2e_ms"):
        m=med(r,c);  print(f"   {c:16s} median {m[0]:.1f}  range {m[1]:.0f}-{m[2]:.0f}  (n={m[3]})") if m[0] else None
    m=med(r,"maa_verify_ms",lambda v:v>1.0); print(f"   {'maa_verify_ms':16s} median {m[0]:.1f}  range {m[1]:.0f}-{m[2]:.0f}  (n={m[3]})") if m[0] else None
    req=sorted({int(x['frontend_reqs']) for x in r if x['frontend_reqs'] not in('NA','')})
    print(f"   frontend_reqs    set={req}")
    if mode=="redirection":
        m=med(r,"dcproxy_ms"); print(f"   {'dcproxy_ms':16s} median {m[0]:.1f}  range {m[1]:.1f}-{m[2]:.1f}  (n={m[3]})") if m[0] else None
PY
