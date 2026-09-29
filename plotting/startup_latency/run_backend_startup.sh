#!/bin/bash
# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

# Historical collector for the paper's Table 1 (server side). Every value below is a parameter:
# override with environment variables; by default a NEW timestamped CSV is written next to this
# script so the archived CSV is never modified.
# Backend (SEV-SNP CVM) registration-latency repeats — REAL path: real HCL/VCEK/
# TPM evidence bundle + real Azure MAA /attest/SevSnpVm verify (frontend-side) +
# real frontend DC issuance. Runs on the frontend host (the SGX host); SSHes to the
# SNP CVM. Each run: kill any backend (by PORT — pkill -f self-matches the ssh
# shell), clear enclave-sealed dir (fresh keygen), launch backend_server as a
# module from the codebase clone, wait for the registration summary, parse the
# backend phase timings, and pull the frontend-side MAA-verify from docker logs.
#
# Phases (ms): keygen, SNP evidence/quote gen, MAA verify (frontend), DC E2E.
# Usage: bash run_backend_startup.sh [RUNS]
set -uo pipefail

RUNS="${1:-5}"
IP="${BACKEND_IP:?set BACKEND_IP to the backend CVM used for the startup test}"
KEY="${SSH_KEY:?set SSH_KEY to the private key that reaches the backend CVM}"
FRONTEND_URL="${FRONTEND_URL:?set FRONTEND_URL, e.g. https://<frontend-host>:6037}"
CB="${BACKEND_REPO:-/home/janus/Janus}"          # repo clone on the backend
OUT="${OUT:-$(cd "$(dirname "$0")" && pwd)/backend_startup-$(date -u +%Y%m%dT%H%M%SZ).csv}"

ssh_cmd() { ssh -i "$KEY" -o StrictHostKeyChecking=no -o ConnectTimeout=10 "${SSH_USER:-$USER}@${IP}" "$@" 2>/dev/null; }
num() { grep -oP '[0-9.]+(?= ms)' | tail -1; }

echo "run,keygen_ms,quote_gen_ms,maa_verify_ms,dc_e2e_ms" > "$OUT"

for run in $(seq 1 "$RUNS"); do
  echo "--- backend registration run $run/$RUNS ---"
  SINCE="$(date -u +%Y-%m-%dT%H:%M:%S)"
  ssh_cmd "fuser -k 8443/tcp 8080/tcp 2>/dev/null; sleep 1; rm -f $CB/janus/backend/sealed/*.pem $CB/janus/backend/sealed/*.db 2>/dev/null; cd $CB && setsid env APP_HOME=$CB python3 -m janus.backend.backend_server --frontend-url $FRONTEND_URL --cvm-type snp --my-ip $IP --port 8443 --type cvm > /tmp/be_run.log 2>&1 < /dev/null & sleep 1; for i in \$(seq 1 90); do grep -q 'BACKEND STARTUP LATENCY' /tmp/be_run.log 2>/dev/null && break; sleep 1; done"
  L="$(ssh_cmd 'cat /tmp/be_run.log')"

  keygen=$(echo "$L"   | grep "TLS key generation"   | num)
  quote=$(echo "$L"    | grep "Quote generation"     | num)
  dce2e=$(echo "$L"    | grep "Credential issuance"  | num)
  # frontend-side real MAA verification of this backend's SNP bundle
  maa=$(docker logs --since "$SINCE" janus-frontend 2>&1 | grep "Attestation verification (backend)" | num)

  echo "$run,${keygen:-NA},${quote:-NA},${maa:-NA},${dce2e:-NA}" | tee -a "$OUT"
done

echo ""; echo "=== averages (numeric rows only) ==="
awk -F, 'NR>1 && $2!="NA"{for(j=2;j<=NF;j++){s[j]+=$j;n[j]++}} END{
  split("run keygen quote_gen maa_verify dc_e2e",h," ");
  for(j=2;j<=5;j++) if(n[j]) printf "  %-14s %8.2f ms  (n=%d)\n", h[j], s[j]/n[j], n[j]}' "$OUT"
