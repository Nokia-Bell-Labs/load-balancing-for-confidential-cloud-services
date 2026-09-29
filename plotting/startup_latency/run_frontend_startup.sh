#!/bin/bash
# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

# Historical collector for the paper's Table 1 (server side). Every value below is a parameter:
# override with environment variables; by default a NEW timestamped CSV is written next to this
# script so the archived CSV is never modified.
# Frontend (SGX/Gramine) startup-latency repeats — REAL path (real SGX quote,
# real Azure MAA, real Pebble ACME). For each run: stop the graminized frontend
# container, clear the enclave-sealed dir (forces fresh keypair -> full bootstrap),
# restart, wait for the FRONTEND STARTUP LATENCY summary, and extract the phase
# timings from that run's logs (isolated via `docker logs --since`).
#
# Phases captured (ms): keypair gen (server+CA), SGX quote gen, MAA round trip
# (own JWT), ACME issuance total, ACME HTTP-01 domain validation, ACME finalize
# (= CA signs the CSR).
#
# Usage: bash run_frontend_startup.sh [RUNS]
set -uo pipefail

RUNS="${1:-5}"
CTR="${FRONTEND_CONTAINER:-janus-frontend}"          # the frontend container to restart
SEALED="${FRONTEND_SEALED_DIR:?set FRONTEND_SEALED_DIR to a DISPOSABLE sealed directory of a startup-test frontend}"
OUT="${OUT:-$(cd "$(dirname "$0")" && pwd)/frontend_startup-$(date -u +%Y%m%dT%H%M%SZ).csv}"
# Model a REMOTE public CA: inject one-way delay on the container's loopback
# (frontend<->bundled Pebble path) so ACME pays a realistic RTT per round trip.
# CA_DELAY_MS is one-way; RTT = 2*CA_DELAY_MS. Default 20ms => 40ms RTT (matches
# the apps eval). Set CA_DELAY_MS=0 to measure the co-located (no-WAN) baseline.
CA_DELAY_MS="${CA_DELAY_MS:-20}"

echo "run,keygen_ms,quote_ms,maa_own_ms,acme_total_ms,acme_validate_ms,acme_finalize_ms" > "$OUT"

num() { grep -oP '[0-9.]+(?= ms)' | tail -1; }

for i in $(seq 1 "$RUNS"); do
  echo "--- frontend startup run $i/$RUNS ---"
  docker stop "$CTR" >/dev/null 2>&1 || true
  rm -f "$SEALED"/server_private_key.pem "$SEALED"/tls_certificate.pem \
        "$SEALED"/ca_*.pem "$SEALED"/keystore.db 2>/dev/null || true
  SINCE="$(date -u +%Y-%m-%dT%H:%M:%S)"
  docker start "$CTR" >/dev/null 2>&1

  # Re-apply the CA-path delay inside the (fresh) container netns before the
  # bootstrap reaches ACME. Container restart wipes the qdisc, so do it each run.
  if [ "$CA_DELAY_MS" -gt 0 ]; then
    PID=$(docker inspect -f '{{.State.Pid}}' "$CTR" 2>/dev/null)
    sudo nsenter -t "$PID" -n tc qdisc add dev lo root netem delay "${CA_DELAY_MS}ms" 2>/dev/null \
      && echo "    [netem] ${CA_DELAY_MS}ms one-way on lo (RTT $((2*CA_DELAY_MS))ms) for run $i"
  fi

  # wait (bounded) for this run's startup summary to appear
  for w in $(seq 1 40); do
    if docker logs --since "$SINCE" "$CTR" 2>&1 | grep -q "FRONTEND STARTUP LATENCY"; then break; fi
    sleep 2
  done
  L="$(docker logs --since "$SINCE" "$CTR" 2>&1)"

  keygen=$(echo "$L"   | grep "TLS key generation (server + CA)" | num)
  quote=$(echo "$L"    | grep "SGX Quote generation"            | num)
  maa=$(echo "$L"      | grep "Azure MAA verification (own)"    | num)
  acme=$(echo "$L"     | grep "ACME certificate issuance"       | num)
  validate=$(echo "$L" | grep -A1 "Challenge answered"          | grep "⏱ Time" | num)
  finalize=$(echo "$L" | grep -A2 "Order finalized"            | grep "⏱ Time" | num)

  echo "$i,$keygen,$quote,$maa,$acme,$validate,$finalize" | tee -a "$OUT"
done

echo ""; echo "=== averages ==="
awk -F, 'NR>1{for(j=2;j<=NF;j++){s[j]+=$j;n[j]++}} END{
  split("run keygen quote maa_own acme_total acme_validate acme_finalize",h," ");
  for(j=2;j<=7;j++) printf "  %-16s %8.2f ms\n", h[j], s[j]/n[j]}' "$OUT"
