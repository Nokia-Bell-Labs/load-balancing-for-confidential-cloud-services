#!/bin/bash
# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

# Bring up one capped scalability backend on a cTLS-backend-* CVM.
#   start_capped_backend.sh <my_ip> <frontend_url> [service_ms] [max_inflight]
# service_ms=0 => uncapped (for frontend-ceiling calibration).
#
# Architecture: backend_server.py serves PLAIN HTTP on :8080 (registers with the
# frontend -> fresh DC in /home/janus/ctls/backend/sealed) with the CTLS_SERVICE_MS
# rate cap; dc_proxy(DC):8443 -> :8080 fronts it for redirect clients. The frontend
# /forward (proxy mode) hits :8080 directly. Both modes terminate at the capped
# backend_server, so the cap applies to both.
set -u
MY_IP="${1:?my_ip}"; FE="${2:?frontend_url}"; SVC="${3:-0}"; INF="${4:-0}"
SEALED=/home/janus/ctls/backend/sealed
cd /home/janus/ctls_backend || exit 1

pkill -f backend_server.py 2>/dev/null
pkill -f 'dc_proxy_new --listen 8443' 2>/dev/null
sleep 1

# These CVMs are clones with an identical sealed EC keypair -> identical cvm_id,
# which the frontend dedups into a single pool entry. Clear the sealed identity
# so backend_server.py generates a FRESH distinct keypair (distinct cvm_id) and
# the frontend pool gets one entry per backend (required for round-robin).
rm -f "$SEALED"/* 2>/dev/null

export APP_HOME="${APP_HOME:-/home/janus}" PYTHONPATH="${JANUS_REPO:-/home/janus/Janus}"
export CTLS_SERVICE_MS="$SVC" CTLS_MAX_INFLIGHT="$INF"
nohup python3 backend_server.py --frontend-url "$FE" --cvm-type snp \
    --my-ip "$MY_IP" --port 8080 --plain --type cvm \
    > /tmp/be.log 2>&1 &
echo "[start] backend_server (plain :8080, cap svc=${SVC}ms inflight=${INF}) launched"

# wait for plain serve + registration
for i in $(seq 1 40); do
    curl -s -m2 http://127.0.0.1:8080/health >/dev/null 2>&1 && break
    sleep 1
done
if ! curl -s -m2 http://127.0.0.1:8080/health >/dev/null 2>&1; then
    echo "[start] ERROR backend_server not serving :8080"; tail -5 /tmp/be.log; exit 1
fi

# dc_proxy(DC) :8443 -> :8080 for redirect clients
nohup /home/janus/dc_proxy_new --listen 8443 --backend 127.0.0.1:8080 \
    --sealed-dir "$SEALED" > /tmp/dcp.log 2>&1 &
echo "[start] dc_proxy(DC) :8443 -> :8080 launched (sealed=$SEALED)"
sleep 2

echo "[start] be8080=$(curl -s -m3 http://127.0.0.1:8080/health)"
if (echo >/dev/tcp/127.0.0.1/8443) 2>/dev/null; then echo "[start] dcp8443=UP"; else echo "[start] dcp8443=DOWN"; tail -3 /tmp/dcp.log; fi
