#!/bin/bash
# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

#
# Startup script for the Janus back-end server with DC proxy.
#
# Architecture:
#   Client ─TLS+DC:8443─→ [dc_proxy] ─HTTP:127.0.0.1:8080─→ [Flask backend_server.py]
#
# Both run in the same container (same TEE attestation boundary).
#

set -e

FRONTEND_URL="${FRONTEND_URL:-https://frontend:6037}"
PUBLIC_PORT="${BACKEND_PORT:-8443}"      # externally exposed TLS port
APP_PORT="${BACKEND_APP_PORT:-8080}"      # local HTTP port for Flask
CVM_TYPE="${CVM_TYPE:-snp}"
# Sealed dir: on a real CVM the private key lives in RAM-backed storage and
# never touches the OS disk (design §3); mock/gramine testing keeps the disk
# path.  Exported so backend_server.py and dc_proxy use the same directory.
if [ -z "${SEALED_DIR}" ]; then
    if [ "${CVM_TYPE}" = "snp" ] || [ "${CVM_TYPE}" = "tdx" ]; then
        SEALED_DIR="${JANUS_BACKEND_SEALED_DIR:-/dev/shm/janus-backend-sealed}"
    else
        SEALED_DIR="${JANUS_BACKEND_SEALED_DIR:-${APP_HOME:-/home/janus}/janus/backend/sealed}"
    fi
fi
export JANUS_BACKEND_SEALED_DIR="${SEALED_DIR}"
mkdir -p "${SEALED_DIR}" && chmod 700 "${SEALED_DIR}"

# Auto-detect container IP if MY_IP not set explicitly
if [ -z "${MY_IP}" ]; then
    MY_IP=$(hostname -I | awk '{print $1}')
    echo "[Startup] Auto-detected MY_IP=${MY_IP}"
fi

echo "[Startup] Waiting for frontend at ${FRONTEND_URL}..."
for i in $(seq 1 40); do
    if curl -k -s "${FRONTEND_URL}/" > /dev/null 2>&1; then
        echo "[Startup] ✓ Frontend is ready"
        break
    fi
    if [ "$i" -eq 40 ]; then
        echo "[Startup] ⚠ Frontend not reachable after 20 s — starting anyway"
    fi
    sleep 0.5
done

# ── 1. Launch Flask backend server (plain HTTP on 127.0.0.1:APP_PORT) ──────
# This will register with the frontend and populate the sealed directory
# with the DC, frontend cert chain, and backend cert.
echo "[Startup] Starting Flask backend on 127.0.0.1:${APP_PORT} (plain HTTP)..."
cd "${APP_HOME:-/home/janus}"

python3 -m janus.backend.backend_server \
    --frontend-url "${FRONTEND_URL}"  \
    --cvm-type     "${CVM_TYPE}"      \
    --my-ip        "${MY_IP}"         \
    --port         "${APP_PORT}"      \
    --public-port  "${PUBLIC_PORT}"   \
    --bind         "127.0.0.1"        \
    --plain                           \
    --type         direct             &
FLASK_PID=$!

# Wait for Flask to come up and populate the sealed directory
echo "[Startup] Waiting for Flask + sealed credentials..."
for i in $(seq 1 60); do
    if [ -f "${SEALED_DIR}/delegated_credential.bin" ] && \
       [ -f "${SEALED_DIR}/frontend_chain.pem" ] && \
       [ -f "${SEALED_DIR}/private_key.pem" ] && \
       curl -s "http://127.0.0.1:${APP_PORT}/health" > /dev/null 2>&1; then
        echo "[Startup] ✓ Flask is ready and credentials are populated"
        break
    fi
    if [ "$i" -eq 60 ]; then
        echo "[Startup] ⚠ Flask/credentials not ready after 30 s"
        kill $FLASK_PID 2>/dev/null || true
        exit 1
    fi
    sleep 0.5
done

# ── 2. Launch dc_proxy (TLS+DC on 0.0.0.0:PUBLIC_PORT) ─────────────────────
echo "[Startup] Starting dc_proxy on :${PUBLIC_PORT} → 127.0.0.1:${APP_PORT}..."

DC_PROXY_BIN="${DC_PROXY_BIN:-${APP_HOME:-/home/janus}/dc_proxy}"
if [ ! -x "${DC_PROXY_BIN}" ]; then
    echo "[Startup] ⚠ dc_proxy binary not found at ${DC_PROXY_BIN}"
    echo "[Startup] Falling back to Flask HTTPS on ${PUBLIC_PORT}"
    kill $FLASK_PID 2>/dev/null || true
    exec python3 -m janus.backend.backend_server \
        --frontend-url "${FRONTEND_URL}" \
        --cvm-type     "${CVM_TYPE}"     \
        --my-ip        "${MY_IP}"        \
        --port         "${PUBLIC_PORT}"  \
        --type         direct
fi

# Trap signals to clean up Flask when proxy exits
trap "kill $FLASK_PID 2>/dev/null || true" EXIT INT TERM

exec "${DC_PROXY_BIN}" \
    --listen     "${PUBLIC_PORT}" \
    --backend    "127.0.0.1:${APP_PORT}" \
    --sealed-dir "${SEALED_DIR}"
