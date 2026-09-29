#!/bin/bash
# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

#
# Startup script for the Janus Frontend Server
# Starts Pebble CA in background, then launches the frontend server.
#

set -e

echo "[Startup] Starting Pebble CA in background..."

cd "${APP_HOME:-/home/janus}/pebble"
# Pebble is the test CA. PEBBLE_VA_ALWAYS_VALID lets it issue the frontend's
# cert for the deployment's service/backend SANs (JANUS_EXTRA_SANS) without an
# HTTP-01 challenge reachable at those private test hostnames. The browser-side
# guarantees we rely on (CA-trusted cert, SAN match, DC validation) are
# unaffected; in production the frontend uses a real CA cert for real domains.
export PEBBLE_VA_ALWAYS_VALID="${PEBBLE_VA_ALWAYS_VALID:-1}"
./pebble -config pebble-config.json > /tmp/pebble.log 2>&1 &
PEBBLE_PID=$!

echo "[Startup] Pebble CA started with PID $PEBBLE_PID"
echo "[Startup] Waiting for Pebble to be ready..."

for i in {1..20}; do
    sleep 0.5
    if curl -k -s https://localhost:14000/dir > /dev/null 2>&1; then
        echo "[Startup] ✓ Pebble CA is ready"
        break
    fi
    if [ $i -eq 20 ]; then
        echo "[Startup] ⚠ Pebble CA timeout — continuing anyway"
    fi
done

echo "[Startup] Starting Janus frontend server (type=${SERVER_TYPE:-direct})..."
cd "${APP_HOME:-/home/janus}"

exec python3 -m janus.frontend.frontend_server \
    --type "${SERVER_TYPE:-direct}" \
    --port "${FRONTEND_PORT:-6037}"
