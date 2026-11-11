#!/bin/bash
# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear
# Start Pebble (ACME CA) then the OHTTP+KMS role (frontend code + ohttp.kms).
# Same shape as janus/frontend/start_with_pebble.sh.
set -e
cd "${APP_HOME:-/home/janus}/pebble"
export PEBBLE_VA_ALWAYS_VALID="${PEBBLE_VA_ALWAYS_VALID:-1}"
./pebble -config pebble-config.json > /tmp/pebble.log 2>&1 &
for i in {1..20}; do
    sleep 0.5
    curl -k -s https://localhost:14000/dir > /dev/null 2>&1 && break
done
cd "${APP_HOME:-/home/janus}"
exec python3 -m ohttp.kms --type "${SERVER_TYPE:-direct}" --port "${FRONTEND_PORT:-6038}"
