#!/bin/bash

# © 2024 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

# The entrypoint for all graminized containers

set -e

# Start Pebble CA in background if it exists
# This enables ACME certificate issuance for testing
# Pebble is copied to this location by the frontend or ratls server Dockerfile
APP_HOME="${APP_HOME:-/home/janus}"
PEBBLE_DIR="${PEBBLE_DIR:-$APP_HOME/pebble}"
if [ -f "$PEBBLE_DIR/pebble" ] && [ -f "$PEBBLE_DIR/pebble-config.json" ]; then
    echo "[Apploader] Starting Pebble CA in background..."
    cd "$PEBBLE_DIR"
    # Pebble is the test CA standing in for a public CA (per the paper). Skip
    # HTTP-01 reachability so it issues the frontend cert for the deployment's
    # service/backend SANs (JANUS_EXTRA_SANS) — a real public CA would issue for
    # the corresponding real domains. Browser-side guarantees (CA-trusted cert,
    # SAN match, DC validation) are unchanged. Override with PEBBLE_VA_ALWAYS_VALID=0.
    export PEBBLE_VA_ALWAYS_VALID="${PEBBLE_VA_ALWAYS_VALID:-1}"
    ./pebble -config pebble-config.json > /tmp/pebble.log 2>&1 &
    PEBBLE_PID=$!
    echo "[Apploader] Pebble CA started with PID $PEBBLE_PID"

    # Wait for Pebble to be ready (max 5 seconds)
    echo "[Apploader] Waiting for Pebble to be ready..."
    for i in {1..10}; do
        sleep 0.5
        if curl -k -s https://localhost:14000/dir > /dev/null 2>&1; then
            echo "[Apploader] ✓ Pebble CA is ready on https://localhost:14000"
            break
        fi
        if [ $i -eq 10 ]; then
            echo "[Apploader] ⚠ Pebble CA not responding after 5s, continuing anyway..."
            echo "[Apploader] Check logs: docker exec <container> cat /tmp/pebble.log"
        fi
    done
    cd /
else
    echo "[Apploader] Pebble CA not found - ACME will not be available"
fi

# Auto-detect container IP if MY_IP not set (for backend registration)
if [ -z "${MY_IP}" ]; then
    MY_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
    if [ -n "$MY_IP" ]; then
        export MY_IP
        echo "[Apploader] Auto-detected MY_IP=${MY_IP}"
    fi
fi

# Launch Gramine application
echo "[Apploader] Starting Gramine-SGX application..."
gramine-sgx entrypoint