#!/bin/bash
# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

# Start (or restart) the Janus frontend container on an SGX host.
#   SEALED_DIR     host directory for the frontend's sealed state (identity survives restarts)
#   FRONTEND_PORT  client-facing port (6037)
#   EXTRA_SANS     comma-separated extra names for the certificate: the service name and every
#                  backend name browsers are redirected to (design §4.4); must resolve via DNS
#   IMAGE          janus/frontend-graminized (built by `make -C gramine signed-image MODULE=frontend`)
set -euo pipefail
SEALED_DIR="${SEALED_DIR:-$HOME/janus_frontend_sealed}"; FRONTEND_PORT="${FRONTEND_PORT:-6037}"
EXTRA_SANS="${EXTRA_SANS:?comma-separated SAN names}"; IMAGE="${IMAGE:-janus/frontend-graminized}"; NAME="${NAME:-janus-frontend}"
mkdir -p "$SEALED_DIR"
docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" -p "$FRONTEND_PORT:$FRONTEND_PORT" \
  --device /dev/sgx_enclave --device /dev/sgx_provision \
  -v "$SEALED_DIR":/home/janus/janus/frontend/sealed -v /var/run/aesmd:/var/run/aesmd \
  -e APP_HOME=/home/janus -e ISSUE_DC=1 -e SERVER_TYPE=sgx -e app_user=janus -e FRONTEND_PORT="$FRONTEND_PORT" \
  -e JANUS_EXTRA_SANS="$EXTRA_SANS" \
  -e AZDCAP_DEBUG_LOG_LEVEL=4 -e AZDCAP_COLLATERAL_VERSION=v4 -e AZDCAP_BASE_CERT_URL=https://global.acccache.azure.net/sgx/certification/v4/ \
  "$IMAGE" >/dev/null
for i in $(seq 1 60); do curl -sk "https://127.0.0.1:$FRONTEND_PORT/pool_status" >/dev/null 2>&1 && break; sleep 5; done
echo "frontend: $(curl -sk https://127.0.0.1:$FRONTEND_PORT/pool_status | cut -c1-80)"
openssl s_client -connect "127.0.0.1:$FRONTEND_PORT" </dev/null 2>/dev/null | openssl x509 -noout -ext subjectAltName | tail -1
