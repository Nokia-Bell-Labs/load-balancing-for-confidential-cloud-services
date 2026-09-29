#!/bin/bash
# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

# Install and start the Janus back-end server on a freshly provisioned CVM.
#
# Environment variables (set by the frontend provisioner before calling this script):
#   FRONTEND_URL  – base URL of the frontend server  (e.g. https://10.0.0.4:6037)
#   CVM_TYPE      – 'snp' or 'tdx'
#   BACKEND_PORT  – HTTPS port for this backend (default: 8443)

set -e

BACKEND_PORT=${BACKEND_PORT:-8443}
CVM_TYPE=${CVM_TYPE:-snp}
FRONTEND_URL=${FRONTEND_URL:-"https://localhost:6037"}
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "[install_backend] CVM_TYPE=$CVM_TYPE  FRONTEND_URL=$FRONTEND_URL  PORT=$BACKEND_PORT"

# ── 1. System packages ────────────────────────────────────────────────────────
sudo apt-get update -qq
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    python3 python3-pip python3-venv \
    build-essential pkg-config libssl-dev curl git wget

# ── 2. Python dependencies ────────────────────────────────────────────────────
sudo pip3 install --quiet flask "cryptography>=42.0.0" requests python-dotenv

# ── 3. SEV-SNP attestation toolchain (snpguest + tpm2-tools) ─────────────────
# The live registration flow produces raw SNP evidence with these tools
# (janus/common/snp_attestation.py: snpguest report/fetch + tpm2_nvread/quote).
# Pinned and built by the co-located fetch script.
"$HERE/fetch_snp_tools.sh"

# ── 4. Create working directory ───────────────────────────────────────────────
WORKDIR="$HOME/janus_backend"
mkdir -p "$WORKDIR/static"

cp "$HOME/backend_server.py"   "$WORKDIR/"
cp "$HOME/index.html"          "$WORKDIR/static/" 2>/dev/null || true
cp "$HOME/style.css"           "$WORKDIR/static/" 2>/dev/null || true

mkdir -p "$WORKDIR/sealed"

# ── 5. Detect public IP ───────────────────────────────────────────────────────
# Try Azure IMDS for the instance-level public IP; fall back to private IP if
# IMDS returns empty (NAT'd public IPs are not exposed via IMDS).
MY_IP=$(curl -sf --max-time 5 -H "Metadata: true" \
    "http://169.254.169.254/metadata/instance/network/interface/0/ipv4/ipAddress/0/publicIpAddress?api-version=2021-02-01&format=text" 2>/dev/null)
if [ -z "$MY_IP" ]; then
    MY_IP=$(hostname -I | awk '{print $1}')
fi
echo "[install_backend] My IP: $MY_IP"

# ── 6. Start backend server ───────────────────────────────────────────────────
export FRONTEND_URL CVM_TYPE BACKEND_PORT APP_HOME="$HOME"

nohup python3 "$WORKDIR/backend_server.py" \
    --frontend-url "$FRONTEND_URL" \
    --cvm-type     "$CVM_TYPE"     \
    --my-ip        "$MY_IP"        \
    --port         "$BACKEND_PORT" \
    --type         cvm             \
    > "$WORKDIR/backend.log" 2>&1 &

echo "[install_backend] Backend server started (PID $!)"
echo "[install_backend] Logs: $WORKDIR/backend.log"
