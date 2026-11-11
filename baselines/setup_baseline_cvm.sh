#!/bin/bash
# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear
# Prepare an Azure SEV-SNP CVM (Ubuntu 22.04) for the OHTTP+KMS gateway and the
# Oak server. Run this script on the CVM, in a clone of this repository.
# You can run it again safely.
#
#   bash baselines/setup_baseline_cvm.sh
#
# Installs: build toolchain, tpm2-tools, snpguest (janus/backend/fetch_snp_tools.sh),
# the Python packages of the backend plus pyhpke/noiseprotocol, then self-tests
# SNP evidence generation + MAA verification with the backend's own code.
set -euo pipefail
REPO="${REPO:-$(cd "$(dirname "$0")/.." && pwd)}"
cd "$REPO"

echo "[1/4] apt packages"
# wait for the apt lock that unattended-upgrades holds after a fresh boot, as deploy/backend_setup.sh does
APT="sudo DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=600"
$APT update -qq >/dev/null
$APT install -y -qq \
    python3-pip build-essential pkg-config libssl-dev curl git tpm2-tools >/dev/null

echo "[2/4] python packages"
sudo pip3 install -q -r janus/backend/requirements.txt \
    pyhpke==0.6.5 noiseprotocol==0.3.1 gunicorn==23.0.0 2>&1 | grep -v WARNING || true
python3 -c "import flask, cryptography, pyhpke, noise, gunicorn; print('  python packages OK')"

echo "[3/4] SNP evidence toolchain (snpguest + tpm2-tools)"
bash janus/backend/fetch_snp_tools.sh 2>&1 | tail -1

echo "[4/4] evidence self-test (build bundle, verify at MAA like the frontend)"
sudo env PYTHONPATH="$REPO" python3 - <<'EOF'
import time
from janus.common.snp_attestation import build_snp_evidence_bundle, verify_snp_bundle
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
k = ec.generate_private_key(ec.SECP256R1())
pub = k.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
t0 = time.time(); b = build_snp_evidence_bundle(nonce=b"selftest", pubkey_spki_der=pub); t1 = time.time()
ok, info = verify_snp_bundle(b, expected_nonce=b"selftest", expected_pubkey_spki_der=pub); t2 = time.time()
print("  bundle %d B, build %.0f ms, verify %.0f ms, verified=%s, tpm_quote=%s, measurement=%s..."
      % (len(b), (t1-t0)*1000, (t2-t1)*1000, ok, info.get("tpm_quote_verified"), info.get("measurement", "")[:16]))
assert ok
EOF

cat <<EOF

CVM ready.  If the Janus backend runs on this CVM, stop it first: its dc_proxy holds :8443 and
its backend server holds :8080.  Then start the application on 127.0.0.1:8080 and the services, e.g.:
  cd $REPO && export PYTHONPATH=$REPO:$REPO/baselines/ohttp:$REPO/baselines/oak
  # latency runs: the web app (the paper runs requested /, protocols.<oak|ohttp_kms>.path in eval/configs/env.yaml)
  nohup python3 apps/browser_app/app.py --port 8080 > /tmp/app.log 2>&1 &
  # throughput runs, instead: the rate-capped backend (10 req/s, as the Janus backends in Fig. 6)
  #   nohup python3 plotting/scalability_capped/capped_backend.py --bind 127.0.0.1 --port 8080 \\
  #     --workers 1 --service-ms 100 > /tmp/app.log 2>&1 &
  export KMS_URL=https://<kms-host>:6038 FRONTEND_URL=https://<fe-host>:6039 MY_IP=\$(hostname -I | awk '{print \$1}') \\
    OHTTP_TARGET=http://127.0.0.1:8080 FRONTEND_CA_CERT_PATH=insecure MAA_URL=<maa url of eval/configs/env.yaml> \\
    JANUS_BACKEND_SEALED_DIR=/dev/shm/ohttp-gateway-sealed
  read GW_CERT GW_KEY < <(sudo -E env PYTHONPATH=\$PYTHONPATH python3 -m ohttp.gateway --print-tls-files)
  sudo -E env PYTHONPATH=\$PYTHONPATH nohup python3 -m gunicorn --worker-class gthread --workers 1 --threads 32 \\
    --keep-alive 75 --certfile \$GW_CERT --keyfile \$GW_KEY -b 0.0.0.0:8443 'ohttp.gateway:create_app()' > /tmp/gateway.log 2>&1 &
  OAK_TARGET=127.0.0.1:8080 sudo -E env PYTHONPATH=\$PYTHONPATH nohup python3 -m oak.server --port 8543 > /tmp/oak.log 2>&1 &
(sudo: the vTPM device is root/tss-owned, as for the Janus backend. The gateway keeps its keys
in its own directory, so the Janus backend can start again on this CVM afterwards.)
EOF
