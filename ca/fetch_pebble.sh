#!/usr/bin/env bash
# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

# Fetch + patch Pebble for the Janus CA: clone the pinned upstream tag, apply
# our changes (pebble-janus.patch), and build the pebble binary. Re-runnable.
#
# Our changes (see pebble-janus.patch): ca/ca.go — preserve the AS-JWT/SGX
# (OID 1.3.6.1.4.1.99999.3.*) and RFC 9345 DelegationUsage (44363.44) extensions
# from the CSR, load a persistent CA chain, and honor PEBBLE_CA_CERTS_DIR/$HOME;
# plus the SGX tests, the ca_certs/ chain generator, and the deployment config.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="https://github.com/letsencrypt/pebble.git"
TAG="v2.9.0"
DEST="${1:-$HERE/pebble}"
PATCH="$HERE/pebble-janus.patch"

if [ ! -d "$DEST/.git" ]; then
    echo "[ca] cloning Pebble $TAG -> $DEST"
    git clone -q "$REPO" "$DEST"
    git -C "$DEST" checkout -q "$TAG"
fi

echo "[ca] applying pebble-janus.patch"
if git -C "$DEST" apply --reverse --check "$PATCH" 2>/dev/null; then
    echo "  patch already applied"
elif git -C "$DEST" apply --check "$PATCH" 2>/dev/null; then
    git -C "$DEST" apply "$PATCH"
    echo "  patch applied"
else
    echo "  ERROR: pebble-janus.patch does not apply ($DEST must be a clean $TAG checkout)" >&2
    exit 1
fi

echo "[ca] building pebble (Go >= 1.22 installed; go.mod asks for 1.24, which the Go toolchain downloads on first build)"
( cd "$DEST" && go build -o pebble ./cmd/pebble )

# Install the Janus HTTPS-cert helper into the clone. This is a Janus file (not
# upstream Pebble); the frontend image build runs it to sign Pebble's listener
# cert with the Janus CA. Without it the frontend Dockerfile's ADD of
# test/certs/generate_pebble_cert.sh fails on a clean checkout.
install -m 0755 "$HERE/generate_pebble_cert.sh" "$DEST/test/certs/generate_pebble_cert.sh"

echo "[ca] done -> $DEST/pebble (+ test/certs/generate_pebble_cert.sh)"
# The CA chain the frontend image bakes in (root + intermediate; regenerate by deleting ca_certs/*.pem)
if [ ! -f "$DEST/ca_certs/root-ca.pem" ]; then
    echo "[ca] generating the CA chain (ca_certs/generate_ca_certificates.sh)"
    ( cd "$DEST/ca_certs" && bash ./generate_ca_certificates.sh >/dev/null )
fi
echo "[ca] CA chain: $DEST/ca_certs/root-ca.pem (+ intermediate) — ready for 'docker compose up --build'"
