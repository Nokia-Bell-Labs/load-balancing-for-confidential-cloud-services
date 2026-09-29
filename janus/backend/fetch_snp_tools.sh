#!/usr/bin/env bash
# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

# Fetch + build the SEV-SNP attestation toolchain the backend needs to produce
# raw evidence. janus/common/snp_attestation.py shells out to:
#   - snpguest  (virtee, pinned tag) — read the SNP report, fetch VCEK/CA chain
#   - tpm2-tools (apt)               — tpm2_nvread (HCL report @ NV 0x01400001),
#                                      tpm2_quote (per-connection binding)
#
# Run this ON the SNP backend CVM (it installs a system package and a binary
# into /usr/local/bin, and reads /dev/tpm0 at runtime). Re-runnable.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="https://github.com/virtee/snpguest.git"
TAG="v0.10.0"
DEST="${1:-$HERE/snpguest}"
PREFIX="${PREFIX:-/usr/local/bin}"

# 1. tpm2-tools (provides tpm2_nvread / tpm2_quote)
if ! command -v tpm2_nvread >/dev/null 2>&1; then
    echo "[snp-tools] installing tpm2-tools (apt)"
    sudo apt-get update -qq
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends tpm2-tools
else
    echo "[snp-tools] tpm2-tools already present"
fi

# 2. Rust toolchain — snpguest is built from source at the pinned tag. Ubuntu's
#    apt cargo can be too old for recent snpguest, so prefer rustup if cargo is
#    absent.
if ! command -v cargo >/dev/null 2>&1; then
    echo "[snp-tools] installing Rust toolchain (rustup)"
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    # shellcheck disable=SC1091
    . "$HOME/.cargo/env"
fi

# 3. snpguest @ pinned tag
if [ ! -d "$DEST/.git" ]; then
    echo "[snp-tools] cloning snpguest $TAG -> $DEST"
    git clone -q "$REPO" "$DEST"
fi
git -C "$DEST" checkout -q "$TAG"

echo "[snp-tools] building snpguest $TAG (cargo, release)"
( cd "$DEST" && cargo build --release )
sudo install -m 0755 "$DEST/target/release/snpguest" "$PREFIX/snpguest"

echo "[snp-tools] done -> $PREFIX/snpguest ($("$PREFIX/snpguest" --version 2>/dev/null || echo installed)); tpm2-tools via apt"
