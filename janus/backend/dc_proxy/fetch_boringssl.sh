#!/usr/bin/env bash
# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

# Fetch + build BoringSSL for dc_proxy: clone the pinned commit, apply the
# RFC 9345 Delegated-Credential server patch, and build the static libs the
# Makefile links. See boringssl-dc.patch.README.
#
#   ./fetch_boringssl.sh        # checkout into ./boringssl (gitignored), then `make`
set -euo pipefail

REPO="https://boringssl.googlesource.com/boringssl"
COMMIT="d258906c992e30c07328eac375f2c6a4a0f30fd9"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEST="${BORINGSSL:-$HERE/boringssl}"
PATCH="$HERE/boringssl-dc.patch"

if [ ! -d "$DEST/.git" ]; then
    echo "[dc_proxy] cloning BoringSSL -> $DEST"
    git clone "$REPO" "$DEST"
fi
git -C "$DEST" checkout "$COMMIT"

echo "[dc_proxy] applying boringssl-dc.patch"
if git -C "$DEST" apply --check "$PATCH" 2>/dev/null; then
    git -C "$DEST" apply "$PATCH"
    echo "  patch applied"
elif git -C "$DEST" apply --reverse --check "$PATCH" 2>/dev/null; then
    echo "  patch already applied"
else
    echo "  ERROR: boringssl-dc.patch does not apply cleanly to $COMMIT" >&2
    exit 1
fi

echo "[dc_proxy] building BoringSSL (cmake, Release)"
cmake -S "$DEST" -B "$DEST/build" -DCMAKE_BUILD_TYPE=Release
cmake --build "$DEST/build"

echo "[dc_proxy] done — static libs at $DEST/build/{libssl,libcrypto}.a"
echo "  Build dc_proxy with:  make            (BORINGSSL defaults to ./boringssl)"
