#!/usr/bin/env bash
# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

# Fetch the microservice workload: DeathStarBench hotelReservation at the pinned
# commit (see ../../docs/DEPENDENCIES.md). It is used UNMODIFIED — no Janus patch.
#
#   ./fetch.sh [DEST]      # default DEST: ./DeathStarBench (gitignored)
set -euo pipefail

REPO="https://github.com/delimitrou/DeathStarBench.git"
COMMIT="6ecb09706140f8730b5385c08f1386c654c3c526"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEST="${1:-$HERE/DeathStarBench}"

if [ -d "$DEST/.git" ]; then
    echo "[microservice] $DEST exists — checking out $COMMIT"
    git -C "$DEST" fetch origin
else
    echo "[microservice] cloning DeathStarBench -> $DEST"
    git clone "$REPO" "$DEST"
fi
git -C "$DEST" checkout "$COMMIT"

echo "[microservice] ready: $DEST/hotelReservation (pinned $COMMIT, unmodified)"
echo "  Bring it up with its own docker-compose and front the 'frontend' service"
echo "  (:5000); see README.md. No patch is applied — the service is stock."
