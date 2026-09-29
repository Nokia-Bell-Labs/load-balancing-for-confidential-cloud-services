#!/usr/bin/env bash
# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

# Capture the host environment for a measurement run.
#
# A CSV is only as reproducible as the environment that produced it; this
# script writes a JSON snapshot into the run dir so a result can always be
# tied back to the machine, libraries, and code version it came from.
#
# Usage: env_snapshot.sh <output_dir>

set -euo pipefail

OUT="${1:?usage: env_snapshot.sh <output_dir>}"
mkdir -p "$OUT"
SNAP="$OUT/env_snapshot.json"

# Best-effort field collection.  Missing tools yield "missing"; metadata
# service timeouts yield "unknown".  We never fail the snapshot.
_or() { local v; v="$("$@" 2>/dev/null)" || v=""; echo "${v:-missing}"; }
_imds() {
  local path="$1"
  local v
  v="$(curl -s -H Metadata:true -m 2 \
    "http://169.254.169.254/metadata/instance/compute/${path}?api-version=2021-02-01&format=text" \
    2>/dev/null)" || v=""
  echo "${v:-unknown}"
}
_json_str() { python3 -c 'import json,sys; print(json.dumps(sys.argv[1]))' "$1"; }

HOSTNAME_V="$(hostname)"
KERNEL_V="$(uname -srm)"
OS_V="$(. /etc/os-release 2>/dev/null && echo "$PRETTY_NAME" || echo missing)"
CPU_V="$(grep -m1 'model name' /proc/cpuinfo 2>/dev/null | sed 's/.*: //' || echo missing)"
NPROC_V="$(nproc 2>/dev/null || echo 0)"
MEM_KB_V="$(grep MemTotal /proc/meminfo 2>/dev/null | awk '{print $2}' || echo 0)"
VM_SIZE_V="$(_imds vmSize)"
REGION_V="$(_imds location)"
OPENSSL_V="$(_or openssl version)"
PYTHON_V="$(_or python3 --version)"
GRAMINE_V="$(_or gramine-sgx --version)"
GIT_COMMIT_V="$(_or git rev-parse HEAD)"
GIT_DIRTY_V=False
git diff --quiet 2>/dev/null || GIT_DIRTY_V=True

python3 - "$SNAP" <<PY
import json, sys
snap = {
    "snapshot_iso": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),
    "host":         $(_json_str "$HOSTNAME_V"),
    "kernel":       $(_json_str "$KERNEL_V"),
    "os":           $(_json_str "$OS_V"),
    "cpu_model":    $(_json_str "$CPU_V"),
    "cpu_count":    int("$NPROC_V" or 0),
    "mem_kb":       int("$MEM_KB_V" or 0),
    "azure_vm_size":$(_json_str "$VM_SIZE_V"),
    "azure_region": $(_json_str "$REGION_V"),
    "openssl":      $(_json_str "$OPENSSL_V"),
    "python":       $(_json_str "$PYTHON_V"),
    "gramine":      $(_json_str "$GRAMINE_V"),
    "git_commit":   $(_json_str "$GIT_COMMIT_V"),
    "git_dirty":    $GIT_DIRTY_V,
}
open(sys.argv[1], "w").write(json.dumps(snap, indent=2) + "\n")
PY

echo "wrote $SNAP"
