#!/bin/bash
# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

# Frontend resource profiler — samples the SGX frontend container's CPU/mem
# while a scale run is in flight, for the Overhead subsection (control-plane
# cost of the frontend as backend count / load scales).
#
# Usage: fe_profiler.sh <out.csv> <duration_s> [container]
# Run ON the frontend host (the SGX host). Sample every 1s via `docker stats`.
set -u
OUT="${1:?out.csv}"; DUR="${2:?duration_s}"; C="${3:-ctls-frontend}"
echo "ts_unix,cpu_pct,mem_used_mb,mem_pct,net_io,pids" > "$OUT"
end=$(( $(date +%s) + DUR ))
while [ "$(date +%s)" -lt "$end" ]; do
  # one-shot stats; strip % and units to numeric where easy
  line=$(docker stats --no-stream --format '{{.CPUPerc}};{{.MemUsage}};{{.MemPerc}};{{.NetIO}};{{.PIDs}}' "$C" 2>/dev/null)
  cpu=$(echo "$line" | cut -d';' -f1 | tr -d '%')
  memu=$(echo "$line" | cut -d';' -f2 | awk '{print $1}')
  memp=$(echo "$line" | cut -d';' -f3 | tr -d '%')
  net=$(echo "$line" | cut -d';' -f4 | tr -d ' ')
  pids=$(echo "$line" | cut -d';' -f5)
  echo "$(date +%s),${cpu:-NA},${memu:-NA},${memp:-NA},${net:-NA},${pids:-NA}" >> "$OUT"
done
