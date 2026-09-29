#!/bin/bash
# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

# Table 2 and Fig. 5: connection-establishment latency against RTT, five protocols.
#
# For each RTT, the script injects a one-sided egress delay on the interface of this client.
# See eval/README.md, section "RTT series and backend-scaling runs". It runs the measurement scripts for all five
# protocols. It uses a warm and a cold AS-key cache (n=200 after 30 warm-ups each). Then it clears the
# delay.  Raw per-attempt CSVs land in eval/data/ae-rtt-<R>/. The summary.csv in
# each directory holds the medians that Table 2 reports.  ~1 h for the four RTTs of the paper.
#
#   ./run_table2_fig5.sh            # RTTs 0 40 80 120 (Table 2)
#   ./run_table2_fig5.sh 0 40           # a subset (Fig. 5 plots the same four RTTs as Table 2)
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; ROOT="$(cd "$HERE/../.." && pwd)"; source "$HERE/testbed.env"; python3 "$HERE/render_env.py" >/dev/null || { echo "testbed.env is incomplete"; exit 1; }
RTTS=("$@"); [ ${#RTTS[@]} -eq 0 ] && RTTS=(0 40 80 120)
# PROTOCOLS="vanilla ctls_proxy" ./run_table2_fig5.sh 0   restricts the run (default: all five)
PROTOCOLS="${PROTOCOLS:-vanilla ctls_proxy ctls_redirect httpa ratls}"
cleanup() { sudo tc qdisc del dev "$IFACE" root 2>/dev/null || true; }
trap cleanup EXIT
cd "$ROOT/eval"
# A second run keeps the earlier data: eval/data/<run> moves to eval/data/previous/.
keep_previous() { [ -d "data/$1" ] || return 0; mkdir -p data/previous; mv "data/$1" "data/previous/$1-$(date -u +%Y%m%dT%H%M%SZ)"; echo "    (earlier data/$1 kept under data/previous/)"; }
for R in "${RTTS[@]}"; do
  cleanup
  if [ "$R" -gt 0 ]; then sudo tc qdisc add dev "$IFACE" root netem delay "${R}ms"; fi
  echo "==> RTT +${R} ms: $(sudo tc qdisc show dev "$IFACE" | head -1)"
  keep_previous "${AE_RUN:-ae}-rtt-$R"
  # The paper reports the warm-cache medians (Table 2, Fig. 5). COLD=1 also runs the cold-cache pass.
  make eval-warm RUN_ID="${AE_RUN:-ae}-rtt-$R" RATLS_PYTHON="$RATLS_PYTHON" PROTOCOLS="$PROTOCOLS"
  [ "${COLD:-0}" = 1 ] && make eval-cold RUN_ID="${AE_RUN:-ae}-rtt-$R" RATLS_PYTHON="$RATLS_PYTHON" PROTOCOLS="$PROTOCOLS"
  make aggregate RUN_ID="${AE_RUN:-ae}-rtt-$R"
done
cleanup
echo
echo "Medians (ms) per protocol (Table 2):"
for R in "${RTTS[@]}"; do
  echo "--- RTT +$R ms  (eval/data/${AE_RUN:-ae}-rtt-$R/summary.csv)"
  python3 - "$ROOT/eval/data/${AE_RUN:-ae}-rtt-$R/summary.csv" <<'PY'
import csv, sys
for r in csv.DictReader(open(sys.argv[1])):
    if r.get("cache_policy", "warm") != "warm": continue
    p50 = r.get("p50_total_e2e_ms") or r.get("p50_ms") or next((v for k, v in r.items() if k.startswith("p50")), "?")
    print(f"   {r.get('protocol','?'):14s} p50 {p50}")
PY
done
echo "Next: eval/ae/make_figures.sh  (renders Fig. 5 from these runs)"
