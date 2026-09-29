#!/bin/bash
# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

# Fig. 6: maximum sustained throughput against the number of backends (scale-out).
#
# The pool of the frontend holds N registered, rate-capped backends (c = 10 req/s
# each, plotting/scalability_capped/capped_backend.py). The authors set N for
# the evaluation window that you announced (see docs/ACCESS.md). The pre-flight check
# prints the current pool size.  This script drives the open-loop Poisson
# run (eval/configs/runs.yaml, `scale:`) and records the peak achieved rate
# per protocol. make_figures.sh assembles the points into the figure.
#
#   ./run_fig6.sh <N>                       # Janus proxy + redirection at this N
#   ./run_fig6.sh 1 --with-baselines        # N=1 also runs vanilla, RA+TLS, HTTPA/2
#
# ~7 min per N (10 offered rates x 19 s x 2 protocols) + ~8 min for the baselines, on the grids of the paper.
# The points of the paper are N = 1, 2, 4, 8, 16, 32. The standing pool has 4. We set larger pools for your window.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; ROOT="$(cd "$HERE/../.." && pwd)"; source "$HERE/testbed.env"; python3 "$HERE/render_env.py" >/dev/null || { echo "testbed.env is incomplete"; exit 1; }
N="${1:?usage: run_fig6.sh <N> [--with-baselines]}"; shift || true
[[ "$N" =~ ^[1-9][0-9]*$ ]] || { echo "N must be a positive integer (got '$N')"; exit 2; }
IN_SERVICE=$(python3 - "$FRONTEND_HOST" "$FRONTEND_PORT" <<'PY'
import sys, ssl, json, urllib.request
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
d = json.load(urllib.request.urlopen(f"https://{sys.argv[1]}:{sys.argv[2]}/pool_status", context=ctx, timeout=10))
print(sum(1 for b in d["backends"] if b["cvm_mode"] == "in-service"))
PY
)
[ "$IN_SERVICE" = "$N" ] || { echo "the pool has $IN_SERVICE backend(s) in service, not $N. You cannot measure this point now (docs/ACCESS.md: pool size per window)"; exit 2; }
PROTOS="ctls_proxy ctls_redirect"; WITH_BASELINES=0
[ "${1:-}" = "--with-baselines" ] && { PROTOS="vanilla ctls_proxy ctls_redirect ratls httpa"; WITH_BASELINES=1; }
cd "$ROOT/eval"
# A second run keeps the earlier data: eval/data/<run> moves to eval/data/previous/.
keep_previous() { [ -d "data/$1" ] || return 0; mkdir -p data/previous; mv "data/$1" "data/previous/$1-$(date -u +%Y%m%dT%H%M%SZ)"; echo "    (earlier data/$1 kept under data/previous/)"; }
sudo tc qdisc del dev "$IFACE" root 2>/dev/null || true      # scale-out runs at native RTT
# The frontend relays every proxy-mode request to a backend (GET /forward/health), as in
# the runs of the paper. The latency run (Table 2) measures establishment only and
# hits the frontend index (eval/clients/ctls_proxy.py).
export JANUS_PROXY_PATH=/forward/health
# Redirection: the client makes the control connection (frontend /route, attestation check) once.
# It amortizes it over the pool, as in the Fig. 6 runs of the paper. The Fig. 6 runs of the paper had no per-request control phases (eval/clients/ctls_redirect.py).
# Table 2 measures it per attempt instead.
export JANUS_AMORTIZE_CONTROL=1
# The Janus backends and the vanilla front answer the rate-capped /health (the capped microbenchmark
# endpoint of the paper. The same capped handler served vanilla, plotting/scalability_capped/vanilla_capped.py).
# The RA+TLS and HTTPA/2 baseline servers have the same rate cap as the Janus backends, c = 10 req/s.
# This is pool profile "scale", as in the Fig. 6 runs of the paper. Their throughput stays below the cap anyway.
# Their per-connection attestation limits it.
export JANUS_PAYLOAD_PATH=/health
# The offered-rate grid and window of the runs of the paper:
# N <= 8: 25..300 req/s in 10 steps. N >= 16: 50..500. 4 s warm-up and a 15 s window per step.
if [ "$N" -le 8 ]; then export JANUS_SCALE_RATES=25,50,75,100,125,150,175,200,250,300; else export JANUS_SCALE_RATES=50,100,150,200,250,300,350,400,450,500; fi
export JANUS_SCALE_WARMUP_S=4 JANUS_SCALE_WINDOW_S=15
echo "==> N=$N, protocols: $PROTOS"
keep_previous "${AE_RUN:-ae}-scale-N$N"
make eval-scale RUN_ID="${AE_RUN:-ae}-scale-N$N" PROTOCOLS="ctls_proxy ctls_redirect" RATLS_PYTHON="$RATLS_PYTHON"
if [ "$WITH_BASELINES" = 1 ]; then
  # The single-server baselines have their own offered-rate grids, as in the paper.
  JANUS_SCALE_RATES=8,12,15,20,30,50,75,100,150,200 make eval-scale RUN_ID="${AE_RUN:-ae}-scale-N$N" PROTOCOLS="vanilla" RATLS_PYTHON="$RATLS_PYTHON"
  JANUS_SCALE_RATES=4,6,8,10,12,15,20,30 make eval-scale RUN_ID="${AE_RUN:-ae}-scale-N$N" PROTOCOLS="ratls httpa" RATLS_PYTHON="$RATLS_PYTHON"
fi
echo
echo "Peak achieved rate (req/s) at N=$N (Fig. 6):"
for p in $PROTOS; do
  f="data/${AE_RUN:-ae}-scale-N$N/${p}_scale_warm_steps.csv"
  [ -f "$f" ] && python3 -c "
import csv,sys; rows=list(csv.DictReader(open('$f'))); m=max(rows,key=lambda r: float(r['achieved_rps']))
print(f\"   {'$p':14s} peak {float(m['achieved_rps']):7.1f} at offered {float(m['target_rate_rps']):.0f} req/s  (p50 response {float(m['p50_resp_ms']):.0f} ms)\")"
done
