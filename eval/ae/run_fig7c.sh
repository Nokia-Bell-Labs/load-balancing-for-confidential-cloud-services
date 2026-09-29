#!/bin/bash
# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

# Fig. 7(c), microservice workload (DeathStarBench hotelReservation,
# /reservation) at 40 ms RTT, five protocols, n=200 after 20 warm-ups.
# All five fronts relay to the same application on the backend CVM. So the
# delta is protocol overhead only (eval/benches/microservice_bench.py docstring).
# RA+TLS needs the interpreter with the RA+TLS bridge, so it runs separately.
# ~10 min.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; ROOT="$(cd "$HERE/../.." && pwd)"; source "$HERE/testbed.env"; python3 "$HERE/render_env.py" >/dev/null || { echo "testbed.env is incomplete"; exit 1; }
OUT="$RUN_ROOT/fig7c"; mkdir -p "$OUT"; rm -f "$OUT/microservice_raw.csv"   # one attempt = one raw file (the RA+TLS invocation below appends to it)
cleanup() { sudo tc qdisc del dev "$IFACE" root 2>/dev/null || true; }; trap cleanup EXIT
cleanup; sudo tc qdisc add dev "$IFACE" root netem delay 40ms
# Pre-check: every measured path must reach the SAME hotel application (the docstring of the bench).
# Proxy mode goes through the /forward endpoint of the frontend, that is, to the registered pool backend. So the pool must
# point at the hotel front (operator profile "hotel", docs/ACCESS.md). The script also checks the direct fronts.
export PYTHONPATH="$ROOT${PYTHONPATH:+:$PYTHONPATH}"   # the benches import janus.* from the repo root
RES="$(python3 -c "import sys; sys.path.insert(0, \"$ROOT/eval/benches\"); import microservice_bench as m; print(m.RPATH)")"   # the same request that the bench measures
check() { local code; code=$(curl -sk -o /dev/null -m 10 -w "%{http_code}" "$1"); [ "$code" = 200 ] || { echo "pre-check failed: $2 -> HTTP $code at $1"; echo "Ask us to switch the pool to the hotel profile for this experiment (docs/ACCESS.md)."; exit 2; }; }
check "https://$FRONTEND_HOST:$FRONTEND_PORT/forward$RES" "proxy mode (frontend /forward -> registered pool backend)"
check "https://$BACKEND_HOST:${APP_DC_PORT:-8543}$RES" "redirection data leg (DC front)"
check "https://$BACKEND_HOST:${APP_VANILLA_PORT:-8544}$RES" "vanilla (X.509 front)"
echo "pre-check: proxy, redirection and vanilla paths all reach the hotel application"
cd "$ROOT/eval/benches"
# The application fronts relay to the hotel stack (:5000 on the backend CVM).
# The fronts are dc_proxy with the DC on APP_DC_PORT, and the plain X.509 terminator on
# APP_VANILLA_PORT. HTTPA/2 and RA+TLS listen on their own ports (testbed.env).
COMMON=(--backend "$BACKEND_HOST" --frontend "$FRONTEND_HOST" --frontend-port "$FRONTEND_PORT" --maa "$MAA_URL"
        --ctls-port "${APP_DC_PORT:-8543}" --vanilla-port "${APP_VANILLA_PORT:-8544}" --n "${N:-200}" --warmup "${WARMUP:-20}"
        --nss-helper "$NSS_HELPER" --nss-db "$NSS_DB"
        --httpa-host "$HTTPA_HOST" --httpa-port "$HTTPA_PORT" --ratls-url "https://$RATLS_HOST:$RATLS_PORT"
        --raw-out "$OUT/microservice_raw.csv")
# ONLY=vanilla,redirect ./run_fig7c.sh   restricts the protocols (default: all five)
ONLY="${ONLY:-vanilla,redirect,proxy,httpa,ratls}"
MAIN="$(echo "$ONLY" | tr ',' '\n' | grep -vx ratls | paste -sd, - || true)"   # ONLY=ratls alone leaves MAIN empty (pipefail)
[ -n "$MAIN" ] && python3 microservice_bench.py "${COMMON[@]}" --only "$MAIN" | tee "$OUT/microservice_main.txt"
echo "$ONLY" | tr ',' '\n' | grep -qx ratls && "$RATLS_PYTHON" microservice_bench.py "${COMMON[@]}" --only ratls | tee "$OUT/microservice_ratls.txt"
cleanup
echo; echo "Results in $OUT."
