#!/bin/bash
# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

# Fig. 7(a), web browsing: page-load time of a confidential web app. The browser
# is a stock Firefox with the Janus extension. Settings: 40 ms RTT, n=30 after 3 warm-ups.
# Protocols: vanilla TLS, Janus proxy and Janus redirection. RA+TLS and HTTPA/2 cannot run
# in an unmodified browser, so they are absent by design (paper §6.4).
# The script needs Firefox, geckodriver and the packed extension on this client VM
# (pre-installed, see check_testbed.sh).  ~10 min.
#
# ASK FOR A BROWSER WINDOW FIRST.  The /route endpoint of the frontend sends a browser (302)
# to the registered port of a pool backend. For this figure the pool must
# point at the web-app front (WEB_DC_PORT) instead of the backends of the measurement scripts.
# We switch it for your window and switch it back afterwards (docs/ACCESS.md).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; ROOT="$(cd "$HERE/../.." && pwd)"; source "$HERE/testbed.env"; python3 "$HERE/render_env.py" >/dev/null || { echo "testbed.env is incomplete"; exit 1; }
OUT="$RUN_ROOT/fig7a"; mkdir -p "$OUT"
cleanup() { sudo tc qdisc del dev "$IFACE" root 2>/dev/null || true; }; trap cleanup EXIT
cleanup; sudo tc qdisc add dev "$IFACE" root netem delay 40ms
# Pre-check: a browser navigation to /route must go to the web-app front (pool profile "browser").
LOC=$(curl -sk -o /dev/null -m 10 -H "Accept: text/html" -w "%{redirect_url}" "https://$BROWSER_FRONTEND:$FRONTEND_PORT/route")
case "$LOC" in *":${WEB_DC_PORT:-8643}/"*) echo "pre-check: /route redirects to the web-app front ($LOC)";; *) echo "pre-check failed: /route redirects to '$LOC', not to port ${WEB_DC_PORT:-8643} (the web-app front). Ask us to switch the pool to the browser profile for this experiment (docs/ACCESS.md)."; exit 2;; esac
curl -sk -o /dev/null -m 10 -w "%{http_code}" "https://$BROWSER_BACKEND:${WEB_VANILLA_PORT:-8644}/" | grep -q 200 || { echo "pre-check failed: the vanilla web-app front does not answer"; exit 2; }
export PYTHONPATH="$ROOT${PYTHONPATH:+:$PYTHONPATH}"   # the benches import janus.* from the repo root
cd "$ROOT/eval/benches"
python3 browser_plt_bench.py --n 30 --warmup 3 \
    --frontend "$BROWSER_FRONTEND" --backend "$BROWSER_BACKEND" \
    --route-port "$FRONTEND_PORT" --proxy-url "https://$BROWSER_FRONTEND:$FRONTEND_PORT/forward/" --vanilla-port "${WEB_VANILLA_PORT:-8644}" \
    --xpi "$EXT_XPI" --firefox "$FIREFOX" --geckodriver "$GECKODRIVER" \
    --out "$OUT/plt.csv" | tee "$OUT/browser.txt"
cleanup
echo; echo "Results in $OUT/plt.csv (one row per page load; every Janus load reports whether the attestation was verified)."
