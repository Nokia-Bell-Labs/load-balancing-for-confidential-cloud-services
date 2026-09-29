#!/bin/bash
# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

# Fig. 7(b), LLM inference: time to first token of Llama-3.1-8B. vLLM serves
# the model on a confidential H100 CVM. Settings: 40 ms RTT, 50 ShareGPT prompts.
#
# Topology: vLLM runs on the H100 CVM behind its DC (:8443) and X.509 (:8444) fronts. Proxy mode goes through the
# forwarding path of the frontend inside the enclave (/forward/generate, streamed). The HTTPA/2 and RA+TLS servers on the backend CVM
# relay to the LLM, as in the paper (profile "gpu").
# AVAILABLE ON REQUEST ONLY.  The H100 CVM is expensive and loses its model
# staging on every deallocation. So it is not part of the standing testbed.
# make_figures.sh draws the figure panel from your run. To measure, ask in
# the HotCRP thread for a GPU window. The authors will bring the VM up
# (~30 min) and set GPU_HOST in testbed.env.  ~20 min to run.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; ROOT="$(cd "$HERE/../.." && pwd)"; source "$HERE/testbed.env"; python3 "$HERE/render_env.py" >/dev/null || { echo "testbed.env is incomplete"; exit 1; }
[ -n "${GPU_HOST:-}" ] || { echo "GPU_HOST is not set: the H100 CVM is not up. See the header of this script."; exit 2; }
OUT="$RUN_ROOT/fig7b"; mkdir -p "$OUT"; rm -f "$OUT/llm_raw.csv"   # one attempt = one raw file
cleanup() { sudo tc qdisc del dev "$IFACE" root 2>/dev/null || true; }; trap cleanup EXIT
cleanup; sudo tc qdisc add dev "$IFACE" root netem delay 40ms
export PYTHONPATH="$ROOT${PYTHONPATH:+:$PYTHONPATH}"   # the benches import janus.* from the repo root
cd "$ROOT/eval/benches"
COMMON=(--backend "$GPU_HOST" --ctls-port "$BACKEND_PORT" --vanilla-port "$VANILLA_PORT" --prompts "$LLM_PROMPTS"
        --nss-helper "$NSS_HELPER" --nss-db "$NSS_DB" --frontend "$FRONTEND_HOST" --frontend-port "$FRONTEND_PORT"
        --httpa-host "$HTTPA_HOST" --httpa-port "$HTTPA_PORT" --ratls-url "https://$RATLS_HOST:$RATLS_PORT" --maa "$MAA_URL"
        --raw-out "$OUT/llm_raw.csv")
python3 llm_ttft_bench.py "${COMMON[@]}" --only vanilla,redirect,proxy,httpa | tee "$OUT/llm_main.txt"
"$RATLS_PYTHON" llm_ttft_bench.py "${COMMON[@]}" --only ratls | tee "$OUT/llm_ratls.txt"
cleanup
echo; echo "Results in $OUT."
