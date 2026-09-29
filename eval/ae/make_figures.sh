#!/bin/bash
# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

# Draw the figures of the paper from the data of ONE run, with the generators of the paper.
#
#   ./make_figures.sh     # run $AE_RUN (default ae) -> $RUN_ROOT/results-repro/figures/ + coverage.md
#
# overlay_runs.py builds the inputs of the generators from the run (the per-RTT series, the throughput
# points, the application samples of Fig. 7). It fails if the run has no data. coverage.md says which
# elements the run measured. Elements the run did not measure are left out of the figures.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; ROOT="$(cd "$HERE/../.." && pwd)"
[ -f "$HERE/testbed.env" ] && { source "$HERE/testbed.env"; python3 "$HERE/render_env.py" >/dev/null || true; }
[ "${1:-}" = "--from-runs" ] && shift   # accepted for compatibility: the run is the only source
DEST="${RUN_ROOT:-$HOME/ae-results}/results-repro"
python3 "$HERE/overlay_runs.py" --run "${AE_RUN:-ae}" --run-root "${RUN_ROOT:-$HOME/ae-results}" --dest "$DEST" || exit $?
(cd "$DEST" && python3 make_paper_figures.py)
echo "figures from run '${AE_RUN:-ae}': $DEST/figures/   coverage: $DEST/coverage.md"
