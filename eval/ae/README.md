<!--
  © 2026 Nokia
  Licensed under the BSD 3-Clause Clear License
  SPDX-License-Identifier: BSD-3-Clause-Clear
-->

# eval/ae — one script per claim

Wrappers around the measurement scripts (`eval/runner.py`, `eval/Makefile`,
`eval/benches/*.py`) for artifact evaluation from the client VM. Each corresponds
to one row of `ARTIFACT.md`, prints the measured numbers, and writes
under `$RUN_ROOT` (`testbed.env`) or `eval/data/ae-*`, never under `plotting/`.
Every script can be run again: an earlier run of the same id is moved to
`eval/data/previous/` first, so nothing you measured is lost.

`ae.py` is the single entry point (`-m test | data | figures | paper | status |
clean`, `-r` run id, `-e` to pick experiments); it calls the scripts below in
order, records every experiment's status and exit code in the run's
`manifest.json`, resumes a run on re-invocation, and names the outputs after
the paper (`figure_5.pdf`, `figure_6.pdf`, `figure_7.pdf`, `table_1.txt`,
`table_2.md`, `table_3.txt`). `overlay_runs.py` builds the figures from one
run's data only and writes `coverage.md` (fresh vs reference per element).
`loc.sh` prints the line counts behind the code-size statements.

Where things land (`RUN_ROOT` = `<results>/<run id>`; `<results>` defaults to `~/ae-results`):

```
eval/data/<run>-rtt-<R>/         raw per-attempt CSVs + summary.csv per RTT      (run_table2_fig5.sh)
eval/data/<run>-scale-N<N>/      per-step throughput CSVs                        (run_fig6.sh)
eval/data/previous/              earlier runs of the same id, moved aside on re-run
$RUN_ROOT/manifest.json, logs/, table_1.txt, table_3.txt, fig7a/, fig7b/, fig7c/   run manifest, logs, app-bench output and raw samples
$RUN_ROOT/results-repro/         the generators with the data of your run         (make_figures.sh)
$RUN_ROOT/paper-repro/           figure_5/6/7.pdf + table_1/2/3 + coverage.md from this run   (ae.py -m figures)
```

| Script | Claim | Time |
| --- | --- | --- |
| `ae-remote.sh ae@<client> test\|data\|figures\|all\|attach\|status\|fetch\|run` | laptop side: run the evaluation on the client over SSH (detached) and copy the results back | |
| `check_testbed.sh` | pre-flight: every endpoint answers, the frontend's attestation verifies from here, the pool is registered | 1 min |
| `run_table2_fig5.sh [RTTs]` | Table 2 + Fig. 5 — establishment latency vs RTT, 5 protocols, warm AS-key cache (`COLD=1` adds the cold pass) | ~1 h |
| `run_fig6.sh <N> [--with-baselines]` | Fig. 6 — sustained throughput at N backends | ~15 min per N |
| `run_fig7c.sh` | Fig. 7(c) — microservice | ~10 min |
| `run_fig7a.sh` | Fig. 7(a) — browser page-load | ~10 min |
| `run_fig7b.sh` | Fig. 7(b) — LLM TTFT (H100, **on request**) | ~20 min + bring-up |
| `run_table3.sh` | Table 3 — bandwidth overhead, live | seconds |
| `run_table1.sh` | Table 1 — the DC-issuance signing cost, live; the server-side steps are timed by us on request | seconds |
| `make_figures.sh` | draw the three figures of the paper from your run | 1 min |

`testbed.env` (from `testbed.env.example`) is pre-filled on the client VM and
is the only place addresses live; every script renders the measurement scripts' own
`eval/configs/env.yaml` from it (`render_env.py`). You should not need to edit
anything. Run `check_testbed.sh` first.
