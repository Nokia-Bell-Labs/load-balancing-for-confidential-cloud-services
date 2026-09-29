<!--
  © 2026 Nokia
  Licensed under the BSD 3-Clause Clear License
  SPDX-License-Identifier: BSD-3-Clause-Clear
-->

# Plotting scripts

This directory holds the scripts that draw the three evaluation figures of the
paper. It holds no measurement data. `eval/ae/make_figures.sh` copies this
directory next to the results of a run, writes the data of the run into the
layout below, and runs `make_paper_figures.py` there.

## Shared style: `janus_style.py`

Every generator imports this file.
- `apply()` sets the rcParams (serif, font sizes, dpi).
- `PROTO` gives the color, marker, hatch and label of each protocol.
- `PCTL` gives the palette of each percentile in the application bars.
- `PHASE` gives the palette of each phase in the latency breakdown.
- `C_FE = 162` is the forwarding capacity of the frontend.

## Figure, script and data

| Paper figure | Dir | Script | Data of the run |
|---|---|---|---|
| Fig. 5 `fig_latency_breakdowns` | `bench_figures/` | `gen_latency.py` | `data/rtt-<R>/<protocol>_warm.csv` and `_breakdown.csv` (from `run_table2_fig5.sh`) |
| Fig. 6 `fig_scale_backends` | `scalability_capped/` | `gen_capped_scaleout.py` | `capped_scaleout.csv`, `capped_baselines_n1.csv` (peaks of the `run_fig6.sh` steps) |
| Fig. 7 `fig_apps` | `bench_figures/` | `paper_figures.py` (`fig_apps`) | `data/apps/{browser,llm_gpu_ttft,microservice}.csv` (from the Fig. 7 benches) |

`eval/ae/overlay_runs.py` writes these files from the run. A figure shows only
what the run measured.

`startup_latency/` holds the collectors of Table 1 (`run_*.sh`, run on the
servers) and `dc_sign_microbench.py` (the DC-issuance cost, run on the client
by `run_table1.sh`). `scalability_capped/capped_backend.py` and
`vanilla_capped.py` are the rate-capped test application of the backends.

## Data processing

These are the only transformations between the raw files of a run and a
plotted or printed value.

- **The scripts discard warm-ups.** Table 2 / Fig. 5: the first 30 attempts
  of each run (`eval/configs/runs.yaml`, `n_warmup`). Fig. 6: each offered
  rate runs a warm-up period of 4 s before its window of 15 s. Fig. 7(c): 20
  warm-up requests per protocol. Fig. 7(a): 3 page loads. Fig. 7(b): 2 prompts.
  Warm-up rows stay in the raw files, marked in the `warmup` column.
- **Failed attempts stay in the raw files. The statistics exclude them.** A
  failed attempt has `ok=0` and the error. A latency run counts as a
  reproduction only if at least 90 % of its attempts succeeded
  (`eval/runner.py`, the three application benches). Otherwise the run fails,
  and `coverage.md` says which elements came from the run.
- **Medians, means, percentiles, min and max** come from the successful
  attempts after the warm-up (`eval/ae/overlay_runs.py`). Fig. 7 plots the mean with min-max bars. Table 2
  and the printed tables show medians.
- **Fig. 6 is the peak achieved rate over the offered-rate steps** of a run.
  The per-step rates are in the `*_scale_warm_steps.csv` files of the run.
- **Nothing is anonymised or rewritten** in the raw files.

## Run by hand

```
cd <results>/results-repro && python3 make_paper_figures.py     # writes figures/ (png and pdf)
```

The scripts need matplotlib.
