<!--
  © 2026 Nokia
  Licensed under the BSD 3-Clause Clear License
  SPDX-License-Identifier: BSD-3-Clause-Clear
-->

# Janus Benchmark Infrastructure

The measurement scripts in this directory measure end-to-end latency for vanilla TLS, Janus (proxy + redirection), RA+TLS, and HTTPA2. They produce one uniform CSV schema for all protocols. Thus the same aggregation and plotting pipeline serves every figure in the paper.

## What "end-to-end" means here

`total_e2e_ms` for every attempt covers the time from a single `t_start` to the first byte of the HTTP response:

```
TCP connect → all TLS handshakes (1 for vanilla / proxy / RA+TLS / HTTPA,
                                  2 for Janus redirection)
            → attestation verification (incl. AS round trip if cache missed)
            → HTTP/1.1 GET → first response byte
```

The per-phase fields (`tcp_ms`, `tls_ms`, `attest_ms`, `extra_tcp_ms`, `extra_tls_ms`, `http_ms`) sum to `total_e2e_ms` within measurement noise. The clients write the protocol-specific sub-breakdowns (for example `jwks_fetch_ms`, `jwt_sig_ms`, `quote_gen_ms`) to a sibling `*_breakdown.csv`. That file is keyed on `(run_id, attempt_id)`.

## Layout

```
configs/env.yaml         per-protocol endpoints; edit before first run
configs/runs.yaml        run parameters (counts, cache policy, payload)
clients/_base.py         AttemptResult, phase(), JwksCache
clients/<proto>.py       per-protocol measurement client (one per protocol)
runner.py                entry point: python3 runner.py --protocol X --out Y
env_snapshot.sh          writes env_snapshot.json into the run dir
analysis/aggregate.py    raw CSVs → summary.csv
data/<run_id>/           raw per-attempt CSVs, env snapshot, JWKS cache
```

## Modes

* **Latency** (`--mode latency`, the default). The runner does sequential per-attempt timing. It discards ``n_warmup`` attempts, then records ``n_measure`` attempts. It writes one row per attempt. Use this mode for the connection-establishment latency figures.
* **Scale** (`--mode scale`). An open-loop driver sends Poisson arrivals at each rate in ``runs.yaml::scale.rates_rps``. It records per-attempt rows with ``wait_ms`` (the client-side queue time). It also writes a per-step CSV that summarises the achieved throughput and the tail response time at each offered rate. Use this mode for the scalability figures. Response time = ``wait_ms + total_e2e_ms``. Thus closed-loop coordination effects do not hide saturation.

## Running the measurements

Run the measurements with the scripts in `eval/ae/`, not with `make` by hand.
`eval/ae/ae.py -m data` runs the experiments of the paper, and
`eval/ae/ae.py -m figures` draws the figures and tables from that run (see
the main README). Each `eval/ae/run_*.sh` script runs one experiment with the
RTT, the rates and the client settings of the paper. `ae.py -m data` calls
these scripts and records the run, so use `ae.py` when you want the figures.
`deploy/README.md` says how to build the testbed.

## RTT and application benchmarks

`run_table2_fig5.sh` adds a one-sided `tc-netem` egress delay on the client for
each RTT and removes it when it exits. `run_fig6.sh <N>` measures one pool
size N. The application benchmarks (`benches/microservice_bench.py`,
`benches/llm_ttft_bench.py`, `benches/browser_plt_bench.py`) run at 40 ms RTT
through `run_fig7c.sh`, `run_fig7b.sh` and `run_fig7a.sh`. The LLM workload
also needs the model and the dataset staged onto the H100 CVM (`staging/`).

## Reproducibility guarantees

* Every CSV header carries `schema_version`. Any incompatible change to the schema bumps that integer.
* Every run dir contains `env_snapshot.json` (VM type, kernel, OpenSSL, MAA region, git commit, dirty bit). It also contains a `<protocol>_<cache>.meta.json` per protocol run.
* The runner never overwrites raw CSVs silently. A re-run with the same `RUN_ID` refuses unless you pass `--force`.
* The JWKS cache lives in `data/<run_id>/jwks_cache/` and is per-run. Thus warm and cold measurements are separated explicitly, not by coincidence.
* The quote-generation policy for RA+TLS / HTTPA2 is `fresh_per_connection` (`configs/runs.yaml`). The config documents it, so any change is reviewable.
