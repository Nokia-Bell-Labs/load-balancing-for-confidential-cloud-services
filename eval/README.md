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

## One-shot reproduction

1. Start the five services (vanilla TLS, Janus frontend, Janus backend, RA+TLS server, HTTPA2 server). Fill in `configs/env.yaml`. The repo root README says how to start these services. Read its **Azure testbed** section (host SKUs, MAA) and its **Reproduce the evaluation** section (ordered bring-up).
2. Latency figures: run `make eval`. It does warm and cold cache passes for all protocols.
3. Scalability figures: run `make eval-scale`. It does a Poisson rate run per `runs.yaml::scale` for all protocols. Set `CACHE=cold` for the cold-cache scalability slice.
4. Run `make aggregate`. It writes `data/<RUN_ID>/summary.csv` (latency) and `data/<RUN_ID>/scale_summary.csv` (scalability steps).
5. Run `eval/ae/ae.py -m figures` to make the figures of the paper from the run. See `plotting/README.md`.

Tag a specific run:

    make eval RUN_ID=2026-05-28-paper-rev1

## RTT series and backend-scaling runs

`make eval` and `make eval-scale` measure at the testbed's native RTT, which is below 1 ms. Two figures vary the topology. This section says how to produce them.

**Latency vs RTT** (`fig_e2e_latency`, `fig_latency_breakdown`). On the client VM, inject RTT toward the servers with `tc-netem`. Tag one run per RTT:

```sh
IFACE=eth0   # interface toward the frontend/backends
for rtt in 0 20 40 80 120 160; do
  sudo tc qdisc del dev "$IFACE" root 2>/dev/null || true
  [ "$rtt" -gt 0 ] && sudo tc qdisc add dev "$IFACE" root netem delay "${rtt}ms"
  make eval RUN_ID=rtt-$rtt          # one-sided egress delay ≈ +rtt ms RTT
done
sudo tc qdisc del dev "$IFACE" root 2>/dev/null || true
```

**Backend scaling** (`fig_scalability_backends`). Register N backends. The pool is set per window. Then do one scale run per N with `eval/ae/run_fig6.sh <N>`. This script sets the paper's offered-rate grid and `JANUS_AMORTIZE_CONTROL=1`. With that variable, the client validates the frontend once and fans out across its `/route` pool. By hand:

```sh
make eval-scale RUN_ID=mb-N$N PROTOCOLS='ctls_redirect'
```

The application benchmarks (`apps/microservice_bench.py`, `apps/llm_ttft_bench.py`, `apps/browser_plt_bench.py`) run at native RTT against the same services. The LLM workload also needs the model and the dataset staged onto the H100 CVM (`staging/`).

## Reproducibility guarantees

* Every CSV header carries `schema_version`. Any incompatible change to the schema bumps that integer.
* Every run dir contains `env_snapshot.json` (VM type, kernel, OpenSSL, MAA region, git commit, dirty bit). It also contains a `<protocol>_<cache>.meta.json` per protocol run.
* The runner never overwrites raw CSVs silently. A re-run with the same `RUN_ID` refuses unless you pass `--force`.
* The JWKS cache lives in `data/<run_id>/jwks_cache/` and is per-run. Thus warm and cold measurements are separated explicitly, not by coincidence.
* The quote-generation policy for RA+TLS / HTTPA2 is `fresh_per_connection` (`configs/runs.yaml`). The config documents it, so any change is reviewable.
