<!--
  © 2026 Nokia
  Licensed under the BSD 3-Clause Clear License
  SPDX-License-Identifier: BSD-3-Clause-Clear
-->

# Artifact appendix: Janus (ACM SIGOPS ATC '26)

*Janus: Practical Load Balancing for Confidential Cloud Services.*
This document maps every claim in the paper to the code that implements it.
It also maps every claim to the experiment that reproduces it. For each
experiment, it gives the commands, the time the experiment takes, and the
numbers to expect. `docs/DESIGN-MAP.md` is the code-side companion.

## What the artifact is

A Janus service has one attested frontend and an elastic pool of attested
backends. Janus lets **unmodified TLS clients and browsers** verify this
service as a single service identity.

The frontend runs in an Intel SGX enclave. The frontend holds the only
CA-issued certificate. This certificate carries the attestation evidence of
the frontend in an X.509 extension.

The backends run in AMD SEV-SNP confidential VMs. The frontend admits each
backend once, on nonce-bound evidence. In redirection mode, the backends serve
clients under the frontend's identity through RFC 9345 Delegated Credentials.

The artifact contains:

- the full system,
- the two attested-TLS baselines that the paper compares against,
- the three application workloads,
- the measurement scripts,
- the raw data behind every number, and
- the scripts that regenerate every figure and table.

## Badges sought

- **Available**: this repository, at tag `atc26-ae`, under the BSD 3-Clause
  Clear License (Nokia Bell Labs). This repository is private; we give a
  read-only access token with the testbed access. Upon Nokia's internal
  approval, we will share a separate public GitHub repository with the same
  artifacts, and deposit that version on Zenodo with a DOI.
- **Functional**: the system builds and runs end to end on the provided
  testbed.
- **Results Reproduced**: every client-driven experiment re-runs on the testbed
  with the scripts in `eval/ae/`. Every figure and table is drawn from that
  data. The repository ships no measurement data.

## Hardware and access

The evaluation needs Intel SGX for the frontend, AMD SEV-SNP CVMs for the
backends, and an attestation service. Note: evaluators are unlikely to have
this hardware. We give you access to our Azure testbed. **You receive an
account on the client VM only.** We deploy and operate the frontend, the
backends, and the baseline servers. You drive everything in the paper's
evaluation from that client.

`docs/ACCESS.md` tells you how to get access. It also tells you how the
one-evaluator-at-a-time scheduling works. From the client, you are in exactly
the position of a Janus client. You verify the SGX attestation of the frontend
and the admission of the backends on every connection you make.
`eval/ae/check_testbed.sh` does that explicitly before all other steps.

## Reproducing the claims

`eval/ae/ae.py` runs everything in order. Its modes are `-m test`, `-m data`,
and `-m figures`. See `README.md`. Phase 1 is `-e default`. This is the
default experiment. It covers Tables 1–3 and Fig. 5 on the standing pool.

After phase 1, you run one experiment per pool profile. We switch the pool
profile for you. See `docs/ACCESS.md`. The experiments are:

- `-e fig6` with profile *scale*,
- `-e fig7c` with profile *hotel*,
- `-e fig7a` with profile *browser*, and
- `-e fig7b` with profile *gpu*, on request.

The table below lists what `ae.py` runs, with one script per claim. Thus you
can also run any single claim. Run `eval/ae/check_testbed.sh` first.
`ae.py -m test` does the same check.

The times are for the standing testbed. The standing testbed has one SGX host,
four standing SEV-SNP backends, and one client VM. Up to 32 backends are
available on request. Disk: all raw output together is under 1 GB on the
client. Memory use is negligible. The exact machines and software versions are
in `README.md`, section "Environment".

| Paper claim | Experiment | Command | Time | In the paper | Machines | Disk |
| --- | --- | --- | --- | --- | --- | --- |
| **Table 1** startup ≈7.1 s dominated by CA issuance; registration ≈2.0 s dominated by the SNP quote; DC issuance 0.03 ms | the startup and registration steps are timed on the servers by the collectors in `plotting/startup_latency/run_*.sh`. We run them for you on request and post the timings in the thread. On the client, `run_table1.sh` measures the DC-issuance signing cost live and checks the certificate of the running frontend | `eval/ae/run_table1.sh` | 1 min | frontend: keypair 5 ms, quote 19 ms, AS 112 ms, CA 7.0 s; backend: keypair 3 ms, quote 1.9 s, AS 38 ms | the servers (on request) and the client VM | < 1 MB |
| **Table 2 / Fig. 5** Janus-proxy within ≈4 ms of vanilla TLS at every RTT; redirection pays one extra connection; RA+TLS and HTTPA/2 pay a quote + AS call per connection | a series of measurements over RTT, n=200, warm + cold AS-key cache | `eval/ae/run_table2_fig5.sh` | ~1 h (COLD=1: ~2 h) | medians at RTT 0/40/80/120 ms: vanilla 2/83/163/243; Janus-proxy 6/86/167/247; Janus-redir. 14/217/417/617; RA+TLS 105/275/438/608; HTTPA/2 107/312/524/724 | client VM, SGX frontend, 1 backend CVM (any pool size) | < 5 MB |
| **Fig. 6** redirection scales linearly with the pool (318 req/s at N=32); proxy plateaus at the frontend's forwarding capacity (≈157–162); per-connection attestation caps the baselines below one capped backend | open-loop Poisson run per N | `eval/ae/ae.py -m data -e fig6` runs the whole curve. It asks our pool-size service for 32, 16, 8, 4, 2 and 1 backends in turn. It runs `eval/ae/run_fig6.sh <N>` at each size. The baselines run at N=1. `FIG6_SIZES=current` measures one point at the present pool size | ~1.5 h (≈7 min per point + 8 min baselines + 3–6 min per resize) | N=32: Janus-redirection 318 req/s, Janus-proxy plateau ≈152–157; N=16: redirection ≈159, proxy ≈153–157 (both modes are still ≈10·N at N≤8); N=1 baselines: vanilla 9.9, Janus 9.9, RA+TLS 8.5, HTTPA/2 7.2 req/s | client VM, SGX frontend, the 32 backend CVMs (the Fig. 6 window) | < 5 MB |
| **Fig. 7(a)** browser: Janus adds 20 ms (proxy) / 136 ms (redirection, a second connection) to page load; RA+TLS/HTTPA/2 cannot run in a browser | stock Firefox + extension, n=30 | `eval/ae/run_fig7a.sh` | ~10 min | mean PLT vanilla 436, proxy 457, redirection 572 ms (medians 433 / 456 / 568). | client VM (Firefox), SGX frontend, the application backend CVM (profile *browser*) | < 1 MB |
| **Fig. 7(b)** LLM: Janus-proxy equals vanilla TTFT; RA+TLS 2.7× and HTTPA/2 3.6× | vLLM on an H100 CVM, n=50 | `eval/ae/run_fig7b.sh` (**on request**) | ~20 min + bring-up | mean TTFT: vanilla ≈156 ms, Janus-proxy ≈ vanilla, Janus-redirection 285 ms, RA+TLS 425 ms, HTTPA/2 560 ms (medians 154 / 156 / 285 / 355 / 487; the bench prints p50/p95/p99 and the mean). | client VM, SGX frontend, the H100 CVM (on request) and the application backend CVM for the baselines | < 1 MB |
| **Fig. 7(c)** microservice: Janus-proxy within ≈8 ms of vanilla; baselines ≈3× | hotelReservation, n=200 | `eval/ae/run_fig7c.sh` | ~10 min | mean vanilla 131, proxy 139, redirection 263, RA+TLS 406, HTTPA/2 370 ms (medians 130 / 138 / 262 / 341 / 327) | client VM, SGX frontend, the application backend CVM (profile *hotel*) | < 1 MB |
| **Table 3** +4,697 B certificate (the AS JWT), +175 B handshake (the DC) | live certificate sizes | `eval/ae/run_table3.sh` | 1 min | vanilla leaf 783 B; JWT extension 4,697 B; DC 175 B | client VM, SGX frontend, 1 backend CVM | < 1 MB |
| all three figures | draw from the data of your run | `eval/ae/make_figures.sh` | 1 min | `results-repro/figures/*.pdf` under your results directory, drawn by the generators of the paper from your run, in the presentation of the paper. Elements the run did not measure are left out. | client VM only | < 50 MB |

Every `ae.py` run has an id and a manifest at `<results>/<run>/manifest.json`.
The manifest records the source commit, the testbed configuration digest, and
the pool at start and end. It also records the status, exit code and log of
every experiment.

`ae.py -m figures` plots only that run's data. It writes `coverage.md` next to
the figures. `coverage.md` lists, for every RTT, pool size and Fig. 7 panel,
whether the run measured it. Note: the manifest marks a failed experiment as
failed, and the figure leaves it out.

## Where things are

| Directory | Contents |
| --- | --- |
| `janus/frontend/` | the attested frontend (Flask, SGX/Gramine); key store |
| `janus/backend/` | backend registration + application shim; `dc_proxy/` DC-TLS terminator (C, BoringSSL) |
| `janus/client/` | reference clients: Python (proxy/redirection), NSS native DC client, Firefox extension |
| `janus/common/` | attestation (SGX via MAA SDK, SEV-SNP via HCL report + vTPM quote), DC sign/verify |
| `janus/tests/` | offline unit tests |
| `ca/` | Pebble CA patch (preserve attestation CSR extensions) + fetch/build script |
| `gramine/` | SGX packaging of the frontend |
| `baselines/` | RA+TLS (Barkhausen Institut's prototype, pinned + patched) and HTTPA/2 |
| `apps/` | the three workloads (web app, vLLM server, DeathStarBench fetch script) |
| `eval/` | measurement scripts: `runner.py`, per-protocol clients, configs, app benches, `ae/` wrappers |
| `plotting/` | the generators of the three figures and the Table 1 collectors |
| `docs/` | testbed access, troubleshooting |
| `deploy/` | scripts + guide to build the testbed from scratch (no addresses hardcoded) |
