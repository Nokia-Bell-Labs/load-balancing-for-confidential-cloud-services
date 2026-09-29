<!--
  © 2026 Nokia
  Licensed under the BSD 3-Clause Clear License
  SPDX-License-Identifier: BSD-3-Clause-Clear
-->

# Microservice workload

The microservice benchmark runs **DeathStarBench `hotelReservation`** unmodified
— a clean upstream clone at the pinned commit in `../../docs/DEPENDENCIES.md`
(`6ecb097`, verified no local changes). Unlike `browser_app/` and `llm_app/`,
there is no Janus-authored code here: Janus fronts the stock service, so nothing
is vendored.

Fetch: `./fetch.sh` clones DeathStarBench at the pinned commit into
`./DeathStarBench/` (gitignored); no patch is applied.

Deployment:
- Bring up `DeathStarBench/hotelReservation` with its own `docker-compose.yml`.
- Front its `frontend` service (`:5000`) the same way as the other workloads —
  `dc_proxy` for redirection mode, or the Janus frontend's `/forward` for proxy
  mode. The service is unaware it is fronted.

Measurement: `eval/benches/microservice_bench.py` drives `/reservation` and reports
end-to-end latency. Both fronts relay to the same backend, so the difference is the
protocol overhead.
