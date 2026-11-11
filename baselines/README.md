<!--
  © 2026 Nokia
  Licensed under the BSD 3-Clause Clear License
  SPDX-License-Identifier: BSD-3-Clause-Clear
-->

# Baselines

The designs that the paper compares against. RA+TLS and HTTPA/2 run on a
backend CVM next to the Janus backend. Their measurement clients are in
`eval/clients/ratls.py` and `eval/clients/httpa.py`. The final version of the
paper also compares against Oak and OHTTP+KMS. We added these two baselines
after the artifact evaluation. Their measurement clients are in
`eval/clients/oak.py` and `eval/clients/ohttp_kms.py`.
`setup_baseline_cvm.sh` prepares a CVM for the Oak server and the OHTTP gateway.

The runner measures Oak and OHTTP+KMS for Table 2 (`make -C eval eval-warm`, and `eval-cold` for
OHTTP+KMS, at each RTT; add the RTT with a one-sided netem delay on the client, as
`eval/ae/run_table2_fig5.sh` does) and for Fig. 6 (`make -C eval eval-scale`). The application
benchmarks of Fig. 7 and the figure scripts do not include these two baselines.

| Directory | Baseline | Origin | Our changes |
| --- | --- | --- | --- |
| `ratls/` | RA+TLS: attestation evidence carried in the TLS handshake, verified per connection | Barkhausen Institut `ratls` at commit `c05b640` (pinned), built into a dedicated CPython by `ratls/build_python_with_ratls.sh` | `ratls/ratls-external-intel-sgx.patch` (SEV-SNP evidence via the vTPM/HCL path, as in the paper); `ratls/server/` HTTP server + Python bridge; `ratls/client.py` |
| `httpa/` | HTTPA/2: attested HTTP session over TLS (per-session attestation exchange) | our implementation of the protocol as published, following the HTTPA/2 specification | `httpa/httpa/server.py`, `httpa/httpa/client.py` |
| `oak/` | Oak: attested Noise session inside an untrusted outer TLS connection, fresh evidence on every connection, no load balancing | our implementation of the attested session of Project Oak (`oak_session`) | `oak/oak/server.py`, `oak/oak/client.py`, `oak/oak/wire.py` |
| `ohttp/` | OHTTP+KMS: Oblivious HTTP (RFC 9458) to gateways behind an untrusted load balancer. An attested KMS releases the keys. A gateway attests once per key epoch | our implementation of the design of Azure AI confidential inferencing | `ohttp/ohttp/kms.py`, `ohttp/ohttp/gateway.py`, `ohttp/ohttp/client.py`, `ohttp/ohttp/wire.py`, `ohttp/relay/` |

`ratls/README.md` and the docstrings of `httpa/httpa/server.py` and `httpa/httpa/client.py` describe each in detail. Pins and
fetch scripts are indexed in `docs/DEPENDENCIES.md`.
