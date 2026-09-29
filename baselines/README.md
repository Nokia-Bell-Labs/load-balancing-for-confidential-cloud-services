<!--
  © 2026 Nokia
  Licensed under the BSD 3-Clause Clear License
  SPDX-License-Identifier: BSD-3-Clause-Clear
-->

# Baselines

The two attested-TLS designs the paper compares against. Both run on a backend
CVM next to the Janus backend; the measurement clients for them are in
`eval/clients/ratls.py` and `eval/clients/httpa.py`.

| Directory | Baseline | Origin | Our changes |
| --- | --- | --- | --- |
| `ratls/` | RA+TLS: attestation evidence carried in the TLS handshake, verified per connection | Barkhausen Institut `ratls` at commit `c05b640` (pinned), built into a dedicated CPython by `ratls/build_python_with_ratls.sh` | `ratls/ratls-external-intel-sgx.patch` (SEV-SNP evidence via the vTPM/HCL path, as in the paper); `ratls/server/` HTTP server + Python bridge; `ratls/client.py` |
| `httpa/` | HTTPA/2: attested HTTP session over TLS (per-session attestation exchange) | our implementation of the protocol as published, following the HTTPA/2 specification | `httpa/server.py`, `httpa/client.py` |

`ratls/README.md` and the docstrings of `httpa/httpa/server.py` and `httpa/httpa/client.py` describe each in detail. Pins and
fetch scripts are indexed in `docs/DEPENDENCIES.md`.
