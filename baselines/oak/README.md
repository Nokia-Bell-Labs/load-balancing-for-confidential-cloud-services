<!--
  © 2026 Nokia
  Licensed under the BSD 3-Clause Clear License
  SPDX-License-Identifier: BSD-3-Clause-Clear
-->

# Oak baseline

This directory is our proof-of-concept of the attested session of Project Oak (`oak_session`, github.com/project-oak/oak). It has the same layout as `baselines/httpa`.

The session follows the protocol shape of Oak. A Noise NN handshake is bound to attestation evidence by a signature over the handshake hash. The session runs inside an outer TLS connection. The client does not trust the outer TLS connection, as in the deployed form of Oak.

1. **ATTESTATION.** The server makes a fresh binding key. It sends an SNP evidence bundle whose TPM quote binds that key (`janus.common.snp_attestation`, the same binding as a Janus backend). It also sends the attestation result (JWT) that it got for that evidence from Microsoft Azure Attestation (MAA). The client checks these items locally: the JWT signature with the cached key of the Attestation Service, the validity, the measurement policy and the quote binding (`oak/wire.py::verify_evidence`).
2. **HANDSHAKE.** The handshake is `Noise_NN_25519_ChaChaPoly_SHA256`, from the Python package `noiseprotocol`. That package uses the `cryptography` package, as the rest of Janus does. The server signs the handshake hash with the binding key.
3. **OPEN.** The application bytes travel as Noise-encrypted records. The server relays them to the unmodified application on loopback.

Attestation policy: **fresh evidence on every connection**. Each connection gets a new binding key, a new quote and a new MAA token. RA+TLS and HTTPA/2 use the same policy. The transparent proxy that Oak ships behaves the same way. Oak has no load balancing of its own, so this baseline uses one client and one server.

The client trusts only the inner session. It never checks the certificate of the outer TLS connection. All cryptographic operations use the same OpenSSL-backed engine as the other baselines. Thus the measured differences come from the protocol structure.

## Run

Local run, without a TEE (mock evidence):

```sh
make -C baselines/oak/oak local-test
```

On a CVM, with the application on `127.0.0.1:8080`. This needs `snpguest`, `tpm2-tools` and access to MAA. Run `bash baselines/setup_baseline_cvm.sh` first. It prints the commands that start the application: the web app (`apps/browser_app`) for latency runs, or the rate-capped backend for throughput runs. The measurement client requests `protocols.oak.path` of `eval/configs/env.yaml` (`/`, as in the paper runs). If the Janus backend runs on this CVM, stop its backend server first, because it holds `:8080`.

```sh
OAK_TARGET=127.0.0.1:8080 PYTHONPATH=$PWD:$PWD/baselines/oak python3 -m oak.server --port 8543
```

Measurement: set `protocols.oak` in `eval/configs/env.yaml`, then run the commands below. `total_e2e_ms` ends when the attested session is established. It does not include the application request. Table 2 reports this value.

```sh
make -C eval eval PROTOCOLS=oak
```
