<!--
  © 2026 Nokia
  Licensed under the BSD 3-Clause Clear License
  SPDX-License-Identifier: BSD-3-Clause-Clear
-->

# RA+TLS baseline

RA+TLS attests on every TLS connection. In this artifact the server runs on a
SEV-SNP CVM, and the client runs on the client VM.

```
Every TLS connection:
  1. The client asks for attestation in TLS extension 420.
  2. The server builds fresh SEV-SNP evidence bound to the handshake binder secret.
  3. The server sends the evidence in TLS extension 421.
  4. The client verifies the evidence.
```

## Contents

- `server/`: the RA+TLS server and its C bridge to OpenSSL (`server/README.md`).
- `client.py`: the RA+TLS client.
- `build_python_with_ratls.sh`: builds the RA+TLS interpreter.
- `ratls-external-intel-sgx.patch`: our patch to the upstream `ratls`
  repository (`docs/DEPENDENCIES.md`).

## Build

The deploy scripts build everything: `deploy/client_setup.sh` on the client
VM and `deploy/backend_setup.sh app` on the application backend. To build by
hand, run from the repository root:

```sh
sudo apt-get install -y build-essential libtool autoconf automake libssl-dev libffi-dev zlib1g-dev \
  libbz2-dev libreadline-dev libsqlite3-dev liblzma-dev
baselines/ratls/build_python_with_ratls.sh
cd baselines/ratls/server && ../../python-ratls/bin/python3 setup.py build_ext --inplace
```

The first command installs the build packages that the deploy scripts
install. The upstream bootstrap needs the autotools among them. The script
clones the upstream `ratls` at the pinned commit into
`baselines/ratls-external/` and applies the patch. It builds the patched
OpenSSL 1.1.1m, libsodium and the TPM2 TSS (`make bootstrap`), and then
Python 3.10.12 against them into `baselines/python-ratls/`. The last command
builds the bridge module. The client and the server both need it.

## Client

Run the client with the RA+TLS interpreter. The system `python3` lacks the
OpenSSL extension API.

```sh
baselines/python-ratls/bin/python3 baselines/ratls/client.py --server https://<backend>:5004
```

Options: `--no-verify` skips the evidence check, `--ca-cert <pem>` checks the
TLS certificate against a CA, `--no-tls-verify` skips the certificate check,
and `--path` names the request path.
