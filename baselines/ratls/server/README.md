<!--
  © 2026 Nokia
  Licensed under the BSD 3-Clause Clear License
  SPDX-License-Identifier: BSD-3-Clause-Clear
-->

# RA+TLS server

The server of the RA+TLS baseline. It attests on every TLS connection.

- `ratls_python_bridge.c` registers TLS extensions 420 and 421 with OpenSSL
  (`SSL_CTX_add_custom_ext()`). It also exports the 48-byte handshake binder
  secret (`SSL_export_handshake_binder_secret()`, from the patched OpenSSL in
  `baselines/ratls-external/`). `setup.py` builds it.
- `ratls_http_server.py` answers each request for attestation. It builds
  SEV-SNP evidence with `janus.common.snp_attestation`, with the binder secret
  as the nonce, so the evidence commits to this handshake.

## Run

`deploy/backend_setup.sh app` builds and starts the server on the application
backend. It runs the server from `baselines/` like this:

```sh
HOTEL_URL=http://127.0.0.1:5000 PYTHONPATH=<repo> APP_HOME=$HOME \
  RATLS_BUNDLE_CLI=<repo>/janus/common/snp_bundle_cli.py \
  python-ratls/bin/python3 ratls/server/ratls_http_server.py --port 5004 --type snp
```

- `--type snp` sends real SEV-SNP evidence. `--type direct` sends a fake report,
  for tests without a CVM.
- The server relays requests to the hotelReservation application
  (`HOTEL_URL`) or to the LLM (`LLM_URL`).

`baselines/ratls/README.md` describes the build and the client. The `Dockerfile`
and the `Makefile` here are from the upstream prototype's SGX mode. The
artifact does not use them.
