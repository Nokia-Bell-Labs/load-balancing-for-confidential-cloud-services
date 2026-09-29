<!--
  © 2026 Nokia
  Licensed under the BSD 3-Clause Clear License
  SPDX-License-Identifier: BSD-3-Clause-Clear
-->

# Gramine (SGX) packaging

Wraps a base application image (`janus/<module>`, built by
`janus/<module>/Dockerfile`) into a graminized, SGX-signed image
`janus/<module>-graminized`. Only the frontend is graminized here; the paper's
backends are SEV-SNP CVMs (the whole VM is the TEE) and run unmodified, so there
is no `MODULE=backend` image — see `janus/README.md` for how a backend runs.

```sh
make gramine-image                      # build janus/gramine base (once)
make signed-image MODULE=frontend       # needs janus/frontend already built
```

Only the frontend is graminized (`MODULE=frontend`); the backends run in
SEV-SNP CVMs and need no enclave packaging. The loader entrypoint is set in
the `Makefile` (`LOADER_ARGS`): `-m home.janus.janus.frontend.frontend_server`.

`signed-image` generates `Dockerfile_<module>_graminized` from
`Dockerfile.build.template`, expands `entrypoint.manifest.template` via
`finalize-manifest.py` (mounts `$APP_HOME/janus`, encrypts the module's
`sealed/` under the SGX sealing key), and signs with `keys/signer-key.pem`
(auto-generated 3072-bit RSA if absent).

Knobs: `SIGNING_KEY`, `APP_HOME=/home/janus`, `RA_TYPE=dcap`, `DEBUG=1` (manifest
log level). Host needs `/dev/sgx_enclave`, `/dev/sgx_provision`, and `aesmd`;
the image bundles the Azure DCAP quote provider.

**The signing key sets MRENCLAVE.** Rebuilding (or changing the manifest/code)
changes the frontend's MRENCLAVE, which is the client's admission policy — keep
`keys/signer-key.pem` stable across a deployment, or re-pin clients.
