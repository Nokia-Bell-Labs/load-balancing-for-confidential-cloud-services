<!--
  © 2026 Nokia
  Licensed under the BSD 3-Clause Clear License
  SPDX-License-Identifier: BSD-3-Clause-Clear
-->

# Native client — `nss_dc_helper`

`nss_dc_helper` is the data-leg of the redirection-mode client: it performs the
real in-band RFC 9345 Delegated-Credential TLS handshake to a backend and
reports per-phase timing plus whether a DC was used and the leaf fingerprint.

It is built on **NSS** because NSS is the only client TLS stack that validates
Delegated Credentials (the same stack Firefox uses); BoringSSL exposes the DC
*server* API only, and Python's `ssl` has no DC support. The Python reference
client (`janus/client/redirect.py`) drives this helper for step (v) of the
pipeline; the measurement scripts pool several of them for concurrency.

## Prerequisite

NSS development headers (provides `pkg-config --cflags/--libs nss`):

```sh
sudo apt-get install -y libnss3-dev libnss3-tools   # Debian/Ubuntu
```

`libnss3-tools` also gives you `certutil`, used to build the NSS trust DB that
imports the deployment CA root (the helper is pointed at that DB at runtime).

## Build

```sh
make            # -> nss_dc_helper   (gitignored)
```

## Use

```sh
./nss_dc_helper <nss_db_dir>
# then write lines on stdin:  "<host> <port> <path>"
# each reply:  "OK tcp_ms=.. tls_ms=.. http_ms=.. dc=1 status=200 leaf_sha256=.."
```

`<nss_db_dir>` is an NSS trust database (created with `certutil`) that trusts the
deployment CA root, so the frontend's delegating certificate chain validates as
in standard TLS before the DC is checked.
