<!--
  © 2026 Nokia
  Licensed under the BSD 3-Clause Clear License
  SPDX-License-Identifier: BSD-3-Clause-Clear
-->

# CA (Pebble fork)

The frontend gets its TLS certificate by ACME from this CA. It is upstream
[Pebble](https://github.com/letsencrypt/pebble) **v2.9.0** plus a small patch
(`pebble-janus.patch`); `fetch_pebble.sh` clones the pinned tag and applies it.
The patch makes two changes upstream does not do:

- **Persistent CA chain.** Upstream Pebble mints a random CA on each start.
  `loadPersistentCA`/`loadPersistentChain` instead load a fixed root +
  intermediate from `ca_certs/`, so issued certs stay trusted across restarts
  and clients import the root once.
- **Extension passthrough.** The CSR's AS-JWT extension
  (`1.3.6.1.4.1.99999.3.1`) and the RFC 9345 DelegationUsage extension
  (`1.3.6.1.4.1.44363.44`) are copied into the issued certificate. Public CAs strip non-SAN extensions; Janus needs both preserved.

## Build

```sh
ca/fetch_pebble.sh      # clone Pebble v2.9.0, apply pebble-janus.patch, build (Go >= 1.24)
```

This clones upstream into `ca/pebble/` (gitignored) and applies
`pebble-janus.patch` — to see exactly what we changed, read that patch (or run
`git -C ca/pebble diff` after fetching). The frontend image bundles the
resulting binary and runs it on `localhost:14000`; the frontend is its only
ACME client.

## CA certificates

```sh
ca/pebble/ca_certs/generate_ca_certificates.sh       # after ca/fetch_pebble.sh
```

Writes `root-ca.pem`/`-key.pem`, `intermediate-ca.pem`/`-key.pem`, and
`ca-chain.pem` (root + intermediate are 4096-bit RSA, 10-year). Keys are
gitignored — generate per deployment. The issued leaf is 90-day:

```
root-ca  ->  intermediate-ca  ->  frontend leaf (AS-JWT + DelegationUsage exts)
```

For the browser client, import `root-ca.pem` once (Firefox: Settings → Privacy →
View Certificates → Authorities → Import, trust for websites).
