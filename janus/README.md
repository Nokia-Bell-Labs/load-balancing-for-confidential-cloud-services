<!--
  © 2026 Nokia
  Licensed under the BSD 3-Clause Clear License
  SPDX-License-Identifier: BSD-3-Clause-Clear
-->

# janus/ — the system

Frontend and backend are Python ∂(Flask); the TLS-terminating `dc_proxy` and the reference clients are C/BoringSSL.

## Structure of the codebase

| Path | Contents |
|---|---|
| `frontend/frontend_server.py` | Registration (`/register_backend`, `/provision_backend` legacy alias), the proxy-mode data path (`/forward`), admin API, and `sign_dc()`. |
| `frontend/key_store.py` | Sealed store of admitted backends and the frontend identity. |
| `frontend/backend_provisioner.py` | Optional: provisions Azure CVMs and deploys the backend onto them. Not on the request path. |
| `backend/backend_server.py` | Registration client: keygen in-TEE, builds the SNP evidence bundle, registers, persists the DC + frontend chain. |
| `backend/dc_proxy/proxy.c` | Terminates client TLS inside the TEE and relays to the unmodified app over a loopback/Unix socket. Presents the DC (`--sealed-dir`) or a plain X.509 leaf (`--x509-cert/--x509-key`, the vanilla baseline). |
| `client/` | The application-agnostic client (proxy + redirection modes): `proxy.py`, `redirect.py`, `attest.py`. It sets up the attested channel and speaks plain HTTP to whatever app sits behind `dc_proxy` — **see `client/README.md` for how to drive it against a given application**. |
| `client/native/nss_dc_helper.c` | The native client: a real RFC 9345 DC handshake over NSS (the stack Firefox uses). Driven directly by the bench redirect client and the app benches. |
| `client/browser_extension/` | Firefox WebExtension: per-origin JWT validation, pins the served cert to the attested one. The browser client. |
| `common/` | `snp_attestation.py` (SNP bundle build + MAA verify), `attestation_verifier.py`, `acme_client.py`, `cert_generator.py` (JWT-embedding CSR/cert). |

## Key operation modes

- **Proxy mode**: client → frontend `:6037`; `frontend_server.py:/forward` relays
  to the backend's `dc_proxy` over TLS. Frontend on the data path.
- **Redirection mode**: `sign_dc()` issues the RFC 9345 DC at registration;
  client connects straight to the backend's `dc_proxy`, which presents it.
- **Registration**: `register_backend()` verifies the SNP bundle at MAA
  (`common/snp_attestation.verify_snp_bundle`) and checks that the quote's
  qualifyingData binds the challenge nonce together with the CSR's public key,
  then signs the DC and returns the frontend chain. The backend tolerates an
  empty DC (proxy-only).

## Implementation notes

- Sealed state lives at `$APP_HOME/janus/{frontend,backend}/sealed` (gramine
  encrypts it under the SGX sealing key).
- `sign_dc()` carries the NSS Bug 2018200 workaround (the `algorithm` field is
  placed after the credential in the signed input) so Firefox/NSS accept the DC.
- Frontend env knobs: `ISSUE_DC=0` skips DC issuance (proxy-only deployments);
  `EXPECTED_BACKEND_MEASUREMENT=<hex>` enforces a backend launch-measurement
  admission policy (off by default — any MAA-signed measurement is admitted).

Build/run the whole stack from the repo root README; SGX packaging is in
`../gramine/` and the CA in `../ca/`.
