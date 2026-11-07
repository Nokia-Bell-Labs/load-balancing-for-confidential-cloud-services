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
  `EXPECTED_BACKEND_MEASUREMENT=sha256:<hex>` enforces a backend admission policy
  on SEV-SNP/TDX backends (off by default: any proven code measurement is
  admitted). The backend extends its code measurement into vTPM PCR 15 once per
  boot, and the quote proves the value of PCR 15. The SNP launch measurement
  covers only Azure's firmware and paravisor; it is logged, not compared.
  `deploy/frontend_run.sh` passes the variable to the container, and the
  enclave manifest passes it on to the frontend.
- The code measurement (`snp_attestation.code_measurement_entries`) covers:
  every `.py` file of the `janus` package, except the BoringSSL and snpguest
  checkouts that the setup fetches into it; the `dc_proxy` binary (BoringSSL is
  linked into it); the files of the Python distributions in
  `backend/requirements.txt` and of their dependencies; and the application:
  the files and directories in `JANUS_APP_MEASURE` and the container image IDs
  in `JANUS_APP_IMAGES` (comma-separated, set on the backend). All backends of
  a pool need the same code, dependencies and application settings.
- Python dependencies that are not pinned can resolve to other versions on a
  backend that is set up later, and then the measurement differs. Set up all
  backends of a pool from the same package versions.
- To get the value for the policy, run
  `python3 -m janus.common.snp_attestation --list` on a backend that is set up
  like the others, with the same `JANUS_APP_*` settings. The backend also logs
  the value at startup (`Code measurement sha256:<hex> (PCR 15)`). A changed
  measurement needs a reboot of the CVM, because PCR 15 records one
  measurement per boot.
- Scope: the backend measures itself. The check detects a backend whose code,
  dependencies or application differ from the approved ones. It does not
  detect code that reports a false value. A measured boot chain that would
  close this is future work.
- A changed policy applies to new registrations. Backends already in the pool
  stay until the pool is reset (`deploy/README.md`, section 2).

Build/run the whole stack from the repo root README; SGX packaging is in
`../gramine/` and the CA in `../ca/`.
