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
- Frontend env knob: `ISSUE_DC=0` skips DC issuance (proxy-only deployments).

## Backend admission (SEV-SNP/TDX)

The frontend admits a backend on three separate identities. Each is checked
against its own source of truth.

1. **CVM.** On Azure the CVM has no expected value. The SNP launch
   measurement covers only Azure's firmware and paravisor, and it differs
   between hosts. Neither Azure nor Canonical publishes reference values for
   the Ubuntu CVM image. The frontend therefore requires the Azure Attestation
   claims `x-ms-attestation-type=sevsnpvm`,
   `x-ms-compliance-status=azure-compliant-cvm` and
   `x-ms-sevsnpvm-is-debuggable=false`. It logs the launch measurement as the
   CVM hash. `EXPECTED_CVM_MEASUREMENT=<hex>`, when set, must equal the launch
   measurement. It is for platforms that publish a CVM measurement, and stays
   unset on Azure.
2. **Janus, checked against a Janus release.** The Janus measurement
   (`snp_attestation.janus_measurement_entries`) covers:
   - every `.py` file of the `janus` package, except the BoringSSL and
     snpguest checkouts that the setup fetches into it;
   - the `dc_proxy` binary, with BoringSSL linked into it;
   - the installed `snpguest` binary;
   - the setup scripts that run on the backend (`deploy/backend_setup.sh`,
     `janus/backend/*.sh`);
   - the files of the Python distributions in `backend/requirements.txt` and
     of their dependencies.

   The frontend compares it with `EXPECTED_JANUS_MEASUREMENT=sha256:<hex>`.
3. **Application, checked against the developer's package.** The application
   measurement (`snp_attestation.app_measurement_entries`) covers the files and
   directories in `JANUS_APP_MEASURE` and the container image IDs in
   `JANUS_APP_IMAGES`. Both are comma-separated and set on the backend. The
   frontend compares it with `EXPECTED_APP_MEASUREMENT=sha256:<hex>`. A
   backend with no application measures an empty list, which is
   `sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.

Each `EXPECTED_*` value is optional. When it's unset, the frontend admits any
value that the quote proves, and logs it.

The backend extends vTPM PCR 15 with two events per boot, the Janus
measurement first and then the application measurement. It sends both values,
and the frontend checks that the quoted PCR 15 equals exactly that sequence of
two extensions. If the measured code or application changes, reboot the CVM
before you start the backend again.

To get the expected values, run `python3 -m janus.common.snp_attestation
--list`, with the same `JANUS_APP_*` settings, on a backend set up from the
release and package. The backend also logs both values at startup.

`deploy/frontend_run.sh` passes the `EXPECTED_*` variables to the container,
and the enclave manifest passes them on to the frontend. A changed policy
applies to new registrations. Backends already in the pool stay until the pool
is reset (`deploy/README.md`, section 2).

### Limitations

- **The backend measures itself.** The check detects a backend whose code,
  dependencies or application differ from the approved ones. It relies on the
  CVM giving no one root access, which an audit of the CVM configuration must
  establish. Anyone with root can extend any value into PCR 15.
- **The testbed is insecure.** The artifact-evaluation testbed (`deploy/`)
  gives the operator SSH and `sudo`. On Azure the frontend can't tell it apart
  from an audited CVM, so its measurements prove nothing against the operator.
- **The host supplies the expected values.** They reach the SGX frontend as
  environment variables, through the existing `loader.insecure__use_host_env`
  (see `gramine/entrypoint.manifest.template`).
- **Pinned versions are needed for matching values.** Python dependencies that
  aren't pinned can resolve to other versions on a backend set up later. The
  `dc_proxy` and `snpguest` binaries are built on the backend, so the release
  value holds only where those builds are reproducible. Both were identical
  across two Azure CVMs, once `fetch_snp_tools.sh` pinned the build date of
  `snpguest` with `SOURCE_DATE_EPOCH`. A newer compiler can still change them.
  Set up every backend of a pool from the same package versions.

Build/run the whole stack from the repo root README; SGX packaging is in
`../gramine/` and the CA in `../ca/`.
