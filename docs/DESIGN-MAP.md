<!--
  © 2026 Nokia
  Licensed under the BSD 3-Clause Clear License
  SPDX-License-Identifier: BSD-3-Clause-Clear
-->

# Design to code map

This document lists every mechanism that the paper describes, and where it lives in the code. Section numbers are the paper's. Each entry names the function. The same text is also in the source as a comment of the form `PAPER: §4.3 Step 5 — …`. Thus these commands find the implementation directly:

```
grep -rn "PAPER: §4.3" janus/        # everything for backend registration
grep -rn "PAPER: §4.4 Check" janus/  # the client-side checks
```

There are 29 markers across Python, C and JS.

## Components (§4.1 architecture)

| Paper component | Code | Runs on |
| --- | --- | --- |
| Frontend (small attested TEE, sole CA-issued identity, admits backends, issues DCs) | `janus/frontend/frontend_server.py`: `FrontendServer` (non-TEE mode) and `FrontendServerEnclave` (SGX). Key store: `janus/frontend/key_store.py` | Intel SGX under Gramine (`gramine/`) |
| Backend (TEE hosting the application) | `janus/backend/backend_server.py` (registration, app) + `janus/backend/dc_proxy/proxy.c` (DC-TLS terminator inside the TEE) | AMD SEV-SNP CVM |
| Client (library) | `janus/client/proxy.py` (proxy mode), `janus/client/redirect.py` (redirection mode), `janus/client/attest.py` (checks 2–4) | anywhere |
| Client (browser) | `janus/client/browser_extension/` (Firefox WebExtension: `janus/client/browser_extension/src/lib/sgx-validator.js`, `janus/client/browser_extension/src/background/background.js`) | stock Firefox |
| Client (native, DC-capable) | `janus/client/native/nss_dc_helper.c` (NSS, validates the DC in-band) | anywhere with NSS |
| CA (preserves the attestation CSR extension) | `ca/pebble-janus.patch` on Pebble v2.9.0. `ca/fetch_pebble.sh` | frontend host |
| AS | Azure MAA (`https://sharedweu.weu.attest.azure.net`). SGX path `janus/common/attestation_verifier.py`, SNP path `janus/common/snp_attestation.py` | external service |
| Shared DC code (RFC 9345 sign / parse / verify) | `janus/common/dc.py` | not applicable |

## §4.2 Frontend startup

| Step | Where |
| --- | --- |
| 1: keypair generated in the TEE | `FrontendServerEnclave._init_server_keypair` (sealed under Gramine's encrypted mount, `gramine/entrypoint.manifest.template`, key `_sgx_mrenclave`) |
| 2: quote with `REPORTDATA = SHA-256(public key)`, no nonce | `_write_enclave_report_data` |
| 3–4: quote to the AS, JWT back | `_init_tls_certificate_with_sgx` → `attestation_verifier.get_attestation_verifier().verify_quote` |
| 5: CSR with the JWT extension (OID `1.3.6.1.4.1.99999.3.1`) and RFC 9345 `DelegationUsage` (`1.3.6.1.4.1.44363.44`) | `_build_csr_with_extensions` |
| 6: CA verifies the CSR and binds the JWT into the certificate | `ca/pebble-janus.patch` (`ca/ca.go`). ACME client: `janus/common/acme_client.py` |
| Persistence and fault tolerance: a restart unseals and resumes, and re-attests only near JWT/certificate expiry | `_certificate_remaining_s`, `_sealed_certificate_valid`, the check in `FrontendServerEnclave.__init__`, and the watchdog `_renewal_loop` / `start_renewal_thread` (`JANUS_RENEW_MARGIN_S`, default 1 h. MAA JWTs live 8 h) |
| Small and stable TCB | the frontend is `janus/frontend/` + `janus/common/` only, with no application code |

## §4.3 Backend registration

| Step | Where |
| --- | --- |
| 1: TLS keypair in the TEE (fresh on every start) | `BackendServer._init_keypair` |
| 2: frontend issues a challenge nonce | frontend `handle_nonce` (`GET /nonce`) ↔ backend `_fetch_nonce` |
| 3: evidence binds `SHA-256(nonce ‖ TLS public key)` | `snp_attestation.registration_reportdata`, `build_snp_evidence_bundle` (SEV-SNP: vTPM quote `qualifyingData`, because the paravisor fixes the SNP report's `REPORT_DATA` at boot). SGX path `_write_report_data` |
| 4: CSR + evidence to the frontend | `BackendServer.register_with_frontend` → `POST /register_backend` |
| 5: frontend checks nonce freshness and the key binding | `FrontendServer.register_backend` (nonce registered, unused, unexpired: `NONCE_TTL_S`) → `snp_attestation.verify_snp_bundle` → `_verify_tpm_quote` |
| 6: AS verifies once per registration | `snp_attestation.submit_to_maa` (called from `verify_snp_bundle`) |
| 7: redirection mode, DC over the backend key, returned with the frontend chain | `FrontendServer.sign_dc` (format in `janus/common/dc.py`). The backend stores it in its sealed directory as `delegated_credential.bin` (`/dev/shm/janus-backend-sealed` on a CVM, `sealed/` in direct mode) |
| DC in the TLS `Certificate` message | `dc_proxy` `add_dc_credential` (BoringSSL `SSL_CREDENTIAL_new_delegated`) |
| Backend irregularities, decommission / compromise: drop from the pool | `handle_mark_cvm`, `handle_stop_cvm` (owner-signed), `select_backend` serves in-service only |
| Backend irregularities, certificate renewal: re-sign and send all DCs | frontend `_resign_and_push_dcs` → backend `handle_renew_dc` / `install_renewed_dc` (validates under the pinned frontend key) → `dc_proxy` reloads on `SIGHUP` (`build_ctx`, pidfile) |
| Restarted backend re-registers as a fresh one | `BackendServer.initialise` (no credential reuse) |

## §4.4 Client connection establishment

| Element | Where |
| --- | --- |
| Proxy mode, Check 1: standard chain validation | Firefox natively. NSS client via its trust DB. The Python measurement client connects by IP to a certificate of the testbed CA (`janus/client/proxy.py` constructor) |
| Check 2: JWT signature with the AS key, AS pinned | `attest.get_maa_public_key` + `attest.check_as_trust` (issuer and JWKS origin must be the configured AS) + `attest.verify_jwt_rs256`, `verify_jwt_validity` |
| Check 3: `REPORTDATA == SHA-256(frontend public key)` | `attest.verify_reportdata_ctls` |
| Check 4: measurement / platform claims policy | browser: `sgx-validator.js` (`expectedMrenclave`, `expectedMrsigner`). Python clients: none. The evaluator's pre-flight `eval/ae/check_testbed.sh` compares the frontend's MRENCLAVE with `EXPECTED_MRENCLAVE` |
| Abort on any failure | Python raises. Browser `background.js handleHeaders` cancels the navigation |
| Proxy mode: frontend↔backend TLS into the backend TEE, authenticated with the key recorded at registration | `FrontendServer.get_backend_session` (pinned to the backend's certificate fingerprint recorded in `register_backend`) ↔ `dc_proxy` `add_x509_credential`. `handle_forward` |
| Redirection mode: `/route` returns the backend address | `handle_route`, `select_backend`. Client `RedirectClient.attest_frontend` |
| Redirection mode: client verifies the DC against the frontend certificate | NSS in-band (`nss_dc_helper.c`, `SSL_ENABLE_DELEGATED_CREDENTIALS`, `peerDelegCred`). `RedirectClient.check_binding` also requires the delegating leaf to be the attested frontend certificate |
| AS signing-key caching, refresh at the rotation window or passively on a failed check | `eval/clients/_base.py JwksCache` (`JANUS_JWKS_MAX_AGE_S`), refetch-on-failure in `proxy.py` / `redirect.py` |

## §5 Implementation

| Claim | Where |
| --- | --- |
| Frontend: Python/Flask on SGX under Gramine | `gramine/Dockerfile_frontend_graminized`, `gramine/entrypoint.manifest.template` |
| Backend: Python/Flask on SEV-SNP, C reverse proxy on BoringSSL terminating DC-TLS in the TEE | `janus/backend/dc_proxy/proxy.c` (relays to the app over TCP. A Unix socket is supported with `--backend /path`) |
| Clients: Firefox extension, native client | `janus/client/browser_extension/`, `janus/client/native/` (NSS) |
| CA: Pebble patched to preserve CSR extensions | `ca/pebble-janus.patch` |
