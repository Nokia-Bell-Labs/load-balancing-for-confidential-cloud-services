<!--
  © 2026 Nokia
  Licensed under the BSD 3-Clause Clear License
  SPDX-License-Identifier: BSD-3-Clause-Clear
-->

# Deploy a Janus testbed from scratch

The evaluation testbed has three roles. Nothing in these scripts is specific
to our machines. Every address, name and port is a parameter.

| Role | What we used | Script |
| --- | --- | --- |
| SGX host (frontend) | Azure `Standard_DC2s_v3`, Ubuntu 22.04.5, kernel 6.8 (azure-fde), Gramine 1.7, Docker 29 | `install_vm_dependencies.sh`, the image build below, then `frontend_run.sh` |
| Backend CVM(s) | Azure `Standard_DC2ads_v5` (AMD SEV-SNP, vTPM), Ubuntu 22.04 CVM image | `backend_setup.sh` (pool backend or application backend) |
| Client / load generator | Azure `Standard_D8s_v5`, Ubuntu 22.04.5 | `client_setup.sh` |

All three roles must share a network. We use one subnet. All three roles
must reach the attestation service. The attestation service is Azure MAA,
at the regional endpoint, with no credentials.

The names used in browser experiments must resolve on the client **and**
inside the frontend. Cloud internal DNS names resolve inside the frontend.
Note: `/etc/hosts` entries do not reach the enclave.

## 1. SGX host

```sh
deploy/install_vm_dependencies.sh       # SGX driver/DCAP, Docker, Go, Node, Gramine build deps (Ubuntu 22.04)
ca/fetch_pebble.sh                      # the CA: Pebble v2.9.0 + ca/pebble-janus.patch, started as a container
docker build -f janus/frontend/Dockerfile -t janus/frontend .
make -C gramine signed-image MODULE=frontend        # -> janus/frontend-graminized (new MRENCLAVE per build)
EXTRA_SANS=<service-name>,<backend-name> deploy/frontend_run.sh    # the DNS names browsers dial (service + web-app backend);
                                                                 # SEALED_DIR, FRONTEND_PORT optional (see the script)
```

`frontend_run.sh` starts the container that the testbed of the artifact
runs. The sealed directory keeps the identity of the frontend across
restarts (design §4.2). Delete the contents of the sealed directory to force
a new certificate. A new certificate is necessary after you change the SANs
or rebuild the image.

## 2. Backend CVM

```sh
FRONTEND_URL=https://<frontend-ip>:6037 MY_NAME=<this-cvm-ip-or-dns-name> deploy/backend_setup.sh pool
FRONTEND_URL=https://<frontend-ip>:6037 MY_NAME=<this-cvm-ip-or-dns-name> deploy/backend_setup.sh app
```

A pool of N backends is N CVMs. Each CVM runs `backend_setup.sh pool`
against the same `FRONTEND_URL`. Each backend registers itself and appears
in the `/pool_status` of the frontend.

To reset the pool, do these steps:

1. Stop the backends.
2. Empty the sealed directory of the frontend.
3. Restart the frontend with `frontend_run.sh`.
4. Start the backends again.

After the reset, the frontend gets a fresh identity and the backends get
fresh keys (design §4.2/§4.3). The application backend is one of the pool
members. You start it with `app` instead of `pool`.

`pool` installs the dependencies. It builds `dc_proxy` against the pinned
BoringSSL (`janus/backend/dc_proxy/`). It starts a rate-capped backend
(10 req/s, as in Fig. 6) with one DC-TLS terminator on `:8443`. `app` does
the same and adds what the application workloads need:

- the hotelReservation stack (`apps/microservice_app/fetch.sh`),
- the web app,
- the RA+TLS interpreter and server,
- the HTTPA/2 server,
- the DC and X.509 fronts for each of them.

The script header lists the ports. You can re-run either mode. Both modes
are idempotent.

## 3. Client

```sh
FRONTEND_HOST=<frontend> BACKEND_HOST=<application backend> CA_ROOT_PEM=<the CA root certificate> \
  VANILLA_CA_PEM=<the backend's vanilla-CA certificate, ~/vanilla-ca/ca.crt from backend_setup.sh app> \
  BROWSER_FRONTEND=<service DNS name> BROWSER_BACKEND=<web-app backend DNS name> deploy/client_setup.sh
```

`client_setup.sh` does these steps:

- It installs the dependencies of the measurement scripts in `eval/`.
- It builds the NSS DC client and its trust database.
- It builds the RA+TLS interpreter (`baselines/ratls/build_python_with_ratls.sh`).
- It installs Firefox ESR and geckodriver with an enterprise policy that trusts the CA.
- It packages the browser extension.
- It writes `eval/ae/testbed.env` from the values you pass.

Then run `eval/ae/check_testbed.sh`.

Two files come from the operator. The first file is the CA root that the
frontend certificate chains to. It is `ca/pebble/ca_certs/root-ca.pem` on
the SGX host. The second file is the vanilla CA that the X.509 front of the
web app uses. It is `~/vanilla-ca/ca.crt` on the application backend. The
setup takes the intermediate from the certificate chain that the frontend
serves.

DNS on the client and inside the enclave must resolve the browser names.

## 4. LLM backend (on request)

The H100 CVM serves Llama-3.1-8B-Instruct with vLLM
(`apps/llm_app/serve_vllm.py`). You obtain the model and the ShareGPT
prompts yourself (`docs/DEPENDENCIES.md`).

The directory `eval/staging/` holds the scripts we used to stage the data
through a blob container. We wrote these scripts for our storage account.
Set `RG`, `STORAGE_ACCOUNT` and `MODEL_ID` in `eval/staging/env.sh`. The
CVM-side pull script is a template that lists the manual steps.

Topology for Fig. 7(b): the H100 CVM registers with the frontend like any
backend. It runs `dc_proxy` on `:8443` (DC) and `:8444` (X.509). Both relay
to vLLM on `:8000`. Janus-proxy goes through the `/forward` of the frontend
to `:8443`.

The HTTPA/2 and RA+TLS servers stay on the application backend CVM. They
relay to the LLM with `LLM_URL=http://<h100-private-ip>:8000`. Thus vLLM
must listen on the private interface (`--bind 0.0.0.0`, private VNet only),
not on localhost.

The pool holds only the H100 CVM during this experiment. The X.509 front of
the H100 CVM serves a leaf that the vanilla CA of the testbed issued. The
NSS database of the client and Firefox trust this vanilla CA.
`deploy/backend_setup.sh` creates the vanilla CA, and `deploy/client_setup.sh`
installs it. The fronts of the application backend serve leaves from the
same vanilla CA. Thus the same NSS client measures the vanilla rows and the
Janus rows.
