<!--
  © 2026 Nokia
  Licensed under the BSD 3-Clause Clear License
  SPDX-License-Identifier: BSD-3-Clause-Clear
-->

# OHTTP+KMS baseline

This directory is our proof-of-concept of the design that combines attested Oblivious HTTP (OHTTP) with a key management service (KMS). Azure AI confidential inferencing uses this design (Microsoft technical deep-dive, 2024). The directory has the same layout as `baselines/httpa`.

Entities and roles:

| Entity | Location | Code |
| --- | --- | --- |
| **KMS** (attested, SGX) | frontend host, in an enclave | `ohttp/kms.py`. It uses the Janus frontend code (`FrontendServer`) for the attested identity (ACME certificate and MAA JWT) and for the attestation of the gateways (`register_backend`). It adds key generation, key rotation, `/keyconfig` and `/release_key`. |
| **Untrusted front end** (L7 load balancer, no TEE) | frontend host | The Janus frontend in direct mode with `ISSUE_DC=0`. It forwards `/forward/ohttp` round-robin. Janus-proxy uses the same code. |
| **Gateway** (backend) | each SEV-SNP CVM, in the `dc_proxy` slot | `ohttp/gateway.py`. It decapsulates each request, relays the plaintext to the application on loopback and seals the chunked response. It gets keys from the KMS when it first needs them. It uses the evidence code of the Janus backend. |
| **Client** | load generator | `ohttp/client.py`. It checks the KMS in the same way as the Janus client checks the frontend. It makes a new HPKE context for each request. |
| **Relay** (optional) | a separate VM | `relay/` holds an nginx relay (RFC 9458 Oblivious Relay Resource) and its setup scripts. |

`ohttp/relay.py` is an untrusted Python forwarder to the gateways (`OHTTP_GATEWAYS`). It keeps persistent upstream connections and streams the responses.

`ohttp/wire.py` holds the RFC 9458 primitives: the key configuration, request encapsulation with a fresh HPKE context for each request, the response key schedule, chunked records and the `enc`-window replay check (Section 6.5). The inner HTTP message uses a compact length-prefixed encoding instead of RFC 9292 binary HTTP. This encoding has no effect on the cryptographic cost or on the round trips.

Attestation policy: **once per key epoch per gateway**. A gateway attests to the KMS on the first request whose key identifier it does not hold. This occurs at startup and after each key rotation, as in the reference design. `OHTTP_ROTATION_S` sets the rotation interval. The default is one day. (The reference gateway of Microsoft keeps a released key for 24 hours. The Privacy Sandbox coordinator of Google rotates keys every week.)

## Run

Local run, without a TEE. The KMS and the front end run in direct mode. The gateway uses a mock quote.

```sh
make -C baselines/ohttp/ohttp local-test
```

Testbed:

```sh
# 1. The KMS, in the SGX enclave (frontend host):
docker build -f baselines/ohttp/Dockerfile -t janus/ohttp_kms .
make -C gramine signed-image MODULE=ohttp_kms
docker run -d --name ohttp-kms -e SERVER_TYPE=sgx -e APP_HOME=/home/janus \
  -e FRONTEND_PORT=6038 -e OHTTP_ALLOW_ROTATE_API=1 \
  --device /dev/sgx_enclave --device /dev/sgx_provision \
  -v /var/run/aesmd:/var/run/aesmd -p 6038:6038 janus/ohttp_kms-graminized
# 2. The untrusted front end (frontend host, no enclave). It admits pool members
#    without evidence, because the KMS attests them:
JANUS_SEALED_DIR=/tmp/ohttp_fe ISSUE_DC=0 JANUS_ALLOW_MOCK_ATTESTATION=1 \
  python3 -m janus.frontend.frontend_server --type direct --port 6039
# 3. A gateway on each CVM, with the application on 127.0.0.1:8080. Run
#    bash baselines/setup_baseline_cvm.sh on the CVM first. It prints the commands that
#    start the application for latency and for throughput runs. The gateway runs under
#    gunicorn, as in the paper runs, and keeps its keys in its own directory, apart from
#    the Janus backend:
export PYTHONPATH=$PWD:$PWD/baselines/ohttp KMS_URL=https://<kms>:6038 FRONTEND_URL=https://<fe>:6039 \
  MY_IP=<cvm-ip> MAA_URL=<maa url> JANUS_BACKEND_SEALED_DIR=/dev/shm/ohttp-gateway-sealed
read GW_CERT GW_KEY < <(sudo -E env PYTHONPATH=$PYTHONPATH python3 -m ohttp.gateway --print-tls-files)
sudo -E env PYTHONPATH=$PYTHONPATH python3 -m gunicorn --worker-class gthread --workers 1 --threads 32 \
  --keep-alive 75 --certfile $GW_CERT --keyfile $GW_KEY -b 0.0.0.0:8443 'ohttp.gateway:create_app()'
# 4. Measurement: set protocols.ohttp_kms in eval/configs/env.yaml, then (total_e2e_ms
#    ends at the first verified response, as in Table 2):
make -C eval eval PROTOCOLS=ohttp_kms
```

The gateway uses the evidence code of the Janus backend. Thus it extends PCR 15 with the Janus and application measurements, as a Janus backend does. If PCR 15 of the CVM already holds other measurements since boot, reboot the CVM first.

The gateway listens on `:8443`, the port of the `dc_proxy` of the Janus backend. On a CVM that runs the Janus backend, stop its `dc_proxy` (`:8443`) and its backend server (`:8080`) first.

Warm and cold (`cache_policy` in `eval/configs/runs.yaml`): in a warm run, the client holds the key configuration and the gateway holds the key. In a cold run, the client fetches and checks the key configuration again. With `rotate_on_cold`, the KMS also rotates its key first. Thus the gateway also attests on that request (the first request after a rotation). The breakdown CSV records the two costs in separate fields.
