# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

# OHTTP+KMS baseline — convenience targets (same shape as baselines/httpa).
#
# `make mock`   — bring up KMS + untrusted front end + gateway + stand-in app
#                 on this host with attestation mocked (no TEE, no MAA)
# `make local-test` — `make mock`, run the client warm and cold, stop all
# `make stop`   — tear the mock stack down
#
# Ports: KMS 6038 (attested identity), front end 6039 (untrusted forwarder),
#        gateway 8443 (in the CVM slot), app 8080 (loopback).

PY        ?= python3
ROOT      := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/../../..)
RUN       := /tmp/ohttp-mock
KMS_PORT  ?= 6038
FE_PORT   ?= 6039
GW_PORT   ?= 8443
APP_PORT  ?= 8080

export PYTHONPATH := $(ROOT):$(ROOT)/baselines/ohttp

mock:
	@rm -rf $(RUN)
	@mkdir -p $(RUN)/kms $(RUN)/fe $(RUN)/gw   # fresh state: an empty pool, a fresh gateway key
	@echo "[mock] KMS (frontend code, direct mode) on :$(KMS_PORT)"
	@JANUS_SEALED_DIR=$(RUN)/kms OHTTP_ALLOW_ROTATE_API=1 OHTTP_ROTATION_S=86400 JANUS_ALLOW_MOCK_ATTESTATION=1 \
	  nohup $(PY) -m ohttp.kms --type direct --port $(KMS_PORT) > $(RUN)/kms.log 2>&1 & echo $$! > $(RUN)/kms.pid
	@echo "[mock] untrusted front end (frontend code, direct mode, no DC) on :$(FE_PORT)"
	@JANUS_SEALED_DIR=$(RUN)/fe ISSUE_DC=0 JANUS_ALLOW_MOCK_ATTESTATION=1 \
	  nohup $(PY) -m janus.frontend.frontend_server --type direct --port $(FE_PORT) > $(RUN)/fe.log 2>&1 & echo $$! > $(RUN)/fe.pid
	@echo "[mock] stand-in app on 127.0.0.1:$(APP_PORT)"
	@nohup $(PY) $(ROOT)/apps/browser_app/app.py --port $(APP_PORT) > $(RUN)/app.log 2>&1 & echo $$! > $(RUN)/app.pid
	@for i in $$(seq 1 40); do curl -sk https://127.0.0.1:$(KMS_PORT)/ >/dev/null && curl -sk https://127.0.0.1:$(FE_PORT)/ >/dev/null && break; sleep 0.5; done
	@echo "[mock] gateway on :$(GW_PORT) -> app (mock attestation, lazy key fetch)"
	@cd $(RUN)/gw && APP_HOME=$(RUN)/gw OHTTP_MOCK_ATTEST=1 FRONTEND_CA_CERT_PATH=insecure \
	  OHTTP_TARGET=http://127.0.0.1:$(APP_PORT) \
	  nohup $(PY) -m ohttp.gateway --kms-url https://127.0.0.1:$(KMS_PORT) \
	    --frontend-url https://127.0.0.1:$(FE_PORT) --my-ip 127.0.0.1 --port $(GW_PORT) --cvm-type snp \
	    > $(RUN)/gw.log 2>&1 & echo $$! > $(RUN)/gw.pid
	@for i in $$(seq 1 40); do curl -sk https://127.0.0.1:$(GW_PORT)/health >/dev/null && break; sleep 0.5; done
	@echo "[mock] up. logs in $(RUN)/*.log"

local-test: mock
	@sleep 1
	@OHTTP_MOCK_VERIFY=1 $(PY) -m ohttp.client --kms https://127.0.0.1:$(KMS_PORT) \
	  --frontend https://127.0.0.1:$(FE_PORT) --path / --runs 2; RC=$$?; \
	  echo "[local-test] cold (rotate + refetch):"; \
	  curl -sk -X POST https://127.0.0.1:$(KMS_PORT)/rotate >/dev/null; \
	  OHTTP_MOCK_VERIFY=1 $(PY) -m ohttp.client --kms https://127.0.0.1:$(KMS_PORT) \
	    --frontend https://127.0.0.1:$(FE_PORT) --path / --cold --runs 1; RC2=$$?; \
	  $(MAKE) -s stop; exit $$((RC+RC2))

stop:
	@for p in gw app fe kms; do [ -f $(RUN)/$$p.pid ] && kill $$(cat $(RUN)/$$p.pid) 2>/dev/null; rm -f $(RUN)/$$p.pid; done; true

.PHONY: mock local-test stop
