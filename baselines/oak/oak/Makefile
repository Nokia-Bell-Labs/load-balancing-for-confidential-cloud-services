# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

# Oak baseline — convenience targets (same shape as baselines/httpa).
#
# `make mock`   — start the server with attestation mocked (no TEE) + stand-in app
# `make local-test` — `make mock`, run the client three times, stop all
# `make run`    — start the server for real (needs snpguest/tpm2-tools + MAA)

PY       ?= python3
ROOT     := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/../../..)
RUN      := /tmp/oak-mock
PORT     ?= 8543
APP_PORT ?= 8080

export PYTHONPATH := $(ROOT):$(ROOT)/baselines/oak

mock:
	@mkdir -p $(RUN)
	@nohup $(PY) $(ROOT)/apps/browser_app/app.py --port $(APP_PORT) > $(RUN)/app.log 2>&1 & echo $$! > $(RUN)/app.pid
	@cd $(RUN) && OAK_MOCK_ATTEST=1 OAK_TARGET=127.0.0.1:$(APP_PORT) \
	  nohup $(PY) -m oak.server --port $(PORT) > $(RUN)/server.log 2>&1 & echo $$! > $(RUN)/server.pid
	@sleep 1.5
	@echo "[mock] up. logs in $(RUN)/*.log"

local-test: mock
	@OAK_MOCK_VERIFY=1 $(PY) -m oak.client --host 127.0.0.1 --port $(PORT) --path / --runs 3; RC=$$?; \
	  $(MAKE) -s stop; exit $$RC

run:
	@cd $(RUN) 2>/dev/null || mkdir -p $(RUN) && cd $(RUN); OAK_TARGET=127.0.0.1:$(APP_PORT) $(PY) -m oak.server --port $(PORT)

stop:
	@for p in server app; do [ -f $(RUN)/$$p.pid ] && kill $$(cat $(RUN)/$$p.pid) 2>/dev/null; rm -f $(RUN)/$$p.pid; done; true

.PHONY: mock local-test run stop
