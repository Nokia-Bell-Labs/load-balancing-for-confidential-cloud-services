# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

# Orchestration of the measurement scripts.
#
# All targets accept RUN_ID=<id> (default: date-shortsha).  If you run again
# with the same RUN_ID, runner.py refuses to overwrite the raw CSVs. To overwrite them,
# pass --force to runner.py directly.

SHELL := /usr/bin/env bash

DATE      := $(shell date -u +%Y-%m-%d)
SHORT_SHA := $(shell git rev-parse --short HEAD 2>/dev/null || echo nogit)
RUN_ID    ?= $(DATE)-$(SHORT_SHA)
OUT       := data/$(RUN_ID)
RESULTS   := results/$(RUN_ID)

# Stock Python for all protocols except RA+TLS.  RA+TLS needs the patched
# Python build that exposes the ``ratls_bridge`` C extension.
PYTHON       ?= python3
RATLS_PYTHON ?= $(abspath $(dir $(lastword $(MAKEFILE_LIST))))/../baselines/python-ratls/bin/python3

# RA+TLS is in the last slot, so a missing RATLS_PYTHON does not block the
# other protocols.  Override PROTOCOLS to skip a protocol, for example:
#   make eval PROTOCOLS='vanilla ctls_proxy ctls_redirect httpa'
PROTOCOLS := vanilla ctls_proxy ctls_redirect httpa ratls

.PHONY: help print env eval eval-warm eval-cold eval-scale aggregate clean-pyc

help:
	@echo 'Measurement scripts.  Common targets:'
	@echo '  make print         show resolved RUN_ID / paths'
	@echo '  make env           capture environment snapshot into $$(OUT)'
	@echo '  make eval          latency (warm + cold) for all protocols'
	@echo '  make eval-warm     latency warm-cache pass (headline)'
	@echo '  make eval-cold     latency cold-cache pass'
	@echo '  make eval-scale    scalability run (per-rate, all protocols)'
	@echo '  make aggregate     summary statistics into $$(OUT)/summary.csv'
	@echo '  (figures: eval/ae/ae.py -m figures, see plotting/README.md)'
	@echo
	@echo 'Override RUN_ID to run again or to tag a run:'
	@echo '  make eval RUN_ID=2026-05-28-paper-rev1'

print:
	@echo "RUN_ID=$(RUN_ID)"
	@echo "OUT=$(OUT)"
	@echo "RESULTS=$(RESULTS)"

env:
	./env_snapshot.sh $(OUT)

eval-warm: env
	@for p in $(PROTOCOLS); do \
		py=$(PYTHON); [ "$$p" = "ratls" ] && py=$(RATLS_PYTHON); \
		echo "==> $$p (warm) [$$py]"; \
		"$$py" runner.py --protocol $$p --mode latency --out $(OUT) --cache-policy warm || exit $$?; \
	done

eval-cold: env
	@for p in $(PROTOCOLS); do \
		py=$(PYTHON); [ "$$p" = "ratls" ] && py=$(RATLS_PYTHON); \
		echo "==> $$p (cold) [$$py]"; \
		"$$py" runner.py --protocol $$p --mode latency --out $(OUT) --cache-policy cold || exit $$?; \
	done

# Scalability run: open-loop Poisson arrivals at each rate in
# runs.yaml::scale.rates_rps.  The default is the warm cache for the headline
# saturation curves. Override CACHE=cold to also collect cold runs.
CACHE ?= warm

eval-scale: env
	@for p in $(PROTOCOLS); do \
		py=$(PYTHON); [ "$$p" = "ratls" ] && py=$(RATLS_PYTHON); \
		echo "==> $$p (scale, $(CACHE)) [$$py]"; \
		"$$py" runner.py --protocol $$p --mode scale --out $(OUT) --cache-policy $(CACHE) || exit $$?; \
	done

eval: eval-warm eval-cold

aggregate:
	python3 analysis/aggregate.py $(OUT)

clean-pyc:
	find . -type d -name __pycache__ -exec rm -rf {} +
