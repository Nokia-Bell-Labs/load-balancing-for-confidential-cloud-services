# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

# RA-TLS Server Makefile
SHELL := /bin/bash

APP_USER ?= janus
APP_HOME ?= /home/$(APP_USER)

default: image

RATLS_SOURCE = $(shell find .)
image: \
	Dockerfile \
	$(RATLS_SOURCE)
	cd ../.. && docker -D -l debug build -f ratls/server/Dockerfile -t janus/ratls .

graminize: \
	Dockerfile \
	$(RATLS_SOURCE) \
	image
	make -C ../../graminize MODULE=ratls signed-image
	rm -f sealed/private_key
	rm -f sealed/fernet_key

sealed_dir:
	@$(shell mkdir -p "$(shell pwd)/sealed")
	@$(shell chmod 770 "$(shell pwd)/sealed")

# Run RA-TLS server in Docker (non-SGX)
run-docker:
	docker run -d --rm \
		--name ratls-server \
		-v $(shell pwd)/sealed:/home/janus/ratls/server/sealed \
		-p 5001:5001 \
		-e RATLS_PORT=5001 \
		-e ENVIRONMENT=direct \
		janus/ratls

# Run RA-TLS server in Docker with SGX
run-sgx: sealed_dir
	docker run -d --rm \
		--name ratls-server-sgx \
		--device=/dev/sgx_enclave:/dev/sgx_enclave \
		-v /var/run/aesmd/aesm.socket:/var/run/aesmd/aesm.socket \
		-v $(shell pwd)/sealed:$(APP_HOME)/ratls/server/sealed --user 1000:1000 \
		-p 5001:5001 \
		-e RATLS_PORT=5001 \
		-e ENVIRONMENT=sgx \
		-e APP_HOME=$(APP_HOME) \
		janus/ratls-graminized

# RA-TLS targets (non-SGX testing)
run-local:
	@echo "Starting RA-TLS server locally..."
	../../python-ratls/bin/python3 ratls_server.py --port 5001 --environment direct

run-client:
	@echo "Testing RA-TLS client connection..."
	../../python-ratls/bin/python3 ../client/ratls_client.py --host localhost --port 5001

# RA-TLS SGX targets
ratls-manifest:
	@echo "Generating RA-TLS manifest..."
	cd ../gramine && python3 finalize-manifest.py \
		--template ratls.manifest.template \
		--output ../server/ratls.manifest \
		--module ratls_server.py

ratls-sign: ratls-manifest
	@echo "Signing RA-TLS manifest..."
	gramine-sgx-sign \
		--manifest ratls.manifest \
		--output ratls.manifest.sgx

run-sgx-local: ratls-sign sealed_dir
	@echo "Starting RA-TLS server in SGX mode..."
	gramine-sgx python3 ratls_server.py --port 5001

# Benchmark RA-TLS performance
benchmark:
	@echo "Running RA-TLS benchmark..."
	../../python-ratls/bin/python3 ../../benchmarks/scripts/benchmark_ratls.py --skip-tls --ratls-port 5001 --iterations 50

benchmark-compare:
	@echo "Running TLS vs RA-TLS comparison benchmark..."
	../../python-ratls/bin/python3 ../../benchmarks/scripts/benchmark_ratls.py --tls-port 6037 --ratls-port 5001 --iterations 50

clean:
	rm -f *.tar.gz
	rm -rf sealed/*
	rm -f ratls.manifest ratls.manifest.sgx ratls.sig
