# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

# HTTPA/2 baseline — convenience targets.
#
# `make cert`   — generate a self-signed cert/key for local testing
# `make run`    — run the server with the self-signed cert
# `make mock`   — run the server with attestation mocked (no snpguest needed)
# `make check`  — start mock server, run client once, stop server

PY      ?= python3
PORT    ?= 5443
CERT    ?= cert.pem
KEY     ?= key.pem
HOST    ?= 127.0.0.1

$(CERT) $(KEY):
	openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
	    -keyout $(KEY) -out $(CERT) -days 30 -nodes \
	    -subj '/CN=localhost' -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1'

cert: $(CERT) $(KEY)

run: cert
	$(PY) server.py --port $(PORT) --cert $(CERT) --key $(KEY)

mock: cert
	HTTPA_MOCK_ATTEST=1 $(PY) server.py --port $(PORT) --cert $(CERT) --key $(KEY)

check: cert
	HTTPA_MOCK_ATTEST=1 $(PY) server.py --port $(PORT) --cert $(CERT) --key $(KEY) & \
	  SERVER_PID=$$!; \
	  sleep 1; \
	  HTTPA_MOCK_VERIFY=1 $(PY) client.py --host $(HOST) --port $(PORT) --insecure; \
	  RC=$$?; \
	  kill $$SERVER_PID 2>/dev/null; wait $$SERVER_PID 2>/dev/null; \
	  exit $$RC

clean:
	rm -f $(CERT) $(KEY)

.PHONY: cert run mock check clean
