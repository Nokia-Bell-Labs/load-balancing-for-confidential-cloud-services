#!/bin/bash
# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

# Set up and start a Janus backend on a SEV-SNP CVM (Ubuntu 22.04).  Idempotent.
#   backend_setup.sh pool   capped backend + DC terminator :8443 (Fig. 6 pool member; Tables 1-2)
#   backend_setup.sh app    the same, plus the application workloads and baseline servers
# Env:
#   FRONTEND_URL  https://<frontend>:6037            (required)
#   MY_NAME       address or DNS name to register as (required; browsers dial it in redirection mode)
#   PUBLIC_PORT   registered port (8443); CAP=0 disables the 10 req/s cap
#   SEALED_DIR    /dev/shm/janus-backend-sealed (RAM-backed; design §4.3)
# Ports (app): hotel :5000 behind :8543 (DC) / :8544 (X.509); web app :5001 behind :8643 / :8644;
#              HTTPA/2 :5002; RA+TLS :5004; test application :8080 behind :8443 (DC) / :8444 (X.509)
set -euo pipefail
ROLE="${1:?pool|app}"; FRONTEND_URL="${FRONTEND_URL:?}"; MY_NAME="${MY_NAME:?}"; PUBLIC_PORT="${PUBLIC_PORT:-8443}"
SEALED_DIR="${SEALED_DIR:-/dev/shm/janus-backend-sealed}"; CAP="${CAP:-1}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; cd "$ROOT"
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq build-essential cmake git python3-pip pkg-config >/dev/null 2>&1
python3 -c "import flask, cryptography, requests" 2>/dev/null || pip3 install -q -r janus/backend/requirements.txt
command -v snpguest >/dev/null || bash janus/backend/fetch_snp_tools.sh          # snpguest (pinned) + tpm2-tools: the SEV-SNP evidence path
[ -d janus/backend/dc_proxy/boringssl ] || bash janus/backend/dc_proxy/fetch_boringssl.sh   # pinned BoringSSL + boringssl-dc.patch
[ -x janus/backend/dc_proxy/dc_proxy ] || make -C janus/backend/dc_proxy
B=./janus/backend/dc_proxy/dc_proxy
pkill -f "janus.backend.backend_server" 2>/dev/null || true; sleep 1
CAPENV=""; [ "$CAP" = 1 ] && CAPENV="CTLS_SERVICE_MS=100 CTLS_MAX_INFLIGHT=1"
env $CAPENV JANUS_BACKEND_SEALED_DIR="$SEALED_DIR" setsid nohup python3 -m janus.backend.backend_server \
  --frontend-url "$FRONTEND_URL" --cvm-type snp --my-ip "$MY_NAME" --port 8080 --public-port "$PUBLIC_PORT" \
  --bind 127.0.0.1 --plain --type direct > /tmp/janus-backend.log 2>&1 < /dev/null &
for i in $(seq 1 30); do grep -q "Registered: cvm_id" /tmp/janus-backend.log 2>/dev/null && break; sleep 3; done
grep -q "Registered: cvm_id" /tmp/janus-backend.log || { echo "registration failed:"; tail -5 /tmp/janus-backend.log; exit 1; }
front() { local port=$1; shift; pgrep -f "dc_proxy --listen $port " >/dev/null || { setsid nohup $B --listen "$port" "$@" > "/tmp/dc_proxy-$port.log" 2>&1 < /dev/null & }; }
front 8443 --backend 127.0.0.1:8080 --sealed-dir "$SEALED_DIR"
if [ "$ROLE" = app ]; then
  # X.509 identities for the vanilla-TLS fronts: a self-signed one for the test-application, hotel and HTTPA fronts,
  # and, for the web app that browsers dial, a leaf for MY_NAME under a small "public" CA (see deploy/README.md)
  mkdir -p "$HOME/vanilla-ca"; cd "$HOME/vanilla-ca"
  [ -f van.crt ] || openssl req -x509 -newkey rsa:2048 -keyout van.key -out van.crt -days 365 -nodes -subj "/CN=$MY_NAME" 2>/dev/null
  [ -f ca.crt ] || openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout ca.key -out ca.crt -days 3650 -subj "/O=Janus testbed/CN=Vanilla TLS CA" -addext basicConstraints=critical,CA:TRUE 2>/dev/null
  [ -f be.crt ] || { openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout be.key -out be.csr -subj "/CN=$MY_NAME" 2>/dev/null
    printf "subjectAltName=DNS:%s\nbasicConstraints=CA:FALSE\n" "$MY_NAME" > ext.cnf; openssl x509 -req -in be.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 825 -extfile ext.cnf -out be.crt 2>/dev/null; }
  cd "$ROOT"
  command -v docker >/dev/null || sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq docker.io docker-compose-v2 >/dev/null 2>&1
  [ -d apps/microservice_app/DeathStarBench ] || bash apps/microservice_app/fetch.sh     # pinned, unmodified
  # the checkout's compose file names deathstarbench/hotel-reservation:latest; pin the image the paper's testbed ran (docs/DEPENDENCIES.md)
  sudo docker image inspect deathstarbench/hotel-reservation:latest >/dev/null 2>&1 || { sudo docker pull -q deathstarbench/hotel-reservation@sha256:488d8980c81eeae337d089185f2dd2643dec589809e102c2abf65a4d6e9bb436 && sudo docker tag deathstarbench/hotel-reservation@sha256:488d8980c81eeae337d089185f2dd2643dec589809e102c2abf65a4d6e9bb436 deathstarbench/hotel-reservation:latest; }
  sudo docker ps --format '{{.Names}}' | grep -q hotelreservation-frontend || (cd apps/microservice_app/DeathStarBench/hotelReservation &&  sudo docker compose up -d --no-build >/dev/null 2>&1)
  pgrep -f "apps/browser_app/app.py --port 5001" >/dev/null || { setsid nohup python3 apps/browser_app/app.py --port 5001 --bind 127.0.0.1 > /tmp/webapp.log 2>&1 < /dev/null & }
  front 8444 --backend 127.0.0.1:8080 --x509-cert "$HOME/vanilla-ca/van.crt" --x509-key "$HOME/vanilla-ca/van.key"
  front 8543 --backend 127.0.0.1:5000 --sealed-dir "$SEALED_DIR"
  front 8544 --backend 127.0.0.1:5000 --x509-cert "$HOME/vanilla-ca/van.crt" --x509-key "$HOME/vanilla-ca/van.key"
  front 8643 --backend 127.0.0.1:5001 --sealed-dir "$SEALED_DIR"
  front 8644 --backend 127.0.0.1:5001 --x509-cert "$HOME/vanilla-ca/be.crt" --x509-key "$HOME/vanilla-ca/be.key"
  pgrep -f "httpa/server.py --port 5002" >/dev/null || { HOTEL_URL=http://127.0.0.1:5000 setsid nohup python3 baselines/httpa/httpa/server.py --port 5002 --cert "$HOME/vanilla-ca/van.crt" --key "$HOME/vanilla-ca/van.key" > /tmp/httpa.log 2>&1 < /dev/null & }
  [ -x baselines/python-ratls/bin/python3 ] || bash baselines/ratls/build_python_with_ratls.sh > /tmp/python-ratls-build.log 2>&1
  # the RA+TLS bridge spawns the SNP evidence helper; point it at this checkout (its compiled-in fallback path is not ours)
  pgrep -f "ratls_http_server.py --port 5004" >/dev/null || (cd baselines && HOTEL_URL=http://127.0.0.1:5000 PYTHONPATH="$ROOT" APP_HOME="$HOME" RATLS_BUNDLE_CLI="$ROOT/janus/common/snp_bundle_cli.py" setsid nohup python-ratls/bin/python3 ratls/server/ratls_http_server.py --port 5004 --type snp > /tmp/ratls.log 2>&1 < /dev/null &)
fi
sleep 3; echo "$(hostname) registered as $MY_NAME:$PUBLIC_PORT; listening: $(ss -ltn | grep -oE ':(8443|8444|8543|8544|8643|8644|5002|5004) ' | tr -d ' ' | sort | tr '\n' ' ')"
