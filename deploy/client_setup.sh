#!/bin/bash
# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

# Prepare a client / load-generator VM (Ubuntu 22.04) for the artifact's experiments.  Idempotent.
# Env (required): FRONTEND_HOST, BACKEND_HOST, CA_ROOT_PEM (the testbed CA's root certificate, PEM)
# Env (optional): FRONTEND_PORT (6037), RATLS_HOST/HTTPA_HOST (=BACKEND_HOST), BROWSER_FRONTEND/BROWSER_BACKEND
#                 (DNS names in the frontend certificate's SAN; default: the hosts above), IFACE (eth0)
set -euo pipefail
: "${FRONTEND_HOST:?}" "${BACKEND_HOST:?}" "${CA_ROOT_PEM:?}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; cd "$ROOT"; FRONTEND_PORT="${FRONTEND_PORT:-6037}"
sudo DEBIAN_FRONTEND=noninteractive apt-get update -qq >/dev/null
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq build-essential pkg-config git wget curl libnss3-dev libnss3-tools \
  python3-pip libffi-dev zlib1g-dev libbz2-dev libreadline-dev libsqlite3-dev liblzma-dev libssl-dev libtool autoconf automake \
  iproute2 patchelf libgtk-3-0 libdbus-glib-1-2 libasound2 libx11-xcb1 libxt6 nodejs npm >/dev/null 2>&1
sudo pip3 install -q -r eval/requirements.txt
# 1. NSS DC client + trust database with the CA root
make -s -C janus/client/native
mkdir -p "$HOME/nss_client/nssdb"; cp -f janus/client/native/nss_dc_helper "$HOME/nss_client/"
[ -f "$HOME/nss_client/nssdb/cert9.db" ] || certutil -N -d "sql:$HOME/nss_client/nssdb" --empty-password
certutil -L -d "sql:$HOME/nss_client/nssdb" | grep -q janus-root || certutil -A -d "sql:$HOME/nss_client/nssdb" -n janus-root -t "CT,C,C" -i "$CA_ROOT_PEM"
# 2. RA+TLS interpreter (Python 3.10 + the RA+TLS OpenSSL, pinned + patched) and its bridge
[ -x baselines/python-ratls/bin/python3 ] || bash baselines/ratls/build_python_with_ratls.sh > "$HOME/python-ratls-build.log" 2>&1
baselines/python-ratls/bin/python3 -m pip install -q pyyaml==5.4.1 cryptography==50.0.1 requests==2.34.2 urllib3==2.8.0
(cd baselines/ratls/server && ../../python-ratls/bin/python3 setup.py build_ext --inplace >/dev/null 2>&1)
# 3. Firefox ESR + geckodriver + the extension, trusting the CA root and the frontend's intermediate via enterprise policy
mkdir -p "$HOME/browser_bench" "$HOME/downloads"
# pinned downloads (versions used for the paper's browser runs), verified by checksum
FIREFOX_VER=140.16.0esr; FIREFOX_SHA256=a90174f8fecfb1767371015a625a2f7ffc1edafd9110717348e797a46a066edf
GECKO_VER=v0.35.0;       GECKO_SHA256=ac26e9ba8f3b8ce0fbf7339b9c9020192f6dcfcbf04a2bcd2af80dfe6bb24260
fetch() { local url=$1 out=$2 sum=$3; [ -f "$out" ] || wget -q -O "$out" "$url"; echo "$sum  $out" | sha256sum -c --quiet || { echo "checksum mismatch for $out"; exit 1; }; }
[ -x "$HOME/firefox/firefox" ] || { fetch "https://archive.mozilla.org/pub/firefox/releases/$FIREFOX_VER/linux-x86_64/en-US/firefox-$FIREFOX_VER.tar.xz" "$HOME/downloads/firefox.tar.xz" "$FIREFOX_SHA256"; tar -xf "$HOME/downloads/firefox.tar.xz" -C "$HOME"; }
[ -x "$HOME/geckodriver" ] || { fetch "https://github.com/mozilla/geckodriver/releases/download/$GECKO_VER/geckodriver-$GECKO_VER-linux64.tar.gz" "$HOME/downloads/geckodriver.tar.gz" "$GECKO_SHA256"; tar -xzf "$HOME/downloads/geckodriver.tar.gz" -C "$HOME"; }
cp -f "$CA_ROOT_PEM" "$HOME/browser_bench/janus-root.pem"
openssl s_client -connect "$FRONTEND_HOST:$FRONTEND_PORT" -showcerts </dev/null 2>/dev/null | awk '/BEGIN CERT/{n++} n==2' | sed -n '/BEGIN CERT/,/END CERT/p' > "$HOME/browser_bench/janus-intermediate.pem"
CERTS="\"$HOME/browser_bench/janus-root.pem\", \"$HOME/browser_bench/janus-intermediate.pem\""
[ -n "${VANILLA_CA_PEM:-}" ] && { cp -f "$VANILLA_CA_PEM" "$HOME/browser_bench/vanilla-ca.pem"; CERTS="$CERTS, \"$HOME/browser_bench/vanilla-ca.pem\""; certutil -L -d "sql:$HOME/nss_client/nssdb" | grep -q vanilla-ca || certutil -A -d "sql:$HOME/nss_client/nssdb" -n vanilla-ca -t "CT,C,C" -i "$VANILLA_CA_PEM"; }
mkdir -p "$HOME/firefox/distribution"
printf '{ "policies": { "Certificates": { "Install": [ %s ] }, "DisableAppUpdate": true, "DisableTelemetry": true } }\n' "$CERTS" > "$HOME/firefox/distribution/policies.json"
(cd janus/client/browser_extension && npm install --silent >/dev/null 2>&1 && npm run package >/dev/null 2>&1 && cp -f dist/*.zip "$HOME/browser_bench/ctls-ext.xpi")
# 4. the endpoint file the wrappers read (eval/configs/env.yaml is rendered from it)
sed -e "s|^FRONTEND_HOST=.*|FRONTEND_HOST=$FRONTEND_HOST|" -e "s|^FRONTEND_PORT=.*|FRONTEND_PORT=$FRONTEND_PORT|" \
    -e "s|^BACKEND_HOST=.*|BACKEND_HOST=$BACKEND_HOST|" -e "s|^RATLS_HOST=.*|RATLS_HOST=${RATLS_HOST:-$BACKEND_HOST}|" -e "s|^HTTPA_HOST=.*|HTTPA_HOST=${HTTPA_HOST:-$BACKEND_HOST}|" \
    -e "s|^BROWSER_FRONTEND=.*|BROWSER_FRONTEND=${BROWSER_FRONTEND:-$FRONTEND_HOST}|" -e "s|^BROWSER_BACKEND=.*|BROWSER_BACKEND=${BROWSER_BACKEND:-$BACKEND_HOST}|" \
    -e "s|^IFACE=.*|IFACE=${IFACE:-eth0}|" -e "s|^RATLS_PYTHON=.*|RATLS_PYTHON=\"$ROOT/baselines/python-ratls/bin/python3\"|" eval/ae/testbed.env.example > eval/ae/testbed.env
python3 eval/ae/render_env.py
echo "client ready — run eval/ae/check_testbed.sh"
