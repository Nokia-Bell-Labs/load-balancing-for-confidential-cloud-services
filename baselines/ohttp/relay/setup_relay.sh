#!/bin/bash
# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear
# Runs ON the relay VM: install nginx if needed, make a self-signed TLS key (clients do not need to trust
# the relay: OHTTP protects the content end to end), render nginx-relay.conf.template and (re)start it.
#   setup_relay.sh <service_host> [lb_port 6039] [kms_port 6038] [relay_port 7039] [forward_path /forward/ohttp]
set -e
SVC=${1:?service host (load balancer and KMS)}; LB_PORT=${2:-6039}; KMS_PORT=${3:-6038}; RELAY_PORT=${4:-7039}; FWD=${5:-/forward/ohttp}
HERE=$(cd "$(dirname "$0")" && pwd); D=$HOME/ohttp-relay; mkdir -p $D/tmp
command -v nginx >/dev/null || { sudo apt-get update -qq >/dev/null; sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq nginx >/dev/null; }
sudo systemctl disable --now nginx >/dev/null 2>&1 || true          # only our own instance runs
[ -f $D/relay.key ] || openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -keyout $D/relay.key \
     -out $D/relay.crt -days 365 -nodes -subj "/CN=ohttp-relay" 2>/dev/null
sed -e "s|@DIR@|$D|g" -e "s|@LB_HOST@|$SVC|" -e "s|@KMS_HOST@|$SVC|" -e "s|@LB_PORT@|$LB_PORT|" \
    -e "s|@KMS_PORT@|$KMS_PORT|" -e "s|@RELAY_PORT@|$RELAY_PORT|" -e "s|@FORWARD_PATH@|$FWD|" \
    "$HERE/nginx-relay.conf.template" > $D/nginx.conf
sudo nginx -t -c $D/nginx.conf
[ -f $D/nginx.pid ] && sudo nginx -s quit -c $D/nginx.conf 2>/dev/null && sleep 1 || true
sudo nginx -c $D/nginx.conf && sleep 1 && echo "relay up on :$RELAY_PORT -> $SVC:$LB_PORT (requests), $SVC:$KMS_PORT (key configuration)"
