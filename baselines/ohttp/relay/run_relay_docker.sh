#!/bin/bash
# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear
# Same relay as setup_relay.sh, but in an nginx container on a host without nginx (host network).
#   run_relay_docker.sh <service_host> [lb_port 6039] [kms_port 6038] [relay_port 7039] [forward_path /forward/ohttp]
set -e
SVC=${1:?service host}; LB_PORT=${2:-6039}; KMS_PORT=${3:-6038}; RELAY_PORT=${4:-7039}; FWD=${5:-/forward/ohttp}
HERE=$(cd "$(dirname "$0")" && pwd); D=$HOME/ohttp-relay; mkdir -p $D/tmp
[ -f $D/relay.key ] || openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -keyout $D/relay.key \
     -out $D/relay.crt -days 365 -nodes -subj "/CN=ohttp-relay" 2>/dev/null
sed -e "s|@DIR@|/relay|g" -e "s|@LB_HOST@|$SVC|" -e "s|@KMS_HOST@|$SVC|" -e "s|@LB_PORT@|$LB_PORT|" \
    -e "s|@KMS_PORT@|$KMS_PORT|" -e "s|@RELAY_PORT@|$RELAY_PORT|" -e "s|@FORWARD_PATH@|$FWD|" \
    "$HERE/nginx-relay.conf.template" > $D/nginx.conf
DK="bash -c"; docker ps >/dev/null 2>&1 || DK="sg docker -c"
$DK "docker rm -f ohttp-relay >/dev/null 2>&1; docker run -d --name ohttp-relay --network host -v $D:/relay nginx:stable nginx -c /relay/nginx.conf -g 'daemon off;'" >/dev/null
sleep 1; $DK "docker ps --filter name=ohttp-relay --format '{{.Status}}'" | grep -q Up && echo "relay container up on :$RELAY_PORT -> $SVC" || $DK "docker logs ohttp-relay 2>&1 | tail -5"
