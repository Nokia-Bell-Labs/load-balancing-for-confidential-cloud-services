#!/bin/bash
# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear
# Runs ON the relay VM, for the edge placement: the relay sits next to the client, so the long path is
# relay -> service. The delay applies only to traffic toward the service. Traffic back to the client
# is not delayed.
#   netem_relay.sh set <ms> <service_ip> | clear
case "$1" in
  set)   sudo tc qdisc del dev eth0 root 2>/dev/null
         if [ "$2" -gt 0 ]; then
           sudo tc qdisc add dev eth0 root handle 1: prio
           sudo tc qdisc add dev eth0 parent 1:3 handle 30: netem delay "$2ms"
           sudo tc filter add dev eth0 protocol ip parent 1:0 prio 1 u32 match ip dst "${3:?service IP}/32" flowid 1:3
         fi; tc qdisc show dev eth0 | head -2 ;;
  clear) sudo tc qdisc del dev eth0 root 2>/dev/null; echo cleared ;;
  *) echo "usage: $0 set <ms> <service_ip> | clear"; exit 1 ;;
esac
