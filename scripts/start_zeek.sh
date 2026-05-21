#!/bin/bash
# start_zeek.sh — Starts Zeek on the selected interface
# Reads selection from /tmp/ndr_interface

IFACE=$(cat /tmp/ndr_interface 2>/dev/null || echo "eth0")

echo "Starting Zeek on interface: $IFACE"
# Note: Ensure /opt/zeek/bin/zeek exists or update the path
/opt/zeek/bin/zeek -i $IFACE local Log::default_logdir=/home/jithin/logs/zeek
