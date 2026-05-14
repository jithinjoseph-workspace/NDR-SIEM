#!/bin/bash
# start_suricata.sh — Starts Suricata on the selected interface
# Reads selection from /tmp/ndr_interface

IFACE=$(cat /tmp/ndr_interface 2>/dev/null || echo "eth0")

echo "Starting Suricata on interface: $IFACE"
# Note: Ensure suricata is in your PATH or update the command
suricata -c /etc/suricata/suricata.yaml -i $IFACE -l /home/jithin/logs/suricata
