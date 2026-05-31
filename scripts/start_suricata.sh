#!/bin/bash
# start_suricata.sh — Starts Suricata on the selected interface
# Reads selection from the installer runtime file

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
INSTALL_DIR=$(cd "$SCRIPT_DIR/.." && pwd)
IFACE_FILE="$INSTALL_DIR/.runtime/ndr_interface"
IFACE=$(cat "$IFACE_FILE" 2>/dev/null || echo "eth0")

echo "Starting Suricata on interface: $IFACE"
# Note: Ensure suricata is in your PATH or update the command
suricata -c /etc/suricata/suricata.yaml -i $IFACE -l /home/jithin/logs/suricata
