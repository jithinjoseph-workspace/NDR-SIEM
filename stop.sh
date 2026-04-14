#!/bin/bash
INSTALL_DIR=$(cd "$(dirname "$0")" && pwd)

echo "🛑 Stopping NDR Stack..."

# Stop Zeek and Suricata via agent
curl -s -X POST http://localhost:3001/agent/stop > /dev/null 2>&1 || true

# Stop Angular UI
if [ -f /tmp/ndr-ui.pid ]; then
    kill $(cat /tmp/ndr-ui.pid) 2>/dev/null || true
    rm /tmp/ndr-ui.pid
fi

# Stop Docker stack
cd $INSTALL_DIR
docker compose down

echo "✅ NDR Stack stopped"
