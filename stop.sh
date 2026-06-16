#!/bin/bash
INSTALL_DIR=$(cd "$(dirname "$0")" && pwd)

echo "🛑 Stopping NDR Stack..."

# Stop Zeek and Suricata via agent
echo "  → Stopping Zeek and Suricata..."
curl -s -X POST http://localhost:3001/agent/stop > /dev/null 2>&1 || true
sleep 2

# Stop NDR Agent service
echo "  → Stopping NDR Agent..."
sudo systemctl stop ndr-agent 2>/dev/null || true
pkill -f ndr-agent.py 2>/dev/null || true

# Stop Angular UI
echo "  → Stopping Angular UI..."
if [ -f /tmp/ndr-ui.pid ]; then
    kill $(cat /tmp/ndr-ui.pid) 2>/dev/null || true
    rm -f /tmp/ndr-ui.pid
fi
pkill -f "ng serve" 2>/dev/null || true
pkill -f "npm start" 2>/dev/null || true

# Stop Docker stack
echo "  → Stopping Docker stack..."
cd $INSTALL_DIR
# Stop dynamically created engines (engine-4, 5, etc.)
DYNAMIC_ENGINES=$(sudo docker ps -a     --filter "name=ndr-engine-"     --format "{{.Names}}" |     grep -v -E "ndr-engine-[123]$" || true)

if [ -n "$DYNAMIC_ENGINES" ]; then
    echo "Stopping dynamic engines: $DYNAMIC_ENGINES"
    echo "$DYNAMIC_ENGINES" | xargs sudo docker rm -f         2>/dev/null || true
fi

sudo docker compose --profile onpremise down

# Stop ClickHouse
echo "  → Stopping ClickHouse..."
sudo service clickhouse-server stop 2>/dev/null || true

# Kill any leftover processes
sudo pkill -f suricata 2>/dev/null || true
sudo pkill -f zeek 2>/dev/null || true

# Verify
echo ""
echo "📊 Verification:"
echo "  Docker:    $(sudo docker ps --format '{{.Names}}' | tr '\n' ' ' || echo 'none')"
echo "  Agent:     $(curl -s http://localhost:3001/agent/status 2>/dev/null || echo 'stopped')"
echo "  Zeek/Suri: $(ps aux | grep -E 'zeek|suricata' | grep -v grep | wc -l) processes"

echo ""
echo "✅ NDR Stack stopped"

