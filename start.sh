#!/bin/bash
INSTALL_DIR=$(cd "$(dirname "$0")" && pwd)

echo "🚀 Starting NDR Stack..."

# Start ClickHouse
echo "  → Starting ClickHouse..."
sudo service clickhouse-server start 2>/dev/null || true
sleep 3

# Start NDR Agent
echo "  → Starting NDR Agent..."
sudo systemctl start ndr-agent 2>/dev/null || \
    nohup python3 $INSTALL_DIR/scripts/ndr-agent.py > /tmp/ndr-agent.log 2>&1 &
sleep 2

# Start Docker stack
echo "  → Starting Docker stack..."
cd $INSTALL_DIR
docker compose up -d

# Wait for Kafka to be healthy
echo "  → Waiting for Kafka..."
sleep 10

# Start Angular UI
echo "  → Starting Angular UI..."
cd $INSTALL_DIR/ndr-ui
nohup npm start > /tmp/ndr-ui.log 2>&1 &
echo $! > /tmp/ndr-ui.pid

echo ""
echo "📊 Status:"
echo "  ClickHouse: $(curl -s http://localhost:8123/ping 2>/dev/null || echo 'starting...')"
echo "  Docker: $(docker ps --format '{{.Names}}' | tr '\n' ' ')"
echo "  Agent:  $(curl -s http://localhost:3001/agent/status 2>/dev/null)"
echo ""
echo "✅ NDR Stack started"
echo "   UI:    http://localhost:4200"
echo "   API:   http://localhost:3000"
echo "   Agent: http://localhost:3001"
