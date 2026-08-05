#!/bin/bash
INSTALL_DIR=$(cd "$(dirname "$0")" && pwd)
HOME_DIR=$HOME
RUNTIME_DIR="$INSTALL_DIR/.runtime"
IFACE_FILE="$RUNTIME_DIR/ndr_interface"

log()  { echo -e "\033[0;32m[NDR]\033[0m $1"; }
warn() { echo -e "\033[1;33m[WARN]\033[0m $1"; }

echo "🚀 Starting NDR Stack..."

# ── Load kernel modules ───────────────────────
echo "  → Loading kernel modules..."
sudo modprobe overlay 2>/dev/null || true
sudo modprobe br_netfilter 2>/dev/null || true

# ── Set interface ─────────────────────────────
if [ -f "$INSTALL_DIR/.env" ]; then
    source "$INSTALL_DIR/.env"
fi


IFACE=${IFACE:-$(ip -o -4 addr show 2>/dev/null | \
    grep -v "127.0.0.1\|docker\|br-\|veth" | \
    awk '{print $2}' | head -1)}
mkdir -p "$RUNTIME_DIR"
echo "$IFACE" > "$IFACE_FILE"
echo "  → Interface: $IFACE"

# ClickHouse is now containerized — started via docker compose up below

# Start NDR Agent
echo "  → Starting NDR Agent..."
sudo systemctl start ndr-agent 2>/dev/null || \
    nohup python3 $INSTALL_DIR/scripts/ndr-agent.py > /tmp/ndr-agent.log 2>&1 &
sleep 2

# Engine containers run as root and access docker socket via group ownership (660)

# ── Clear Vector checkpoints BEFORE starting Docker ──────────────
# Must happen before docker compose up so Vector starts with no memory
# of old log positions — otherwise it skips data it thinks it already read
log "Resetting Vector checkpoints..."
sudo rm -rf $HOME_DIR/.vector/data/suricata \
    $HOME_DIR/.vector/data/zeek 2>/dev/null || true
mkdir -p $HOME_DIR/.vector/data/suricata \
         $HOME_DIR/.vector/data/zeek
log "✅ Vector checkpoints cleared"

# Start Docker stack (--profile onpremise includes OpenSearch)
echo "  → Starting Docker stack..."
cd $INSTALL_DIR
sudo docker rm -f vector 2>/dev/null || true
sudo docker compose --profile onpremise up -d

# Start Arkime viewer only after OpenSearch is confirmed ready
echo "  → Waiting for OpenSearch..."
OS_READY=false
for i in {1..40}; do
    if curl -sf http://localhost:9200/_cluster/health > /dev/null 2>&1; then
        OS_READY=true
        log "✅ OpenSearch ready"
        break
    fi
    echo -n "."
    sleep 3
done
echo ""

if [ "$OS_READY" = true ]; then
    echo "  → Starting Arkime viewer..."
    sudo systemctl restart arkimeviewer 2>/dev/null || true
    sleep 2
    if systemctl is-active --quiet arkimeviewer 2>/dev/null; then
        log "✅ Arkime viewer running"
    else
        warn "Arkime viewer failed — check: journalctl -u arkimeviewer -n 20"
    fi
else
    warn "OpenSearch not ready — skipping Arkime viewer start"
fi
# Arkime capture starts/stops via NDR UI Agent button

# ── Set Kafka retention and ensure 3-partition topic ─────────────
# Wait for Kafka to be healthy before touching topics
echo "  → Waiting for Kafka to be ready..."
for i in {1..30}; do
    if sudo docker exec kafka1 /opt/kafka/bin/kafka-broker-api-versions.sh \
        --bootstrap-server localhost:9092 > /dev/null 2>&1; then
        log "✅ Kafka ready"
        break
    fi
    sleep 3
done

# Set retention
sudo docker exec kafka1 \
    /opt/kafka/bin/kafka-configs.sh \
    --bootstrap-server localhost:9092 \
    --alter --entity-type topics \
    --entity-name ndr-events \
    --add-config retention.ms=3600000 \
    2>/dev/null || true

# Create topic with 3 partitions only if it doesn't exist yet
# Never delete an existing topic — that breaks live consumer connections
sudo docker exec kafka1 \
    /opt/kafka/bin/kafka-topics.sh \
    --bootstrap-server localhost:9092 \
    --create --if-not-exists \
    --topic ndr-events \
    --partitions 3 \
    --replication-factor 3 \
    2>/dev/null || true

ACTUAL_PARTS=$(sudo docker exec kafka1 /opt/kafka/bin/kafka-topics.sh --bootstrap-server localhost:9092 --describe --topic ndr-events 2>/dev/null | grep PartitionCount | grep -oP 'PartitionCount:\s*\K\d+' || echo "?")
log "✅ Kafka ${ACTUAL_PARTS} partitions ready for scaling"

# Verify
sudo docker exec kafka1 \
    /opt/kafka/bin/kafka-topics.sh \
    --bootstrap-server localhost:9092 \
    --describe --topic ndr-events

# Check consumer group
sleep 5
sudo docker exec kafka1 \
    /opt/kafka/bin/kafka-consumer-groups.sh \
    --bootstrap-server localhost:9092 \
    --group ndr-engine-group \
    --describe

# ── Native SOAR ───────────────────────────────
echo "  ✅ Native SOAR is built into the NDR engine (no external services needed)"

# UI is served by the ndr-ui Docker container (nginx on port 80, proxied by ndr-nginx on 443/3000)
# No local npm start needed — wait for the container to be ready
log "Waiting for ndr-ui container to be ready..."
for i in {1..30}; do
    if sudo docker exec ndr-ui curl -s http://localhost:80 > /dev/null 2>&1; then
        log "✅ ndr-ui container ready"
        break
    fi
    echo -n "."
    sleep 3
done
echo ""

echo ""
echo "📊 Status:"
echo "  ClickHouse:  $(curl -s http://localhost:8123/ping 2>/dev/null || echo 'starting...')"
echo "  OpenSearch:  $(curl -s http://localhost:9200 2>/dev/null | grep -o '"tagline":".*"' || echo 'starting...')"
echo "  Docker:      $(sudo docker ps --format '{{.Names}}' | tr '\n' ' ')"
echo "  Agent:       $(curl -s http://localhost:3001/agent/status 2>/dev/null || echo 'not running')"
echo "  Arkime viewer:  $(systemctl is-active arkimeviewer 2>/dev/null || echo 'stopped (starts only when OpenSearch is ready)')"
echo "  Arkime capture: start via NDR UI → Agent → Start"

echo ""
echo "✅ NDR Stack started"
echo "   UI:     https://localhost:3000  (or https://<HOST_IP>:3000)"
echo "   API:    https://localhost:3000/api"
echo "   Agent:  http://localhost:3001"
