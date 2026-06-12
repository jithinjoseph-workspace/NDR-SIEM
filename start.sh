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

WEBHOOK=$(clickhouse-client --user=ndr \
    --password=ndr123 \
    --query "SELECT value FROM ndr.soar_config \
    FINAL WHERE key='webhook_url'" 2>/dev/null)
if [ -n "$WEBHOOK" ]; then
    sed -i \
        "s|SHUFFLE_WEBHOOK_URL=.*|SHUFFLE_WEBHOOK_URL=$WEBHOOK|" \
        $INSTALL_DIR/.env
    log "✅ SOAR webhook restored"
fi


IFACE=${IFACE:-$(ip -o -4 addr show 2>/dev/null | \
    grep -v "127.0.0.1\|docker\|br-\|veth" | \
    awk '{print $2}' | head -1)}
mkdir -p "$RUNTIME_DIR"
echo "$IFACE" > "$IFACE_FILE"
echo "  → Interface: $IFACE"

# Start ClickHouse
echo "  → Starting ClickHouse..."
sudo service clickhouse-server start 2>/dev/null || true
sleep 3

# Start NDR Agent
echo "  → Starting NDR Agent..."
sudo systemctl start ndr-agent 2>/dev/null || \
    nohup python3 $INSTALL_DIR/scripts/ndr-agent.py > /tmp/ndr-agent.log 2>&1 &
sleep 2
# Fix Docker socket permissions
sudo chmod 666 /var/run/docker.sock 2>/dev/null || true

# ── Clear Vector checkpoints BEFORE starting Docker ──────────────
# Must happen before `docker compose up` so Vector starts fresh,
# not skipping log data it thinks it already read
log "Resetting Vector checkpoints..."
sudo rm -rf $HOME_DIR/.vector/data/suricata \
    $HOME_DIR/.vector/data/zeek 2>/dev/null || true
mkdir -p $HOME_DIR/.vector/data
log "✅ Vector checkpoints cleared"

# Start Docker stack
echo "  → Starting Docker stack..."
cd $INSTALL_DIR
sudo docker rm -f vector 2>/dev/null || true
sudo docker compose up -d

# Arkime capture is started only via the NDR UI (Start Agent button)

# ── Set Kafka retention ───────────────────────
sleep 15
sudo docker exec kafka \
    /opt/kafka/bin/kafka-configs.sh \
    --bootstrap-server localhost:9092 \
    --alter --entity-type topics \
    --entity-name ndr-events \
    --add-config retention.ms=3600000 \
    2>/dev/null || true


# Create topic with 3 partitions (or reset to 3 if exists with more)
sudo docker exec kafka \
    /opt/kafka/bin/kafka-topics.sh \
    --bootstrap-server localhost:9092 \
    --create --if-not-exists \
    --topic ndr-events \
    --partitions 3 \
    --replication-factor 1 \
    2>/dev/null || true

# Delete and recreate if partition count is wrong
PARTITION_COUNT=$(sudo docker exec kafka \
    /opt/kafka/bin/kafka-topics.sh \
    --bootstrap-server localhost:9092 \
    --describe --topic ndr-events 2>/dev/null | \
    grep PartitionCount | awk -F: '{print $2}' | tr -d ' ')

if [ "$PARTITION_COUNT" != "3" ]; then
    log "Resetting Kafka topic to 3 partitions..."
    sudo docker exec kafka \
        /opt/kafka/bin/kafka-topics.sh \
        --bootstrap-server localhost:9092 \
        --delete --topic ndr-events \
        2>/dev/null || true
    sleep 3
    sudo docker exec kafka \
        /opt/kafka/bin/kafka-topics.sh \
        --bootstrap-server localhost:9092 \
        --create --topic ndr-events \
        --partitions 3 \
        --replication-factor 1 \
        2>/dev/null || true
fi
log "✅ Kafka 3 partitions ready for scaling"

# Verify
sudo docker exec kafka \
    /opt/kafka/bin/kafka-topics.sh \
    --bootstrap-server localhost:9092 \
    --describe --topic ndr-events

# Check consumer group now
sleep 5
sudo docker exec kafka \
    /opt/kafka/bin/kafka-consumer-groups.sh \
    --bootstrap-server localhost:9092 \
    --group ndr-engine-group \
    --describe

    
# ── Check Shuffle SOAR ────────────────────────
echo "  → Checking Shuffle SOAR..."
sleep 5
if curl -s http://localhost:5001/api/v1/health \
    > /dev/null 2>&1; then
    echo "  ✅ Shuffle SOAR running"

    # Check webhook configured
    source $INSTALL_DIR/.env 2>/dev/null || true
    if [ -z "$SHUFFLE_WEBHOOK_URL" ]; then
        echo "  ⚠️  Shuffle webhook not configured"
        echo "      Open UI → SOAR page to configure"
    else
        echo "  ✅ Shuffle webhook configured"
    fi
else
    echo "  ⚠️  Shuffle not running"
fi

# ── Refresh Shuffle API key ───────────────────
log "Refreshing Shuffle API key..."
SESSION=$(curl -s \
    -X POST "http://localhost:5001/api/v1/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"admin","password":"shufflepassword"}' \
    2>/dev/null | python3 -c "
import sys,json
d=json.load(sys.stdin)
for c in d.get('cookies',[]):
    if c['key']=='session_token':
        print(c['value'])
" 2>/dev/null)

if [ -n "$SESSION" ]; then
    NEW_KEY=$(curl -s \
        -b "session_token=$SESSION" \
        "http://localhost:5001/api/v1/users/generateapikey" \
        2>/dev/null | python3 -c "
import sys,json
d=json.load(sys.stdin)
print(d.get('apikey',''))
" 2>/dev/null)

    if [ -n "$NEW_KEY" ]; then
        sed -i \
            "s|SHUFFLE_API_KEY=.*|SHUFFLE_API_KEY=$NEW_KEY|" \
            $INSTALL_DIR/.env
        log "✅ Shuffle API key refreshed"
        # Restart engine with new key
        sudo docker compose up -d ndr-engine-1
    fi
fi

# Wait for Kafka to be healthy
echo "  → Waiting for Kafka..."
sleep 10



# Start Angular UI
echo "  → Starting Angular UI..."
cd $INSTALL_DIR/ndr-ui
if curl -s http://localhost:4200 > /dev/null 2>&1; then
    log "Angular UI already running at http://localhost:4200"
else
    if [ -f /tmp/ndr-ui.pid ]; then
        OLD_UI_PID=$(cat /tmp/ndr-ui.pid 2>/dev/null || true)
        if [ -n "$OLD_UI_PID" ] && kill -0 "$OLD_UI_PID" 2>/dev/null; then
            warn "Existing Angular UI process found - restarting it"
            kill "$OLD_UI_PID" 2>/dev/null || true
            sleep 2
        fi
        rm -f /tmp/ndr-ui.pid
    fi

    nohup npm start > /tmp/ndr-ui.log 2>&1 &
    echo $! > /tmp/ndr-ui.pid
fi

# Verify UI started
log "Waiting for Angular UI to be ready..."
for i in {1..60}; do
    if curl -s http://localhost:4200 > /dev/null 2>&1; then
        log "✅ Angular UI ready at http://localhost:4200"
        break
    fi
    echo -n "."
    sleep 3
done
echo ""

echo ""
echo "📊 Status:"
echo "  ClickHouse: $(curl -s http://localhost:8123/ping 2>/dev/null || echo 'starting...')"
echo "  Docker: $(sudo docker ps --format '{{.Names}}' | tr '\n' ' ')"
echo "  Agent:  $(curl -s http://localhost:3001/agent/status 2>/dev/null)"


echo ""
echo "✅ NDR Stack started"
echo "   UI:     http://localhost:4200"
echo "   API:    http://localhost:3000"
echo "   Agent:  http://localhost:3001"
echo "   SOAR:   http://localhost:3002"
