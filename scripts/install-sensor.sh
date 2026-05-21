#!/bin/bash
# NDR Sensor Installation Script
# Usage: ./install-sensor.sh --cloud-url https://ndr.yourcompany.com --tenant-id company-a --api-key YOUR_KEY

set -e

# ── Colors ────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log()  { echo -e "${GREEN}[NDR]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error(){ echo -e "${RED}[ERROR]${NC} $1"; exit 1; }
info() { echo -e "${BLUE}[INFO]${NC} $1"; }

# ── Banner ────────────────────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════╗"
echo "║     NDR Stack — Sensor Installation      ║"
echo "║     Network Detection & Response         ║"
echo "╚══════════════════════════════════════════╝"
echo ""

# ── Parse arguments ───────────────────────────────────────────────────────
CLOUD_URL=""
TENANT_ID=""
API_KEY=""
IFACE=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --cloud-url)   CLOUD_URL="$2";  shift 2 ;;
        --tenant-id)   TENANT_ID="$2";  shift 2 ;;
        --api-key)     API_KEY="$2";    shift 2 ;;
        --interface)   IFACE="$2";      shift 2 ;;
        *) warn "Unknown option: $1"; shift ;;
    esac
done

# ── Validate arguments ────────────────────────────────────────────────────
if [ -z "$CLOUD_URL" ] || [ -z "$TENANT_ID" ] || [ -z "$API_KEY" ]; then
    echo "Usage: $0 --cloud-url URL --tenant-id ID --api-key KEY [--interface eth0]"
    echo ""
    echo "Example:"
    echo "  $0 --cloud-url https://ndr.yourcompany.com \\"
    echo "     --tenant-id acme-corp \\"
    echo "     --api-key your-api-key-here"
    exit 1
fi

# ── Detect interface ──────────────────────────────────────────────────────
if [ -z "$IFACE" ]; then
    IFACE=$(ip -o -4 addr show 2>/dev/null | \
        grep -v "127.0.0.1\|docker\|br-\|veth" | \
        awk '{print $2}' | head -1)
    log "Auto-detected interface: $IFACE"
fi

# ── Check OS ──────────────────────────────────────────────────────────────
if [ ! -f /etc/os-release ]; then
    error "Unsupported OS"
fi
source /etc/os-release
log "OS: $PRETTY_NAME"

# ── Check root ────────────────────────────────────────────────────────────
if [ "$EUID" -ne 0 ]; then
    error "Please run as root: sudo $0"
fi

# ── Install dependencies ──────────────────────────────────────────────────
log "Installing dependencies..."
apt-get update -qq
apt-get install -y -qq \
    curl wget git python3 python3-pip \
    apt-transport-https gnupg2 \
    software-properties-common > /dev/null

# ── Install Zeek ──────────────────────────────────────────────────────────
log "Installing Zeek..."
if ! command -v zeek &>/dev/null && ! command -v /opt/zeek/bin/zeek &>/dev/null; then
    # Auto-detect Ubuntu version
    UBUNTU_VER=$(lsb_release -rs 2>/dev/null || echo "22.04")
    UBUNTU_MAJOR=$(echo $UBUNTU_VER | cut -d. -f1)
    log "Detected Ubuntu $UBUNTU_VER"

    # Install Zeek based on Ubuntu version
    if [ "$UBUNTU_MAJOR" = "20" ]; then
        # Ubuntu 20.04 - use PPA
        log "Using Zeek PPA for Ubuntu 20.04..."
        apt-get install -y -qq software-properties-common > /dev/null
        add-apt-repository -y ppa:zeek/zeek > /dev/null 2>&1
        apt-get update -qq
        apt-get install -y -qq zeek > /dev/null 2>&1 || \
        apt-get install -y -qq zeek-lts > /dev/null 2>&1 || true
    elif [ "$UBUNTU_MAJOR" = "22" ]; then
        # Ubuntu 22.04
        echo "deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/ /" \
            > /etc/apt/sources.list.d/security:zeek.list
        curl -fsSL "https://download.opensuse.org/repositories/security:zeek/xUbuntu_22.04/Release.key" \
            | gpg --dearmor \
            > /etc/apt/trusted.gpg.d/security_zeek.gpg 2>/dev/null
        apt-get update -qq
        apt-get install -y -qq zeek > /dev/null
    elif [ "$UBUNTU_MAJOR" = "24" ]; then
        # Ubuntu 24.04
        echo "deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_24.04/ /" \
            > /etc/apt/sources.list.d/security:zeek.list
        curl -fsSL "https://download.opensuse.org/repositories/security:zeek/xUbuntu_24.04/Release.key" \
            | gpg --dearmor \
            > /etc/apt/trusted.gpg.d/security_zeek.gpg 2>/dev/null
        apt-get update -qq
        apt-get install -y -qq zeek > /dev/null
    else
        warn "Unsupported Ubuntu version $UBUNTU_VER for Zeek auto-install"
        warn "Install manually: https://zeek.org/get-zeek/"
    fi
    echo 'export PATH=$PATH:/opt/zeek/bin' >> /etc/profile
    export PATH=$PATH:/opt/zeek/bin
    log "✅ Zeek installed"
else
    log "✅ Zeek already installed"
fi

# ── Install Suricata ──────────────────────────────────────────────────────
log "Installing Suricata..."
if ! command -v suricata &>/dev/null; then
    add-apt-repository -y ppa:oisf/suricata-stable > /dev/null 2>&1
    apt-get update -qq
    apt-get install -y -qq suricata > /dev/null
    # Download rules
    suricata-update > /dev/null 2>&1 || true
    log "✅ Suricata installed"
else
    log "✅ Suricata already installed"
fi

# ── Install Vector ────────────────────────────────────────────────────────
log "Installing Vector..."
if ! command -v vector &>/dev/null; then
    # Try official Vector install script
    log "Downloading Vector..."
    curl -fsSL https://sh.vector.dev | bash -s -- --yes > /dev/null 2>&1 || {
        # Fallback: download binary directly
        warn "Vector script failed, trying direct download..."
        VECTOR_VERSION="0.32.1"
        ARCH=$(dpkg --print-architecture)
        if [ "$ARCH" = "amd64" ]; then
            VECTOR_URL="https://github.com/vectordotdev/vector/releases/download/v${VECTOR_VERSION}/vector_${VECTOR_VERSION}-1_amd64.deb"
        else
            VECTOR_URL="https://github.com/vectordotdev/vector/releases/download/v${VECTOR_VERSION}/vector_${VECTOR_VERSION}-1_arm64.deb"
        fi
        wget -q "$VECTOR_URL" -O /tmp/vector.deb && \
        dpkg -i /tmp/vector.deb > /dev/null 2>&1 && \
        rm /tmp/vector.deb || \
        warn "Vector install failed — install manually from https://vector.dev"
    }
    log "✅ Vector installed"
else
    log "✅ Vector already installed"
fi

# ── Create directories ────────────────────────────────────────────────────
log "Creating directories..."
mkdir -p /opt/ndr-sensor
mkdir -p /var/log/ndr/zeek
mkdir -p /var/log/ndr/suricata
mkdir -p /etc/ndr

# ── Save config ───────────────────────────────────────────────────────────
log "Saving sensor config..."
cat > /etc/ndr/sensor.conf << EOF
CLOUD_URL=$CLOUD_URL
TENANT_ID=$TENANT_ID
API_KEY=$API_KEY
IFACE=$IFACE
INSTALL_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ)
EOF

# ── Extract Kafka host from cloud URL ─────────────────────────────────────
CLOUD_HOST=$(echo $CLOUD_URL | sed 's|https\?://||' | cut -d/ -f1)
KAFKA_URL="${CLOUD_HOST}:9092"

# ── Configure Vector ──────────────────────────────────────────────────────
log "Configuring Vector → $KAFKA_URL..."
cat > /etc/ndr/vector.toml << EOF
[sources.zeek_logs]
type = "file"
include = ["/var/log/ndr/zeek/conn.log",
           "/var/log/ndr/zeek/dns.log",
           "/var/log/ndr/zeek/http.log",
           "/var/log/ndr/zeek/ssl.log"]
read_from = "end"

[sources.suricata_logs]
type = "file"
include = ["/var/log/ndr/suricata/eve.json"]
read_from = "end"

[transforms.add_tenant]
type = "remap"
inputs = ["zeek_logs", "suricata_logs"]
source = '''
.tenant_id = "${TENANT_ID}"
.sensor_host = "$(hostname)"
'''

[sinks.kafka_out]
type = "kafka"
inputs = ["add_tenant"]
bootstrap_servers = "${KAFKA_URL}"
topic = "ndr-events-${TENANT_ID}"
encoding.codec = "json"
EOF

# ── Configure Zeek ────────────────────────────────────────────────────────
log "Configuring Zeek..."
ZEEK_BIN=$(which zeek 2>/dev/null || echo "/opt/zeek/bin/zeek")
ZEEKCTL=$(which zeekctl 2>/dev/null || echo "/opt/zeek/bin/zeekctl")

if [ -f /opt/zeek/etc/node.cfg ]; then
    cat > /opt/zeek/etc/node.cfg << EOF
[zeek]
type=standalone
host=localhost
interface=$IFACE
EOF

    cat > /opt/zeek/etc/zeekctl.cfg << EOF
LogRotationInterval = 3600
LogExpireInterval = 0
StatsLogEnable = 0
LogDir = /var/log/ndr/zeek
EOF
fi

# ── Configure Suricata ────────────────────────────────────────────────────
log "Configuring Suricata..."
if [ -f /etc/suricata/suricata.yaml ]; then
    sed -i "s/interface: eth0/interface: $IFACE/" \
        /etc/suricata/suricata.yaml 2>/dev/null || true
    sed -i "s|/var/log/suricata|/var/log/ndr/suricata|g" \
        /etc/suricata/suricata.yaml 2>/dev/null || true
fi

# ── Create sensor agent ───────────────────────────────────────────────────
log "Creating sensor agent..."
cat > /opt/ndr-sensor/agent.py << 'AGENT'
#!/usr/bin/env python3
"""NDR Sensor Agent - reports status to cloud"""
import os, json, time, subprocess, requests
from datetime import datetime

config = {}
with open('/etc/ndr/sensor.conf') as f:
    for line in f:
        if '=' in line:
            k,v = line.strip().split('=',1)
            config[k] = v

CLOUD_URL = config.get('CLOUD_URL','')
TENANT_ID = config.get('TENANT_ID','')
API_KEY   = config.get('API_KEY','')

def get_status():
    def is_running(name):
        try:
            out = subprocess.run(['pgrep','-x',name],
                capture_output=True).returncode
            return out == 0
        except: return False
    return {
        'tenant_id': TENANT_ID,
        'zeek':      'running' if is_running('zeek') else 'stopped',
        'suricata':  'running' if is_running('Suricata') else 'stopped',
        'vector':    'running' if is_running('vector') else 'stopped',
        'timestamp': datetime.utcnow().isoformat()
    }

def report_status():
    status = get_status()
    try:
        requests.post(
            f'{CLOUD_URL}/api/sensor/heartbeat',
            json=status,
            headers={'Authorization': f'Bearer {API_KEY}'},
            timeout=5
        )
        print(f"[NDR] Status reported: {status}")
    except Exception as e:
        print(f"[NDR] Failed to report: {e}")

if __name__ == '__main__':
    print(f"[NDR] Sensor agent starting for tenant: {TENANT_ID}")
    while True:
        report_status()
        time.sleep(30)
AGENT

chmod +x /opt/ndr-sensor/agent.py

# ── Create systemd services ───────────────────────────────────────────────
log "Creating systemd services..."

# Vector service
cat > /etc/systemd/system/ndr-vector.service << EOF
[Unit]
Description=NDR Vector Log Forwarder
After=network.target

[Service]
ExecStart=/usr/bin/vector --config /etc/ndr/vector.toml
Restart=always
RestartSec=5
Environment=TENANT_ID=$TENANT_ID

[Install]
WantedBy=multi-user.target
EOF

# Sensor agent service
cat > /etc/systemd/system/ndr-agent.service << EOF
[Unit]
Description=NDR Sensor Agent
After=network.target

[Service]
ExecStart=/usr/bin/python3 /opt/ndr-sensor/agent.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# ── Enable and start services ─────────────────────────────────────────────
log "Starting services..."
systemctl daemon-reload
systemctl enable ndr-vector ndr-agent 2>/dev/null || true

# ── Register sensor with cloud ────────────────────────────────────────────
log "Registering sensor with cloud..."
REG_RESULT=$(curl -s -X POST \
    "$CLOUD_URL/api/sensor/register" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $API_KEY" \
    -d "{
        \"tenant_id\": \"$TENANT_ID\",
        \"hostname\": \"$(hostname)\",
        \"interface\": \"$IFACE\",
        \"os\": \"$PRETTY_NAME\"
    }" 2>/dev/null)

if echo "$REG_RESULT" | grep -q '"status":"ok"'; then
    log "✅ Sensor registered with cloud!"
else
    warn "Cloud registration failed — check URL and API key"
    warn "Response: $REG_RESULT"
fi

# ── Print summary ─────────────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════╗"
echo "║     ✅ NDR Sensor Installation Done!     ║"
echo "╠══════════════════════════════════════════╣"
printf "║  Tenant:    %-28s ║\n" "$TENANT_ID"
printf "║  Interface: %-28s ║\n" "$IFACE"
printf "║  Cloud:     %-28s ║\n" "${CLOUD_HOST:0:28}"
echo "╠══════════════════════════════════════════╣"
echo "║  Start sensor:                           ║"
echo "║  sudo systemctl start ndr-vector         ║"
echo "║  sudo zeekctl deploy                     ║"
echo "║  sudo systemctl start suricata           ║"
echo "╚══════════════════════════════════════════╝"
echo ""
log "Config saved to: /etc/ndr/sensor.conf"
log "Logs: /var/log/ndr/"
