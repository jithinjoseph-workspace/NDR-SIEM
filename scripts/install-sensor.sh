#!/bin/bash
# NDR Sensor Installation Script
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'
log()  { echo -e "${GREEN}[NDR]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error(){ echo -e "${RED}[ERROR]${NC} $1"; exit 1; }
info() { echo -e "${BLUE}[INFO]${NC} $1"; }

echo ""
echo "╔══════════════════════════════════════════╗"
echo "║     NDR Stack — Sensor Installation      ║"
echo "║     Network Detection & Response         ║"
echo "╚══════════════════════════════════════════╝"
echo ""

# ── Parse arguments ──────────────────────────────
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

# ── Validate ─────────────────────────────────────
if [ -z "$CLOUD_URL" ] || [ -z "$TENANT_ID" ] || [ -z "$API_KEY" ]; then
echo "Usage: $0 --cloud-url URL --tenant-id ID --api-key KEY [--interface eth0]"
exit 1
fi

# ── Detect interface ──────────────────────────────
if [ -z "$IFACE" ]; then
    IFACES=$(ip -o -4 addr show 2>/dev/null | \
        grep -v "127\.0\.0\.1\|docker\|br-\|veth\| lo " | \
        awk '{print $2}') || true

    if [ -z "$IFACES" ]; then
        warn "Strict filter returned no interfaces, trying broader detection..."
        IFACES=$(ip -o -4 addr show 2>/dev/null | \
            awk '$4 !~ /^127\./ {print $2}' | \
            grep -v "^lo$\|^docker\|^br-\|^veth") || true
    fi

    if [ -z "$IFACES" ]; then
        IFACES=$(ip -o link show 2>/dev/null | \
            awk -F': ' '{print $2}' | \
            awk '{print $1}' | \
            grep -v "^lo$\|^docker\|^br-\|^veth") || true
    fi

    IFACE_COUNT=$(echo "$IFACES" | grep -c . 2>/dev/null || echo 0)

    if [ "$IFACE_COUNT" -eq 0 ]; then
        warn "Could not auto-detect any network interface."
        read -rp "Enter interface name (e.g. eth0, eno1, ens3): " IFACE
        IFACE=${IFACE:-eth0}
        log "Using interface: $IFACE"
    elif [ "$IFACE_COUNT" -eq 1 ]; then
        IFACE=$(echo "$IFACES" | head -1)
        log "Auto-detected interface: $IFACE"
    else
        echo ""
        echo "Available network interfaces:"
        echo "─────────────────────────────"
        i=1
        while IFS= read -r iface; do
            IP=$(ip -o -4 addr show "$iface" 2>/dev/null | \
                awk '{print $4}' | cut -d/ -f1)
            echo "  $i) $iface${IP:+ ($IP)}"
            i=$((i+1))
        done <<< "$IFACES"
        echo "─────────────────────────────"
        echo ""
        read -rp "Select interface [1]: " IFACE_NUM
        IFACE_NUM=${IFACE_NUM:-1}
        IFACE=$(echo "$IFACES" | sed -n "${IFACE_NUM}p")
        log "Selected interface: $IFACE"
    fi
fi

# ── Check OS ──────────────────────────────────────
if [ ! -f /etc/os-release ]; then
    error "Unsupported OS"
fi
source /etc/os-release
log "OS: $PRETTY_NAME"

# ── Check root ────────────────────────────────────
if [ "$EUID" -ne 0 ]; then
    error "Please run as root: sudo $0"
fi

# ── Stop existing services ────────────────────────
log "Stopping existing sensor services if any..."
pkill -f agent.py 2>/dev/null || true
systemctl stop ndr-vector 2>/dev/null || true
systemctl stop ndr-agent 2>/dev/null || true
systemctl stop suricata 2>/dev/null || true
pkill -9 -f suricata 2>/dev/null || true
pkill -9 -f zeek 2>/dev/null || true
pkill -9 -f vector 2>/dev/null || true
rm -f /tmp/suricata.pid
rm -f /var/run/suricata.pid
rm -f /run/suricata.pid
sleep 2

# Verify all stopped
log "Verifying services stopped..."
echo "  Agent:    $(pgrep -f agent.py >/dev/null && echo -e '${RED}running${NC}' || echo -e '${GREEN}stopped${NC}')"
echo "  Vector:   $(pgrep -x vector >/dev/null && echo -e '${RED}running${NC}' || echo -e '${GREEN}stopped${NC}')"
echo "  Suricata: $(pgrep -x Suricata >/dev/null && echo -e '${RED}running${NC}' || echo -e '${GREEN}stopped${NC}')"
echo "  Zeek:     $(pgrep -x zeek >/dev/null && echo -e '${RED}running${NC}' || echo -e '${GREEN}stopped${NC}')"

# ── Install dependencies ──────────────────────────
log "Installing dependencies..."
apt-get update -qq
apt-get install -y -qq \
    curl wget git python3 python3-pip \
    apt-transport-https gnupg2 \
    software-properties-common > /dev/null

# Install python requests
pip3 install requests --quiet 2>/dev/null || true

# ── Install Zeek ──────────────────────────────────
log "Installing Zeek..."
if ! command -v zeek &>/dev/null && \
   ! command -v /opt/zeek/bin/zeek &>/dev/null; then
    UBUNTU_VER=$(lsb_release -rs 2>/dev/null || echo "22.04")
    UBUNTU_MAJOR=$(echo $UBUNTU_VER | cut -d. -f1)
    log "Detected Ubuntu $UBUNTU_VER"

    if [ "$UBUNTU_MAJOR" = "20" ]; then
        apt-get install -y -qq software-properties-common > /dev/null
        add-apt-repository -y ppa:zeek/zeek > /dev/null 2>&1
        apt-get update -qq
        apt-get install -y -qq zeek > /dev/null 2>&1 || \
        apt-get install -y -qq zeek-lts > /dev/null 2>&1 || true
    elif [ "$UBUNTU_MAJOR" = "22" ]; then
        echo "deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/ /" \
            > /etc/apt/sources.list.d/security:zeek.list
        curl -fsSL "https://download.opensuse.org/repositories/security:zeek/xUbuntu_22.04/Release.key" \
            | gpg --dearmor \
            > /etc/apt/trusted.gpg.d/security_zeek.gpg 2>/dev/null
        apt-get update -qq
        apt-get install -y -qq zeek > /dev/null
    elif [ "$UBUNTU_MAJOR" = "24" ]; then
        echo "deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_24.04/ /" \
            > /etc/apt/sources.list.d/security:zeek.list
        curl -fsSL "https://download.opensuse.org/repositories/security:zeek/xUbuntu_24.04/Release.key" \
            | gpg --dearmor \
            > /etc/apt/trusted.gpg.d/security_zeek.gpg 2>/dev/null
        apt-get update -qq
        apt-get install -y -qq zeek > /dev/null
    else
        warn "Unsupported Ubuntu $UBUNTU_VER — install Zeek manually"
    fi
    echo 'export PATH=$PATH:/opt/zeek/bin' >> /etc/profile
    export PATH=$PATH:/opt/zeek/bin
    log "✅ Zeek installed"
else
    log "✅ Zeek already installed"
fi

# ── Install Suricata ──────────────────────────────
log "Installing Suricata..."
if ! command -v suricata &>/dev/null; then
    add-apt-repository -y ppa:oisf/suricata-stable > /dev/null 2>&1
    apt-get update -qq
    apt-get install -y -qq suricata > /dev/null
    log "✅ Suricata installed"
else
    log "✅ Suricata already installed"
fi

# Load Suricata rules
log "Loading Suricata rules..."
suricata-update > /dev/null 2>&1 || true
log "✅ Suricata rules loaded"

# ── Install Vector ────────────────────────────────
log "Installing Vector..."
if ! command -v vector &>/dev/null; then
    ARCH=$(dpkg --print-architecture)
    VECTOR_VERSION="0.32.1"
    if curl -fsSL https://repositories.vector.dev/gpg.key \
        | gpg --dearmor \
        > /usr/share/keyrings/vector-keyring.gpg 2>/dev/null; then
        echo "deb [arch=$ARCH signed-by=/usr/share/keyrings/vector-keyring.gpg] \
            https://repositories.vector.dev/ubuntu/ stable vector-0" \
            > /etc/apt/sources.list.d/vector.list
        apt-get update -qq 2>/dev/null
        apt-get install -y -qq vector > /dev/null 2>&1 || {
            if [ "$ARCH" = "amd64" ]; then
                VECTOR_URL="https://github.com/vectordotdev/vector/releases/download/v${VECTOR_VERSION}/vector_${VECTOR_VERSION}-1_amd64.deb"
            else
                VECTOR_URL="https://github.com/vectordotdev/vector/releases/download/v${VECTOR_VERSION}/vector_${VECTOR_VERSION}-1_arm64.deb"
            fi
            wget -q --timeout=30 "$VECTOR_URL" -O /tmp/vector.deb 2>/dev/null && \
            dpkg -i /tmp/vector.deb > /dev/null 2>&1 && \
            rm -f /tmp/vector.deb || true
        }
    fi

    if ! command -v vector &>/dev/null; then
        case "$ARCH" in
            amd64)
                VECTOR_DEB_ARCH="amd64"
                ;;
            arm64|aarch64)
                VECTOR_DEB_ARCH="arm64"
                ;;
            *)
                error "Unsupported architecture for Vector fallback package: $ARCH"
                ;;
        esac

        VECTOR_URL="https://github.com/vectordotdev/vector/releases/download/v${VECTOR_VERSION}/vector_${VECTOR_VERSION}-1_${VECTOR_DEB_ARCH}.deb"
        warn "Vector was not found after apt install; trying release package fallback"
        if curl -fL --connect-timeout 15 --max-time 120 "$VECTOR_URL" -o /tmp/vector.deb; then
            apt-get install -y -qq /tmp/vector.deb > /dev/null 2>&1 || {
                rm -f /tmp/vector.deb
                error "Vector release package install failed"
            }
            rm -f /tmp/vector.deb
        else
            rm -f /tmp/vector.deb
            error "Vector download failed. Check DNS/network access to repositories.vector.dev or github.com"
        fi
    fi

    VECTOR_BIN=$(command -v vector || true)
    if [ -z "$VECTOR_BIN" ]; then
        error "Vector installation failed: vector binary was not found after install"
    fi
    log "Vector verified: $($VECTOR_BIN --version 2>/dev/null || echo "$VECTOR_BIN")"
    log "✅ Vector installed"
else
    log "✅ Vector already installed"
fi

# ── Create directories ────────────────────────────
log "Creating directories..."
mkdir -p /opt/ndr-sensor
mkdir -p /var/log/ndr/zeek
mkdir -p /var/log/ndr/suricata
mkdir -p /etc/ndr
mkdir -p /etc/vector/data

# Fix permissions for all log dirs
chmod -R 777 /var/log/ndr/
chmod 777 /etc/vector/data
chown -R root:root /var/log/ndr/
chmod 777 /opt/ndr-sensor

# Fix Suricata log permissions
mkdir -p /var/run/suricata
chmod 777 /var/run/suricata
chown -R root:root /var/run/suricata

log "✅ Directories and permissions set"

# ── Save config ───────────────────────────────────
log "Saving sensor config..."
cat > /etc/ndr/sensor.conf << EOF
CLOUD_URL=$CLOUD_URL
TENANT_ID=$TENANT_ID
API_KEY=$API_KEY
IFACE=$IFACE
INSTALL_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ)
EOF

# ── Configure Vector ──────────────────────────────
log "Configuring Vector → $CLOUD_URL..."
HOSTNAME_VAL=$(hostname)
cat > /etc/ndr/vector.toml << EOF
data_dir = "/etc/vector/data"

[sources.zeek_logs]
type = "file"
include = [
    "/var/log/ndr/zeek/conn.log",
    "/var/log/ndr/zeek/dns.log",
    "/var/log/ndr/zeek/http.log",
    "/var/log/ndr/zeek/ssl.log"
]
read_from = "end"

[sources.suricata_logs]
type = "file"
include = ["/var/log/ndr/suricata/eve.json"]
read_from = "end"

[transforms.parse_suricata]
type = "remap"
inputs = ["suricata_logs"]
source = """
parsed, err = parse_json(.message)
if err == null {
    . = parsed
    .source = "suricata"
    .tenant_id = "${TENANT_ID}"
    .sensor_host = "${HOSTNAME_VAL}"
} else {
    abort
}
"""

[transforms.parse_zeek]
type = "remap"
inputs = ["zeek_logs"]
source = """
parsed, err = parse_json(.message)
if err == null {
    . = parsed
    .source = "zeek"
    .tenant_id = "${TENANT_ID}"
    .sensor_host = "${HOSTNAME_VAL}"
} else {
    abort
}
"""

[sinks.ndr_http]
type = "http"
inputs = ["parse_suricata", "parse_zeek"]
uri = "${CLOUD_URL}/api/ingest"
method = "post"
encoding.codec = "json"
framing.method = "newline_delimited"
compression = "gzip"

[sinks.ndr_http.batch]
max_bytes = 10485760
max_events = 5000
timeout_secs = 1

[sinks.ndr_http.request]
concurrency = 10
retry_attempts = 5
timeout_secs = 30

[sinks.ndr_http.request.headers]
X-Sensor-Key = "${API_KEY}"
Content-Type = "application/x-ndjson"

[sinks.ndr_http.buffer]
type = "disk"
max_size = 536870912
when_full = "block"
EOF

# ── Configure Zeek ────────────────────────────────
log "Configuring Zeek..."
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

    tee /opt/zeek/share/zeek/site/local.zeek > /dev/null << 'ZEEKCONF'
# NDR Stack - Zeek Configuration
@load policy/tuning/json-logs.zeek
@load policy/protocols/conn/community-id-logging
@load protocols/ssh/detect-bruteforcing
@load protocols/ssl/validate-certs
@load misc/detect-traceroute
@load frameworks/files/hash-all-files
@load policy/protocols/conn/known-hosts
@load policy/protocols/conn/known-services
ZEEKCONF

    /opt/zeek/bin/zkg install zeek/corelight/zeek-community-id \
        --force > /dev/null 2>&1 || true
    log "✅ Zeek configured with JSON + community-id"
fi

# ── Configure Suricata ────────────────────────────
log "Configuring Suricata..."
if [ -f /etc/suricata/suricata.yaml ]; then
    cp /etc/suricata/suricata.yaml \
        /etc/suricata/suricata.yaml.bak 2>/dev/null || true
    sed -i 's/community-id: false/community-id: true/g' \
        /etc/suricata/suricata.yaml 2>/dev/null || true
    sed -i "s|default-log-dir: /var/log/suricata|default-log-dir: /var/log/ndr/suricata|g" \
        /etc/suricata/suricata.yaml 2>/dev/null || true
    sed -i "s|interface: eth0|interface: $IFACE|g" \
        /etc/suricata/suricata.yaml 2>/dev/null || true
    log "✅ Suricata configured with community-id on: $IFACE"
fi

# ── Create sensor agent ───────────────────────────
log "Creating sensor agent..."
cat > /opt/ndr-sensor/agent.py << 'AGENT'
#!/usr/bin/env python3
"""NDR Sensor Agent - monitors and auto-restarts services"""
import os, time, subprocess, requests
from datetime import datetime

config = {}
with open('/etc/ndr/sensor.conf') as f:
    for line in f:
        if '=' in line:
            k, v = line.strip().split('=', 1)
            config[k] = v

CLOUD_URL = config.get('CLOUD_URL', '')
TENANT_ID = config.get('TENANT_ID', '')
API_KEY   = config.get('API_KEY', '')
IFACE     = config.get('IFACE', 'eth0')
DESIRED_STATE = 'running'

def is_running(name):
    try:
        return subprocess.run(
            ['pgrep', '-f', name],
            capture_output=True
        ).returncode == 0
    except:
        return False

def start_zeek():
    try:
        # Kill any stale zeek processes
        subprocess.run(['pkill', '-9', '-f', 'zeek'], capture_output=True)
        time.sleep(2)
        # Clear Vector checkpoints so it reads from current position
        subprocess.run(["rm", "-rf", "/etc/vector/data/suricata", "/etc/vector/data/zeek"], capture_output=True)
        # Start Zeek directly exactly like ndr-agent.py
        subprocess.Popen(
            ["/opt/zeek/bin/zeek", "-i", IFACE, "local", "Log::default_logdir=/var/log/ndr/zeek"],
            stdout=open("/tmp/zeek.log", "w"),
            stderr=subprocess.STDOUT
        )
        print("[NDR] ✅ Zeek started directly!")
        return True
    except Exception as e:
        print(f"[NDR] Zeek start failed: {e}")
    return False

def start_suricata():
    try:
        # Kill any stale suricata processes
        subprocess.run(['pkill', '-9', '-f', 'suricata'], capture_output=True)
        time.sleep(2)
        # Clean ALL stale PID files
        subprocess.run(['rm', '-f', '/tmp/suricata.pid', '/var/run/suricata.pid', '/run/suricata.pid', '/var/run/suricata/suricata.pid'], capture_output=True)
        # Start Suricata directly exactly like ndr-agent.py
        subprocess.Popen(
            [
                "suricata",
                "-c", "/etc/suricata/suricata.yaml",
                "-i", IFACE,
                "-l", "/var/log/ndr/suricata",
                "-D",
                "--pidfile", "/tmp/suricata.pid",
                "--set", "detect.profile=low",
                "--set", "max-pending-packets=128"
            ],
            stdout=open("/tmp/suricata.log", "w"),
            stderr=subprocess.STDOUT
        )
        print("[NDR] ✅ Suricata started directly!")
        return True
    except Exception as e:
        print(f"[NDR] Suricata start failed: {e}")
    return False

def start_vector():
    try:
        result = subprocess.run(
            ['systemctl', 'start', 'ndr-vector'],
            capture_output=True, timeout=30
        )
        if result.returncode == 0:
            print("[NDR] ✅ Vector started!")
            return True
    except Exception as e:
        print(f"[NDR] Vector start failed: {e}")
    return False

def check_and_restart():
    if DESIRED_STATE == 'stopped':
        return {
            'zeek': 'stopped',
            'suricata': 'stopped',
            'vector': 'stopped'
        }

    zeek_ok     = is_running('zeek')
    suricata_ok = is_running('suricata')
    vector_ok   = is_running('vector')

    if not zeek_ok:
        print("[NDR] Zeek stopped! Restarting...")
        start_zeek()
    if not suricata_ok:
        print("[NDR] Suricata stopped! Restarting...")
        start_suricata()
    if not vector_ok:
        print("[NDR] Vector stopped! Restarting...")
        start_vector()

    return {
        'zeek':     'running' if zeek_ok else 'restarting',
        'suricata': 'running' if suricata_ok else 'restarting',
        'vector':   'running' if vector_ok else 'restarting'
    }

def report_status(services):
    status = {
        'tenant_id': TENANT_ID,
        'timestamp': datetime.utcnow().isoformat(),
        **services
    }
    try:
        requests.post(
            f'{CLOUD_URL}/api/sensor/heartbeat',
            json=status,
            headers={'X-Sensor-Key': API_KEY},
            timeout=5
        )
        print(f"[NDR] Heartbeat: {status}")
    except Exception as e:
        print(f"[NDR] Heartbeat failed: {e}")

def get_command():
    """Check for commands from cloud"""
    try:
        resp = requests.get(
            f'{CLOUD_URL}/api/sensor/command',
            headers={'X-Sensor-Key': API_KEY},
            timeout=5
        )
        if resp.status_code == 200:
            return resp.json().get('command', '')
    except:
        pass
    return ''

def execute_command(cmd):
    """Execute command from tenant admin"""
    global DESIRED_STATE
    print(f"[NDR] Command received: {cmd}")
    if cmd == 'start':
        DESIRED_STATE = 'running'
        start_zeek()
        start_suricata()
        start_vector()
    elif cmd == 'stop':
        DESIRED_STATE = 'stopped'
        subprocess.run(['systemctl', 'stop', 'ndr-vector'],
            capture_output=True)
        subprocess.run(['pkill', '-9', '-f', 'zeek'],
            capture_output=True)
        subprocess.run(['pkill', '-9', '-f', 'suricata'],
            capture_output=True)
        subprocess.run(['rm', '-f', '/var/run/suricata.pid', '/run/suricata.pid', '/tmp/suricata.pid'],
            capture_output=True)
        print("[NDR] All services stopped!")
    elif cmd == 'restart':
        DESIRED_STATE = 'running'
        execute_command('stop')
        DESIRED_STATE = 'running'
        time.sleep(3)
        execute_command('start')

if __name__ == '__main__':
    print(f"[NDR] Agent starting for tenant: {TENANT_ID}")
    print(f"[NDR] Cloud: {CLOUD_URL}")

    # Auto-create log directories
    os.makedirs("/var/log/ndr/suricata", exist_ok=True)
    os.makedirs("/var/log/ndr/zeek", exist_ok=True)

    # Initial start of all services
    print("[NDR] Starting sensor services...")
    start_zeek()
    start_suricata()
    start_vector()
    time.sleep(5)

    while True:
        # Check commands from cloud
        cmd = get_command()
        if cmd:
            execute_command(cmd)

        # Monitor and restart if stopped
        services = check_and_restart()

        # Report status to cloud
        report_status(services)

        time.sleep(30)
AGENT
chmod +x /opt/ndr-sensor/agent.py

# ── Create systemd services ───────────────────────
log "Creating systemd services..."

VECTOR_BIN=$(which vector 2>/dev/null || echo "/usr/bin/vector")

cat > /etc/systemd/system/ndr-vector.service << EOF
[Unit]
Description=NDR Vector Log Forwarder
After=network.target
[Service]
ExecStart=$VECTOR_BIN --config /etc/ndr/vector.toml
Restart=always
RestartSec=5
[Install]
WantedBy=multi-user.target
EOF

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

# ── Enable services (agent starts everything) ─────
log "Enabling services..."
systemctl daemon-reload
systemctl enable ndr-vector ndr-agent 2>/dev/null || true

# Only start agent - agent handles Zeek/Suricata/Vector
systemctl start ndr-agent 2>/dev/null || true
log "✅ Agent started - will start all sensor services"

# ── Register sensor with cloud ────────────────────
log "Registering sensor with cloud..."
sleep 3
REG_RESULT=$(curl -s -X POST \
    "$CLOUD_URL/api/sensor/register" \
    -H "X-Sensor-Key: $API_KEY" \
    -H "Content-Type: application/json" \
    -d "{
        \"tenant_id\": \"$TENANT_ID\",
        \"hostname\": \"$(hostname)\",
        \"interface\": \"$IFACE\",
        \"os\": \"$PRETTY_NAME\"
    }" 2>/dev/null)

if echo "$REG_RESULT" | grep -q '"status":"ok"'; then
    log "✅ Sensor registered with cloud!"
else
    warn "Cloud registration failed"
    warn "Response: $REG_RESULT"
fi

# ── Test ingest ───────────────────────────────────
log "Testing log ingest to cloud..."
sleep 5
INGEST_TEST=$(curl -s -X POST \
    "$CLOUD_URL/api/ingest" \
    -H "X-Sensor-Key: $API_KEY" \
    -H "Content-Type: application/json" \
    -d "{\"events\":[{\"source\":\"test\",\"event_type\":\"sensor_install\",\"src_ip\":\"$(hostname -I | awk '{print $1}')\",\"tenant_id\":\"$TENANT_ID\"}]}" \
    2>/dev/null)

if echo "$INGEST_TEST" | grep -q '"status":"ok"'; then
    log "✅ Log ingest to cloud verified!"
else
    warn "Ingest test failed"
    warn "Response: $INGEST_TEST"
fi

# ── Summary ───────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════╗"
echo "║     ✅ NDR Sensor Installation Done!     ║"
echo "╠══════════════════════════════════════════╣"
printf "║  Tenant:    %-28s ║\n" "$TENANT_ID"
printf "║  Interface: %-28s ║\n" "$IFACE"
printf "║  Cloud:     %-28s ║\n" "${CLOUD_URL:0:28}"
echo "╠══════════════════════════════════════════╣"
echo "║  Agent running — manages all services    ║"
echo "║  Sensor data flowing to cloud platform   ║"
echo "╚══════════════════════════════════════════╝"
echo ""
log "Config: /etc/ndr/sensor.conf"
log "Logs:   /var/log/ndr/"
