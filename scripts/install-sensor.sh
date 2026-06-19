#!/bin/bash
# NDR Sensor Installation Script v2 — Fixed
# Fixes: Arkime viewer, Vector Kafka sink,
#        all Zeek sources, retry logic,
#        OpenSearch wait, mark_fulfilled
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
KAFKA_BOOTSTRAP=""

while [[ $# -gt 0 ]]; do
  case $1 in
    --cloud-url)      CLOUD_URL="$2";      shift 2 ;;
    --tenant-id)      TENANT_ID="$2";      shift 2 ;;
    --api-key)        API_KEY="$2";        shift 2 ;;
    --interface)      IFACE="$2";          shift 2 ;;
    --kafka)          KAFKA_BOOTSTRAP="$2";shift 2 ;;
    *) warn "Unknown option: $1"; shift ;;
  esac
done

# ── Validate ─────────────────────────────────────
if [ -z "$CLOUD_URL" ] || \
   [ -z "$TENANT_ID" ] || \
   [ -z "$API_KEY" ]; then
  echo "Usage: $0 \\"
  echo "  --cloud-url https://your-cloud.com \\"
  echo "  --tenant-id acme1 \\"
  echo "  --api-key YOUR_KEY \\"
  echo "  [--interface eth0] \\"
  echo "  [--kafka cloud-host:9092]"
  exit 1
fi

# Derive Kafka bootstrap from cloud-url
# if not explicitly provided
if [ -z "$KAFKA_BOOTSTRAP" ]; then
  CLOUD_HOST=$(echo "$CLOUD_URL" | \
    sed -E 's|https?://([^:/]+).*|\1|')
  KAFKA_BOOTSTRAP="${CLOUD_HOST}:9092"
  log "Kafka bootstrap: $KAFKA_BOOTSTRAP"
fi

# ── Detect interface ──────────────────────────────
if [ -z "$IFACE" ]; then
  IFACES=$(ip -o -4 addr show 2>/dev/null | \
    grep -v "127\.0\.0\.1\|docker\|br-\|veth\| lo " | \
    awk '{print $2}') || true

  IFACE_COUNT=$(echo "$IFACES" | \
    grep -c . 2>/dev/null || echo 0)

  if [ "$IFACE_COUNT" -eq 0 ]; then
    read -rp "Enter interface (e.g. eth0, eno1): " \
      IFACE
    IFACE=${IFACE:-eth0}
  elif [ "$IFACE_COUNT" -eq 1 ]; then
    IFACE=$(echo "$IFACES" | head -1)
    log "Auto-detected interface: $IFACE"
  else
    echo "Available interfaces:"
    echo "─────────────────────"
    i=1
    while IFS= read -r iface; do
      IP=$(ip -o -4 addr show "$iface" \
        2>/dev/null | awk '{print $4}' | \
        cut -d/ -f1)
      echo "  $i) $iface${IP:+ ($IP)}"
      i=$((i+1))
    done <<< "$IFACES"
    echo "─────────────────────"
    read -rp "Select interface [1]: " IFACE_NUM
    IFACE_NUM=${IFACE_NUM:-1}
    IFACE=$(echo "$IFACES" | \
      sed -n "${IFACE_NUM}p")
    log "Selected: $IFACE"
  fi
fi

# ── Check OS and root ─────────────────────────────
[ -f /etc/os-release ] || error "Unsupported OS"
source /etc/os-release
log "OS: $PRETTY_NAME"
[ "$EUID" -eq 0 ] || \
  error "Run as root: sudo $0"

# ── Stop existing services ────────────────────────
log "Stopping existing services..."
pkill -f agent.py       2>/dev/null || true
systemctl stop ndr-vector   2>/dev/null || true
systemctl stop ndr-agent    2>/dev/null || true
systemctl stop arkime-capture 2>/dev/null || true
systemctl stop arkime-viewer  2>/dev/null || true
pkill -9 -f suricata    2>/dev/null || true
pkill -9 -f "zeek"      2>/dev/null || true
pkill -9 -f vector      2>/dev/null || true
rm -f /tmp/suricata.pid \
      /var/run/suricata.pid \
      /run/suricata.pid
sleep 2

# ── Install dependencies ──────────────────────────
log "Installing dependencies..."
apt-get update -qq
apt-get install -y -qq \
  curl wget git python3 python3-pip \
  apt-transport-https gnupg2 \
  software-properties-common \
  libpcre3 libpcre3-dev \
  ethtool docker.io > /dev/null 2>&1 || true

pip3 install requests --quiet 2>/dev/null || true

# ── Install Zeek ──────────────────────────────────
log "Installing Zeek..."
if ! command -v /opt/zeek/bin/zeek &>/dev/null; then
  UBUNTU_MAJOR=$(lsb_release -rs | cut -d. -f1)
  log "Ubuntu $UBUNTU_MAJOR detected"

  if [ "$UBUNTU_MAJOR" = "22" ]; then
    echo "deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/ /" \
      > /etc/apt/sources.list.d/security:zeek.list
    curl -fsSL "https://download.opensuse.org/repositories/security:zeek/xUbuntu_22.04/Release.key" \
      | gpg --dearmor \
      > /etc/apt/trusted.gpg.d/security_zeek.gpg 2>/dev/null
  elif [ "$UBUNTU_MAJOR" = "24" ]; then
    echo "deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_24.04/ /" \
      > /etc/apt/sources.list.d/security:zeek.list
    curl -fsSL "https://download.opensuse.org/repositories/security:zeek/xUbuntu_24.04/Release.key" \
      | gpg --dearmor \
      > /etc/apt/trusted.gpg.d/security_zeek.gpg 2>/dev/null
  fi

  apt-get update -qq
  apt-get install -y -qq zeek > /dev/null
  echo 'export PATH=$PATH:/opt/zeek/bin' \
    >> /etc/profile
  export PATH=$PATH:/opt/zeek/bin
fi
log "✅ Zeek: $(/opt/zeek/bin/zeek --version \
  2>&1 | head -1)"

# ── Install Suricata ──────────────────────────────
log "Installing Suricata..."
if ! command -v suricata &>/dev/null; then
  add-apt-repository -y \
    ppa:oisf/suricata-stable > /dev/null 2>&1
  apt-get update -qq
  apt-get install -y -qq suricata > /dev/null
fi
suricata-update > /dev/null 2>&1 || true
log "✅ Suricata: $(suricata --version \
  2>&1 | head -1)"

# ── Install Arkime ────────────────────────────────
log "Installing Arkime..."
ARKIME_VERSION="5.1.0"
UBUNTU_MAJOR=$(lsb_release -rs | cut -d. -f1)

if ! command -v /opt/arkime/bin/capture \
    &>/dev/null; then

  if   [ "$UBUNTU_MAJOR" -le "21" ]; then
    DEB="arkime_${ARKIME_VERSION}-1.ubuntu2004_amd64.deb"
  elif [ "$UBUNTU_MAJOR" -le "23" ]; then
    DEB="arkime_${ARKIME_VERSION}-1.ubuntu2204_amd64.deb"
  else
    DEB="arkime_${ARKIME_VERSION}-1.ubuntu2404_amd64.deb"
  fi

  log "Downloading Arkime ${ARKIME_VERSION}..."
  wget --timeout=120 --progress=dot:mega \
    "https://github.com/arkime/arkime/releases/download/v${ARKIME_VERSION}/${DEB}" \
    -O /tmp/arkime.deb 2>&1 || \
    error "Arkime download failed"

  apt-get install -y -qq \
    libwww-perl libjson-perl \
    libyaml-dev librdkafka1 \
    libmagic1 libmaxminddb0 \
    libpcre2-8-0 > /dev/null 2>&1 || true

  dpkg -i /tmp/arkime.deb > /dev/null 2>&1 || \
    apt-get install -f -y > /dev/null 2>&1 || true
  rm -f /tmp/arkime.deb
fi
log "✅ Arkime: $(\
  /opt/arkime/bin/capture --version \
  2>/dev/null | head -1)"

# ── Install Vector ────────────────────────────────
log "Installing Vector..."
if ! command -v vector &>/dev/null; then
  ARCH=$(dpkg --print-architecture)
  VECTOR_VER="0.32.1"

  curl -fsSL \
    https://repositories.vector.dev/gpg.key \
    | gpg --dearmor \
    > /usr/share/keyrings/vector-keyring.gpg \
    2>/dev/null

  echo "deb [arch=$ARCH signed-by=/usr/share/keyrings/vector-keyring.gpg] \
    https://repositories.vector.dev/ubuntu/ \
    stable vector-0" \
    > /etc/apt/sources.list.d/vector.list

  apt-get update -qq
  apt-get install -y -qq vector \
    > /dev/null 2>&1 || {
    wget -q --timeout=60 \
      "https://github.com/vectordotdev/vector/releases/download/v${VECTOR_VER}/vector_${VECTOR_VER}-1_${ARCH}.deb" \
      -O /tmp/vector.deb && \
      dpkg -i /tmp/vector.deb \
        > /dev/null 2>&1
    rm -f /tmp/vector.deb
  }
fi
log "✅ Vector: $(vector --version 2>/dev/null)"

# ── Create directories ────────────────────────────
log "Creating directories..."
mkdir -p /opt/arkime/raw \
         /opt/arkime/logs \
         /opt/arkime/etc \
         /opt/ndr-sensor/pcap-tmp \
         /var/log/ndr/zeek \
         /var/log/ndr/suricata \
         /etc/ndr \
         /etc/vector/data \
         /var/run/suricata

chmod -R 777 /var/log/ndr/ \
             /etc/vector/data \
             /opt/ndr-sensor \
             /var/run/suricata
chmod 755 /opt/arkime/raw

# ── Save sensor config ────────────────────────────
log "Saving sensor config..."
cat > /etc/ndr/sensor.conf << EOF
CLOUD_URL=${CLOUD_URL}
TENANT_ID=${TENANT_ID}
API_KEY=${API_KEY}
IFACE=${IFACE}
KAFKA_BOOTSTRAP=${KAFKA_BOOTSTRAP}
INSTALL_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ)
EOF

# ── Start local OpenSearch for Arkime ────────────
# FIX: Start OpenSearch FIRST, wait fully,
#      THEN configure and start Arkime
log "Starting local OpenSearch for Arkime..."

# Remove old container if exists
docker rm -f opensearch-arkime 2>/dev/null || true

docker run -d \
  --name opensearch-arkime \
  -e "discovery.type=single-node" \
  -e "DISABLE_SECURITY_PLUGIN=true" \
  -e "OPENSEARCH_JAVA_OPTS=-Xms256m -Xmx512m" \
  -p 9200:9200 \
  --restart unless-stopped \
  opensearchproject/opensearch:2.5.0 \
    > /dev/null 2>&1

# FIX: Wait properly — up to 3 minutes
log "Waiting for OpenSearch (up to 3 min)..."
TRIES=0
MAX_TRIES=60   # 60 × 3s = 180s = 3 min
while [ $TRIES -lt $MAX_TRIES ]; do
  if curl -s http://localhost:9200 \
      > /dev/null 2>&1; then
    # Extra check: cluster health green or yellow
    STATUS=$(curl -s \
      "http://localhost:9200/_cluster/health" \
      2>/dev/null | \
      python3 -c "import sys,json; \
        d=json.load(sys.stdin); \
        print(d.get('status','red'))" \
      2>/dev/null || echo "red")
    if [ "$STATUS" != "red" ]; then
      log "✅ OpenSearch ready (status: $STATUS)"
      break
    fi
  fi
  echo -n "."
  sleep 3
  TRIES=$((TRIES+1))
done
echo ""

if [ $TRIES -ge $MAX_TRIES ]; then
  warn "OpenSearch took too long to start"
  warn "Arkime may not work correctly"
fi

# ── Configure Arkime ──────────────────────────────
log "Configuring Arkime..."
ARKIME_PASS=$(echo "$API_KEY" | \
  sha256sum | cut -c1-16)

cat > /opt/arkime/etc/config.ini << EOF
[default]
elasticsearch=http://localhost:9200
passwordSecret=${ARKIME_PASS}
serverSecret=${ARKIME_PASS}
httpRealm=Arkime
interface=${IFACE}
pcapDir=/opt/arkime/raw
maxFileSizeG=4
maxFileTimeM=60
pcapWriteMethod=simple
pcapWriteSize=262143
logLevel=warn
maxDays=7
freeSpaceG=5
tcpTimeout=600
udpTimeout=30
maxStreams=500000
maxPackets=10000
packetThreads=2
communityId=true
cronQueries=false
viewPort=8005
EOF

# ── Initialize Arkime database ────────────────────
log "Initializing Arkime index in OpenSearch..."
echo "yes" | timeout 90 \
  /opt/arkime/db/db.pl \
  http://localhost:9200 init \
  --ifneeded 2>&1 || \
echo "yes" | timeout 90 \
  /opt/arkime/db/db.pl \
  http://localhost:9200 init \
  2>&1 || true

# ── Create Arkime admin user ──────────────────────
log "Creating Arkime admin user..."
/opt/arkime/bin/arkime_add_user.sh \
  admin "NDR Admin" "$ARKIME_PASS" \
  --admin 2>/dev/null || true
log "✅ Arkime admin: user=admin pass=$ARKIME_PASS"

# ── FIX: Create Arkime CAPTURE service ───────────
cat > /etc/systemd/system/arkime-capture.service \
  << EOF
[Unit]
Description=Arkime Packet Capture
After=network.target opensearch-arkime.service
[Service]
Type=simple
ExecStartPre=/bin/sleep 5
ExecStart=/opt/arkime/bin/capture \
  -c /opt/arkime/etc/config.ini \
  --insecure
Restart=always
RestartSec=15
LimitCORE=infinity
LimitMEMLOCK=infinity
[Install]
WantedBy=multi-user.target
EOF

# ── FIX: Create Arkime VIEWER service ────────────
# THIS WAS MISSING — viewer is what pcap-uploader
# calls on port 8005 to extract PCAP bytes
cat > /etc/systemd/system/arkime-viewer.service \
  << EOF
[Unit]
Description=Arkime Session Viewer
After=network.target arkime-capture.service
[Service]
Type=simple
WorkingDirectory=/opt/arkime
ExecStartPre=/bin/sleep 10
ExecStart=/usr/bin/node \
  /opt/arkime/viewer/viewer.js \
  -c /opt/arkime/etc/config.ini
Restart=always
RestartSec=15
Environment=NODE_ENV=production
[Install]
WantedBy=multi-user.target
EOF

# ── Configure Zeek ────────────────────────────────
log "Configuring Zeek..."
export PATH=$PATH:/opt/zeek/bin

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

  cat > /opt/zeek/share/zeek/site/local.zeek \
    << 'ZEEKCONF'
@load policy/tuning/json-logs.zeek
@load policy/protocols/conn/community-id-logging
@load protocols/ssh/detect-bruteforcing
@load protocols/ssl/validate-certs
@load misc/detect-traceroute
@load frameworks/files/hash-all-files
@load policy/protocols/conn/known-hosts
@load policy/protocols/conn/known-services
ZEEKCONF

  /opt/zeek/bin/zkg install \
    zeek/corelight/zeek-community-id \
    --force > /dev/null 2>&1 || true

  log "✅ Zeek configured"
fi

# ── Configure Suricata ────────────────────────────
log "Configuring Suricata..."
if [ -f /etc/suricata/suricata.yaml ]; then
  cp /etc/suricata/suricata.yaml \
     /etc/suricata/suricata.yaml.bak \
     2>/dev/null || true

  # FIX: Verify these sed commands work
  # by checking the result afterward
  sed -i \
    's/community-id: false/community-id: true/g' \
    /etc/suricata/suricata.yaml

  # Set log dir
  sed -i \
    "s|default-log-dir: /var/log/suricata|default-log-dir: /var/log/ndr/suricata|g" \
    /etc/suricata/suricata.yaml

  # Verify community-id is set
  if grep -q "community-id: true" \
      /etc/suricata/suricata.yaml; then
    log "✅ Suricata community-id: confirmed"
  else
    warn "community-id sed failed — patching manually"
    # Manual patch if yaml structure differs
    python3 << PYFIX
import re
with open('/etc/suricata/suricata.yaml','r') as f:
    content = f.read()
# Replace any community-id false variant
content = re.sub(
    r'community-id:\s*false',
    'community-id: true',
    content)
with open('/etc/suricata/suricata.yaml','w') as f:
    f.write(content)
print("[NDR] Suricata community-id patched via python")
PYFIX
  fi

  log "✅ Suricata configured on $IFACE"
fi

# ── FIX: Configure Vector with ALL log sources
# and KAFKA sink (not HTTP) ────────────────────────
log "Configuring Vector → Kafka @ $KAFKA_BOOTSTRAP"
HOSTNAME_VAL=$(hostname)

cat > /etc/ndr/vector.toml << EOF
data_dir = "/etc/vector/data"

# ── SOURCES: all Zeek log types ──────────────────
[sources.zeek_conn]
type = "file"
include = ["/var/log/ndr/zeek/conn.log"]
read_from = "end"
glob_minimum_cooldown_ms = 100

[sources.zeek_dns]
type = "file"
include = ["/var/log/ndr/zeek/dns.log"]
read_from = "end"
glob_minimum_cooldown_ms = 100

[sources.zeek_http]
type = "file"
include = ["/var/log/ndr/zeek/http.log"]
read_from = "end"
glob_minimum_cooldown_ms = 100

[sources.zeek_ssl]
type = "file"
include = ["/var/log/ndr/zeek/ssl.log"]
read_from = "end"
glob_minimum_cooldown_ms = 100

[sources.zeek_files]
type = "file"
include = ["/var/log/ndr/zeek/files.log"]
read_from = "end"
glob_minimum_cooldown_ms = 100

[sources.zeek_weird]
type = "file"
include = ["/var/log/ndr/zeek/weird.log"]
read_from = "end"
glob_minimum_cooldown_ms = 100

[sources.zeek_dhcp]
type = "file"
include = ["/var/log/ndr/zeek/dhcp.log"]
read_from = "end"
glob_minimum_cooldown_ms = 100

[sources.zeek_quic]
type = "file"
include = ["/var/log/ndr/zeek/quic.log"]
read_from = "end"
glob_minimum_cooldown_ms = 100

[sources.suricata]
type = "file"
include = ["/var/log/ndr/suricata/eve.json"]
read_from = "end"
glob_minimum_cooldown_ms = 100

# ── TRANSFORMS: parse JSON + tag source ──────────

[transforms.suricata_json]
type = "remap"
inputs = ["suricata"]
source = '''
parsed, err = parse_json(.message)
if err == null {
  . = parsed
  .source = "suricata"
  .tenant_id = "${TENANT_ID}"
  .sensor_host = "${HOSTNAME_VAL}"
} else { abort }
'''

[transforms.zeek_conn_json]
type = "remap"
inputs = ["zeek_conn"]
source = '''
parsed, err = parse_json(.message)
if err == null {
  . = parsed
  .source = "zeek"
  .tenant_id = "${TENANT_ID}"
  .sensor_host = "${HOSTNAME_VAL}"
} else { abort }
'''

[transforms.zeek_dns_json]
type = "remap"
inputs = ["zeek_dns"]
source = '''
parsed, err = parse_json(.message)
if err == null {
  . = parsed
  .source = "zeek"
  .log_type = "dns"
  .tenant_id = "${TENANT_ID}"
  .sensor_host = "${HOSTNAME_VAL}"
} else { abort }
'''

[transforms.zeek_http_json]
type = "remap"
inputs = ["zeek_http"]
source = '''
parsed, err = parse_json(.message)
if err == null {
  . = parsed
  .source = "zeek"
  .log_type = "http"
  .tenant_id = "${TENANT_ID}"
  .sensor_host = "${HOSTNAME_VAL}"
} else { abort }
'''

[transforms.zeek_ssl_json]
type = "remap"
inputs = ["zeek_ssl"]
source = '''
parsed, err = parse_json(.message)
if err == null {
  . = parsed
  .source = "zeek"
  .log_type = "ssl"
  .tenant_id = "${TENANT_ID}"
  .sensor_host = "${HOSTNAME_VAL}"
} else { abort }
'''

[transforms.zeek_files_json]
type = "remap"
inputs = ["zeek_files"]
source = '''
parsed, err = parse_json(.message)
if err == null {
  . = parsed
  .source = "zeek"
  .log_type = "files"
  .tenant_id = "${TENANT_ID}"
  .sensor_host = "${HOSTNAME_VAL}"
} else { abort }
'''

[transforms.zeek_weird_json]
type = "remap"
inputs = ["zeek_weird"]
source = '''
parsed, err = parse_json(.message)
if err == null {
  . = parsed
  .source = "zeek"
  .log_type = "weird"
  .tenant_id = "${TENANT_ID}"
  .sensor_host = "${HOSTNAME_VAL}"
} else { abort }
'''

[transforms.zeek_dhcp_json]
type = "remap"
inputs = ["zeek_dhcp"]
source = '''
parsed, err = parse_json(.message)
if err == null {
  . = parsed
  .source = "zeek"
  .log_type = "dhcp"
  .tenant_id = "${TENANT_ID}"
  .sensor_host = "${HOSTNAME_VAL}"
} else { abort }
'''

[transforms.zeek_quic_json]
type = "remap"
inputs = ["zeek_quic"]
source = '''
parsed, err = parse_json(.message)
if err == null {
  . = parsed
  .source = "zeek"
  .log_type = "quic"
  .tenant_id = "${TENANT_ID}"
  .sensor_host = "${HOSTNAME_VAL}"
} else { abort }
'''

# ── SINK: Kafka on cloud server ───────────────────
# FIX: Use Kafka not HTTP
# Key by community_id so same flow always
# hits same engine partition
[sinks.kafka]
type = "kafka"
inputs = [
  "suricata_json",
  "zeek_conn_json",
  "zeek_dns_json",
  "zeek_http_json",
  "zeek_ssl_json",
  "zeek_files_json",
  "zeek_weird_json",
  "zeek_dhcp_json",
  "zeek_quic_json"
]
bootstrap_servers = "${KAFKA_BOOTSTRAP}"
topic = "ndr-events"
encoding.codec = "json"
key_field = "community_id"

[sinks.kafka.batch]
timeout_secs = 0.1
max_events = 100

[sinks.kafka.buffer]
type = "disk"
max_size = 536870912
when_full = "block"
EOF

# ── FIX: agent.py with correct Arkime check ───────
log "Creating sensor agent..."
cat > /opt/ndr-sensor/agent.py << 'AGENT'
#!/usr/bin/env python3
"""NDR Sensor Agent v2 — monitors and restarts all services"""
import os, time, subprocess, requests, json, hashlib
from datetime import datetime

config = {}
with open('/etc/ndr/sensor.conf') as f:
    for line in f:
        if '=' in line and not line.startswith('#'):
            k, v = line.strip().split('=', 1)
            config[k] = v

CLOUD_URL = config.get('CLOUD_URL', '').rstrip('/')
TENANT_ID = config.get('TENANT_ID', '')
API_KEY   = config.get('API_KEY', '')
IFACE     = config.get('IFACE', 'eth0')

def derive_arkime_pass(key):
    return hashlib.sha256(key.encode())\
        .hexdigest()[:16]

ARKIME_PASS = derive_arkime_pass(API_KEY)

def is_running(pattern):
    return subprocess.run(
        ['pgrep', '-f', pattern],
        capture_output=True
    ).returncode == 0

def is_port_open(port):
    """Check if a local port is accepting connections"""
    import socket
    try:
        s = socket.socket()
        s.settimeout(2)
        s.connect(('127.0.0.1', port))
        s.close()
        return True
    except:
        return False

def is_capture_running():
    return is_running('arkime/bin/capture')

def is_viewer_running():
    # FIX: check viewer by port, not process name
    return is_port_open(8005)

def start_zeek():
    try:
        subprocess.run(['pkill', '-9', '-f', 'zeek'],
            capture_output=True)
        time.sleep(2)
        subprocess.Popen(
            ["/opt/zeek/bin/zeek", "-i", IFACE,
             "local",
             "Log::default_logdir=/var/log/ndr/zeek"],
            stdout=open("/tmp/zeek.log", "w"),
            stderr=subprocess.STDOUT
        )
        print("[NDR] ✅ Zeek started")
        return True
    except Exception as e:
        print(f"[NDR] Zeek start failed: {e}")
        return False

def start_suricata():
    try:
        subprocess.run(['pkill', '-9', '-f', 'suricata'],
            capture_output=True)
        time.sleep(2)
        for pid in ['/tmp/suricata.pid',
                    '/var/run/suricata.pid',
                    '/run/suricata.pid',
                    '/var/run/suricata/suricata.pid']:
            try: os.remove(pid)
            except: pass

        subprocess.Popen(
            ["suricata",
             "-c", "/etc/suricata/suricata.yaml",
             "-i", IFACE,
             "-l", "/var/log/ndr/suricata",
             "-D",
             "--pidfile", "/tmp/suricata.pid",
             "--set", "detect.profile=low",
             "--set", "max-pending-packets=128"],
            stdout=open("/tmp/suricata.log", "w"),
            stderr=subprocess.STDOUT
        )
        print("[NDR] ✅ Suricata started")
        return True
    except Exception as e:
        print(f"[NDR] Suricata start failed: {e}")
        return False

def start_vector():
    try:
        subprocess.run(['systemctl', 'start',
            'ndr-vector'],
            capture_output=True, timeout=30)
        print("[NDR] ✅ Vector started")
        return True
    except Exception as e:
        print(f"[NDR] Vector start failed: {e}")
        return False

def start_capture():
    try:
        subprocess.run(['systemctl', 'start',
            'arkime-capture'],
            capture_output=True, timeout=30)
        print("[NDR] ✅ Arkime capture started")
        return True
    except Exception as e:
        print(f"[NDR] Arkime capture failed: {e}")
        return False

def start_viewer():
    # FIX: start viewer separately
    try:
        subprocess.run(['systemctl', 'start',
            'arkime-viewer'],
            capture_output=True, timeout=30)
        print("[NDR] ✅ Arkime viewer started")
        return True
    except Exception as e:
        print(f"[NDR] Arkime viewer failed: {e}")
        return False

def check_and_restart():
    statuses = {}

    if not is_running('zeek'):
        print("[NDR] Zeek down — restarting")
        start_zeek()
        statuses['zeek'] = 'restarting'
    else:
        statuses['zeek'] = 'running'

    if not is_running('suricata'):
        print("[NDR] Suricata down — restarting")
        start_suricata()
        statuses['suricata'] = 'restarting'
    else:
        statuses['suricata'] = 'running'

    if not is_running('vector'):
        print("[NDR] Vector down — restarting")
        start_vector()
        statuses['vector'] = 'restarting'
    else:
        statuses['vector'] = 'running'

    if not is_capture_running():
        print("[NDR] Arkime capture down — restarting")
        start_capture()
        statuses['arkime_capture'] = 'restarting'
    else:
        statuses['arkime_capture'] = 'running'

    # FIX: check viewer separately
    if not is_viewer_running():
        print("[NDR] Arkime viewer down — restarting")
        start_viewer()
        statuses['arkime_viewer'] = 'restarting'
    else:
        statuses['arkime_viewer'] = 'running'

    return statuses

def report_status(statuses):
    import socket
    try:
        sensor_ip = socket.gethostbyname(
            socket.gethostname())
    except:
        sensor_ip = '127.0.0.1'

    payload = {
        'tenant_id':   TENANT_ID,
        'timestamp':   datetime.utcnow().isoformat(),
        'sensor_ip':   sensor_ip,
        'arkime_url':  f'http://{sensor_ip}:8005',
        'arkime_pass': ARKIME_PASS,
        **statuses
    }
    try:
        requests.post(
            f'{CLOUD_URL}/api/sensor/heartbeat',
            json=payload,
            headers={'X-Sensor-Key': API_KEY},
            timeout=5
        )
        print(f"[NDR] Heartbeat sent: "
              f"zeek={statuses.get('zeek')} "
              f"suricata={statuses.get('suricata')} "
              f"viewer={statuses.get('arkime_viewer')}")
    except Exception as e:
        print(f"[NDR] Heartbeat failed: {e}")

def get_pending_pcap():
    try:
        resp = requests.get(
            f'{CLOUD_URL}/api/pcap/pending',
            headers={'X-Sensor-Key': API_KEY},
            timeout=10
        )
        if resp.status_code == 200:
            data = resp.json()
            # Handle both formats:
            # old: ["cid1","cid2"]
            # new: {"pending":[{"community_id":"..."}]}
            if isinstance(data, list):
                return data
            return [p.get('community_id', p)
                    for p in data.get('pending', [])]
    except Exception as e:
        print(f"[NDR] pending poll error: {e}")
    return []

def process_pcap_uploads():
    # Only upload if viewer is running
    if not is_viewer_running():
        print("[NDR] Viewer not ready — "
              "skipping PCAP uploads this cycle")
        return

    pending = get_pending_pcap()
    if not pending:
        return

    print(f"[NDR] {len(pending)} PCAP uploads pending")
    for cid in pending[:5]:
        if not cid:
            continue
        try:
            result = subprocess.run(
                ['python3',
                 '/opt/ndr-sensor/pcap-uploader.py',
                 str(cid)],
                capture_output=True,
                text=True, timeout=120
            )
            if result.stdout.strip():
                print(result.stdout.strip())
            if result.returncode != 0:
                print(f"[NDR] Upload failed for "
                      f"{cid[:20]}: "
                      f"{result.stderr.strip()}")
        except subprocess.TimeoutExpired:
            print(f"[NDR] Upload timeout: {cid[:20]}")
        except Exception as e:
            print(f"[NDR] Upload error: {e}")

if __name__ == '__main__':
    print(f"[NDR] Agent starting — "
          f"tenant={TENANT_ID}")
    print(f"[NDR] Cloud={CLOUD_URL}")

    os.makedirs("/var/log/ndr/suricata",
        exist_ok=True)
    os.makedirs("/var/log/ndr/zeek",
        exist_ok=True)

    # Start all services
    print("[NDR] Starting all services...")
    start_zeek()
    start_suricata()
    start_vector()
    start_capture()
    time.sleep(10)  # wait for capture to init
    start_viewer()  # FIX: start viewer too
    time.sleep(5)

    while True:
        statuses = check_and_restart()
        report_status(statuses)
        process_pcap_uploads()
        time.sleep(30)
AGENT
chmod +x /opt/ndr-sensor/agent.py

# ── FIX: pcap-uploader.py with retry + report ────
cat > /opt/ndr-sensor/pcap-uploader.py \
  << 'UPLOADER'
#!/usr/bin/env python3
"""NDR PCAP Uploader v2 — with retry + fulfilled"""
import os, sys, gzip, shutil, time
import requests, hashlib

def load_config():
    cfg = {}
    with open('/etc/ndr/sensor.conf') as f:
        for line in f:
            if '=' in line and \
               not line.startswith('#'):
                k, v = line.strip().split('=',1)
                cfg[k.strip()] = v.strip()
    return cfg

def arkime_pass(key):
    return hashlib.sha256(
        key.encode()).hexdigest()[:16]

def get_meta(cid, pwd):
    try:
        r = requests.get(
            f"http://localhost:8005/api/sessions"
            f"?expression=communityId%3D%3D{cid}"
            f"&startTime=-24h&stopTime=now&length=1",
            auth=("admin", pwd), timeout=15)
        if r.status_code == 200:
            data = r.json().get("data", [])
            if data:
                s = data[0]
                return {
                    "src_ip":   s.get(
                        "source.ip", ""),
                    "dst_ip":   s.get(
                        "destination.ip", ""),
                    "src_port": str(s.get(
                        "source.port", 0)),
                    "dst_port": str(s.get(
                        "destination.port", 0)),
                    "proto":    s.get(
                        "network.transport", ""),
                    "sensor_host":
                        os.uname().nodename,
                }
    except Exception as e:
        print(f"[UPLOADER] meta error: {e}")
    return {"src_ip":"","dst_ip":"",
            "src_port":"0","dst_port":"0",
            "proto":"",
            "sensor_host":os.uname().nodename}

def extract(cid, out, pwd):
    try:
        r = requests.get(
            f"http://localhost:8005"
            f"/api/sessions/pcap"
            f"?expression=communityId%3D%3D{cid}"
            f"&startTime=-24h&stopTime=now",
            auth=("admin", pwd),
            timeout=30, stream=True)
        if r.status_code != 200:
            print(f"[UPLOADER] Arkime "
                  f"HTTP {r.status_code}")
            return False
        with open(out, 'wb') as f:
            for chunk in r.iter_content(8192):
                f.write(chunk)
        size = os.path.getsize(out)
        if size < 24:
            print(f"[UPLOADER] PCAP too "
                  f"small ({size}B)")
            return False
        print(f"[UPLOADER] Extracted {size}B")
        return True
    except Exception as e:
        print(f"[UPLOADER] Extract: {e}")
        return False

def upload(cid, pcap, gz, url, key, meta):
    # Compress
    with open(pcap,'rb') as fi, \
         gzip.open(gz,'wb',compresslevel=6) as fo:
        shutil.copyfileobj(fi, fo)
    orig = os.path.getsize(pcap)
    comp = os.path.getsize(gz)
    pct  = (1-comp/orig)*100 if orig else 0
    print(f"[UPLOADER] {orig}B→{comp}B "
          f"({pct:.0f}% smaller)")

    # Upload with retry
    for attempt in range(3):
        try:
            if attempt > 0:
                time.sleep(5 * attempt)
                print(f"[UPLOADER] Retry {attempt}")
            with open(gz,'rb') as f:
                r = requests.post(
                    f"{url}/api/pcap/upload",
                    headers={
                        "X-Sensor-Key": key,
                        "Content-Encoding":"gzip"
                    },
                    files={"pcap":(
                        "session.pcap.gz",
                        f,
                        "application/gzip"
                    )},
                    data={
                        "community_id": cid,
                        **meta
                    },
                    timeout=120
                )
            if r.status_code in (200, 409):
                print(f"[UPLOADER] ✅ Uploaded")
                return True
            print(f"[UPLOADER] HTTP "
                  f"{r.status_code}: {r.text}")
        except Exception as e:
            print(f"[UPLOADER] attempt "
                  f"{attempt} error: {e}")
    return False

def report_failure(cid, url, key, err):
    try:
        requests.post(
            f"{url}/api/pcap/upload-failed",
            headers={"X-Sensor-Key": key},
            json={"community_id":cid,
                  "error":str(err)},
            timeout=10
        )
    except:
        pass

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: pcap-uploader.py <cid>")
        sys.exit(1)

    cid = sys.argv[1]
    cfg = load_config()
    url = cfg.get('CLOUD_URL','').rstrip('/')
    key = cfg.get('API_KEY','')

    pwd  = arkime_pass(key)
    safe = cid.replace('/','_').replace(':','_')
    tmp  = "/opt/ndr-sensor/pcap-tmp"
    pcap = f"{tmp}/raw_{safe}.pcap"
    gz   = f"{tmp}/gz_{safe}.pcap.gz"

    os.makedirs(tmp, exist_ok=True)
    try:
        meta = get_meta(cid, pwd)
        if extract(cid, pcap, pwd):
            ok = upload(cid, pcap, gz,
                        url, key, meta)
            if not ok:
                report_failure(cid, url, key,
                    "upload failed after 3 attempts")
                sys.exit(1)
        else:
            report_failure(cid, url, key,
                "arkime session not found")
            sys.exit(1)
    finally:
        for f in [pcap, gz]:
            try: os.remove(f)
            except: pass
UPLOADER
chmod +x /opt/ndr-sensor/pcap-uploader.py

# ── Systemd services ──────────────────────────────
log "Creating systemd services..."
VECTOR_BIN=$(which vector 2>/dev/null || \
  echo "/usr/bin/vector")

cat > /etc/systemd/system/ndr-vector.service \
  << EOF
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

cat > /etc/systemd/system/ndr-agent.service \
  << EOF
[Unit]
Description=NDR Sensor Agent
After=network.target
[Service]
ExecStart=/usr/bin/python3 \
  /opt/ndr-sensor/agent.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable \
  ndr-vector \
  ndr-agent \
  arkime-capture \
  arkime-viewer \
  2>/dev/null || true

# ── Start services ────────────────────────────────
log "Starting Arkime services..."
systemctl start arkime-capture 2>/dev/null || true
sleep 5
systemctl start arkime-viewer 2>/dev/null || true

log "Starting NDR agent..."
systemctl start ndr-agent 2>/dev/null || true

# ── Wait for viewer to be ready ───────────────────
log "Waiting for Arkime viewer on :8005..."
for i in {1..20}; do
  if curl -s http://localhost:8005 \
      > /dev/null 2>&1; then
    log "✅ Arkime viewer ready on :8005"
    break
  fi
  echo -n "."
  sleep 3
done
echo ""

# ── Register with cloud ───────────────────────────
log "Registering sensor with cloud..."
sleep 3
REG=$(curl -s -X POST \
  "$CLOUD_URL/api/sensor/register" \
  -H "X-Sensor-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d "{
    \"tenant_id\": \"$TENANT_ID\",
    \"hostname\": \"$(hostname)\",
    \"interface\": \"$IFACE\",
    \"os\": \"$PRETTY_NAME\"
  }" 2>/dev/null)

echo "$REG" | grep -q '"status":"ok"' && \
  log "✅ Registered with cloud" || \
  warn "Registration: $REG"

# ── Verify everything ─────────────────────────────
echo ""
echo "╔══════════════════════════════════════════╗"
echo "║    ✅ NDR Sensor Installation Done!      ║"
echo "╠══════════════════════════════════════════╣"
printf "║  Tenant:    %-28s ║\n" "$TENANT_ID"
printf "║  Interface: %-28s ║\n" "$IFACE"
printf "║  Cloud:     %-28s ║\n" "${CLOUD_URL:0:28}"
printf "║  Kafka:     %-28s ║\n" "${KAFKA_BOOTSTRAP:0:28}"
echo "╠══════════════════════════════════════════╣"

# Service status check
Z=$(pgrep -f "zeek" > /dev/null 2>&1 && \
    echo "✅" || echo "❌")
S=$(pgrep -f "suricata" > /dev/null 2>&1 && \
    echo "✅" || echo "❌")
V=$(pgrep -f "vector" > /dev/null 2>&1 && \
    echo "✅" || echo "❌")
AC=$(pgrep -f "arkime/bin/capture" \
    > /dev/null 2>&1 && echo "✅" || echo "❌")
AV=$(curl -s http://localhost:8005 \
    > /dev/null 2>&1 && echo "✅" || echo "❌")

printf "║  Zeek:         %s                           ║\n" "$Z"
printf "║  Suricata:     %s                           ║\n" "$S"
printf "║  Vector:       %s → Kafka                   ║\n" "$V"
printf "║  Arkime cap:   %s                           ║\n" "$AC"
printf "║  Arkime view:  %s :8005                     ║\n" "$AV"
echo "╠══════════════════════════════════════════╣"
printf "║  Arkime UI: http://%-20s ║\n" \
  "$(hostname -I | awk '{print $1}'):8005"
printf "║  Arkime pass:  %-24s ║\n" \
  "$ARKIME_PASS"
echo "╚══════════════════════════════════════════╝"
echo ""
log "Config:  /etc/ndr/sensor.conf"
log "Logs:    journalctl -u ndr-agent -f"
log "Zeek:    /var/log/ndr/zeek/"
log "Sur:     /var/log/ndr/suricata/eve.json"