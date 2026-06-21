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

log "Installing tshark (>= 3.4 required for community-id filter) and zstd..."
# communityid.id dissector requires tshark >= 3.4.0 AND --enable-protocol communityid.
# Distro default apt is often frozen on 3.2.x.
# Check existing version first — upgrade only if needed.

DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
  software-properties-common zstd > /dev/null 2>&1 || true

# Helper: returns tshark major.minor as integers
tshark_ver_ok() {
  local MAJOR MINOR
  MAJOR=$(tshark --version 2>/dev/null | grep -oP '(?<=TShark \(Wireshark\) )\d+' || echo 0)
  MINOR=$(tshark --version 2>/dev/null | grep -oP '(?<=TShark \(Wireshark\) \d\.)\d+' || echo 0)
  # returns 0 (true) if >= 3.4
  [ "${MAJOR:-0}" -gt 3 ] || \
    { [ "${MAJOR:-0}" -eq 3 ] && [ "${MINOR:-0}" -ge 4 ]; }
}

if tshark_ver_ok; then
  log "  ✅ tshark already >= 3.4: $(tshark --version 2>/dev/null | head -1) — skipping upgrade"
else
  log "  tshark too old ($(tshark --version 2>/dev/null | head -1 || echo 'not installed')) — upgrading..."

  # ── Option A: Wireshark PPA ─────────────────────────────────────────────
  log "  Trying Wireshark PPA (Option A)..."
  if add-apt-repository -y ppa:wireshark-dev/stable > /dev/null 2>&1; then
    apt-get update -qq > /dev/null 2>&1 || true
    DEBIAN_FRONTEND=noninteractive \
      apt-get install -y -qq tshark wireshark-common > /dev/null 2>&1 || true
  fi

  if tshark_ver_ok; then
    log "  ✅ tshark upgraded via PPA: $(tshark --version 2>/dev/null | head -1)"
  else
    # ── Option B: snap fallback ──────────────────────────────────────────
    log "  PPA insufficient — installing via snap (Option B)..."
    apt-get install -y -qq snapd > /dev/null 2>&1 || true
    snap install wireshark > /dev/null 2>&1 || true
    ln -sf /snap/bin/tshark /usr/local/bin/tshark 2>/dev/null || true
    if tshark_ver_ok; then
      log "  ✅ tshark upgraded via snap: $(tshark --version 2>/dev/null | head -1)"
    else
      warn "  tshark upgrade failed — communityid filter unavailable, will use raw copy"
    fi
  fi
fi

log "tshark: $(tshark --version 2>/dev/null | head -1 || echo 'not installed')"
log "zstd:   $(zstd --version 2>/dev/null | head -1 || echo 'not installed')"

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
simpleCompression=none
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

# ── Suppress known false-positive Suricata SIDs ───────
# These rules fire on legitimate NDR sensor traffic and
# would otherwise generate constant noise.
log "Writing Suricata false-positive suppressions..."
THRESHOLD_FILE="/etc/suricata/threshold.conf"
touch "$THRESHOLD_FILE"

# Known false positives — add new SIDs here as needed
SUPPRESS_SIDS=(
  2066052   # ET INFO ngrok-free.dev in TLS SNI — sensor heartbeat to cloud
  2066057   # Related ngrok tunneling rule
)

for SID in "${SUPPRESS_SIDS[@]}"; do
  LINE="suppress gen_id 1, sig_id ${SID}"
  if ! grep -qF "$LINE" "$THRESHOLD_FILE" 2>/dev/null; then
    echo "$LINE" >> "$THRESHOLD_FILE"
    log "  ✅ Suppressed SID $SID"
  else
    log "  SID $SID already suppressed"
  fi
done

# Configure Suricata to load the threshold file
if grep -q "threshold-file:" /etc/suricata/suricata.yaml 2>/dev/null; then
  sed -i "s|threshold-file:.*|threshold-file: $THRESHOLD_FILE|g" \
    /etc/suricata/suricata.yaml
else
  echo "threshold-file: $THRESHOLD_FILE" >> /etc/suricata/suricata.yaml
fi
log "✅ Suricata suppressions written to $THRESHOLD_FILE"

# ── Configure Vector with ALL log sources + HTTP sink ─
log "Configuring Vector → HTTP @ $CLOUD_URL/api/ingest"
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

# ── SINK: HTTP POST to cloud /api/ingest ─────────
# Works through ngrok, reverse proxy, or direct IP.
# Sends NDJSON batches; ingest endpoint handles it.
[sinks.cloud_http]
type = "http"
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
uri = "${CLOUD_URL}/api/ingest"
method = "post"
encoding.codec = "json"
framing.method = "newline_delimited"

[sinks.cloud_http.batch]
max_events = 100
timeout_secs = 1

[sinks.cloud_http.request]
retry_attempts = 5
retry_initial_backoff_secs = 1
retry_max_duration_secs = 30
timeout_secs = 10
headers.X-Sensor-Key = "${API_KEY}"
headers.Content-Type = "application/x-ndjson"

[sinks.cloud_http.buffer]
type = "disk"
max_size = 536870912
when_full = "drop_newest"
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

# Prevents check_and_restart from undoing an intentional stop command
MANUALLY_STOPPED = False

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

def check_and_restart():
    statuses = {}

    if MANUALLY_STOPPED:
        # Services were intentionally stopped — report stopped, do not restart
        statuses['zeek']          = 'stopped'
        statuses['suricata']      = 'stopped'
        statuses['vector']        = 'stopped'
        statuses['arkime_capture'] = 'stopped'
        return statuses

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
              f"capture={statuses.get('arkime_capture')}")
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
            items = data.get('pending', [])
            result = []
            for p in items:
                if isinstance(p, str):
                    result.append(p)
                elif isinstance(p, dict):
                    result.append(p.get('community_id', ''))
            return [x for x in result if x]
    except Exception as e:
        print(f"[NDR] pending poll error: {e}")
    return []

def process_pcap_uploads():
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

def execute_command(cmd):
    """Execute a received command string. Called by do_checkin() and
    the legacy check_and_execute_command() for backward compat."""
    global MANUALLY_STOPPED
    print(f"[NDR] *** COMMAND RECEIVED: {cmd} ***")
    if cmd == 'stop':
        MANUALLY_STOPPED = True
        subprocess.run(['pkill', '-9', '-f', 'zeek'], capture_output=True)
        subprocess.run(['pkill', '-9', '-f', 'suricata'], capture_output=True)
        subprocess.run(['systemctl', 'stop', 'ndr-vector'], capture_output=True)
        subprocess.run(['pkill', '-9', '-f', 'vector --config'], capture_output=True)
        subprocess.run(['pkill', '-9', '-f', '/usr/local/bin/vector'], capture_output=True)
        subprocess.run(['systemctl', 'stop', 'arkime-capture'], capture_output=True)
        subprocess.run(['pkill', '-9', '-f', 'arkime-capture'], capture_output=True)
        print("[NDR] All services stopped")
    elif cmd == 'start':
        MANUALLY_STOPPED = False
        start_zeek()
        start_suricata()
        start_vector()
        start_capture()
        print("[NDR] All services started")
    elif cmd == 'restart':
        MANUALLY_STOPPED = False
        subprocess.run(['systemctl', 'restart', 'zeek'], capture_output=True)
        subprocess.run(['systemctl', 'restart', 'suricata'], capture_output=True)
        subprocess.run(['pkill', '-f', 'vector'], capture_output=True)
        time.sleep(2)
        start_vector()
        subprocess.run(['pkill', '-f', 'arkime-capture'], capture_output=True)
        time.sleep(2)
        start_capture()
        print("[NDR] All services restarted")
    elif cmd.startswith('suppress_sid:'):
        # Formats:
        #   suppress_sid:2066052               → blanket SID suppress
        #   suppress_sid:2066052:by_dst:1.2.3.4 → suppress SID to specific dst IP
        #   suppress_sid:2066052:by_src:1.2.3.4 → suppress SID from specific src IP
        parts = cmd.split(':')
        sid = parts[1].strip()
        threshold_file = '/etc/suricata/threshold.conf'
        if len(parts) >= 4:
            track_type = parts[2].strip()
            track_ip   = parts[3].strip()
            track_kw   = 'by_dst' if track_type == 'by_dst' else 'by_src'
            suppress_line = (
                f'suppress gen_id 1, sig_id {sid}, '
                f'track {track_kw}, ip {track_ip}\n'
            )
        else:
            suppress_line = f'suppress gen_id 1, sig_id {sid}\n'
        try:
            with open(threshold_file, 'r') as f:
                existing = f.read()
        except FileNotFoundError:
            existing = ''
        if suppress_line.strip() not in existing:
            with open(threshold_file, 'a') as f:
                f.write(suppress_line)
            print(f"[NDR] Suppressed SID {sid} ({suppress_line.strip()})")
            reloaded = False
            try:
                pid_out = subprocess.run(['pidof', 'suricata'], capture_output=True, text=True)
                pid = pid_out.stdout.strip().split()[0]
                subprocess.run(['kill', '-USR2', pid], check=True)
                reloaded = True
            except Exception:
                pass
            if not reloaded:
                subprocess.run(['suricatasc', '-c', 'reload-rules'], capture_output=True)
        else:
            print(f"[NDR] SID {sid} already suppressed")
    else:
        print(f"[NDR] Unknown command ignored: {cmd}")

def check_and_execute_command():
    """Legacy single-poll command handler — kept for backward compat.
    New sensors use do_checkin() which combines this with heartbeat
    and pcap pending into one request."""
    try:
        resp = requests.get(
            f'{CLOUD_URL}/api/sensor/command',
            headers={'X-Sensor-Key': API_KEY},
            timeout=5
        )
        if resp.status_code != 200:
            return
        cmd = resp.json().get('command', '').strip()
        if cmd:
            execute_command(cmd)
    except Exception as e:
        print(f"[NDR] Command poll error: {e}")

def do_checkin():
    """Single combined check-in — replaces the old 3 separate polls
    (heartbeat, command, pcap pending) with one request.
    Cuts per-sensor HTTP volume by ~3x."""
    import socket
    try:
        sensor_ip = socket.gethostbyname(socket.gethostname())
    except Exception:
        sensor_ip = '127.0.0.1'

    statuses = check_and_restart()

    payload = {
        'tenant_id':      TENANT_ID,
        'sensor_ip':      sensor_ip,
        'arkime_url':     f'http://{sensor_ip}:8005',
        'arkime_pass':    ARKIME_PASS,
        'zeek':           statuses.get('zeek', 'unknown'),
        'suricata':       statuses.get('suricata', 'unknown'),
        'vector':         statuses.get('vector', 'unknown'),
        'arkime_capture': statuses.get('arkime_capture', 'unknown'),
        'arkime_viewer':  statuses.get('arkime_viewer', 'unknown'),
    }

    try:
        resp = requests.post(
            f'{CLOUD_URL}/api/sensor/checkin',
            json=payload,
            headers={'X-Sensor-Key': API_KEY},
            timeout=10
        )
        if resp.status_code != 200:
            print(f"[NDR] Checkin HTTP {resp.status_code}")
            return

        data = resp.json()
        print(f"[NDR] Checkin ok — "
              f"zeek={payload['zeek']} "
              f"suricata={payload['suricata']} "
              f"arkime={payload['arkime_capture']}")

        cmd = data.get('command', '').strip()
        if cmd:
            execute_command(cmd)

        pending = data.get('pcap_pending', [])
        if pending:
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
                    print(f"[NDR] PCAP upload error: {e}")

    except Exception as e:
        print(f"[NDR] Checkin failed: {e}")

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

    while True:
        do_checkin()   # heartbeat + command + pcap pending in one call
        time.sleep(10)
AGENT
chmod +x /opt/ndr-sensor/agent.py

# ── pcap-uploader.py v3 — OpenSearch direct + tshark ─
cat > /opt/ndr-sensor/pcap-uploader.py \
  << 'UPLOADER'
#!/usr/bin/env python3
"""
NDR PCAP Uploader v3
- Queries OpenSearch directly (no viewer needed)
- Extracts from raw Arkime .pcap files using tshark
- Falls back to mergecap / raw copy
- Gzip compressed upload with 3 retries
"""
import os, sys, gzip, shutil, time, json
import requests, hashlib, subprocess
from datetime import datetime

def load_config():
    cfg = {}
    with open('/etc/ndr/sensor.conf') as f:
        for line in f:
            if '=' in line and \
               not line.startswith('#'):
                k,v = line.strip().split('=',1)
                cfg[k.strip()] = v.strip()
    return cfg

def sha16(key):
    return hashlib.sha256(
        key.encode()).hexdigest()[:16]

def find_session_in_opensearch(cid):
    try:
        url = "http://localhost:9200/" \
              "arkime_sessions3-*/_search"
        query = {
            "query": {
                "term": {
                    "network.community_id": cid
                }
            },
            "_source": [
                "rootId","packetPos","packetLen",
                "fileId","source.ip",
                "destination.ip","source.port",
                "destination.port",
                "network.transport"
            ],
            "size": 10
        }
        r = requests.post(url,
            json=query, timeout=15)
        if r.status_code != 200:
            print(f"[UPLOADER] OpenSearch "
                  f"HTTP {r.status_code}")
            return None, None
        hits = r.json().get(
            'hits',{}).get('hits',[])
        if not hits:
            print(f"[UPLOADER] No session "
                  f"for {cid[:20]}")
            return None, None
        src = hits[0].get('_source', {})
        file_ids = src.get('fileId',
            src.get('fileIds', []))
        # OpenSearch returns ECS nested objects:
        # {"source":{"ip":"x"},"destination":{...}}
        # Use .get(key,{}).get(subkey) not dotted str
        meta = {
            "src_ip":    src.get('source',{}).get(
                             'ip',''),
            "dst_ip":    src.get('destination',{}).get(
                             'ip',''),
            "src_port":  str(src.get('source',{}).get(
                             'port', 0)),
            "dst_port":  str(src.get('destination',{}).get(
                             'port', 0)),
            "proto":     src.get('network',{}).get(
                             'transport',''),
            "sensor_host": os.uname().nodename,
            "file_ids":  file_ids,
            "root_id":   src.get('rootId',''),
        }
        print(f"[UPLOADER] Found session: "
              f"{meta['src_ip']}→"
              f"{meta['dst_ip']} "
              f"files={file_ids}")
        return meta, hits
    except Exception as e:
        print(f"[UPLOADER] OpenSearch error: {e}")
        return None, None

def get_arkime_files(file_ids):
    if not file_ids:
        return []
    try:
        url = "http://localhost:9200/" \
              "arkime_files/_search"
        query = {
            "query": {"terms": {"num": file_ids}},
            "_source": ["name","num"],
            "size": 20
        }
        r = requests.post(url,
            json=query, timeout=10)
        if r.status_code != 200:
            return []
        hits = r.json().get(
            'hits',{}).get('hits',[])
        files = []
        for h in hits:
            path = h.get('_source',{}).get(
                'name','')
            if path and os.path.exists(path):
                files.append(path)
                print(f"[UPLOADER] "
                      f"pcap file: {path}")
        return files
    except Exception as e:
        print(f"[UPLOADER] File lookup: {e}")
        return []

def decompress_if_needed(path, tmp_dir):
    """Decompress .pcap.zst to plain .pcap for tshark.
    Skips files modified in the last 30s (still being written by Arkime)."""
    if path.endswith('.pcap.zst') or path.endswith('.zst'):
        # Skip active files Arkime is still writing
        age = time.time() - os.path.getmtime(path)
        if age < 30:
            print(f"[UPLOADER] skipping active file "
                  f"(modified {age:.0f}s ago): "
                  f"{os.path.basename(path)}")
            return None
        out = os.path.join(tmp_dir,
            os.path.basename(path).replace('.zst',''))
        if not os.path.exists(out):
            result = subprocess.run(
                ['zstd', '-d', path, '-o', out, '-f'],
                capture_output=True, timeout=60)
            if result.returncode != 0:
                print(f"[UPLOADER] zstd failed: "
                      f"{result.stderr.decode()[:100]}")
                return None
        return out
    return path

def extract_with_tshark(pcap_files, cid, output):
    if not pcap_files:
        return False
    tmp_dir = os.path.dirname(output)
    decompressed = []
    for f in pcap_files:
        d = decompress_if_needed(f, tmp_dir)
        if d:
            decompressed.append(d)
    if not decompressed:
        return False
    input_args = []
    for f in decompressed:
        input_args += ['-r', f]
    # --enable-protocol communityid is required even on tshark >= 3.4
    # because the dissector ships disabled by default
    cmd = (['tshark',
            '--enable-protocol', 'communityid']
           + input_args +
           ['-Y',
            f'communityid.id == "{cid}"',
            '-w', output, '-F', 'pcap'])
    try:
        subprocess.run(cmd,
            capture_output=True, timeout=60)
        if (os.path.exists(output) and
                os.path.getsize(output) >= 24):
            print(f"[UPLOADER] tshark "
                  f"{os.path.getsize(output)}B")
            return True
    except FileNotFoundError:
        pass
    except Exception as e:
        print(f"[UPLOADER] tshark: {e}")
    return False

def extract_with_mergecap(pcap_files, output):
    if not pcap_files:
        return False
    tmp_dir = os.path.dirname(output)
    decompressed = []
    for f in pcap_files:
        d = decompress_if_needed(f, tmp_dir)
        if d:
            decompressed.append(d)
    if not decompressed:
        return False
    if len(decompressed) == 1:
        shutil.copy2(decompressed[0], output)
        return os.path.getsize(output) >= 24
    try:
        cmd = (['mergecap', '-w', output]
               + decompressed)
        subprocess.run(cmd,
            capture_output=True, timeout=60)
        if (os.path.exists(output) and
                os.path.getsize(output) >= 24):
            print(f"[UPLOADER] mergecap "
                  f"{os.path.getsize(output)}B")
            return True
    except FileNotFoundError:
        pass
    except Exception as e:
        print(f"[UPLOADER] mergecap: {e}")
    return False

def extract_raw_copy(pcap_files, output):
    if not pcap_files:
        return False
    shutil.copy2(pcap_files[0], output)
    size = os.path.getsize(output) \
        if os.path.exists(output) else 0
    if size >= 24:
        print(f"[UPLOADER] raw copy {size}B")
        return True
    return False

def compress_and_upload(
        cid, pcap, url, key, meta):
    gz = pcap + '.gz'
    try:
        with open(pcap,'rb') as fi, \
             gzip.open(gz,'wb',
                       compresslevel=6) as fo:
            shutil.copyfileobj(fi, fo)
        orig = os.path.getsize(pcap)
        comp = os.path.getsize(gz)
        pct = (1-comp/orig)*100 if orig else 0
        print(f"[UPLOADER] compressed "
              f"{orig}→{comp}B "
              f"({pct:.0f}% smaller)")
        for attempt in range(3):
            if attempt > 0:
                time.sleep(5 * attempt)
                print(f"[UPLOADER] retry "
                      f"{attempt}/2")
            try:
                with open(gz,'rb') as f:
                    r = requests.post(
                        f"{url}/api/pcap/upload",
                        headers={
                            "X-Sensor-Key": key,
                        },
                        files={"pcap":(
                            "session.pcap.gz",
                            f,
                            "application/gzip"
                        )},
                        data={
                            "community_id": cid,
                            "src_ip":   meta.get(
                                "src_ip",""),
                            "dst_ip":   meta.get(
                                "dst_ip",""),
                            "src_port": meta.get(
                                "src_port","0"),
                            "dst_port": meta.get(
                                "dst_port","0"),
                            "proto":    meta.get(
                                "proto",""),
                            "sensor_host": meta.get(
                                "sensor_host",""),
                        },
                        timeout=120
                    )
                if r.status_code == 409:
                    print("[UPLOADER] ✅ uploaded "
                          "(already exists)")
                    return True
                if r.status_code == 200:
                    try:
                        body = r.json()
                    except Exception:
                        body = {}
                    if body.get('status') \
                            == 'error':
                        print(f"[UPLOADER] "
                              f"server rejected:"
                              f" {body.get('message','?')}")
                        continue
                    sid = body.get(
                        'session_id','?')
                    print(f"[UPLOADER] "
                          f"✅ uploaded "
                          f"sid={sid[:8]}")
                    return True
                print(f"[UPLOADER] HTTP "
                      f"{r.status_code}: "
                      f"{r.text[:100]}")
            except Exception as e:
                print(f"[UPLOADER] upload: {e}")
        return False
    finally:
        try: os.remove(gz)
        except: pass

def report_failure(cid, url, key, err):
    try:
        requests.post(
            f"{url}/api/pcap/upload-failed",
            headers={"X-Sensor-Key": key},
            json={"community_id": cid,
                  "error": str(err)},
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
    pwd = sha16(key)

    safe = cid.replace(
        '/','_').replace(':','_')
    tmp  = "/opt/ndr-sensor/pcap-tmp"
    os.makedirs(tmp, exist_ok=True)
    raw_out = f"{tmp}/raw_{safe}.pcap"

    try:
        print(f"[UPLOADER] Processing: "
              f"{cid[:30]}")

        meta, os_hits = \
            find_session_in_opensearch(cid)

        if not meta:
            # Arkime hasn't indexed this session
            # yet — exit silently so pcap_pending
            # stays unfulfilled and retries later
            print(f"[UPLOADER] not in Arkime "
                  f"yet, will retry: "
                  f"{cid[:20]}")
            sys.exit(0)

        extracted = False
        pcap_files = get_arkime_files(
            meta.get('file_ids', []))
        if pcap_files:
            extracted = extract_with_tshark(
                pcap_files, cid, raw_out)
            if not extracted:
                extracted = \
                    extract_with_mergecap(
                        pcap_files, raw_out)
            if not extracted:
                extracted = extract_raw_copy(
                    pcap_files, raw_out)

        if not extracted:
            print(f"[UPLOADER] ❌ all methods "
                  f"failed for {cid[:20]}")
            report_failure(cid, url, key,
                "all extraction methods failed")
            sys.exit(1)

        ok = compress_and_upload(
            cid, raw_out, url, key, meta or {})
        if not ok:
            report_failure(cid, url, key,
                "upload failed after 3 retries")
            sys.exit(1)

        print(f"[UPLOADER] ✅ Done: {cid[:20]}")

    finally:
        try: os.remove(raw_out)
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
ExecStart=/usr/bin/python3 -u \
  /opt/ndr-sensor/agent.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
Environment=PYTHONUNBUFFERED=1
[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable \
  ndr-vector \
  ndr-agent \
  arkime-capture \
  2>/dev/null || true

# ── Start services ────────────────────────────────
log "Starting Arkime services..."
systemctl start arkime-capture 2>/dev/null || true

log "Starting Vector..."
systemctl start ndr-vector 2>/dev/null || true

log "Starting NDR agent..."
systemctl start ndr-agent 2>/dev/null || true

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

printf "║  Zeek:         %s                           ║\n" "$Z"
printf "║  Suricata:     %s                           ║\n" "$S"
printf "║  Vector:       %s → HTTP                    ║\n" "$V"
printf "║  Arkime cap:   %s                           ║\n" "$AC"
echo "╚══════════════════════════════════════════╝"
echo ""
log "Config:  /etc/ndr/sensor.conf"
log "Logs:    journalctl -u ndr-agent -f"
log "Zeek:    /var/log/ndr/zeek/"
log "Sur:     /var/log/ndr/suricata/eve.json"