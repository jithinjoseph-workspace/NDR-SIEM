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
    software-properties-common \
    libpcre3 > /dev/null 2>&1 || true
# libpcre3 may not be in repos on Ubuntu 24+ — fallback to direct download
if ! dpkg -l libpcre3 2>/dev/null | grep -q '^ii'; then
    for PCRE3_URL in \
        "http://archive.ubuntu.com/ubuntu/pool/main/p/pcre3/libpcre3_8.45-4_amd64.deb" \
        "http://archive.ubuntu.com/ubuntu/pool/main/p/pcre3/libpcre3_8.39-17build1_amd64.deb" \
        "http://security.ubuntu.com/ubuntu/pool/main/p/pcre3/libpcre3_8.39-13ubuntu0.22.04.1_amd64.deb"; do
        if wget -q --timeout=60 "$PCRE3_URL" -O /tmp/libpcre3.deb 2>/dev/null \
            && dpkg -i /tmp/libpcre3.deb > /dev/null 2>&1; then
            rm -f /tmp/libpcre3.deb
            break
        fi
        rm -f /tmp/libpcre3.deb
    done
fi
# Ensure libpcre.so.3 symlink exists (missing on some Ubuntu installs)
if [ ! -e /usr/lib/x86_64-linux-gnu/libpcre.so.3 ]; then
    PCRE_SO=$(find /usr/lib/x86_64-linux-gnu /lib/x86_64-linux-gnu \
        -name "libpcre.so.3.*" 2>/dev/null | head -1)
    [ -n "$PCRE_SO" ] && ln -sf "$PCRE_SO" /usr/lib/x86_64-linux-gnu/libpcre.so.3 \
        && ldconfig
fi

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

# ── Install Arkime ────────────────────────────────
log "Installing Arkime (Full Packet Capture)..."

ARKIME_VERSION="5.1.0"
UBUNTU_VER=$(lsb_release -rs 2>/dev/null || echo "22.04")
UBUNTU_MAJOR=$(echo $UBUNTU_VER | cut -d. -f1)

if ! command -v /opt/arkime/bin/capture &>/dev/null; then
    if [ "$UBUNTU_MAJOR" -le "21" ] 2>/dev/null; then
        ARKIME_DEB="arkime_${ARKIME_VERSION}-1.ubuntu2004_amd64.deb"
    elif [ "$UBUNTU_MAJOR" -le "23" ] 2>/dev/null; then
        ARKIME_DEB="arkime_${ARKIME_VERSION}-1.ubuntu2204_amd64.deb"
    elif [ "$UBUNTU_MAJOR" -ge "24" ] 2>/dev/null; then
        ARKIME_DEB="arkime_${ARKIME_VERSION}-1.ubuntu2404_amd64.deb"
    else
        warn "Unsupported Ubuntu version for Arkime: $UBUNTU_VER"
        ARKIME_DEB=""
    fi

    if [ -n "$ARKIME_DEB" ]; then
        log "Downloading Arkime ${ARKIME_VERSION} (${ARKIME_DEB})..."
        if wget --timeout=120 --progress=dot:mega \
            "https://github.com/arkime/arkime/releases/download/v${ARKIME_VERSION}/${ARKIME_DEB}" \
            -O /tmp/arkime.deb 2>&1; then
            DEB_SIZE=$(du -sh /tmp/arkime.deb 2>/dev/null | cut -f1)
            log "Download complete (${DEB_SIZE})"
        else
            warn "❌ Arkime download FAILED"
            warn "  URL: https://github.com/arkime/arkime/releases/download/v${ARKIME_VERSION}/${ARKIME_DEB}"
            warn "  Check internet/proxy and re-run"
            ARKIME_DEB=""
            rm -f /tmp/arkime.deb
        fi
    fi

    if [ -n "$ARKIME_DEB" ] && [ -f /tmp/arkime.deb ]; then
        log "Installing Arkime dependencies..."
        sudo apt-get install -y -qq \
            libwww-perl libjson-perl \
            libyaml-dev libyara10 \
            librdkafka1 ethtool \
            libpcre3 libpcre3-dev \
            libmagic1 libmaxminddb0 \
            libpcre2-8-0 \
            libyaml-0-2 > /dev/null 2>&1 || true

        # Install real libpcre3 (Arkime capture needs pcre_version symbol; PCRE2 is not compatible)
        if ! dpkg -l libpcre3 2>/dev/null | grep -q '^ii'; then
            if sudo apt-get install -y -qq libpcre3 > /dev/null 2>&1; then
                log "✅ libpcre3 installed from apt"
            else
                log "libpcre3 not in repos — downloading from Ubuntu archive..."
                PCRE3_INSTALLED=false
                for PCRE3_URL in \
                    "http://archive.ubuntu.com/ubuntu/pool/main/p/pcre3/libpcre3_8.45-4_amd64.deb" \
                    "http://archive.ubuntu.com/ubuntu/pool/main/p/pcre3/libpcre3_8.39-17build1_amd64.deb" \
                    "http://security.ubuntu.com/ubuntu/pool/main/p/pcre3/libpcre3_8.39-13ubuntu0.22.04.1_amd64.deb"; do
                    if wget -q --timeout=60 "$PCRE3_URL" -O /tmp/libpcre3.deb 2>/dev/null \
                        && dpkg -i /tmp/libpcre3.deb > /dev/null 2>&1; then
                        rm -f /tmp/libpcre3.deb
                        log "✅ libpcre3 installed"
                        PCRE3_INSTALLED=true
                        break
                    fi
                    rm -f /tmp/libpcre3.deb
                done
                $PCRE3_INSTALLED || warn "⚠️ libpcre3 install failed — capture may crash"
            fi
        fi

        log "Installing Arkime package..."
        if dpkg -i /tmp/arkime.deb 2>&1; then
            log "dpkg install succeeded"
        else
            warn "dpkg reported errors — running apt-get install -f to fix..."
            apt-get install -f -y 2>&1 || true
        fi
        rm -f /tmp/arkime.deb

        if [ -f /opt/arkime/bin/capture ]; then
            ARKIME_VER=$(/opt/arkime/bin/capture --version 2>/dev/null | head -1 || echo "unknown")
            log "✅ Arkime installed: ${ARKIME_VER}"
        else
            warn "❌ Arkime install FAILED — /opt/arkime/bin/capture not found"
            warn "  Run: dpkg -l arkime  or  apt-get install -f -y  for details"
        fi
    else
        warn "❌ Arkime installation skipped (no .deb available)"
    fi
else
    ARKIME_VER=$(/opt/arkime/bin/capture --version 2>/dev/null | head -1 || echo "unknown")
    log "✅ Arkime already installed: ${ARKIME_VER}"
fi

# ── Configure Arkime ──────────────────────────────
if [ -f /opt/arkime/bin/capture ]; then
    log "Configuring Arkime..."
    log "Arkime using interface: $IFACE"

    # Create directories BEFORE config
    mkdir -p /opt/arkime/raw
    mkdir -p /opt/arkime/logs
    mkdir -p /opt/arkime/etc
    chmod 755 /opt/arkime/raw

    cat > /opt/arkime/etc/config.ini << ARKIME_EOF
[default]
elasticsearch=http://localhost:9200
passwordSecret=${API_KEY:-ndr-arkime-secret}
serverSecret=${API_KEY:-ndr-arkime-secret}
httpRealm=Arkime
interface=${IFACE:-eno1}
pcapDir=/opt/arkime/raw
maxFileSizeG=4
maxFileTimeM=60
viewPort=8005
viewHost=0.0.0.0
pcapWriteMethod=simple
pcapWriteSize=262143
authMode=basic
logLevel=warn
maxDays=7
freeSpaceG=5
tcpTimeout=600
udpTimeout=30
maxStreams=500000
maxPackets=10000
packetThreads=2
communityId=true
cronQueries=true
ARKIME_EOF

    # Create Arkime capture service
    cat > /etc/systemd/system/arkime-capture.service << EOF
[Unit]
Description=Arkime Packet Capture
After=network.target

[Service]
Type=simple
ExecStart=/opt/arkime/bin/capture \
    -c /opt/arkime/etc/config.ini \
    -o pcapDir=/opt/arkime/raw \
    --insecure
Restart=always
RestartSec=10
LimitCORE=infinity
LimitMEMLOCK=infinity

[Install]
WantedBy=multi-user.target
EOF

    # Create Arkime viewer service
    cat > /etc/systemd/system/arkime-viewer.service << EOF
[Unit]
Description=Arkime Packet Viewer
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/arkime/viewer
ExecStart=/opt/arkime/bin/node \
    viewer.js \
    -c /opt/arkime/etc/config.ini
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl disable \
        arkime-capture \
        arkime-viewer 2>/dev/null || true

    if [ -f /opt/arkime/bin/capture ]; then
        log "✅ Arkime configured on interface: ${IFACE}"
    else
        warn "❌ Arkime install FAILED"
    fi
fi

# ── Install OpenSearch for Arkime ─────────────────
log "Installing OpenSearch (required for Arkime)..."
if ! command -v docker &>/dev/null; then
    apt-get install -y -qq ca-certificates curl gnupg lsb-release > /dev/null
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
        | gpg --dearmor -o /etc/apt/keyrings/docker.gpg 2>/dev/null
    chmod a+r /etc/apt/keyrings/docker.gpg
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
        https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" \
        > /etc/apt/sources.list.d/docker.list
    apt-get update -qq
    apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-compose-plugin > /dev/null
    systemctl enable docker
    systemctl start docker
    chmod 666 /var/run/docker.sock 2>/dev/null || true
    log "✅ Docker installed"
fi

if ! docker ps 2>/dev/null | grep -q opensearch-arkime; then
    docker run -d --name opensearch-arkime \
        -e "discovery.type=single-node" \
        -e "DISABLE_SECURITY_PLUGIN=true" \
        -e "OPENSEARCH_JAVA_OPTS=-Xms512m -Xmx512m" \
        -p 9200:9200 \
        --restart unless-stopped \
        opensearchproject/opensearch:2.5.0 > /dev/null 2>&1 \
    && log "✅ OpenSearch container started" \
    || warn "⚠️ OpenSearch container start failed"
else
    log "✅ OpenSearch already running"
fi

log "Waiting for OpenSearch to be ready..."
for i in {1..30}; do
    if curl -s http://localhost:9200 > /dev/null 2>&1; then
        log "✅ OpenSearch ready"
        break
    fi
    echo -n "."
    sleep 3
done
echo ""

# Initialize Arkime DB and create admin user now that OpenSearch is ready
if [ -f /opt/arkime/bin/capture ]; then
    log "Initializing Arkime database..."
    echo "yes" | timeout 60 /opt/arkime/db/db.pl http://localhost:9200 init --ifneeded 2>&1 || \
        echo "yes" | timeout 60 /opt/arkime/db/db.pl http://localhost:9200 init 2>&1 || true
    log "✅ Arkime database initialized"
    log "Creating Arkime admin user..."
    ARKIME_PASS=$(echo "$API_KEY" | sha256sum | cut -c1-16)
    /opt/arkime/bin/arkime_add_user.sh admin "Admin" "$ARKIME_PASS" --admin 2>/dev/null \
        && log "✅ Arkime admin user ready (user: admin / pass derived from API_KEY)" \
        || warn "⚠️ Arkime admin user creation failed — run manually after install"
fi

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
mkdir -p /opt/ndr-sensor/pcap-tmp
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
import os, time, subprocess, requests, json
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

def start_arkime():
    try:
        subprocess.run(
            ['systemctl', 'start', 'arkime-capture'],
            capture_output=True, timeout=30)
        subprocess.run(
            ['systemctl', 'start', 'arkime-viewer'],
            capture_output=True, timeout=30)
        print("[NDR] ✅ Arkime started!")
        return True
    except Exception as e:
        print(f"[NDR] Arkime start failed: {e}")
    return False

def stop_arkime():
    subprocess.run(
        ['systemctl', 'stop', 'arkime-capture'],
        capture_output=True)
    subprocess.run(
        ['systemctl', 'stop', 'arkime-viewer'],
        capture_output=True)

def is_arkime_running():
    capture = subprocess.run(
        ['pgrep', '-f', 'arkime/bin/capture'],
        capture_output=True
    ).returncode == 0
    viewer = subprocess.run(
        ['pgrep', '-f', 'viewer.js'],
        capture_output=True
    ).returncode == 0
    return capture and viewer

def check_and_restart():
    if DESIRED_STATE == 'stopped':
        return {
            'zeek': 'stopped',
            'suricata': 'stopped',
            'vector': 'stopped',
            'arkime': 'stopped'
        }

    zeek_ok     = is_running('zeek')
    suricata_ok = is_running('suricata')
    vector_ok   = is_running('vector')
    arkime_ok   = is_arkime_running()

    if not zeek_ok:
        print("[NDR] Zeek stopped! Restarting...")
        start_zeek()
    if not suricata_ok:
        print("[NDR] Suricata stopped! Restarting...")
        start_suricata()
    if not vector_ok:
        print("[NDR] Vector stopped! Restarting...")
        start_vector()
    if not arkime_ok:
        print("[NDR] Arkime stopped! Restarting...")
        start_arkime()

    return {
        'zeek':     'running' if zeek_ok else 'restarting',
        'suricata': 'running' if suricata_ok else 'restarting',
        'vector':   'running' if vector_ok else 'restarting',
        'arkime':   'running' if arkime_ok else 'restarting'
    }

def derive_arkime_pass(api_key):
    import hashlib
    return hashlib.sha256(api_key.encode()).hexdigest()[:16]

def report_status(services):
    import socket
    try:
        sensor_ip = socket.gethostbyname(socket.gethostname())
    except Exception:
        sensor_ip = '127.0.0.1'
    status = {
        'tenant_id': TENANT_ID,
        'timestamp': datetime.utcnow().isoformat(),
        'arkime_url': f'http://{sensor_ip}:8005',
        'arkime_pass': derive_arkime_pass(API_KEY),
        **services,
        'arkime': 'running' if is_arkime_running() else 'stopped'
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
        start_arkime()
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
        stop_arkime()
        print("[NDR] All services stopped!")
    elif cmd == 'restart':
        DESIRED_STATE = 'running'
        execute_command('stop')
        DESIRED_STATE = 'running'
        time.sleep(3)
        execute_command('start')

def get_pending_pcap_requests(cloud_url, api_key):
    """Poll cloud for community_ids needing PCAP upload"""
    try:
        resp = requests.get(
            f"{cloud_url}/api/pcap/pending",
            headers={"X-Sensor-Key": api_key},
            timeout=10
        )
        if resp.status_code == 200:
            return resp.json().get('pending', [])
    except Exception as e:
        print(f"[NDR] pcap pending poll error: {e}")
    return []

def process_pcap_uploads(cloud_url, api_key):
    """Upload PCAPs for all pending requests"""
    pending = get_pending_pcap_requests(cloud_url, api_key)
    if not pending:
        return
    print(f"[NDR] Found {len(pending)} pending PCAP requests")
    for cid in pending[:5]:  # max 5 per cycle
        if not cid:
            continue
        print(f"[NDR] Uploading PCAP for CID: {cid}")
        try:
            result = subprocess.run(
                ['python3', '/opt/ndr-sensor/pcap-uploader.py', cid],
                capture_output=True, text=True, timeout=120
            )
            if result.stdout.strip():
                print(result.stdout.strip())
            if result.returncode != 0 and result.stderr.strip():
                print(f"[NDR] Uploader error: {result.stderr.strip()}")
        except subprocess.TimeoutExpired:
            print(f"[NDR] PCAP upload timeout for {cid}")
        except Exception as e:
            print(f"[NDR] PCAP upload error for {cid}: {e}")

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
    start_arkime()
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

        # Upload any pending PCAPs the cloud has queued for this sensor
        process_pcap_uploads(CLOUD_URL, API_KEY)

        time.sleep(30)
AGENT
chmod +x /opt/ndr-sensor/agent.py

# ── Write pcap-uploader.py ────────────────────────
# Create temp PCAP directory
mkdir -p /opt/ndr-sensor/pcap-tmp
chmod 755 /opt/ndr-sensor/pcap-tmp

cat > /opt/ndr-sensor/pcap-uploader.py << 'UPLOADER_EOF'
#!/usr/bin/env python3
"""
NDR PCAP Uploader
Extracts PCAP for a community_id from local Arkime
and uploads to NDR cloud engine.
Called by agent.py for each pending CID.
"""
import os
import sys
import subprocess
import requests
import hashlib
import json
import tempfile

def load_config():
    config = {}
    try:
        with open('/etc/ndr/sensor.conf') as f:
            for line in f:
                line = line.strip()
                if '=' in line and not line.startswith('#'):
                    k, v = line.split('=', 1)
                    config[k.strip()] = v.strip()
    except Exception as e:
        print(f"[PCAP-UPLOADER] Config error: {e}")
        sys.exit(1)
    return config

def get_arkime_pass(api_key):
    return hashlib.sha256(api_key.encode()).hexdigest()[:16]

def get_session_meta(community_id, arkime_pass):
    """Fetch session metadata (IPs, ports, proto) from Arkime"""
    try:
        expr = f"communityId=={community_id}"
        resp = requests.get(
            f"http://localhost:8005/api/sessions"
            f"?expression={expr}&startTime=-24h&stopTime=now&length=1",
            auth=("admin", arkime_pass),
            timeout=15
        )
        if resp.status_code == 200:
            sessions = resp.json().get("data", [])
            if sessions:
                s = sessions[0]
                return {
                    "src_ip":      s.get("source.ip", s.get("srcIp", "")),
                    "dst_ip":      s.get("destination.ip", s.get("dstIp", "")),
                    "src_port":    str(s.get("source.port", s.get("srcPort", 0))),
                    "dst_port":    str(s.get("destination.port", s.get("dstPort", 0))),
                    "proto":       s.get("network.transport", s.get("protocol", "")),
                    "sensor_host": s.get("node", os.uname().nodename),
                }
    except Exception as e:
        print(f"[PCAP-UPLOADER] Meta fetch error: {e}")
    return {"src_ip": "", "dst_ip": "", "src_port": "0",
            "dst_port": "0", "proto": "", "sensor_host": os.uname().nodename}

def extract_pcap(community_id, output_file, arkime_pass):
    """Download PCAP from local Arkime for a CID"""
    try:
        expr = f"communityId=={community_id}"
        resp = requests.get(
            f"http://localhost:8005/api/sessions/pcap"
            f"?expression={expr}&startTime=-24h&stopTime=now",
            auth=("admin", arkime_pass),
            timeout=30,
            stream=True
        )
        if resp.status_code != 200:
            print(f"[PCAP-UPLOADER] Arkime returned {resp.status_code} for {community_id}")
            return False
        with open(output_file, 'wb') as f:
            for chunk in resp.iter_content(8192):
                f.write(chunk)
        size = os.path.getsize(output_file)
        if size < 24:
            print(f"[PCAP-UPLOADER] PCAP too small ({size} bytes) — session not found")
            return False
        print(f"[PCAP-UPLOADER] Extracted {size} bytes for {community_id}")
        return True
    except Exception as e:
        print(f"[PCAP-UPLOADER] Extract error: {e}")
        return False

def upload_pcap(community_id, pcap_file, cloud_url, api_key, meta):
    """Upload extracted PCAP to NDR cloud"""
    try:
        with open(pcap_file, 'rb') as f:
            resp = requests.post(
                f"{cloud_url}/api/pcap/upload",
                headers={"X-Sensor-Key": api_key},
                files={"pcap": ("session.pcap", f, "application/octet-stream")},
                data={
                    "community_id": community_id,
                    "src_ip":       meta["src_ip"],
                    "dst_ip":       meta["dst_ip"],
                    "src_port":     meta["src_port"],
                    "dst_port":     meta["dst_port"],
                    "proto":        meta["proto"],
                    "sensor_host":  meta["sensor_host"],
                },
                timeout=120
            )
        if resp.status_code == 200:
            print(f"[PCAP-UPLOADER] ✅ Uploaded {community_id} → cloud")
            return True
        else:
            print(f"[PCAP-UPLOADER] ❌ Upload failed HTTP {resp.status_code}: {resp.text}")
            return False
    except Exception as e:
        print(f"[PCAP-UPLOADER] Upload error: {e}")
        return False

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: pcap-uploader.py <community_id>")
        sys.exit(1)

    community_id = sys.argv[1]
    config   = load_config()
    cloud_url = config.get('CLOUD_URL', '').rstrip('/')
    api_key   = config.get('API_KEY', '')

    if not cloud_url or not api_key:
        print("[PCAP-UPLOADER] Missing CLOUD_URL or API_KEY")
        sys.exit(1)

    arkime_pass = get_arkime_pass(api_key)
    safe_cid    = community_id.replace('/', '_').replace(':', '_')
    tmp_file    = f"/opt/ndr-sensor/pcap-tmp/pcap_{safe_cid}.pcap"

    try:
        meta = get_session_meta(community_id, arkime_pass)
        if extract_pcap(community_id, tmp_file, arkime_pass):
            upload_pcap(community_id, tmp_file, cloud_url, api_key, meta)
        else:
            print(f"[PCAP-UPLOADER] No PCAP found for {community_id}")
    finally:
        if os.path.exists(tmp_file):
            os.remove(tmp_file)
UPLOADER_EOF

chmod +x /opt/ndr-sensor/pcap-uploader.py
echo "✅ pcap-uploader.py installed"

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
printf "║  Arkime UI: http://%-20s ║\n" \
    "$(hostname -I | awk '{print $1}'):8005"
echo "╚══════════════════════════════════════════╝"
echo ""
log "Config: /etc/ndr/sensor.conf"
log "Logs:   /var/log/ndr/"
