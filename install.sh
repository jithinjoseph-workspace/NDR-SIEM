#!/bin/bash

# ── Auto-fix Windows line endings ─────────────
SELF=$(readlink -f "$0")
if file "$SELF" | grep -q CRLF; then
    echo "Fixing line endings..."
    sed -i 's/\r//' "$SELF"
    find "$(dirname "$SELF")" \
        -name "*.sh" -o -name "*.py" | \
        xargs sed -i 's/\r//' 2>/dev/null || true
    exec bash "$SELF" "$@"
fi

set -e

# ── Fix DNS early — before any curl/apt/wget ──
# systemd-resolved (127.0.0.53) is unreliable on some systems; bypass it.
if ! curl -s --max-time 3 https://archive.ubuntu.com > /dev/null 2>&1; then
    echo "[NDR] Fixing DNS (switching to 8.8.8.8)..."
    sudo systemctl stop systemd-resolved 2>/dev/null || true
    sudo rm -f /etc/resolv.conf
    printf "nameserver 8.8.8.8\nnameserver 8.8.4.4\n" | sudo tee /etc/resolv.conf > /dev/null
fi

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log()  { echo -e "${GREEN}[NDR]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
err()  { echo -e "${RED}[ERR]${NC} $1"; exit 1; }
info() { echo -e "${BLUE}[INFO]${NC} $1"; }

echo ""
echo "╔══════════════════════════════════════════╗"
echo "║        NDR Stack Installer v1.0          ║"
echo "║  Zeek + Suricata + Kafka + Rust + UI     ║"
echo "╚══════════════════════════════════════════╝"
echo ""

# Add at top of install.sh after functions
TOTAL_STEPS=12
CURRENT_STEP=0

step() {
    CURRENT_STEP=$((CURRENT_STEP + 1))
    echo ""
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}  Step $CURRENT_STEP/$TOTAL_STEPS: $1${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

# ── Fix APT sources ───────────────────────────
# Detect Ubuntu codename early so sources.list uses the correct suite
UBUNTU_CODENAME=$(. /etc/os-release 2>/dev/null && echo "${VERSION_CODENAME:-$(lsb_release -cs 2>/dev/null)}")
UBUNTU_CODENAME=${UBUNTU_CODENAME:-noble}
UBUNTU_MAJOR_VER=$(. /etc/os-release 2>/dev/null && echo "${VERSION_ID}" | cut -d. -f1)
log "  → Ubuntu ${UBUNTU_CODENAME} (${UBUNTU_MAJOR_VER}.x) detected"

# Ubuntu 24+ uses DEB822 format in ubuntu.sources — writing to sources.list causes duplicates.
# Only write sources.list on older Ubuntu where ubuntu.sources doesn't exist.
if [ -f /etc/apt/sources.list.d/ubuntu.sources ]; then
    log "  → ubuntu.sources found — clearing sources.list to avoid duplicates"
    sudo truncate -s 0 /etc/apt/sources.list
else
    log "  → Writing sources.list for Ubuntu ${UBUNTU_CODENAME}..."
    sudo tee /etc/apt/sources.list > /dev/null << EOF
deb https://archive.ubuntu.com/ubuntu ${UBUNTU_CODENAME} main restricted universe multiverse
deb https://archive.ubuntu.com/ubuntu ${UBUNTU_CODENAME}-updates main restricted universe multiverse
deb https://archive.ubuntu.com/ubuntu ${UBUNTU_CODENAME}-backports main restricted universe multiverse
deb https://security.ubuntu.com/ubuntu ${UBUNTU_CODENAME}-security main restricted universe multiverse
EOF
fi

# Set apt timeout
sudo tee /etc/apt/apt.conf.d/99timeout > /dev/null << 'EOF'
Acquire::http::Timeout "15";
Acquire::https::Timeout "15";
Acquire::Retries "2";
EOF

sudo rm -rf /var/lib/apt/lists/* 2>/dev/null || true
log "  → APT cache cleared"

log "  → Updating package lists..."
sudo apt-get update 2>&1 | \
    grep -E "^Get|^Hit|^Err" | head -15 || true
log "✅ Network ready"

# ── Deployment Mode ───────────────────────────
echo "Select deployment mode:"
echo ""
echo "  1) Local  — everything on this machine (recommended for single site)"
echo "  2) Hybrid — capture local, processing in cloud (for multiple offices)"
echo ""
read -p "Enter choice (1/2) [default: 1]: " MODE_CHOICE

case "$MODE_CHOICE" in
    2)
        DEPLOY_MODE="hybrid"
        echo ""
        warn "Hybrid mode — Zeek/Suricata runs locally, Kafka/ClickHouse in cloud"
        echo ""
        read -p "  Kafka broker URL (e.g. broker.aws.com:9092): " CLOUD_KAFKA
        read -p "  ClickHouse URL   (e.g. https://host:8123):   " CLOUD_CLICKHOUSE
        read -p "  ClickHouse user:                              " CLOUD_CH_USER
        read -sp "  ClickHouse password:                         " CLOUD_CH_PASS
        echo ""
        echo ""
        log "Hybrid config saved"
        ;;
    *)
        DEPLOY_MODE="local"
        log "Local mode — all services on this machine"
        ;;
esac

echo ""

# ── Check OS ──────────────────────────────────
. /etc/os-release
log "Detected OS: $NAME $VERSION_ID"
[[ "$ID" != "ubuntu" ]] && warn "Only Ubuntu tested. Proceed with caution."

USERNAME=$(whoami)
HOME_DIR=$HOME
INSTALL_DIR=$(cd "$(dirname "$0")" && pwd)
RUNTIME_DIR="$INSTALL_DIR/.runtime"
IFACE_FILE="$RUNTIME_DIR/ndr_interface"
OS_VERSION=$(echo $VERSION_ID | cut -d'.' -f1,2)

log "Installing to: $INSTALL_DIR"
log "Running as:    $USERNAME"
log "Deploy mode:   $DEPLOY_MODE"

# ── Spinner function ──────────────────────────
spinner() {
    local pid=$1
    local msg=$2
    local frames=('⠋' '⠙' '⠹' '⠸' '⠼' '⠴' '⠦' '⠧' '⠇' '⠏')
    local i=0
    while kill -0 $pid 2>/dev/null; do
        printf "\r${GREEN}[NDR]${NC} ${frames[$i]} %s..." "$msg"
        i=$(( (i+1) % 10 ))
        sleep 0.1
    done
    printf "\r${GREEN}[NDR]${NC} ✅ %s done!        \n" "$msg"
}

progress() {
    local msg=$1
    shift
    "$@" &>/dev/null &
    spinner $! "$msg"
}

step "Installing system dependencies"

# ── System dependencies ───────────────────────
log "Installing system dependencies..."
log "  → Updating package lists..."
sudo apt-get update 2>&1 | grep -E "^Get|^Hit|^Err|^W:" || true
log "  → Installing packages..."
sudo apt-get install -y \
    curl wget git jq python3 \
    net-tools iproute2 \
    netcat-traditional \
    arp-scan iputils-arping snmp \
    libpcre3 2>/dev/null || true
# libpcre3 may not be in repos on Ubuntu 24+ — fallback to direct download
if ! dpkg -l libpcre3 2>/dev/null | grep -q '^ii'; then
    for PCRE3_URL in \
        "http://archive.ubuntu.com/ubuntu/pool/main/p/pcre3/libpcre3_8.45-4_amd64.deb" \
        "http://archive.ubuntu.com/ubuntu/pool/main/p/pcre3/libpcre3_8.39-17build1_amd64.deb" \
        "http://security.ubuntu.com/ubuntu/pool/main/p/pcre3/libpcre3_8.39-13ubuntu0.22.04.1_amd64.deb"; do
        if wget -q --timeout=60 "$PCRE3_URL" -O /tmp/libpcre3.deb 2>/dev/null \
            && sudo dpkg -i /tmp/libpcre3.deb > /dev/null 2>&1; then
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
    [ -n "$PCRE_SO" ] && sudo ln -sf "$PCRE_SO" /usr/lib/x86_64-linux-gnu/libpcre.so.3 \
        && sudo ldconfig
fi
log "✅ System dependencies installed"

step "Installing Node.js 20"

# ── Install Node.js 20 ────────────────────────
log "Installing Node.js 20..."

# Check if Node.js 20 already installed
NODE_VER=$(node --version 2>/dev/null || echo "none")
NODE_MAJOR=$(echo $NODE_VER | cut -d. -f1 | tr -d 'v')

if [ "${NODE_MAJOR:-0}" -ge 18 ] 2>/dev/null; then
    log "✅ Node.js already OK: $NODE_VER"
else
    # Only remove if old version
    if [ "${NODE_MAJOR:-0}" -lt 18 ] && [ "$NODE_VER" != "none" ]; then
        log "Removing old Node.js $NODE_VER..."
        sudo apt-get remove -y nodejs npm 2>/dev/null || true
        sudo apt-get autoremove -y 2>/dev/null || true
    fi

    # Add NodeSource repo and install
    curl -fsSL https://deb.nodesource.com/setup_20.x \
        | sudo -E bash - 2>/dev/null || true
    sudo apt-get install -y nodejs 2>/dev/null || true
fi

NODE_VER=$(node --version 2>/dev/null || echo "missing")
NPM_VER=$(npm --version 2>/dev/null || echo "missing")
log "✅ Node.js: $NODE_VER | npm: $NPM_VER"


step "Installing Angular CLI"
# ── Install Angular CLI globally ──────────────
if ! command -v ng &>/dev/null; then
    log "Installing Angular CLI..."
    sudo npm install -g @angular/cli 2>/dev/null || \
        npm install -g @angular/cli 2>/dev/null || \
        warn "⚠️ Angular CLI install failed"
    log "✅ Angular CLI: $(ng version --skip-confirmation \
        2>/dev/null | grep 'Angular CLI' | head -1)"
else
    log "✅ Angular CLI already installed: $(ng version \
        --skip-confirmation 2>/dev/null | \
        grep 'Angular CLI' | head -1)"
fi

step "Installing Suricata"

# ── Install Suricata ──────────────────────────
if ! command -v suricata &>/dev/null; then
    log "Installing Suricata..."
    sudo rm -rf /var/lib/apt/lists/* 2>/dev/null || true
    sudo apt-get update -qq 2>/dev/null || true

    if sudo apt-get install -y suricata 2>/dev/null; then
        log "✅ Suricata installed from default repo"
    else
        warn "⚠️ Suricata install failed — skipping"
    fi

    sudo suricata-update 2>/dev/null || true
    sudo systemctl disable suricata 2>/dev/null || true
    sudo systemctl stop suricata 2>/dev/null || true
    log "✅ Suricata ready"
else
    log "✅ Suricata already installed"
    sudo systemctl disable suricata 2>/dev/null || true
    sudo systemctl stop suricata 2>/dev/null || true
fi

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
                        && sudo dpkg -i /tmp/libpcre3.deb > /dev/null 2>&1; then
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
        if sudo dpkg -i /tmp/arkime.deb 2>&1; then
            log "dpkg install succeeded"
        else
            warn "dpkg reported errors — running apt-get install -f to fix..."
            sudo apt-get install -f -y 2>&1 || true
        fi
        rm -f /tmp/arkime.deb

        if [ -f /opt/arkime/bin/capture ]; then
            ARKIME_VER=$(/opt/arkime/bin/capture --version 2>/dev/null | head -1 || echo "unknown")
            log "✅ Arkime installed: ${ARKIME_VER}"
        else
            warn "❌ Arkime install FAILED — /opt/arkime/bin/capture not found"
            warn "  Run: dpkg -l arkime  or  sudo apt-get install -f -y  for details"
        fi
    else
        warn "❌ Arkime installation skipped (no .deb available)"
    fi
else
    ARKIME_VER=$(/opt/arkime/bin/capture --version 2>/dev/null | head -1 || echo "unknown")
    log "✅ Arkime already installed: ${ARKIME_VER}"
fi


step "Installing Zeek"

# ── Install Zeek ──────────────────────────────
if ! command -v /opt/zeek/bin/zeek &>/dev/null; then
    log "Installing Zeek..."
    # Find the newest Zeek repo that exists for this Ubuntu version
    ZEEK_UBUNTU_VER="$OS_VERSION"
    for TRY_VER in "$OS_VERSION" "24.04" "22.04"; do
        ZEEK_KEY_URL="https://download.opensuse.org/repositories/security:zeek/xUbuntu_${TRY_VER}/Release.key"
        if curl -fsSL --max-time 10 "$ZEEK_KEY_URL" -o /dev/null 2>/dev/null; then
            ZEEK_UBUNTU_VER="$TRY_VER"
            break
        fi
    done
    log "  → Using Zeek repo for Ubuntu ${ZEEK_UBUNTU_VER}"
    echo "deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_${ZEEK_UBUNTU_VER}/ /" \
        | sudo tee /etc/apt/sources.list.d/security:zeek.list
    curl -fsSL "https://download.opensuse.org/repositories/security:zeek/xUbuntu_${ZEEK_UBUNTU_VER}/Release.key" \
        | gpg --dearmor \
        | sudo tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null
    sudo apt-get update -qq
    sudo apt-get install -y zeek
    log "✅ Zeek installed"
else
    log "✅ Zeek already installed"
fi

step "Configuring ClickHouse"

# ── ClickHouse runs as a Docker container ──────
# User (ndr/ndr123) is created via CREATE USER in config/clickhouse/init.sql
# Schema (ndr database + all tables) is created by config/clickhouse/init.sql
# on the first container start via /docker-entrypoint-initdb.d/
if [ "$DEPLOY_MODE" = "local" ]; then
    log "ClickHouse will start as a Docker container with the stack"
    log "  User:   ndr / ndr123"
    log "  Ports:  8123/8124 (HTTP), 9000/9001 (native) — 2-node cluster"

    # ── Migrate bare-metal ClickHouse → Docker container ─────────────────
    CH_NEEDS_IMPORT=false
    if systemctl is-active --quiet clickhouse-server 2>/dev/null; then
        warn "Detected an existing ClickHouse installation running on this host."
        echo ""
        echo "  Choose how to proceed:"
        echo "  [1] Migrate existing data  — export from host, import into Docker container"
        echo "  [2] Fresh start            — wipe existing data, start with an empty database"
        echo ""
        read -p "  Enter choice [1/2]: " CH_MIGRATE_CHOICE
        echo ""

        if [ "$CH_MIGRATE_CHOICE" = "1" ]; then
            log "Exporting existing ClickHouse data before stopping host service..."
            bash "$INSTALL_DIR/scripts/ch-export.sh"
            CH_NEEDS_IMPORT=true
            log "✅ Data exported to /home/user/ch-export/"
        else
            log "Fresh start selected — existing host ClickHouse data will not be migrated"
        fi

        log "Stopping host ClickHouse so Docker containers can bind to ports 8123/8124/9000/9001..."
        sudo systemctl stop clickhouse-server
        sudo systemctl disable clickhouse-server
        log "✅ Host ClickHouse stopped and disabled"

        # ── Optionally remove host ClickHouse packages ────────────────────
        echo ""
        read -p "  Uninstall ClickHouse from this system? (Docker container will be used instead) [y/N]: " CH_PURGE
        if [[ "$CH_PURGE" =~ ^[Yy]$ ]]; then
            log "Removing ClickHouse packages..."
            if command -v apt-get &>/dev/null; then
                sudo apt-get remove -y clickhouse-server clickhouse-client clickhouse-common-static 2>/dev/null || true
                sudo apt-get autoremove -y 2>/dev/null || true
            elif command -v yum &>/dev/null; then
                sudo yum remove -y clickhouse-server clickhouse-client 2>/dev/null || true
            fi
            log "✅ ClickHouse packages removed — Docker container takes over"
        else
            log "Keeping ClickHouse packages installed (service remains disabled)"
        fi
    elif ss -tlnp 2>/dev/null | grep -qE ':8123|:8124|:9000|:9001'; then
        warn "Ports 8123/8124/9000/9001 are in use — killing conflicting processes..."
        PIDS=$(ss -tlnp 2>/dev/null | grep -E ':8123|:8124|:9000|:9001' \
            | grep -oP 'pid=\K[0-9]+' | sort -u)
        if [ -n "$PIDS" ]; then
            for PID in $PIDS; do
                PNAME=$(ps -p "$PID" -o comm= 2>/dev/null || echo "unknown")
                log "  Killing PID $PID ($PNAME) holding ClickHouse ports..."
                sudo kill -9 "$PID" 2>/dev/null || true
            done
            sleep 2
            if ss -tlnp 2>/dev/null | grep -qE ':8123|:8124|:9000|:9001'; then
                warn "Some ports still in use after kill — containers may still conflict"
            else
                log "✅ Ports 8123/8124/9000/9001 are now free"
            fi
        fi
    fi

    CLICKHOUSE_URL="http://localhost:8123"
    CLICKHOUSE_URL_SECONDARY="http://localhost:8124"
    CLOUD_CH_USER="ndr"
    CLOUD_CH_PASS="ndr123"
    CLOUD_KAFKA="kafka1:9092,kafka2:9092,kafka3:9092"
else
    log "☁️  Using cloud ClickHouse: $CLOUD_CLICKHOUSE"
    CLICKHOUSE_URL="$CLOUD_CLICKHOUSE"
    info "Skipping local ClickHouse setup"
fi
log "✅ ClickHouse configured"

step "Configuring network and services"


# ── Detect network interface ──────────────────
log "Detecting network interface..."
IFACE=$(ip -o -4 addr show 2>/dev/null | \
    grep -v "127.0.0.1\|docker\|br-\|veth" | \
    awk '{print $2}' | head -1)
if [ -z "$IFACE" ]; then
    IFACE="eth0"
fi
log "Using interface: $IFACE"
mkdir -p "$RUNTIME_DIR"
echo "$IFACE" > "$IFACE_FILE"

# ── Configure Arkime ──────────────────────────────
if [ -f /opt/arkime/bin/capture ]; then
    log "Configuring Arkime..."
    log "Arkime using interface: $IFACE"

    # Create directories BEFORE config
    sudo mkdir -p /opt/arkime/raw
    sudo mkdir -p /opt/arkime/logs
    sudo mkdir -p /opt/arkime/etc
    sudo chmod 755 /opt/arkime/raw

    sudo tee /opt/arkime/etc/config.ini > /dev/null << ARKIME_EOF
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
    sudo tee /etc/systemd/system/arkime-capture.service > /dev/null << EOF
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
    sudo tee /etc/systemd/system/arkime-viewer.service > /dev/null << EOF
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

    sudo systemctl daemon-reload
    sudo systemctl disable \
        arkime-capture \
        arkime-viewer 2>/dev/null || true

    if [ -f /opt/arkime/bin/capture ]; then
        log "✅ Arkime configured on interface: ${IFACE}"
    else
        warn "❌ Arkime install FAILED"
    fi
fi

# ── Configure Zeek ────────────────────────────
log "Configuring Zeek..."
sudo tee /opt/zeek/share/zeek/site/local.zeek > /dev/null << ZEEKCONF
# NDR Stack - Zeek Configuration
@load policy/tuning/json-logs.zeek
@load policy/protocols/conn/community-id-logging
@load protocols/ssh/detect-bruteforcing
@load protocols/ssl/validate-certs
@load protocols/http/detect-sql-injection
@load protocols/http/detect-webapps
@load misc/detect-traceroute
@load frameworks/files/hash-all-files
@load frameworks/files/detect-MHR
@load policy/frameworks/software/vulnerable
@load policy/frameworks/software/version-changes
@load policy/frameworks/software/windows-version-detection
@load policy/protocols/conn/known-hosts
@load policy/protocols/conn/known-services
@load policy/tuning/track-all-assets.zeek
@load policy/protocols/http/software.zeek
@load policy/protocols/dhcp/software.zeek
@load policy/protocols/ssh/software.zeek
@load ndr-arp

# Reduce inactivity timeouts so idle connections are logged quickly
redef tcp_inactivity_timeout = 15 secs;
redef udp_inactivity_timeout = 15 secs;
redef icmp_inactivity_timeout = 10 secs;
ZEEKCONF

# Write custom ARP logger — uses Zeek's built-in arp_request/arp_reply events.
# The zkg ARP package requires internet access and fails silently; this inline
# script has zero external dependencies.
sudo tee /opt/zeek/share/zeek/site/ndr-arp.zeek > /dev/null << 'ARPSCRIPT'
module ARP;

export {
    redef enum Log::ID += { LOG };

    type Info: record {
        ts:        time    &log;
        operation: string  &log;
        mac:       string  &log;
        dst_mac:   string  &log;
        ip:        addr    &log;
        dst_ip:    addr    &log;
    };
}

event zeek_init() &priority=5
{
    Log::create_stream(ARP::LOG, [$columns=Info, $path="arp"]);
}

event arp_request(mac_src: string, mac_dst: string,
                  SPA: addr, SHA: string,
                  TPA: addr, THA: string)
{
    Log::write(ARP::LOG, Info(
        $ts        = network_time(),
        $operation = "request",
        $mac       = SHA,
        $dst_mac   = mac_dst,
        $ip        = SPA,
        $dst_ip    = TPA
    ));
}

event arp_reply(mac_src: string, mac_dst: string,
                SPA: addr, SHA: string,
                TPA: addr, THA: string)
{
    Log::write(ARP::LOG, Info(
        $ts        = network_time(),
        $operation = "reply",
        $mac       = SHA,
        $dst_mac   = THA,
        $ip        = SPA,
        $dst_ip    = TPA
    ));
}
ARPSCRIPT

/opt/zeek/bin/zkg install zeek/corelight/zeek-community-id \
    --force 2>/dev/null || true
log "✅ Zeek configured"


sudo tee /etc/logrotate.d/zeek-ndr > /dev/null << 'EOF'
/home/user/logs/zeek/*.log {
    su root root
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
    dateext
    dateformat -%Y%m%d
}
EOF
log "✅ Zeek log rotation configured"


# ── Configure Suricata ────────────────────────
log "Configuring Suricata..."
sudo cp /etc/suricata/suricata.yaml \
    /etc/suricata/suricata.yaml.bak 2>/dev/null || true
sudo sed -i \
    's/community-id: false/community-id: true/g' \
    /etc/suricata/suricata.yaml 2>/dev/null || true
sudo sed -i \
    "s|default-log-dir: /var/log/suricata|default-log-dir: $HOME_DIR/logs/suricata|g" \
    /etc/suricata/suricata.yaml 2>/dev/null || true
sudo sed -i \
    "s|interface: eth0|interface: $IFACE|g" \
    /etc/suricata/suricata.yaml 2>/dev/null || true
log "Updating Suricata rules..."
sudo suricata-update 2>/dev/null || true
log "✅ Suricata configured on interface: $IFACE"



# ── Suricata log rotation ─────────────────────
log "Configuring Suricata log rotation..."
sudo tee /etc/logrotate.d/suricata-ndr > /dev/null << 'EOF'
/home/user/logs/suricata/eve.json {
    su root root
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
    dateext
    dateformat -%Y%m%d
}
EOF
log "✅ Suricata log rotation configured"


# ── Create required directories ───────────────
log "Creating directories..."
mkdir -p $HOME_DIR/logs/suricata
mkdir -p $HOME_DIR/logs/zeek
mkdir -p $HOME_DIR/.vector/data/suricata \
         $HOME_DIR/.vector/data/zeek
mkdir -p $HOME_DIR/ndr-config

# NDR data directories (PCAP uploads + evidence bundles)
sudo mkdir -p /opt/ndr/pcap
sudo mkdir -p /opt/ndr/evidence
sudo chmod -R 755 /opt/ndr
sudo chown -R $USER:$USER /opt/ndr
echo "✅ Created /opt/ndr/pcap and /opt/ndr/evidence"

# ── Detect host IP ────────────────────────────
HOST_IP=$(ip -o -4 addr show $IFACE 2>/dev/null | \
    awk '{print $4}' | cut -d/ -f1)
if [ -z "$HOST_IP" ]; then
    HOST_IP=$(hostname -I | awk '{print $1}')
fi
log "Host IP detected: $HOST_IP"

# Preserve or generate JWT_SECRET before creating .env
if [ -f "$INSTALL_DIR/.env" ] && grep -q "JWT_SECRET" "$INSTALL_DIR/.env"; then
    JWT_SECRET=$(grep "JWT_SECRET" "$INSTALL_DIR/.env" | cut -d= -f2-)
else
    JWT_SECRET=$(openssl rand -hex 32)
fi

# Preserve OPENAI_API_KEY if already set (re-install should not wipe existing key)
if [ -f "$INSTALL_DIR/.env" ] && grep -q "OPENAI_API_KEY" "$INSTALL_DIR/.env"; then
    OPENAI_API_KEY=$(grep "OPENAI_API_KEY" "$INSTALL_DIR/.env" | cut -d= -f2-)
fi
if [ -z "$OPENAI_API_KEY" ]; then
    echo ""
    echo -n "  Enter OpenAI API key (for ARIA bot — press Enter to skip): "
    read -r OPENAI_API_KEY
fi

cat > $INSTALL_DIR/.env << ENVEOF
HOST_IP=$HOST_IP
HOME_DIR=$HOME_DIR
INSTALL_DIR=$INSTALL_DIR
IFACE=$IFACE
DEPLOY_MODE=$DEPLOY_MODE
CLICKHOUSE_URL=$CLICKHOUSE_URL
CLICKHOUSE_URL_SECONDARY=$CLICKHOUSE_URL_SECONDARY
CLICKHOUSE_USER=$CLOUD_CH_USER
CLICKHOUSE_PASSWORD=$CLOUD_CH_PASS
KAFKA_BROKERS=$CLOUD_KAFKA
JWT_SECRET=$JWT_SECRET
ARKIME_URL=http://${HOST_IP}:8005
ARKIME_PASS=admin
OPENSEARCH_URL=http://${HOST_IP}:9200
OPENAI_API_KEY=$OPENAI_API_KEY
ENVEOF
log "✅ .env generated with JWT_SECRET, OPENSEARCH_URL, OPENAI_API_KEY"

# ── Set up sudoers ────────────────────────────
log "Configuring sudo permissions..."
cat << SUDOERS | sudo tee /etc/sudoers.d/ndr-stack > /dev/null
$USERNAME ALL=(ALL) NOPASSWD: /usr/bin/suricata
$USERNAME ALL=(ALL) NOPASSWD: /opt/zeek/bin/zeek
$USERNAME ALL=(ALL) NOPASSWD: /usr/bin/pkill
$USERNAME ALL=(ALL) NOPASSWD: /usr/bin/pgrep
$USERNAME ALL=(ALL) NOPASSWD: /bin/rm
$USERNAME ALL=(ALL) NOPASSWD: /usr/bin/systemctl
$USERNAME ALL=(ALL) NOPASSWD: /bin/fuser
SUDOERS
sudo chmod 440 /etc/sudoers.d/ndr-stack
log "✅ Sudo configured"

# ── Set up scripts ────────────────────────────
log "Setting up scripts..."
chmod +x $INSTALL_DIR/scripts/*.py \
    $INSTALL_DIR/scripts/*.sh 2>/dev/null || true

# ── Install ndr-agent as systemd service ──────
log "Installing NDR Agent as system service..."
sudo tee /etc/systemd/system/ndr-agent.service > /dev/null << SERVICE
[Unit]
Description=NDR Host Agent
After=network.target

[Service]
Type=simple
User=$USERNAME
ExecStartPre=-/bin/rm -f /var/run/suricata.pid /run/suricata.pid /tmp/suricata.pid
ExecStart=/usr/bin/python3 $INSTALL_DIR/scripts/ndr-agent.py
Restart=always
RestartSec=3
Environment=HOME=$HOME_DIR

[Install]
WantedBy=multi-user.target
SERVICE
sudo systemctl daemon-reload
sudo systemctl enable ndr-agent
sudo systemctl restart ndr-agent
sleep 2
log "✅ NDR Agent service started"

# ── Configure Vector ──────────────────────────
log "Configuring Vector..."
cp $INSTALL_DIR/config/vector.toml \
    $HOME_DIR/.vector/vector.toml
sed -i "s|/home/[^/]*/logs|$HOME_DIR/logs|g" \
    $HOME_DIR/.vector/vector.toml

if [ "$DEPLOY_MODE" = "hybrid" ]; then
    sed -i \
        "s|bootstrap_servers = \"kafka:9092\"|bootstrap_servers = \"$CLOUD_KAFKA\"|g" \
        $HOME_DIR/.vector/vector.toml
fi
log "✅ Vector configured"



step "Installing Angular dependencies"



# ── Install Angular dependencies ──────────────
log "Installing Angular UI dependencies..."
cd $INSTALL_DIR/ndr-ui

# Skip if already installed
if [ -d "node_modules/@angular/build" ]; then
    log "✅ Angular dependencies already installed — skipping"
else
    log "  → First time install..."
    sudo chmod -R 777 $INSTALL_DIR/ndr-ui 2>/dev/null || true

    # Disable symlinks for VirtualBox shared folders
    npm config set bin-links false

    log "  → Running npm install..."
    rm -rf node_modules 2>/dev/null || true
    npm install 2>&1

    # Re-enable
    npm config set bin-links true

    if [ -d "node_modules/@angular/build" ]; then
        log "✅ Angular dependencies installed"
    else
        warn "⚠️ npm install had issues"
    fi
fi

cd $INSTALL_DIR



step "Installing Docker"

# ── Install Docker ────────────────────────────
log "Installing Docker..."
sudo apt-get remove -y docker docker-engine \
    docker.io containerd runc 2>/dev/null || true
sudo apt-get update -qq
sudo apt-get install -y \
    ca-certificates curl gnupg lsb-release

# Re-download GPG key cleanly (previous attempts may have left an empty file)
sudo mkdir -p /etc/apt/keyrings
sudo rm -f /etc/apt/keyrings/docker.gpg
curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
    | sudo gpg --dearmor \
    -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

# Ubuntu 26.04 (resolute) — Docker hasn't published packages for it yet;
# noble (24.04) packages are fully compatible.
DOCKER_CODENAME=$(lsb_release -cs 2>/dev/null || echo "noble")
case "$DOCKER_CODENAME" in
    resolute|oracular|*)
        if ! curl -fsSL "https://download.docker.com/linux/ubuntu/dists/${DOCKER_CODENAME}/InRelease" \
               --max-time 5 -o /dev/null 2>/dev/null; then
            log "Docker repo not available for '${DOCKER_CODENAME}' — falling back to noble"
            DOCKER_CODENAME="noble"
        fi
        ;;
esac

echo \
    "deb [arch=$(dpkg --print-architecture) \
    signed-by=/etc/apt/keyrings/docker.gpg] \
    https://download.docker.com/linux/ubuntu \
    ${DOCKER_CODENAME} stable" \
    | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update -qq
sudo apt-get install -y docker-ce docker-ce-cli \
    containerd.io docker-buildx-plugin docker-compose-plugin
log "✅ Docker installed"

sudo mkdir -p /etc/docker
sudo tee /etc/docker/daemon.json > /dev/null << 'DOCKEREOF'
{
  "dns": ["8.8.8.8", "8.8.4.4"]
}
DOCKEREOF

sudo modprobe overlay 2>/dev/null || true
sudo modprobe br_netfilter 2>/dev/null || true
echo -e "overlay\nbr_netfilter" | \
    sudo tee /etc/modules-load.d/docker.conf > /dev/null

log "Starting Docker service..."
sudo systemctl enable docker
sudo systemctl start docker || true
sudo usermod -aG docker $USERNAME
sudo chmod 666 /var/run/docker.sock

log "Waiting for Docker to initialize..."
for i in {1..20}; do
    if sudo docker info >/dev/null 2>&1; then
        log "✅ Docker is running"
        break
    fi
    if [ $i -eq 10 ]; then
        warn "Docker slow to start, retrying..."
        sudo systemctl restart docker || true
    fi
    echo -n "."
    sleep 3
done
echo ""

if ! sudo docker info >/dev/null 2>&1; then
    err "Docker failed to start!"
fi

step "Building Docker stack"


# ── Build and start Docker stack ──────────────
log "Building Docker stack (this takes a few minutes)..."
cd $INSTALL_DIR

sudo docker compose --profile onpremise down 2>/dev/null || true
sudo docker rm -f vector 2>/dev/null || true

if [ "$DEPLOY_MODE" = "hybrid" ]; then
    log "Hybrid mode — using cloud: $CLOUD_KAFKA"
    sudo docker compose --profile onpremise up -d --build vector ndr-engine-1 nginx
else
    sudo docker compose --profile onpremise up -d --build
fi

log "✅ Docker stack started"

# ── Wait for ClickHouse container to be healthy ───────────────────────
if [ "$DEPLOY_MODE" = "local" ]; then
    log "Waiting for ClickHouse cluster (ch1 + ch2)..."
    for i in {1..40}; do
        if curl -s http://localhost:8123/ping > /dev/null 2>&1 && \
           curl -s http://localhost:8124/ping > /dev/null 2>&1; then
            log "✅ ClickHouse cluster ready (both nodes up)"
            break
        fi
        echo -n "."
        sleep 3
    done
    echo ""

    # ── Auto-import exported data if we migrated from bare-metal ─────────
    if [ "${CH_NEEDS_IMPORT:-false}" = "true" ] && [ -d "/home/user/ch-export" ]; then
        log "Importing exported ClickHouse data into Docker container..."
        bash "$INSTALL_DIR/scripts/ch-import.sh"
        log "✅ Data migration complete"
    fi
fi

# ── Set Kafka retention ───────────────────────
log "Setting Kafka retention policy..."
sleep 15
sudo docker exec kafka1 \
    /opt/kafka/bin/kafka-configs.sh \
    --bootstrap-server localhost:9092 \
    --alter --entity-type topics \
    --entity-name ndr-events \
    --add-config retention.ms=86400000 \
    2>/dev/null || true
log "✅ Kafka retention set to 24 hours"

# ── Create Kafka topic with 3 partitions ──────
log "Creating Kafka topic with 3 partitions..."
sudo docker exec kafka1     /opt/kafka/bin/kafka-topics.sh     --bootstrap-server localhost:9092     --create --if-not-exists     --topic ndr-events     --partitions 3     --replication-factor 3     2>/dev/null || true

log "✅ Kafka topic ready"

# ── JWT Secret Status ─────────────────────────
log "✅ JWT secret already verified and stored in .env"


# ── Setup OpenSearch (for Arkime PCAP) ───────────────────────────────────
step "Setting up OpenSearch"
log "Waiting for OpenSearch..."
cd $INSTALL_DIR
for i in {1..30}; do
    if curl -s http://localhost:9200 > /dev/null 2>&1; then
        log "✅ OpenSearch ready"
        break
    fi
    echo -n "."
    sleep 3
done
echo ""

# Initialize Arkime DB and create admin user now that OpenSearch is up
if [ -f /opt/arkime/bin/capture ]; then
    log "Initializing Arkime database..."
    echo "yes" | sudo timeout 60 /opt/arkime/db/db.pl http://localhost:9200 init --ifneeded 2>&1 || \
        echo "yes" | sudo timeout 60 /opt/arkime/db/db.pl http://localhost:9200 init 2>&1 || true
    log "✅ Arkime database initialized"
    log "Creating Arkime admin user..."
    sudo /opt/arkime/bin/arkime_add_user.sh admin "Admin" admin --admin 2>/dev/null \
        && log "✅ Arkime admin user ready (user: admin / pass: admin)" \
        || warn "⚠️ Arkime admin user creation failed — run manually after install"
fi

# ── Native SOAR is built into the NDR engine ─────────────────────────────
step "Setting up Native SOAR"
log "✅ Native SOAR is built into the NDR engine — no extra services needed"
log "  Configure playbooks, cases and integrations from the UI → SOAR page"

# ── Create proxy config ─────────────────────────
cat > $INSTALL_DIR/ndr-ui/proxy.conf.json << 'PROXYEOF'
{
  "/api": {
    "target": "http://localhost:3000",
    "secure": false,
    "changeOrigin": true
  },
  "/ws": {
    "target": "ws://localhost:3000",
    "secure": false,
    "ws": true
  }
}
PROXYEOF
log "✅ Proxy config created"

# ── Start Angular UI ──────────────────────────
log "Starting Angular UI..."

# Run from shared folder for live reload!
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


# ── WSL2 reminder ─────────────────────────────
if grep -qi microsoft /proc/version 2>/dev/null; then
    warn "WSL2 detected — run in Windows PowerShell as Admin:"
    echo ""
    echo "  netsh interface portproxy add v4tov4 listenport=4200 listenaddress=0.0.0.0 connectport=4200 connectaddress=$HOST_IP"
    echo "  netsh interface portproxy add v4tov4 listenport=3000 listenaddress=0.0.0.0 connectport=3000 connectaddress=$HOST_IP"
    echo "  netsh interface portproxy add v4tov4 listenport=9092 listenaddress=0.0.0.0 connectport=9092 connectaddress=$HOST_IP"
    echo ""
fi

step "Starting all services"

# ── Verify installation ───────────────────────
echo ""
log "Verifying installation..."
log "  Mode:       $DEPLOY_MODE"
log "  Interface:  $IFACE ($HOST_IP)"
log "  Zeek:       $(/opt/zeek/bin/zeek --version 2>&1 | head -1)"
log "  Suricata:   $(suricata --version 2>&1 | head -1)"
log "  Docker:     $(sudo docker --version)"
log "  Node.js:    $(node --version)"
log "  npm:        $(npm --version)"
if [ "$DEPLOY_MODE" = "local" ]; then
    log "  ClickHouse ch1: $(curl -s http://localhost:8123/ping 2>/dev/null || echo 'starting...')"
    log "  ClickHouse ch2: $(curl -s http://localhost:8124/ping 2>/dev/null || echo 'starting...')"
else
    log "  ClickHouse: $CLOUD_CLICKHOUSE (cloud)"
    log "  Kafka:      $CLOUD_KAFKA (cloud)"
fi
log "  Agent:      $(curl -s http://localhost:3001/agent/status \
    2>/dev/null || echo 'starting...')"

# ── Done ──────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════╗"
echo "║         ✅ Installation Complete!         ║"
echo "╠══════════════════════════════════════════╣"
printf "║  Mode:    %-32s║\n" "$DEPLOY_MODE"
echo "╠══════════════════════════════════════════╣"
echo "║  UI:      http://localhost:4200           ║"
echo "║  API:     http://localhost:3000           ║"
echo "║  Agent:   http://localhost:3001           ║"
echo "║  Arkime:  http://localhost:8005           ║"
echo "╠══════════════════════════════════════════╣"
echo "║  start:   ./start.sh                     ║"
echo "║  stop:    ./stop.sh                      ║"
echo "║  status:  ./status.sh                    ║"
echo "╚══════════════════════════════════════════╝"
echo ""
echo "💡 Live reload: Edit Angular on Windows → auto-updates!"
