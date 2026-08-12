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

# ── Bootstrap: download only the required config files (no source code) ──
if [ ! -f "$(dirname "$0")/docker-compose.yml" ]; then
    echo ""
    echo "  NDR installer — downloading required files..."
    echo ""
    read -rp "  GitHub token (provided by Proma Secure): " GH_TOKEN
    INSTALL_DIR="${1:-/opt/ndr}"
    echo "  Installing to: $INSTALL_DIR"
    sudo mkdir -p "$INSTALL_DIR"
    sudo chmod 755 "$INSTALL_DIR"

    echo "  Downloading config files via API..."
    GH_TOKEN="$GH_TOKEN" INSTALL_DIR="$INSTALL_DIR" python3 - << 'PYEOF'
import urllib.request, json, os, base64, sys

token    = os.environ["GH_TOKEN"]
dest     = os.environ["INSTALL_DIR"]
api_base = "https://api.github.com/repos/jithinjoseph-workspace/NDR-Demo"
headers  = {"Authorization": f"token {token}", "Accept": "application/vnd.github.v3+json"}

def gh_get(url):
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req) as r:
            return r.read()
    except Exception as e:
        print(f"  ERROR: API request failed: {e}")
        sys.exit(1)

def download_file(repo_path, local_path):
    meta = json.loads(gh_get(f"{api_base}/contents/{repo_path}?ref=arkime"))
    content = base64.b64decode(meta["content"].replace("\n", ""))
    os.makedirs(os.path.dirname(local_path), exist_ok=True)
    with open(local_path, "wb") as f:
        f.write(content)
    print(f"    {repo_path}")

def download_dir(repo_path, local_path):
    os.makedirs(local_path, exist_ok=True)
    items = json.loads(gh_get(f"{api_base}/contents/{repo_path}?ref=arkime"))
    for item in items:
        target = os.path.join(local_path, item["name"])
        if item["type"] == "file":
            meta = json.loads(gh_get(f"{api_base}/contents/{item['path']}?ref=arkime"))
            content = base64.b64decode(meta["content"].replace("\n", ""))
            with open(target, "wb") as f:
                f.write(content)
            print(f"    {item['path']}")
        elif item["type"] == "dir":
            download_dir(item["path"], target)

download_file("docker-compose.yml",   f"{dest}/docker-compose.yml")
download_file("install-customer.sh",  f"{dest}/install-customer.sh")
download_file("start.sh",             f"{dest}/start.sh")
download_file("stop.sh",              f"{dest}/stop.sh")
download_file("status.sh",            f"{dest}/status.sh")
download_dir("config",                f"{dest}/config")
download_dir("scripts",               f"{dest}/scripts")
download_dir("rust/ndr-engine/rules", f"{dest}/rust/ndr-engine/rules")
PYEOF
    chmod +x "$INSTALL_DIR/install-customer.sh"
    chmod +x "$INSTALL_DIR/start.sh"
    chmod +x "$INSTALL_DIR/stop.sh"
    chmod +x "$INSTALL_DIR/status.sh"

    echo ""
    exec bash "$INSTALL_DIR/install-customer.sh" "$INSTALL_DIR"
fi

# ── Fix DNS early — before any curl/apt/wget ──
if ! curl -s --max-time 3 https://archive.ubuntu.com > /dev/null 2>&1; then
    echo "[NDR] Fixing DNS (switching to 8.8.8.8)..."
    if systemctl is-active systemd-resolved > /dev/null 2>&1; then
        sudo mkdir -p /etc/systemd/resolved.conf.d/
        printf "[Resolve]\nDNS=8.8.8.8 8.8.4.4\nFallbackDNS=1.1.1.1\n" \
            | sudo tee /etc/systemd/resolved.conf.d/ndr-dns.conf > /dev/null
        sudo systemctl restart systemd-resolved 2>/dev/null || true
    else
        printf "nameserver 8.8.8.8\nnameserver 8.8.4.4\n" | sudo tee /etc/resolv.conf > /dev/null
    fi
fi

# ── Colors ────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

# ── Log helpers ───────────────────────────────
log()  { echo -e "  ${GREEN}[+]${NC} $1"; }
warn() { echo -e "  ${YELLOW}[!]${NC} $1"; }
err()  { echo -e "  ${RED}[x]${NC} $1"; exit 1; }
info() { echo -e "  ${BLUE}[>]${NC} $1"; }
hdr()  {
    echo -e ""
    echo -e "  ${CYAN}${BOLD}┌─────────────────────────────────────────────┐${NC}"
    printf  "  ${CYAN}${BOLD}│${NC}  %-43s${CYAN}${BOLD}│${NC}\n" "$1"
    echo -e "  ${CYAN}${BOLD}└─────────────────────────────────────────────┘${NC}"
}

# ── Banner ────────────────────────────────────
clear
printf "\n"
printf "  ${CYAN}╔══════════════════════════════════════════════╗${NC}\n"
printf "  ${CYAN}║${NC}                                              ${CYAN}║${NC}\n"
printf "  ${CYAN}║${NC}    ${BOLD}P R O M A   A L P H A   v 1 . 0${NC}          ${CYAN}║${NC}\n"
printf "  ${CYAN}║${NC}                                              ${CYAN}║${NC}\n"
printf "  ${CYAN}║${NC}    Network Detection & Response Platform      ${CYAN}║${NC}\n"
printf "  ${CYAN}║${NC}    Sensor  ·  Engine  ·  Analytics  ·  UI    ${CYAN}║${NC}\n"
printf "  ${CYAN}║${NC}                                              ${CYAN}║${NC}\n"
printf "  ${CYAN}║${NC}    ${DIM}◆  Powered by Proma Secure  ◆${NC}              ${CYAN}║${NC}\n"
printf "  ${CYAN}║${NC}                                              ${CYAN}║${NC}\n"
printf "  ${CYAN}╚══════════════════════════════════════════════╝${NC}\n"
printf "\n"

# ── Progress bar (inline, no cursor gymnastics) ─
TOTAL_STEPS=12
CURRENT_STEP=0

step() {
    CURRENT_STEP=$((CURRENT_STEP + 1))
    local label="$1" BAR_WIDTH=36
    local filled=$(( (CURRENT_STEP * BAR_WIDTH) / TOTAL_STEPS ))
    local pct=$(( (CURRENT_STEP * 100) / TOTAL_STEPS ))
    local bar="" i
    for ((i=0; i<filled; i++));          do bar+="▓"; done
    for ((i=filled; i<BAR_WIDTH; i++));  do bar+="░"; done
    printf "\n  ${CYAN}[%s]${NC}  ${BOLD}%3d%%${NC}  ${DIM}%d/%d${NC}\n" \
        "$bar" "$pct" "$CURRENT_STEP" "$TOTAL_STEPS"
    hdr "$label"
}

# ── Fix APT sources ───────────────────────────
UBUNTU_CODENAME=$(. /etc/os-release 2>/dev/null && echo "${VERSION_CODENAME:-$(lsb_release -cs 2>/dev/null)}")
UBUNTU_CODENAME=${UBUNTU_CODENAME:-noble}
UBUNTU_MAJOR_VER=$(. /etc/os-release 2>/dev/null && echo "${VERSION_ID}" | cut -d. -f1)
log "Ubuntu ${UBUNTU_CODENAME} (${UBUNTU_MAJOR_VER}.x) detected"

if [ -f /etc/apt/sources.list.d/ubuntu.sources ]; then
    log "ubuntu.sources found — clearing sources.list to avoid duplicates"
    sudo truncate -s 0 /etc/apt/sources.list
else
    log "Writing sources.list for Ubuntu ${UBUNTU_CODENAME}..."
    SECURITY_REPO_LINE=""
    if curl -fsSL --max-time 8 \
        "https://security.ubuntu.com/ubuntu/dists/${UBUNTU_CODENAME}-security/InRelease" \
        -o /dev/null 2>/dev/null; then
        SECURITY_REPO_LINE="deb https://security.ubuntu.com/ubuntu ${UBUNTU_CODENAME}-security main restricted universe multiverse"
    else
        warn "security.ubuntu.com/${UBUNTU_CODENAME}-security not yet available — skipping"
    fi
    sudo tee /etc/apt/sources.list > /dev/null << EOF
deb https://archive.ubuntu.com/ubuntu ${UBUNTU_CODENAME} main restricted universe multiverse
deb https://archive.ubuntu.com/ubuntu ${UBUNTU_CODENAME}-updates main restricted universe multiverse
deb https://archive.ubuntu.com/ubuntu ${UBUNTU_CODENAME}-backports main restricted universe multiverse
${SECURITY_REPO_LINE}
EOF
fi

sudo tee /etc/apt/apt.conf.d/99timeout > /dev/null << 'EOF'
Acquire::http::Timeout "15";
Acquire::https::Timeout "15";
Acquire::Retries "2";
EOF

sudo rm -rf /var/lib/apt/lists/* 2>/dev/null || true
log "APT cache cleared"
log "Updating package lists..."
sudo apt-get update 2>&1 | grep -E "^Get|^Hit|^Err" | head -15 || true
log "Network ready"

# ── Deployment Mode ───────────────────────────
printf "\n"
printf "  ${CYAN}┌──────────────────────────────────────────────┐${NC}\n"
printf "  ${CYAN}│${NC}  ${BOLD}Select Deployment Mode${NC}                        ${CYAN}│${NC}\n"
printf "  ${CYAN}├──────────────────────────────────────────────┤${NC}\n"
printf "  ${CYAN}│${NC}  ${GREEN}[1]${NC} Local  — all services on this machine      ${CYAN}│${NC}\n"
printf "  ${CYAN}│${NC}       Recommended for single-site deployment  ${CYAN}│${NC}\n"
printf "  ${CYAN}│${NC}                                              ${CYAN}│${NC}\n"
printf "  ${CYAN}│${NC}  ${BLUE}[2]${NC} Hybrid — capture local, cloud processing   ${CYAN}│${NC}\n"
printf "  ${CYAN}│${NC}       For multi-office or cloud-connected use ${CYAN}│${NC}\n"
printf "  ${CYAN}└──────────────────────────────────────────────┘${NC}\n"
printf "\n"
read -p "  Enter choice (1/2) [default: 1]: " MODE_CHOICE

case "$MODE_CHOICE" in
    2)
        DEPLOY_MODE="hybrid"
        printf "\n"
        warn "Hybrid mode — Agent-Z/Agent-S local, Event Bus/DB in cloud"
        printf "\n"
        read -p "  Kafka broker URL  (e.g. broker.aws.com:9092):   " CLOUD_KAFKA
        read -p "  ClickHouse URL    (e.g. https://host:8123):     " CLOUD_CLICKHOUSE
        read -p "  ClickHouse user:                                 " CLOUD_CH_USER
        read -sp "  ClickHouse password:                            " CLOUD_CH_PASS
        echo ""
        printf "\n"
        log "Hybrid configuration saved"
        ;;
    *)
        DEPLOY_MODE="local"
        log "Local mode — all services on this machine"
        ;;
esac

printf "\n"

# ── Registry login (customer mode) ───────────
REGISTRY="ghcr.io/jithinjoseph-workspace"
read -rp "  Registry token (provided by Proma Secure): " REGISTRY_TOKEN
echo "$REGISTRY_TOKEN" | sudo docker login ghcr.io -u ndr-customer --password-stdin \
    || err "Registry login failed — check your token and try again"
log "Registry login successful"
printf "\n"

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

log "Installing to:  $INSTALL_DIR"
log "Running as:     $USERNAME"
log "Deploy mode:    $DEPLOY_MODE"

# Write a minimal .env immediately so docker compose never sees blank variables.
# The network step overwrites this with full values once HOST_IP/JWT_SECRET are known.
IFACE_EARLY=$(ip route get 8.8.8.8 2>/dev/null | awk '{for(i=1;i<=NF;i++) if ($i=="dev") {print $(i+1); exit}}')
if [ -z "$IFACE_EARLY" ]; then
    IFACE_EARLY=$(ip -o -4 addr show 2>/dev/null | grep -v "127.0.0.1\|docker\|br-\|veth\| lo " | awk '{print $2}' | head -1)
fi
IFACE_EARLY=${IFACE_EARLY:-eth0}
HOST_IP_EARLY=$(ip -o -4 addr show "$IFACE_EARLY" 2>/dev/null | awk '{print $4}' | cut -d/ -f1)
HOST_IP_EARLY=${HOST_IP_EARLY:-$(hostname -I | awk '{print $1}')}
JWT_SECRET_EARLY=$(openssl rand -hex 32 2>/dev/null || echo "changeme-$(date +%s)")
NDR_AGENT_SECRET_EARLY=$(openssl rand -hex 32 2>/dev/null || echo "changeme-agent-$(date +%s)")

cat > "$INSTALL_DIR/.env" << _EARLY_ENV
HOST_IP=${HOST_IP_EARLY}
HOME_DIR=${HOME_DIR}
INSTALL_DIR=${INSTALL_DIR}
IFACE=${IFACE_EARLY}
DEPLOY_MODE=${DEPLOY_MODE}
LOCAL_SENSOR_ID=local-central
TENANT_ID=default
CLICKHOUSE_URL=http://ndr-nginx:8123
CLICKHOUSE_URL_SECONDARY=http://clickhouse2:8123
CLICKHOUSE_USER=ndr
CLICKHOUSE_PASSWORD=$(openssl rand -hex 16 2>/dev/null || echo "$(date +%s%N | sha256sum | head -c 32)")
KAFKA_BROKERS=kafka1:9092,kafka2:9092,kafka3:9092
JWT_SECRET=${JWT_SECRET_EARLY}
NDR_AGENT_SECRET=${NDR_AGENT_SECRET_EARLY}
CORS_ORIGIN=https://${HOST_IP_EARLY}:3000
ARKIME_URL=http://${HOST_IP_EARLY}:8005
ARKIME_PASS=$(openssl rand -hex 12 2>/dev/null || echo "$(date +%s%N | sha256sum | head -c 24)")
OPENSEARCH_URL=http://${HOST_IP_EARLY}:9200
OPENAI_API_KEY=
GROQ_API_KEY=
GROQ_MODEL=llama-3.3-70b-versatile
BEACON_WINDOW_HOURS=1
INGEST_RATE_LIMIT=50000
SIEM_SYSLOG_HOST=
SIEM_SYSLOG_PORT=514
TRUSTED_SOURCE_CIDRS=
LICENSE_PUBLIC_KEY=
LICENSE_TOKEN=
TENANT_ADMIN_USER=
TENANT_ADMIN_PASS=
_EARLY_ENV
log ".env written early (will be updated with final values in network step)"

# ── Spinner ───────────────────────────────────
spinner() {
    local pid=$1 msg=$2
    local frames=('⠋' '⠙' '⠹' '⠸' '⠼' '⠴' '⠦' '⠧' '⠇' '⠏')
    local i=0
    while kill -0 $pid 2>/dev/null; do
        printf "\r  ${CYAN}${frames[$i]}${NC}  %s..." "$msg"
        i=$(( (i+1) % 10 ))
        sleep 0.1
    done
    printf "\r  ${GREEN}[+]${NC}  %s — done       \n" "$msg"
}

progress() {
    local msg=$1; shift
    "$@" &>/dev/null &
    spinner $! "$msg"
}

# ══════════════════════════════════════════════
step "System Dependencies"

log "Updating package lists..."
sudo apt-get update 2>&1 | grep -E "^Get|^Hit|^Err|^W:" || true

# auditd requires CAP_AUDIT_CONTROL which many hypervisors deny.
# Mask it so systemd refuses to start it during dpkg post-install,
# letting dpkg configure succeed without the daemon actually running.
sudo systemctl mask auditd 2>/dev/null || true
sudo dpkg --configure -a 2>/dev/null || true

log "Installing packages..."
sudo apt-get install -y \
    curl wget git jq python3 python3-pip \
    net-tools iproute2 \
    netcat-traditional \
    arp-scan iputils-arping snmp \
    libpcre3 2>/dev/null || true


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

if [ ! -e /usr/lib/x86_64-linux-gnu/libpcre.so.3 ]; then
    PCRE_SO=$(find /usr/lib/x86_64-linux-gnu /lib/x86_64-linux-gnu \
        -name "libpcre.so.3.*" 2>/dev/null | head -1)
    [ -n "$PCRE_SO" ] && sudo ln -sf "$PCRE_SO" /usr/lib/x86_64-linux-gnu/libpcre.so.3 \
        && sudo ldconfig
fi
log "System dependencies installed"

# ══════════════════════════════════════════════
step "Node.js 20"

log "Skipped — UI runs from Docker image, Node.js not required"

# ══════════════════════════════════════════════
step "Agent-S"

log "Skipped — Agent-S runs on dedicated remote sensor machines"

# ── Packet Recorder (Arkime) ──────────────────
log "Installing Packet Recorder..."

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
        warn "Unsupported OS for Packet Recorder: $UBUNTU_VER"
        ARKIME_DEB=""
    fi

    if [ -n "$ARKIME_DEB" ]; then
        log "Downloading Packet Recorder ${ARKIME_VERSION}..."
        if wget --timeout=120 --progress=dot:mega \
            "https://github.com/arkime/arkime/releases/download/v${ARKIME_VERSION}/${ARKIME_DEB}" \
            -O /tmp/arkime.deb 2>&1; then
            DEB_SIZE=$(du -sh /tmp/arkime.deb 2>/dev/null | cut -f1)
            log "Download complete (${DEB_SIZE})"
        else
            warn "Packet Recorder download failed — check internet and re-run"
            ARKIME_DEB=""
            rm -f /tmp/arkime.deb
        fi
    fi

    if [ -n "$ARKIME_DEB" ] && [ -f /tmp/arkime.deb ]; then
        log "Installing Packet Recorder dependencies..."
        sudo apt-get install -y -qq \
            libwww-perl libjson-perl \
            libyaml-dev libyara10 \
            librdkafka1 ethtool \
            libpcre3 libpcre3-dev \
            libmagic1 libmaxminddb0 \
            libpcre2-8-0 \
            libyaml-0-2 > /dev/null 2>&1 || true

        if ! dpkg -l libpcre3 2>/dev/null | grep -q '^ii'; then
            if sudo apt-get install -y -qq libpcre3 > /dev/null 2>&1; then
                log "libpcre3 installed from apt"
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
                        log "libpcre3 installed"
                        PCRE3_INSTALLED=true
                        break
                    fi
                    rm -f /tmp/libpcre3.deb
                done
                $PCRE3_INSTALLED || warn "libpcre3 install failed — capture may crash"
            fi
        fi

        log "Installing Packet Recorder package..."
        if sudo dpkg -i /tmp/arkime.deb 2>&1; then
            log "dpkg install succeeded"
        else
            warn "dpkg reported errors — running apt-get install -f..."
            sudo apt-get install -f -y 2>&1 || true
        fi
        rm -f /tmp/arkime.deb

        if [ -f /opt/arkime/bin/capture ]; then
            ARKIME_VER=$(/opt/arkime/bin/capture --version 2>/dev/null | head -1 || echo "unknown")
            log "Packet Recorder installed: ${ARKIME_VER}"
        else
            warn "Arkime install failed — /opt/arkime/bin/capture not found"
        fi
    else
        warn "Packet Recorder skipped (no package available)"
    fi
else
    ARKIME_VER=$(/opt/arkime/bin/capture --version 2>/dev/null | head -1 || echo "unknown")
    log "Packet Recorder already installed: ${ARKIME_VER}"
fi

# ══════════════════════════════════════════════
step "Agent-Z"

log "Skipped — Agent-Z runs on dedicated remote sensor machines"

# ══════════════════════════════════════════════
step "Analytics Database  (ClickHouse)"

if [ "$DEPLOY_MODE" = "local" ]; then
    log "ClickHouse — Docker container cluster (2 nodes, bridge network)"
    log "  Credentials:  ndr / ndr123"
    log "  Endpoint:     http://localhost:8123  (node 1, localhost-only)"

    CH_NEEDS_IMPORT=false
    if systemctl is-active --quiet clickhouse-server 2>/dev/null; then
        warn "Existing ClickHouse installation detected on this host."
        printf "\n"
        printf "  ${CYAN}┌─────────────────────────────────────────┐${NC}\n"
        printf "  ${CYAN}│${NC}  ${BOLD}Migration Options${NC}                        ${CYAN}│${NC}\n"
        printf "  ${CYAN}├─────────────────────────────────────────┤${NC}\n"
        printf "  ${CYAN}│${NC}  [1] Migrate existing data into Docker   ${CYAN}│${NC}\n"
        printf "  ${CYAN}│${NC}  [2] Fresh start — wipe existing data    ${CYAN}│${NC}\n"
        printf "  ${CYAN}└─────────────────────────────────────────┘${NC}\n"
        printf "\n"
        read -p "  Enter choice [1/2]: " CH_MIGRATE_CHOICE
        printf "\n"

        if [ "$CH_MIGRATE_CHOICE" = "1" ]; then
            log "Exporting existing ClickHouse data..."
            bash "$INSTALL_DIR/scripts/ch-export.sh"
            CH_NEEDS_IMPORT=true
            log "Data exported to /home/user/ch-export/"
        else
            log "Fresh start — existing data will not be migrated"
        fi

        log "Stopping host ClickHouse (Docker takes over)..."
        sudo systemctl stop clickhouse-server
        sudo systemctl disable clickhouse-server
        log "Host ClickHouse stopped and disabled"

        printf "\n"
        read -p "  Uninstall ClickHouse packages from host? [y/N]: " CH_PURGE
        if [[ "$CH_PURGE" =~ ^[Yy]$ ]]; then
            log "Removing ClickHouse packages..."
            if command -v apt-get &>/dev/null; then
                sudo apt-get remove -y clickhouse-server clickhouse-client clickhouse-common-static 2>/dev/null || true
                sudo apt-get autoremove -y 2>/dev/null || true
            elif command -v yum &>/dev/null; then
                sudo yum remove -y clickhouse-server clickhouse-client 2>/dev/null || true
            fi
            log "ClickHouse packages removed — Docker container takes over"
        else
            log "Keeping packages (service remains disabled)"
        fi
    elif ss -tlnp 2>/dev/null | grep -qE ':8123|:9000'; then
        warn "Ports 8123/9000 in use — killing conflicting processes..."
        PIDS=$(ss -tlnp 2>/dev/null | grep -E ':8123|:9000' \
            | grep -oP 'pid=\K[0-9]+' | sort -u)
        if [ -n "$PIDS" ]; then
            for PID in $PIDS; do
                PNAME=$(ps -p "$PID" -o comm= 2>/dev/null || echo "unknown")
                log "  Killing PID $PID ($PNAME) holding ClickHouse ports..."
                sudo kill -9 "$PID" 2>/dev/null || true
            done
            sleep 2
            if ss -tlnp 2>/dev/null | grep -qE ':8123|:9000'; then
                warn "Some ports still in use — containers may conflict"
            else
                log "Ports 8123/9000 are now free"
            fi
        fi
    fi

    CLICKHOUSE_URL="http://localhost:8123"
    CLICKHOUSE_URL_SECONDARY="http://localhost:8123"
    CLOUD_CH_USER="ndr"
    CLOUD_CH_PASS="ndr123"
    CLOUD_KAFKA="kafka1:9092,kafka2:9092,kafka3:9092"
else
    log "Using cloud ClickHouse: $CLOUD_CLICKHOUSE"
    CLICKHOUSE_URL="$CLOUD_CLICKHOUSE"
    info "Skipping local ClickHouse setup"
fi
log "ClickHouse configured"

# ══════════════════════════════════════════════
step "Network & Sensor Configuration"

log "Detecting network interface..."
IFACE=$(ip route get 8.8.8.8 2>/dev/null | awk '{for(i=1;i<=NF;i++) if ($i=="dev") {print $(i+1); exit}}')
if [ -z "$IFACE" ]; then
    IFACE=$(ip -o -4 addr show 2>/dev/null | \
        grep -v "127.0.0.1\|docker\|br-\|veth\| lo " | \
        awk '{print $2}' | head -1)
fi
[ -z "$IFACE" ] && IFACE="eth0"
log "Using interface: $IFACE"
mkdir -p "$RUNTIME_DIR"
echo "$IFACE" > "$IFACE_FILE"

# ── Configure Arkime ──────────────────────────
if [ -f /opt/arkime/bin/capture ]; then
    log "Configuring Packet Recorder..."
    sudo mkdir -p /opt/arkime/raw /opt/arkime/logs /opt/arkime/etc
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

    sudo tee /etc/systemd/system/arkime-capture.service > /dev/null << EOF
[Unit]
Description=Arkime Packet Capture
After=network.target

[Service]
Type=simple
ExecStart=/opt/arkime/bin/capture \\
    -c /opt/arkime/etc/config.ini \\
    -o pcapDir=/opt/arkime/raw \\
    --insecure
Restart=always
RestartSec=10
LimitCORE=infinity
LimitMEMLOCK=infinity

[Install]
WantedBy=multi-user.target
EOF

    sudo tee /etc/systemd/system/arkime-viewer.service > /dev/null << EOF
[Unit]
Description=Arkime Packet Viewer
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/arkime/viewer
ExecStart=/opt/arkime/bin/node \\
    viewer.js \\
    -c /opt/arkime/etc/config.ini
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

    sudo systemctl daemon-reload
    sudo systemctl disable arkime-capture arkime-viewer 2>/dev/null || true
    log "Packet Recorder configured on interface: ${IFACE}"
fi

# ── Firewall ──────────────────────────────────
log "Configuring firewall rules for internal ports..."
INTERNAL_PORTS="8123 9000 2181 3001"
if command -v iptables &>/dev/null; then
    for PORT in $INTERNAL_PORTS; do
        while sudo iptables -D INPUT -p tcp --dport $PORT -i lo      -j ACCEPT 2>/dev/null; do :; done
        while sudo iptables -D INPUT -p tcp --dport $PORT -i docker+ -j ACCEPT 2>/dev/null; do :; done
        while sudo iptables -D INPUT -p tcp --dport $PORT -i br+     -j ACCEPT 2>/dev/null; do :; done
        while sudo iptables -D INPUT -p tcp --dport $PORT            -j DROP   2>/dev/null; do :; done
        sudo iptables -I INPUT -p tcp --dport $PORT -i lo      -j ACCEPT 2>/dev/null || true
        sudo iptables -I INPUT -p tcp --dport $PORT -i docker+ -j ACCEPT 2>/dev/null || true
        sudo iptables -I INPUT -p tcp --dport $PORT -i br+     -j ACCEPT 2>/dev/null || true
        sudo iptables -A INPUT -p tcp --dport $PORT            -j DROP   2>/dev/null || true
    done
    if command -v netfilter-persistent &>/dev/null; then
        sudo netfilter-persistent save 2>/dev/null || true
    elif command -v iptables-save &>/dev/null; then
        sudo mkdir -p /etc/iptables
        sudo iptables-save | sudo tee /etc/iptables/rules.v4 > /dev/null 2>&1 || true
    fi
    log "Firewall: ClickHouse/Keeper blocked externally, Docker+loopback allowed"
else
    warn "iptables not found — manually block ports $INTERNAL_PORTS from external access"
fi

# ── Directories ───────────────────────────────
log "Creating runtime directories..."
mkdir -p "$HOME_DIR/ndr-config"
sudo mkdir -p /opt/ndr/pcap /opt/ndr/evidence
sudo chmod -R 755 /opt/ndr
sudo chown -R "$USER:$USER" /opt/ndr
log "Runtime directories created"

# ── Detect host IP ────────────────────────────
HOST_IP=$(ip -o -4 addr show "$IFACE" 2>/dev/null | awk '{print $4}' | cut -d/ -f1)
[ -z "$HOST_IP" ] && HOST_IP=$(hostname -I | awk '{print $1}')
log "Host IP: $HOST_IP"

# ── JWT & API keys ────────────────────────────
if [ -f "$INSTALL_DIR/.env" ] && grep -q "JWT_SECRET" "$INSTALL_DIR/.env"; then
    JWT_SECRET=$(grep "^JWT_SECRET=" "$INSTALL_DIR/.env" | cut -d= -f2-)
else
    JWT_SECRET=$(openssl rand -hex 32)
fi
if [ -f "$INSTALL_DIR/.env" ] && grep -q "NDR_AGENT_SECRET" "$INSTALL_DIR/.env"; then
    NDR_AGENT_SECRET=$(grep "^NDR_AGENT_SECRET=" "$INSTALL_DIR/.env" | cut -d= -f2-)
else
    NDR_AGENT_SECRET=$(openssl rand -hex 32)
fi

if [ -f "$INSTALL_DIR/.env" ] && grep -q "OPENAI_API_KEY" "$INSTALL_DIR/.env"; then
    OPENAI_API_KEY=$(grep "OPENAI_API_KEY" "$INSTALL_DIR/.env" | cut -d= -f2-)
fi
if [ -z "$OPENAI_API_KEY" ]; then
    printf "\n"
    read -p "  OpenAI API key for ARIA (press Enter to skip): " -r OPENAI_API_KEY
fi

# ── License public key + token (from PromaSecure super admin portal) ─────────
if [ -f "$INSTALL_DIR/.env" ] && grep -q "LICENSE_PUBLIC_KEY" "$INSTALL_DIR/.env"; then
    LICENSE_PUBLIC_KEY=$(grep "^LICENSE_PUBLIC_KEY=" "$INSTALL_DIR/.env" | cut -d= -f2-)
fi
if [ -z "$LICENSE_PUBLIC_KEY" ]; then
    printf "\n"
    printf "  License public key (paste base64 or PEM block, then press Enter twice):\n  "
    _RAW_KEY=""
    while IFS= read -r _line; do
        [ -z "$_line" ] && break
        _RAW_KEY="${_RAW_KEY}${_line}"$'\n'
    done
    # If pasted as PEM block, base64-encode it to a single line for .env storage
    if echo "$_RAW_KEY" | grep -q "BEGIN PUBLIC KEY"; then
        LICENSE_PUBLIC_KEY=$(printf '%s' "$_RAW_KEY" | base64 -w0)
    else
        LICENSE_PUBLIC_KEY=$(printf '%s' "$_RAW_KEY" | tr -d '\n\r ')
    fi
fi

if [ -f "$INSTALL_DIR/.env" ] && grep -q "LICENSE_TOKEN" "$INSTALL_DIR/.env"; then
    LICENSE_TOKEN=$(grep "^LICENSE_TOKEN=" "$INSTALL_DIR/.env" | cut -d= -f2-)
fi
if [ -z "$LICENSE_TOKEN" ]; then
    printf "\n"
    read -p "  License token (paste from your NDR admin portal, press Enter to skip): " -r LICENSE_TOKEN
fi

# ── Tenant admin credentials (provisioned on first engine boot) ──────────
if [ -f "$INSTALL_DIR/.env" ] && grep -q "^TENANT_ADMIN_USER=." "$INSTALL_DIR/.env"; then
    TENANT_ADMIN_USER=$(grep "^TENANT_ADMIN_USER=" "$INSTALL_DIR/.env" | cut -d= -f2-)
fi
if [ -z "$TENANT_ADMIN_USER" ]; then
    printf "\n"
    read -p "  Tenant admin username (e.g. acme-admin): " -r TENANT_ADMIN_USER
fi

if [ -f "$INSTALL_DIR/.env" ] && grep -q "^TENANT_ADMIN_PASS=." "$INSTALL_DIR/.env"; then
    TENANT_ADMIN_PASS=$(grep "^TENANT_ADMIN_PASS=" "$INSTALL_DIR/.env" | cut -d= -f2-)
fi
if [ -z "$TENANT_ADMIN_PASS" ]; then
    printf "\n"
    read -sp "  Tenant admin password: " TENANT_ADMIN_PASS
    echo ""
    read -sp "  Confirm password    : " _PASS_CONFIRM
    echo ""
    [ "$TENANT_ADMIN_PASS" != "$_PASS_CONFIRM" ] && err "Passwords do not match — re-run the installer"
fi

# Auto-extract TENANT_ID from the license token so events are stored under
# the correct tenant, not hardcoded "default".
TENANT_ID="default"
if [ -n "$LICENSE_TOKEN" ]; then
    PAYLOAD=$(echo "$LICENSE_TOKEN" | cut -d. -f2)
    # JWT uses base64url (- and _ instead of + and /); add padding if needed
    PADDED=$(echo "$PAYLOAD" | tr '_-' '/+')
    case $(( ${#PAYLOAD} % 4 )) in
        2) PADDED="${PADDED}==" ;;
        3) PADDED="${PADDED}=" ;;
    esac
    EXTRACTED=$(echo "$PADDED" | base64 -d 2>/dev/null \
        | python3 -c "import json,sys; print(json.load(sys.stdin).get('tenant_id','default'))" 2>/dev/null \
        || echo "default")
    if [ -n "$EXTRACTED" ]; then
        TENANT_ID="$EXTRACTED"
        log "Tenant ID from license: $TENANT_ID"
    fi
fi

cat > "$INSTALL_DIR/.env" << ENVEOF
HOST_IP=$HOST_IP
HOME_DIR=$HOME_DIR
INSTALL_DIR=$INSTALL_DIR
IFACE=$IFACE
DEPLOY_MODE=$DEPLOY_MODE
LOCAL_SENSOR_ID=local-central
TENANT_ID=$TENANT_ID
CLICKHOUSE_URL=$CLICKHOUSE_URL
CLICKHOUSE_URL_SECONDARY=$CLICKHOUSE_URL_SECONDARY
CLICKHOUSE_USER=$CLOUD_CH_USER
CLICKHOUSE_PASSWORD=$CLOUD_CH_PASS
KAFKA_BROKERS=$CLOUD_KAFKA
JWT_SECRET=$JWT_SECRET
NDR_AGENT_SECRET=$NDR_AGENT_SECRET
CORS_ORIGIN=https://${HOST_IP}:3000
ARKIME_URL=http://${HOST_IP}:8005
ARKIME_PASS=$ARKIME_PASS
OPENSEARCH_URL=http://${HOST_IP}:9200
OPENAI_API_KEY=$OPENAI_API_KEY
GROQ_API_KEY=
GROQ_MODEL=llama-3.3-70b-versatile
BEACON_WINDOW_HOURS=1
INGEST_RATE_LIMIT=50000
SIEM_SYSLOG_HOST=
SIEM_SYSLOG_PORT=514
LICENSE_PUBLIC_KEY=$LICENSE_PUBLIC_KEY
LICENSE_TOKEN=$LICENSE_TOKEN
TENANT_ADMIN_USER=$TENANT_ADMIN_USER
TENANT_ADMIN_PASS=$TENANT_ADMIN_PASS
ENVEOF
log ".env generated"

# ── Sudoers ───────────────────────────────────
log "Configuring sudo permissions..."
cat << SUDOERS | sudo tee /etc/sudoers.d/ndr-stack > /dev/null
# NDR platform — restricted sudo for platform services only
Cmnd_Alias NDR_SYSTEMCTL = /usr/bin/systemctl daemon-reload, /usr/bin/systemctl start ndr-autoscaler, /usr/bin/systemctl stop ndr-autoscaler, /usr/bin/systemctl restart ndr-autoscaler, /usr/bin/systemctl enable ndr-autoscaler, /usr/bin/systemctl disable ndr-autoscaler, /usr/bin/systemctl start ndr-worker-autoscaler, /usr/bin/systemctl stop ndr-worker-autoscaler, /usr/bin/systemctl restart ndr-worker-autoscaler, /usr/bin/systemctl enable ndr-worker-autoscaler, /usr/bin/systemctl disable ndr-worker-autoscaler, /usr/bin/systemctl start ndr-updater, /usr/bin/systemctl stop ndr-updater, /usr/bin/systemctl restart ndr-updater, /usr/bin/systemctl enable ndr-updater, /usr/bin/systemctl start arkime-capture, /usr/bin/systemctl stop arkime-capture, /usr/bin/systemctl restart arkime-capture, /usr/bin/systemctl start arkime-viewer, /usr/bin/systemctl stop arkime-viewer, /usr/bin/systemctl restart arkime-viewer
Cmnd_Alias NDR_TEE       = /usr/bin/tee /etc/systemd/system/ndr-autoscaler.service, /usr/bin/tee /etc/systemd/system/ndr-worker-autoscaler.service
Cmnd_Alias NDR_IPTABLES  = /usr/sbin/iptables
$USERNAME ALL=(ALL)  NOPASSWD: NDR_SYSTEMCTL, NDR_TEE
$USERNAME ALL=(root) NOPASSWD: NDR_IPTABLES
SUDOERS
sudo chmod 440 /etc/sudoers.d/ndr-stack
log "Sudo configured"

log "NDR Agent skipped — Agent-S/Agent-Z run on remote sensor machines"

# ══════════════════════════════════════════════
step "Dashboard UI  (Angular)"

log "UI image will be pulled after container runtime is ready"

# ══════════════════════════════════════════════
step "Container Runtime  (Docker)"

log "Installing Docker..."
sudo apt-get remove -y docker docker-engine docker.io containerd runc 2>/dev/null || true
sudo apt-get update -qq 2>/dev/null || true
sudo apt-get install -y ca-certificates curl gnupg lsb-release

sudo mkdir -p /etc/apt/keyrings
sudo rm -f /etc/apt/keyrings/docker.gpg
curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
    | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

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
sudo apt-get update -qq 2>/dev/null || true
sudo apt-get install -y docker-ce docker-ce-cli \
    containerd.io docker-buildx-plugin docker-compose-plugin
log "Docker installed"

sudo mkdir -p /etc/docker
sudo tee /etc/docker/daemon.json > /dev/null << 'DOCKEREOF'
{
  "dns": ["8.8.8.8", "8.8.4.4"]
}
DOCKEREOF

sudo modprobe overlay 2>/dev/null || true
sudo modprobe br_netfilter 2>/dev/null || true
echo -e "overlay\nbr_netfilter" | sudo tee /etc/modules-load.d/docker.conf > /dev/null

log "Starting Docker service..."
sudo systemctl enable docker
sudo systemctl start docker || true
sudo usermod -aG docker "$USERNAME"
# Socket stays at default 660 (root:docker) — engine containers run as root and have access

log "Waiting for Docker to initialize..."
for i in {1..20}; do
    if sudo docker info >/dev/null 2>&1; then
        log "Docker is running"
        break
    fi
    [ $i -eq 10 ] && sudo systemctl restart docker || true
    echo -n "."
    sleep 3
done
echo ""
sudo docker info >/dev/null 2>&1 || err "Docker failed to start"

# ══════════════════════════════════════════════
step "Detection Stack  (Building)"

log "Building Docker stack (this may take a few minutes)..."
cd "$INSTALL_DIR"

# ── TLS certificate for Nginx ─────────────────────────────────────────────────
# Generated once before Docker starts so Nginx can find it at /etc/nginx/ssl/.
# Skipped automatically if a cert already exists (e.g. CA-signed cert placed by admin).
SSL_DIR="$INSTALL_DIR/config/nginx/ssl"
if [ ! -f "$SSL_DIR/ndr.crt" ] || [ ! -f "$SSL_DIR/ndr.key" ]; then
    log "Generating self-signed TLS certificate for $HOST_IP..."
    mkdir -p "$SSL_DIR"
    openssl req -x509 -nodes -days 730 -newkey rsa:2048 \
        -keyout "$SSL_DIR/ndr.key" \
        -out    "$SSL_DIR/ndr.crt" \
        -subj   "/CN=$HOST_IP" \
        -addext "subjectAltName=IP:$HOST_IP,IP:127.0.0.1,DNS:localhost" \
        2>/dev/null
    chmod 600 "$SSL_DIR/ndr.key"
    log "✅ TLS certificate generated → $SSL_DIR"
else
    log "TLS certificate already exists — skipping generation"
fi
# ─────────────────────────────────────────────────────────────────────────────

# Write customer nginx.conf — same as default but adds location / → ndr-ui
log "Writing customer nginx config..."
mkdir -p "$INSTALL_DIR/config/nginx"
cat > "$INSTALL_DIR/config/nginx/nginx.conf" << 'NGINXEOF'
events {
    worker_connections 1024;
}

http {
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;

    resolver 127.0.0.11 valid=5s ipv6=off;
    resolver_timeout 5s;

    upstream clickhouse_pool {
        least_conn;
        server clickhouse1:8123 max_fails=2 fail_timeout=10s;
        server clickhouse2:8123 max_fails=2 fail_timeout=10s backup;
    }

    server {
        listen 8123;
        location / {
            proxy_pass         http://clickhouse_pool;
            proxy_set_header   Host $host;
            proxy_set_header   X-Real-IP $remote_addr;
            proxy_connect_timeout 3s;
            proxy_read_timeout    60s;
            proxy_next_upstream   error timeout http_502 http_503;
        }
    }

    upstream ndr_engines {
        least_conn;
        server ndr-engine-1:3000 max_fails=3 fail_timeout=30s;
        server ndr-engine-2:3000 max_fails=3 fail_timeout=30s;
        server ndr-engine-3:3000 max_fails=3 fail_timeout=30s;
        # ENGINES_MARKER
    }

    upstream ws_engines {
        ip_hash;
        server ndr-engine-1:3000;
        server ndr-engine-2:3000;
        server ndr-engine-3:3000;
        # WS_ENGINES_MARKER
    }

    server {
        listen 80;
        server_name _;
        return 301 https://$host$request_uri;
    }

    server {
        listen 443 ssl;
        client_max_body_size 100m;

        ssl_certificate     /etc/nginx/ssl/ndr.crt;
        ssl_certificate_key /etc/nginx/ssl/ndr.key;

        ssl_protocols       TLSv1.2 TLSv1.3;
        ssl_ciphers         HIGH:!aNULL:!MD5;
        ssl_session_cache   shared:SSL:10m;
        ssl_session_timeout 10m;

        add_header X-Frame-Options        "SAMEORIGIN"  always;
        add_header X-Content-Type-Options "nosniff"     always;
        add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
        add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self' wss: ws: https:; worker-src 'self' blob:;" always;

        location /ws {
            proxy_pass         http://ws_engines;
            proxy_http_version 1.1;
            proxy_set_header   Upgrade $http_upgrade;
            proxy_set_header   Connection "upgrade";
            proxy_set_header   Host $host;
            proxy_read_timeout 3600s;
        }

        location /api {
            proxy_pass         http://ndr_engines;
            proxy_set_header   Host $host;
            proxy_set_header   X-Real-IP $remote_addr;
            proxy_set_header   X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header   X-Forwarded-Proto $scheme;
        }

        location /health {
            proxy_pass http://ndr_engines;
        }

        # UI — served by the ndr-ui container (nginx + Angular SPA)
        location / {
            proxy_pass         http://ndr-ui:80;
            proxy_http_version 1.1;
            proxy_set_header   Host $host;
            proxy_set_header   X-Real-IP $remote_addr;
            proxy_set_header   X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header   X-Forwarded-Proto $scheme;
            proxy_read_timeout 60s;
        }
    }
}
NGINXEOF
log "Customer nginx config written"

sudo docker compose --profile onpremise down 2>/dev/null || true
sudo docker rm -f vector 2>/dev/null || true

log "Pulling pre-built images..."
sudo docker pull "${REGISTRY}/ndr-engine:latest"
sudo docker pull "${REGISTRY}/ndr-ui:latest"

# Write a compose override that replaces build: with the pre-built image
cat > "$INSTALL_DIR/docker-compose.customer.yml" << OVERRIDE
services:
  ndr-engine-1:
    image: ${REGISTRY}/ndr-engine:latest
  ndr-engine-2:
    image: ${REGISTRY}/ndr-engine:latest
  ndr-engine-3:
    image: ${REGISTRY}/ndr-engine:latest
  ndr-ui:
    image: ${REGISTRY}/ndr-ui:latest
    build: !reset null
OVERRIDE

if [ "$DEPLOY_MODE" = "hybrid" ]; then
    log "Hybrid mode — using cloud: $CLOUD_KAFKA"
    sudo docker compose -f docker-compose.yml -f docker-compose.customer.yml \
        --profile onpremise up -d vector ndr-engine-1 nginx ndr-ui
else
    sudo docker compose -f docker-compose.yml -f docker-compose.customer.yml \
        --profile onpremise up -d
fi
log "Docker stack started"

if [ "$DEPLOY_MODE" = "local" ]; then
    log "Waiting for ClickHouse node 1..."
    for i in {1..40}; do
        if curl -s http://localhost:8123/ping > /dev/null 2>&1; then
            log "ClickHouse node 1 ready"
            break
        fi
        echo -n "."
        sleep 3
    done
    echo ""

    if [ "${CH_NEEDS_IMPORT:-false}" = "true" ] && [ -d "/home/user/ch-export" ]; then
        log "Importing exported ClickHouse data into Docker container..."
        bash "$INSTALL_DIR/scripts/ch-import.sh"
        log "Data migration complete"
    fi
fi

log "Configuring Kafka retention..."
sleep 15
sudo docker exec kafka1 \
    /opt/kafka/bin/kafka-configs.sh \
    --bootstrap-server localhost:9092 \
    --alter --entity-type topics \
    --entity-name ndr-events \
    --add-config retention.ms=86400000 \
    2>/dev/null || true
log "Kafka retention set to 24 hours"

log "Creating Kafka topic with 3 partitions..."
sudo docker exec kafka1 /opt/kafka/bin/kafka-topics.sh \
    --bootstrap-server localhost:9092 \
    --create --if-not-exists \
    --topic ndr-events \
    --partitions 3 \
    --replication-factor 3 \
    2>/dev/null || true
log "Kafka topic ready"

# ══════════════════════════════════════════════
step "Search Index  (OpenSearch)"

log "Waiting for OpenSearch..."
cd "$INSTALL_DIR"
for i in {1..30}; do
    if curl -s http://localhost:9200 > /dev/null 2>&1; then
        log "OpenSearch ready"
        break
    fi
    echo -n "."
    sleep 3
done
echo ""

if [ -f /opt/arkime/bin/capture ]; then
    log "Initializing Packet Recorder database..."
    echo "yes" | sudo timeout 60 /opt/arkime/db/db.pl http://localhost:9200 init --ifneeded 2>&1 || \
        echo "yes" | sudo timeout 60 /opt/arkime/db/db.pl http://localhost:9200 init 2>&1 || true
    log "Packet Recorder database initialized"
    log "Creating Packet Recorder admin user..."
    sudo /opt/arkime/bin/arkime_add_user.sh admin "Admin" admin --admin 2>/dev/null \
        && log "Packet Recorder admin ready (user: admin / pass: admin)" \
        || warn "Packet Recorder admin creation failed — run manually after install"
fi

# ══════════════════════════════════════════════
step "Response Automation  (SOAR)"

log "Native SOAR is built into the NDR engine — no extra services needed"
info "Configure playbooks, cases and integrations from the UI → SOAR page"

log "Skipped — UI runs from ndr-ui Docker container (no Node.js/Angular build needed)"

log "Waiting for ndr-ui container to be ready..."
for i in {1..30}; do
    if sudo docker exec ndr-ui curl -s http://localhost:80 > /dev/null 2>&1; then
        log "ndr-ui container ready"
        break
    fi
    echo -n "."
    sleep 3
done
echo ""

if grep -qi microsoft /proc/version 2>/dev/null; then
    warn "WSL2 detected — run in Windows PowerShell as Admin:"
    printf "\n"
    echo "  netsh interface portproxy add v4tov4 listenport=3000 listenaddress=0.0.0.0 connectport=3000 connectaddress=$HOST_IP"
    echo "  netsh interface portproxy add v4tov4 listenport=9092 listenaddress=0.0.0.0 connectport=9092 connectaddress=$HOST_IP"
    printf "\n"
fi

# ── NDR Updater: host-side watcher that applies engine/UI updates ─────
log "Installing NDR update watcher..."

cat > "$INSTALL_DIR/scripts/update-watcher.sh" << 'WATCHEREOF'
#!/bin/bash
# Host-side update watcher. Runs as a systemd service.
# The ndr-engine container writes /scripts/.update-requested (same path as
# ${INSTALL_DIR}/scripts/.update-requested on the host) to trigger an update.
REGISTRY="ghcr.io/jithinjoseph-workspace"
INSTALL_DIR="$(dirname "$(dirname "$(realpath "$0")")")"
FLAG="$INSTALL_DIR/scripts/.update-requested"

while true; do
    if [ -f "$FLAG" ]; then
        TARGET_VERSION=$(cat "$FLAG" 2>/dev/null || echo "")
        rm -f "$FLAG"
        logger -t ndr-updater "Update triggered → pulling ${TARGET_VERSION:-latest}"
        cd "$INSTALL_DIR" || exit 1
        docker pull "${REGISTRY}/ndr-engine:latest" 2>&1 | logger -t ndr-updater
        docker pull "${REGISTRY}/ndr-ui:latest"     2>&1 | logger -t ndr-updater
        docker compose -f docker-compose.yml -f docker-compose.customer.yml \
            --profile onpremise up -d --no-build    2>&1 | logger -t ndr-updater
        logger -t ndr-updater "Update complete"
    fi
    sleep 30
done
WATCHEREOF
chmod +x "$INSTALL_DIR/scripts/update-watcher.sh"

sudo tee /etc/systemd/system/ndr-updater.service > /dev/null << EOF
[Unit]
Description=NDR Update Watcher
After=docker.service
Requires=docker.service

[Service]
Type=simple
ExecStart=$INSTALL_DIR/scripts/update-watcher.sh
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo tee /etc/systemd/system/ndr.service > /dev/null << EOF
[Unit]
Description=NDR Platform
After=docker.service network-online.target
Requires=docker.service
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=$INSTALL_DIR
ExecStart=/bin/bash $INSTALL_DIR/start.sh
ExecStop=/bin/bash $INSTALL_DIR/stop.sh
TimeoutStartSec=300

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable ndr.service
sudo systemctl enable --now ndr-updater.service
log "NDR auto-start on boot enabled"
log "NDR update watcher installed and running"

# ══════════════════════════════════════════════
step "Verification"

log "Verifying installation..."
info "Mode:       $DEPLOY_MODE"
info "Interface:  $IFACE  ($HOST_IP)"
info "Sensors:    remote (install-sensor.sh on probe machines)"
info "Docker:     $(sudo docker --version)"
info "ndr-ui:     $(sudo docker inspect --format='{{.State.Status}}' ndr-ui 2>/dev/null || echo 'not started')"
if [ "$DEPLOY_MODE" = "local" ]; then
    info "ClickHouse: $(curl -s http://localhost:8123/ping 2>/dev/null || echo 'starting...')"
else
    info "ClickHouse: $CLOUD_CLICKHOUSE  (cloud)"
    info "Kafka:      $CLOUD_KAFKA  (cloud)"
fi
info "NDR Agent:  $(curl -s http://localhost:3001/agent/status 2>/dev/null || echo 'starting...')"

# ── Completion banner ─────────────────────────
_pad() { printf '%-44s' "$1"; }

printf "\n\n"
printf "  ${CYAN}╔══════════════════════════════════════════════╗${NC}\n"
printf "  ${CYAN}║${NC}                                              ${CYAN}║${NC}\n"
printf "  ${CYAN}║${NC}  ${GREEN}${BOLD}      INSTALLATION COMPLETE               ${NC}  ${CYAN}║${NC}\n"
printf "  ${CYAN}║${NC}  ${DIM}         Proma Alpha v1.0  —  Proma Secure  ${NC}  ${CYAN}║${NC}\n"
printf "  ${CYAN}║${NC}                                              ${CYAN}║${NC}\n"
printf "  ${CYAN}╠══════════════════════════════════════════════╣${NC}\n"
printf "  ${CYAN}║${NC}  $(_pad "Mode:       ${DEPLOY_MODE}")${CYAN}║${NC}\n"
printf "  ${CYAN}║${NC}  $(_pad "Interface:  ${IFACE}  (${HOST_IP})")${CYAN}║${NC}\n"
printf "  ${CYAN}╠══════════════════════════════════════════════╣${NC}\n"
printf "  ${CYAN}║${NC}  ${BOLD}$(_pad "Service         Access Point")${NC}  ${CYAN}║${NC}\n"
printf "  ${CYAN}║${NC}  ${DIM}$(_pad "─────────────── ────────────────────────")${NC}  ${CYAN}║${NC}\n"
printf "  ${CYAN}║${NC}  $(_pad "Dashboard       https://${HOST_IP}:3000")${CYAN}║${NC}\n"
printf "  ${CYAN}║${NC}  $(_pad "API Gateway     https://${HOST_IP}:3000")${CYAN}║${NC}\n"
printf "  ${CYAN}║${NC}  $(_pad "NDR Agent       http://localhost:3001")${CYAN}║${NC}\n"
printf "  ${CYAN}║${NC}  $(_pad "Packet Recorder http://localhost:8005")${CYAN}║${NC}\n"
printf "  ${CYAN}╠══════════════════════════════════════════════╣${NC}\n"
printf "  ${CYAN}║${NC}  $(_pad "start:    ./start.sh")${CYAN}║${NC}\n"
printf "  ${CYAN}║${NC}  $(_pad "stop:     ./stop.sh")${CYAN}║${NC}\n"
printf "  ${CYAN}║${NC}  $(_pad "status:   ./status.sh")${CYAN}║${NC}\n"
printf "  ${CYAN}╚══════════════════════════════════════════════╝${NC}\n"
printf "\n"
printf "  ${DIM}Proma Secure — Network Detection & Response Platform${NC}\n\n"
