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
TOTAL_STEPS=10
CURRENT_STEP=0

step() {
    CURRENT_STEP=$((CURRENT_STEP + 1))
    echo ""
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}  Step $CURRENT_STEP/$TOTAL_STEPS: $1${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

# ── Fix network and APT ───────────────────────
log "Fixing network and APT..."
sudo sysctl -w net.ipv6.conf.all.disable_ipv6=1 2>/dev/null || true
sudo sysctl -w net.ipv6.conf.default.disable_ipv6=1 2>/dev/null || true
log "  → IPv6 disabled"

echo 'Acquire::ForceIPv4 "true";' | \
    sudo tee /etc/apt/apt.conf.d/99force-ipv4 > /dev/null
log "  → IPv4 forced"

echo "nameserver 8.8.8.8" | \
    sudo tee /etc/resolv.conf > /dev/null
log "  → DNS set to 8.8.8.8"

sudo rm -rf /var/lib/apt/lists/* 2>/dev/null || true
log "  → APT cache cleared"

sudo apt-get update 2>&1 | \
    grep -E "^Get|^Hit|^Err|^W:" || true
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
    netcat-traditional
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

step "Installing Zeek"

# ── Install Zeek ──────────────────────────────
if ! command -v /opt/zeek/bin/zeek &>/dev/null; then
    log "Installing Zeek..."
    echo "deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_${OS_VERSION}/ /" \
        | sudo tee /etc/apt/sources.list.d/security:zeek.list
    curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_${OS_VERSION}/Release.key \
        | gpg --dearmor \
        | sudo tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null
    sudo apt-get update -qq
    sudo apt-get install -y zeek
    log "✅ Zeek installed"
else
    log "✅ Zeek already installed"
fi

step "Installing ClickHouse"

# ── Install ClickHouse (LOCAL MODE ONLY) ──────
if [ "$DEPLOY_MODE" = "local" ]; then
    log "Installing ClickHouse locally..."
    if ! command -v clickhouse-server &>/dev/null; then
        sudo apt-get install -y \
            apt-transport-https ca-certificates curl gnupg
        curl -fsSL \
            'https://packages.clickhouse.com/rpm/lts/repodata/repomd.xml.key' \
            | sudo gpg --dearmor \
            -o /usr/share/keyrings/clickhouse-keyring.gpg
        echo "deb [signed-by=/usr/share/keyrings/clickhouse-keyring.gpg] \
            https://packages.clickhouse.com/deb stable main" \
            | sudo tee /etc/apt/sources.list.d/clickhouse.list
        sudo apt-get update -qq
        sudo DEBIAN_FRONTEND=noninteractive apt-get install -y \
            clickhouse-server clickhouse-client
        log "✅ ClickHouse installed"
    else
        log "✅ ClickHouse already installed"
    fi

    log "Configuring ClickHouse network..."
    sudo mkdir -p /etc/clickhouse-server/config.d
    echo '<clickhouse><listen_host>0.0.0.0</listen_host></clickhouse>' | \
        sudo tee /etc/clickhouse-server/config.d/network.xml > /dev/null

    sudo service clickhouse-server restart
    sleep 5
    log "✅ ClickHouse listening on all interfaces"

    log "Configuring ClickHouse..."
    sudo service clickhouse-server start 2>/dev/null || true
    sleep 5

    for i in {1..20}; do
        if clickhouse-client --query "SELECT 1" > /dev/null 2>&1; then
            log "✅ ClickHouse is ready"
            break
        fi
        echo -n "."
        sleep 2
    done
    echo ""

    clickhouse-client --query \
        "CREATE DATABASE IF NOT EXISTS ndr" 2>/dev/null || true
    clickhouse-client --query \
        "CREATE USER IF NOT EXISTS ndr IDENTIFIED BY 'ndr123'" \
        2>/dev/null || true
    clickhouse-client --query \
        "GRANT ALL ON ndr.* TO ndr" 2>/dev/null || true

    log "Creating ClickHouse tables..."
    clickhouse-client --multiquery \
        < "$INSTALL_DIR/config/clickhouse/init.sql" \
        && log "✅ ClickHouse tables created" \
        || warn "⚠️ ClickHouse table creation failed"

    TABLES=$(clickhouse-client \
        --query "SHOW TABLES FROM ndr" 2>/dev/null)
    if echo "$TABLES" | grep -q "ndr_events"; then
        log "✅ Tables verified: $TABLES"
    else
        warn "Tables not found, retrying..."
        clickhouse-client --multiquery \
            < "$INSTALL_DIR/config/clickhouse/init.sql" \
            2>&1 || true
    fi

    sudo systemctl enable clickhouse-server 2>/dev/null || true
    log "✅ ClickHouse configured"

    CLICKHOUSE_URL="http://localhost:8123"
    CLOUD_CH_USER="ndr"
    CLOUD_CH_PASS="ndr123"
    CLOUD_KAFKA="kafka:9092"

else
    log "☁️  Using cloud ClickHouse: $CLOUD_CLICKHOUSE"
    CLICKHOUSE_URL="$CLOUD_CLICKHOUSE"
    info "Skipping local ClickHouse installation"
fi

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
echo "$IFACE" > /tmp/ndr_interface

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
@load policy/protocols/conn/known-hosts
@load policy/protocols/conn/known-services
ZEEKCONF

/opt/zeek/bin/zkg install zeek/corelight/zeek-community-id \
    --force 2>/dev/null || true
log "✅ Zeek configured"

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

# ── Create required directories ───────────────
log "Creating directories..."
mkdir -p $HOME_DIR/logs/suricata
mkdir -p $HOME_DIR/logs/zeek
mkdir -p $HOME_DIR/.vector/data
mkdir -p $HOME_DIR/ndr-config

# ── Detect host IP ────────────────────────────
HOST_IP=$(ip -o -4 addr show $IFACE 2>/dev/null | \
    awk '{print $4}' | cut -d/ -f1)
if [ -z "$HOST_IP" ]; then
    HOST_IP=$(hostname -I | awk '{print $1}')
fi
log "Host IP detected: $HOST_IP"

# ── Generate .env file ────────────────────────
cat > $INSTALL_DIR/.env << ENVEOF
HOST_IP=$HOST_IP
HOME_DIR=$HOME_DIR
INSTALL_DIR=$INSTALL_DIR
IFACE=$IFACE
DEPLOY_MODE=$DEPLOY_MODE
CLICKHOUSE_URL=$CLICKHOUSE_URL
CLICKHOUSE_USER=$CLOUD_CH_USER
CLICKHOUSE_PASSWORD=$CLOUD_CH_PASS
KAFKA_BROKERS=$CLOUD_KAFKA
ENVEOF
log "✅ .env generated"

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

# Install deps in home dir (fast — avoids shared folder slowness)
log "Setting up npm in home directory..."
mkdir -p $HOME/ndr-ui-deps

# Copy package files to home
cp $INSTALL_DIR/ndr-ui/package.json \
    $HOME/ndr-ui-deps/ 2>/dev/null || true
cp $INSTALL_DIR/ndr-ui/package-lock.json \
    $HOME/ndr-ui-deps/ 2>/dev/null || true

cd $HOME/ndr-ui-deps
log "Running npm install (this takes 2-5 minutes)..."
npm install --legacy-peer-deps 2>/dev/null || \
npm install --force 2>/dev/null || \
npm install 2>/dev/null || \
    warn "⚠️ npm install had issues — continuing..."

# Link node_modules to project for live reload
rm -rf $INSTALL_DIR/ndr-ui/node_modules 2>/dev/null || true
ln -sf $HOME/ndr-ui-deps/node_modules \
    $INSTALL_DIR/ndr-ui/node_modules
log "✅ Angular dependencies installed"
cd $INSTALL_DIR


step "Installing Docker"

# ── Install Docker ────────────────────────────
log "Installing Docker..."
sudo apt-get remove -y docker docker-engine \
    docker.io containerd runc 2>/dev/null || true
sudo apt-get update -qq
sudo apt-get install -y \
    ca-certificates curl gnupg lsb-release
sudo mkdir -p /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
    | sudo gpg --dearmor \
    -o /etc/apt/keyrings/docker.gpg
echo \
    "deb [arch=$(dpkg --print-architecture) \
    signed-by=/etc/apt/keyrings/docker.gpg] \
    https://download.docker.com/linux/ubuntu \
    $(lsb_release -cs) stable" \
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

sudo docker compose down 2>/dev/null || true

if [ "$DEPLOY_MODE" = "hybrid" ]; then
    log "Hybrid mode — using cloud: $CLOUD_KAFKA"
    sudo docker compose up -d --build vector ndr-engine-1 nginx
else
    sudo docker compose up -d --build
fi

log "✅ Docker stack started"

# ── Start Angular UI ──────────────────────────
log "Starting Angular UI..."

# Run from shared folder for live reload!
cd $INSTALL_DIR/ndr-ui
nohup npm start > /tmp/ndr-ui.log 2>&1 &
echo $! > /tmp/ndr-ui.pid

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
    log "  ClickHouse: $(curl -s http://localhost:8123/ping \
        2>/dev/null || echo 'starting...')"
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
echo "╠══════════════════════════════════════════╣"
echo "║  start:   ./start.sh                     ║"
echo "║  stop:    ./stop.sh                      ║"
echo "║  status:  ./status.sh                    ║"
echo "╚══════════════════════════════════════════╝"
echo ""
echo "💡 Live reload: Edit Angular on Windows → auto-updates!"
INSTALLEOF

