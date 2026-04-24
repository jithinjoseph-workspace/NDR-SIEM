#!/bin/bash
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log()  { echo -e "${GREEN}[NDR]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
err()  { echo -e "${RED}[ERR]${NC} $1"; exit 1; }

echo ""
echo "╔══════════════════════════════════════════╗"
echo "║        NDR Stack Installer v1.0          ║"
echo "║  Zeek + Suricata + Kafka + Rust + UI     ║"
echo "╚══════════════════════════════════════════╝"
echo ""

# ── Check OS ──────────────────────────────────
. /etc/os-release
log "Detected OS: $NAME $VERSION_ID"
[[ "$ID" != "ubuntu" ]] && warn "Only Ubuntu tested. Proceed with caution."

USERNAME=$(whoami)
HOME_DIR=$HOME
INSTALL_DIR=$(cd "$(dirname "$0")" && pwd)

log "Installing to: $INSTALL_DIR"
log "Running as:    $USERNAME"

# ── Install system dependencies ───────────────
log "Installing system dependencies..."
sudo apt-get update -qq
sudo apt-get install -y -qq \
    curl wget git jq python3 \
    net-tools iproute2 \
    docker.io \
    netcat-traditional 2>/dev/null || true

# ── Install docker compose plugin ─────────────
if ! docker compose version &>/dev/null 2>&1; then
    log "Installing docker compose plugin..."
    sudo apt-get install -y docker-compose-plugin 2>/dev/null || \
    sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" \
        -o /usr/local/bin/docker-compose && sudo chmod +x /usr/local/bin/docker-compose
fi

# ── Add user to docker group ──────────────────
sudo usermod -aG docker $USERNAME 2>/dev/null || true

# ── Install Suricata ──────────────────────────
if ! command -v suricata &>/dev/null; then
    log "Installing Suricata..."
    sudo add-apt-repository -y ppa:oisf/suricata-stable 2>/dev/null
    sudo apt-get update -qq
    sudo apt-get install -y suricata
    log "Updating Suricata rules..."
    sudo suricata-update 2>/dev/null || true
    sudo systemctl disable suricata 2>/dev/null || true
    sudo systemctl stop suricata 2>/dev/null || true
    log " Suricata installed"
else
    log "✅ Suricata already installed"
    sudo systemctl disable suricata 2>/dev/null || true
    sudo systemctl stop suricata 2>/dev/null || true
fi
OS_VERSION=$(echo $VERSION_ID | cut -d'.' -f1,2)




# ── Install Zeek ──────────────────────────────
if ! command -v /opt/zeek/bin/zeek &>/dev/null; then
    log "Installing Zeek..."
    echo "Using Zeek repo for Ubuntu $OS_VERSION"
    echo "deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_${OS_VERSION}/ /" \
    | sudo tee /etc/apt/sources.list.d/security:zeek.list
    curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_${OS_VERSION}/Release.key \
        | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null
    sudo apt-get update -qq
    sudo apt-get install -y zeek
    log "✅ Zeek installed"
else
    log "✅ Zeek already installed"
fi


# ── Install ClickHouse ────────────────────────
log "Installing ClickHouse..."
if ! command -v clickhouse-server &>/dev/null; then
    sudo apt-get install -y apt-transport-https ca-certificates curl gnupg

    curl -fsSL 'https://packages.clickhouse.com/rpm/lts/repodata/repomd.xml.key' \
        | sudo gpg --dearmor -o /usr/share/keyrings/clickhouse-keyring.gpg

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

# ── Configure ClickHouse ──────────────────────
log "Configuring ClickHouse..."
sudo service clickhouse-server start
sleep 5

# Create NDR user and database
clickhouse-client --multiquery << 'CHSQL'
CREATE DATABASE IF NOT EXISTS ndr;
CREATE USER IF NOT EXISTS ndr IDENTIFIED BY 'ndr123';
GRANT ALL ON ndr.* TO ndr;
CHSQL

# Create tables
clickhouse-client --user=ndr --password=ndr123 \
    --multiquery \
    < $INSTALL_DIR/config/clickhouse/init.sql \
    && log "✅ ClickHouse tables created" \
    || warn "⚠️ ClickHouse table creation failed"

# Enable ClickHouse on boot
sudo systemctl enable clickhouse-server 2>/dev/null || true
log "✅ ClickHouse configured"


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

# JSON logging (required for Vector/Kafka pipeline)
@load policy/tuning/json-logs.zeek

# Community ID (required for Zeek-Suricata correlation)
@load policy/protocols/conn/community-id-logging

# Protocol detection
@load protocols/ssh/detect-bruteforcing
@load protocols/ssl/validate-certs
@load protocols/http/detect-sqli
@load protocols/http/detect-webapps
@load misc/detect-traceroute

# File analysis
@load frameworks/files/hash-all-files
@load frameworks/files/detect-MHR

# Known hosts/services tracking
@load policy/frameworks/software/vulnerable
@load policy/frameworks/software/version-changes
@load policy/protocols/conn/known-hosts
@load policy/protocols/conn/known-services

# Security
redef digest_salt = "ndr-stack-$(hostname)-$(date +%s)";
ZEEKCONF

# Install Zeek community ID package
/opt/zeek/bin/zkg install zeek/corelight/zeek-community-id \
    --force 2>/dev/null || true

log "✅ Zeek configured"

# ── Configure Suricata ────────────────────────
log "Configuring Suricata..."

# Backup original config
sudo cp /etc/suricata/suricata.yaml \
    /etc/suricata/suricata.yaml.bak 2>/dev/null || true

# Enable community ID
sudo sed -i 's/community-id: false/community-id: true/g' \
    /etc/suricata/suricata.yaml

# Set log directory
sudo sed -i \
    "s|default-log-dir: /var/log/suricata|default-log-dir: $HOME_DIR/logs/suricata|g" \
    /etc/suricata/suricata.yaml

# Set correct interface
sudo sed -i "s|interface: eth0|interface: $IFACE|g" \
    /etc/suricata/suricata.yaml

# Update Suricata rules
log "Updating Suricata rules (this takes a few minutes)..."
sudo suricata-update 2>/dev/null || true

log "✅ Suricata configured on interface: $IFACE"

# ── Install Node.js ───────────────────────────
if ! command -v node &>/dev/null; then
    log "Installing Node.js..."
    curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
    sudo apt-get install -y nodejs
    log "✅ Node.js installed: $(node --version)"
else
    log "✅ Node.js already installed: $(node --version)"
fi

# ── Create required directories ───────────────
log "Creating directories..."
mkdir -p $HOME_DIR/logs/suricata
mkdir -p $HOME_DIR/logs/zeek
mkdir -p $HOME_DIR/.vector/data
mkdir -p $HOME_DIR/ndr-config

# ── Detect host IP ────────────────────────────
HOST_IP=$(ip -o -4 addr show $IFACE 2>/dev/null | awk '{print $4}' | cut -d/ -f1)
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
chmod +x $INSTALL_DIR/scripts/*.py $INSTALL_DIR/scripts/*.sh 2>/dev/null || true

# ── Install ndr-agent as systemd service ──────
log "Installing NDR Agent as system service..."
sudo tee /etc/systemd/system/ndr-agent.service > /dev/null << SERVICE
[Unit]
Description=NDR Host Agent
After=network.target

[Service]
Type=simple
User=$USERNAME
ExecStartPre=/bin/rm -f /var/run/suricata.pid /run/suricata.pid /tmp/suricata.pid
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
cp $INSTALL_DIR/config/vector.toml $HOME_DIR/.vector/vector.toml
sed -i "s|/home/[^/]*/logs|$HOME_DIR/logs|g" $HOME_DIR/.vector/vector.toml
log "✅ Vector configured"

# ── Install Angular dependencies ──────────────
log "Installing Angular UI dependencies..."
cd $INSTALL_DIR/ndr-ui
npm install --silent
log "✅ Angular dependencies installed"
# ── Install Docker ─────────────────────────────
log "Installing Docker..."

sudo apt-get remove -y docker docker-engine docker.io containerd runc 2>/dev/null || true

sudo apt-get update -qq
sudo apt-get install -y \
    ca-certificates \
    curl \
    gnupg \
    lsb-release

# Add Docker official GPG key
sudo mkdir -p /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
  | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg

# Add Docker repo
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
  https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" \
  | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt-get update -qq

# Install Docker + Compose plugin
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

log "✅ Docker + Compose installed"

# ── Start Docker service ─────────────
log "Starting Docker service..."
sudo systemctl start docker
sudo systemctl enable docker

# Fix permissions
sudo usermod -aG docker $USERNAME
  log "Checking Docker..."

for i in {1..10}; do
    if docker info >/dev/null 2>&1; then
        break
    fi
    sleep 2
done

if ! docker info >/dev/null 2>&1; then
    err "Docker failed to start!"
fi
# Verify Docker
if ! docker info >/dev/null 2>&1; then
    err "Docker is not running!"
fi

log "✅ Docker is running"

# ── Build and start Docker stack ──────────────
log "Building Docker stack (this takes a few minutes)..."
cd $INSTALL_DIR
docker compose down 2>/dev/null || true
docker compose up -d --build
log "✅ Docker stack started"

# ── Initialize ClickHouse tables ──────────────
log "Waiting for ClickHouse to be ready..."
for i in {1..30}; do
    if curl -s "http://ndr:ndr123@localhost:8123/ping" 2>/dev/null | grep -q "Ok"; then
        log "✅ ClickHouse is ready"
        break
    fi
    echo -n "."
    sleep 3
done
echo ""

log "Creating ClickHouse tables..."
docker exec -i clickhouse clickhouse-client \
    --user=default \
    --multiquery \
    < $INSTALL_DIR/config/clickhouse/init.sql \
    && log "✅ ClickHouse tables created" \
    || warn "⚠️  ClickHouse table creation failed"

# ── Start Angular UI ──────────────────────────
log "Starting Angular UI..."
cd $INSTALL_DIR/ndr-ui
nohup npm start > /tmp/ndr-ui.log 2>&1 &
echo $! > /tmp/ndr-ui.pid
log "✅ Angular UI starting at http://localhost:4200"

# ── WSL2 port forwarding reminder ─────────────
if grep -qi microsoft /proc/version 2>/dev/null; then
    warn "WSL2 detected — run in Windows PowerShell as Admin:"
    echo ""
    echo "  netsh interface portproxy add v4tov4 listenport=4200 listenaddress=0.0.0.0 connectport=4200 connectaddress=$HOST_IP"
    echo "  netsh interface portproxy add v4tov4 listenport=3000 listenaddress=0.0.0.0 connectport=3000 connectaddress=$HOST_IP"
    echo "  netsh interface portproxy add v4tov4 listenport=9092 listenaddress=0.0.0.0 connectport=9092 connectaddress=$HOST_IP"
    echo ""
fi

# ── Verify installation ───────────────────────
echo ""
log "Verifying installation..."
log "  Interface:  $IFACE ($HOST_IP)"
log "  Zeek:       $(/opt/zeek/bin/zeek --version 2>&1 | head -1)"
log "  Suricata:   $(suricata --version 2>&1 | head -1)"
log "  Docker:     $(docker --version)"
log "  Node.js:    $(node --version)"
log "  Agent:      $(curl -s http://localhost:3001/agent/status 2>/dev/null || echo 'starting...')"

# ── Done ──────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════╗"
echo "║         ✅ Installation Complete!         ║"
echo "╠══════════════════════════════════════════╣"
echo "║  UI:      http://localhost:4200           ║"
echo "║  API:     http://localhost:3000           ║"
echo "║  Agent:   http://localhost:3001           ║"
echo "╠══════════════════════════════════════════╣"
echo "║  start:   ./start.sh                     ║"
echo "║  stop:    ./stop.sh                      ║"
echo "║  status:  ./status.sh                    ║"
echo "╚══════════════════════════════════════════╝"
