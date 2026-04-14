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
log "Running as: $USERNAME"

# ── Install system dependencies ───────────────
log "Installing system dependencies..."
sudo apt-get update -qq
sudo apt-get install -y -qq \
    curl wget git jq python3 \
    net-tools iproute2 \
    docker.io \
    netcat-traditional 2>/dev/null || true

# ── Install docker compose plugin ────────────
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
    log "✅ Suricata installed"
else
    log "✅ Suricata already installed: $(suricata --build-info | head -1)"
    sudo systemctl disable suricata 2>/dev/null || true
    sudo systemctl stop suricata 2>/dev/null || true
fi

# ── Install Zeek ──────────────────────────────
if ! command -v /opt/zeek/bin/zeek &>/dev/null; then
    log "Installing Zeek..."
    echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_20.04/ /' \
        | sudo tee /etc/apt/sources.list.d/security:zeek.list
    curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_20.04/Release.key \
        | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null
    sudo apt-get update -qq
    sudo apt-get install -y zeek
    log "✅ Zeek installed"
else
    log "✅ Zeek already installed: $(/opt/zeek/bin/zeek --version 2>&1 | head -1)"
fi

# ── Install Node.js for Angular UI ───────────
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

# ── Get WSL host IP ───────────────────────────
HOST_IP=$(ip -o -4 addr show eth0 | awk '{print $4}' | cut -d/ -f1)
log "Host IP detected: $HOST_IP"

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

# ── Copy scripts ──────────────────────────────
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

# ── Update docker-compose with correct IP ─────
log "Configuring docker-compose..."
sed -i "s|NDR_AGENT_URL=http://[0-9.]*:3001|NDR_AGENT_URL=http://$HOST_IP:3001|g" \
    $INSTALL_DIR/docker-compose.yml

# ── Update vector.toml paths ──────────────────
log "Configuring Vector..."
sed -i "s|/home/[^/]*/logs|$HOME_DIR/logs|g" \
    $INSTALL_DIR/config/vector.toml 2>/dev/null || true
cp $INSTALL_DIR/config/vector.toml $HOME_DIR/.vector/vector.toml

# ── Install Angular UI dependencies ───────────
log "Installing Angular UI dependencies..."
cd $INSTALL_DIR/ndr-ui
npm install --silent
log "✅ Angular dependencies installed"

# ── Build Docker stack ────────────────────────
log "Building Docker stack (this takes a few minutes)..."
cd $INSTALL_DIR
docker compose down 2>/dev/null || true
docker compose up -d --build
log "✅ Docker stack started"

# ── Start Angular UI ──────────────────────────
log "Starting Angular UI..."
cd $INSTALL_DIR/ndr-ui
nohup npm start > /tmp/ndr-ui.log 2>&1 &
echo $! > /tmp/ndr-ui.pid
log "✅ Angular UI starting..."

# ── Setup Windows port proxy (WSL2) ───────────
if grep -qi microsoft /proc/version 2>/dev/null; then
    warn "WSL2 detected — run these in Windows PowerShell as Admin:"
    echo ""
    echo "  netsh interface portproxy add v4tov4 listenport=4200 listenaddress=0.0.0.0 connectport=4200 connectaddress=$HOST_IP"
    echo "  netsh interface portproxy add v4tov4 listenport=3000 listenaddress=0.0.0.0 connectport=3000 connectaddress=$HOST_IP"
    echo "  netsh interface portproxy add v4tov4 listenport=9092 listenaddress=0.0.0.0 connectport=9092 connectaddress=$HOST_IP"
    echo ""
fi

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
