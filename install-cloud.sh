#!/bin/bash

# ── Auto-fix Windows line endings ─────────────
SELF=$(readlink -f "$0")
if file "$SELF" | grep -q CRLF; then
    echo "Fixing line endings..."
    sed -i 's/\r//' "$SELF"
    exec bash "$SELF" "$@"
fi

# ── Bootstrap: download required files if not already present ─────────────────
# Triggered when running via:  bash <(curl -fsSL .../install-cloud.sh)
# In that case $0 is /dev/stdin or /dev/fd/N — no docker-compose.yml next to it.
if [ ! -f "$(dirname "$0")/docker-compose.yml" ]; then
    echo ""
    echo "  NDR Cloud Installer — downloading required files..."
    echo ""
    read -rp "  GitHub token (provided by Proma Secure): " GH_TOKEN
    INSTALL_DIR="${1:-/opt/ndr}"
    echo "  Installing to: $INSTALL_DIR"
    sudo mkdir -p "$INSTALL_DIR"
    sudo chmod 755 "$INSTALL_DIR"

    echo "  Downloading config files via GitHub API..."
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
        print(f"  ERROR: {e}")
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

download_file("docker-compose.yml",  f"{dest}/docker-compose.yml")
download_file("install-cloud.sh",    f"{dest}/install-cloud.sh")
download_file("start.sh",            f"{dest}/start.sh")
download_file("stop.sh",             f"{dest}/stop.sh")
download_file("status.sh",           f"{dest}/status.sh")
download_dir("config",               f"{dest}/config")
download_dir("scripts",              f"{dest}/scripts")
download_dir("rust/ndr-engine/rules",f"{dest}/rust/ndr-engine/rules")
PYEOF
    chmod +x "$INSTALL_DIR/install-cloud.sh"
    chmod +x "$INSTALL_DIR/start.sh" "$INSTALL_DIR/stop.sh" "$INSTALL_DIR/status.sh"
    echo ""
    exec bash "$INSTALL_DIR/install-cloud.sh" "$INSTALL_DIR"
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
echo "║     NDR Cloud Installer v1.0             ║"
echo "║  Kafka + ClickHouse + Redis + Engine     ║"
echo "╚══════════════════════════════════════════╝"
echo ""

TOTAL_STEPS=9
CURRENT_STEP=0

step() {
    CURRENT_STEP=$((CURRENT_STEP + 1))
    echo ""
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}  Step $CURRENT_STEP/$TOTAL_STEPS: $1${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

# ── Detect public IP ──────────────────────────
log "Detecting public IP..."
PUBLIC_IP=$(curl -s --max-time 10 ifconfig.me 2>/dev/null || \
            curl -s --max-time 10 api.ipify.org 2>/dev/null || \
            hostname -I | awk '{print $1}')
log "✅ Public IP: $PUBLIC_IP"

USERNAME=$(whoami)
HOME_DIR=$HOME
INSTALL_DIR="${1:-$(cd "$(dirname "$0")" && pwd)}"

log "Installing to: $INSTALL_DIR"
log "Running as:    $USERNAME"
log "Mode:          cloud (no Agent-Z/Agent-S/Arkime/OpenSearch)"

# ── Check OS ──────────────────────────────────
. /etc/os-release
log "Detected OS: $NAME $VERSION_ID"
[[ "$ID" != "ubuntu" ]] && warn "Only Ubuntu tested. Proceed with caution."

# ── Fix APT sources ───────────────────────────
UBUNTU_CODENAME=$(. /etc/os-release 2>/dev/null && echo "${VERSION_CODENAME:-$(lsb_release -cs 2>/dev/null)}")
UBUNTU_CODENAME=${UBUNTU_CODENAME:-noble}
log "Ubuntu codename: ${UBUNTU_CODENAME}"

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
sudo apt-get update -qq 2>&1 | grep -E "^Get|^Hit|^Err" | head -10 || true

# ── Step 1: System dependencies ───────────────
step "Installing system dependencies"

log "Installing packages..."
sudo apt-get install -y \
    curl wget git jq \
    python3 python3-pip python3-requests \
    net-tools iproute2 \
    ufw \
    apt-transport-https ca-certificates gnupg \
    lsb-release openssl
log "✅ System packages installed"

# ── Docker ────────────────────────────────────
if ! command -v docker &>/dev/null; then
    log "Installing Docker..."
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
        | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
    DOCKER_CODENAME="${UBUNTU_CODENAME}"
    # Fall back to noble if Docker repo doesn't exist for this codename yet
    if ! curl -fsSL "https://download.docker.com/linux/ubuntu/dists/${DOCKER_CODENAME}/InRelease" \
               --max-time 5 -o /dev/null 2>/dev/null; then
        log "Docker repo not yet available for '${DOCKER_CODENAME}' — falling back to noble"
        DOCKER_CODENAME="noble"
    fi
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] \
        https://download.docker.com/linux/ubuntu ${DOCKER_CODENAME} stable" \
        | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
    sudo apt-get update -qq
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y \
        docker-ce docker-ce-cli containerd.io docker-compose-plugin
    sudo usermod -aG docker "$USERNAME"
    sudo systemctl enable docker
    sudo systemctl start docker
    log "✅ Docker installed"
else
    log "✅ Docker already installed"
fi

# ── Docker daemon config ──────────────────────────────────────────────────────
sudo tee /etc/docker/daemon.json > /dev/null << 'DOCKEREOF'
{
  "log-driver": "json-file",
  "log-opts": { "max-size": "10m", "max-file": "3" }
}
DOCKEREOF
sudo systemctl restart docker
sleep 3

# ── Step 2: Create NDR directories ────────────
step "Creating NDR storage directories"

sudo mkdir -p /opt/ndr/pcap
sudo mkdir -p /opt/ndr/evidence
sudo chmod -R 755 /opt/ndr
sudo chown -R "$USERNAME:$USERNAME" /opt/ndr
log "✅ Created /opt/ndr/pcap and /opt/ndr/evidence"

# ── SSL directory setup ───────────────────────
sudo mkdir -p /etc/ssl/ndr
sudo chmod 750 /etc/ssl/ndr
log "✅ SSL directory created at /etc/ssl/ndr"
info "  Place your certificates here:"
info "    /etc/ssl/ndr/cert.pem   (TLS certificate)"
info "    /etc/ssl/ndr/key.pem    (TLS private key)"
info "  Use certbot: certbot certonly --standalone -d your.domain.com"

# ── Step 3: Configure ClickHouse ─────────────
step "Configuring ClickHouse"

# ClickHouse runs as a Docker container — started in Step 6 via docker compose up.
# User (ndr/ndr123) is created via CREATE USER in init.sql on first start.
# Schema (ndr database + all tables) is created by config/clickhouse/init.sql
# on the first container start via /docker-entrypoint-initdb.d/.
log "ClickHouse will start as a Docker container with the stack"
log "  User:   ndr / ndr123  (via init.sql)"
log "  Ports:  8123/8124 (HTTP), 9000/9001 (native) — 2-node cluster"
log "  Schema: auto-created on first start via init.sql"
log "✅ ClickHouse configured"

# ── Step 4: Generate .env ─────────────────────
step "Generating cloud .env"

if [ -f "$INSTALL_DIR/.env" ] && grep -q "JWT_SECRET" "$INSTALL_DIR/.env"; then
    JWT_SECRET=$(grep "JWT_SECRET" "$INSTALL_DIR/.env" | cut -d= -f2-)
else
    JWT_SECRET=$(openssl rand -hex 32)
fi

if [ -f "$INSTALL_DIR/.env" ] && grep -q "^NDR_AGENT_SECRET=." "$INSTALL_DIR/.env"; then
    NDR_AGENT_SECRET=$(grep "^NDR_AGENT_SECRET=" "$INSTALL_DIR/.env" | cut -d= -f2-)
else
    NDR_AGENT_SECRET=$(openssl rand -hex 32)
fi

# ── RSA license key pair (generated once; private key stays on this server) ──
if [ -f "$INSTALL_DIR/.env" ] && grep -q "^LICENSE_PRIVATE_KEY=." "$INSTALL_DIR/.env"; then
    LICENSE_PRIVATE_KEY=$(grep "^LICENSE_PRIVATE_KEY=" "$INSTALL_DIR/.env" | cut -d= -f2-)
    LICENSE_PUBLIC_KEY=$(grep "^LICENSE_PUBLIC_KEY=" "$INSTALL_DIR/.env" | cut -d= -f2-)
fi
if [ -z "$LICENSE_PRIVATE_KEY" ]; then
    log "Generating RSA-2048 key pair for license signing..."
    _TMP_KEY=$(mktemp)
    openssl genrsa -out "$_TMP_KEY" 2048 2>/dev/null
    LICENSE_PRIVATE_KEY=$(base64 -w0 < "$_TMP_KEY")
    LICENSE_PUBLIC_KEY=$(openssl rsa -in "$_TMP_KEY" -pubout 2>/dev/null | base64 -w0)
    rm -f "$_TMP_KEY"
    log "RSA key pair generated"
fi

# Prompt for Groq API key
GROQ_API_KEY=""
if [ -f "$INSTALL_DIR/.env" ]; then
    GROQ_API_KEY=$(grep "^GROQ_API_KEY=" "$INSTALL_DIR/.env" | cut -d= -f2- 2>/dev/null || echo "")
fi
if [ -z "$GROQ_API_KEY" ]; then
    echo ""
    info "  NDR uses Groq for AI threat analysis (free at console.groq.com)"
    read -rp "  Enter your Groq API key (or press Enter to skip): " GROQ_API_KEY
    GROQ_API_KEY="${GROQ_API_KEY:-}"
fi

cat > "$INSTALL_DIR/.env" << ENVEOF
HOST_IP=$PUBLIC_IP
HOME_DIR=$HOME_DIR
INSTALL_DIR=$INSTALL_DIR
CLOUD_MODE=true
DEPLOY_MODE=cloud
LOCAL_SENSOR_ID=local-central
TENANT_ID=default
CLICKHOUSE_URL=http://clickhouse1:8123
CLICKHOUSE_URL_SECONDARY=http://clickhouse2:8123
CLICKHOUSE_USER=ndr
CLICKHOUSE_PASSWORD=ndr123
KAFKA_BROKERS=kafka1:9092,kafka2:9092,kafka3:9092
JWT_SECRET=$JWT_SECRET
NDR_AGENT_SECRET=$NDR_AGENT_SECRET
CORS_ORIGIN=http://$PUBLIC_IP
OPENSEARCH_URL=
ARKIME_URL=
ARKIME_PASS=
OPENAI_API_KEY=
GROQ_API_KEY=$GROQ_API_KEY
GROQ_MODEL=llama-3.3-70b-versatile
BEACON_WINDOW_HOURS=1
INGEST_RATE_LIMIT=50000
SIEM_SYSLOG_HOST=
SIEM_SYSLOG_PORT=514
TRUSTED_SOURCE_CIDRS=
LICENSE_PRIVATE_KEY=$LICENSE_PRIVATE_KEY
LICENSE_PUBLIC_KEY=$LICENSE_PUBLIC_KEY
LICENSE_TOKEN=
TENANT_ADMIN_USER=
TENANT_ADMIN_PASS=
ENVEOF
log "✅ Cloud .env generated"
info "  CLOUD_MODE=true — Agent-Z/Agent-S/Arkime/OpenSearch are disabled"
if [ -n "$GROQ_API_KEY" ]; then
    info "  AI: Groq llama-3.3-70b-versatile (fallback). Add providers in Settings for full control."
else
    warn "  AI: No Groq key set — add a provider in Settings > AI Providers after install."
fi

# ── Step 5: Cloud nginx config ────────────────
step "Writing cloud nginx configuration"

mkdir -p "$INSTALL_DIR/config/nginx"
cat > "$INSTALL_DIR/config/nginx/nginx.conf" << 'NGINXEOF'
events { worker_connections 1024; }

http {
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;

    upstream ndr_engines {
        least_conn;
        server ndr-engine-1:3000 max_fails=3 fail_timeout=30s;
        server ndr-engine-2:3000 max_fails=3 fail_timeout=30s;
        server ndr-engine-3:3000 max_fails=3 fail_timeout=30s;
    }

    upstream ws_engines {
        ip_hash;
        server ndr-engine-1:3000;
        server ndr-engine-2:3000;
        server ndr-engine-3:3000;
    }

    # Redirect HTTP → HTTPS (enable after placing certs)
    # server {
    #     listen 80;
    #     server_name _;
    #     return 301 https://$host$request_uri;
    # }

    server {
        listen 80;

        # SSL (uncomment after placing certs at /etc/ssl/ndr/)
        # listen 443 ssl;
        # ssl_certificate     /etc/ssl/ndr/cert.pem;
        # ssl_certificate_key /etc/ssl/ndr/key.pem;
        # ssl_protocols       TLSv1.2 TLSv1.3;

        client_max_body_size 500m;

        location /ws {
            proxy_pass         http://ws_engines;
            proxy_http_version 1.1;
            proxy_set_header   Upgrade    $http_upgrade;
            proxy_set_header   Connection "upgrade";
            proxy_set_header   Host       $host;
            proxy_read_timeout 3600s;
        }

        location /api {
            proxy_pass         http://ndr_engines;
            proxy_http_version 1.1;
            proxy_set_header   Host              $host;
            proxy_set_header   X-Real-IP         $remote_addr;
            proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;
            proxy_set_header   X-Forwarded-Proto $scheme;
            proxy_read_timeout 120s;
        }

        location /health {
            proxy_pass http://ndr_engines;
        }

        location / {
            proxy_pass         http://ndr-ui:80;
            proxy_http_version 1.1;
            proxy_set_header   Host              $host;
            proxy_set_header   X-Real-IP         $remote_addr;
            proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;
            proxy_set_header   X-Forwarded-Proto $scheme;
            proxy_read_timeout 60s;
        }
    }
}
NGINXEOF
log "✅ Cloud nginx config written"
info "  SSL: uncomment the ssl_* lines after placing certs at /etc/ssl/ndr/"

# ── Step 6: Start Docker stack ────────────────
step "Starting Docker stack (cloud profile)"

info "  ℹ️  Cloud mode starts: kafka (internal), redis, ndr-engine x3, nginx, ndr-ui"
info "  ℹ️  Skipped (onpremise profile only): opensearch, vector"
info "  ℹ️  Sensors send data via HTTP POST to https://$PUBLIC_IP/api/ingest"
info "  ℹ️  Kafka runs internally only — not exposed to sensors"
info ""

# ── Registry login ────────────────────────────
REGISTRY="ghcr.io/jithinjoseph-workspace"
printf "\n"
read -rp "  Registry token (provided by Proma Secure): " REGISTRY_TOKEN
echo "$REGISTRY_TOKEN" | sudo docker login ghcr.io -u ndr-customer --password-stdin \
    || err "Registry login failed — check your token and try again"
log "Registry login successful"

# ── Pull pre-built images ─────────────────────
log "Pulling pre-built images..."
sudo docker pull "${REGISTRY}/ndr-engine:latest"
sudo docker pull "${REGISTRY}/ndr-ui:latest"

# ── Write compose override (pre-built images, no build:) ─────────────
cat > "$INSTALL_DIR/docker-compose.cloud.yml" << OVERRIDE
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

cd "$INSTALL_DIR"
sudo docker compose down 2>/dev/null || true

sudo docker compose -f docker-compose.yml -f docker-compose.cloud.yml up -d
log "✅ Docker stack started with pre-built images"
# docker compose up -d already waited for every depends_on:healthy condition
# before returning, so ch1 and ch2 are guaranteed healthy at this point.

# ── Step 7: Create Kafka topic ───────────────
step "Creating Kafka topics (3 partitions, replication-factor 3)"

log "Waiting for Kafka to be ready..."
sleep 20
for i in {1..30}; do
    if sudo docker exec kafka1 \
        /opt/kafka/bin/kafka-broker-api-versions.sh \
        --bootstrap-server localhost:9092 > /dev/null 2>&1; then
        log "✅ Kafka is ready"
        break
    fi
    echo -n "."
    sleep 3
done
echo ""

sudo docker exec kafka1 \
    /opt/kafka/bin/kafka-topics.sh \
    --bootstrap-server localhost:9092 \
    --create --if-not-exists \
    --topic ndr-events \
    --partitions 3 \
    --replication-factor 3 \
    2>/dev/null || true
log "✅ Kafka topic ndr-events created with 3 partitions, replication-factor 3"

sudo docker exec kafka1 \
    /opt/kafka/bin/kafka-configs.sh \
    --bootstrap-server localhost:9092 \
    --alter --entity-type topics \
    --entity-name ndr-events \
    --add-config retention.ms=86400000 \
    2>/dev/null || true
log "✅ Kafka retention set to 24 hours"

log "✅ Kafka topic and retention set"

# ── Step 8: UFW firewall rules ────────────────
step "Configuring UFW firewall"

if command -v ufw &>/dev/null; then
    log "Applying firewall rules..."
    sudo ufw --force reset > /dev/null 2>&1 || true
    sudo ufw default deny incoming > /dev/null
    sudo ufw default allow outgoing > /dev/null

    # Public-facing ports — sensors use HTTP, Kafka is internal only
    sudo ufw allow 22/tcp  comment "SSH"
    sudo ufw allow 80/tcp  comment "NDR API HTTP  (sensors + UI)"
    sudo ufw allow 443/tcp comment "NDR API HTTPS (sensors + UI)"
    sudo ufw allow 3000/tcp comment "NDR API legacy port"

    # Internal-only: Kafka, ClickHouse, Redis, Keeper all stay private
    sudo ufw deny 9092/tcp comment "Kafka (internal only — sensors use HTTP)"
    sudo ufw deny 8123/tcp comment "ClickHouse HTTP ch1 (internal only)"
    sudo ufw deny 8124/tcp comment "ClickHouse HTTP ch2 (internal only)"
    sudo ufw deny 9000/tcp comment "ClickHouse TCP ch1  (internal only)"
    sudo ufw deny 9001/tcp comment "ClickHouse TCP ch2  (internal only)"
    sudo ufw deny 9181/tcp comment "ClickHouse Keeper   (internal only)"
    sudo ufw deny 2181/tcp comment "ZooKeeper           (internal only)"
    sudo ufw deny 6379/tcp comment "Redis               (internal only)"

    sudo ufw --force enable > /dev/null
    log "✅ UFW rules applied:"
    log "   OPEN  : 22 (SSH), 80 (HTTP), 443 (HTTPS), 3000 (API)"
    log "   CLOSED: 9092 (Kafka), 8123/8124/9000/9001/9181 (ClickHouse/Keeper), 6379 (Redis)"
else
    warn "ufw not found — skipping firewall setup"
fi

# ── Step 9: Health checks ────────────────────
step "Running health checks"

echo ""
log "Checking services..."

# ClickHouse
if curl -s http://localhost:8123/ping > /dev/null 2>&1; then
    log "  ✅ ClickHouse ch1 — OK"
else
    warn "  ⚠️  ClickHouse ch1 — NOT READY"
fi
if sudo docker inspect --format='{{.State.Health.Status}}' clickhouse2 2>/dev/null | grep -q "^healthy$"; then
    log "  ✅ ClickHouse ch2 — OK"
else
    warn "  ⚠️  ClickHouse ch2 — NOT READY"
fi

# Kafka container
if sudo docker ps --format '{{.Names}}' | grep -q "^kafka1$"; then
    log "  ✅ Kafka         — running"
else
    warn "  ⚠️  Kafka         — NOT running"
fi

# Redis container
if sudo docker ps --format '{{.Names}}' | grep -q "^ndr-redis$"; then
    log "  ✅ Redis         — running"
else
    warn "  ⚠️  Redis         — NOT running"
fi

# Engine containers
for i in 1 2 3; do
    if sudo docker ps --format '{{.Names}}' | grep -q "^ndr-engine-$i$"; then
        log "  ✅ ndr-engine-$i  — running"
    else
        warn "  ⚠️  ndr-engine-$i  — NOT running"
    fi
done

# Nginx container
if sudo docker ps --format '{{.Names}}' | grep -q "^ndr-nginx$"; then
    log "  ✅ nginx         — running"
else
    warn "  ⚠️  nginx         — NOT running"
fi

# API health
sleep 5
if curl -s --max-time 5 http://localhost:80/api/health > /dev/null 2>&1; then
    log "  ✅ NDR API       — reachable at http://localhost"
else
    warn "  ⚠️  NDR API       — not responding yet (engines may still be starting)"
fi

# Skipped services confirmation
log "  ⏭️  OpenSearch    — skipped (cloud mode)"
log "  ⏭️  Vector        — skipped (cloud mode)"
log "  ⏭️  Agent-Z       — not installed (cloud mode)"
log "  ⏭️  Agent-S       — not installed (cloud mode)"
log "  ⏭️  Arkime        — not installed (cloud mode)"

# ── WSL2 auto port-forwarding ────────────────────────────────────────────────
# WSL2 runs in a VM — Windows doesn't auto-route external traffic into it.
# Call netsh.exe via WSL2 interop to set up the forwarding automatically.
if grep -qi microsoft /proc/version 2>/dev/null; then
    WSL_IP=$(ip addr show eth0 2>/dev/null | grep 'inet ' | awk '{print $2}' | cut -d/ -f1)
    if [ -n "$WSL_IP" ]; then
        log "WSL2 detected — configuring Windows port forwarding..."
        # Clear any stale rules first
        netsh.exe interface portproxy delete v4tov4 listenport=80  listenaddress=0.0.0.0 > /dev/null 2>&1 || true
        netsh.exe interface portproxy delete v4tov4 listenport=443 listenaddress=0.0.0.0 > /dev/null 2>&1 || true
        # Add forwarding rules: Windows 0.0.0.0:80/443 → WSL2 IP:80/443
        PORTPROXY_OK=true
        netsh.exe interface portproxy add v4tov4 \
            listenport=80 listenaddress=0.0.0.0 \
            connectport=80 connectaddress="$WSL_IP" > /dev/null 2>&1 || PORTPROXY_OK=false
        netsh.exe interface portproxy add v4tov4 \
            listenport=443 listenaddress=0.0.0.0 \
            connectport=443 connectaddress="$WSL_IP" > /dev/null 2>&1 || PORTPROXY_OK=false
        if $PORTPROXY_OK; then
            # Open Windows Firewall
            netsh.exe advfirewall firewall delete rule name="NDR HTTP"  > /dev/null 2>&1 || true
            netsh.exe advfirewall firewall delete rule name="NDR HTTPS" > /dev/null 2>&1 || true
            netsh.exe advfirewall firewall add rule name="NDR HTTP"  dir=in action=allow protocol=TCP localport=80  > /dev/null 2>&1 || true
            netsh.exe advfirewall firewall add rule name="NDR HTTPS" dir=in action=allow protocol=TCP localport=443 > /dev/null 2>&1 || true
            log "✅ Windows port forwarding configured (WSL2 $WSL_IP → 0.0.0.0:80/443)"
            info "  Open in browser: http://localhost"
            warn "  WSL2 IP changes on reboot — re-run install-cloud.sh to refresh forwarding"
        else
            warn "  netsh failed (needs admin) — open PowerShell as Administrator and run:"
            echo "    netsh interface portproxy add v4tov4 listenport=80  listenaddress=0.0.0.0 connectport=80  connectaddress=$WSL_IP"
            echo "    netsh interface portproxy add v4tov4 listenport=443 listenaddress=0.0.0.0 connectport=443 connectaddress=$WSL_IP"
            echo "    netsh advfirewall firewall add rule name=\"NDR HTTP\"  dir=in action=allow protocol=TCP localport=80"
            echo "    netsh advfirewall firewall add rule name=\"NDR HTTPS\" dir=in action=allow protocol=TCP localport=443"
        fi
    fi
fi

# ── Final Summary ─────────────────────────────
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║         NDR Cloud Deployment Complete!               ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${BLUE}  Public IP   :${NC} $PUBLIC_IP"
echo -e "${BLUE}  API (HTTP)  :${NC} http://$PUBLIC_IP (port 80)"
echo -e "${BLUE}  API (HTTPS) :${NC} https://$PUBLIC_IP (port 443, after cert setup)"
echo -e "${BLUE}  ClickHouse  :${NC} internal only (clickhouse1:8123, clickhouse2:8123)"
echo -e "${BLUE}  Kafka       :${NC} internal only (sensors use HTTP POST to /api/ingest)"
echo -e "${BLUE}  Redis       :${NC} internal only (ndr-redis:6379)"
echo -e "${BLUE}  SSL certs   :${NC} /etc/ssl/ndr/cert.pem + key.pem"
echo ""
echo -e "${YELLOW}  Next steps:${NC}"
echo "   1. Point your domain DNS → $PUBLIC_IP"
echo "   2. Run: certbot certonly --standalone -d your.domain.com"
echo "   3. Copy certs to /etc/ssl/ndr/"
echo "   4. Edit $INSTALL_DIR/config/nginx/nginx.conf — uncomment SSL lines"
echo "   5. Restart nginx: docker restart ndr-nginx"
echo "   6. On sensors: set CLOUD_URL=https://$PUBLIC_IP in /opt/ndr-sensor/.env"
echo ""
echo -e "${GREEN}  Install log: $INSTALL_DIR/install-cloud.log${NC}"
echo ""
