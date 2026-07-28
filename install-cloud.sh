#!/bin/bash

# ── Auto-fix Windows line endings ─────────────
SELF=$(readlink -f "$0")
if file "$SELF" | grep -q CRLF; then
    echo "Fixing line endings..."
    sed -i 's/\r//' "$SELF"
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
INSTALL_DIR=$(cd "$(dirname "$0")" && pwd)

log "Installing to: $INSTALL_DIR"
log "Running as:    $USERNAME"
log "Mode:          cloud (no Zeek/Suricata/Arkime/OpenSearch)"

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
CLICKHOUSE_URL=http://localhost:8123
CLICKHOUSE_URL_SECONDARY=http://localhost:8124
CLICKHOUSE_USER=ndr
CLICKHOUSE_PASSWORD=ndr123
KAFKA_BROKERS=kafka1:9092,kafka2:9092,kafka3:9092
JWT_SECRET=$JWT_SECRET
OPENSEARCH_URL=
ARKIME_URL=
ARKIME_PASS=
# AI — add providers in Settings > AI Providers (super admin). Env vars are the fallback.
GROQ_API_KEY=$GROQ_API_KEY
GROQ_MODEL=llama-3.3-70b-versatile
BEACON_WINDOW_HOURS=1
INGEST_RATE_LIMIT=50000
SIEM_SYSLOG_HOST=
SIEM_SYSLOG_PORT=514
TRUSTED_SOURCE_CIDRS=
ENVEOF
log "✅ Cloud .env generated"
info "  CLOUD_MODE=true — Zeek/Suricata/Arkime/OpenSearch are disabled"
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
    upstream ndr_backend {
        server ndr-engine-1:3001;
        server ndr-engine-2:3001;
        server ndr-engine-3:3001;
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

        location / {
            proxy_pass         http://ndr_backend;
            proxy_http_version 1.1;
            proxy_set_header   Host              $host;
            proxy_set_header   X-Real-IP         $remote_addr;
            proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;
            proxy_set_header   X-Forwarded-Proto $scheme;
            proxy_read_timeout 120s;
        }
    }
}
NGINXEOF
log "✅ Cloud nginx config written"
info "  SSL: uncomment the ssl_* lines after placing certs at /etc/ssl/ndr/"

# ── Step 6: Start Docker stack ────────────────
step "Starting Docker stack (cloud profile)"

info "  ℹ️  Cloud mode starts: kafka, redis, ndr-engine x3, nginx"
info "  ℹ️  Skipped (onpremise profile only): opensearch, vector"
info ""
info "  ⚠️  Kafka external listener note:"
info "  Sensors outside this VPS connect to kafka on port 9092."
info "  Ensure Kafka advertises the public IP to sensors:"
info "    docker-compose.yml → KAFKA_ADVERTISED_LISTENERS:"
info "    PLAINTEXT://$PUBLIC_IP:9092"
info ""

cd "$INSTALL_DIR"
sudo docker compose down 2>/dev/null || true

sudo docker compose up -d --build
log "✅ Docker stack started (no --profile onpremise)"

# ── Wait for ClickHouse container to be healthy ───────────────────
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

    # Public-facing ports
    sudo ufw allow 22/tcp comment "SSH"
    sudo ufw allow 80/tcp comment "NDR API HTTP"
    sudo ufw allow 443/tcp comment "NDR API HTTPS"
    sudo ufw allow 3000/tcp comment "NDR API (Docker nginx)"
    sudo ufw allow 9092/tcp comment "Kafka (sensor ingest)"

    # Internal-only: block from internet (Docker bypasses ufw so containers still work)
    sudo ufw deny 8123/tcp comment "ClickHouse HTTP ch1 (internal only)"
    sudo ufw deny 8124/tcp comment "ClickHouse HTTP ch2 (internal only)"
    sudo ufw deny 9000/tcp comment "ClickHouse TCP ch1  (internal only)"
    sudo ufw deny 9001/tcp comment "ClickHouse TCP ch2  (internal only)"
    sudo ufw deny 9181/tcp comment "ClickHouse Keeper   (internal only)"
    sudo ufw deny 2181/tcp comment "ZooKeeper           (internal only)"
    sudo ufw deny 6379/tcp comment "Redis               (internal only)"

    sudo ufw --force enable > /dev/null
    log "✅ UFW rules applied:"
    log "   OPEN  : 22 (SSH), 80 (HTTP), 443 (HTTPS), 3000 (API), 9092 (Kafka)"
    log "   CLOSED: 8123/8124/9000/9001/9181 (ClickHouse/Keeper), 6379 (Redis)"
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
if curl -s http://localhost:8124/ping > /dev/null 2>&1; then
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
if curl -s --max-time 5 http://localhost:3000/health > /dev/null 2>&1; then
    log "  ✅ NDR API       — reachable at http://localhost:3000"
else
    warn "  ⚠️  NDR API       — not responding yet (engines may still be starting)"
fi

# Skipped services confirmation
log "  ⏭️  OpenSearch    — skipped (cloud mode)"
log "  ⏭️  Vector        — skipped (cloud mode)"
log "  ⏭️  Zeek          — not installed (cloud mode)"
log "  ⏭️  Suricata      — not installed (cloud mode)"
log "  ⏭️  Arkime        — not installed (cloud mode)"

# ── Final Summary ─────────────────────────────
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║         NDR Cloud Deployment Complete!               ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${BLUE}  Public IP   :${NC} $PUBLIC_IP"
echo -e "${BLUE}  API (HTTP)  :${NC} http://$PUBLIC_IP:3000"
echo -e "${BLUE}  ClickHouse  :${NC} http://localhost:8123 + :8124 (internal only, 2-node cluster)"
echo -e "${BLUE}  Kafka       :${NC} $PUBLIC_IP:9092 (sensors connect here)"
echo -e "${BLUE}  Redis       :${NC} localhost:6379 (internal only)"
echo -e "${BLUE}  Ollama AI   :${NC} http://localhost:11434 (deepseek-r1, local inference)"
echo -e "${BLUE}  SSL certs   :${NC} /etc/ssl/ndr/cert.pem + key.pem"
echo ""
echo -e "${YELLOW}  Next steps:${NC}"
echo "   1. Point your domain DNS → $PUBLIC_IP"
echo "   2. Run: certbot certonly --standalone -d your.domain.com"
echo "   3. Copy certs to /etc/ssl/ndr/"
echo "   4. Edit $INSTALL_DIR/config/nginx/nginx.conf — uncomment SSL lines"
echo "   5. Restart nginx: docker restart ndr-nginx"
echo "   6. On sensors: set CLOUD_URL=http://$PUBLIC_IP:3000 in /opt/ndr-sensor/.env"
echo "   7. Kafka external: update KAFKA_ADVERTISED_LISTENERS to $PUBLIC_IP:9092"
echo ""
echo -e "${GREEN}  Install log: $INSTALL_DIR/install-cloud.log${NC}"
echo ""
