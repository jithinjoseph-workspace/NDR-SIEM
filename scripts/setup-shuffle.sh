#!/bin/bash
INSTALL_DIR=$(cd "$(dirname "$0")/.." && pwd)
HOST_IP=$(ip -o -4 addr show 2>/dev/null | \
    grep -v "127.0.0.1\|docker\|br-\|veth" | \
    awk '{print $4}' | cut -d/ -f1 | head -1)
SHUFFLE_URL="http://${HOST_IP}:5001"
# Load API key from .env
SHUFFLE_API_KEY=$(grep "SHUFFLE_API_KEY" \
    $INSTALL_DIR/.env 2>/dev/null | \
    cut -d= -f2 | tr -d '[:space:]')
log "Using API key: ${SHUFFLE_API_KEY:0:8}..."

log()  { echo -e "\033[0;32m[NDR]\033[0m $1"; }
warn() { echo -e "\033[1;33m[WARN]\033[0m $1"; }

log "Setting up Shuffle SOAR webhook..."

# Wait for Shuffle
for i in {1..30}; do
    if curl -s "$SHUFFLE_URL/api/v1/health" \
        > /dev/null 2>&1; then
        break
    fi
    echo -n "."
    sleep 3
done
echo ""

# Login and get session token
log "Logging in..."
LOGIN=$(curl -s -c /tmp/shuffle-cookies.txt \
    -X POST \
    "$SHUFFLE_URL/api/v1/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"admin","password":"shufflepassword"}' \
    2>/dev/null)

# Extract session token from cookies file
SESSION=$(grep "session_token" /tmp/shuffle-cookies.txt \
    2>/dev/null | awk '{print $NF}' | head -1)

if [ -z "$SESSION" ]; then
    SESSION=$(echo $LOGIN | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    cookies = d.get('cookies', [])
    for c in cookies:
        if c.get('key') == 'session_token':
            print(c.get('value',''))
            break
except: pass
" 2>/dev/null)
fi

log "Session: ${SESSION:0:20}..."
 # If no session — try API key directly
if [ -z "$SESSION" ] && [ -n "$SHUFFLE_API_KEY" ]; then
    log "Using API key auth..."
    SESSION=$SHUFFLE_API_KEY
fi

if [ -z "$SESSION" ]; then
    warn "No auth available — cannot create webhook"
    exit 1
fi

# Create workflow using session cookie
log "Creating NDR workflow..."
WORKFLOW=$(curl -s \
    -b "session_token=$SESSION" \
    -X POST \
    "$SHUFFLE_URL/api/v1/workflows" \
    -H "Content-Type: application/json" \
    -d '{
        "name": "NDR Alert Response",
        "description": "NDR Stack automated response"
    }' 2>/dev/null)

log "Workflow: ${WORKFLOW:0:200}"

WORKFLOW_ID=$(echo $WORKFLOW | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    print(d.get('id',''))
except: pass
" 2>/dev/null)

log "Workflow ID: $WORKFLOW_ID"

if [ -n "$WORKFLOW_ID" ]; then
    # Get workflow triggers to find webhook ID
    sleep 3
    DETAIL=$(curl -s \
        -b "session_token=$SESSION" \
        "$SHUFFLE_URL/api/v1/workflows/$WORKFLOW_ID" \
        2>/dev/null)

    HOOK_ID=$(echo $DETAIL | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    for t in d.get('triggers', []):
        if 'webhook' in t.get('type','').lower():
            print(t.get('id',''))
            break
except: pass
" 2>/dev/null)

    if [ -z "$HOOK_ID" ]; then
        HOOK_ID="webhook_$WORKFLOW_ID"
    fi

WEBHOOK_URL="$SHUFFLE_URL/api/v1/workflows/$WORKFLOW_ID/run"
    log "✅ Webhook URL: $WEBHOOK_URL"

    # Save to .env
    if grep -q "SHUFFLE_WEBHOOK_URL" $INSTALL_DIR/.env 2>/dev/null; then
        sed -i \
            "s|SHUFFLE_WEBHOOK_URL=.*|SHUFFLE_WEBHOOK_URL=$WEBHOOK_URL|" \
            $INSTALL_DIR/.env
    else
        echo "SHUFFLE_WEBHOOK_URL=$WEBHOOK_URL" >> $INSTALL_DIR/.env
    fi
    log "✅ Webhook saved to .env"

    # Test webhook
    TEST=$(curl -s -X POST "$WEBHOOK_URL" \
        -H "Content-Type: application/json" \
        -d '{"test":"ndr","score":85}' 2>/dev/null)
    log "Webhook test: $TEST"
else
    warn "Auto-create failed!"
    warn "Manual setup:"
    warn "1. Open http://${HOST_IP}:3002"
    warn "2. Create workflow → add webhook trigger"
    warn "3. Run: sed -i 's|SHUFFLE_WEBHOOK_URL=.*|SHUFFLE_WEBHOOK_URL=YOUR_URL|' $INSTALL_DIR/.env"
fi

rm -f /tmp/shuffle-cookies.txt
